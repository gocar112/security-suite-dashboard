using System.Diagnostics;
using System.Text.Json;
using System.Threading.Channels;

namespace SecuritySuite.Storage;

/// <summary>
/// Append-only NDJSON event store with an in-memory ring buffer and a pub/sub
/// bus for the dashboard's event stream.
/// </summary>
/// <remarks>
/// Durable on disk, bounded in memory. The ring buffer is what the dashboard
/// reads; the NDJSON file is the record, and for remediation it is the audit
/// trail, which is why <see cref="Clear"/> refuses to drop those entries.
/// </remarks>
public sealed class EventStore
{
    private readonly Lock _gate = new();
    private readonly Queue<SuiteEvent> _events;
    private readonly List<Subscription> _subscribers = [];
    private readonly Dictionary<string, TriageState> _triage = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _counters = new(StringComparer.Ordinal);
    private readonly Stopwatch _uptime = Stopwatch.StartNew();
    private readonly Action<string> _warn;

    public string Path { get; }
    public string TriagePath { get; }
    public int HistoryLimit { get; }

    public EventStore(string findingsLog, string triageFile, int historyLimit = 2000,
                      Action<string>? warn = null)
    {
        Path = SuitePathsOrSelf(findingsLog);
        TriagePath = SuitePathsOrSelf(triageFile);
        HistoryLimit = Math.Max(1, historyLimit);
        _events = new Queue<SuiteEvent>(Math.Min(HistoryLimit, 1024));
        _warn = warn ?? (_ => { });

        var parent = System.IO.Path.GetDirectoryName(Path);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

        LoadTriage();
        LoadHistory();
    }

    private static string SuitePathsOrSelf(string path) =>
        System.IO.Path.IsPathRooted(path) ? path : System.IO.Path.GetFullPath(path);

    public static string NowIso() => DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:sszzz");

    public static double NowEpoch() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

    /// <summary>Short, collision-resistant enough for a per-host event log.</summary>
    public static string NewId() => Guid.NewGuid().ToString("N")[..12];

    // ------------------------------------------------------------------ load
    private void LoadTriage()
    {
        if (!File.Exists(TriagePath)) return;
        try
        {
            var parsed = JsonSerializer.Deserialize<Dictionary<string, TriageState>>(
                File.ReadAllText(TriagePath), SuiteJson.Options);
            if (parsed is null) return;
            foreach (var (key, value) in parsed) _triage[key] = value;
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
        {
            _warn("[!] Ignoring unreadable triage state: " + exc.Message);
        }
    }

    /// <summary>
    /// Replay the tail of the findings log so a restart keeps the dashboard warm.
    /// </summary>
    /// <remarks>
    /// Streams the file and keeps only the last <see cref="HistoryLimit"/> lines
    /// rather than reading it whole: this log grows without bound by design, and
    /// loading a 200 MB history to show the newest 2,000 entries would make
    /// startup scale with the lifetime of the install.
    /// </remarks>
    private void LoadHistory()
    {
        if (!File.Exists(Path)) return;

        var tail = new Queue<string>(HistoryLimit);
        try
        {
            using var reader = new StreamReader(
                new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            while (reader.ReadLine() is { } line)
            {
                if (line.Length == 0) continue;
                tail.Enqueue(line);
                if (tail.Count > HistoryLimit) tail.Dequeue();
            }
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            _warn("[!] Could not replay findings log: " + exc.Message);
            return;
        }

        var malformed = 0;
        foreach (var line in tail)
        {
            SuiteEvent? parsed;
            try { parsed = JsonSerializer.Deserialize<SuiteEvent>(line, SuiteJson.Options); }
            catch (JsonException) { malformed++; continue; }
            if (parsed is null) continue;

            if (string.IsNullOrEmpty(parsed.Id)) parsed.Id = StableId(line);
            ApplyTriage(parsed);
            Append(parsed);
            Count(parsed);
        }
        if (malformed > 0)
            _warn("[!] Skipped " + malformed + " malformed line(s) in the findings log");
    }

    /// <summary>
    /// Every remediation record in the log, however old.
    /// </summary>
    /// <remarks>
    /// Streams the file rather than using the ring buffer, because the whole
    /// point is to find the records the buffer has already forgotten. Throws on
    /// an unreadable log so the caller can abort instead of rewriting a file it
    /// could not read.
    /// </remarks>
    private List<SuiteEvent> RemediationRecordsOnDisk()
    {
        var kept = new List<SuiteEvent>();
        if (!File.Exists(Path)) return kept;

        using var reader = new StreamReader(
            new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));

        while (reader.ReadLine() is { } line)
        {
            if (line.Length == 0) continue;

            // Cheap prefilter: parsing every line of a large log to find the
            // few remediation records is the expensive way to do this.
            if (!line.Contains(SuiteEvent.TypeRemediation, StringComparison.Ordinal)) continue;

            SuiteEvent? parsed;
            try { parsed = JsonSerializer.Deserialize<SuiteEvent>(line, SuiteJson.Options); }
            catch (JsonException) { continue; }

            if (parsed?.EventType == SuiteEvent.TypeRemediation)
            {
                if (string.IsNullOrEmpty(parsed.Id)) parsed.Id = StableId(line);
                kept.Add(parsed);
            }
        }
        return kept;
    }

    /// <summary>
    /// Find one event anywhere in the log, including outside the memory window.
    /// </summary>
    /// <remarks>
    /// Used by triage, which must not 404 on a finding simply because it has
    /// scrolled out of the ring buffer. Returns null on an unreadable log,
    /// because for this caller "cannot find it" and "cannot read" lead to the
    /// same refusal.
    /// </remarks>
    private SuiteEvent? FindOnDisk(string eventId)
    {
        if (!File.Exists(Path) || eventId.Length == 0) return null;

        try
        {
            using var reader = new StreamReader(
                new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));

            while (reader.ReadLine() is { } line)
            {
                if (line.Length == 0) continue;
                if (!line.Contains(eventId, StringComparison.Ordinal)) continue;

                SuiteEvent? parsed;
                try { parsed = JsonSerializer.Deserialize<SuiteEvent>(line, SuiteJson.Options); }
                catch (JsonException) { continue; }

                if (parsed is not null && parsed.Id == eventId) return parsed;
            }
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return null;
        }
        return null;
    }

    /// <summary>
    /// A deterministic id for a log line that carries none.
    /// </summary>
    /// <remarks>
    /// Derived from the line's own bytes, so it is the same on every restart.
    /// A random id looked fine until someone triaged such a finding and the
    /// state failed to reattach after a restart, because the id it was filed
    /// under no longer existed.
    /// </remarks>
    private static string StableId(string line) =>
        System.Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(line)))[..12].ToLowerInvariant();

    // ----------------------------------------------------------------- write
    private void Append(SuiteEvent item)
    {
        _events.Enqueue(item);
        while (_events.Count > HistoryLimit) _events.Dequeue();
    }

    private void Bump(string key) =>
        _counters[key] = _counters.GetValueOrDefault(key) + 1;

    private void Count(SuiteEvent item)
    {
        Bump("type:" + (item.EventType.Length == 0 ? "unknown" : item.EventType));
        if (item.EventType is SuiteEvent.TypeScan or SuiteEvent.TypeMatch && item.Skipped is null)
            Bump("files_scanned");
        if (item.EventType == SuiteEvent.TypeMatch)
            Bump("sev:" + Severity.Normalise(item.Severity));
    }

    private void ApplyTriage(SuiteEvent item)
    {
        if (item.Id.Length > 0 && _triage.TryGetValue(item.Id, out var state))
        {
            item.Status = state.Status ?? "new";
            item.TriagedAt = state.At;
            item.TriageNote = state.Note ?? "";
        }
        else if (string.IsNullOrEmpty(item.Status))
        {
            item.Status = "new";
        }
    }

    /// <summary>
    /// Record an event. <paramref name="persist"/> false keeps it in memory only.
    /// </summary>
    /// <remarks>
    /// Clean scans are not persisted: findings.ndjson is an alert log, and
    /// writing a line per clean file would bury the alerts and grow the log by
    /// the size of the watched tree on every sweep.
    /// </remarks>
    public SuiteEvent Add(SuiteEvent item, bool persist = true)
    {
        if (string.IsNullOrEmpty(item.Id)) item.Id = NewId();
        if (string.IsNullOrEmpty(item.Timestamp)) item.Timestamp = NowIso();
        if (string.IsNullOrEmpty(item.Status)) item.Status = "new";
        if (item.Epoch == 0) item.Epoch = NowEpoch();

        lock (_gate)
        {
            if (persist)
            {
                try
                {
                    File.AppendAllText(Path,
                        JsonSerializer.Serialize(item, SuiteJson.Options) + "\n");
                }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
                {
                    _warn("[-] Could not persist finding: " + exc.Message);
                }
            }
            Append(item);
            Count(item);
            Publish(item);
        }
        return item;
    }

    /// <summary>
    /// Push to live subscribers.
    /// </summary>
    /// <remarks>
    /// The channels drop the oldest item when a reader falls behind, so one slow
    /// dashboard tab cannot block a scan or wedge the store. The Python build
    /// dropped the <em>subscriber</em> on a full queue, which silently killed
    /// the stream for a client that had only paused; here the client misses a
    /// few events and recovers on its next refresh, and a genuinely dead client
    /// is removed by the stream handler when its socket write fails.
    /// </remarks>
    private void Publish(SuiteEvent item)
    {
        foreach (var subscriber in _subscribers)
        {
            if (subscriber.Channel.Writer.TryWrite(item)) continue;

            // The reader is too far behind to keep up. Record it rather than
            // discarding the event quietly: a dashboard that has missed
            // findings while still showing a live dot and a ticking uptime is
            // worse than one that reconnects.
            subscriber.MarkOverflowed();
        }
    }

    public SuiteEvent? SetStatus(string eventId, string status, string note = "")
    {
        lock (_gate)
        {
            var target = _events.FirstOrDefault(e => e.Id == eventId);

            // A finding that has scrolled out of the ring buffer is still a
            // real finding. Fall back to the log so triage does not 404 on
            // anything older than the memory window; the state is recorded
            // either way, and ApplyTriage reattaches it on the next load.
            var inMemory = target is not null;
            target ??= FindOnDisk(eventId);
            if (target is null) return null;

            target.Status = status;
            target.TriagedAt = NowIso();
            target.TriageNote = note;
            _triage[eventId] = new TriageState
            {
                Status = status,
                At = target.TriagedAt,
                Note = note,
            };
            try
            {
                File.WriteAllText(TriagePath,
                    JsonSerializer.Serialize(_triage, SuiteJson.Pretty));
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                _warn("[-] Could not persist triage state: " + exc.Message);
            }

            var result = target.Clone();
            if (!inMemory) result.SetExtra("outside_memory_window", true);
            return result;
        }
    }

    /// <summary>
    /// Clear detection noise from the dashboard, keeping the audit trail.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Remediation records are deliberately not cleared. The findings log is the
    /// only evidence of what the tool deleted and what it refused to delete, and
    /// truncating it would destroy that. Clearing is a dashboard convenience; it
    /// must not become a way to erase the history of destructive actions.
    /// </para>
    /// <para>
    /// The backup is unconditional for the same reason, which is why this method
    /// takes no parameter to switch it off.
    /// </para>
    /// </remarks>
    public ClearResult Clear()
    {
        lock (_gate)
        {
            var eventCount = _events.Count;
            var triageCount = _triage.Count;

            // Retention is read from the log, not from the ring buffer. Building
            // it from memory destroyed exactly what this method promises to
            // keep: a remediation record older than HistoryLimit events is not
            // in the buffer, so rewriting the file from the buffer erased it -
            // and the result reported a falsely low audit_retained without
            // complaint.
            List<SuiteEvent> kept;
            try
            {
                kept = RemediationRecordsOnDisk();
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                // Abort rather than truncate. A log we cannot read is a log we
                // cannot safely rewrite.
                _warn("[-] Refusing to clear: the findings log could not be read (" +
                      exc.Message + ")");
                return new ClearResult
                {
                    Cleared = false,
                    Events = eventCount,
                    Triage = triageCount,
                    Error = "the findings log could not be read, so nothing was cleared",
                };
            }

            var backupDir = "";
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var target = System.IO.Path.Combine(
                System.IO.Path.GetDirectoryName(Path) ?? ".", "log-backups", stamp);
            var hadFindings = File.Exists(Path);
            var hadTriage = File.Exists(TriagePath);
            try
            {
                Directory.CreateDirectory(target);
                if (hadFindings)
                    File.Copy(Path, System.IO.Path.Combine(target, System.IO.Path.GetFileName(Path)), true);
                if (hadTriage)
                    File.Copy(TriagePath, System.IO.Path.Combine(target, System.IO.Path.GetFileName(TriagePath)), true);
                backupDir = target;
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                _warn("[-] Refusing to clear: logs could not be backed up (" + exc.Message + ")");
                return new ClearResult
                {
                    Cleared = false,
                    Events = eventCount,
                    Triage = triageCount,
                    Error = "the backup failed, so nothing was cleared",
                };
            }

            var findingsStaging = Path + ".clearing";
            var triageStaging = TriagePath + ".clearing";
            try
            {
                // Prepare both replacement files before touching either live
                // file. If the second rename fails after the first succeeds,
                // restore both originals from the unconditional backup.
                File.WriteAllText(findingsStaging, string.Concat(
                    kept.Select(e => JsonSerializer.Serialize(e, SuiteJson.Options) + "\n")));
                File.WriteAllText(triageStaging, "{}");
                File.Move(findingsStaging, Path, overwrite: true);
                File.Move(triageStaging, TriagePath, overwrite: true);
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                var rollbackError = "";
                try
                {
                    var backedFindings = System.IO.Path.Combine(
                        target, System.IO.Path.GetFileName(Path));
                    var backedTriage = System.IO.Path.Combine(
                        target, System.IO.Path.GetFileName(TriagePath));

                    if (hadFindings) File.Copy(backedFindings, Path, true);
                    else if (File.Exists(Path)) File.Delete(Path);

                    if (hadTriage) File.Copy(backedTriage, TriagePath, true);
                    else if (File.Exists(TriagePath)) File.Delete(TriagePath);
                }
                catch (Exception rollback) when (rollback is IOException or UnauthorizedAccessException)
                {
                    rollbackError = "; rollback also failed: " + rollback.Message;
                }
                finally
                {
                    try { if (File.Exists(findingsStaging)) File.Delete(findingsStaging); }
                    catch (Exception cleanup) when (cleanup is IOException or UnauthorizedAccessException) { }
                    try { if (File.Exists(triageStaging)) File.Delete(triageStaging); }
                    catch (Exception cleanup) when (cleanup is IOException or UnauthorizedAccessException) { }
                }

                _warn("[-] Refusing to clear: replacement failed (" + exc.Message + rollbackError + ")");
                return new ClearResult
                {
                    Cleared = false,
                    Events = eventCount,
                    Triage = triageCount,
                    AuditRetained = kept.Count,
                    BackupDir = backupDir,
                    Error = "the replacement failed, so the clear was rolled back" + rollbackError,
                };
            }

            // Memory changes only after both durable files were replaced.
            _events.Clear();
            _triage.Clear();
            _counters.Clear();
            foreach (var item in kept)
            {
                Append(item);
                Count(item);
            }

            return new ClearResult
            {
                Cleared = true,
                Events = eventCount,
                Triage = triageCount,
                AuditRetained = kept.Count,
                BackupDir = backupDir,
            };
        }
    }

    // ------------------------------------------------------------------ read
    /// <summary>Newest first, filtered. "all" and null both mean no filter.</summary>
    public List<SuiteEvent> Events(int limit = 200, string? severity = null,
                                   string? eventType = null, string? status = null,
                                   string? search = null)
    {
        List<SuiteEvent> snapshot;
        lock (_gate) snapshot = [.. _events];

        var needle = (search ?? "").Trim();
        var results = new List<SuiteEvent>(Math.Min(limit, 256));

        for (var i = snapshot.Count - 1; i >= 0 && results.Count < limit; i--)
        {
            var item = snapshot[i];
            if (Filtered(severity) && !Matches(item.Severity, severity)) continue;
            if (Filtered(eventType) && !Matches(item.EventType, eventType)) continue;
            if (Filtered(status) && !Matches(item.Status.Length == 0 ? "new" : item.Status, status)) continue;
            if (needle.Length > 0 && !ContainsText(item, needle)) continue;
            results.Add(item);
        }
        return results;

        static bool Filtered(string? value) =>
            !string.IsNullOrEmpty(value) && value != "all";

        static bool Matches(string? actual, string? wanted) =>
            string.Equals(actual, wanted, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Free-text search across the whole serialised event, as the dashboard's
    /// search box implies.
    /// </summary>
    private static bool ContainsText(SuiteEvent item, string needle)
    {
        try
        {
            return JsonSerializer.Serialize(item, SuiteJson.Options)
                .Contains(needle, StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public SuiteEvent? Find(string eventId, int limit = 5000)
    {
        lock (_gate) return _events.FirstOrDefault(e => e.Id == eventId);
    }

    public StoreStats Stats()
    {
        List<SuiteEvent> snapshot;
        long scanned;
        lock (_gate)
        {
            snapshot = [.. _events];
            scanned = _counters.GetValueOrDefault("files_scanned");
        }

        var bySeverity = Severity.All.ToDictionary(name => name, _ => 0);
        var byRule = new Dictionary<string, int>(StringComparer.Ordinal);
        int open = 0, matches = 0, errors = 0, cleanScans = 0;

        foreach (var item in snapshot)
        {
            switch (item.EventType)
            {
                case SuiteEvent.TypeScan:
                    cleanScans++;
                    break;
                case SuiteEvent.TypeMatch:
                    matches++;
                    var sev = Severity.Normalise(item.Severity);
                    bySeverity[sev] = bySeverity.GetValueOrDefault(sev) + 1;
                    if (item.Status is "new" or "") open++;
                    foreach (var match in item.Matches ?? [])
                    {
                        var name = match.Rule.Length > 0 ? match.Rule : "?";
                        byRule[name] = byRule.GetValueOrDefault(name) + 1;
                    }
                    break;
                case SuiteEvent.TypeError:
                    errors++;
                    break;
            }
        }

        long logSize = 0;
        try { if (File.Exists(Path)) logSize = new FileInfo(Path).Length; }
        catch (IOException) { /* size is cosmetic */ }

        return new StoreStats
        {
            FilesScanned = scanned,
            CleanScans = cleanScans,
            Matches = matches,
            OpenAlerts = open,
            Errors = errors,
            BySeverity = bySeverity,
            TopRules = byRule.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key)
                             .Take(6).Select(kv => new RuleCount(kv.Key, kv.Value)).ToList(),
            Timeline = Timeline(snapshot),
            UptimeSeconds = (long)_uptime.Elapsed.TotalSeconds,
            LogPath = Path,
            LogSize = logSize,
        };
    }

    /// <summary>Match counts bucketed across the trailing hour, oldest bucket first.</summary>
    private static List<TimelineBucket> Timeline(List<SuiteEvent> items, int buckets = 24, int minutes = 60)
    {
        var span = minutes * 60.0 / buckets;
        var now = NowEpoch();
        var counts = new int[buckets];

        foreach (var item in items)
        {
            if (item.EventType != SuiteEvent.TypeMatch) continue;

            var stamp = item.Epoch;
            if (stamp == 0)
            {
                // Pre-_epoch records, and anything hand-edited.
                if (!DateTimeOffset.TryParse(item.Timestamp, out var parsed)) continue;
                stamp = parsed.ToUnixTimeMilliseconds() / 1000.0;
            }

            var age = now - stamp;
            if (age < 0 || age > minutes * 60) continue;

            var index = buckets - 1 - (int)(age / span);
            if (index >= 0 && index < buckets) counts[index]++;
        }

        return [.. counts.Select((count, i) => new TimelineBucket(
            (int)((buckets - 1 - i) * (minutes / (double)buckets)), count))];
    }

    // --------------------------------------------------------------- pub/sub
    public Subscription Subscribe()
    {
        // Wait mode, driven by TryWrite: the write fails when the buffer is
        // full instead of silently dropping, which is the only way the store
        // can tell that a reader has fallen behind.
        var subscription = new Subscription(Channel.CreateBounded<SuiteEvent>(
            new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
            }));

        lock (_gate) _subscribers.Add(subscription);
        return subscription;
    }

    public void Unsubscribe(Subscription subscription)
    {
        lock (_gate) _subscribers.Remove(subscription);
        subscription.Channel.Writer.TryComplete();
    }

    /// <summary>Push a transient notice to live clients without storing it.</summary>
    public void Broadcast(SuiteEvent item)
    {
        if (string.IsNullOrEmpty(item.Timestamp)) item.Timestamp = NowIso();
        lock (_gate) Publish(item);
    }

    public void Broadcast(string message) => Broadcast(new SuiteEvent
    {
        EventType = SuiteEvent.TypeMonitor,
        Timestamp = NowIso(),
        Message = message,
    });

    public int SubscriberCount
    {
        get { lock (_gate) return _subscribers.Count; }
    }
}
