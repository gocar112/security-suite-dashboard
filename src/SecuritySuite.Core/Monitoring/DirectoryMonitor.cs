using System.Text.Json;
using System.Text.Json.Serialization;
using SecuritySuite.Configuration;
using SecuritySuite.Detection;
using SecuritySuite.Jobs;
using SecuritySuite.Storage;
using SecuritySuite.Telemetry;

namespace SecuritySuite.Monitoring;

/// <summary>
/// Polls the watched paths, waits for each file to stop changing before
/// scanning it, and correlates every hit with authentication telemetry from
/// the same time window.
/// </summary>
/// <remarks>
/// Polling rather than <see cref="FileSystemWatcher"/> on purpose. A change
/// notification arrives while the file is still being written, so a watcher
/// would need the same settle logic bolted on top, and it silently drops
/// events when its buffer overflows under load — exactly when a scanner must
/// not miss files.
/// </remarks>
public sealed class DirectoryMonitor
{
    private readonly YaraEngine _engine;
    private readonly EventStore _store;
    private readonly AuthTelemetry _telemetry;
    private readonly Action<string> _report;

    /// <summary>
    /// Files whose contents would alert on themselves.
    /// </summary>
    /// <remarks>
    /// The findings log records the strings that tripped each rule, so scanning
    /// it matches those rules again, writes that match to the same file, and
    /// alerts forever. The triage and remediation sidecars carry the same
    /// strings for the same reason.
    /// </remarks>
    private readonly HashSet<string> _selfPaths;

    /// <summary>
    /// Directories excluded wholesale.
    /// </summary>
    /// <remarks>
    /// A quarantined file still contains whatever tripped the rule. If the
    /// quarantine sits inside a watched tree it is re-detected on every sweep:
    /// the findings-log feedback loop again, with a file somebody deliberately
    /// set aside.
    /// </remarks>
    private readonly List<string> _excludedDirs;

    /// <summary>Path to the (mtime, size) signature at the moment it was last scanned.</summary>
    private readonly Dictionary<string, FileSignature> _scanned = new(StringComparer.Ordinal);

    /// <summary>Path to its signature and when it was first seen, for files still settling.</summary>
    private readonly Dictionary<string, PendingFile> _pending = new(StringComparer.Ordinal);

    private readonly Lock _gate = new();
    private readonly ManualResetEventSlim _wake = new(false);
    private CancellationTokenSource? _stop;
    private Thread? _thread;
    private volatile bool _paused;
    private ScanJobs? _jobs;

    public SuiteConfig Config { get; }
    public Remediation.Remediator? Remediator { get; set; }

    public long ScannedCount { get; private set; }
    public string? LastSweep { get; private set; }
    public string? LastError { get; private set; }

    public DirectoryMonitor(SuiteConfig config, YaraEngine engine, EventStore store,
                            AuthTelemetry telemetry, Action<string>? report = null)
    {
        Config = config;
        _engine = engine;
        _store = store;
        _telemetry = telemetry;

        // Diagnostics go to stderr so --scan stays pipeable: the JSON a caller
        // wants to pipe shares stdout with nothing else.
        _report = report ?? (message => Console.Error.WriteLine(message));

        _selfPaths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in (string?[])[config.FindingsLog, config.TriageFile, config.RemediationFile])
        {
            if (!string.IsNullOrEmpty(path)) _selfPaths.Add(PathUtil.Norm(path));
        }

        _excludedDirs = [];
        if (!string.IsNullOrEmpty(config.QuarantineDir))
            _excludedDirs.Add(PathUtil.Norm(config.QuarantineDir));
    }

    /// <summary>The scan-job owner, created on first use.</summary>
    public ScanJobs Jobs
    {
        get
        {
            lock (_gate) return _jobs ??= new ScanJobs(this);
        }
    }

    // --------------------------------------------------------------- control
    public void Start()
    {
        lock (_gate)
        {
            if (_thread is not null) return;
            _stop = new CancellationTokenSource();
            var token = _stop.Token;
            _thread = new Thread(() => Loop(token))
            {
                Name = "securitysuite-monitor",
                IsBackground = true,
            };
            _thread.Start();
        }
    }

    public void Stop()
    {
        Thread? thread;
        lock (_gate)
        {
            _stop?.Cancel();
            thread = _thread;
            _thread = null;
        }
        _wake.Set();
        thread?.Join(TimeSpan.FromSeconds(5));
    }

    public void Pause() => _paused = true;

    public void Resume()
    {
        _paused = false;
        _wake.Set();
    }

    public bool Paused => _paused;

    public bool Running
    {
        get { lock (_gate) return _thread is not null && _stop?.IsCancellationRequested == false; }
    }

    public MonitorStatus Status()
    {
        lock (_gate)
        {
            return new MonitorStatus
            {
                Running = _thread is not null && _stop?.IsCancellationRequested == false,
                Paused = _paused,
                WatchPaths = [.. Config.WatchPaths],
                Recursive = Config.Recursive,
                PollInterval = Config.PollInterval,
                SettleSeconds = Config.SettleSeconds,
                TrackedFiles = _scanned.Count,
                PendingFiles = _pending.Count,
                ScannedCount = ScannedCount,
                LastSweep = LastSweep,
                LastError = LastError,
            };
        }
    }

    // ------------------------------------------------------------------ loop
    private void Loop(CancellationToken token)
    {
        if (!Config.ScanExistingOnStart)
        {
            // Baseline what is already there so only new work raises an alert.
            foreach (var (path, signature) in Enumerate())
            {
                if (token.IsCancellationRequested) return;
                lock (_gate) _scanned[path] = signature;
            }
        }

        _store.Broadcast("Monitoring " + string.Join(", ", Config.WatchPaths));

        var interval = TimeSpan.FromSeconds(Math.Max(0.1, Config.PollInterval));
        while (!token.IsCancellationRequested)
        {
            if (!_paused)
            {
                try
                {
                    Sweep(token);
                    LastError = null;
                }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
                {
                    // Keep the monitor alive through a bad path: a watch root on
                    // a disconnected share must not stop the other roots.
                    LastError = exc.Message;
                }
            }
            _wake.Wait(interval, token);
            _wake.Reset();
        }
    }

    /// <summary>Every candidate file under the watch paths, with its signature.</summary>
    private IEnumerable<(string Path, FileSignature Signature)> Enumerate()
    {
        var ignore = Config.IgnoreSuffixes
            .Select(s => s.StartsWith('.') ? s : "." + s)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var root in Config.WatchPaths)
        {
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFiles(root, "*",
                    Config.Recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var entry in Guarded(entries))
            {
                if (ignore.Contains(Path.GetExtension(entry))) continue;

                var resolved = PathUtil.Norm(entry);
                if (_selfPaths.Contains(resolved)) continue;
                if (_excludedDirs.Any(d => PathUtil.IsWithin(resolved, d))) continue;

                FileSignature signature;
                try
                {
                    var info = new FileInfo(entry);
                    if (!info.Exists) continue;
                    signature = new FileSignature(info.LastWriteTimeUtc.Ticks, info.Length);
                }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
                {
                    continue;
                }
                yield return (entry, signature);
            }
        }
    }

    /// <summary>
    /// Enumerate lazily without letting one unreadable subdirectory end the walk.
    /// </summary>
    /// <remarks>
    /// <see cref="Directory.EnumerateFiles(string,string,SearchOption)"/> throws
    /// from <c>MoveNext</c>, part-way through iteration, when it reaches a
    /// directory it cannot read. A <c>foreach</c> over it therefore abandons
    /// every remaining file. Driving the enumerator by hand lets the walk
    /// continue past the failure.
    /// </remarks>
    private static IEnumerable<string> Guarded(IEnumerable<string> entries)
    {
        using var enumerator = entries.GetEnumerator();
        while (true)
        {
            string current;
            try
            {
                if (!enumerator.MoveNext()) break;
                current = enumerator.Current;
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                continue;
            }
            yield return current;
        }
    }

    /// <summary>
    /// One pass: scan what is new and settled, forget what is gone.
    /// </summary>
    /// <remarks>
    /// A file must present the same (mtime, size) signature twice, at least
    /// <c>settle_seconds</c> apart, before it is scanned. Without that a large
    /// upload is scanned while it is still being written, and the scan sees a
    /// truncated file: the most common way for a watcher to miss a detection
    /// is to look too early.
    /// </remarks>
    private void Sweep(CancellationToken token)
    {
        var now = DateTimeOffset.UtcNow;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var settle = TimeSpan.FromSeconds(Math.Max(0, Config.SettleSeconds));
        var ready = new List<string>();

        foreach (var (path, signature) in Enumerate())
        {
            if (token.IsCancellationRequested) return;
            seen.Add(path);

            lock (_gate)
            {
                if (_scanned.TryGetValue(path, out var last) && last == signature) continue;

                if (!_pending.TryGetValue(path, out var pending) || pending.Signature != signature)
                {
                    // New, or changed since we last looked: restart the timer.
                    _pending[path] = new PendingFile(signature, now);
                    continue;
                }
                if (now - pending.FirstSeen < settle) continue;

                _pending.Remove(path);
                _scanned[path] = signature;
            }
            ready.Add(path);
        }

        // Scan outside the lock: a scan can take a while, and holding the lock
        // would block the status endpoint and every other sweep participant.
        foreach (var path in ready)
        {
            if (token.IsCancellationRequested) return;
            ScanAndRecord(path, trigger: "monitor");
        }

        lock (_gate)
        {
            // Forget what disappeared, so a re-upload of the same name is
            // scanned again rather than matching a stale signature.
            foreach (var gone in _scanned.Keys.Where(p => !seen.Contains(p)).ToList())
                _scanned.Remove(gone);
            foreach (var gone in _pending.Keys.Where(p => !seen.Contains(p)).ToList())
                _pending.Remove(gone);
            LastSweep = EventStore.NowIso();
        }
    }

    // -------------------------------------------------------------- scanning
    /// <summary>Scan one file and record the outcome. Returns the stored event.</summary>
    public SuiteEvent ScanAndRecord(string path, string trigger = "manual")
    {
        ScanOutcome outcome;
        try
        {
            outcome = _engine.ScanFile(path);
        }
        catch (Exception exc) when (exc is FileNotFoundException or DirectoryNotFoundException
                                        or UnauthorizedAccessException or IOException)
        {
            // Normal on a live endpoint: antivirus quarantined the file, or it
            // was moved or locked between the sweep and the scan. Not an error,
            // and not persisted, or a busy host fills the log with them.
            return _store.Add(new SuiteEvent
            {
                EventType = SuiteEvent.TypeScan,
                FilePath = path,
                FileName = Path.GetFileName(path),
                Skipped = "unavailable at scan time (" + exc.GetType().Name + ")",
                Trigger = trigger,
            }, persist: false);
        }
        catch (Exception exc)
        {
            return _store.Add(new SuiteEvent
            {
                EventType = SuiteEvent.TypeError,
                Severity = Severity.Low,
                FilePath = path,
                FileName = Path.GetFileName(path),
                Message = "Scan failed: " + exc.Message,
                Trigger = trigger,
            });
        }

        if (outcome.Skipped is not null)
        {
            return _store.Add(new SuiteEvent
            {
                EventType = SuiteEvent.TypeScan,
                FilePath = outcome.FilePath,
                FileName = Path.GetFileName(path),
                FileSize = outcome.FileSize,
                Skipped = outcome.Skipped,
                Trigger = trigger,
            }, persist: false);
        }

        lock (_gate) ScannedCount++;

        var stored = ToEvent(outcome, trigger);
        if (!outcome.Hit)
        {
            // Clean scans stay in memory; the findings log remains an alert log.
            return _store.Add(stored, persist: false);
        }

        var telemetry = _telemetry.Recent();
        stored.EventType = SuiteEvent.TypeMatch;
        stored.Verdict = "rule_match";
        stored.RuleNames = outcome.Matches.Select(m => m.Rule).ToList();
        stored.Telemetry = JsonSerializer.SerializeToNode(telemetry, SuiteJson.Options);
        stored.CorrelatedAuthFailures = telemetry.Count;

        var saved = _store.Add(stored);

        // The finding is stored first so the action has an id to reference and
        // an audit trail to append to.
        if (Remediator is not null)
        {
            try
            {
                var auto = Remediator.ConsiderAuto(saved);
                if (auto is { Ok: true })
                    _report("[!] AUTO-REMEDIATE " + auto.Outcome + " " + saved.FilePath);
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                _report("[-] Auto-remediation failed: " + exc.Message);
            }
        }

        _report("[!] ALERT " + (saved.Severity ?? "?").ToUpperInvariant() + " " +
                string.Join(", ", saved.RuleNames ?? []) + " in " + outcome.FilePath);
        return saved;
    }

    private static SuiteEvent ToEvent(ScanOutcome outcome, string trigger)
    {
        var entry = new SuiteEvent
        {
            EventType = SuiteEvent.TypeScan,
            Verdict = "clean",
            Trigger = trigger,
            FilePath = outcome.FilePath,
            FileName = outcome.FileName,
            FileSize = outcome.FileSize,
            Sha256 = outcome.Sha256,
            ScanMs = outcome.ScanMs,
            Severity = outcome.Severity,
            Matches = outcome.Matches.Count > 0 ? outcome.Matches : null,
        };
        entry.SetExtra("entropy", outcome.Entropy);
        if (outcome.Modified is not null) entry.SetExtra("modified", outcome.Modified);
        if (outcome.Hit) entry.SetExtra("iocs", outcome.Iocs);
        return entry;
    }

    /// <summary>Run a one-off scan of a tree and wait for it, for the CLI.</summary>
    public ScanJob? ScanPath(string target, CancellationToken token = default)
    {
        var started = Jobs.Start(target);
        if (started is ScanJobError error)
        {
            return new ScanJob
            {
                Path = target,
                State = ScanJobState.Error,
                Error = error.Error,
                Errors = 1,
                FinishedAt = EventStore.NowIso(),
            };
        }
        return Jobs.Wait(((ScanJob)started).Id, token);
    }
}

/// <summary>(mtime, size) at a point in time. Equality is how settling is detected.</summary>
public readonly record struct FileSignature(long WriteTicks, long Length);

internal readonly record struct PendingFile(FileSignature Signature, DateTimeOffset FirstSeen);

public sealed class MonitorStatus
{
    [JsonPropertyName("running")] public bool Running { get; set; }
    [JsonPropertyName("paused")] public bool Paused { get; set; }
    [JsonPropertyName("watch_paths")] public List<string> WatchPaths { get; set; } = [];
    [JsonPropertyName("recursive")] public bool Recursive { get; set; }
    [JsonPropertyName("poll_interval")] public double PollInterval { get; set; }
    [JsonPropertyName("settle_seconds")] public double SettleSeconds { get; set; }
    [JsonPropertyName("tracked_files")] public int TrackedFiles { get; set; }
    [JsonPropertyName("pending_files")] public int PendingFiles { get; set; }
    [JsonPropertyName("scanned_count")] public long ScannedCount { get; set; }
    [JsonPropertyName("last_sweep")] public string? LastSweep { get; set; }
    [JsonPropertyName("last_error")] public string? LastError { get; set; }
}
