using SecuritySuite.Monitoring;
using SecuritySuite.Storage;

namespace SecuritySuite.Jobs;

/// <summary>
/// Bounded background scans, independent of the monitor's settle and
/// extension rules.
/// </summary>
/// <remarks>
/// <para>
/// One worker and at most <see cref="HistoryLimit"/> job snapshots per owner.
/// Traversal holds at most <see cref="MaxOpenDirectories"/> directory
/// enumerators and keeps no file list or per-file history, so scanning a large
/// tree costs a bounded amount of memory. Deeper subtrees are reported as
/// <c>depth_limit</c> skips rather than silently omitted.
/// </para>
/// <para>
/// Scanning never modifies watch paths, remediation roots or the monitor's
/// baselines. An explicit scan is a read: it must not change what the monitor
/// considers already-seen.
/// </para>
/// </remarks>
public sealed class ScanJobs(DirectoryMonitor monitor)
{
    private const int HistoryLimit = 20;

    /// <summary>
    /// Directory enumerators held open at once.
    /// </summary>
    /// <remarks>
    /// This bounds both handle use and recursion depth. A tree deeper than this
    /// is unusual enough that reporting the pruning is more useful than
    /// following it, and a reparse-point loop that slipped past the link check
    /// would otherwise run until the process ran out of handles.
    /// </remarks>
    private const int MaxOpenDirectories = 128;

    private readonly Lock _gate = new();
    private readonly LinkedList<ScanJob> _jobs = [];

    private string? _activeId;
    private CancellationTokenSource _cancel = new();
    private Thread? _worker;

    /// <summary>Fixed local drives, as scan roots the dashboard can offer.</summary>
    public List<DriveEntry> Drives()
    {
        if (!OperatingSystem.IsWindows())
            return [new DriveEntry("/", "Filesystem (/)")];

        var drives = new List<DriveEntry>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType != DriveType.Fixed) continue;
                drives.Add(new DriveEntry(drive.Name,
                    "Local disk (" + drive.Name.TrimEnd('\\') + ")"));
            }
            catch (IOException) { /* a drive that vanished between calls */ }
        }
        return drives;
    }

    public object Start(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
            return new ScanJobError { Error = "A non-empty filesystem path is required" };

        string target;
        try
        {
            var expanded = path.StartsWith('~')
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                               path[1..].TrimStart('/', '\\'))
                : path;
            target = Path.GetFullPath(expanded);
        }
        catch (Exception exc) when (exc is ArgumentException or NotSupportedException
                                        or PathTooLongException or IOException)
        {
            return new ScanJobError { Error = "Invalid path: " + exc.Message };
        }

        ScanJob job;
        CancellationTokenSource cancel;
        lock (_gate)
        {
            if (_activeId is not null)
                return new ScanJobError { Error = "A scan job is already active", JobId = _activeId };

            job = new ScanJob { Id = Guid.NewGuid().ToString("N"), Path = target };
            _jobs.AddFirst(job);
            while (_jobs.Count > HistoryLimit) _jobs.RemoveLast();
            _activeId = job.Id;

            _cancel.Dispose();
            cancel = _cancel = new CancellationTokenSource();

            try
            {
                _worker = new Thread(() => Run(job, cancel.Token))
                {
                    Name = "securitysuite-scan-job",
                    IsBackground = true,
                };
                _worker.Start();
            }
            catch (Exception exc) when (exc is OutOfMemoryException or ThreadStateException)
            {
                job.State = ScanJobState.Error;
                job.Error = job.LastError = exc.Message;
                job.Errors = 1;
                job.FinishedAt = EventStore.NowIso();
                _activeId = null;
            }
            return job.Copy();
        }
    }

    public List<ScanJob> Status()
    {
        lock (_gate) return [.. _jobs.Select(j => j.Copy())];
    }

    public object Cancel(string jobId)
    {
        lock (_gate)
        {
            var job = _jobs.FirstOrDefault(j => j.Id == jobId);
            if (job is null) return new ScanJobError { Error = "Unknown scan job" };

            if (job.Id == _activeId)
            {
                job.CancellationRequested = true;
                _cancel.Cancel();
            }
            return job.Copy();
        }
    }

    /// <summary>Wait for the active job to finish. Used by the synchronous CLI path.</summary>
    public ScanJob? Wait(string jobId, CancellationToken token = default)
    {
        var worker = _worker;
        while (worker is not null && worker.IsAlive)
        {
            if (token.IsCancellationRequested) Cancel(jobId);
            worker.Join(100);
        }
        lock (_gate) return _jobs.FirstOrDefault(j => j.Id == jobId)?.Copy();
    }

    private void Run(ScanJob job, CancellationToken token)
    {
        var failed = false;
        try
        {
            lock (_gate)
            {
                if (!token.IsCancellationRequested)
                {
                    job.State = ScanJobState.Running;
                    job.StartedAt = EventStore.NowIso();
                }
            }
            if (!token.IsCancellationRequested) Walk(job, token);
        }
        catch (Exception exc)
        {
            // The walker rethrows only when the scan root itself is
            // unreadable, which must not be reported as a completed empty scan.
            failed = true;
            lock (_gate)
            {
                job.Error = job.LastError = exc.Message;
                job.Errors++;
            }
        }
        finally
        {
            lock (_gate)
            {
                job.State = token.IsCancellationRequested ? ScanJobState.Cancelled
                    : failed ? ScanJobState.Error
                    : ScanJobState.Completed;
                job.CurrentPath = null;
                job.FinishedAt = EventStore.NowIso();
                _activeId = null;
            }
        }
    }

    /// <summary>
    /// Paths an explicit scan must not touch.
    /// </summary>
    /// <remarks>
    /// The same self-scan problem the monitor has: the findings log contains
    /// the strings that tripped the rules, so scanning it alerts on itself, and
    /// a quarantined file still contains whatever got it quarantined. Both the
    /// configured path and its link-resolved form are excluded, because either
    /// spelling can be what the walker arrives at.
    /// </remarks>
    private (HashSet<string> Files, List<string> Directories) Exclusions()
    {
        var cfg = monitor.Config;
        var files = new HashSet<string>(StringComparer.Ordinal);
        var directories = new List<string>();

        void AddFile(string? value)
        {
            if (string.IsNullOrEmpty(value)) return;
            files.Add(PathUtil.Norm(value));
        }

        void AddDir(string? value)
        {
            if (string.IsNullOrEmpty(value)) return;
            directories.Add(PathUtil.Norm(value));
        }

        AddFile(cfg.FindingsLog);
        AddFile(cfg.TriageFile);
        AddFile(cfg.RemediationFile);

        // Workbench sidecars live beside the triage file.
        var triageDir = Path.GetDirectoryName(cfg.TriageFile);
        if (!string.IsNullOrEmpty(triageDir))
        {
            foreach (var name in (string[])["playbooks.json", "response-policy.json", "blocked-domains.json"])
                AddFile(Path.Combine(triageDir, name));
        }

        AddDir(cfg.QuarantineDir);
        AddDir(cfg.NvdCacheDir);
        AddDir(cfg.OsvCacheDir);
        AddDir(cfg.VtCacheDir);
        AddDir(cfg.GuidanceCacheDir);

        var findingsDir = Path.GetDirectoryName(cfg.FindingsLog);
        if (!string.IsNullOrEmpty(findingsDir)) AddDir(Path.Combine(findingsDir, "log-backups"));

        return (files, directories);
    }

    private void Skip(ScanJob job, string reason, Exception? exc = null)
    {
        lock (_gate)
        {
            job.Skipped++;
            job.SkipReasons[reason] = job.SkipReasons.GetValueOrDefault(reason) + 1;
            if (exc is not null)
            {
                job.Errors++;
                job.LastError = exc.Message;
            }
        }
    }

    /// <summary>
    /// True for a symlink, a junction, or any other reparse point.
    /// </summary>
    /// <remarks>
    /// Links are never followed. Following them turns a bounded tree walk into
    /// an unbounded one and lets a link inside the scan root pull in anything
    /// on the volume, which is the same escape the remediation rails refuse.
    /// </remarks>
    private static bool IsLink(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException
                                        or ArgumentException)
        {
            return false;
        }
    }

    private void Walk(ScanJob job, CancellationToken token)
    {
        var (excludedFiles, excludedDirs) = Exclusions();
        var root = job.Path;

        // A root that is not there at all is a failed scan, not a successful
        // empty one. Without this the walk finds nothing to enumerate, falls
        // straight out of the loop and reports "completed", so a typo in a scan
        // path looks like a clean result.
        if (!Directory.Exists(root) && !File.Exists(root))
        {
            Skip(job, "unavailable");
            lock (_gate) job.Error = root + " does not exist";
            throw new DirectoryNotFoundException(job.Error);
        }

        // Check the ancestors too: a caller can ask for link/child.txt directly,
        // where the link is above the requested path rather than at it.
        for (var parent = Directory.GetParent(root); parent is not null; parent = parent.Parent)
        {
            if (token.IsCancellationRequested) return;
            if (IsLink(parent.FullName))
            {
                Skip(job, "link");
                return;
            }
        }

        var stack = new List<(string Directory, IEnumerator<string> Entries)>();
        string? path = root;
        try
        {
            while (!token.IsCancellationRequested)
            {
                if (path is null)
                {
                    if (stack.Count == 0) break;
                    var (directory, entries) = stack[^1];
                    try
                    {
                        if (!entries.MoveNext())
                        {
                            entries.Dispose();
                            stack.RemoveAt(stack.Count - 1);
                            continue;
                        }
                        path = entries.Current;
                    }
                    catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
                    {
                        var isRoot = directory == root;
                        Skip(job, "unavailable", isRoot ? null : exc);
                        entries.Dispose();
                        stack.RemoveAt(stack.Count - 1);
                        if (isRoot)
                        {
                            lock (_gate) job.Error = exc.Message;
                            throw;
                        }
                        continue;
                    }
                }

                if (token.IsCancellationRequested) break;
                lock (_gate) job.CurrentPath = path;

                var normalised = PathUtil.Norm(path);
                if (excludedFiles.Contains(normalised) ||
                    excludedDirs.Any(d => PathUtil.IsWithin(normalised, d)))
                {
                    Skip(job, "excluded");
                    path = null;
                    continue;
                }

                try
                {
                    if (IsLink(path))
                    {
                        Skip(job, "link");
                    }
                    else if (Directory.Exists(path))
                    {
                        if (stack.Count >= MaxOpenDirectories)
                        {
                            Skip(job, "depth_limit");
                        }
                        else
                        {
                            stack.Add((path, Directory.EnumerateFileSystemEntries(path).GetEnumerator()));
                        }
                    }
                    else if (File.Exists(path))
                    {
                        if (!token.IsCancellationRequested) ScanOne(job, path);
                    }
                    else
                    {
                        // A device, a pipe, or something that vanished.
                        Skip(job, "special_file");
                    }
                }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
                {
                    if (path == root)
                    {
                        Skip(job, "unavailable");
                        throw;
                    }
                    Skip(job, "unavailable", exc);
                }
                path = null;
            }
        }
        finally
        {
            for (var i = stack.Count - 1; i >= 0; i--) stack[i].Entries.Dispose();
        }
    }

    private void ScanOne(ScanJob job, string path)
    {
        SuiteEvent entry;
        try
        {
            entry = monitor.ScanAndRecord(path, trigger: "job");
        }
        catch (Exception exc)
        {
            // The monitor already converts the expected failures into events;
            // anything reaching here is unexpected and belongs on this job
            // rather than killing the walk.
            lock (_gate)
            {
                job.Errors++;
                job.LastError = exc.Message;
            }
            return;
        }

        if (entry.Skipped is { } reason)
        {
            if (reason.Contains("unavailable", StringComparison.OrdinalIgnoreCase))
                Skip(job, "unavailable", new IOException(reason));
            else
                Skip(job, reason.Contains("larger than", StringComparison.OrdinalIgnoreCase) ? "size" : "engine");
            return;
        }

        if (entry.EventType == SuiteEvent.TypeError)
        {
            lock (_gate)
            {
                job.Errors++;
                job.LastError = entry.Message ?? "Scan failed";
            }
            return;
        }

        lock (_gate)
        {
            job.Scanned++;
            if (entry.EventType == SuiteEvent.TypeMatch) job.Matches++;
        }
    }
}
