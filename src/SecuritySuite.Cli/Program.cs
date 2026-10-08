using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using SecuritySuite.Configuration;
using SecuritySuite.Detection;
using SecuritySuite.Http;
using SecuritySuite.Intel;
using SecuritySuite.Jobs;
using SecuritySuite.Monitoring;
using SecuritySuite.Remediation;
using SecuritySuite.Storage;
using SecuritySuite.Telemetry;

namespace SecuritySuite.Cli;

internal static class Program
{
    private const string Banner = """

          ___  ___  ___ _   _ ___ ___ _______   __  ___ _   _ ___ _____ ___
         / __|| __|/ __| | | | _ \_ _|_   _\ \ / / / __| | | |_ _|_   _| __|
         \__ \| _|| (__| |_| |   /| |  | |  \ V /  \__ \ |_| || |  | | | _|
         |___/|___|\___|\___/|_|_\___| |_|   |_|   |___/\___/|___| |_| |___|

        """;

    /// <summary>
    /// Diagnostics go to stderr so <c>--scan</c> can be piped.
    /// </summary>
    /// <remarks>
    /// <c>--scan</c> advertises "print JSON, exit", but the banner and the
    /// status lines once shared stdout with it, so the output could not be
    /// parsed: <c>securitysuite --scan x | jq</c> choked on the ASCII art. Data
    /// on stdout, everything else on stderr, is what makes the documented
    /// behaviour true — and in dashboard mode the operator sees no difference,
    /// because stderr is still the terminal.
    /// </remarks>
    private static void Status(string message = "") => Console.Error.WriteLine(message);

    private static int Main(string[] rawArgs)
    {
        try
        {
            return Run(rawArgs);
        }
        catch (CliUsageException exc)
        {
            Status("[-] " + exc.Message);
            Status("");
            Status(CliOptions.Usage);
            return 2;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            Status("[-] " + exc.Message);
            return 1;
        }
    }

    private static int Run(string[] rawArgs)
    {
        var args = CliOptions.Parse(rawArgs);
        if (args.ShowHelp)
        {
            Console.WriteLine(CliOptions.Usage);
            return 0;
        }
        if (args.ShowVersion)
        {
            Console.WriteLine("securitysuite " + RouteTableVersion);
            return 0;
        }
        // Not disposed: Main still reports a failure after Run returns, and that
        // report belongs in the log too. AutoFlush means nothing is lost at exit.
        if (args.LogFile is { } logFile) RedirectToLog(logFile);

        if (args.InstallShortcut || args.RemoveShortcut) return Shortcut(args);

        var cfg = BuildConfig(args);

        using var engine = new YaraEngine(cfg.RulesDir, cfg.MaxFileBytes);
        var store = new EventStore(cfg.FindingsLog, cfg.TriageFile, cfg.HistoryLimit, Status);
        var telemetry = new AuthTelemetry(cfg.AuthLogPath, cfg.LookbackMinutes,
            cfg.TelemetryCacheSeconds, cfg.MaxTelemetryEvents);

        var nvd = new NvdClient(cfg.NvdCacheDir, cfg.NvdApiKey);
        var osv = new OsvClient(cfg.OsvCacheDir);
        var vt = new VirusTotalClient(cfg.VirustotalApiKey, cfg.VtCacheDir);
        var remediator = new Remediator(cfg, store, Status);
        var guidance = new GuidanceService(cfg.GuidanceCacheDir, nvd);

        var monitor = new DirectoryMonitor(cfg, engine, store, telemetry, Status)
        {
            Remediator = remediator,
        };

        PrintStartupReport(cfg, engine, telemetry, nvd);

        // --scan is a one-shot: scan, print JSON to stdout, exit.
        if (args.ScanTarget is { Length: > 0 } target) return ScanOnce(monitor, target);

        var ports = args.Port is not null
            ? [cfg.Port]
            : Enumerable.Range(cfg.Port, Math.Min(10, 65536 - cfg.Port)).ToList();

        // Reuse an existing dashboard rather than starting a second writer
        // against the same findings log. Skipped when the invocation overrides
        // what is watched, because then the running instance is not equivalent.
        if (!args.Headless && args.Watch.Count == 0 && args.RulesDir is null && !args.ScanExisting)
        {
            if (FindRunningInstance(cfg, ports) is { } existing)
            {
                Status("[*] Dashboard already running: " + existing);
                if (!args.NoBrowser) OpenBrowser(existing);
                return 0;
            }
        }

        // One monitor per workspace. The probe above only finds an instance on
        // a port we guessed; this catches one on any port, which is how the
        // same file ended up detected twice with an identical hash.
        using var workspace = WorkspaceLock.Acquire(cfg.FindingsLog);
        if (!workspace.Held)
        {
            Status("[-] Another Security Suite is already monitoring this workspace.");
            Status("    Findings log : " + cfg.FindingsLog);
            if (workspace.HeldBy is { } owner) Status("    Held by      : " + owner);
            Status("    Two monitors on one workspace scan every file twice and write");
            Status("    duplicate findings, so this one will not start. Stop the other,");
            Status("    or point this one at a different workspace with its own config.");
            return 1;
        }

        monitor.Start();
        Status("[*] Watching   : " + string.Join(", ", cfg.WatchPaths));
        Status("[*] Findings   : " + cfg.FindingsLog);

        SuiteContext? context = null;
        DashboardServer? server = null;

        if (!args.Headless)
        {
            context = new SuiteContext(cfg, engine, store, telemetry, monitor,
                nvd, osv, vt, remediator, guidance);

            Exception? bindError = null;
            foreach (var port in ports)
            {
                cfg.Port = port;
                try
                {
                    server = DashboardServer.Serve(context, Status);
                    break;
                }
                catch (ArgumentException exc)
                {
                    // A non-loopback bind is a configuration error, not a busy
                    // port: trying the next port would not help.
                    bindError = exc;
                    break;
                }
                catch (InvalidOperationException exc)
                {
                    bindError = exc;
                }
            }

            if (server is null)
            {
                Status("[-] Could not start dashboard: " + (bindError?.Message ?? "unknown error"));
                monitor.Stop();
                return 1;
            }

            Status("[*] Dashboard  : " + server.Url);
            if (!args.NoBrowser) OpenBrowser(server.Url);
        }

        Status("[*] Ctrl-C to stop.");
        Status();

        using var shutdown = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            // Handle it ourselves so the monitor and any running scan get to
            // stop cleanly instead of the process being torn down mid-write.
            eventArgs.Cancel = true;
            shutdown.Set();
        };
        shutdown.Wait();

        Status();
        Status("[*] Shutting down...");

        monitor.Stop();
        if (context is not null)
        {
            foreach (var job in context.Jobs.Status().Where(j => ScanJobState.IsActive(j.State)))
                context.Jobs.Cancel(job.Id);
            context.Inventory.Cancel();
        }
        server?.Dispose();
        return 0;
    }

    private static string RouteTableVersion => SuiteVersion.Current;

    /// <summary>Past this size the log is rolled to <c>.1</c> at the next start.</summary>
    private const long LogRollBytes = 5 * 1024 * 1024;

    /// <summary>
    /// Send stdout and stderr to a file, for a suite running without a window.
    /// </summary>
    /// <remarks>
    /// The windowless launcher passes this, because otherwise every status line
    /// - including why the suite refused to start - would go to a console no one
    /// can see. The file is shared for reading so it can be followed while the
    /// suite runs.
    /// </remarks>
    private static void RedirectToLog(string path)
    {
        var full = SuitePaths.Resolve(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);

        var info = new FileInfo(full);
        if (info.Exists && info.Length > LogRollBytes)
            File.Move(full, full + ".1", overwrite: true);

        var stream = new FileStream(full, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        var writer = TextWriter.Synchronized(new StreamWriter(stream) { AutoFlush = true });

        writer.WriteLine();
        writer.WriteLine("==== " + DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz") +
                         " securitysuite " + SuiteVersion.Current +
                         " (pid " + Environment.ProcessId + ")");
        Console.SetOut(writer);
        Console.SetError(writer);
    }

    /// <summary>Create or remove the desktop or startup shortcut, then exit.</summary>
    private static int Shortcut(CliOptions args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Status("[-] Shortcuts are Windows-only, as is the YARA binding this suite uses.");
            return 1;
        }

        var where = args.Startup ? "startup" : "desktop";
        try
        {
            if (args.RemoveShortcut)
            {
                var existed = Platform.DesktopLauncher.Remove(args.Startup);
                Status(existed
                    ? "[*] Removed the " + where + " shortcut"
                    : "[*] No " + where + " shortcut was present");
                return 0;
            }

            var target = Platform.DesktopLauncher.Install(args.Startup);
            Status("[*] Created   : " + target);
            Status("[*] Runs      : " + (Platform.DesktopLauncher.LaunchPath + " " +
                                       Platform.DesktopLauncher.Arguments(args.Startup)).TrimEnd());
            if (Platform.DesktopLauncher.LaunchPath == Platform.DesktopLauncher.ExecutablePath)
                Status("[!] securitysuitew.exe is not beside it, so a console window will open." +
                       " Publish with: dotnet publish src/SecuritySuite.Cli -c Release -o dist");
            Status("[*] From      : " + SuitePaths.Root);
            Status("[*] Icon      : " + Platform.DesktopLauncher.IconPath);
            return 0;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException
                                        or System.Runtime.InteropServices.COMException)
        {
            Status("[-] Could not update the " + where + " shortcut: " + exc.Message);
            return 1;
        }
    }

    private static SuiteConfig BuildConfig(CliOptions args)
    {
        var cfg = SuiteConfig.Load(warn: Status);

        if (args.Host is { } host) cfg.Host = host;
        if (args.Port is { } port) cfg.Port = port;
        if (args.Watch.Count > 0) cfg.WatchPaths = [.. args.Watch];
        if (args.RulesDir is { } rules) cfg.RulesDir = rules;
        if (args.ScanExisting) cfg.ScanExistingOnStart = true;

        // Re-create any directory a command-line override introduced.
        foreach (var watched in cfg.WatchPaths)
        {
            try { Directory.CreateDirectory(SuitePaths.Resolve(watched)); }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                Status("[!] Could not create " + watched + ": " + exc.Message);
            }
        }
        return cfg;
    }

    private static void PrintStartupReport(SuiteConfig cfg, YaraEngine engine,
                                           AuthTelemetry telemetry, NvdClient nvd)
    {
        var info = engine.Info();
        Status(Banner);
        Status("[*] Backend    : " + info.Backend);
        Status("[*] Rules      : " + info.RuleCount + " loaded from " + info.RulesDir +
               (info.UsingFallback ? " (FALLBACK RULE ONLY)" : ""));

        foreach (var error in info.LoadErrors)
            Status("[!] Rule error : " + error.File + " -> " + error.Error);

        var state = telemetry.Recent();
        Status("[*] Telemetry  : " + state.Source + " -> " + state.Status +
               (state.Detail.Length > 0 ? " (" + state.Detail + ")" : ""));

        var nvdState = nvd.Status();
        Status("[*] NVD        : " + (nvdState.Sync?.Cached ?? 0) + " CVEs cached, " +
               nvdState.RateLimit + ", tls via " + nvdState.TlsBundle +
               (nvdState.Sync?.LastSync is { Length: > 0 } last ? " (last sync " + last + ")" : ""));

        if (cfg.AutoRemediate)
        {
            Status("[!] AUTO-REMEDIATE ARMED: " + cfg.AutoRemediateAction + " at severity " +
                   cfg.AutoRemediateSeverity + " - files will be acted on without confirmation");
        }
        else
        {
            Status("[*] Remediate  : manual only (auto-remediate off)");
        }
    }

    private static int ScanOnce(DirectoryMonitor monitor, string target)
    {
        var job = monitor.ScanPath(target);
        Console.WriteLine(JsonSerializer.Serialize(job, SuiteJson.Pretty));
        return job?.Error is null ? 0 : 1;
    }

    /// <summary>
    /// Find a dashboard already serving this same workspace.
    /// </summary>
    /// <remarks>
    /// Matching on the findings log, not just the port, is what makes this
    /// safe: two instances writing the same NDJSON would interleave lines, and
    /// an unrelated service on port 8787 must not be mistaken for ours.
    /// </remarks>
    private static string? FindRunningInstance(SuiteConfig cfg, IEnumerable<int> ports)
    {
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false })
        {
            Timeout = TimeSpan.FromMilliseconds(400),
        };

        foreach (var port in ports)
        {
            var url = "http://127.0.0.1:" + port;
            try
            {
                var instance = client.GetFromJsonAsync<InstanceInfo>(url + "/api/instance")
                    .GetAwaiter().GetResult();

                if (instance?.Version != RouteTableVersion) continue;
                if (instance.FindingsLog is null) continue;
                if (PathUtil.Norm(instance.FindingsLog) != PathUtil.Norm(cfg.FindingsLog)) continue;

                return url;
            }
            catch (Exception exc) when (exc is HttpRequestException or TaskCanceledException
                                            or JsonException or NotSupportedException)
            {
                // Nothing there, something else there, or too slow. Move on.
            }
        }
        return null;
    }

    private static void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception exc) when (exc is System.ComponentModel.Win32Exception
                                        or InvalidOperationException or PlatformNotSupportedException)
        {
            Status("[!] Could not open a browser; visit " + url);
        }
    }

    private sealed class InstanceInfo
    {
        [System.Text.Json.Serialization.JsonPropertyName("version")]
        public string? Version { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("findings_log")]
        public string? FindingsLog { get; set; }
    }
}

internal sealed class CliUsageException(string message) : Exception(message);
