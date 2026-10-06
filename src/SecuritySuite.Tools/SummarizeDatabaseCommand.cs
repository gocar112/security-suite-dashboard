using System.Text;
using System.Text.Json;
using SecuritySuite.Configuration;
using SecuritySuite.Remediation;
using SecuritySuite.Storage;

namespace SecuritySuite.Tools;

/// <summary>
/// Summarise local suite state into a small Markdown report.
/// </summary>
/// <remarks>
/// Read-only, and tolerant of everything being absent: this is often run on a
/// fresh checkout to show what a clean install looks like.
/// </remarks>
internal static class SummarizeDatabaseCommand
{
    private const string Usage = """
        suite-tools summarize-database - Markdown report of local suite state

        Options:
          --root PATH      project root (default: the detected suite root)
          --output PATH    write to a file instead of stdout
          -h, --help       show this help
        """;

    public static int Run(string[] args)
    {
        var root = SuitePaths.Root;
        var output = "";

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    Console.WriteLine(Usage);
                    return 0;
                case "--root":
                    root = Next(args, ref i, "--root");
                    break;
                case "--output":
                    output = Next(args, ref i, "--output");
                    break;
                default:
                    throw new ToolUsageException("Unknown option: " + args[i]);
            }
        }

        root = Path.GetFullPath(root);
        var report = Summarise(root);

        if (output.Length == 0)
        {
            Console.Write(report);
            return 0;
        }

        var target = Path.IsPathRooted(output) ? output : Path.Combine(root, output);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.WriteAllText(target, report);
        Console.Error.WriteLine("[*] Wrote " + target);
        return 0;
    }

    private static string Summarise(string root)
    {
        var dataDir = Path.Combine(root, "data");
        var nvdDir = Path.Combine(root, "nvds");

        var findings = LoadNdjson(Path.Combine(dataDir, "findings.ndjson"));
        var triage = LoadJson<Dictionary<string, TriageState>>(Path.Combine(dataDir, "triage.json")) ?? [];
        var remediation = LoadJson<Dictionary<string, RemediationState>>(
            Path.Combine(dataDir, "remediation.json")) ?? [];
        var nvdIndex = LoadJson<Intel.NvdSyncIndex>(Path.Combine(nvdDir, "index.json"));

        var eventTypes = Tally(findings.Select(f => f.EventType.Length > 0 ? f.EventType : "unknown"));
        var severities = Tally(findings.Where(f => f.IsMatch).Select(f => Severity.Normalise(f.Severity)));
        var statuses = Tally(findings.Select(f => f.Status.Length > 0 ? f.Status : "new"));

        var quarantined = remediation.Values.Count(v => v.Action == RemediationActions.Quarantine);
        var quarantineEntries = CountEntries(Path.Combine(root, "quarantine"));
        var backups = CountDirectories(Path.Combine(dataDir, "log-backups"));

        var builder = new StringBuilder();
        builder.AppendLine("# Database Summary");
        builder.AppendLine();
        builder.AppendLine("Generated: `" + DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:sszzz") + "`");
        builder.AppendLine();
        builder.AppendLine("## NVD Cache");
        builder.AppendLine();
        builder.AppendLine("- Last sync: `" + (nvdIndex?.LastSync ?? "not synced") + "`");
        builder.AppendLine("- Window: `" + (nvdIndex?.WindowStart ?? "-") + "` to `" +
                           (nvdIndex?.WindowEnd ?? "-") + "`");
        builder.AppendLine("- Cached records: `" +
            (nvdIndex?.Cached ?? CountLines(Path.Combine(nvdDir, "cves.ndjson"))) + "`");
        builder.AppendLine("- Total in window: `" + (nvdIndex?.TotalInWindow.ToString() ?? "-") + "`");
        builder.AppendLine("- Truncated: `" + (nvdIndex?.Truncated.ToString() ?? "-") + "`");
        builder.AppendLine("- Pages fetched: `" + (nvdIndex?.PagesFetched.ToString() ?? "-") + "`");
        builder.AppendLine();
        builder.AppendLine("Severity cache counts:");
        AppendBullets(builder, nvdIndex?.BySeverity ?? []);
        builder.AppendLine();
        builder.AppendLine("## Findings Log");
        builder.AppendLine();
        builder.AppendLine("- Active findings/events: `" + findings.Count + "`");
        builder.AppendLine("- Triage sidecar entries: `" + triage.Count + "`");
        builder.AppendLine("- Remediation state entries: `" + remediation.Count + "`");
        builder.AppendLine("- Quarantined active states: `" + quarantined + "`");
        builder.AppendLine("- Quarantine directory entries: `" + quarantineEntries + "`");
        builder.AppendLine("- Log backups: `" + backups + "`");
        builder.AppendLine();
        builder.AppendLine("Event types:");
        AppendBullets(builder, eventTypes);
        builder.AppendLine();
        builder.AppendLine("Detection severities:");
        AppendBullets(builder, severities);
        builder.AppendLine();
        builder.AppendLine("Statuses:");
        AppendBullets(builder, statuses);
        return builder.ToString();
    }

    private static Dictionary<string, int> Tally(IEnumerable<string> values)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var value in values) counts[value] = counts.GetValueOrDefault(value) + 1;
        return counts;
    }

    private static void AppendBullets(StringBuilder builder, Dictionary<string, int> values)
    {
        if (values.Count == 0)
        {
            builder.AppendLine("- none");
            return;
        }
        foreach (var (key, value) in values.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            builder.AppendLine("- " + key + ": " + value);
    }

    private static T? LoadJson<T>(string path) where T : class
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), SuiteJson.Options)
                : null;
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static List<SuiteEvent> LoadNdjson(string path)
    {
        var rows = new List<SuiteEvent>();
        if (!File.Exists(path)) return rows;

        try
        {
            using var reader = new StreamReader(
                new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            while (reader.ReadLine() is { } line)
            {
                if (line.Length == 0) continue;
                try
                {
                    if (JsonSerializer.Deserialize<SuiteEvent>(line, SuiteJson.Options) is { } row)
                        rows.Add(row);
                }
                catch (JsonException) { /* skip a malformed line, report the rest */ }
            }
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
        return rows;
    }

    private static int CountLines(string path)
    {
        if (!File.Exists(path)) return 0;
        try
        {
            using var reader = new StreamReader(
                new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            var total = 0;
            while (reader.ReadLine() is { } line)
            {
                if (line.Trim().Length > 0) total++;
            }
            return total;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static int CountEntries(string directory)
    {
        try
        {
            return Directory.Exists(directory)
                ? Directory.EnumerateFileSystemEntries(directory)
                    .Count(e => Path.GetFileName(e) != ".gitkeep")
                : 0;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static int CountDirectories(string directory)
    {
        try
        {
            return Directory.Exists(directory) ? Directory.EnumerateDirectories(directory).Count() : 0;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static string Next(string[] args, ref int index, string flag)
    {
        if (index + 1 >= args.Length) throw new ToolUsageException(flag + " needs a value");
        return args[++index];
    }
}
