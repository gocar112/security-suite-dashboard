using System.Diagnostics;
using System.Formats.Tar;
using System.Text;
using SecuritySuite.Configuration;

namespace SecuritySuite.Tools;

/// <summary>
/// Refresh the read-only mirror from this repository.
/// </summary>
/// <remarks>
/// <para>
/// This repository is canonical. <c>soc-yara-scanner</c> is a mirror kept for
/// the project's history: it is where the original single-file
/// <c>YARA_scanning.py</c> started, and it still carries the first installer
/// and compose file alongside the current suite.
/// </para>
/// <para>
/// Two copies of a codebase drift the moment someone edits the wrong one, so
/// refreshing the mirror is one command rather than a manual copy, and the
/// mirror's README is stamped with a banner saying where the real work happens.
/// Nothing here edits the canonical repository.
/// </para>
/// <para>
/// Only committed, tracked files are mirrored: the export runs
/// <c>git archive HEAD</c>, so an uncommitted change, a <c>.env</c>, a cache
/// directory or a quarantined file cannot reach the mirror even by accident.
/// </para>
/// </remarks>
internal static class SyncMirrorCommand
{
    private const string MirrorUrl = "https://github.com/gocar112/soc-yara-scanner.git";
    private const string MirrorName = "gocar112/soc-yara-scanner";
    private const string CanonicalUrl = "https://github.com/gocar112/security-suite-dashboard";

    private const string Usage = """
        suite-tools sync-mirror - refresh the read-only mirror repository

        Options:
          --dry-run        report what would change without pushing
          --message TEXT   override the commit message
          -h, --help       show this help
        """;

    /// <summary>
    /// Files belonging to the mirror's own history that must survive a refresh.
    /// </summary>
    /// <remarks>
    /// The whole reason the mirror still exists. Overwriting these would erase
    /// the project's starting point, which is the only thing the mirror has
    /// that this repository does not.
    /// </remarks>
    private static readonly string[] Keep =
    [
        "YARA_scanning.py",
        "install.sh",
        "docker-compose.yml",
        "manual installer",
        "rules_test_rule.yar",
    ];

    private const string BannerTemplate = """
        > ### This is a mirror
        >
        > The canonical repository is **[security-suite-dashboard]({canonical})**.
        > Open issues and send changes there; anything committed here is overwritten by
        > the next sync.
        >
        > This repo is kept because the project started here as a single file. The
        > original `YARA_scanning.py`, `install.sh`, `docker-compose.yml` and manual
        > installer are still present alongside the current suite. The suite is now a
        > .NET application: build it with `dotnet build` and run `securitysuite`.
        >
        > _Last synced from {sha} on {date}._

        """;

    public static int Run(string[] args)
    {
        var dryRun = false;
        var message = "";

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    Console.WriteLine(Usage);
                    return 0;
                case "--dry-run":
                    dryRun = true;
                    break;
                case "--message":
                    if (i + 1 >= args.Length) throw new ToolUsageException("--message needs a value");
                    message = args[++i];
                    break;
                default:
                    throw new ToolUsageException("Unknown option: " + args[i]);
            }
        }

        var root = SuitePaths.Root;

        var dirty = Git(root, "status", "--porcelain");
        if (dirty.Length > 0)
        {
            Console.WriteLine("[!] This repository has uncommitted changes. Only committed work is");
            Console.WriteLine("    mirrored, so the mirror would not match your working tree:");
            foreach (var line in dirty.Split('\n').Take(8))
                Console.WriteLine("      " + line.TrimEnd());
            Console.WriteLine();
        }

        var sha = Git(root, "rev-parse", "--short", "HEAD");
        var date = Git(root, "log", "-1", "--format=%cs");
        var subject = Git(root, "log", "-1", "--format=%s");

        Console.WriteLine("[*] Canonical : " + Path.GetFileName(root) + " at " + sha + " (" + date + ")");
        Console.WriteLine("[*] Mirror    : " + MirrorName);

        var work = Directory.CreateTempSubdirectory("mirror-").FullName;
        var clone = Path.Combine(work, "mirror");
        try
        {
            Console.WriteLine("[*] Cloning the mirror...");
            Git(work, "clone", "--quiet", MirrorUrl, clone);

            var preserved = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var name in Keep)
            {
                var source = Path.Combine(clone, name);
                if (File.Exists(source)) preserved[name] = File.ReadAllBytes(source);
            }

            foreach (var child in Directory.EnumerateFileSystemEntries(clone))
            {
                if (Path.GetFileName(child) == ".git") continue;
                if (Directory.Exists(child)) Directory.Delete(child, recursive: true);
                else File.Delete(child);
            }

            Console.WriteLine("[*] Exporting tracked files from HEAD...");
            var archive = Path.Combine(work, "export.tar");
            ExportArchive(root, archive);
            TarFile.ExtractToDirectory(archive, clone, overwriteFiles: true);

            foreach (var (name, blob) in preserved) File.WriteAllBytes(Path.Combine(clone, name), blob);
            Console.WriteLine(preserved.Count > 0
                ? "[*] Preserved : " + string.Join(", ", preserved.Keys.OrderBy(k => k, StringComparer.Ordinal))
                : "[*] Preserved : nothing (mirror had none of the originals)");

            AddBanner(Path.Combine(clone, "README.md"), sha, date);

            Git(clone, "add", "-A");
            var status = Git(clone, "status", "--porcelain");
            if (status.Length == 0)
            {
                Console.WriteLine("[*] Mirror is already up to date. Nothing to do.");
                return 0;
            }

            var changed = status.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Console.WriteLine("[*] Changes   : " + changed.Length + " file(s)");
            foreach (var line in changed.Take(10)) Console.WriteLine("      " + line.TrimEnd());
            if (changed.Length > 10) Console.WriteLine("      ... and " + (changed.Length - 10) + " more");

            if (dryRun)
            {
                Console.WriteLine();
                Console.WriteLine("[*] --dry-run: nothing pushed.");
                return 0;
            }

            var commitMessage = message.Length > 0 ? message :
                "Sync from security-suite-dashboard " + sha + "\n\n" + subject + "\n\n" +
                "Mirrored with suite-tools sync-mirror. The canonical repository is\n" +
                CanonicalUrl + " - changes made here are overwritten by the next sync.";

            Git(clone, "commit", "--quiet", "-m", commitMessage);
            Console.WriteLine("[*] Pushing...");
            Git(clone, "push", "--quiet", "origin", "HEAD");
            Console.WriteLine("[*] Mirror updated to " + sha);
            return 0;
        }
        finally
        {
            try { Directory.Delete(work, recursive: true); }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Put the mirror notice above the first heading, replacing any previous one.
    /// </summary>
    /// <remarks>
    /// Replacing rather than prepending matters: without it, every sync would
    /// stack another banner and the mirror's README would grow a wall of them.
    /// </remarks>
    internal static void AddBanner(string readme, string sha, string date)
    {
        var lines = File.Exists(readme)
            ? File.ReadAllLines(readme).ToList()
            : ["# Security Suite"];

        var existing = lines.Take(40).ToList().FindIndex(l => l.Contains("This is a mirror", StringComparison.Ordinal));
        if (existing >= 0)
        {
            var start = Math.Max(0, existing - 1);
            var end = start;
            while (end < lines.Count &&
                   (lines[end].StartsWith('>') || lines[end].Trim().Length == 0))
            {
                end++;
            }
            lines.RemoveRange(start, end - start);
        }

        var banner = BannerTemplate
            .Replace("{canonical}", CanonicalUrl)
            .Replace("{sha}", sha)
            .Replace("{date}", date)
            .Split('\n')
            .Select(l => l.TrimEnd('\r'))
            .ToList();

        var heading = lines.FindIndex(l => l.StartsWith("# ", StringComparison.Ordinal));
        if (heading >= 0) lines.InsertRange(heading + 1, new[] { "" }.Concat(banner));
        else lines.InsertRange(0, banner);

        File.WriteAllLines(readme, lines);
    }

    /// <summary>
    /// Export the committed tree with <c>git archive HEAD</c>.
    /// </summary>
    /// <remarks>
    /// This is the control that keeps secrets out of the mirror. Copying the
    /// working directory would carry <c>.env</c>, the NVD cache and anything
    /// sitting in quarantine; an archive of HEAD can only contain tracked,
    /// committed files.
    /// </remarks>
    private static void ExportArchive(string root, string archivePath)
    {
        using var output = File.Create(archivePath);
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("git")
            {
                ArgumentList = { "archive", "HEAD" },
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        process.Start();
        process.StandardOutput.BaseStream.CopyTo(output);
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
            throw new IOException("git archive failed: " + Clip(error, 200));
    }

    private static string Git(string workingDirectory, params string[] arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("git")
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            },
        };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);

        process.Start();
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new IOException("git " + string.Join(' ', arguments.Take(3)) + " failed:\n" +
                                  Clip(error.Trim(), 400));
        }
        return output.Trim();
    }

    private static string Clip(string value, int length) =>
        value.Length > length ? value[..length] : value;
}
