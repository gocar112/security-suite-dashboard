using System.Text;
using SecuritySuite.Configuration;
using SecuritySuite.Generation;
using SecuritySuite.Intel;

namespace SecuritySuite.Tools;

/// <summary>
/// Generate vulnerable-component rules from NVD, gated against a benign corpus.
/// </summary>
/// <remarks>
/// The gate is the point. Most candidates are rejected, and the rejection tally
/// is the interesting output: it shows how much of a CVE feed simply is not
/// expressible as a file-matching rule.
/// </remarks>
internal static class GenerateRulesCommand
{
    private const string Usage = """
        suite-tools generate-rules - build vulnerable-component rules from NVD

        Options:
          --limit N        maximum candidate rules to consider (default 1000)
          --days N         how far back to take recent CVEs (default 1460)
          --min-score N    minimum CVSS base score (default 9.0)
          --out PATH       output file (default rules/generated/nvd_components.yar)
          --dry-run        report the tally without writing the file
          -h, --help       show this help
        """;

    /// <summary>
    /// Prose that mentions software by name and version.
    /// </summary>
    /// <remarks>
    /// A generated rule that fires on any of this is too loose to ship. These
    /// are the shapes a false positive actually takes: release notes, a
    /// dependency manifest, a changelog, an invoice.
    /// </remarks>
    private static readonly string[] BenignProse =
    [
        "Release notes: upgraded to version 2.14.1 of the logging library and " +
        "bumped the client to 1.2.3. See the changelog for details.\n",

        "Our stack runs nginx 1.18.0 behind a load balancer, with PostgreSQL 13.4 " +
        "and Redis 6.2.5 on the data tier.\n",

        "requirements.txt\nrequests==2.31.0\nurllib3==2.0.7\ncertifi==2024.2.2\n",

        "{\"name\":\"web\",\"version\":\"1.0.0\",\"dependencies\":{\"react\":\"18.2.0\"," +
        "\"express\":\"4.18.2\",\"lodash\":\"4.17.21\"}}",

        "Quarterly review: the platform team upgraded three services this month. " +
        "No customer impact was recorded and all tests passed.\n",

        "# Changelog\n## 2.7.0\n- Fixed a crash on startup\n- Updated dependencies\n",

        "Dear team, please find attached the invoice for September. Payment terms " +
        "are 30 days. Regards, Accounts.\n",
    ];

    public static int Run(string[] args)
    {
        var limit = 1000;
        var days = 1460;
        var minScore = 9.0;
        var output = Path.Combine("rules", "generated", "nvd_components.yar");
        var dryRun = false;

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
                case "--limit":
                    limit = Number(args, ref i, "--limit");
                    break;
                case "--days":
                    days = Number(args, ref i, "--days");
                    break;
                case "--min-score":
                    minScore = Decimal(args, ref i, "--min-score");
                    break;
                case "--out":
                    output = Value(args, ref i, "--out");
                    break;
                default:
                    throw new ToolUsageException("Unknown option: " + args[i]);
            }
        }

        var cfg = SuiteConfig.Load(warn: Console.Error.WriteLine);
        var client = new NvdClient(cfg.NvdCacheDir, cfg.NvdApiKey);

        if (!client.HasApiKey)
            Console.WriteLine("[!] No NVD_API_KEY set - this will be slow (5 requests / 30 s).");

        var corpus = BuildCorpus();
        Console.WriteLine("[*] Benign corpus : " + corpus.Count + " documents");
        Console.WriteLine("[*] Harvesting CVEs from NVD (CVSS >= " + minScore.ToString("0.0") + ")...");

        var report = new RuleGenerator(client)
            .GenerateAsync(days, limit, minScore, corpus,
                (label, seen, total) => Console.WriteLine(
                    "    " + label.PadRight(24) + " " + seen + " of " + total.ToString("N0")))
            .GetAwaiter().GetResult();

        Console.WriteLine();
        Console.WriteLine("[*] CVEs examined : " + report.CvesExamined);
        Console.WriteLine("[*] Candidates    : " + report.Candidates);
        Console.WriteLine("[*] Survived gate : " + report.Survivors);
        Console.WriteLine();

        if (report.Rejections.Count > 0)
        {
            Console.WriteLine("[*] Rejected, by reason:");
            foreach (var (reason, count) in report.Rejections.OrderByDescending(kv => kv.Value))
                Console.WriteLine("      " + reason.PadRight(44) + " " + count);
        }

        var kept = report.Rules;
        if (kept.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("[*] Kept " + kept.Count + " rules, " +
                              kept.Count(r => r.Kev) + " for CISA KEV entries");

            var bySeverity = kept.GroupBy(r => r.Severity)
                .OrderBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => g.Key + " " + g.Count());
            Console.WriteLine("[*] Severity      : " + string.Join(", ", bySeverity));

            Console.WriteLine("[*] Sample        :");
            foreach (var rule in kept.Take(5))
            {
                Console.WriteLine("      " + rule.Cve.PadRight(16) + " " +
                    (rule.Vendor + ":" + rule.Product).PadRight(28) + " " +
                    string.Join(",", rule.Versions.Take(3)));
            }
        }

        if (dryRun)
        {
            Console.WriteLine();
            Console.WriteLine("[*] --dry-run: nothing written.");
            return 0;
        }

        var target = Path.IsPathRooted(output) ? output : Path.Combine(SuitePaths.Root, output);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.WriteAllText(target, RuleGenerator.EmitFile(kept));

        Console.WriteLine();
        Console.WriteLine("[*] Wrote " + target + " (" + kept.Count + " rules)");
        return 0;
    }

    /// <summary>
    /// The benign corpus: synthetic prose plus the repository's own files.
    /// </summary>
    /// <remarks>
    /// The repository is the harshest realistic corpus available, because it is
    /// full of product names, version numbers and security vocabulary — exactly
    /// what a loose generated rule latches onto.
    /// </remarks>
    private static List<byte[]> BuildCorpus()
    {
        var corpus = BenignProse.Select(Encoding.UTF8.GetBytes).ToList();

        string[] patterns = ["*.md", "*.txt", "samples/*", "web/*.js", "web/*.html",
                             "src/SecuritySuite.Core/*/*.cs"];
        foreach (var pattern in patterns)
        {
            var directory = Path.Combine(SuitePaths.Root, Path.GetDirectoryName(pattern) ?? "");
            var mask = Path.GetFileName(pattern);

            IEnumerable<string> files;
            try
            {
                if (!Directory.Exists(directory)) continue;
                files = Directory.EnumerateFiles(directory, mask)
                    .OrderBy(f => f, StringComparer.Ordinal)
                    .Take(40);
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                try
                {
                    // A 2 MB cap keeps the gate's per-candidate scan bounded:
                    // every surviving rule is matched against every document.
                    if (new FileInfo(file).Length >= 2_000_000) continue;
                    corpus.Add(File.ReadAllBytes(file));
                }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
            }
        }
        return corpus;
    }

    private static string Value(string[] args, ref int index, string flag)
    {
        if (index + 1 >= args.Length) throw new ToolUsageException(flag + " needs a value");
        return args[++index];
    }

    private static int Number(string[] args, ref int index, string flag)
    {
        var raw = Value(args, ref index, flag);
        if (!int.TryParse(raw, out var value) || value < 1)
            throw new ToolUsageException(flag + " must be a positive integer");
        return value;
    }

    private static double Decimal(string[] args, ref int index, string flag)
    {
        var raw = Value(args, ref index, flag);
        if (!double.TryParse(raw, out var value) || value is < 0 or > 10)
            throw new ToolUsageException(flag + " must be a CVSS score between 0 and 10");
        return value;
    }
}
