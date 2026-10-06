using System.Text.Json.Serialization;
using SecuritySuite.Configuration;
using SecuritySuite.Detection;
using SecuritySuite.Remediation;
using SecuritySuite.Storage;

namespace SecuritySuite.Shield;

/// <summary>
/// Defensive AV/IDS/IPS posture model for the dashboard.
/// </summary>
/// <remarks>
/// Local and read-only by design. It does not attempt to drive third-party
/// products without their credentials; it shows what is active inside the
/// suite, where commercial controls would plug in, and which defensive
/// playbooks cover common attack pressure.
/// </remarks>
public static class ShieldPosture
{
    private static readonly string[] AttackGoals =
    [
        "credential theft", "ransomware deployment", "data theft",
        "persistence", "command and control", "defense evasion",
        "initial access", "privilege escalation", "lateral movement",
        "web shell access", "supply-chain abuse", "cloud token theft",
        "cryptomining", "phishing delivery", "living-off-the-land execution",
        "remote management abuse", "browser session theft", "payload staging",
        "vulnerable service exploitation", "insider misuse",
    ];

    private static readonly string[] EntryPoints =
    [
        "email attachment", "downloaded executable", "PowerShell script",
        "Python script", "Office macro", "archive file", "web upload",
        "SSH account", "RDP account", "browser extension", "npm package",
        "pip package", "container image", "USB media", "scheduled task",
        "startup folder", "Windows service", "cron entry", "registry run key",
        "public-facing application", "VPN appliance", "router firmware",
        "database credential", "cloud access key", "shared folder",
    ];

    /// <summary>Goals severe enough to rate critical wherever they enter from.</summary>
    private static readonly HashSet<string> CriticalGoals = new(StringComparer.Ordinal)
    {
        "ransomware deployment", "credential theft", "data theft", "privilege escalation",
    };

    public static readonly ControlLayer[] Layers =
    [
        new()
        {
            Name = "Local antivirus sensor",
            Kind = "AV",
            Status = "active",
            Coverage = "YARA file scanning, entropy, hash identity, IOC extraction",
            Patch = "Keep rules current; quarantine before delete; reload after rule changes.",
        },
        new()
        {
            Name = "Remediation rails",
            Kind = "AV",
            Status = "active",
            Coverage = "SHA-256 recheck, path confinement, suite self-protection, audit log",
            Patch = "Use preview first; keep auto-remediation off until rules are tuned.",
        },
        new()
        {
            Name = "IDS stream",
            Kind = "IDS",
            Status = "active",
            Coverage = "Findings feed, auth telemetry correlation, live alerts, IOC pivots",
            Patch = "Investigate critical/high alerts first and export IOCs to your SIEM.",
        },
        new()
        {
            Name = "IPS decision layer",
            Kind = "IPS",
            Status = "guarded",
            Coverage = "Manual quarantine/delete/purge actions after preview and confirm",
            Patch = "Block by quarantine first; delete only after evidence review.",
        },
        new()
        {
            Name = "Bitdefender GravityZone",
            Kind = "AV/EDR",
            Status = "connector-ready",
            Coverage = "Policy, reports, quarantine, sandbox and network APIs can be bridged",
            Patch = "Set BITDEFENDER_API_KEY and BITDEFENDER_API_URL when adding a live connector.",
            Url = "https://www.bitdefender.com/business/support/en/77212-125277-public-api.html",
        },
        new()
        {
            Name = "NVD + CISA KEV",
            Kind = "Patch",
            Status = "active",
            Coverage = "CVE lookup, known-exploited prioritization, vendor patch references",
            Patch = "Patch KEV/critical CVEs first; use NVD URLs from IOC and guidance panels.",
            Url = "https://nvd.nist.gov/",
        },
    ];

    public static readonly PatchPlaybook[] PatchPlaybooks =
    [
        new()
        {
            Name = "Ransomware",
            Patterns = ["ransom note", "wallet", "onion portal", "mass rename"],
            Actions =
            [
                "isolate host", "quarantine payload", "preserve evidence",
                "rotate credentials", "restore from known-good backup",
            ],
        },
        new()
        {
            Name = "Credential theft",
            Patterns = ["dump tool strings", "browser token paths", "LSASS access"],
            Actions =
            [
                "quarantine tool", "reset affected secrets", "review logons",
                "enable MFA", "patch exposed services",
            ],
        },
        new()
        {
            Name = "Web shell",
            Patterns = ["script upload", "eval/exec", "suspicious request parameter"],
            Actions =
            [
                "remove shell", "patch application", "rotate app secrets",
                "review access logs", "block upload vector",
            ],
        },
        new()
        {
            Name = "Supply chain",
            Patterns = ["package manifest", "install script", "obfuscated loader"],
            Actions =
            [
                "pin dependency", "upgrade package", "review lockfile",
                "rebuild from clean source", "scan artifacts",
            ],
        },
        new()
        {
            Name = "Vulnerable component",
            Patterns = ["CVE indicator", "product/version marker", "KEV match"],
            Actions =
            [
                "open NVD advisory", "apply vendor patch", "use temporary mitigation",
                "rescan", "document exception",
            ],
        },
    ];

    public static PostureReport Build(SuiteConfig cfg, YaraEngine engine, EventStore store,
                                      Remediator? remediator = null)
    {
        var stats = store.Stats();
        var critical = stats.BySeverity.GetValueOrDefault(Severity.Critical);
        var high = stats.BySeverity.GetValueOrDefault(Severity.High);

        // A single number for a wall display, weighted so criticals dominate.
        // Flagged as heuristic in the payload because it is a rendering of
        // three counts, not a measurement of anything.
        var score = Math.Clamp(100 - (critical * 12) - (high * 5) - stats.OpenAlerts, 0, 100);
        var pressure = AttackPressureRows();

        return new PostureReport
        {
            Platform = Environment.OSVersion.Platform.ToString(),
            Score = score,
            ScoreIsHeuristic = true,
            Rules = engine.Info().RuleCount,
            AttackReasons = pressure.Count,
            AttackReasonsSample = [.. pressure.Take(18)],
            Layers = Layers,
            PatchPlaybooks = PatchPlaybooks,
            Integrations = new Dictionary<string, IntegrationState>
            {
                ["bitdefender"] = FromEnvironment("BITDEFENDER_API_KEY", "BITDEFENDER_API_URL"),
                ["nvd"] = new()
                {
                    Configured = cfg.NvdApiKey.Length > 0,
                    Status = cfg.NvdApiKey.Length > 0 ? "configured" : "public rate",
                },
                ["virustotal"] = new()
                {
                    Configured = cfg.VirustotalApiKey.Length > 0,
                    Status = cfg.VirustotalApiKey.Length > 0 ? "configured" : "not configured",
                },
            },
            FileGroups = new Dictionary<string, string[]>
            {
                ["scripts"] = [".ps1", ".py", ".js", ".vbs", ".sh", ".bat", ".cmd"],
                ["executables"] = [".exe", ".dll", ".scr", ".msi", ".elf", ".dylib"],
                ["documents"] = [".doc", ".docm", ".xls", ".xlsm", ".pdf", ".rtf"],
                ["archives"] = [".zip", ".rar", ".7z", ".iso", ".img", ".tar", ".gz"],
            },
            Remediation = remediator?.Status(),
            Sources =
            [
                new("Bitdefender GravityZone API",
                    "https://www.bitdefender.com/business/support/en/77212-125277-public-api.html"),
                new("NVD", "https://nvd.nist.gov/"),
                new("CISA Known Exploited Vulnerabilities",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            ],
        };
    }

    private static IntegrationState FromEnvironment(string key, string? urlKey = null)
    {
        var configured = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(key));
        if (urlKey is not null)
        {
            configured = configured &&
                !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(urlKey));
        }
        return new IntegrationState
        {
            Configured = configured,
            Status = configured ? "configured" : "not configured",
        };
    }

    /// <summary>
    /// The goal-by-entry-point matrix, each row with its defence.
    /// </summary>
    /// <remarks>
    /// Public because the tabletop question bank is built from the same rows.
    /// Two generators would drift, and a training question whose "correct"
    /// answer no longer matched the posture panel would be teaching the wrong
    /// thing.
    /// </remarks>
    public static List<AttackPressure> AttackPressureRows(int limit = 500)
    {
        var rows = new List<AttackPressure>(Math.Min(limit, AttackGoals.Length * EntryPoints.Length));
        foreach (var goal in AttackGoals)
        {
            foreach (var entry in EntryPoints)
            {
                if (rows.Count >= limit) return rows;
                rows.Add(new AttackPressure
                {
                    Id = "AP-" + (rows.Count + 1).ToString("D3"),
                    Goal = goal,
                    Entry = entry,
                    Severity = CriticalGoals.Contains(goal) ? Storage.Severity.Critical : Storage.Severity.High,
                    Defense = DefenseFor(goal, entry),
                });
            }
        }
        return rows;
    }

    internal static string DefenseFor(string goal, string entry)
    {
        if (goal.Contains("vulnerable", StringComparison.Ordinal) ||
            entry.Contains("firmware", StringComparison.Ordinal) ||
            entry.Contains("application", StringComparison.Ordinal))
        {
            return "Patch from NVD/vendor guidance, then rescan the affected path.";
        }
        if (goal.Contains("credential", StringComparison.Ordinal) ||
            entry.Contains("account", StringComparison.Ordinal) ||
            entry.Contains("key", StringComparison.Ordinal))
        {
            return "Reset secrets, review auth telemetry, and quarantine detected tooling.";
        }
        if (goal.Contains("ransomware", StringComparison.Ordinal))
            return "Isolate, quarantine, preserve evidence, and restore from clean backup.";
        if (goal.Contains("supply", StringComparison.Ordinal) ||
            entry.Contains("package", StringComparison.Ordinal))
        {
            return "Pin or upgrade dependency, review install scripts, and rebuild artifacts.";
        }
        return "Alert, triage, quarantine suspicious files, and document the decision.";
    }

    /// <summary>What the launcher does on each platform, for the help panel.</summary>
    public static Dictionary<string, string> StartupTargets() => new()
    {
        ["windows"] = "Startup shortcut runs the published executable with no console window.",
        ["linux"] = "Desktop entry uses Terminal=false.",
        ["macos"] = "App bundle launcher runs without a terminal window.",
        ["root"] = SuitePaths.Root,
    };
}

public sealed class ControlLayer
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("kind")] public string Kind { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "";
    [JsonPropertyName("coverage")] public string Coverage { get; init; } = "";
    [JsonPropertyName("patch")] public string Patch { get; init; } = "";

    [JsonPropertyName("url")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Url { get; init; }
}

public sealed class PatchPlaybook
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("patterns")] public string[] Patterns { get; init; } = [];
    [JsonPropertyName("actions")] public string[] Actions { get; init; } = [];
}

public sealed class AttackPressure
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("goal")] public string Goal { get; init; } = "";
    [JsonPropertyName("entry")] public string Entry { get; init; } = "";
    [JsonPropertyName("severity")] public string Severity { get; init; } = "";
    [JsonPropertyName("defense")] public string Defense { get; init; } = "";
}

public sealed class IntegrationState
{
    [JsonPropertyName("configured")] public bool Configured { get; init; }
    [JsonPropertyName("status")] public string Status { get; init; } = "";
}

public sealed record SourceLink(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("url")] string Url);

public sealed class PostureReport
{
    [JsonPropertyName("platform")] public string Platform { get; init; } = "";
    [JsonPropertyName("score")] public int Score { get; init; }

    /// <summary>
    /// Always true, and in the payload so the UI cannot present the score as a
    /// measurement. It is a weighting of three counts.
    /// </summary>
    [JsonPropertyName("score_is_heuristic")] public bool ScoreIsHeuristic { get; init; }

    [JsonPropertyName("rules")] public int Rules { get; init; }
    [JsonPropertyName("attack_reasons")] public int AttackReasons { get; init; }
    [JsonPropertyName("attack_reasons_sample")] public List<AttackPressure> AttackReasonsSample { get; init; } = [];
    [JsonPropertyName("layers")] public ControlLayer[] Layers { get; init; } = [];
    [JsonPropertyName("patch_playbooks")] public PatchPlaybook[] PatchPlaybooks { get; init; } = [];
    [JsonPropertyName("integrations")] public Dictionary<string, IntegrationState> Integrations { get; init; } = [];
    [JsonPropertyName("file_groups")] public Dictionary<string, string[]> FileGroups { get; init; } = [];

    [JsonPropertyName("remediation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public RemediationStatus? Remediation { get; init; }

    [JsonPropertyName("sources")] public SourceLink[] Sources { get; init; } = [];
}
