using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecuritySuite.Detection;
using SecuritySuite.Storage;

namespace SecuritySuite.Intel;

/// <summary>
/// MITRE ATT&amp;CK mapping for the rule set.
/// </summary>
/// <remarks>
/// <para>
/// A YARA hit says <em>this file is bad</em>. ATT&amp;CK says <em>what the
/// adversary was trying to do</em>, and that is the language detection coverage
/// is argued in. A rule that fires on <c>vssadmin delete shadows</c> is not
/// just "critical"; it is T1490, Inhibit System Recovery, and if nothing else
/// in the rule set covers Impact then that is a gap worth knowing about.
/// </para>
/// <para>
/// <b>The table is embedded, not fetched.</b> The suite is loopback-bound and
/// may run with no outbound network at all. A coverage matrix that needs
/// attack.mitre.org to render is one that fails closed in the environment this
/// tool is built for. Only the techniques the rule set actually references are
/// carried here; this is not a mirror of ATT&amp;CK.
/// </para>
/// <para>
/// <b>Mapping lives in rule metadata.</b> <c>mitre = "T1486"</c> sits beside
/// <c>severity = "critical"</c> in the rule itself, so the rule author owns it
/// the same way they already own triage priority. Nothing here hardcodes rule
/// names.
/// </para>
/// <para>
/// <b>Techniques are resolved on read, not stored.</b> Findings keep the raw
/// <c>mitre</c> metadata they matched on, and this class resolves it whenever
/// the matrix is built. Storing resolved technique objects in every event would
/// bloat the log and, worse, freeze old findings against the table as it was
/// when they were written, so correcting a mapping would never reach them.
/// </para>
/// <para>Technique names and tactic assignments follow ATT&amp;CK Enterprise v14.</para>
/// </remarks>
public static partial class AttackMapping
{
    /// <summary>
    /// Kill-chain order. The matrix renders tactic columns in this sequence, so
    /// it reads left to right the way an intrusion actually unfolds.
    /// </summary>
    public static readonly (string Id, string Name)[] Tactics =
    [
        ("reconnaissance", "Reconnaissance"),
        ("resource-development", "Resource Development"),
        ("initial-access", "Initial Access"),
        ("execution", "Execution"),
        ("persistence", "Persistence"),
        ("privilege-escalation", "Privilege Escalation"),
        ("defense-evasion", "Defense Evasion"),
        ("credential-access", "Credential Access"),
        ("discovery", "Discovery"),
        ("lateral-movement", "Lateral Movement"),
        ("collection", "Collection"),
        ("command-and-control", "Command and Control"),
        ("exfiltration", "Exfiltration"),
        ("impact", "Impact"),
    ];

    /// <summary>
    /// Technique id to name and tactics. Sub-techniques carry their own entry,
    /// so a finding can say T1003.001 rather than the vaguer T1003.
    /// </summary>
    public static readonly Dictionary<string, (string Name, string[] Tactics)> Techniques = new(StringComparer.Ordinal)
    {
        ["T1003"] = ("OS Credential Dumping", ["credential-access"]),
        ["T1003.001"] = ("OS Credential Dumping: LSASS Memory", ["credential-access"]),
        ["T1003.002"] = ("OS Credential Dumping: Security Account Manager", ["credential-access"]),
        ["T1005"] = ("Data from Local System", ["collection"]),
        ["T1014"] = ("Rootkit", ["defense-evasion"]),
        ["T1016"] = ("System Network Configuration Discovery", ["discovery"]),
        ["T1021.001"] = ("Remote Services: Remote Desktop Protocol", ["lateral-movement"]),
        ["T1027"] = ("Obfuscated Files or Information", ["defense-evasion"]),
        ["T1027.002"] = ("Obfuscated Files or Information: Software Packing", ["defense-evasion"]),
        ["T1036.007"] = ("Masquerading: Double File Extension", ["defense-evasion"]),
        ["T1041"] = ("Exfiltration Over C2 Channel", ["exfiltration"]),
        ["T1053.003"] = ("Scheduled Task/Job: Cron",
            ["execution", "persistence", "privilege-escalation"]),
        ["T1053.005"] = ("Scheduled Task/Job: Scheduled Task",
            ["execution", "persistence", "privilege-escalation"]),
        ["T1056.001"] = ("Input Capture: Keylogging", ["collection", "credential-access"]),
        ["T1056.003"] = ("Input Capture: Web Portal Capture", ["collection", "credential-access"]),
        ["T1059"] = ("Command and Scripting Interpreter", ["execution"]),
        ["T1059.001"] = ("Command and Scripting Interpreter: PowerShell", ["execution"]),
        ["T1059.004"] = ("Command and Scripting Interpreter: Unix Shell", ["execution"]),
        ["T1059.005"] = ("Command and Scripting Interpreter: Visual Basic", ["execution"]),
        ["T1070.002"] = ("Indicator Removal: Clear Linux or Mac System Logs", ["defense-evasion"]),
        ["T1070.003"] = ("Indicator Removal: Clear Command History", ["defense-evasion"]),
        ["T1071.001"] = ("Application Layer Protocol: Web Protocols", ["command-and-control"]),
        ["T1071.004"] = ("Application Layer Protocol: DNS", ["command-and-control"]),
        ["T1082"] = ("System Information Discovery", ["discovery"]),
        ["T1105"] = ("Ingress Tool Transfer", ["command-and-control"]),
        ["T1113"] = ("Screen Capture", ["collection"]),
        ["T1115"] = ("Clipboard Data", ["collection"]),
        ["T1125"] = ("Video Capture", ["collection"]),
        ["T1190"] = ("Exploit Public-Facing Application", ["initial-access"]),
        ["T1195.002"] = ("Supply Chain Compromise: Compromise Software Supply Chain",
            ["initial-access"]),
        ["T1204.002"] = ("User Execution: Malicious File", ["execution"]),
        ["T1218"] = ("System Binary Proxy Execution", ["defense-evasion"]),
        ["T1219"] = ("Remote Access Software", ["command-and-control"]),
        ["T1486"] = ("Data Encrypted for Impact", ["impact"]),
        ["T1490"] = ("Inhibit System Recovery", ["impact"]),
        ["T1496"] = ("Resource Hijacking", ["impact"]),
        ["T1505.003"] = ("Server Software Component: Web Shell", ["persistence"]),
        ["T1543.002"] = ("Create or Modify System Process: Systemd Service",
            ["persistence", "privilege-escalation"]),
        ["T1543.003"] = ("Create or Modify System Process: Windows Service",
            ["persistence", "privilege-escalation"]),
        ["T1546.003"] = ("Event Triggered Execution: WMI Event Subscription",
            ["persistence", "privilege-escalation"]),
        ["T1547.001"] = ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            ["persistence", "privilege-escalation"]),
        ["T1552"] = ("Unsecured Credentials", ["credential-access"]),
        ["T1552.001"] = ("Unsecured Credentials: Credentials In Files", ["credential-access"]),
        ["T1552.004"] = ("Unsecured Credentials: Private Keys", ["credential-access"]),
        ["T1555"] = ("Credentials from Password Stores", ["credential-access"]),
        ["T1555.003"] = ("Credentials from Password Stores: Credentials from Web Browsers",
            ["credential-access"]),
        ["T1562.001"] = ("Impair Defenses: Disable or Modify Tools", ["defense-evasion"]),
        ["T1562.004"] = ("Impair Defenses: Disable or Modify System Firewall", ["defense-evasion"]),
        ["T1566.001"] = ("Phishing: Spearphishing Attachment", ["initial-access"]),
        ["T1566.002"] = ("Phishing: Spearphishing Link", ["initial-access"]),
        ["T1572"] = ("Protocol Tunneling", ["command-and-control"]),
        ["T1573"] = ("Encrypted Channel", ["command-and-control"]),
        ["T1574.006"] = ("Hijack Execution Flow: Dynamic Linker Hijacking",
            ["persistence", "privilege-escalation", "defense-evasion"]),
        ["T1611"] = ("Escape to Host", ["privilege-escalation"]),
    };

    /// <summary>
    /// Rule-file defaults for rules that carry no mapping of their own.
    /// </summary>
    /// <remarks>
    /// The generated vulnerable-component rules are all "this file references a
    /// component with a known CVE", which is one technique. Tagging 931
    /// generated rules individually would be noise, so the file carries it.
    /// </remarks>
    public static readonly Dictionary<string, string[]> NamespaceDefaults = new(StringComparer.OrdinalIgnoreCase)
    {
        ["nvd_components"] = ["T1190"],
        ["generated"] = ["T1190"],
    };

    [GeneratedRegex(@"T\d{4}(?:\.\d{3})?", RegexOptions.None, 2000)]
    private static partial Regex TechniquePattern();

    /// <summary>
    /// Pull technique ids out of a rule's <c>mitre</c> metadata value.
    /// </summary>
    /// <remarks>
    /// Accepts <c>T1486</c>, <c>T1486,T1490</c>, <c>T1486 T1490</c> and
    /// similar. Anything not shaped like a technique id is ignored rather than
    /// guessed at.
    /// </remarks>
    public static List<string> ParseIds(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return [];

        var found = new List<string>();
        foreach (var match in TechniquePattern().EnumerateMatches(raw.ToUpperInvariant()))
        {
            var id = raw.ToUpperInvariant().Substring(match.Index, match.Length);
            if (!found.Contains(id)) found.Add(id);
        }
        return found;
    }

    /// <summary>
    /// One technique as the dashboard wants it, even when the table has never
    /// heard of it.
    /// </summary>
    /// <remarks>
    /// An unknown id is returned rather than dropped: a rule author who adds
    /// a technique before this table knows about it should see their id in the
    /// UI, not silently lose the mapping.
    /// </remarks>
    public static AttackTechnique Describe(string techniqueId)
    {
        var known = Techniques.TryGetValue(techniqueId, out var entry);
        return new AttackTechnique
        {
            Id = techniqueId,
            Name = known ? entry.Name : "Unmapped technique",
            Tactics = known ? [.. entry.Tactics] : [],
            Known = known,
            Url = "https://attack.mitre.org/techniques/" + techniqueId.Replace('.', '/') + "/",
        };
    }

    /// <summary>Techniques for one rule match, falling back to the rule file's default.</summary>
    public static List<AttackTechnique> Resolve(IReadOnlyDictionary<string, string> meta,
                                                string nameSpace = "")
    {
        // "attack" is accepted alongside "mitre" because rule authors write
        // both, and silently ignoring one would lose the mapping.
        if (!meta.TryGetValue("mitre", out var raw) || string.IsNullOrWhiteSpace(raw))
            meta.TryGetValue("attack", out raw);

        var ids = ParseIds(raw);

        if (ids.Count == 0 && nameSpace.Length > 0 &&
            NamespaceDefaults.TryGetValue(nameSpace, out var fallback))
        {
            ids = [.. fallback];
        }
        return [.. ids.Select(Describe)];
    }

    public static List<AttackTechnique> Resolve(RuleMatch match) =>
        Resolve(match.Meta, match.Namespace);

    /// <summary>Distinct tactic ids covered by a set of techniques, in kill-chain order.</summary>
    public static List<string> TacticsFor(IEnumerable<AttackTechnique> techniques)
    {
        var hit = techniques.SelectMany(t => t.Tactics).ToHashSet(StringComparer.Ordinal);
        return [.. Tactics.Where(t => hit.Contains(t.Id)).Select(t => t.Id)];
    }

    /// <summary>
    /// Build the ATT&amp;CK view: what the rule set can see, and what it has seen.
    /// </summary>
    /// <remarks>
    /// The rule set supplies coverage; the findings supply detections. The
    /// difference between the two is the point of the whole view: a technique
    /// with rules but no detections is coverage, and a technique with neither is
    /// a gap.
    /// </remarks>
    public static AttackCoverage Coverage(EngineInfo engine, IEnumerable<SuiteEvent> findings)
    {
        var byTechnique = new Dictionary<string, AttackCell>(StringComparer.Ordinal);

        AttackCell Cell(string id)
        {
            if (!byTechnique.TryGetValue(id, out var cell))
                byTechnique[id] = cell = new AttackCell { Technique = Describe(id) };
            return cell;
        }

        // What the loaded rules claim to cover.
        foreach (var rule in engine.Rules)
        {
            foreach (var technique in Resolve(rule.Meta, rule.Namespace))
            {
                var cell = Cell(technique.Id);
                if (!cell.Rules.Contains(rule.Rule)) cell.Rules.Add(rule.Rule);
            }
        }

        // What has actually fired.
        foreach (var finding in findings)
        {
            if (!finding.IsMatch) continue;

            var severity = Severity.Normalise(finding.Severity);
            var seenHere = new HashSet<string>(StringComparer.Ordinal);

            foreach (var match in finding.Matches ?? [])
            {
                foreach (var technique in Resolve(match))
                {
                    // One finding counts once per technique, however many of its
                    // rules mapped to it.
                    if (!seenHere.Add(technique.Id)) continue;

                    var cell = Cell(technique.Id);
                    cell.Detections++;
                    cell.Severities[severity] = cell.Severities.GetValueOrDefault(severity) + 1;
                }
            }
        }

        var columns = new List<AttackColumn>(Tactics.Length);
        foreach (var (tacticId, tacticName) in Tactics)
        {
            var cells = byTechnique.Values
                .Where(c => c.Technique.Tactics.Contains(tacticId))
                .OrderByDescending(c => c.Detections)
                .ThenBy(c => c.Technique.Id, StringComparer.Ordinal)
                .ToList();

            columns.Add(new AttackColumn
            {
                Id = tacticId,
                Name = tacticName,
                Techniques = cells,
                Covered = cells.Count(c => c.Rules.Count > 0),
                Detected = cells.Count(c => c.Detections > 0),
            });
        }

        return new AttackCoverage
        {
            Tactics = columns,
            TechniqueCount = byTechnique.Count,
            CoveredTechniques = byTechnique.Values.Count(c => c.Rules.Count > 0),
            DetectedTechniques = byTechnique.Values.Count(c => c.Detections > 0),
            TotalDetections = byTechnique.Values.Sum(c => c.Detections),

            // Named so the UI can say "no rule covers this" rather than
            // rendering an empty column and leaving the reader to infer it.
            UncoveredTactics =
            [
                .. columns.Where(c => c.Covered == 0).Select(c => c.Name),
            ],
        };
    }
}

public sealed class AttackTechnique
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("tactics")] public List<string> Tactics { get; init; } = [];

    /// <summary>False when the embedded table has no entry for this id.</summary>
    [JsonPropertyName("known")] public bool Known { get; init; }

    [JsonPropertyName("url")] public string Url { get; init; } = "";
}

public sealed class AttackCell
{
    [JsonPropertyName("technique")] public AttackTechnique Technique { get; init; } = new();

    /// <summary>Loaded rules that map to this technique.</summary>
    [JsonPropertyName("rules")] public List<string> Rules { get; init; } = [];

    /// <summary>Findings that fired on it.</summary>
    [JsonPropertyName("detections")] public int Detections { get; set; }

    [JsonPropertyName("severities")] public Dictionary<string, int> Severities { get; init; } = [];
}

public sealed class AttackColumn
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("techniques")] public List<AttackCell> Techniques { get; init; } = [];

    /// <summary>Techniques in this tactic that at least one rule covers.</summary>
    [JsonPropertyName("covered")] public int Covered { get; init; }

    [JsonPropertyName("detected")] public int Detected { get; init; }
}

public sealed class AttackCoverage
{
    [JsonPropertyName("tactics")] public List<AttackColumn> Tactics { get; init; } = [];
    [JsonPropertyName("technique_count")] public int TechniqueCount { get; init; }
    [JsonPropertyName("covered_techniques")] public int CoveredTechniques { get; init; }
    [JsonPropertyName("detected_techniques")] public int DetectedTechniques { get; init; }
    [JsonPropertyName("total_detections")] public int TotalDetections { get; init; }

    /// <summary>Tactics no loaded rule covers at all. The gaps, stated plainly.</summary>
    [JsonPropertyName("uncovered_tactics")] public List<string> UncoveredTactics { get; init; } = [];
}
