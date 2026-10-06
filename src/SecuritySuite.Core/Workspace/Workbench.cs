using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecuritySuite.Configuration;
using SecuritySuite.Detection;
using SecuritySuite.Remediation;
using SecuritySuite.Storage;

namespace SecuritySuite.Workspace;

/// <summary>
/// Local workbench tools: paste-to-analyse, evidence import, policy and the
/// reviewed domain list.
/// </summary>
/// <remarks>
/// Imported evidence is never an executable command. Everything arriving here
/// is treated as data to parse and validate — a Suricata record's file paths
/// and addresses are checked, not trusted, and nothing imported is ever run or
/// used to decide what to touch on disk.
/// </remarks>
public sealed partial class Workbench
{
    /// <summary>Paste and import both cap at this, so one request cannot hold the server.</summary>
    private const int MaxTextBytes = 48_000;

    private const int MaxEveRecords = 100;
    private const int MaxDomains = 1000;
    private const int MaxFingerprints = 10_000;

    [GeneratedRegex(@"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.None, 2000)]
    private static partial Regex DomainLabel();

    private readonly SuiteConfig _cfg;
    private readonly YaraEngine _engine;
    private readonly EventStore _store;
    private readonly Lock _gate = new();
    private readonly HashSet<string> _imported = new(StringComparer.Ordinal);

    public string PolicyPath { get; }
    public string DomainsPath { get; }
    public NativeAvStatus NativeAv { get; private set; } = new();

    public Workbench(SuiteConfig cfg, YaraEngine engine, EventStore store)
    {
        _cfg = cfg;
        _engine = engine;
        _store = store;

        var sidecarDir = Path.GetDirectoryName(Path.GetFullPath(cfg.TriageFile)) ?? ".";
        PolicyPath = Path.Combine(sidecarDir, "response-policy.json");
        DomainsPath = Path.Combine(sidecarDir, "blocked-domains.json");

        LoadPolicy();
    }

    // ----------------------------------------------------------------- policy
    private void LoadPolicy()
    {
        if (!File.Exists(PolicyPath)) return;
        try
        {
            var saved = JsonSerializer.Deserialize<StoredPolicy>(
                File.ReadAllText(PolicyPath), SuiteJson.Options);
            if (saved?.Enabled is not { } enabled) return;

            _cfg.AutoRemediate = enabled;

            // Forced, not read from the file. The workbench toggle is a
            // quarantine switch; persisting an action here would let a
            // hand-edited sidecar turn it into auto-delete.
            _cfg.AutoRemediateAction = RemediationActions.Quarantine;
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
        {
            // An unreadable policy leaves auto-remediation at its default, off.
        }
    }

    public ResponsePolicy Policy() => new()
    {
        Enabled = _cfg.AutoRemediate,
        Action = RemediationActions.Quarantine,
        Severity = _cfg.AutoRemediateSeverity,
        RequiresRuleOptIn = true,
        Roots = _cfg.RemediationRoots.Count > 0 ? [.. _cfg.RemediationRoots] : [.. _cfg.WatchPaths],
    };

    public ResponsePolicy SetPolicy(bool? enabled)
    {
        if (enabled is not { } value)
            throw new ArgumentException("enabled must be true or false");

        lock (_gate)
        {
            WriteAtomic(PolicyPath, new StoredPolicy { Enabled = value });
            _cfg.AutoRemediateAction = RemediationActions.Quarantine;
            _cfg.AutoRemediate = value;

            _store.Add(new SuiteEvent
            {
                EventType = "policy",
                Message = "Automatic quarantine " + (value ? "enabled" : "disabled"),
            });
            return Policy();
        }
    }

    /// <summary>
    /// Write via a temporary file and rename.
    /// </summary>
    /// <remarks>
    /// A crash part-way through a direct write leaves a truncated JSON file,
    /// and on next start an unparseable policy silently reverts to the default.
    /// Renaming over the target makes the swap atomic.
    /// </remarks>
    private static void WriteAtomic<T>(string path, T payload)
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(payload, SuiteJson.Pretty));
        File.Move(temporary, path, overwrite: true);
    }

    // ---------------------------------------------------------------- analyse
    /// <summary>
    /// Scan pasted text against the rule set without writing it anywhere.
    /// </summary>
    /// <remarks>
    /// The result says <c>executed: false</c> and <c>persisted: false</c>
    /// explicitly. An analyst pasting a suspicious command into a security tool
    /// needs to know the tool did not run it.
    /// </remarks>
    public TextAnalysis Analyze(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException("Paste text to analyze");

        var data = Encoding.UTF8.GetBytes(text);
        if (data.Length > MaxTextBytes)
            throw new ArgumentException("Text analysis accepts at most 48 KB");

        var outcome = _engine.ScanBytes(data, "<text-analysis>");
        return new TextAnalysis
        {
            Executed = false,
            Persisted = false,
            Sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(),
            Verdict = outcome.Hit ? "rule match" : "no rule match",
            Severity = outcome.Severity,
            Entropy = outcome.Entropy,
            ScanMs = outcome.ScanMs,
            Matches = outcome.Matches,
            Iocs = outcome.Iocs,
        };
    }

    // ------------------------------------------------------------- eve import
    /// <summary>
    /// Import Suricata EVE alert records, without trusting anything in them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Format: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
    /// </para>
    /// <para>
    /// Every field is validated rather than copied: addresses must parse,
    /// severity must be one of the four Suricata emits, and the signature must
    /// be a string. A record's own file paths are ignored entirely — an
    /// imported alert must never be able to name a file the suite then acts on.
    /// </para>
    /// <para>
    /// Records are fingerprinted so re-importing the same log does not multiply
    /// the alerts.
    /// </para>
    /// </remarks>
    public EveImportResult ImportEve(string? text)
    {
        if (text is null || Encoding.UTF8.GetByteCount(text) > MaxTextBytes)
            throw new ArgumentException("EVE import accepts up to 48 KB of NDJSON");

        var lines = text.Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0)
            .ToList();

        if (lines.Count == 0 || lines.Count > MaxEveRecords)
            throw new ArgumentException("Import between 1 and 100 EVE records");

        var pending = new List<(string Fingerprint, SuiteEvent Event)>();
        var skipped = 0;

        foreach (var line in lines)
        {
            JsonDocument document;
            try { document = JsonDocument.Parse(line); }
            catch (JsonException) { throw new ArgumentException("Each EVE record must be valid JSON"); }

            using (document)
            {
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                    throw new ArgumentException("Each EVE record must be an object");

                if (Text(root, "event_type") != "alert")
                {
                    skipped++;
                    continue;
                }

                if (!root.TryGetProperty("alert", out var alert) ||
                    alert.ValueKind != JsonValueKind.Object ||
                    Text(alert, "signature") is not { Length: > 0 } signature)
                {
                    throw new ArgumentException("An alert needs a signature");
                }

                var source = RequireAddress(root, "src_ip");
                var destination = RequireAddress(root, "dest_ip");

                var severity = alert.TryGetProperty("severity", out var sev) &&
                               sev.ValueKind == JsonValueKind.Number
                    ? sev.GetInt32()
                    : 3;
                if (severity is < 1 or > 4)
                    throw new ArgumentException("EVE severity must be 1, 2, 3 or 4");

                var entry = new SuiteEvent
                {
                    EventType = "ids_alert",
                    Severity = severity switch
                    {
                        1 => Storage.Severity.High,
                        2 => Storage.Severity.Medium,
                        3 => Storage.Severity.Low,
                        _ => Storage.Severity.Info,
                    },
                    Message = Clip(signature, 500),
                };
                entry.SetExtra("source", "suricata-import");
                entry.SetExtra("src_ip", source);
                entry.SetExtra("dest_ip", destination);
                entry.SetExtra("network_action", Clip(Text(alert, "action"), 40));
                entry.SetExtra("observed_at", Clip(Text(root, "timestamp"), 80));

                var fingerprint = Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes(root.GetRawText())));
                pending.Add((fingerprint, entry));
            }
        }

        var added = 0;
        var duplicate = 0;
        lock (_gate)
        {
            foreach (var (fingerprint, entry) in pending)
            {
                if (!_imported.Add(fingerprint))
                {
                    duplicate++;
                    continue;
                }
                if (_imported.Count > MaxFingerprints) _imported.Clear();
                _store.Add(entry);
                added++;
            }
        }
        return new EveImportResult { Imported = added, Duplicates = duplicate, Skipped = skipped };

        static string RequireAddress(JsonElement root, string name)
        {
            var value = Text(root, name);
            if (value.Length == 0 || !IPAddress.TryParse(value, out var parsed))
                throw new ArgumentException(name + " must be an IP address");
            return parsed.ToString();
        }

        static string Text(JsonElement element, string name) =>
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? ""
                : "";

        static string Clip(string value, int length) =>
            value.Length > length ? value[..length] : value;
    }

    // --------------------------------------------------------------- domains
    public List<string> Domains()
    {
        if (!File.Exists(DomainsPath)) return [];
        try
        {
            return JsonSerializer.Deserialize<List<string>>(
                File.ReadAllText(DomainsPath), SuiteJson.Options) ?? [];
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>
    /// Save a reviewed list of domains, one per line.
    /// </summary>
    /// <remarks>
    /// Validated hard, and <c>enforced: false</c> is returned every time. This
    /// list is a reviewed set of names to hand to whatever does the blocking;
    /// the suite does not touch DNS, hosts files or firewalls, and must not
    /// imply that it did. Addresses and local suffixes are rejected because
    /// blocking either would be a way to break the host from a text box.
    /// </remarks>
    public DomainListResult SaveDomains(string? text)
    {
        if (text is null)
            throw new ArgumentException("text must contain one domain per line");

        var domains = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var domain = raw.Trim().ToLowerInvariant().TrimEnd('.');
            if (domain.Length == 0 || domain.StartsWith('#')) continue;

            if (domain.Length > 253 || !domain.Contains('.') ||
                !domain.Split('.').All(label => DomainLabel().IsMatch(label)))
            {
                throw new ArgumentException("Use domain names only, one per line");
            }

            // An all-numeric name can parse as an address, and an address in a
            // DNS blocklist is a configuration error at best.
            if (IPAddress.TryParse(domain, out _))
                throw new ArgumentException("IP addresses do not belong in the domain list");

            if (domain.EndsWith(".local", StringComparison.Ordinal) ||
                domain.EndsWith(".localhost", StringComparison.Ordinal) ||
                domain.EndsWith(".internal", StringComparison.Ordinal))
            {
                throw new ArgumentException("Local network names cannot be blocked here");
            }
            domains.Add(domain);
        }

        if (domains.Count > MaxDomains)
            throw new ArgumentException("Limit the reviewed list to 1,000 domains");

        lock (_gate) WriteAtomic(DomainsPath, domains.ToList());
        return new DomainListResult { Domains = [.. domains], Enforced = false };
    }

    // ------------------------------------------------------------- native av
    /// <summary>
    /// Ask Windows Security Center which antivirus products are registered.
    /// </summary>
    /// <remarks>
    /// Registration is not protection. A product can be registered while
    /// disabled, with stale signatures, or excluded from the very paths this
    /// suite watches, so the result says so rather than reporting a green tick.
    /// </remarks>
    public NativeAvStatus CheckNativeAv()
    {
        if (!OperatingSystem.IsWindows())
        {
            return NativeAv = new NativeAvStatus
            {
                Status = "manual verification required",
                CheckedAt = EventStore.NowIso(),
                Detail = "Check your installed endpoint protection console.",
            };
        }

        const string command =
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct " +
            "-ErrorAction Stop | Select-Object displayName,productState | ConvertTo-Json -Compress";

        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo("powershell.exe")
                {
                    ArgumentList = { "-NoProfile", "-NonInteractive", "-Command", command },
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };
            process.Start();
            var output = process.StandardOutput.ReadToEnd();

            if (!process.WaitForExit(12_000))
            {
                try { process.Kill(entireProcessTree: true); }
                catch (Exception exc) when (exc is InvalidOperationException or NotSupportedException) { }
                throw new TimeoutException("Security Center query timed out");
            }
            if (process.ExitCode != 0) throw new InvalidOperationException("query failed");

            var products = ParseAvProducts(output);
            return NativeAv = new NativeAvStatus
            {
                Status = products.Count > 0 ? "registered products" : "none reported",
                Products = products,
                CheckedAt = EventStore.NowIso(),
                Detail = "Registration does not verify current protection or signature freshness.",
            };
        }
        catch (Exception exc) when (exc is IOException or JsonException or TimeoutException
                                        or InvalidOperationException or UnauthorizedAccessException
                                        or System.ComponentModel.Win32Exception)
        {
            return NativeAv = new NativeAvStatus
            {
                Status = "unavailable",
                CheckedAt = EventStore.NowIso(),
                Detail = "Windows Security Center did not return product information.",
            };
        }
    }

    /// <summary>
    /// Parse the Security Center result.
    /// </summary>
    /// <remarks>
    /// <c>ConvertTo-Json</c> emits a bare object when there is exactly one
    /// product and an array when there are several, so both shapes have to be
    /// handled or a single-AV host parses as a failure.
    /// </remarks>
    internal static List<AvProduct> ParseAvProducts(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return [];

        using var document = JsonDocument.Parse(output);
        var root = document.RootElement;

        var items = root.ValueKind == JsonValueKind.Array
            ? root.EnumerateArray().ToList()
            : root.ValueKind == JsonValueKind.Object ? [root] : [];

        return
        [
            .. items.Select(item => new AvProduct
            {
                Name = item.TryGetProperty("displayName", out var name) && name.ValueKind == JsonValueKind.String
                    ? name.GetString() ?? "Unknown"
                    : "Unknown",
                State = item.TryGetProperty("productState", out var state) && state.ValueKind == JsonValueKind.Number
                    ? state.GetInt64()
                    : null,
            }),
        ];
    }
}

// ----------------------------------------------------------------------- models
internal sealed class StoredPolicy
{
    [JsonPropertyName("enabled")] public bool? Enabled { get; set; }
}

public sealed class ResponsePolicy
{
    [JsonPropertyName("enabled")] public bool Enabled { get; init; }
    [JsonPropertyName("action")] public string Action { get; init; } = "";
    [JsonPropertyName("severity")] public string Severity { get; init; } = "";
    [JsonPropertyName("requires_rule_opt_in")] public bool RequiresRuleOptIn { get; init; }
    [JsonPropertyName("roots")] public List<string> Roots { get; init; } = [];
}

public sealed class TextAnalysis
{
    /// <summary>Always false, and stated so an analyst knows the paste was not run.</summary>
    [JsonPropertyName("executed")] public bool Executed { get; init; }

    /// <summary>Always false: pasted text is never written to disk.</summary>
    [JsonPropertyName("persisted")] public bool Persisted { get; init; }

    [JsonPropertyName("sha256")] public string Sha256 { get; init; } = "";
    [JsonPropertyName("verdict")] public string Verdict { get; init; } = "";
    [JsonPropertyName("severity")] public string? Severity { get; init; }
    [JsonPropertyName("entropy")] public double Entropy { get; init; }
    [JsonPropertyName("scan_ms")] public double ScanMs { get; init; }
    [JsonPropertyName("matches")] public List<RuleMatch> Matches { get; init; } = [];
    [JsonPropertyName("iocs")] public Intel.IocSummary Iocs { get; init; } = Intel.IocSummary.Empty;
}

public sealed class EveImportResult
{
    [JsonPropertyName("imported")] public int Imported { get; init; }
    [JsonPropertyName("duplicates")] public int Duplicates { get; init; }
    [JsonPropertyName("skipped")] public int Skipped { get; init; }
}

public sealed class DomainListResult
{
    [JsonPropertyName("domains")] public List<string> Domains { get; init; } = [];

    /// <summary>
    /// Always false. The suite does not touch DNS, hosts files or firewalls;
    /// this is a reviewed list to hand to whatever does.
    /// </summary>
    [JsonPropertyName("enforced")] public bool Enforced { get; init; }
}

public sealed class AvProduct
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("state")] public long? State { get; init; }
}

public sealed class NativeAvStatus
{
    [JsonPropertyName("status")] public string Status { get; init; } = "not checked";
    [JsonPropertyName("products")] public List<AvProduct> Products { get; init; } = [];
    [JsonPropertyName("checked_at")] public string? CheckedAt { get; init; }

    [JsonPropertyName("detail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; init; }
}
