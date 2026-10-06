using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecuritySuite.Storage;

namespace SecuritySuite.Intel;

/// <summary>
/// What to do about a finding, from authoritative sources where they exist.
/// </summary>
/// <remarks>
/// <para>
/// Two kinds of finding need two kinds of answer.
/// </para>
/// <para>
/// A finding carrying a CVE — every generated rule does — already has an
/// authoritative answer written down. CISA's Known Exploited Vulnerabilities
/// catalogue publishes <c>cisaRequiredAction</c>, the mandated remediation
/// text, with a due date; NVD carries vendor references tagged Patch or Vendor
/// Advisory. Neither needs to be invented or searched for.
/// </para>
/// <para>
/// A malware finding has neither. What it has is a response shape, which is
/// what <see cref="Playbooks"/> holds.
/// </para>
/// <para>
/// Nothing here is generated text presented as advice. Where the answer is
/// known it is quoted from its source with attribution; where it is not, the
/// playbook names the class of response and leaves the judgement to the
/// analyst.
/// </para>
/// </remarks>
public sealed partial class GuidanceService(string cacheDir, NvdClient? nvd = null)
{
    /// <summary>Bumped when <see cref="CveGuidance"/> changes shape.</summary>
    private const int Schema = 2;

    [GeneratedRegex(@"CVE-\d{4}-\d{4,7}", RegexOptions.IgnoreCase, 2000)]
    private static partial Regex CveId();

    public string CacheDir { get; } = cacheDir;

    private readonly Lock _gate = new();
    private bool _ready;

    private void EnsureCacheDir()
    {
        lock (_gate)
        {
            if (_ready) return;
            Directory.CreateDirectory(CacheDir);
            _ready = true;
        }
    }

    // ------------------------------------------------------------------- cves
    /// <summary>CVEs named by the rules that fired, or extracted from the file.</summary>
    public static List<string> CveIds(SuiteEvent finding)
    {
        var found = new List<string>();

        foreach (var match in finding.Matches ?? [])
        {
            var value = match.Meta.GetValueOrDefault("cve") ?? "";
            foreach (var hit in CveId().Matches(value).Cast<Match>())
            {
                var cve = hit.Value.ToUpperInvariant();
                if (!found.Contains(cve)) found.Add(cve);
            }
        }

        // The file's own contents can name a CVE the rules did not.
        var iocs = finding.GetExtra<IocSummary>("iocs");
        foreach (var indicator in iocs?.Indicators ?? [])
        {
            if (indicator.Type != IocKind.Cve) continue;
            var cve = indicator.Value.ToUpperInvariant();
            if (cve.Length > 0 && !found.Contains(cve)) found.Add(cve);
        }

        return [.. found.Take(8)];
    }

    private async Task<CveGuidance> CveDetailAsync(string cveId, CancellationToken token)
    {
        EnsureCacheDir();
        var cached = Path.Combine(CacheDir, cveId + ".json");

        if (File.Exists(cached))
        {
            try
            {
                var detail = JsonSerializer.Deserialize<CveGuidance>(
                    File.ReadAllText(cached), SuiteJson.Options);
                if (detail is not null && detail.Schema == Schema) return detail;
            }
            catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
            {
                // Fall through and re-fetch.
            }
        }

        if (nvd is null) return CveGuidance.Failure(cveId, "no NVD client configured");

        CveRecord record;
        try
        {
            record = await nvd.FetchCveAsync(cveId, token: token).ConfigureAwait(false);
        }
        catch (Net.HttpFailure exc)
        {
            return CveGuidance.Failure(cveId, exc.Message);
        }

        if (record.Failed) return CveGuidance.Failure(cveId, record.Error ?? "lookup failed");

        var result = new CveGuidance
        {
            Schema = Schema,
            Id = cveId,
            Kev = record.Kev,
            KevName = record.KevName,
            RequiredAction = record.KevRequiredAction,
            ActionDue = record.KevActionDue,
            ExploitAdded = record.ExploitAdded,
            PatchRefs = [.. record.PatchRefs.Take(8)],
            NvdUrl = record.NvdUrl,
            FetchedAt = EventStore.NowIso(),
        };

        try
        {
            File.WriteAllText(cached, JsonSerializer.Serialize(result, SuiteJson.Pretty));
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            // A cache we cannot write costs a lookup next time, nothing more.
        }
        return result;
    }

    // -------------------------------------------------------------- playbooks
    /// <summary>
    /// Rule name, then rule file, then tag, then the default.
    /// </summary>
    /// <remarks>
    /// Rule names are consulted before anything else because a rule's subject
    /// is a better guide than its category. <c>windows_threats</c> is a
    /// catch-all holding ransom-note, credential-dumping and PowerShell rules
    /// alike, so matching on that file name would give all three the same
    /// generic advice.
    /// </remarks>
    public static Playbook PlaybookFor(SuiteEvent finding)
    {
        var namespaces = new List<string>();
        var tags = new List<string>();
        var names = new List<string>();

        foreach (var match in finding.Matches ?? [])
        {
            if (match.Namespace.Length > 0) namespaces.Add(match.Namespace.ToLowerInvariant());
            tags.AddRange(match.Tags.Select(t => t.ToLowerInvariant()));
            if (match.Rule.Length > 0) names.Add(match.Rule.ToLowerInvariant());
        }
        names.AddRange((finding.RuleNames ?? []).Select(r => r.ToLowerInvariant()));

        foreach (var (keyword, playbook) in Playbooks.ByRuleKeyword)
        {
            if (names.Any(name => name.Contains(keyword, StringComparison.Ordinal)))
                return playbook.With("rule:*" + keyword + "*");
        }

        foreach (var key in namespaces)
        {
            if (Playbooks.ByNamespace.TryGetValue(key, out var playbook))
                return playbook.With("namespace:" + key);
        }

        foreach (var key in tags)
        {
            if (Playbooks.ByTag.TryGetValue(key, out var playbook))
                return playbook.With("tag:" + key);
        }

        return Playbooks.Default.With("default");
    }

    // ------------------------------------------------------------------- main
    public async Task<FindingGuidance> ForFindingAsync(SuiteEvent finding,
                                                       CancellationToken token = default)
    {
        var cves = CveIds(finding);
        var details = new List<CveGuidance>(cves.Count);
        foreach (var cve in cves)
            details.Add(await CveDetailAsync(cve, token).ConfigureAwait(false));

        var kev = details.Where(d => d.Kev).ToList();

        return new FindingGuidance
        {
            Finding = finding.Id,
            FileName = finding.FileName,
            Severity = finding.Severity,
            Playbook = PlaybookFor(finding),
            Cves = details,
            KevCount = kev.Count,
            RequiredActions =
            [
                .. kev.Where(d => d.RequiredAction.Length > 0)
                      .Select(d => new RequiredAction(d.Id, d.RequiredAction, d.ActionDue)),
            ],
            PatchRefs = [.. details.SelectMany(d => d.PatchRefs).Take(12)],
            GeneratedAt = EventStore.NowIso(),
        };
    }
}

/// <summary>The authoritative part of the answer, for one CVE.</summary>
public sealed class CveGuidance
{
    [JsonPropertyName("schema")] public int Schema { get; set; }
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("kev")] public bool Kev { get; set; }
    [JsonPropertyName("kev_name")] public string KevName { get; set; } = "";

    /// <summary>CISA's mandated remediation, quoted verbatim.</summary>
    [JsonPropertyName("required_action")] public string RequiredAction { get; set; } = "";

    [JsonPropertyName("action_due")] public string ActionDue { get; set; } = "";
    [JsonPropertyName("exploit_added")] public string ExploitAdded { get; set; } = "";
    [JsonPropertyName("patch_refs")] public List<PatchReference> PatchRefs { get; set; } = [];
    [JsonPropertyName("nvd_url")] public string NvdUrl { get; set; } = "";
    [JsonPropertyName("fetched_at")] public string FetchedAt { get; set; } = "";

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }

    public static CveGuidance Failure(string id, string error) => new()
    {
        Id = id,
        Error = error,
        NvdUrl = "https://nvd.nist.gov/vuln/detail/" + id,
    };
}

public sealed record RequiredAction(
    [property: JsonPropertyName("cve")] string Cve,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("due")] string Due);

public sealed class FindingGuidance
{
    [JsonPropertyName("finding")] public string Finding { get; set; } = "";
    [JsonPropertyName("file_name")] public string? FileName { get; set; }
    [JsonPropertyName("severity")] public string? Severity { get; set; }
    [JsonPropertyName("playbook")] public Playbook Playbook { get; set; } = new();
    [JsonPropertyName("cves")] public List<CveGuidance> Cves { get; set; } = [];
    [JsonPropertyName("kev_count")] public int KevCount { get; set; }
    [JsonPropertyName("required_actions")] public List<RequiredAction> RequiredActions { get; set; } = [];
    [JsonPropertyName("patch_refs")] public List<PatchReference> PatchRefs { get; set; } = [];
    [JsonPropertyName("generated_at")] public string GeneratedAt { get; set; } = "";
}
