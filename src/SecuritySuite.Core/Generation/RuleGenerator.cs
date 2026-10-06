using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using libyaraNET;
using SecuritySuite.Intel;
using SecuritySuite.Net;
using SecuritySuite.Storage;

namespace SecuritySuite.Generation;

/// <summary>
/// Generate YARA rules from NVD CPE data, then throw most of them away.
/// </summary>
/// <remarks>
/// <para>
/// The temptation with a CVE feed is to turn every record into a rule and quote
/// the total. That produces a rule set nobody reviews, whose false positives
/// bury the detections that matter: alert fatigue in its purest form.
/// </para>
/// <para>
/// So this generates <em>candidates</em> from structured data and then gates
/// them hard. A candidate ships only if it came from a CPE application entry
/// with a concrete vendor and product, the product name is distinctive enough
/// to mean something on its own, at least one specific affected version is
/// known, and it fires on none of a benign corpus.
/// </para>
/// <para>
/// The gate is the product. Expect most candidates to be rejected, and read the
/// rejection tally as the useful output: it says how much of a CVE feed is
/// simply not expressible as a file-matching rule.
/// </para>
/// <para>
/// What these rules detect is <b>exposure, not compromise</b>: a vulnerable
/// component present in a scanned artifact. That drives the severity mapping.
/// Finding a vulnerable library is not the same as finding a web shell, and
/// labelling it critical would wreck the scale everything else depends on.
/// </para>
/// </remarks>
public sealed partial class RuleGenerator(NvdClient client)
{
    /// <summary>A product name shorter than this matches half the internet.</summary>
    private const int MinProductLength = 5;

    /// <summary>
    /// Product names too generic to be evidence of anything.
    /// </summary>
    /// <remarks>
    /// A rule whose distinguishing string is "server" or "library" fires on
    /// essentially every artifact that mentions software. These are the names
    /// that would generate the most rules and the least signal.
    /// </remarks>
    private static readonly HashSet<string> GenericProducts = new(StringComparer.OrdinalIgnoreCase)
    {
        "core", "server", "client", "http", "https", "web", "app", "api", "node",
        "java", "python", "linux", "windows", "macos", "android", "system", "data",
        "file", "files", "code", "test", "tests", "admin", "login", "user", "users",
        "portal", "cloud", "mobile", "desktop", "plugin", "module", "library",
        "framework", "engine", "service", "manager", "master", "agent", "common",
        "utils", "tools", "kernel", "driver", "network", "security", "database",
        "browser", "editor", "player", "reader", "viewer", "studio", "office",
        "project", "platform", "console", "gateway", "monitor", "backup", "update",
    };

    [GeneratedRegex(@"^\d+(?:\.\d+){1,3}(?:[-_.][A-Za-z0-9]{1,8})?$", RegexOptions.None, 2000)]
    private static partial Regex ConcreteVersion();

    [GeneratedRegex(@"[^A-Za-z0-9_]", RegexOptions.None, 2000)]
    private static partial Regex UnsafeNameChar();

    [GeneratedRegex(@"^[A-Za-z0-9 ._-]+$", RegexOptions.None, 2000)]
    private static partial Regex MatchableProduct();

    [GeneratedRegex("_+", RegexOptions.None, 2000)]
    private static partial Regex RepeatedUnderscore();

    // --------------------------------------------------------------- parsing
    /// <summary>
    /// Split a CPE 2.3 string into vendor, product and version.
    /// </summary>
    /// <remarks>
    /// Applications only. An OS or hardware CPE describes the platform the
    /// vulnerability needs, not a string an artifact on disk would carry, so a
    /// rule built from one would match the word "windows" and nothing useful.
    /// </remarks>
    internal static (string Vendor, string Product, string Version)? CpeParts(string criteria)
    {
        var bits = criteria.Split(':');
        if (bits.Length < 6 || bits[0] != "cpe" || bits[1] != "2.3") return null;

        var (part, vendor, product, version) = (bits[2], bits[3], bits[4], bits[5]);
        if (part != "a") return null;
        if (vendor is "" or "*" || product is "" or "*") return null;

        return (vendor, product, version);
    }

    /// <summary>Every vulnerable cpeMatch in a CVE's nested configuration tree.</summary>
    private static IEnumerable<JsonElement> WalkMatches(JsonElement cve)
    {
        if (!cve.TryGetProperty("configurations", out var configurations) ||
            configurations.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var configuration in configurations.EnumerateArray())
        {
            if (!configuration.TryGetProperty("nodes", out var nodes)) continue;
            foreach (var match in Walk(nodes)) yield return match;
        }

        static IEnumerable<JsonElement> Walk(JsonElement nodes)
        {
            if (nodes.ValueKind != JsonValueKind.Array) yield break;

            foreach (var node in nodes.EnumerateArray())
            {
                if (node.TryGetProperty("cpeMatch", out var matches) &&
                    matches.ValueKind == JsonValueKind.Array)
                {
                    foreach (var match in matches.EnumerateArray())
                    {
                        if (match.TryGetProperty("vulnerable", out var vulnerable) &&
                            vulnerable.ValueKind == JsonValueKind.True)
                        {
                            yield return match;
                        }
                    }
                }
                if (node.TryGetProperty("children", out var children))
                {
                    foreach (var match in Walk(children)) yield return match;
                }
            }
        }
    }

    private static (double? Score, string Severity) Cvss(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics)) return (null, "");

        foreach (var key in (string[])["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"])
        {
            if (!metrics.TryGetProperty(key, out var items) || items.GetArrayLength() == 0) continue;

            var first = items[0];
            double? score = null;
            var severity = "";

            if (first.TryGetProperty("cvssData", out var data))
            {
                if (data.TryGetProperty("baseScore", out var value) &&
                    value.ValueKind == JsonValueKind.Number)
                {
                    score = value.GetDouble();
                }
                if (data.TryGetProperty("baseSeverity", out var sev) &&
                    sev.ValueKind == JsonValueKind.String)
                {
                    severity = sev.GetString() ?? "";
                }
            }
            if (severity.Length == 0 && first.TryGetProperty("baseSeverity", out var fallback) &&
                fallback.ValueKind == JsonValueKind.String)
            {
                severity = fallback.GetString() ?? "";
            }
            return (score, severity);
        }
        return (null, "");
    }

    /// <summary>
    /// Severity for a vulnerable-component finding.
    /// </summary>
    /// <remarks>
    /// Exposure, not compromise. A component known to be exploited in the wild
    /// earns high. Everything else is a review item, never an interrupt — which
    /// is also why none of these can reach <see cref="Severity.Critical"/> and
    /// so none can trip an auto-remediation threshold set to critical.
    /// </remarks>
    public static string SeverityFor(double? score, bool kev)
    {
        if (kev) return Severity.High;
        if (score >= 9.0) return Severity.Medium;
        return Severity.Low;
    }

    /// <summary>Turn one CVE into zero or more candidates, one per product.</summary>
    public static List<RuleCandidate> CandidatesFromCve(JsonElement cve, int maxVersions = 12)
    {
        var cveId = cve.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "";
        if (cveId.Length == 0) return [];

        var (score, cvssSeverity) = Cvss(cve);
        var kev = cve.TryGetProperty("cisaExploitAdd", out var added) &&
                  added.ValueKind == JsonValueKind.String &&
                  !string.IsNullOrEmpty(added.GetString());

        var byProduct = new Dictionary<(string Vendor, string Product), SortedSet<string>>();

        foreach (var match in WalkMatches(cve))
        {
            var criteria = match.TryGetProperty("criteria", out var value) &&
                           value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? ""
                : "";

            if (CpeParts(criteria) is not var (vendor, product, version)) continue;

            var key = (vendor, product);
            if (!byProduct.TryGetValue(key, out var versions))
                byProduct[key] = versions = new SortedSet<string>(StringComparer.Ordinal);

            if (ConcreteVersion().IsMatch(version))
            {
                versions.Add(version);
                continue;
            }

            // A wildcard version with a bounded range still names the boundary,
            // which is a concrete string an artifact may carry.
            foreach (var bound in (string[])["versionEndExcluding", "versionEndIncluding",
                                             "versionStartIncluding", "versionStartExcluding"])
            {
                if (!match.TryGetProperty(bound, out var boundValue) ||
                    boundValue.ValueKind != JsonValueKind.String) continue;

                var text = boundValue.GetString() ?? "";
                if (ConcreteVersion().IsMatch(text)) versions.Add(text);
            }
        }

        var description = "";
        if (cve.TryGetProperty("descriptions", out var descriptions))
        {
            foreach (var item in descriptions.EnumerateArray())
            {
                if (!item.TryGetProperty("lang", out var lang) || lang.GetString() != "en") continue;
                description = item.TryGetProperty("value", out var text) ? text.GetString() ?? "" : "";
                break;
            }
        }

        var results = new List<RuleCandidate>();
        foreach (var ((vendor, product), versions) in byProduct)
        {
            if (versions.Count == 0) continue;
            results.Add(new RuleCandidate
            {
                Cve = cveId,
                Vendor = vendor,
                Product = product,
                Versions = [.. versions.Take(maxVersions)],
                Score = score,
                CvssSeverity = cvssSeverity,
                Kev = kev,
                Severity = SeverityFor(score, kev),
                Description = description.Length > 220 ? description[..220] : description,
            });
        }
        return results;
    }

    // ------------------------------------------------------------------ gate
    /// <summary>Why a candidate must not ship, or null when it may.</summary>
    public static string? RejectReason(RuleCandidate candidate)
    {
        var product = candidate.Product.Replace('_', ' ').Trim();
        var flat = product.Replace(" ", "");

        if (flat.Length < MinProductLength) return "product name too short";
        if (GenericProducts.Contains(flat) || GenericProducts.Contains(product))
            return "product name too generic";

        // A single generic word is generic; a multi-word name containing one is
        // usually still distinctive ("apache http server" is fine).
        var words = product.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 1 && GenericProducts.Contains(words[0]))
            return "product name too generic";

        if (candidate.Versions.Count == 0) return "no concrete affected version";
        if (!MatchableProduct().IsMatch(product))
            return "product name has characters that do not survive matching";

        return null;
    }

    public static string RuleName(RuleCandidate candidate)
    {
        var raw = "NVD_" + candidate.Cve.Replace('-', '_') + "_" +
                  Truncate(UnsafeNameChar().Replace(candidate.Vendor, "_"), 24) + "_" +
                  Truncate(UnsafeNameChar().Replace(candidate.Product, "_"), 32);

        return RepeatedUnderscore().Replace(raw, "_").Trim('_');

        static string Truncate(string value, int length) =>
            value.Length > length ? value[..length] : value;
    }

    /// <summary>
    /// Emit one YARA rule: the product token AND a specific version must
    /// co-occur.
    /// </summary>
    /// <remarks>
    /// The conjunction is what makes these rules survivable. A product name
    /// alone matches any document that mentions the software; a version number
    /// alone matches any file containing "2.4.1". Requiring both in the same
    /// file, under a size cap, is the narrowest claim the data supports.
    /// </remarks>
    public static string Render(RuleCandidate candidate)
    {
        var product = candidate.Product.Replace('_', ' ');
        var tags = "vulnerable_component" + (candidate.Kev ? " kev" : "");

        var strings = new List<string> { "        $p = \"" + Escape(product) + "\" nocase" };
        var multiWord = product.Contains(' ');
        if (multiWord)
        {
            strings.Add("        $p2 = \"" + Escape(product.Replace(' ', '-')) + "\" nocase");
            strings.Add("        $p3 = \"" + Escape(product.Replace(' ', '_')) + "\" nocase");
        }
        for (var i = 0; i < candidate.Versions.Count; i++)
            strings.Add("        $v" + i + " = \"" + Escape(candidate.Versions[i]) + "\"");

        var meta = new List<string>
        {
            "        description = \"Artifact appears to contain " +
                Escape(candidate.Vendor.Replace('_', ' ')) + " " + Escape(product) +
                ", affected by " + candidate.Cve + "\"",
            "        severity = \"" + candidate.Severity + "\"",
            "        cve = \"" + candidate.Cve + "\"",
            "        cvss = \"" + (candidate.Score?.ToString("0.0") ?? "n/a") + "\"",
            "        vendor = \"" + Escape(candidate.Vendor) + "\"",
            "        product = \"" + Escape(candidate.Product) + "\"",
            "        known_exploited = \"" + (candidate.Kev ? "yes" : "no") + "\"",

            // Read by the auto-remediation gate to refuse generated rules.
            "        generator = \"nvd-rulegen\"",
            "        reference = \"https://nvd.nist.gov/vuln/detail/" + candidate.Cve + "\"",
        };

        return string.Join("\n",
        [
            "rule " + RuleName(candidate) + " : " + tags,
            "{",
            "    meta:",
            string.Join("\n", meta),
            "    strings:",
            string.Join("\n", strings),
            "    condition:",
            "        " + (multiWord ? "any of ($p*)" : "$p") + " and any of ($v*) and filesize < 50MB",
            "}",
            "",
        ]);

        static string Escape(string value) => value.Replace("\\", "").Replace("\"", "");
    }

    /// <summary>
    /// Gate candidates. A rule that fires on benign data dies.
    /// </summary>
    /// <remarks>
    /// Each surviving rule is compiled on its own and run against the corpus,
    /// which is slow and deliberately so: it is the only step that tests a
    /// generated rule against reality before it is allowed to delete files.
    /// </remarks>
    public static (List<RuleCandidate> Survivors, Dictionary<string, int> Rejections) Gate(
        IEnumerable<RuleCandidate> candidates, IReadOnlyList<byte[]> benignCorpus)
    {
        var survivors = new List<RuleCandidate>();
        var rejections = new Dictionary<string, int>(StringComparer.Ordinal);
        var seenNames = new HashSet<string>(StringComparer.Ordinal);

        using var context = new YaraContext();

        foreach (var candidate in candidates)
        {
            if (RejectReason(candidate) is { } reason)
            {
                Reject(reason);
                continue;
            }

            var name = RuleName(candidate);
            if (!seenNames.Add(name))
            {
                Reject("duplicate rule name");
                continue;
            }

            var source = Render(candidate);
            Rules? compiled = null;
            try
            {
                using var compiler = new Compiler();
                compiler.AddRuleString(source);
                compiled = compiler.GetRules();
            }
            catch (Exception exc) when (exc is CompilationException or YaraException)
            {
                seenNames.Remove(name);
                Reject("does not compile: " + Truncate(exc.Message, 40));
                continue;
            }

            using (compiled)
            {
                var fired = false;
                foreach (var sample in benignCorpus)
                {
                    try
                    {
                        if (new Scanner().ScanMemory(sample, compiled).Count > 0)
                        {
                            fired = true;
                            break;
                        }
                    }
                    catch (YaraException)
                    {
                        // A rule that errors on real data is no more shippable
                        // than one that matches it.
                        fired = true;
                        break;
                    }
                }
                if (fired)
                {
                    seenNames.Remove(name);
                    Reject("fires on the benign corpus");
                    continue;
                }
            }

            candidate.Source = source;
            survivors.Add(candidate);
        }

        return (survivors, rejections);

        void Reject(string reason) => rejections[reason] = rejections.GetValueOrDefault(reason) + 1;

        static string Truncate(string value, int length) =>
            value.Length > length ? value[..length] : value;
    }

    // -------------------------------------------------------------- harvest
    /// <summary>
    /// Harvest CVEs worth generating from, build candidates, gate them.
    /// </summary>
    /// <remarks>
    /// Two passes, in order of usefulness. CISA KEV entries come first: a
    /// vulnerability known to be exploited in the wild is worth detecting even
    /// when it is old. Then recent high-severity CVEs, because a rule for a
    /// 2001 CVE in software nobody runs is shelf-filler — and the NVD corpus is
    /// ordered oldest-first, so taking the first N records yields exactly that.
    /// </remarks>
    public async Task<GenerationReport> GenerateAsync(int days = 3650, int limit = 1000,
                                                       double minScore = 7.0,
                                                       IReadOnlyList<byte[]>? benignCorpus = null,
                                                       Action<string, int, int>? progress = null,
                                                       CancellationToken token = default)
    {
        benignCorpus ??= [];
        var severity = minScore >= 9 ? "CRITICAL" : "HIGH";

        var collected = new List<JsonElement>();
        var documents = new List<JsonDocument>();
        var seenIds = new HashSet<string>(StringComparer.Ordinal);

        try
        {
            (string Label, KeyValuePair<string, object?>[] Params)[] passes =
            [
                ("known-exploited (KEV)", [new("hasKev", true)]),
                ("recent " + severity.ToLowerInvariant(),
                [
                    new("cvssV3Severity", severity),
                    new("pubStartDate", StampDaysAgo(days)),
                    new("pubEndDate", StampDaysAgo(0)),
                ]),
            ];

            foreach (var (label, parameters) in passes)
            {
                await foreach (var (document, cve) in HarvestAsync(parameters, limit * 3, label,
                                   progress, token).ConfigureAwait(false))
                {
                    documents.Add(document);
                    var cveId = cve.TryGetProperty("id", out var id) ? id.GetString() : null;
                    if (cveId is null || !seenIds.Add(cveId)) continue;
                    collected.Add(cve);
                }
                if (collected.Count >= limit * 3) break;
            }

            // KEV first, then newest first, so the limit keeps what matters most.
            var ordered = collected
                .OrderBy(c => c.TryGetProperty("cisaExploitAdd", out var added) &&
                              added.ValueKind == JsonValueKind.String ? 0 : 1)
                .ThenByDescending(c => c.TryGetProperty("published", out var published)
                    ? published.GetString() ?? ""
                    : "", StringComparer.Ordinal)
                .ToList();

            var candidates = new List<RuleCandidate>();
            foreach (var cve in ordered)
            {
                candidates.AddRange(CandidatesFromCve(cve));
                if (candidates.Count >= limit) break;
            }
            if (candidates.Count > limit) candidates = candidates.Take(limit).ToList();

            var (survivors, rejections) = Gate(candidates, benignCorpus);
            return new GenerationReport
            {
                CvesExamined = ordered.Count,
                Candidates = candidates.Count,
                Survivors = survivors.Count,
                Rejections = rejections,
                Rules = survivors,
            };
        }
        finally
        {
            foreach (var document in documents) document.Dispose();
        }
    }

    /// <summary>Page one NVD query until <paramref name="want"/> records or exhaustion.</summary>
    private async IAsyncEnumerable<(JsonDocument Document, JsonElement Cve)> HarvestAsync(
        KeyValuePair<string, object?>[] parameters, int want, string label,
        Action<string, int, int>? progress,
        [EnumeratorCancellation] CancellationToken token)
    {
        var collected = 0;
        var startIndex = 0;

        while (collected < want && !token.IsCancellationRequested)
        {
            var query = new List<KeyValuePair<string, object?>>(parameters)
            {
                new("resultsPerPage", Math.Min(2000, want - collected)),
                new("startIndex", startIndex),
            };

            JsonDocument payload;
            try
            {
                payload = await client.RawQueryAsync(query, token).ConfigureAwait(false);
            }
            catch (HttpFailure)
            {
                // Keep whatever was harvested: a failed page near the end of a
                // long run must not discard the pages that worked.
                yield break;
            }

            var root = payload.RootElement;
            var total = root.TryGetProperty("totalResults", out var totalValue)
                ? totalValue.GetInt32() : 0;

            if (!root.TryGetProperty("vulnerabilities", out var batch) ||
                batch.GetArrayLength() == 0)
            {
                payload.Dispose();
                yield break;
            }

            foreach (var item in batch.EnumerateArray())
            {
                if (!item.TryGetProperty("cve", out var cve)) continue;
                collected++;
                yield return (payload, cve);
            }

            startIndex += batch.GetArrayLength();
            progress?.Invoke(label, collected, total);
            if (startIndex >= total) yield break;
        }
    }

    private static string StampDaysAgo(int days) =>
        DateTimeOffset.UtcNow.AddDays(-days).ToString("yyyy-MM-ddTHH:mm:ss.000");

    /// <summary>Assemble a .yar file from gated survivors.</summary>
    public static string EmitFile(IReadOnlyList<RuleCandidate> survivors, string header = "")
    {
        var kev = survivors.Count(s => s.Kev);
        var builder = new StringBuilder();

        builder.AppendLine("/*");
        builder.AppendLine(" * nvd_components.yar - GENERATED, do not hand-edit.");
        builder.AppendLine(" *");
        builder.AppendLine(" * Built from NVD CPE data by SecuritySuite.Generation.RuleGenerator. Each");
        builder.AppendLine(" * rule detects a known-vulnerable component present in a scanned artifact -");
        builder.AppendLine(" * exposure, not compromise. Severity reflects that: KEV entries are high,");
        builder.AppendLine(" * everything else is medium or low, because a vulnerable library is a review");
        builder.AppendLine(" * item and not an interrupt.");
        builder.AppendLine(" *");
        builder.AppendLine(" * " + survivors.Count + " rules, " + kev + " of them for CISA KEV entries.");
        builder.AppendLine(header.Length > 0 ? " * " + header : " *");
        builder.AppendLine(" */");
        builder.AppendLine();

        foreach (var survivor in survivors) builder.AppendLine(survivor.Source);
        return builder.ToString();
    }
}

public sealed class RuleCandidate
{
    [JsonPropertyName("cve")] public string Cve { get; set; } = "";
    [JsonPropertyName("vendor")] public string Vendor { get; set; } = "";
    [JsonPropertyName("product")] public string Product { get; set; } = "";
    [JsonPropertyName("versions")] public List<string> Versions { get; set; } = [];
    [JsonPropertyName("score")] public double? Score { get; set; }
    [JsonPropertyName("cvss_severity")] public string CvssSeverity { get; set; } = "";
    [JsonPropertyName("kev")] public bool Kev { get; set; }
    [JsonPropertyName("severity")] public string Severity { get; set; } = "";
    [JsonPropertyName("description")] public string Description { get; set; } = "";

    /// <summary>The rendered rule text, set once the candidate survives the gate.</summary>
    [JsonIgnore] public string Source { get; set; } = "";
}

public sealed class GenerationReport
{
    [JsonPropertyName("cves_examined")] public int CvesExamined { get; set; }
    [JsonPropertyName("candidates")] public int Candidates { get; set; }
    [JsonPropertyName("survivors")] public int Survivors { get; set; }

    /// <summary>
    /// Why candidates were dropped, by reason.
    /// </summary>
    /// <remarks>
    /// The genuinely useful output. A run that generates 1,000 candidates and
    /// ships 931 says less than the tally saying why the other 69 could not be.
    /// </remarks>
    [JsonPropertyName("rejections")] public Dictionary<string, int> Rejections { get; set; } = [];

    [JsonIgnore] public List<RuleCandidate> Rules { get; set; } = [];
}
