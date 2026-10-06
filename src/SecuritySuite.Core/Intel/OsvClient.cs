using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecuritySuite.Net;
using SecuritySuite.Storage;

namespace SecuritySuite.Intel;

/// <summary>
/// OSV.dev adapter: vulnerability lookup by commit, package, or purl.
/// </summary>
/// <remarks>
/// <para>
/// OSV answers a different question from NVD. NVD is a catalogue you browse by
/// CVE id or keyword; OSV is an index you query with something you actually
/// <em>have</em> — a source commit, a package name and version, or a package
/// URL — and it returns the vulnerabilities affecting exactly that.
/// </para>
/// <para>
/// That makes it the natural companion to a file detector: when a scan turns up
/// a dependency manifest, a vendored library or a checked-out commit, OSV turns
/// that artifact into an answer without anyone first knowing a CVE id. No
/// credential is required.
/// </para>
/// </remarks>
public sealed partial class OsvClient
{
    public const string QueryUrl = "https://api.osv.dev/v1/query";

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.IgnoreCase, 2000)]
    private static partial Regex CommitHash();

    /// <summary>OSV severity words, as the various source databases spell them.</summary>
    private static readonly Dictionary<string, string> SeverityMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CRITICAL"] = Severity.Critical,
        ["HIGH"] = Severity.High,
        ["MODERATE"] = Severity.Medium,
        ["MEDIUM"] = Severity.Medium,
        ["LOW"] = Severity.Low,
    };

    private readonly double _timeout;
    private readonly RateLimiter _limiter = new(0.25);   // OSV is generous; stay polite
    private readonly Lock _gate = new();

    public string CacheDir { get; }
    public int Queries { get; private set; }
    public string? LastQuery { get; private set; }
    public string? LastError { get; private set; }

    public OsvClient(string cacheDir, double timeoutSeconds = 25)
    {
        CacheDir = cacheDir;
        _timeout = timeoutSeconds;
        Directory.CreateDirectory(CacheDir);
    }

    // ------------------------------------------------------------------ cache
    /// <summary>
    /// Cache path for one query, keyed by a canonical rendering of it.
    /// </summary>
    /// <remarks>
    /// The key is built from an explicitly ordered string rather than from
    /// serialised JSON, because JSON property order is an implementation
    /// detail: two equivalent queries that happened to serialise their keys in
    /// a different order would hash differently and miss each other's cache
    /// entry.
    /// </remarks>
    private string CachePath(OsvQuery query)
    {
        var canonical = string.Join("\u001f",
            "commit=" + (query.Commit ?? ""),
            "purl=" + (query.Package?.Purl ?? ""),
            "name=" + (query.Package?.Name ?? ""),
            "ecosystem=" + (query.Package?.Ecosystem ?? ""),
            "version=" + (query.Version ?? ""));

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        return Path.Combine(CacheDir, hash[..24].ToLowerInvariant() + ".json");
    }

    private async Task<OsvResult> RunAsync(OsvQuery query, bool useCache, CancellationToken token)
    {
        var cached = CachePath(query);
        if (useCache && File.Exists(cached))
        {
            try
            {
                var result = JsonSerializer.Deserialize<OsvResult>(
                    File.ReadAllText(cached), SuiteJson.Options);
                if (result is not null)
                {
                    result.Cached = true;
                    return result;
                }
            }
            catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
            {
                // Fall through and query.
            }
        }

        await _limiter.WaitAsync(token).ConfigureAwait(false);

        JsonDocument raw;
        try
        {
            raw = await SuiteHttp.PostJsonAsync(QueryUrl, query, timeoutSeconds: _timeout,
                token: token).ConfigureAwait(false);
        }
        catch (HttpFailure exc)
        {
            LastError = exc.Message;
            return new OsvResult { Error = exc.Message, Query = query };
        }

        string fetchedAt;
        using (raw)
        {
            lock (_gate)
            {
                Queries++;
                LastQuery = fetchedAt = DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:sszzz");
                LastError = null;
            }

            var vulns = raw.RootElement.TryGetProperty("vulns", out var items)
                ? items.EnumerateArray().Select(Normalise)
                       .OrderBy(v => Severity.Rank(v.Severity))
                       .ThenBy(v => v.Id, StringComparer.Ordinal)
                       .ToList()
                : [];

            var result = new OsvResult
            {
                Query = query,
                Count = vulns.Count,
                Vulns = vulns,
                FetchedAt = fetchedAt,
            };

            try
            {
                File.WriteAllText(cached, JsonSerializer.Serialize(result, SuiteJson.Pretty));
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                // A cache we cannot write is a slower lookup, not a failed one.
            }
            result.Cached = false;
            return result;
        }
    }

    // ---------------------------------------------------------------- queries
    public Task<OsvResult> QueryCommitAsync(string commit, bool useCache = true,
                                            CancellationToken token = default)
    {
        commit = commit.Trim().ToLowerInvariant();
        if (!CommitHash().IsMatch(commit))
        {
            return Task.FromResult(new OsvResult
            {
                Error = "not a 40-character git commit hash",
            });
        }
        return RunAsync(new OsvQuery { Commit = commit }, useCache, token);
    }

    public Task<OsvResult> QueryPackageAsync(string name, string ecosystem = "", string version = "",
                                             bool useCache = true, CancellationToken token = default)
    {
        var query = new OsvQuery
        {
            Package = new OsvPackage
            {
                Name = name.Trim(),
                Ecosystem = ecosystem.Trim().Length > 0 ? ecosystem.Trim() : null,
            },
            Version = version.Trim().Length > 0 ? version.Trim() : null,
        };
        return RunAsync(query, useCache, token);
    }

    public Task<OsvResult> QueryPurlAsync(string purl, bool useCache = true,
                                          CancellationToken token = default) =>
        RunAsync(new OsvQuery { Package = new OsvPackage { Purl = purl.Trim() } }, useCache, token);

    /// <summary>Dispatch on whichever identifier the caller supplied.</summary>
    public Task<OsvResult> QueryAsync(string? commit, string? purl, string? package,
                                      string? ecosystem, string? version,
                                      CancellationToken token = default)
    {
        if (!string.IsNullOrWhiteSpace(commit)) return QueryCommitAsync(commit, token: token);
        if (!string.IsNullOrWhiteSpace(purl)) return QueryPurlAsync(purl, token: token);
        if (!string.IsNullOrWhiteSpace(package))
            return QueryPackageAsync(package, ecosystem ?? "", version ?? "", token: token);

        return Task.FromResult(new OsvResult
        {
            Error = "supply one of: commit, purl, or package",
        });
    }

    // ----------------------------------------------------------------- status
    public OsvStatus Status()
    {
        var cached = 0;
        try { cached = Directory.EnumerateFiles(CacheDir, "*.json").Count(); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }

        lock (_gate)
        {
            return new OsvStatus
            {
                QueryUrl = QueryUrl,
                CacheDir = CacheDir,
                CachedQueries = cached,
                QueriesThisSession = Queries,
                LastQuery = LastQuery,
                LastError = LastError,
                TlsBundle = SuiteHttp.TrustStore,
                Credential = false,
            };
        }
    }

    // -------------------------------------------------------------- normalise
    /// <summary>Flatten one OSV record into the shape the dashboard consumes.</summary>
    public static OsvVuln Normalise(JsonElement vuln)
    {
        var severity = "";
        var vector = "";

        // OSV severity lives in a different place depending on which database
        // the record came from, so all three are tried in turn.

        // 1. database_specific.severity, which GitHub advisories populate.
        if (vuln.TryGetProperty("database_specific", out var dbSpecific) &&
            dbSpecific.ValueKind == JsonValueKind.Object)
        {
            severity = Text(dbSpecific, "severity").ToUpperInvariant();
        }

        // 2. severity[] carries CVSS vector strings. The vector is kept
        //    verbatim rather than turned into a base score: scoring a vector
        //    properly is a real calculation, and a wrong number here would be
        //    worse than no number.
        if (vuln.TryGetProperty("severity", out var severityList) &&
            severityList.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in severityList.EnumerateArray())
            {
                var candidate = Text(item, "score");
                if (!candidate.StartsWith("CVSS:", StringComparison.Ordinal)) continue;
                vector = candidate;
                break;
            }
        }

        var affected = vuln.TryGetProperty("affected", out var affectedList) &&
                       affectedList.ValueKind == JsonValueKind.Array
            ? affectedList.EnumerateArray().ToList()
            : [];

        // 3. affected[].ecosystem_specific.severity
        if (severity.Length == 0)
        {
            foreach (var entry in affected)
            {
                if (!entry.TryGetProperty("ecosystem_specific", out var eco) ||
                    eco.ValueKind != JsonValueKind.Object) continue;

                var candidate = Text(eco, "severity").ToUpperInvariant();
                if (!SeverityMap.ContainsKey(candidate)) continue;
                severity = candidate;
                break;
            }
        }

        var packages = new List<OsvAffectedPackage>();
        foreach (var entry in affected.Take(6))
        {
            if (!entry.TryGetProperty("package", out var package)) continue;
            var name = Text(package, "name");
            if (name.Length == 0) continue;

            packages.Add(new OsvAffectedPackage
            {
                Name = name,
                Ecosystem = Text(package, "ecosystem"),
                Purl = Text(package, "purl"),
            });
        }

        // A record with a CVSS vector but no severity word is at least known to
        // be scored, so it lands at medium rather than info.
        var mapped = SeverityMap.GetValueOrDefault(severity,
            vector.Length > 0 ? Severity.Medium : Severity.Info);

        return new OsvVuln
        {
            Id = Text(vuln, "id"),
            Aliases = Strings(vuln, "aliases").Take(6).ToList(),
            Summary = Clip(Text(vuln, "summary"), 300),
            Details = Clip(Text(vuln, "details"), 600),
            Published = Text(vuln, "published"),
            Modified = Text(vuln, "modified"),
            Withdrawn = Text(vuln, "withdrawn"),
            OsvSeverity = severity,
            Vector = vector,
            Severity = mapped,
            Packages = packages,
            AffectedCount = affected.Count,
            References = vuln.TryGetProperty("references", out var refs) &&
                         refs.ValueKind == JsonValueKind.Array ? refs.GetArrayLength() : 0,
        };

        static string Text(JsonElement element, string name) =>
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? ""
                : "";

        static List<string> Strings(JsonElement element, string name) =>
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
                ? [.. value.EnumerateArray().Select(v => v.GetString() ?? "").Where(s => s.Length > 0)]
                : [];

        static string Clip(string value, int length)
        {
            var trimmed = value.Trim();
            return trimmed.Length > length ? trimmed[..length] : trimmed;
        }
    }
}

// --------------------------------------------------------------------- models
public sealed class OsvPackage
{
    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; set; }

    [JsonPropertyName("ecosystem")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ecosystem { get; set; }

    [JsonPropertyName("purl")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Purl { get; set; }
}

/// <summary>The request body OSV expects. Serialised directly as the POST payload.</summary>
public sealed class OsvQuery
{
    [JsonPropertyName("commit")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Commit { get; set; }

    [JsonPropertyName("package")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OsvPackage? Package { get; set; }

    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Version { get; set; }
}

public sealed class OsvAffectedPackage
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("ecosystem")] public string Ecosystem { get; set; } = "";
    [JsonPropertyName("purl")] public string Purl { get; set; } = "";
}

public sealed class OsvVuln
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("aliases")] public List<string> Aliases { get; set; } = [];
    [JsonPropertyName("summary")] public string Summary { get; set; } = "";
    [JsonPropertyName("details")] public string Details { get; set; } = "";
    [JsonPropertyName("published")] public string Published { get; set; } = "";
    [JsonPropertyName("modified")] public string Modified { get; set; } = "";
    [JsonPropertyName("withdrawn")] public string Withdrawn { get; set; } = "";
    [JsonPropertyName("osv_severity")] public string OsvSeverity { get; set; } = "";

    /// <summary>The CVSS vector verbatim, never a score computed from it.</summary>
    [JsonPropertyName("vector")] public string Vector { get; set; } = "";

    [JsonPropertyName("severity")] public string Severity { get; set; } = Storage.Severity.Info;
    [JsonPropertyName("packages")] public List<OsvAffectedPackage> Packages { get; set; } = [];
    [JsonPropertyName("affected_count")] public int AffectedCount { get; set; }
    [JsonPropertyName("references")] public int References { get; set; }
}

public sealed class OsvResult
{
    [JsonPropertyName("query")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OsvQuery? Query { get; set; }

    [JsonPropertyName("count")] public int Count { get; set; }
    [JsonPropertyName("vulns")] public List<OsvVuln> Vulns { get; set; } = [];

    [JsonPropertyName("fetched_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FetchedAt { get; set; }

    [JsonPropertyName("cached")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Cached { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}

public sealed class OsvStatus
{
    [JsonPropertyName("source")] public string Source { get; set; } = "osv";
    [JsonPropertyName("query_url")] public string QueryUrl { get; set; } = "";
    [JsonPropertyName("cache_dir")] public string CacheDir { get; set; } = "";
    [JsonPropertyName("cached_queries")] public int CachedQueries { get; set; }
    [JsonPropertyName("queries_this_session")] public int QueriesThisSession { get; set; }
    [JsonPropertyName("last_query")] public string? LastQuery { get; set; }
    [JsonPropertyName("last_error")] public string? LastError { get; set; }
    [JsonPropertyName("tls_bundle")] public string TlsBundle { get; set; } = "";
    [JsonPropertyName("credential")] public bool Credential { get; set; }
}
