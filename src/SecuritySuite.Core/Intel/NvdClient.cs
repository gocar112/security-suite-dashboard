using System.Diagnostics;
using System.Text.Json;
using SecuritySuite.Net;
using SecuritySuite.Storage;

namespace SecuritySuite.Intel;

/// <summary>
/// NVD CVE API 2.0 adapter with a local cache.
/// </summary>
/// <remarks>
/// <para>
/// Unlike VirusTotal, NVD needs no credential: a key only raises the rate
/// limit, from 5 requests per 30 seconds to 50. Set <c>NVD_API_KEY</c> in
/// <c>.env</c> to use one.
/// </para>
/// <para>
/// The API is offset paginated and the full corpus is around 390,000 records,
/// so this never tries to mirror it. It syncs a trailing window of recently
/// modified CVEs and fetches individual records on demand.
/// </para>
/// </remarks>
public sealed class NvdClient
{
    public const string BaseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    private const int MaxResultsPerPage = 2000;

    /// <summary>NVD rejects a <c>lastMod</c> range wider than this.</summary>
    private const int MaxWindowDays = 120;

    /// <summary>NVD CVSS severity to the suite's own scale.</summary>
    private static readonly Dictionary<string, string> SeverityMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CRITICAL"] = Severity.Critical,
        ["HIGH"] = Severity.High,
        ["MEDIUM"] = Severity.Medium,
        ["LOW"] = Severity.Low,
        ["NONE"] = Severity.Info,
    };

    /// <summary>Reference tags that mark a reference as pointing at a fix.</summary>
    private static readonly HashSet<string> PatchTags =
        new(["Patch", "Vendor Advisory", "Mitigation"], StringComparer.OrdinalIgnoreCase);

    private readonly string _apiKey;
    private readonly double _timeout;
    private readonly RateLimiter _limiter;
    private readonly Lock _gate = new();
    private bool _syncing;

    public string CacheDir { get; }
    public string LookupsDir { get; }
    public string IndexPath { get; }
    public string FeedPath { get; }
    public string? LastError { get; private set; }

    public NvdClient(string cacheDir, string apiKey = "", double timeoutSeconds = 30)
    {
        CacheDir = cacheDir;
        LookupsDir = Path.Combine(cacheDir, "lookups");
        IndexPath = Path.Combine(cacheDir, "index.json");
        FeedPath = Path.Combine(cacheDir, "cves.ndjson");

        _apiKey = (apiKey.Length > 0 ? apiKey
            : Environment.GetEnvironmentVariable("NVD_API_KEY") ?? "").Trim();
        _timeout = timeoutSeconds;

        // Stay comfortably under both published limits rather than at them: a
        // 429 from NVD costs more than the extra second.
        _limiter = new RateLimiter(_apiKey.Length > 0 ? 0.8 : 6.5);

        Directory.CreateDirectory(CacheDir);
        Directory.CreateDirectory(LookupsDir);
    }

    public bool HasApiKey => _apiKey.Length > 0;

    // ------------------------------------------------------------------ http
    private Dictionary<string, string> Headers() =>
        HasApiKey ? new Dictionary<string, string> { ["apiKey"] = _apiKey } : [];

    private async Task<JsonDocument> GetAsync(IEnumerable<KeyValuePair<string, object?>> parameters,
                                              CancellationToken token)
    {
        await _limiter.WaitAsync(token).ConfigureAwait(false);
        return await SuiteHttp.GetJsonAsync(
            BaseUrl + "?" + SuiteHttp.Query(parameters), Headers(), _timeout, token).ConfigureAwait(false);
    }

    /// <summary>NVD wants ISO-8601 with milliseconds and no timezone suffix.</summary>
    private static string Stamp(DateTimeOffset when) =>
        when.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000");

    // --------------------------------------------------------------- queries
    /// <summary>One CVE by id, cached on disk after the first fetch.</summary>
    public async Task<CveRecord> FetchCveAsync(string cveId, bool useCache = true,
                                               CancellationToken token = default)
    {
        cveId = cveId.Trim().ToUpperInvariant();
        if (!cveId.StartsWith("CVE-", StringComparison.Ordinal))
            return CveRecord.Failure(cveId, "not a CVE id: " + cveId);

        var cached = Path.Combine(LookupsDir, cveId + ".json");
        if (useCache && File.Exists(cached))
        {
            try
            {
                var record = JsonSerializer.Deserialize<CveRecord>(
                    File.ReadAllText(cached), SuiteJson.Options);

                // A record written before the shape changed looks valid but has
                // no patch references, so treat it as a miss and re-fetch.
                if (record is not null && record.Schema == CveRecord.CurrentSchema)
                {
                    record.Cached = true;
                    return record;
                }
            }
            catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
            {
                // Unreadable cache entry: fall through and fetch.
            }
        }

        JsonDocument payload;
        try
        {
            payload = await GetAsync([new("cveId", cveId)], token).ConfigureAwait(false);
        }
        catch (HttpFailure exc)
        {
            LastError = exc.Message;
            return CveRecord.Failure(cveId, exc.Message);
        }

        using (payload)
        {
            if (!payload.RootElement.TryGetProperty("vulnerabilities", out var items) ||
                items.GetArrayLength() == 0)
            {
                return CveRecord.Failure(cveId, "not found");
            }

            var record = Normalise(items[0]);
            try
            {
                File.WriteAllText(cached, JsonSerializer.Serialize(record, SuiteJson.Pretty));
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                // A cache we cannot write is a slow lookup, not a failed one.
            }
            record.Cached = false;
            return record;
        }
    }

    /// <summary>Keyword search against the live API; NVD does the matching.</summary>
    public async Task<CveSearchResult> SearchAsync(string keyword, int limit = 20,
                                                   CancellationToken token = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        try
        {
            using var payload = await GetAsync(
            [
                new("keywordSearch", keyword),
                new("resultsPerPage", limit),
                new("startIndex", 0),
            ], token).ConfigureAwait(false);

            var root = payload.RootElement;
            return new CveSearchResult
            {
                Query = keyword,
                Total = root.TryGetProperty("totalResults", out var total) ? total.GetInt32() : 0,
                Results = root.TryGetProperty("vulnerabilities", out var items)
                    ? [.. items.EnumerateArray().Select(Normalise)]
                    : [],
            };
        }
        catch (HttpFailure exc)
        {
            LastError = exc.Message;
            return new CveSearchResult { Query = keyword, Error = exc.Message };
        }
    }

    /// <summary>Known-exploited CVEs only, using NVD's valueless <c>hasKev</c> flag.</summary>
    public async Task<CveSearchResult> KevAsync(int limit = 50, CancellationToken token = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        try
        {
            using var payload = await GetAsync(
            [
                // True emits a bare "hasKev". Sent as hasKev=true it is
                // rejected; sent as hasKev= it is silently ignored, which is
                // how this filter once appeared to work while doing nothing.
                new("hasKev", true),
                new("resultsPerPage", limit),
                new("startIndex", 0),
            ], token).ConfigureAwait(false);

            var root = payload.RootElement;
            return new CveSearchResult
            {
                Query = "hasKev",
                Total = root.TryGetProperty("totalResults", out var total) ? total.GetInt32() : 0,
                Results = root.TryGetProperty("vulnerabilities", out var items)
                    ? [.. items.EnumerateArray().Select(Normalise)]
                    : [],
            };
        }
        catch (HttpFailure exc)
        {
            LastError = exc.Message;
            return new CveSearchResult { Query = "hasKev", Error = exc.Message };
        }
    }

    // ------------------------------------------------------------------ sync
    /// <summary>Pull CVEs modified in the trailing window into the local cache.</summary>
    public async Task<NvdSyncIndex> SyncAsync(int days = 7, int maxRecords = 4000,
                                              CancellationToken token = default)
    {
        lock (_gate)
        {
            if (_syncing) return NvdSyncIndex.Failure("a sync is already running");
            _syncing = true;
        }
        try
        {
            return await RunSyncAsync(days, maxRecords, token).ConfigureAwait(false);
        }
        finally
        {
            lock (_gate) _syncing = false;
        }
    }

    private async Task<NvdSyncIndex> RunSyncAsync(int days, int maxRecords, CancellationToken token)
    {
        days = Math.Clamp(days, 1, MaxWindowDays);
        var end = DateTimeOffset.UtcNow;
        var start = end.AddDays(-days);
        var watch = Stopwatch.StartNew();
        var startedAt = DateTimeOffset.Now;

        var records = new List<CveRecord>();
        var startIndex = 0;
        var total = 0;
        var pages = 0;

        while (true)
        {
            JsonDocument payload;
            try
            {
                payload = await GetAsync(
                [
                    new("lastModStartDate", Stamp(start)),
                    new("lastModEndDate", Stamp(end)),
                    new("resultsPerPage", MaxResultsPerPage),
                    new("startIndex", startIndex),
                ], token).ConfigureAwait(false);
            }
            catch (HttpFailure exc)
            {
                LastError = exc.Message;

                // Keep a partial result rather than losing several pages of
                // work to one failed request near the end of a long sync.
                if (records.Count > 0) break;
                return NvdSyncIndex.Failure(exc.Message);
            }

            using (payload)
            {
                pages++;
                var root = payload.RootElement;
                if (root.TryGetProperty("totalResults", out var totalElement))
                    total = totalElement.GetInt32();

                if (!root.TryGetProperty("vulnerabilities", out var batch) ||
                    batch.GetArrayLength() == 0)
                {
                    break;
                }

                records.AddRange(batch.EnumerateArray().Select(Normalise));
                startIndex += batch.GetArrayLength();
            }

            if (startIndex >= Math.Min(total, maxRecords) || records.Count >= maxRecords) break;
        }

        LastError = null;
        return WriteCache(records, start, end, total > 0 ? total : records.Count,
            pages, startedAt, watch.Elapsed);
    }

    private NvdSyncIndex WriteCache(List<CveRecord> records, DateTimeOffset start, DateTimeOffset end,
                                    int total, int pages, DateTimeOffset startedAt, TimeSpan elapsed)
    {
        var severities = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var record in records)
        {
            var key = record.Severity;
            severities[key] = severities.GetValueOrDefault(key) + 1;
        }

        try
        {
            using var writer = new StreamWriter(FeedPath, append: false);
            foreach (var record in records)
                writer.WriteLine(JsonSerializer.Serialize(record, SuiteJson.Options));
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return NvdSyncIndex.Failure("could not write cache: " + exc.Message);
        }

        var index = new NvdSyncIndex
        {
            LastSync = startedAt.ToString("yyyy-MM-ddTHH:mm:sszzz"),
            WindowStart = start.ToLocalTime().ToString("yyyy-MM-ddTHH:mm:sszzz"),
            WindowEnd = end.ToLocalTime().ToString("yyyy-MM-ddTHH:mm:sszzz"),
            WindowDays = (int)(end - start).TotalDays,
            Cached = records.Count,
            TotalInWindow = total,
            Truncated = records.Count < total,
            PagesFetched = pages,
            BySeverity = severities,
            LastSyncUsedKey = HasApiKey,
            ElapsedSeconds = Math.Round(elapsed.TotalSeconds, 1),
        };

        try
        {
            File.WriteAllText(IndexPath, JsonSerializer.Serialize(index, SuiteJson.Pretty));
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            // The feed is what matters; the index is a report about it.
        }
        return index;
    }

    // ---------------------------------------------------------------- status
    public List<CveRecord> CachedRecords(int limit = 100, string severity = "")
    {
        if (!File.Exists(FeedPath)) return [];

        var records = new List<CveRecord>();
        try
        {
            using var reader = new StreamReader(
                new FileStream(FeedPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            while (reader.ReadLine() is { } line)
            {
                if (line.Length == 0) continue;
                CveRecord? record;
                try { record = JsonSerializer.Deserialize<CveRecord>(line, SuiteJson.Options); }
                catch (JsonException) { continue; }
                if (record is null) continue;

                if (severity.Length > 0 && severity != "all" && record.Severity != severity) continue;
                records.Add(record);
            }
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return [];
        }

        return [.. records.OrderByDescending(r => r.Score ?? 0).Take(limit)];
    }

    public NvdStatus Status()
    {
        NvdSyncIndex? sync = null;
        if (File.Exists(IndexPath))
        {
            try
            {
                sync = JsonSerializer.Deserialize<NvdSyncIndex>(
                    File.ReadAllText(IndexPath), SuiteJson.Options);
            }
            catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
            {
                sync = null;
            }
        }

        var lookups = 0;
        try { lookups = Directory.EnumerateFiles(LookupsDir, "*.json").Count(); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }

        // The last sync's report is nested rather than merged into this object.
        // Merging is how a stale "api_key": false from a months-old sync once
        // reported a configured key as absent; nesting makes that impossible
        // rather than merely fixed.
        return new NvdStatus
        {
            BaseUrl = BaseUrl,
            CacheDir = CacheDir,
            ApiKey = HasApiKey,
            RateLimit = HasApiKey ? "50/30s (key)" : "5/30s (no key)",
            TlsBundle = SuiteHttp.TrustStore,
            Syncing = Syncing,
            LookupsCached = lookups,
            LastError = LastError,
            Sync = sync,
        };
    }

    public bool Syncing
    {
        get { lock (_gate) return _syncing; }
    }

    // ------------------------------------------------------------- normalise
    /// <summary>Flatten one NVD record into the compact shape the dashboard consumes.</summary>
    public static CveRecord Normalise(JsonElement entry)
    {
        var cve = entry.TryGetProperty("cve", out var inner) ? inner : entry;

        double? score = null;
        string severity = "", vector = "", version = "";

        if (cve.TryGetProperty("metrics", out var metrics))
        {
            // Newest CVSS first: a record carrying both v4 and v2 should be
            // scored by v4.
            foreach (var key in (string[])["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"])
            {
                if (!metrics.TryGetProperty(key, out var items) || items.GetArrayLength() == 0) continue;

                var first = items[0];
                if (first.TryGetProperty("cvssData", out var data))
                {
                    if (data.TryGetProperty("baseScore", out var s) && s.ValueKind == JsonValueKind.Number)
                        score = s.GetDouble();
                    severity = Text(data, "baseSeverity");
                    vector = Text(data, "vectorString");
                    version = Text(data, "version");
                }
                if (severity.Length == 0) severity = Text(first, "baseSeverity");
                if (version.Length == 0) version = key;
                break;
            }
        }

        var description = "";
        if (cve.TryGetProperty("descriptions", out var descriptions))
        {
            foreach (var item in descriptions.EnumerateArray())
            {
                if (Text(item, "lang") != "en") continue;
                description = Text(item, "value");
                break;
            }
        }

        var weaknesses = new List<string>();
        if (cve.TryGetProperty("weaknesses", out var weaknessList))
        {
            foreach (var weakness in weaknessList.EnumerateArray())
            {
                if (!weakness.TryGetProperty("description", out var items)) continue;
                foreach (var item in items.EnumerateArray())
                {
                    var value = Text(item, "value");
                    if (value.StartsWith("CWE-", StringComparison.Ordinal) && !weaknesses.Contains(value))
                        weaknesses.Add(value);
                }
            }
        }

        var patchRefs = new List<PatchReference>();
        var referenceCount = 0;
        if (cve.TryGetProperty("references", out var references))
        {
            referenceCount = references.GetArrayLength();
            foreach (var reference in references.EnumerateArray())
            {
                if (!reference.TryGetProperty("tags", out var tags)) continue;

                var matched = tags.EnumerateArray()
                    .Select(t => t.GetString() ?? "")
                    .Where(PatchTags.Contains)
                    .OrderBy(t => t, StringComparer.Ordinal)
                    .ToList();
                if (matched.Count == 0) continue;

                patchRefs.Add(new PatchReference { Url = Text(reference, "url"), Tags = matched });
            }
        }

        var upper = severity.ToUpperInvariant();
        var exploitAdd = Text(cve, "cisaExploitAdd");

        return new CveRecord
        {
            Id = Text(cve, "id"),
            Published = Text(cve, "published"),
            LastModified = Text(cve, "lastModified"),
            Status = Text(cve, "vulnStatus"),
            Score = score,
            CvssSeverity = upper,
            Severity = SeverityMap.GetValueOrDefault(upper, Severity.Info),
            CvssVersion = version,
            Vector = vector,
            Cwe = [.. weaknesses.Take(4)],
            Description = description.Length > 600 ? description[..600] : description,
            References = referenceCount,
            PatchRefs = [.. patchRefs.Take(8)],
            Kev = exploitAdd.Length > 0,
            KevName = Text(cve, "cisaVulnerabilityName"),
            ExploitAdded = exploitAdd,
            KevRequiredAction = Text(cve, "cisaRequiredAction"),
            KevActionDue = Text(cve, "cisaActionDue"),
            Source = Text(cve, "sourceIdentifier"),
        };

        static string Text(JsonElement element, string name) =>
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? ""
                : "";
    }
}
