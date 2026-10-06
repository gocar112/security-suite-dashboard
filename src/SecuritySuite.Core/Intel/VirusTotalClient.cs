using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecuritySuite.Net;
using SecuritySuite.Storage;

namespace SecuritySuite.Intel;

/// <summary>
/// VirusTotal adapter: hash reputation, with honest capability gating.
/// </summary>
/// <remarks>
/// <para>
/// VT Hunting (Livehunt, Retrohunt, VTDIFF) and Intelligence search are
/// Enterprise features. On the public tier every one of those endpoints returns
/// 403, so this client probes what the key can actually do and reports it,
/// rather than shipping panels that cannot work.
/// </para>
/// <para>
/// What the public tier does allow is the part that matters most here: looking
/// up a file by hash. The scanner already computes SHA-256 on every detection,
/// so a lookup turns a local YARA hit into "and here is what seventy-odd
/// engines think of this exact file" while sending nothing but the hash.
/// </para>
/// <para>
/// <b>This client never uploads files.</b> Submitting a file to VirusTotal
/// publishes it to the platform, where other users can download it. Doing that
/// automatically to whatever lands in a watched directory would leak customer
/// data, credentials in config files, and anything else that happened to
/// arrive. Hashes only. Uploading is a decision for a human, in the VT web
/// interface. There is deliberately no method here that takes a file path or a
/// byte array.
/// </para>
/// </remarks>
public sealed partial class VirusTotalClient
{
    public const string BaseUrl = "https://www.virustotal.com/api/v3";

    /// <summary>A VT account tier changes rarely, so the probe result keeps for a day.</summary>
    private static readonly TimeSpan CapabilityTtl = TimeSpan.FromHours(24);

    /// <summary>Endpoints probed to work out what the key is allowed to reach.</summary>
    private static readonly (string Name, string Path)[] Probes =
    [
        // EICAR's hash: always present, so a 403 here means the key itself is
        // the problem rather than the file being unknown.
        ("file_lookup", "/files/44d88612fea8a8f36de82e1278abb02f"),
        ("livehunt", "/intelligence/hunting_rulesets?limit=1"),
        ("retrohunt", "/intelligence/retrohunt_jobs?limit=1"),
        ("intelligence_search", "/intelligence/search?query=type%3Apeexe&limit=1"),
    ];

    private static readonly string[] EnterpriseOnly =
        ["livehunt", "retrohunt", "intelligence_search", "vtdiff"];

    [GeneratedRegex("^[0-9a-f]{32}(?:[0-9a-f]{8})?(?:[0-9a-f]{24})?$",
        RegexOptions.IgnoreCase, 2000)]
    private static partial Regex AnyHash();

    private readonly string _apiKey;
    private readonly double _timeout;

    /// <summary>Public tier allows 4 requests a minute; stay just under it.</summary>
    private readonly RateLimiter _limiter = new(15.5);

    private readonly Lock _gate = new();
    private readonly string _capabilityPath;
    private VtCapabilities? _capabilities;
    private bool _probing;

    public string CacheDir { get; }
    public int Lookups { get; private set; }
    public string? LastError { get; private set; }

    public VirusTotalClient(string apiKey, string cacheDir, double timeoutSeconds = 25)
    {
        _apiKey = (apiKey ?? "").Trim();
        _timeout = timeoutSeconds;
        CacheDir = cacheDir;
        _capabilityPath = Path.Combine(cacheDir, "_capabilities.json");
        Directory.CreateDirectory(CacheDir);
    }

    public bool Configured => _apiKey.Length > 0;

    private Dictionary<string, string> Headers() => new() { ["x-apikey"] = _apiKey };

    // ----------------------------------------------------------- capabilities
    /// <summary>
    /// What this key may actually reach.
    /// </summary>
    /// <remarks>
    /// On the public tier the probe costs four requests about fifteen seconds
    /// apart, so it must never run inside a request handler. An earlier version
    /// did, and <c>/api/intel</c> took 84 seconds on a cold start. The result is
    /// cached in memory and on disk and refreshed in the background, so the
    /// first call returns a "checking" placeholder rather than blocking.
    /// </remarks>
    public VtCapabilities Capabilities(bool refresh = false)
    {
        lock (_gate)
        {
            if (_capabilities is not null && !refresh) return _capabilities;
        }

        if (!Configured)
        {
            var none = new VtCapabilities
            {
                Configured = false,
                Tier = "none",
                Detail = "No VIRUSTOTAL_API_KEY set; the adapter makes no requests.",
            };
            lock (_gate) _capabilities = none;
            return none;
        }

        if (!refresh && LoadCachedCapabilities() is { } cached)
        {
            lock (_gate) _capabilities = cached;
            return cached;
        }

        StartProbe();
        return new VtCapabilities
        {
            Configured = true,
            Tier = "checking",
            Detail = "Probing what this key is permitted to reach (public tier allows " +
                     "4 requests/minute, so this takes about a minute).",
            RateLimit = "unknown until the probe completes",
            TlsBundle = SuiteHttp.TrustStore,
        };
    }

    /// <summary>Probe now and wait. Only for callers that cannot show a placeholder.</summary>
    public async Task<VtCapabilities> CapabilitiesBlockingAsync(CancellationToken token = default)
    {
        lock (_gate)
        {
            if (_capabilities is { Tier: not "checking" }) return _capabilities;
        }
        if (!Configured) return Capabilities();
        if (LoadCachedCapabilities() is { } cached)
        {
            lock (_gate) _capabilities = cached;
            return cached;
        }

        var result = await ProbeAsync(token).ConfigureAwait(false);
        lock (_gate) _capabilities = result;
        SaveCapabilities(result);
        return result;
    }

    private void StartProbe()
    {
        lock (_gate)
        {
            if (_probing) return;
            _probing = true;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                var result = await ProbeAsync(CancellationToken.None).ConfigureAwait(false);
                lock (_gate) _capabilities = result;
                SaveCapabilities(result);
            }
            catch (Exception exc)
            {
                // A background probe must never take the process down, and a
                // failure here only means the tier stays unknown.
                LastError = exc.Message;
            }
            finally
            {
                lock (_gate) _probing = false;
            }
        });
    }

    /// <summary>Reuse a probe from a previous run; tiers change rarely.</summary>
    private VtCapabilities? LoadCachedCapabilities()
    {
        if (!File.Exists(_capabilityPath)) return null;
        try
        {
            var data = JsonSerializer.Deserialize<VtCapabilities>(
                File.ReadAllText(_capabilityPath), SuiteJson.Options);
            if (data?.CheckedAt is null) return null;
            if (!DateTimeOffset.TryParse(data.CheckedAt, out var when)) return null;

            var age = DateTimeOffset.UtcNow - when;

            // A negative age beyond an hour means the clock moved, so the
            // record cannot be trusted to be as fresh as it claims.
            if (age > CapabilityTtl || age < TimeSpan.FromHours(-1)) return null;

            data.FromCache = true;
            return data;
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void SaveCapabilities(VtCapabilities result)
    {
        try
        {
            File.WriteAllText(_capabilityPath, JsonSerializer.Serialize(result, SuiteJson.Pretty));
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
    }

    private async Task<VtCapabilities> ProbeAsync(CancellationToken token)
    {
        var allowed = new Dictionary<string, bool>(StringComparer.Ordinal);

        foreach (var (name, path) in Probes)
        {
            await _limiter.WaitAsync(token).ConfigureAwait(false);
            try
            {
                using var _ = await SuiteHttp.GetJsonAsync(BaseUrl + path, Headers(), _timeout, token)
                    .ConfigureAwait(false);
                allowed[name] = true;
            }
            catch (HttpFailure exc)
            {
                allowed[name] = false;

                // 403 is the definitive "your tier cannot do this" answer, and
                // 401/429 say nothing about the tier either way. Anything else
                // is worth surfacing.
                if (exc.Status is not (403 or 401 or 429)) LastError = exc.Message;
            }
        }

        var enterprise = EnterpriseOnly.Any(name => allowed.GetValueOrDefault(name));
        return new VtCapabilities
        {
            Configured = true,
            Tier = enterprise ? "enterprise" : "public",
            Allowed = allowed,
            HuntingAvailable = allowed.GetValueOrDefault("livehunt"),
            RetrohuntAvailable = allowed.GetValueOrDefault("retrohunt"),
            Detail = enterprise
                ? "Enterprise features reachable."
                : "Public API tier: hash lookups only. Livehunt, Retrohunt, VTDIFF " +
                  "and Intelligence search require a VT Enterprise account.",
            RateLimit = enterprise ? "per contract" : "4/min, 500/day (public tier)",
            CheckedAt = DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:sszzz"),
            TlsBundle = SuiteHttp.TrustStore,
        };
    }

    // --------------------------------------------------------------- lookups
    /// <summary>Look up one file by hash. Sends only the hash, never the file.</summary>
    public async Task<VtReport> LookupHashAsync(string fileHash, bool useCache = true,
                                                CancellationToken token = default)
    {
        fileHash = (fileHash ?? "").Trim().ToLowerInvariant();

        if (!AnyHash().IsMatch(fileHash))
            return VtReport.Failure(fileHash, "not an md5/sha1/sha256 hash");
        if (!Configured)
            return VtReport.Failure(fileHash, "no VirusTotal API key configured");

        var cached = Path.Combine(CacheDir, fileHash + ".json");
        if (useCache && File.Exists(cached))
        {
            try
            {
                var record = JsonSerializer.Deserialize<VtReport>(
                    File.ReadAllText(cached), SuiteJson.Options);
                if (record is not null)
                {
                    record.Cached = true;
                    return record;
                }
            }
            catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
            {
                // Fall through and fetch.
            }
        }

        await _limiter.WaitAsync(token).ConfigureAwait(false);

        JsonDocument payload;
        try
        {
            payload = await SuiteHttp.GetJsonAsync(BaseUrl + "/files/" + fileHash,
                Headers(), _timeout, token).ConfigureAwait(false);
        }
        catch (HttpFailure exc)
        {
            return exc.Status switch
            {
                // Not an error: VT simply has no record, which is itself
                // informative for a freshly built dropper.
                404 => new VtReport
                {
                    Hash = fileHash,
                    Known = false,
                    Detail = "VirusTotal has never seen this file.",
                },
                429 => VtReport.Failure(fileHash, "rate limited",
                    "Public tier allows 4 requests/minute and 500/day."),
                _ => Record(VtReport.Failure(fileHash, exc.Message)),
            };
        }

        using (payload)
        {
            var record = Normalise(payload.RootElement);
            record.Hash = fileHash;
            record.Known = true;

            lock (_gate)
            {
                Lookups++;
                LastError = null;
            }

            try
            {
                File.WriteAllText(cached, JsonSerializer.Serialize(record, SuiteJson.Pretty));
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }

            record.Cached = false;
            return record;
        }

        VtReport Record(VtReport report)
        {
            LastError = report.Error;
            return report;
        }
    }

    // --------------------------------------------------------- hunting (gated)
    /// <summary>Hunting endpoints, behind a real capability check.</summary>
    public async Task<VtHuntingResult> HuntingAsync(string what = "livehunt",
                                                     CancellationToken token = default)
    {
        var caps = await CapabilitiesBlockingAsync(token).ConfigureAwait(false);

        if (!caps.Configured)
            return new VtHuntingResult { Available = false, Feature = what, Error = "no VirusTotal API key configured" };

        if (!caps.Allowed.GetValueOrDefault(what))
        {
            return new VtHuntingResult
            {
                Available = false,
                Feature = what,
                Tier = caps.Tier,
                Error = what + " requires a VirusTotal Enterprise account",
                Detail = "This key returns HTTP 403 for " + what + ". Livehunt, Retrohunt " +
                         "and VTDIFF are Enterprise features; the public API tier cannot " +
                         "reach them. See virustotal.com/gui/hunting-overview.",
            };
        }

        var path = what == "livehunt"
            ? "/intelligence/hunting_rulesets?limit=20"
            : "/intelligence/retrohunt_jobs?limit=20";

        await _limiter.WaitAsync(token).ConfigureAwait(false);
        try
        {
            using var payload = await SuiteHttp.GetJsonAsync(BaseUrl + path, Headers(), _timeout, token)
                .ConfigureAwait(false);
            return new VtHuntingResult
            {
                Available = true,
                Feature = what,
                Data = JsonSerializer.Deserialize<JsonElement>(payload.RootElement.GetRawText()),
            };
        }
        catch (HttpFailure exc)
        {
            return new VtHuntingResult { Available = false, Feature = what, Error = exc.Message };
        }
    }

    // ---------------------------------------------------------------- status
    public VtStatus Status()
    {
        var caps = Capabilities();
        var cached = 0;
        try
        {
            cached = Directory.EnumerateFiles(CacheDir, "*.json")
                .Count(f => !Path.GetFileName(f).StartsWith('_'));
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }

        lock (_gate)
        {
            return new VtStatus
            {
                Configured = Configured,
                Tier = caps.Tier,
                HuntingAvailable = caps.HuntingAvailable,
                RetrohuntAvailable = caps.RetrohuntAvailable,
                Detail = caps.Detail,
                RateLimit = caps.RateLimit,
                CachedLookups = cached,
                LookupsThisSession = Lookups,
                LastError = LastError,
            };
        }
    }

    // ------------------------------------------------------------- normalise
    /// <summary>Map engine consensus onto the suite's triage scale.</summary>
    public static string SeverityFor(int malicious, int suspicious) => malicious switch
    {
        >= 10 => Severity.Critical,
        >= 3 => Severity.High,
        >= 1 => Severity.Medium,
        _ => suspicious >= 3 ? Severity.Medium : suspicious >= 1 ? Severity.Low : Severity.Info,
    };

    /// <summary>Flatten a VT file report into the shape the dashboard consumes.</summary>
    public static VtReport Normalise(JsonElement payload)
    {
        var attrs = payload.TryGetProperty("data", out var data) &&
                    data.TryGetProperty("attributes", out var a) ? a : default;

        int malicious = 0, suspicious = 0, harmless = 0, undetected = 0, total = 0;
        if (attrs.ValueKind == JsonValueKind.Object &&
            attrs.TryGetProperty("last_analysis_stats", out var stats) &&
            stats.ValueKind == JsonValueKind.Object)
        {
            foreach (var stat in stats.EnumerateObject())
            {
                if (stat.Value.ValueKind != JsonValueKind.Number) continue;
                var value = stat.Value.GetInt32();
                total += value;
                switch (stat.Name)
                {
                    case "malicious": malicious = value; break;
                    case "suspicious": suspicious = value; break;
                    case "harmless": harmless = value; break;
                    case "undetected": undetected = value; break;
                }
            }
        }

        var label = "";
        var families = new List<string>();
        if (attrs.ValueKind == JsonValueKind.Object &&
            attrs.TryGetProperty("popular_threat_classification", out var threat) &&
            threat.ValueKind == JsonValueKind.Object)
        {
            label = Text(threat, "suggested_threat_label");
            if (threat.TryGetProperty("popular_threat_name", out var popular) &&
                popular.ValueKind == JsonValueKind.Array)
            {
                families = [.. popular.EnumerateArray()
                    .Select(c => Text(c, "value")).Where(v => v.Length > 0).Take(4)];
            }
        }

        var flagged = new List<VtEngineVerdict>();
        if (attrs.ValueKind == JsonValueKind.Object &&
            attrs.TryGetProperty("last_analysis_results", out var results) &&
            results.ValueKind == JsonValueKind.Object)
        {
            foreach (var engine in results.EnumerateObject())
            {
                var category = Text(engine.Value, "category");
                if (category is not ("malicious" or "suspicious")) continue;
                flagged.Add(new VtEngineVerdict
                {
                    Engine = engine.Name,
                    Category = category,
                    Result = Text(engine.Value, "result"),
                });
            }
            flagged.Sort((x, y) => string.Compare(x.Engine, y.Engine, StringComparison.OrdinalIgnoreCase));
        }

        var sha256 = Text(attrs, "sha256");
        return new VtReport
        {
            Sha256 = sha256,
            Md5 = Text(attrs, "md5"),
            Size = Number(attrs, "size"),
            Type = Text(attrs, "type_description"),
            Names = Strings(attrs, "names").Take(5).ToList(),
            Malicious = malicious,
            Suspicious = suspicious,
            Harmless = harmless,
            Undetected = undetected,
            EnginesTotal = total,
            DetectionRatio = total > 0 ? malicious + "/" + total : "",
            ThreatLabel = label,
            Families = families,
            Reputation = (int?)Number(attrs, "reputation"),
            FirstSeen = Stamp(Number(attrs, "first_submission_date")),
            LastAnalysed = Stamp(Number(attrs, "last_analysis_date")),
            Severity = SeverityFor(malicious, suspicious),
            FlaggedBy = [.. flagged.Take(25)],
            Permalink = sha256.Length > 0 ? "https://www.virustotal.com/gui/file/" + sha256 : "",
        };

        static string Text(JsonElement element, string name) =>
            element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? ""
                : "";

        static long? Number(JsonElement element, string name) =>
            element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
                ? value.GetInt64()
                : null;

        static List<string> Strings(JsonElement element, string name) =>
            element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
                ? [.. value.EnumerateArray().Select(v => v.GetString() ?? "").Where(s => s.Length > 0)]
                : [];

        static string Stamp(long? unixSeconds)
        {
            if (unixSeconds is null or <= 0) return "";
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(unixSeconds.Value)
                    .ToLocalTime().ToString("yyyy-MM-ddTHH:mm:sszzz");
            }
            catch (ArgumentOutOfRangeException)
            {
                return "";
            }
        }
    }
}

// ---------------------------------------------------------------------- models
public sealed class VtCapabilities
{
    [JsonPropertyName("configured")] public bool Configured { get; set; }

    /// <summary>none, checking, public, or enterprise.</summary>
    [JsonPropertyName("tier")] public string Tier { get; set; } = "none";

    [JsonPropertyName("allowed")] public Dictionary<string, bool> Allowed { get; set; } = [];
    [JsonPropertyName("hunting_available")] public bool HuntingAvailable { get; set; }
    [JsonPropertyName("retrohunt_available")] public bool RetrohuntAvailable { get; set; }
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
    [JsonPropertyName("rate_limit")] public string RateLimit { get; set; } = "";
    [JsonPropertyName("checked_at")] public string? CheckedAt { get; set; }
    [JsonPropertyName("tls_bundle")] public string TlsBundle { get; set; } = "";

    [JsonPropertyName("from_cache")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? FromCache { get; set; }
}

public sealed class VtEngineVerdict
{
    [JsonPropertyName("engine")] public string Engine { get; set; } = "";
    [JsonPropertyName("category")] public string Category { get; set; } = "";
    [JsonPropertyName("result")] public string Result { get; set; } = "";
}

public sealed class VtReport
{
    [JsonPropertyName("hash")] public string Hash { get; set; } = "";
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("md5")] public string Md5 { get; set; } = "";
    [JsonPropertyName("size")] public long? Size { get; set; }
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("names")] public List<string> Names { get; set; } = [];
    [JsonPropertyName("malicious")] public int Malicious { get; set; }
    [JsonPropertyName("suspicious")] public int Suspicious { get; set; }
    [JsonPropertyName("harmless")] public int Harmless { get; set; }
    [JsonPropertyName("undetected")] public int Undetected { get; set; }
    [JsonPropertyName("engines_total")] public int EnginesTotal { get; set; }
    [JsonPropertyName("detection_ratio")] public string DetectionRatio { get; set; } = "";
    [JsonPropertyName("threat_label")] public string ThreatLabel { get; set; } = "";
    [JsonPropertyName("families")] public List<string> Families { get; set; } = [];
    [JsonPropertyName("reputation")] public int? Reputation { get; set; }
    [JsonPropertyName("first_seen")] public string FirstSeen { get; set; } = "";
    [JsonPropertyName("last_analysed")] public string LastAnalysed { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = Storage.Severity.Info;
    [JsonPropertyName("flagged_by")] public List<VtEngineVerdict> FlaggedBy { get; set; } = [];
    [JsonPropertyName("permalink")] public string Permalink { get; set; } = "";

    /// <summary>False when VT has no record of the file, which is not an error.</summary>
    [JsonPropertyName("known")] public bool Known { get; set; }

    [JsonPropertyName("detail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; set; }

    [JsonPropertyName("cached")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Cached { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }

    public static VtReport Failure(string hash, string error, string? detail = null) =>
        new() { Hash = hash, Error = error, Detail = detail };
}

public sealed class VtHuntingResult
{
    [JsonPropertyName("available")] public bool Available { get; set; }
    [JsonPropertyName("feature")] public string Feature { get; set; } = "";

    [JsonPropertyName("tier")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tier { get; set; }

    [JsonPropertyName("detail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }

    [JsonPropertyName("data")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? Data { get; set; }
}

public sealed class VtStatus
{
    [JsonPropertyName("source")] public string Source { get; set; } = "virustotal";
    [JsonPropertyName("configured")] public bool Configured { get; set; }
    [JsonPropertyName("tier")] public string Tier { get; set; } = "";
    [JsonPropertyName("hunting_available")] public bool HuntingAvailable { get; set; }
    [JsonPropertyName("retrohunt_available")] public bool RetrohuntAvailable { get; set; }
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
    [JsonPropertyName("rate_limit")] public string RateLimit { get; set; } = "";
    [JsonPropertyName("cached_lookups")] public int CachedLookups { get; set; }
    [JsonPropertyName("lookups_this_session")] public int LookupsThisSession { get; set; }

    /// <summary>Stated in the payload so the guarantee is visible, not just documented.</summary>
    [JsonPropertyName("uploads")] public string Uploads { get; set; } =
        "never - this client only sends hashes";

    [JsonPropertyName("last_error")] public string? LastError { get; set; }
}
