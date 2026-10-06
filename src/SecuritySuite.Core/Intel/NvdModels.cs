using System.Text.Json.Serialization;

namespace SecuritySuite.Intel;

/// <summary>A patch or advisory reference kept from an NVD record.</summary>
public sealed class PatchReference
{
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("tags")] public List<string> Tags { get; set; } = [];
}

/// <summary>
/// One NVD record, flattened to the shape the dashboard consumes.
/// </summary>
public sealed class CveRecord
{
    /// <summary>
    /// Bumped when this shape changes, so a stale cache entry is treated as a
    /// miss instead of being served without its newer fields.
    /// </summary>
    /// <remarks>
    /// Version 2 added <see cref="PatchRefs"/> and the KEV action fields.
    /// Entries written before that exist on disk and look perfectly valid, so
    /// without a version they would be served forever with no patch guidance.
    /// </remarks>
    public const int CurrentSchema = 3;

    [JsonPropertyName("schema")] public int Schema { get; set; } = CurrentSchema;
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("published")] public string Published { get; set; } = "";
    [JsonPropertyName("last_modified")] public string LastModified { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    [JsonPropertyName("score")] public double? Score { get; set; }
    [JsonPropertyName("cvss_severity")] public string CvssSeverity { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = Storage.Severity.Info;
    [JsonPropertyName("cvss_version")] public string CvssVersion { get; set; } = "";
    [JsonPropertyName("vector")] public string Vector { get; set; } = "";
    [JsonPropertyName("cwe")] public List<string> Cwe { get; set; } = [];
    [JsonPropertyName("description")] public string Description { get; set; } = "";

    /// <summary>How many references the record has, in total.</summary>
    [JsonPropertyName("references")] public int References { get; set; }

    /// <summary>
    /// Only the references that point at a fix.
    /// </summary>
    /// <remarks>
    /// The original adapter collapsed references to a bare count at ingestion,
    /// discarding every vendor patch URL. The count is kept for compatibility,
    /// and the useful subset is kept alongside it.
    /// </remarks>
    [JsonPropertyName("patch_refs")] public List<PatchReference> PatchRefs { get; set; } = [];

    // ------------------------------------------------- CISA KEV
    /// <summary>In CISA's Known Exploited Vulnerabilities catalogue.</summary>
    [JsonPropertyName("kev")] public bool Kev { get; set; }

    [JsonPropertyName("kev_name")] public string KevName { get; set; } = "";
    [JsonPropertyName("exploit_added")] public string ExploitAdded { get; set; } = "";

    /// <summary>
    /// CISA's mandated remediation, verbatim.
    /// </summary>
    /// <remarks>
    /// This is why KEV is worth querying: it is authoritative text saying what
    /// to do, which beats anything the suite could generate about a CVE it has
    /// only read a description of.
    /// </remarks>
    [JsonPropertyName("kev_required_action")] public string KevRequiredAction { get; set; } = "";

    [JsonPropertyName("kev_action_due")] public string KevActionDue { get; set; } = "";
    [JsonPropertyName("source")] public string Source { get; set; } = "";

    /// <summary>True when served from the local cache rather than fetched.</summary>
    [JsonPropertyName("cached")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Cached { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }

    [JsonIgnore] public bool Failed => Error is not null;

    public string NvdUrl => "https://nvd.nist.gov/vuln/detail/" + Id;

    public static CveRecord Failure(string id, string error) =>
        new() { Id = id, Error = error };
}

public sealed class CveSearchResult
{
    [JsonPropertyName("query")] public string Query { get; set; } = "";
    [JsonPropertyName("total")] public int Total { get; set; }
    [JsonPropertyName("results")] public List<CveRecord> Results { get; set; } = [];

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}

/// <summary>What the last sync did, written beside the cached feed.</summary>
public sealed class NvdSyncIndex
{
    [JsonPropertyName("last_sync")] public string LastSync { get; set; } = "";
    [JsonPropertyName("window_start")] public string WindowStart { get; set; } = "";
    [JsonPropertyName("window_end")] public string WindowEnd { get; set; } = "";
    [JsonPropertyName("window_days")] public int WindowDays { get; set; }
    [JsonPropertyName("cached")] public int Cached { get; set; }
    [JsonPropertyName("total_in_window")] public int TotalInWindow { get; set; }
    [JsonPropertyName("truncated")] public bool Truncated { get; set; }
    [JsonPropertyName("pages_fetched")] public int PagesFetched { get; set; }
    [JsonPropertyName("by_severity")] public Dictionary<string, int> BySeverity { get; set; } = [];

    /// <summary>
    /// Whether the sync that wrote this used an API key.
    /// </summary>
    /// <remarks>
    /// Named for the sync rather than the client on purpose. An earlier version
    /// stored this as <c>api_key</c>, and because the cached index was spread
    /// into the status payload <em>after</em> the live fields, a stale
    /// <c>false</c> here reported a configured key as absent.
    /// </remarks>
    [JsonPropertyName("last_sync_used_key")] public bool LastSyncUsedKey { get; set; }

    [JsonPropertyName("elapsed_seconds")] public double ElapsedSeconds { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }

    [JsonPropertyName("synced")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Synced { get; set; }

    public static NvdSyncIndex Failure(string error) => new() { Error = error, Synced = 0 };
}

/// <summary>The NVD panel's status line.</summary>
public sealed class NvdStatus
{
    [JsonPropertyName("source")] public string Source { get; set; } = "nvd";
    [JsonPropertyName("base_url")] public string BaseUrl { get; set; } = "";
    [JsonPropertyName("cache_dir")] public string CacheDir { get; set; } = "";

    /// <summary>Whether a key is configured right now, not whether one was used before.</summary>
    [JsonPropertyName("api_key")] public bool ApiKey { get; set; }

    [JsonPropertyName("rate_limit")] public string RateLimit { get; set; } = "";
    [JsonPropertyName("tls_bundle")] public string TlsBundle { get; set; } = "";
    [JsonPropertyName("syncing")] public bool Syncing { get; set; }
    [JsonPropertyName("lookups_cached")] public int LookupsCached { get; set; }
    [JsonPropertyName("last_error")] public string? LastError { get; set; }

    /// <summary>The last sync's index, or null when nothing has synced yet.</summary>
    [JsonPropertyName("sync")] public NvdSyncIndex? Sync { get; set; }
}
