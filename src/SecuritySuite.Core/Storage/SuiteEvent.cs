using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SecuritySuite.Storage;

/// <summary>
/// One record in the findings log: a scan, a detection, an error, a monitor
/// notice, or a remediation audit entry.
/// </summary>
/// <remarks>
/// <para>
/// The Python build used a bare dict, so every producer invented its own keys
/// and every consumer hoped they were there. The common fields are typed here
/// instead, and <see cref="Extra"/> catches the rest through
/// <see cref="JsonExtensionDataAttribute"/>. That keeps the on-disk NDJSON
/// byte-compatible with existing logs while making the fields the dashboard
/// actually reads impossible to misspell.
/// </para>
/// <para>
/// Events are mutable because triage edits them in place in the ring buffer,
/// and because the monitor builds one up across a scan.
/// </para>
/// </remarks>
public sealed class SuiteEvent
{
    public const string TypeScan = "scan";
    public const string TypeMatch = "yara_match";
    public const string TypeError = "error";
    public const string TypeMonitor = "monitor";
    public const string TypeRemediation = "remediation";

    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("event_type")] public string EventType { get; set; } = "";
    [JsonPropertyName("timestamp")] public string Timestamp { get; set; } = "";

    /// <summary>
    /// Unix seconds, recorded alongside the ISO timestamp.
    /// </summary>
    /// <remarks>
    /// The timeline buckets by age, and parsing an ISO string for every event on
    /// every stats call is wasteful when the producer already knew the instant.
    /// Kept under its original <c>_epoch</c> name so old logs still bucket.
    /// </remarks>
    [JsonPropertyName("_epoch")] public double Epoch { get; set; }

    [JsonPropertyName("status")] public string Status { get; set; } = "new";

    [JsonPropertyName("severity")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Severity { get; set; }

    [JsonPropertyName("file_path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FilePath { get; set; }

    [JsonPropertyName("file_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FileName { get; set; }

    [JsonPropertyName("file_size")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? FileSize { get; set; }

    [JsonPropertyName("sha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Sha256 { get; set; }

    /// <summary>Why this file was not scanned. Set means no verdict was reached.</summary>
    [JsonPropertyName("skipped")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Skipped { get; set; }

    [JsonPropertyName("verdict")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Verdict { get; set; }

    [JsonPropertyName("trigger")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Trigger { get; set; }

    [JsonPropertyName("message")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Message { get; set; }

    [JsonPropertyName("scan_ms")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public double? ScanMs { get; set; }

    [JsonPropertyName("matches")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<RuleMatch>? Matches { get; set; }

    [JsonPropertyName("rule_names")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? RuleNames { get; set; }

    [JsonPropertyName("telemetry")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonNode? Telemetry { get; set; }

    [JsonPropertyName("correlated_auth_failures")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? CorrelatedAuthFailures { get; set; }

    // ------------------------------------------------------------ triage state
    [JsonPropertyName("triaged_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TriagedAt { get; set; }

    [JsonPropertyName("triage_note")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TriageNote { get; set; }

    /// <summary>
    /// Anything a producer added that is not modelled above: remediation audit
    /// fields, IOC summaries, guidance. Round-trips untouched.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }

    [JsonIgnore] public bool IsMatch => EventType == TypeMatch;

    /// <summary>Read an unmodelled field, or null when it is absent or the wrong shape.</summary>
    public T? GetExtra<T>(string key)
    {
        if (Extra is null || !Extra.TryGetValue(key, out var element)) return default;
        try { return element.Deserialize<T>(SuiteJson.Options); }
        catch (JsonException) { return default; }
    }

    /// <summary>Attach an unmodelled field.</summary>
    public SuiteEvent SetExtra(string key, object? value)
    {
        Extra ??= [];
        Extra[key] = JsonSerializer.SerializeToElement(value, SuiteJson.Options);
        return this;
    }

    public SuiteEvent Clone() =>
        JsonSerializer.Deserialize<SuiteEvent>(
            JsonSerializer.Serialize(this, SuiteJson.Options), SuiteJson.Options)!;
}

/// <summary>One rule that fired, with the strings that made it fire.</summary>
public sealed class RuleMatch
{
    [JsonPropertyName("rule")] public string Rule { get; set; } = "";

    /// <summary>
    /// The rule file the rule came from.
    /// </summary>
    /// <remarks>
    /// yara-python grouped rules into namespaces at compile time and reported
    /// the namespace on a match. libyara.NET has no namespace parameter, so the
    /// engine builds a rule-name to file map while validating each file and
    /// fills this in from that. Same value, different route.
    /// </remarks>
    [JsonPropertyName("namespace")] public string Namespace { get; set; } = "";

    [JsonPropertyName("severity")] public string Severity { get; set; } = Storage.Severity.Info;

    [JsonPropertyName("tags")] public List<string> Tags { get; set; } = [];

    [JsonPropertyName("meta")] public Dictionary<string, string> Meta { get; set; } = [];

    /// <summary>The matched strings, truncated for display.</summary>
    [JsonPropertyName("strings")] public List<MatchedString> Strings { get; set; } = [];

    [JsonIgnore] public string? Description => Meta.GetValueOrDefault("description");
    [JsonIgnore] public string? Cve => Meta.GetValueOrDefault("cve");
    [JsonIgnore] public string? Confidence => Meta.GetValueOrDefault("confidence");
}

/// <summary>A single string hit inside a matched rule.</summary>
public sealed class MatchedString
{
    [JsonPropertyName("identifier")] public string Identifier { get; set; } = "";
    [JsonPropertyName("offset")] public long Offset { get; set; }
    [JsonPropertyName("preview")] public string Preview { get; set; } = "";
    [JsonPropertyName("count")] public int Count { get; set; } = 1;
}

/// <summary>Shared JSON settings so every writer produces the same shape.</summary>
public static class SuiteJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    };

    /// <summary>Indented variant for files a human may open.</summary>
    public static readonly JsonSerializerOptions Pretty = new(Options) { WriteIndented = true };
}
