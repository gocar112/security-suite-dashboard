using System.Text.Json.Serialization;

namespace SecuritySuite.Telemetry;

/// <summary>How a provider's attempt ended.</summary>
public static class TelemetryStatus
{
    /// <summary>The source was read. Zero events means genuinely quiet.</summary>
    public const string Ok = "ok";

    /// <summary>The source exists but this process may not read it.</summary>
    public const string Denied = "denied";

    /// <summary>The source does not exist on this host.</summary>
    public const string Unavailable = "unavailable";

    /// <summary>The source exists and should have been readable, but failed.</summary>
    public const string Error = "error";
}

/// <summary>One authentication failure.</summary>
public sealed class AuthEvent
{
    [JsonPropertyName("timestamp")] public string Timestamp { get; set; } = "";
    [JsonPropertyName("type")] public string Type { get; set; } = "failed_logon";
    [JsonPropertyName("event_id")] public int? EventId { get; set; }
    [JsonPropertyName("account")] public string Account { get; set; } = "unknown";
    [JsonPropertyName("source_ip")] public string SourceIp { get; set; } = "";

    [JsonPropertyName("process")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Process { get; set; }

    /// <summary>The original line or insert strings, truncated.</summary>
    [JsonPropertyName("raw")] public string Raw { get; set; } = "";
}

/// <summary>What one provider returned.</summary>
public sealed class TelemetryResult
{
    [JsonPropertyName("status")] public string Status { get; set; } = TelemetryStatus.Error;
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
    [JsonPropertyName("events")] public List<AuthEvent> Events { get; set; } = [];

    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; set; }

    [JsonIgnore] public bool Usable => Status == TelemetryStatus.Ok;

    public static TelemetryResult Ok(string source, List<AuthEvent> events) =>
        new() { Status = TelemetryStatus.Ok, Source = source, Events = events };

    public static TelemetryResult Fail(string status, string source, string detail) =>
        new() { Status = status, Source = source, Detail = detail };
}

/// <summary>One provider's attempt, for the diagnostics panel.</summary>
public sealed record TelemetryAttempt(
    [property: JsonPropertyName("provider")] string Provider,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("detail")] string Detail);

/// <summary>
/// The correlated telemetry attached to a finding, or reported on its own.
/// </summary>
public sealed class TelemetrySnapshot
{
    [JsonPropertyName("status")] public string Status { get; set; } = TelemetryStatus.Error;
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
    [JsonPropertyName("events")] public List<AuthEvent> Events { get; set; } = [];
    [JsonPropertyName("count")] public int Count { get; set; }
    [JsonPropertyName("window_minutes")] public int WindowMinutes { get; set; }
    [JsonPropertyName("platform")] public string Platform { get; set; } = "";
    [JsonPropertyName("collected_at")] public string CollectedAt { get; set; } = "";

    /// <summary>
    /// Every provider that was tried, in order, with why each one did or did
    /// not answer.
    /// </summary>
    /// <remarks>
    /// This is the field that lets an operator tell "no failed logons" from
    /// "nothing could read the logs". The two must never look the same, which
    /// is the whole reason a status is reported alongside a count.
    /// </remarks>
    [JsonPropertyName("attempts")] public List<TelemetryAttempt> Attempts { get; set; } = [];

    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; set; }

    /// <summary>
    /// A short phrase for the dashboard that never overstates what is known.
    /// </summary>
    [JsonPropertyName("summary")]
    public string Summary => Status switch
    {
        TelemetryStatus.Ok when Count == 0 => "quiet - no failed logons in the window",
        TelemetryStatus.Ok => Count + " failed logon(s) in the last " + WindowMinutes + " min",
        TelemetryStatus.Denied => "blind - permission denied reading " + Source,
        TelemetryStatus.Unavailable => "blind - no telemetry source on this host",
        _ => "blind - " + (Detail.Length > 0 ? Detail : "telemetry unavailable"),
    };
}
