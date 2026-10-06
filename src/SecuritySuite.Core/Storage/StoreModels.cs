using System.Text.Json.Serialization;

namespace SecuritySuite.Storage;

/// <summary>
/// Latest triage state for one finding, persisted to the triage sidecar.
/// </summary>
/// <remarks>
/// This keeps only the current state, by design: it is a workbench note, not a
/// record. Anything that needs history goes to the findings log instead, which
/// is why remediation audits are written there and not here.
/// </remarks>
public sealed class TriageState
{
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("at")] public string? At { get; set; }
    [JsonPropertyName("note")] public string? Note { get; set; }
}

public sealed class ClearResult
{
    [JsonPropertyName("cleared")] public bool Cleared { get; set; }
    [JsonPropertyName("events")] public int Events { get; set; }
    [JsonPropertyName("triage")] public int Triage { get; set; }

    /// <summary>Remediation audit records that survived the clear.</summary>
    [JsonPropertyName("audit_retained")] public int AuditRetained { get; set; }

    [JsonPropertyName("backup_dir")] public string BackupDir { get; set; } = "";
}

public sealed record RuleCount(
    [property: JsonPropertyName("rule")] string Rule,
    [property: JsonPropertyName("count")] int Count);

public sealed record TimelineBucket(
    [property: JsonPropertyName("minutes_ago")] int MinutesAgo,
    [property: JsonPropertyName("count")] int Count);

public sealed class StoreStats
{
    [JsonPropertyName("files_scanned")] public long FilesScanned { get; set; }
    [JsonPropertyName("clean_scans")] public int CleanScans { get; set; }
    [JsonPropertyName("matches")] public int Matches { get; set; }
    [JsonPropertyName("open_alerts")] public int OpenAlerts { get; set; }
    [JsonPropertyName("errors")] public int Errors { get; set; }
    [JsonPropertyName("by_severity")] public Dictionary<string, int> BySeverity { get; set; } = [];
    [JsonPropertyName("top_rules")] public List<RuleCount> TopRules { get; set; } = [];
    [JsonPropertyName("timeline")] public List<TimelineBucket> Timeline { get; set; } = [];
    [JsonPropertyName("uptime_seconds")] public long UptimeSeconds { get; set; }
    [JsonPropertyName("log_path")] public string LogPath { get; set; } = "";
    [JsonPropertyName("log_size")] public long LogSize { get; set; }
}
