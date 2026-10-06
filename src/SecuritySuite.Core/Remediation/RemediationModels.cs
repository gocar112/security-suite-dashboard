using System.Text.Json.Serialization;

namespace SecuritySuite.Remediation;

/// <summary>
/// A rail rejected the action. Carries the reason shown to the operator.
/// </summary>
/// <remarks>
/// Each rail produces a distinct <see cref="Reason"/>. "Refused" on its own
/// tells an operator nothing actionable; "hash mismatch" tells them the file
/// changed since detection, and "suite-owned path" tells them their watch root
/// is pointed somewhere it should not be.
/// </remarks>
public sealed class RefusedException(string reason, string detail = "") : Exception(reason)
{
    public string Reason { get; } = reason;
    public string Detail { get; } = detail;
}

/// <summary>The outcome of one remediation attempt, successful or refused.</summary>
public sealed class RemediationResult
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("finding")] public string Finding { get; set; } = "";

    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; set; }

    [JsonPropertyName("dry_run")] public bool DryRun { get; set; }
    [JsonPropertyName("trigger")] public string Trigger { get; set; } = "manual";

    [JsonPropertyName("severity")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Severity { get; set; }

    [JsonPropertyName("rules")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Rules { get; set; }

    /// <summary>The rail that refused, or null when the action proceeded.</summary>
    [JsonPropertyName("refused")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Refused { get; set; }

    [JsonPropertyName("detail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; set; }

    /// <summary>What happened: deleted, quarantined, restored, purged, refused, failed.</summary>
    [JsonPropertyName("outcome")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Outcome { get; set; }

    /// <summary>Each rail and its verdict, so a dry run can show the whole decision.</summary>
    [JsonPropertyName("checks")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Checks { get; set; }

    [JsonPropertyName("remediation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public RemediationState? Remediation { get; set; }

    public RemediationResult Refuse(string reason, string detail = "")
    {
        Ok = false;
        Refused = reason;
        Detail = detail;
        Outcome ??= "refused";
        return this;
    }

    public RemediationResult Succeed(string outcome, string detail)
    {
        Ok = true;
        Outcome = outcome;
        Detail = detail;
        Refused = null;
        return this;
    }
}

/// <summary>What was done to one finding's target, persisted across restarts.</summary>
public sealed class RemediationState
{
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("at")] public string At { get; set; } = "";
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
    [JsonPropertyName("trigger")] public string Trigger { get; set; } = "manual";
}

/// <summary>Sidecar written next to a quarantined file, so it can be identified later.</summary>
public sealed class QuarantineMetadata
{
    [JsonPropertyName("finding")] public string Finding { get; set; } = "";
    [JsonPropertyName("original_path")] public string OriginalPath { get; set; } = "";
    [JsonPropertyName("quarantined_at")] public string QuarantinedAt { get; set; } = "";
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("severity")] public string? Severity { get; set; }
    [JsonPropertyName("rules")] public List<string> Rules { get; set; } = [];
}

/// <summary>The result of a filtered sweep.</summary>
public sealed class BulkResult
{
    [JsonPropertyName("matched")] public int Matched { get; set; }
    [JsonPropertyName("acted")] public int Acted { get; set; }
    [JsonPropertyName("actionable")] public int Actionable { get; set; }
    [JsonPropertyName("refused")] public int Refused { get; set; }
    [JsonPropertyName("dry_run")] public bool DryRun { get; set; }
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "all";
    [JsonPropertyName("extensions")] public List<string> Extensions { get; set; } = [];
    [JsonPropertyName("results")] public List<RemediationResult> Results { get; set; } = [];
}

/// <summary>What the remediation panel shows.</summary>
public sealed class RemediationStatus
{
    [JsonPropertyName("quarantine_dir")] public string QuarantineDir { get; set; } = "";
    [JsonPropertyName("quarantined")] public int Quarantined { get; set; }
    [JsonPropertyName("acted_on")] public int ActedOn { get; set; }
    [JsonPropertyName("auto_remediate")] public bool AutoRemediate { get; set; }
    [JsonPropertyName("auto_action")] public string AutoAction { get; set; } = "";
    [JsonPropertyName("auto_severity")] public string AutoSeverity { get; set; } = "";
    [JsonPropertyName("permitted_roots")] public List<string> PermittedRoots { get; set; } = [];
    [JsonPropertyName("protected_roots")] public List<string> ProtectedRoots { get; set; } = [];
    [JsonPropertyName("recent")] public List<Storage.SuiteEvent> Recent { get; set; } = [];
}
