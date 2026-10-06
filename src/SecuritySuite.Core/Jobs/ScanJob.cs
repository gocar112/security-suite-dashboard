using System.Text.Json.Serialization;

namespace SecuritySuite.Jobs;

public static class ScanJobState
{
    public const string Queued = "queued";
    public const string Running = "running";
    public const string Completed = "completed";
    public const string Cancelled = "cancelled";
    public const string Error = "error";

    public static bool IsActive(string state) => state is Queued or Running;
}

/// <summary>
/// One background scan of a filesystem tree.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Scanned"/> counts files successfully scanned and
/// <see cref="Matches"/> counts matching <em>files</em>, not individual
/// matching rules. <see cref="Skipped"/> counts entries encountered and passed
/// over: a pruned directory counts once, not its unknown contents.
/// <see cref="Errors"/> counts failures, including inaccessible skips.
/// </para>
/// <para>
/// Mutated under the owning <see cref="ScanJobs"/> lock and handed out only as
/// a copy, so a reader never sees a half-updated job.
/// </para>
/// </remarks>
public sealed class ScanJob
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("state")] public string State { get; set; } = ScanJobState.Queued;

    /// <summary>What the walker is looking at, for the progress line.</summary>
    [JsonPropertyName("current_path")] public string? CurrentPath { get; set; }

    [JsonPropertyName("started_at")] public string? StartedAt { get; set; }
    [JsonPropertyName("finished_at")] public string? FinishedAt { get; set; }
    [JsonPropertyName("scanned")] public int Scanned { get; set; }
    [JsonPropertyName("matches")] public int Matches { get; set; }
    [JsonPropertyName("skipped")] public int Skipped { get; set; }
    [JsonPropertyName("errors")] public int Errors { get; set; }

    /// <summary>Skip counts by reason: link, excluded, unavailable, depth_limit, size, special_file.</summary>
    [JsonPropertyName("skip_reasons")] public Dictionary<string, int> SkipReasons { get; set; } = [];

    /// <summary>
    /// Set when a cancel was asked for but the job has not stopped yet.
    /// </summary>
    /// <remarks>
    /// Cancellation is cooperative: an engine or OS call already in flight
    /// cannot be interrupted. The job stays active with this set until that
    /// call returns, so repeated cancel-then-start cannot accumulate blocked
    /// scanner threads.
    /// </remarks>
    [JsonPropertyName("cancellation_requested")] public bool CancellationRequested { get; set; }

    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("last_error")] public string? LastError { get; set; }

    public ScanJob Copy() => new()
    {
        Id = Id,
        Path = Path,
        State = State,
        CurrentPath = CurrentPath,
        StartedAt = StartedAt,
        FinishedAt = FinishedAt,
        Scanned = Scanned,
        Matches = Matches,
        Skipped = Skipped,
        Errors = Errors,
        SkipReasons = new Dictionary<string, int>(SkipReasons),
        CancellationRequested = CancellationRequested,
        Error = Error,
        LastError = LastError,
    };
}

public sealed record DriveEntry(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("label")] string Label);

/// <summary>A start or cancel that was rejected, with the reason.</summary>
public sealed class ScanJobError
{
    [JsonPropertyName("error")] public string Error { get; set; } = "";

    [JsonPropertyName("job_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? JobId { get; set; }
}
