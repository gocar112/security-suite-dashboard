using System.Text.Json;
using System.Text.Json.Serialization;
using SecuritySuite.Storage;

namespace SecuritySuite.Casework;

/// <summary>
/// Cases: the container triage does not have.
/// </summary>
/// <remarks>
/// <para>
/// Triage marks a single finding acknowledged or resolved. An intrusion is not
/// a single finding, and "resolved" on six rows says nothing about whether
/// anyone understood how they were related, what was done, or why it was
/// closed. A case holds those findings together with an owner, a status and the
/// notes that make the decision reviewable later.
/// </para>
/// <para>
/// Persistence follows the triage sidecar already beside the findings log: one
/// small JSON file, written whole, holding only what the findings themselves
/// cannot. Cases reference findings <em>by id</em> and never copy them, so a
/// case cannot drift out of date with the evidence it points at.
/// </para>
/// </remarks>
public sealed class CaseStore
{
    public static readonly string[] Statuses = ["open", "investigating", "contained", "closed"];

    /// <summary>Bounds on a single case, so one case cannot grow without limit.</summary>
    private const int MaxTitle = 160;
    private const int MaxOwner = 80;
    private const int MaxSummary = 4000;
    private const int MaxLinkedFindings = 500;
    private const int MaxNotes = 200;

    private readonly Lock _gate = new();
    private readonly Dictionary<string, CaseRecord> _cases = new(StringComparer.Ordinal);
    private readonly Action<string> _warn;

    public string Path { get; }

    public CaseStore(string path, Action<string>? warn = null)
    {
        Path = System.IO.Path.GetFullPath(path);
        _warn = warn ?? (_ => { });
        Load();
    }

    // -------------------------------------------------------------------- io
    private void Load()
    {
        if (!File.Exists(Path)) return;
        try
        {
            var raw = JsonSerializer.Deserialize<Dictionary<string, CaseRecord>>(
                File.ReadAllText(Path), SuiteJson.Options);
            if (raw is null) return;

            foreach (var (key, value) in raw)
            {
                if (value is not null) _cases[key] = value;
            }
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
        {
            _warn("[!] Ignoring unreadable case file: " + exc.Message);
        }
    }

    /// <summary>Write through a temporary file and rename, so a crash cannot truncate it.</summary>
    private void Persist()
    {
        try
        {
            var parent = System.IO.Path.GetDirectoryName(Path);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

            var staging = Path + ".tmp";
            File.WriteAllText(staging, JsonSerializer.Serialize(_cases, SuiteJson.Pretty));
            File.Move(staging, Path, overwrite: true);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            _warn("[-] Could not persist cases: " + exc.Message);
        }
    }

    // ----------------------------------------------------------------- write
    public CaseRecord Create(string? title, string? owner = "", string? severity = Severity.Medium,
                             IEnumerable<string>? findingIds = null, string? summary = "")
    {
        var cleanTitle = Clip(title, MaxTitle);
        if (cleanTitle.Length == 0) throw new ArgumentException("title is required");

        var now = EventStore.NowIso();
        var record = new CaseRecord
        {
            Id = EventStore.NewId(),
            Title = cleanTitle,
            Owner = Clip(owner, MaxOwner),
            Status = "open",
            Severity = Storage.Severity.IsKnown(severity) ? severity! : Storage.Severity.Medium,
            Summary = Clip(summary, MaxSummary),
            FindingIds = [.. (findingIds ?? []).Where(f => !string.IsNullOrEmpty(f))
                                               .Distinct(StringComparer.Ordinal)
                                               .Take(MaxLinkedFindings)],
            CreatedAt = now,
            UpdatedAt = now,
        };

        lock (_gate)
        {
            _cases[record.Id] = record;
            Persist();
        }
        return record.Copy();
    }

    public CaseRecord? Update(string caseId, string? title = null, string? owner = null,
                              string? summary = null, string? status = null, string? severity = null)
    {
        lock (_gate)
        {
            if (!_cases.TryGetValue(caseId, out var record)) return null;

            // Each field is applied only when supplied, so a partial update
            // cannot blank the fields it did not mention.
            if (title is not null && Clip(title, MaxTitle).Length > 0)
                record.Title = Clip(title, MaxTitle);
            if (owner is not null) record.Owner = Clip(owner, MaxOwner);
            if (summary is not null) record.Summary = Clip(summary, MaxSummary);
            if (status is not null && Statuses.Contains(status, StringComparer.Ordinal))
                record.Status = status;
            if (severity is not null && Storage.Severity.IsKnown(severity))
                record.Severity = severity;

            record.UpdatedAt = EventStore.NowIso();
            Persist();
            return record.Copy();
        }
    }

    /// <summary>Attach or detach findings. Ids only; the evidence is never copied.</summary>
    public CaseRecord? Link(string caseId, IEnumerable<string> findingIds, bool detach = false)
    {
        lock (_gate)
        {
            if (!_cases.TryGetValue(caseId, out var record)) return null;

            if (detach)
            {
                var drop = findingIds.ToHashSet(StringComparer.Ordinal);
                record.FindingIds = [.. record.FindingIds.Where(f => !drop.Contains(f))];
            }
            else
            {
                foreach (var id in findingIds)
                {
                    if (string.IsNullOrEmpty(id) || record.FindingIds.Contains(id)) continue;
                    record.FindingIds.Add(id);
                }
                if (record.FindingIds.Count > MaxLinkedFindings)
                    record.FindingIds = [.. record.FindingIds.Take(MaxLinkedFindings)];
            }

            record.UpdatedAt = EventStore.NowIso();
            Persist();
            return record.Copy();
        }
    }

    public CaseRecord? AddNote(string caseId, string? text, string? author = "")
    {
        var clean = Clip(text, MaxSummary);
        if (clean.Length == 0) return null;

        lock (_gate)
        {
            if (!_cases.TryGetValue(caseId, out var record)) return null;

            record.Notes.Add(new CaseNote
            {
                At = EventStore.NowIso(),
                Author = Clip(author, MaxOwner),
                Text = clean,
            });

            // Keep the most recent; a case is a working record, not an archive.
            if (record.Notes.Count > MaxNotes)
                record.Notes = [.. record.Notes.Skip(record.Notes.Count - MaxNotes)];

            record.UpdatedAt = EventStore.NowIso();
            Persist();
            return record.Copy();
        }
    }

    public bool Delete(string caseId)
    {
        lock (_gate)
        {
            if (!_cases.Remove(caseId)) return false;
            Persist();
            return true;
        }
    }

    // ------------------------------------------------------------------ read
    public CaseRecord? Get(string caseId)
    {
        lock (_gate) return _cases.GetValueOrDefault(caseId)?.Copy();
    }

    /// <summary>All cases, worst severity first, then most recently touched.</summary>
    public List<CaseRecord> All(string status = "")
    {
        lock (_gate)
        {
            var cases = _cases.Values.Select(c => c.Copy());

            if (status.Length > 0 && status != "all")
                cases = cases.Where(c => c.Status == status);

            return [.. cases
                .OrderBy(c => Storage.Severity.Rank(c.Severity))
                .ThenByDescending(c => c.UpdatedAt, StringComparer.Ordinal)];
        }
    }

    public CaseSummary Summary()
    {
        lock (_gate)
        {
            var byStatus = Statuses.ToDictionary(s => s, _ => 0, StringComparer.Ordinal);
            foreach (var record in _cases.Values)
            {
                var key = record.Status.Length > 0 ? record.Status : "open";
                byStatus[key] = byStatus.GetValueOrDefault(key) + 1;
            }

            return new CaseSummary
            {
                Total = _cases.Count,
                ByStatus = byStatus,
                Open = _cases.Values.Count(c => c.Status != "closed"),
            };
        }
    }

    private static string Clip(string? value, int length)
    {
        var trimmed = (value ?? "").Trim();
        return trimmed.Length > length ? trimmed[..length] : trimmed;
    }
}

public sealed class CaseNote
{
    [JsonPropertyName("at")] public string At { get; set; } = "";
    [JsonPropertyName("author")] public string Author { get; set; } = "";
    [JsonPropertyName("text")] public string Text { get; set; } = "";

    public CaseNote Copy() => new() { At = At, Author = Author, Text = Text };
}

public sealed class CaseRecord
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("title")] public string Title { get; set; } = "";
    [JsonPropertyName("owner")] public string Owner { get; set; } = "";

    /// <summary>open, investigating, contained or closed.</summary>
    [JsonPropertyName("status")] public string Status { get; set; } = "open";

    [JsonPropertyName("severity")] public string Severity { get; set; } = Storage.Severity.Medium;
    [JsonPropertyName("summary")] public string Summary { get; set; } = "";

    /// <summary>
    /// Findings this case covers, by id. Never the findings themselves, so a
    /// case cannot drift out of date with its own evidence.
    /// </summary>
    [JsonPropertyName("finding_ids")] public List<string> FindingIds { get; set; } = [];

    [JsonPropertyName("notes")] public List<CaseNote> Notes { get; set; } = [];
    [JsonPropertyName("created_at")] public string CreatedAt { get; set; } = "";
    [JsonPropertyName("updated_at")] public string UpdatedAt { get; set; } = "";

    public CaseRecord Copy() => new()
    {
        Id = Id,
        Title = Title,
        Owner = Owner,
        Status = Status,
        Severity = Severity,
        Summary = Summary,
        FindingIds = [.. FindingIds],
        Notes = [.. Notes.Select(n => n.Copy())],
        CreatedAt = CreatedAt,
        UpdatedAt = UpdatedAt,
    };
}

public sealed class CaseSummary
{
    [JsonPropertyName("total")] public int Total { get; init; }
    [JsonPropertyName("by_status")] public Dictionary<string, int> ByStatus { get; init; } = [];

    /// <summary>Anything not closed, which is what an operator wants on the badge.</summary>
    [JsonPropertyName("open")] public int Open { get; init; }
}
