using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecuritySuite.Configuration;
using SecuritySuite.Intel;
using SecuritySuite.Remediation;
using SecuritySuite.Storage;

namespace SecuritySuite.Workspace;

/// <summary>
/// Strict JSON playbooks over a fixed action allowlist.
/// </summary>
/// <remarks>
/// <para>
/// Three actions exist and no more: annotate, guidance, quarantine. No scripts,
/// commands, templates, uploads or executable artifacts are accepted anywhere,
/// and notes are literal text. The only filesystem action is delegated to
/// <see cref="Remediator.Act"/>, so a playbook cannot reach past the six rails.
/// </para>
/// <para>
/// The Python build hand-wrote a JSON Schema validator limited to the
/// checked-in schema's vocabulary, because the schema is the contract the
/// dashboard builds its form from. Here the typed model is the validator:
/// <see cref="JsonUnmappedMemberHandling.Disallow"/> rejects unknown fields,
/// and the length and pattern constraints are checked explicitly. The schema
/// file is still served to the browser and still defines the contract; these
/// two must be changed together.
/// </para>
/// </remarks>
public sealed partial class PlaybookService
{
    private const int MaxPlaybooks = 100;
    private const int MaxPlaybookBytes = 32 * 1024;
    private const int MaxStorageBytes = 256 * 1024;

    public const string ActionAnnotate = "annotate";
    public const string ActionGuidance = "guidance";
    public const string ActionQuarantine = "quarantine";

    private static readonly string[] TriageStatuses =
        ["new", "acknowledged", "resolved", "false_positive"];

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_-]*$", RegexOptions.None, 2000)]
    private static partial Regex Identifier();

    private static readonly JsonSerializerOptions Strict = new(SuiteJson.Options)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly EventStore _store;
    private readonly Remediator? _remediator;
    private readonly GuidanceService? _guidance;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, PlaybookDefinition> _playbooks = new(StringComparer.Ordinal);

    private string _storageError = "";

    public string Path { get; }
    public string SchemaPath { get; }

    public PlaybookService(SuiteConfig cfg, EventStore store, Remediator? remediator,
                           GuidanceService? guidance = null)
    {
        _store = store;
        _remediator = remediator;
        _guidance = guidance;

        var sidecarDir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(cfg.TriageFile)) ?? ".";
        Path = System.IO.Path.Combine(sidecarDir, "playbooks.json");
        SchemaPath = System.IO.Path.Combine(SuitePaths.Root, "web", "playbook.schema.json");

        Load();
    }

    // -------------------------------------------------------------- catalogue
    /// <summary>Saved playbooks, plus metadata describing each allowed action.</summary>
    public PlaybookCatalogue List()
    {
        lock (_gate)
        {
            return new PlaybookCatalogue
            {
                Playbooks = [.. _playbooks.Values.Select(p => p.Copy())],
                Skills =
                [
                    new PlaybookSkill
                    {
                        Action = ActionAnnotate,
                        Label = "Set triage note and optional status",
                        Description = "Replaces the finding's triage note; preserves its " +
                                      "status unless supplied.",
                        Mutates = true,
                        RequiresConfirmation = false,
                    },
                    new PlaybookSkill
                    {
                        Action = ActionGuidance,
                        Label = "Read response guidance",
                        Description = "Returns advice only. Preview uses bundled local advice; " +
                                      "live runs may fetch CVE guidance when a provider is configured.",
                        Mutates = false,
                        RequiresConfirmation = false,
                    },
                    new PlaybookSkill
                    {
                        Action = ActionQuarantine,
                        Label = "Quarantine detected file",
                        Description = "Moves the detected file through the existing remediation " +
                                      "rails. Requires a recorded SHA-256; live runs also require " +
                                      "confirm=true. Does not isolate a host or block network traffic.",
                        Mutates = true,
                        RequiresConfirmation = true,
                    },
                ],
                Error = _storageError.Length > 0 ? _storageError : null,
            };
        }
    }

    // -------------------------------------------------------------- validation
    /// <summary>
    /// Parse and validate one definition. Throws <see cref="ArgumentException"/>.
    /// </summary>
    internal static PlaybookDefinition Validate(JsonNode? node)
    {
        if (node is null) throw new ArgumentException("payload must be a playbook object");

        var raw = node.ToJsonString();
        if (Encoding.UTF8.GetByteCount(raw) > MaxPlaybookBytes)
            throw new ArgumentException("JSON byte limit exceeded (" + MaxPlaybookBytes + ")");

        PlaybookDefinition? definition;
        try
        {
            definition = JsonSerializer.Deserialize<PlaybookDefinition>(raw, Strict);
        }
        catch (JsonException exc)
        {
            // Disallow turns an unknown field into a JsonException, which is the
            // "additionalProperties: false" the schema declares.
            throw new ArgumentException("payload contains unknown or invalid fields: " + exc.Message);
        }
        if (definition is null) throw new ArgumentException("payload must be a playbook object");

        if (definition.Version != 1)
            throw new ArgumentException("payload.version has an unsupported value/version");

        if (!Identifier().IsMatch(definition.Id) || definition.Id.Length > 64)
            throw new ArgumentException("payload.id has an invalid format");

        if (string.IsNullOrWhiteSpace(definition.Name) || definition.Name.Length > 120)
            throw new ArgumentException("payload.name has an invalid length");

        if (definition.Steps.Count is < 1 or > 12)
            throw new ArgumentException("payload.steps has an invalid number of steps (1-12)");

        for (var i = 0; i < definition.Steps.Count; i++)
        {
            var step = definition.Steps[i];
            var where = "payload.steps[" + i + "]";

            switch (step.Action)
            {
                case ActionAnnotate:
                    if (string.IsNullOrWhiteSpace(step.Note) || step.Note.Length > 2000)
                        throw new ArgumentException(where + ".note has an invalid length");
                    if (step.Status is not null && !TriageStatuses.Contains(step.Status))
                        throw new ArgumentException(where + ".status has an unsupported value");
                    break;

                case ActionGuidance:
                case ActionQuarantine:
                    // Neither takes a parameter. A note on one of these would be
                    // a step that looks like it does something it does not.
                    if (step.Note is not null || step.Status is not null)
                        throw new ArgumentException(where + " contains unknown fields");
                    break;

                default:
                    throw new ArgumentException(where + ".action has an unsupported value");
            }
        }
        return definition;
    }

    // ---------------------------------------------------------------- storage
    private void Load()
    {
        if (!File.Exists(Path)) return;
        try
        {
            var info = new FileInfo(Path);
            if (info.Length > MaxStorageBytes) throw new InvalidDataException("storage byte limit exceeded");

            var document = JsonSerializer.Deserialize<PlaybookStore>(File.ReadAllText(Path), Strict)
                ?? throw new InvalidDataException("invalid playbook storage envelope");

            if (document.Version != 1 || document.Playbooks.Count > MaxPlaybooks)
                throw new InvalidDataException("invalid playbook storage envelope");

            var loaded = new Dictionary<string, PlaybookDefinition>(StringComparer.Ordinal);
            foreach (var entry in document.Playbooks)
            {
                var definition = Validate(JsonSerializer.SerializeToNode(entry, SuiteJson.Options));
                if (!loaded.TryAdd(definition.Id, definition))
                    throw new InvalidDataException("duplicate saved playbook id");
            }
            lock (_gate)
            {
                _playbooks.Clear();
                foreach (var (key, value) in loaded) _playbooks[key] = value;
            }
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException
                                        or InvalidDataException or ArgumentException)
        {
            // Preserve corrupt or unsupported storage for inspection. Replacing
            // it with an apparently successful empty catalogue on the next save
            // would silently destroy the operator's playbooks.
            _storageError = "Could not load playbooks: " + exc.Message;
        }
    }

    /// <summary>Write via a temporary file, flushed, then renamed over the target.</summary>
    private void Persist(string json)
    {
        var parent = System.IO.Path.GetDirectoryName(Path);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

        var temporary = System.IO.Path.Combine(parent ?? ".",
            ".playbooks-" + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(json);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, Path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                try { File.Delete(temporary); }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
            }
        }
    }

    public PlaybookSaveResult Save(JsonNode? payload)
    {
        try
        {
            var definition = Validate(payload);
            lock (_gate)
            {
                if (_storageError.Length > 0)
                    return new PlaybookSaveResult { Ok = false, Error = _storageError };

                var candidate = new Dictionary<string, PlaybookDefinition>(_playbooks, StringComparer.Ordinal)
                {
                    [definition.Id] = definition,
                };
                if (candidate.Count > MaxPlaybooks)
                    throw new ArgumentException("at most " + MaxPlaybooks + " playbooks may be saved");

                var json = JsonSerializer.Serialize(
                    new PlaybookStore { Version = 1, Playbooks = [.. candidate.Values] },
                    SuiteJson.Pretty);
                if (Encoding.UTF8.GetByteCount(json) > MaxStorageBytes)
                    throw new ArgumentException("JSON byte limit exceeded (" + MaxStorageBytes + ")");

                Persist(json);
                _playbooks.Clear();
                foreach (var (key, value) in candidate) _playbooks[key] = value;
            }
            return new PlaybookSaveResult { Ok = true, Playbook = definition.Copy() };
        }
        catch (Exception exc) when (exc is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return new PlaybookSaveResult { Ok = false, Error = exc.Message };
        }
    }

    // -------------------------------------------------------------------- run
    public async Task<PlaybookRunResult> RunAsync(PlaybookRunRequest request,
                                                   CancellationToken token = default)
    {
        var result = new PlaybookRunResult
        {
            FindingId = request.FindingId ?? "",
            DryRun = request.DryRun ?? true,
        };

        try
        {
            PlaybookDefinition definition;
            if (request.PlaybookId is { Length: > 0 } saved)
            {
                lock (_gate)
                {
                    if (!_playbooks.TryGetValue(saved, out var found))
                        throw new ArgumentException("unknown saved playbook");
                    definition = found.Copy();
                }
            }
            else
            {
                definition = Validate(request.Playbook);
            }
            result.Playbook = definition.Id;

            var findingId = request.FindingId ?? "";
            if (!Identifier().IsMatch(findingId))
                throw new ArgumentException("finding_id has an invalid format");

            var finding = _store.Find(findingId);
            if (finding is null || !finding.IsMatch)
                throw new ArgumentException("only a stored yara_match finding can run a playbook");

            var dryRun = result.DryRun;
            var confirm = request.Confirm ?? false;
            var hasQuarantine = definition.Steps.Any(s => s.Action == ActionQuarantine);

            if (hasQuarantine && !dryRun)
            {
                if (!confirm)
                {
                    result.Refused = "confirmation required";
                    result.Error = "live quarantine requires confirm=true";
                    return result;
                }

                // Preview first. A live run that is going to be refused should
                // be refused before any earlier step has already mutated state.
                var preview = Quarantine(findingId, definition, dryRun: true, confirm: false);
                if (preview is not { Ok: true })
                {
                    result.Refused = preview?.Refused ?? "quarantine refused";
                    result.Error = result.Refused;
                    result.Preflight = preview;
                    return result;
                }
            }

            foreach (var step in definition.Steps)
            {
                var outcome = new PlaybookStepResult { Action = step.Action, Ok = true };
                try
                {
                    switch (step.Action)
                    {
                        case ActionAnnotate:
                            {
                                var status = step.Status ?? (finding.Status.Length > 0 ? finding.Status : "new");
                                if (!dryRun && _store.SetStatus(findingId, status, step.Note ?? "") is null)
                                    throw new InvalidOperationException("finding is no longer stored");

                                finding.Status = status;
                                finding.TriageNote = step.Note;
                                outcome.Outcome = dryRun ? "would annotate" : "annotated";
                                outcome.Status = status;
                                outcome.Note = step.Note;
                                break;
                            }

                        case ActionGuidance:
                            outcome.Outcome = "guidance";
                            outcome.Guidance = await GuidanceFor(finding, dryRun, token).ConfigureAwait(false);
                            break;

                        case ActionQuarantine:
                            outcome.Remediation = Quarantine(findingId, definition, dryRun,
                                confirm && !dryRun);
                            outcome.Ok = outcome.Remediation?.Ok ?? false;
                            outcome.Outcome = outcome.Remediation?.Outcome;
                            outcome.Refused = outcome.Remediation?.Refused;
                            break;
                    }
                }
                catch (Exception exc) when (exc is ArgumentException or InvalidOperationException
                                                or IOException or UnauthorizedAccessException)
                {
                    outcome.Ok = false;
                    outcome.Error = exc.Message;
                }

                result.Steps.Add(outcome);
                if (!outcome.Ok)
                {
                    // Stop on failure. Completed live steps are not rolled back,
                    // which is why the quarantine preview runs first.
                    result.Error = outcome.Error ?? outcome.Refused ?? "step failed";
                    result.Refused = outcome.Refused ?? "step failed";
                    return result;
                }
            }
            result.Ok = true;
        }
        catch (Exception exc) when (exc is ArgumentException or IOException or UnauthorizedAccessException)
        {
            result.Error = exc.Message;
        }
        return result;
    }

    private async Task<object> GuidanceFor(SuiteEvent finding, bool dryRun, CancellationToken token)
    {
        if (!dryRun && _guidance is not null)
            return await _guidance.ForFindingAsync(finding, token).ConfigureAwait(false);

        // A preview must not reach the network: the operator is looking at what
        // would happen, and a CVE lookup here would make a dry run slow and
        // rate-limited.
        return new
        {
            finding = finding.Id,
            playbook = GuidanceService.PlaybookFor(finding),
            offline = true,
            cve_lookups_skipped = true,
        };
    }

    /// <summary>
    /// Quarantine through the remediator, after refusing the sidecar itself.
    /// </summary>
    /// <remarks>
    /// The playbook storage file may live outside the remediator's suite-owned
    /// tree when the triage file is configured elsewhere, so a playbook whose
    /// finding happened to name that file could otherwise quarantine the
    /// catalogue it is running from.
    /// </remarks>
    private RemediationResult? Quarantine(string findingId, PlaybookDefinition definition,
                                          bool dryRun, bool confirm)
    {
        if (_remediator is null)
            return new RemediationResult { Action = ActionQuarantine, Finding = findingId }
                .Refuse("remediation not enabled");

        var finding = _store.Find(findingId);
        if (finding is null || !finding.IsMatch)
            return new RemediationResult { Action = ActionQuarantine, Finding = findingId }
                .Refuse("not a stored yara_match finding");

        if (finding.Sha256 is not { Length: 64 } digest ||
            !digest.All(Uri.IsHexDigit))
        {
            return new RemediationResult { Action = ActionQuarantine, Finding = findingId }
                .Refuse("a recorded SHA-256 is required");
        }

        var path = finding.FilePath;
        if (string.IsNullOrEmpty(path) || path.Contains('\0'))
            return new RemediationResult { Action = ActionQuarantine, Finding = findingId }
                .Refuse("a stored file path is required");

        if (PathUtil.Norm(path) == PathUtil.Norm(Path))
            return new RemediationResult { Action = ActionQuarantine, Finding = findingId, Path = path }
                .Refuse("suite-owned playbook storage");

        return _remediator.Act(findingId, RemediationActions.Quarantine, confirm, dryRun,
            allowDirectory: false, trigger: "playbook:" + definition.Id);
    }

    /// <summary>The checked-in schema, served so the dashboard can build its form.</summary>
    public string SchemaJson()
    {
        try { return File.ReadAllText(SchemaPath); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return "{}";
        }
    }
}

// ----------------------------------------------------------------------- models
public sealed class PlaybookStep
{
    [JsonPropertyName("action")] public string Action { get; set; } = "";

    [JsonPropertyName("note")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Note { get; set; }

    [JsonPropertyName("status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Status { get; set; }

    public PlaybookStep Copy() => new() { Action = Action, Note = Note, Status = Status };
}

public sealed class PlaybookDefinition
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("version")] public int Version { get; set; } = 1;
    [JsonPropertyName("steps")] public List<PlaybookStep> Steps { get; set; } = [];

    public PlaybookDefinition Copy() => new()
    {
        Id = Id,
        Name = Name,
        Version = Version,
        Steps = [.. Steps.Select(s => s.Copy())],
    };
}

internal sealed class PlaybookStore
{
    [JsonPropertyName("version")] public int Version { get; set; }
    [JsonPropertyName("playbooks")] public List<PlaybookDefinition> Playbooks { get; set; } = [];
}

public sealed class PlaybookSkill
{
    [JsonPropertyName("action")] public string Action { get; init; } = "";
    [JsonPropertyName("label")] public string Label { get; init; } = "";
    [JsonPropertyName("description")] public string Description { get; init; } = "";

    /// <summary>Whether running this step changes stored state.</summary>
    [JsonPropertyName("mutates")] public bool Mutates { get; init; }

    [JsonPropertyName("requires_confirmation")] public bool RequiresConfirmation { get; init; }
}

public sealed class PlaybookCatalogue
{
    [JsonPropertyName("playbooks")] public List<PlaybookDefinition> Playbooks { get; init; } = [];
    [JsonPropertyName("skills")] public List<PlaybookSkill> Skills { get; init; } = [];

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}

public sealed class PlaybookSaveResult
{
    [JsonPropertyName("ok")] public bool Ok { get; init; }

    [JsonPropertyName("playbook")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PlaybookDefinition? Playbook { get; init; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}

/// <summary>
/// A run request. <c>playbook</c> is either a saved id or a whole definition,
/// which is why both shapes are accepted here and resolved by the service.
/// </summary>
public sealed class PlaybookRunRequest
{
    public string? PlaybookId { get; set; }
    public JsonNode? Playbook { get; set; }
    public string? FindingId { get; set; }
    public bool? DryRun { get; set; }
    public bool? Confirm { get; set; }
}

public sealed class PlaybookStepResult
{
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("ok")] public bool Ok { get; set; }

    [JsonPropertyName("outcome")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Outcome { get; set; }

    [JsonPropertyName("status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Status { get; set; }

    [JsonPropertyName("note")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Note { get; set; }

    [JsonPropertyName("guidance")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Guidance { get; set; }

    [JsonPropertyName("remediation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public RemediationResult? Remediation { get; set; }

    [JsonPropertyName("refused")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Refused { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}

public sealed class PlaybookRunResult
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }

    [JsonPropertyName("playbook")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Playbook { get; set; }

    [JsonPropertyName("finding_id")] public string FindingId { get; set; } = "";
    [JsonPropertyName("dry_run")] public bool DryRun { get; set; }
    [JsonPropertyName("steps")] public List<PlaybookStepResult> Steps { get; set; } = [];

    [JsonPropertyName("preflight")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public RemediationResult? Preflight { get; set; }

    [JsonPropertyName("refused")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Refused { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}
