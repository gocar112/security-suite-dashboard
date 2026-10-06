using System.Text.Json;
using SecuritySuite.Configuration;
using SecuritySuite.Detection;
using SecuritySuite.Storage;

namespace SecuritySuite.Remediation;

/// <summary>
/// Acting on a detection: delete, quarantine, restore, purge.
/// </summary>
/// <remarks>
/// <para>
/// Everything else in this assembly is read-only. This is not, and that
/// changes the stakes completely. A detection that is merely wrong produces an
/// alert somebody dismisses; a <em>remediation</em> that is wrong destroys a
/// file.
/// </para>
/// <para>
/// The rule set driving it holds 1,004 rules, 931 of them generated. Pointed at
/// this project's own directory it flags 27 of 55 tracked files, 16 of them
/// critical, including the detector's own rule files. So the question this
/// class answers is not "can I delete a file" but "how do I refuse to delete
/// the wrong one".
/// </para>
/// <para>Six rails, each producing a distinct refusal:</para>
/// <list type="number">
/// <item><description>
/// The target is resolved from a stored finding, never from a path supplied by
/// the caller. The HTTP API must not become an arbitrary-file-deletion
/// primitive, and it has no CSRF token — only loopback binding, a Host check
/// and a content-type requirement.
/// </description></item>
/// <item><description>
/// SHA-256 is re-verified immediately before acting. If the file changed since
/// detection it is no longer the thing that was detected.
/// </description></item>
/// <item><description>
/// The path must resolve inside a configured watch root, or an explicitly
/// allowed remediation root, compared after link resolution so a symlink
/// cannot walk out. See <see cref="PathUtil"/>.
/// </description></item>
/// <item><description>
/// Directories are refused unless explicitly requested, and then only inside
/// those same roots.
/// </description></item>
/// <item><description>
/// A dry run reports the full decision without touching anything, and a real
/// action additionally requires an explicit confirmation.
/// </description></item>
/// <item><description>
/// Suite-owned paths are refused unconditionally, ahead of every other check.
/// Without this rail an operator who points a watch root at the project
/// deletes the rule set that protects them.
/// </description></item>
/// </list>
/// <para>
/// Every attempt, including every refusal, is appended to the findings log as
/// an audit record. The triage sidecar keeps only latest state, so it cannot
/// serve as the history of a destructive action.
/// </para>
/// </remarks>
public sealed class Remediator
{
    private const string MetaSuffix = ".remediation.json";

    private readonly SuiteConfig _cfg;
    private readonly EventStore _store;
    private readonly Action<string> _report;
    private readonly Lock _gate = new();
    private Dictionary<string, RemediationState> _state = new(StringComparer.Ordinal);

    public string QuarantineDir { get; }
    public string StatePath { get; }

    public Remediator(SuiteConfig cfg, EventStore store, Action<string>? report = null)
    {
        _cfg = cfg;
        _store = store;
        _report = report ?? (message => Console.Error.WriteLine(message));

        QuarantineDir = Path.GetFullPath(cfg.QuarantineDir);
        StatePath = Path.GetFullPath(cfg.RemediationFile);

        Directory.CreateDirectory(QuarantineDir);
        var parent = Path.GetDirectoryName(StatePath);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

        LoadState();
    }

    // ------------------------------------------------------------- protection
    public string ProjectRoot => _cfg.ProjectRoot;

    /// <summary>
    /// Paths this tool must never remediate, whatever else is configured.
    /// </summary>
    /// <remarks>
    /// The project directory is protected <em>wholesale</em>. An earlier
    /// version listed only the obvious subdirectories — the package, the rules,
    /// the book — and a test that pointed a watch root at the project promptly
    /// deleted README.md, because a loose file in the project root matched no
    /// entry. Enumerating what to protect is the wrong shape: the list is never
    /// complete. Protect the tree, then carve out the watch paths.
    /// </remarks>
    public List<string> SuiteOwnedRoots()
    {
        var roots = new List<string>
        {
            ProjectRoot,
            QuarantineDir,
            Path.Combine(ProjectRoot, "src"),
            Path.Combine(ProjectRoot, "tests"),
            Path.Combine(ProjectRoot, "book"),
            Path.Combine(ProjectRoot, "assets"),
            Path.Combine(ProjectRoot, "web"),
            Path.Combine(ProjectRoot, "data"),
            _cfg.RulesDir,
        };

        // Individual state paths, in case they are configured outside the tree.
        roots.AddRange([
            _cfg.FindingsLog, _cfg.TriageFile, _cfg.RemediationFile,
            _cfg.NvdCacheDir, _cfg.GuidanceCacheDir, _cfg.OsvCacheDir, _cfg.VtCacheDir,
        ]);

        // Workbench sidecars may also sit outside the project tree.
        var triageDir = Path.GetDirectoryName(_cfg.TriageFile);
        if (!string.IsNullOrEmpty(triageDir))
        {
            roots.AddRange(
                new[] { "playbooks.json", "response-policy.json", "blocked-domains.json" }
                    .Select(name => Path.Combine(triageDir, name)));
        }

        return [.. roots.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>
    /// Watch paths strictly below the project root that stay remediable.
    /// </summary>
    /// <remarks>
    /// <c>uploads/</c> lives inside the project and is the whole point of the
    /// tool, so it must not inherit the project's blanket protection. A watch
    /// path that <em>is</em> the project root grants nothing, or pointing the
    /// monitor at the project would re-open everything rail 6 closes.
    /// </remarks>
    private List<string> CarveOuts()
    {
        var project = PathUtil.Norm(ProjectRoot);
        var protectedChildren = SuiteOwnedRoots()
            .Select(PathUtil.Norm)
            .Where(r => r != project)
            .ToList();

        var carved = new List<string>();
        foreach (var watched in PermittedRoots())
        {
            var resolved = PathUtil.Norm(watched);
            if (resolved == project) continue;
            if (!PathUtil.IsWithin(resolved, project)) continue;

            // A watch path that overlaps a protected child in either direction
            // is not carved out: uploads/ qualifies, data/ does not, and
            // neither does a parent of data/.
            if (protectedChildren.Any(root => PathUtil.Overlaps(resolved, root))) continue;
            carved.Add(watched);
        }
        return carved;
    }

    /// <summary>The protecting root, or "" when the path may be acted on.</summary>
    public string IsProtected(string path)
    {
        foreach (var carve in CarveOuts())
        {
            if (PathUtil.IsWithin(path, carve)) return "";   // inside uploads/ or similar
        }
        foreach (var root in SuiteOwnedRoots())
        {
            if (PathUtil.IsWithin(path, root)) return root;
        }
        return "";
    }

    public List<string> PermittedRoots() =>
        [.. _cfg.WatchPaths.Concat(_cfg.RemediationRoots).Where(r => !string.IsNullOrWhiteSpace(r))];

    // ------------------------------------------------------------------ rails
    /// <summary>Run every rail. Throws <see cref="RefusedException"/> on the first failure.</summary>
    private Dictionary<string, string> Check(string path, bool allowDirectory)
    {
        var checks = new Dictionary<string, string>(StringComparer.Ordinal);

        // Rail 6 first: suite-owned paths lose regardless of configuration.
        var protector = IsProtected(path);
        if (protector.Length > 0)
            throw new RefusedException("suite-owned path", "refusing to remediate inside " + protector);
        checks["suite_owned"] = "clear";

        // Rail 3: confinement.
        var roots = PermittedRoots();
        if (!roots.Any(root => PathUtil.IsWithin(path, root)))
            throw new RefusedException("outside permitted roots", "not inside any of: " + string.Join(", ", roots));
        checks["confinement"] = "clear";

        var isDirectory = Directory.Exists(path);
        if (!isDirectory && !File.Exists(path))
            throw new RefusedException("target is gone", path + " no longer exists");

        // Rail 4: directories.
        if (isDirectory)
        {
            if (!allowDirectory)
                throw new RefusedException("target is a directory", "pass allow_directory to act on a folder");
            checks["directory"] = "permitted";
        }
        else
        {
            checks["directory"] = "n/a";
        }
        return checks;
    }

    /// <summary>Rail 2. A directory has no hash, so this is skipped for one.</summary>
    private static Dictionary<string, string> VerifyHash(string path, string? expected,
                                                         Dictionary<string, string> checks)
    {
        if (Directory.Exists(path))
        {
            checks["hash"] = "skipped (directory)";
            return checks;
        }
        if (string.IsNullOrEmpty(expected))
        {
            checks["hash"] = "no recorded hash on the finding";
            return checks;
        }

        string actual;
        try
        {
            actual = YaraEngine.Sha256Of(path);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            throw new RefusedException("could not read the target", exc.Message);
        }

        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new RefusedException("hash mismatch",
                "file changed since detection (recorded " + Short(expected) +
                ", now " + Short(actual) + ")");
        }
        checks["hash"] = "matches the finding";
        return checks;

        static string Short(string hash) => hash.Length > 12 ? hash[..12] : hash;
    }

    // ------------------------------------------------------------------ state
    private void LoadState()
    {
        if (!File.Exists(StatePath)) return;
        try
        {
            _state = JsonSerializer.Deserialize<Dictionary<string, RemediationState>>(
                File.ReadAllText(StatePath), SuiteJson.Options) ?? new(StringComparer.Ordinal);
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
        {
            _report("[!] Ignoring unreadable remediation state: " + exc.Message);
            _state = new Dictionary<string, RemediationState>(StringComparer.Ordinal);
        }
    }

    private void SaveState()
    {
        try
        {
            File.WriteAllText(StatePath, JsonSerializer.Serialize(_state, SuiteJson.Pretty));
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            _report("[-] Could not persist remediation state: " + exc.Message);
        }
    }

    /// <summary>Append-only. Refusals are recorded as deliberately as successes.</summary>
    private void Audit(RemediationResult result)
    {
        var entry = new SuiteEvent
        {
            EventType = SuiteEvent.TypeRemediation,
            Timestamp = EventStore.NowIso(),
            FilePath = result.Path,
            Severity = result.Severity,
            Trigger = result.Trigger,
        };
        foreach (var (key, value) in Flatten(result)) entry.SetExtra(key, value);
        _store.Add(entry);
    }

    private static IEnumerable<KeyValuePair<string, object?>> Flatten(RemediationResult result)
    {
        yield return new("ok", result.Ok);
        yield return new("action", result.Action);
        yield return new("finding", result.Finding);
        yield return new("dry_run", result.DryRun);
        yield return new("outcome", result.Outcome);
        if (result.Refused is not null) yield return new("refused", result.Refused);
        if (result.Detail is not null) yield return new("detail", result.Detail);
        if (result.Rules is not null) yield return new("rules", result.Rules);
        if (result.Checks is not null) yield return new("checks", result.Checks);
    }

    public RemediationState? StateFor(string findingId)
    {
        lock (_gate) return _state.GetValueOrDefault(findingId);
    }

    /// <summary>Attach remediation and target state to a finding for the UI.</summary>
    public SuiteEvent Annotate(SuiteEvent finding)
    {
        if (!finding.IsMatch) return finding;

        var item = finding.Clone();
        RemediationState? state;
        lock (_gate) state = _state.GetValueOrDefault(item.Id);
        if (state is not null) item.SetExtra("remediation", state);

        var path = item.FilePath ?? "";
        var exists = path.Length > 0 && (File.Exists(path) || Directory.Exists(path));
        item.SetExtra("target_exists", exists);
        item.SetExtra("target_state",
            state is not null && state.Action is RemediationActions.Delete
                or RemediationActions.Quarantine or "purged"
                ? state.Action
                : exists ? "present" : "gone");
        return item;
    }

    public List<SuiteEvent> AnnotateMany(IEnumerable<SuiteEvent> findings) =>
        [.. findings.Select(Annotate)];

    /// <summary>Why this target cannot be acted on again, or "" when it can.</summary>
    private static string TargetRefusal(SuiteEvent annotated) =>
        annotated.GetExtra<string>("target_state") switch
        {
            "gone" => "target is gone",
            RemediationActions.Delete => "already deleted",
            RemediationActions.Quarantine => "already quarantined",
            "purged" => "already purged",
            _ => "",
        };

    // ---------------------------------------------------------------- actions
    /// <summary>
    /// Resolve a finding, run the rails, and act. Never throws.
    /// </summary>
    /// <remarks>
    /// Returning a refusal rather than raising is deliberate: this is called
    /// from an HTTP handler and from the monitor's auto-rule, and in both cases
    /// the refusal and its reason are the useful result.
    /// </remarks>
    public RemediationResult Act(string findingId, string action, bool confirm = false,
                                 bool dryRun = false, bool allowDirectory = false,
                                 string trigger = "manual")
    {
        var result = new RemediationResult
        {
            Action = action,
            Finding = findingId,
            DryRun = dryRun,
            Trigger = trigger,
        };

        if (!RemediationActions.IsKnown(action))
            return Finish(result.Refuse("unknown action",
                "expected one of " + string.Join(", ", RemediationActions.All)), dryRun);

        var finding = _store.Find(findingId);
        if (finding is null)
            return Finish(result.Refuse("unknown finding", "no finding with id " + findingId), dryRun);

        if (trigger == "auto")
        {
            var refusal = AutoRefusal(finding, action);
            if (refusal.Length > 0) return Finish(result.Refuse(refusal), dryRun);

            // An unattended action never operates on a directory, whatever the
            // caller passed.
            allowDirectory = false;
        }

        if (RemediationActions.IsQuarantineAction(action))
            return FromQuarantine(findingId, finding, action, confirm, dryRun, trigger);

        if (!finding.IsMatch)
        {
            result.Path = finding.FilePath;
            return Finish(result.Refuse("not a detection",
                "only yara_match findings can be remediated"), dryRun);
        }

        var path = finding.FilePath ?? "";
        result.Path = path;
        result.Severity = finding.Severity;
        result.Rules = finding.RuleNames;

        RemediationState? previous;
        lock (_gate) previous = _state.GetValueOrDefault(findingId);
        if (previous is not null && previous.Action is RemediationActions.Delete
            or RemediationActions.Quarantine or "purged")
        {
            var label = previous.Action switch
            {
                RemediationActions.Delete => "already deleted",
                RemediationActions.Quarantine => "already quarantined",
                "purged" => "already purged",
                _ => "already handled",
            };
            result.Outcome = label;
            result.Remediation = previous;
            return Finish(result.Refuse(label, previous.Detail), dryRun);
        }

        try
        {
            var checks = Check(path, allowDirectory);
            result.Checks = VerifyHash(path, finding.Sha256, checks);
        }
        catch (RefusedException exc)
        {
            return Finish(result.Refuse(exc.Reason, exc.Detail), dryRun);
        }

        if (dryRun)
        {
            return result.Succeed("would " + action, "dry run - nothing was changed");
        }

        // Rail 5's companion: an explicit confirmation for a destructive act.
        if (!confirm)
        {
            return Finish(result.Refuse("confirmation required", "resend with confirm=true"), false);
        }

        string detail;
        try
        {
            detail = action == RemediationActions.Delete
                ? DeleteTarget(path)
                : QuarantineTarget(findingId, finding, path);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            result.Outcome = "failed";
            Audit(result.Refuse("filesystem error", exc.Message));
            return result;
        }

        var state = new RemediationState
        {
            Action = action,
            At = EventStore.NowIso(),
            Path = path,
            Detail = detail,
            Trigger = trigger,
        };
        lock (_gate)
        {
            _state[findingId] = state;
            SaveState();
        }
        finding.SetExtra("remediation", state);

        result.Succeed(RemediationActions.PastTense(action), detail);
        result.Remediation = state;
        Audit(result);
        _store.Broadcast("Remediated " +
            (Path.GetFileName(path) is { Length: > 0 } name ? name : path) + ": " + result.Outcome);
        return result;
    }

    /// <summary>Audit a refusal unless this was only a dry run.</summary>
    private RemediationResult Finish(RemediationResult result, bool dryRun)
    {
        if (!dryRun) Audit(result);
        return result;
    }

    private static string DeleteTarget(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
            return "directory deleted";
        }
        var size = new FileInfo(path).Length;
        File.Delete(path);
        return "deleted (" + size + " bytes, unrecoverable)";
    }

    private string QuarantineTarget(string findingId, SuiteEvent finding, string path)
    {
        var holding = Path.Combine(QuarantineDir, findingId);
        Directory.CreateDirectory(holding);

        var name = Path.GetFileName(path);
        var target = Path.Combine(holding, name);
        File.Move(path, target, overwrite: false);

        var meta = new QuarantineMetadata
        {
            Finding = findingId,
            OriginalPath = path,
            QuarantinedAt = EventStore.NowIso(),
            Sha256 = finding.Sha256 ?? "",
            Severity = finding.Severity,
            Rules = finding.RuleNames ?? [],
        };
        File.WriteAllText(Path.Combine(holding, name + MetaSuffix),
            JsonSerializer.Serialize(meta, SuiteJson.Pretty));
        return "moved to " + target;
    }

    private RemediationResult FromQuarantine(string findingId, SuiteEvent finding, string action,
                                             bool confirm, bool dryRun, string trigger)
    {
        var result = new RemediationResult
        {
            Action = action,
            Finding = findingId,
            DryRun = dryRun,
            Trigger = trigger,
        };

        RemediationState? state;
        lock (_gate) state = _state.GetValueOrDefault(findingId);
        if (state is null || state.Action != RemediationActions.Quarantine)
            return Finish(result.Refuse("not quarantined", "this finding has no quarantined file"), dryRun);

        var holding = Path.Combine(QuarantineDir, findingId);
        var original = state.Path;
        var stored = Path.Combine(holding, Path.GetFileName(original));

        if (!File.Exists(stored))
            return Finish(result.Refuse("quarantined file is gone", stored), dryRun);

        result.Path = stored;

        if (action == RemediationActions.Restore)
        {
            // Restoring writes a file back to an arbitrary recorded path, so it
            // gets the same confinement and self-protection rails as a delete.
            try
            {
                var protector = IsProtected(original);
                if (protector.Length > 0)
                    throw new RefusedException("suite-owned path", "refusing to restore inside " + protector);

                var roots = PermittedRoots();
                if (!roots.Any(root => PathUtil.IsWithin(original, root)))
                    throw new RefusedException("outside permitted roots",
                        "not inside any of: " + string.Join(", ", roots));

                if (File.Exists(original) || Directory.Exists(original))
                    throw new RefusedException("restore target exists", original + " already exists");
            }
            catch (RefusedException exc)
            {
                return Finish(result.Refuse(exc.Reason, exc.Detail), dryRun);
            }
        }

        if (dryRun) return result.Succeed("would " + action, "dry run - nothing was changed");
        if (!confirm)
            return Finish(result.Refuse("confirmation required", "resend with confirm=true"), false);

        string detail;
        try
        {
            if (action == RemediationActions.Restore)
            {
                var parent = Path.GetDirectoryName(original);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                File.Move(stored, original, overwrite: false);
                detail = "restored to " + original;
            }
            else
            {
                File.Delete(stored);
                detail = "purged from quarantine (unrecoverable)";

                var meta = Path.Combine(holding, Path.GetFileName(original) + MetaSuffix);
                if (File.Exists(meta)) File.Delete(meta);
            }
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            result.Outcome = "failed";
            Audit(result.Refuse("filesystem error", exc.Message));
            return result;
        }

        lock (_gate)
        {
            if (action == RemediationActions.Purge)
            {
                _state[findingId] = new RemediationState
                {
                    Action = "purged",
                    At = EventStore.NowIso(),
                    Path = original,
                    Detail = detail,
                    Trigger = trigger,
                };
            }
            else
            {
                _state.Remove(findingId);
            }
            SaveState();
        }

        result.Succeed(RemediationActions.PastTense(action), detail);
        Audit(result);
        return result;
    }

    // ------------------------------------------------------------------- bulk
    /// <summary>
    /// Act on every outstanding detection matching a filter.
    /// </summary>
    /// <remarks>
    /// Defaults to quarantine and to a dry run, because a filtered destructive
    /// sweep is the single most dangerous operation here: one wrong extension
    /// filter and it is applied to every match at once.
    /// </remarks>
    public BulkResult Bulk(string severity = "", IEnumerable<string>? extensions = null,
                           string action = RemediationActions.Quarantine,
                           bool confirm = false, bool dryRun = true, int limit = 50)
    {
        var wanted = (extensions ?? [])
            .Where(e => !string.IsNullOrWhiteSpace(e))
            .Select(e => e.TrimStart('.').ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);

        var candidates = new List<SuiteEvent>();
        var seenTargets = new HashSet<string>(StringComparer.Ordinal);

        foreach (var item in _store.Events(limit: 2000, eventType: SuiteEvent.TypeMatch))
        {
            lock (_gate)
            {
                if (_state.ContainsKey(item.Id)) continue;    // already acted on
            }

            if (severity.Length > 0 && severity != "all")
            {
                if (!Severity.MeetsThreshold(item.Severity, severity)) continue;

                // "critical" stays exact because it is the top rank, so a
                // threshold comparison would otherwise match nothing extra and
                // read as though it did.
                if (severity == Severity.Critical && item.Severity != Severity.Critical) continue;
            }

            var name = item.FileName ?? Path.GetFileName(item.FilePath ?? "");
            if (wanted.Count > 0)
            {
                var suffix = Path.GetExtension(name).TrimStart('.').ToLowerInvariant();
                if (!wanted.Contains(suffix)) continue;
            }

            // Two findings can name the same file; acting twice is at best a
            // confusing audit trail and at worst a double delete.
            var key = PathUtil.Norm(item.FilePath ?? item.Id);
            if (!seenTargets.Add(key)) continue;

            candidates.Add(item);
            if (candidates.Count >= limit) break;
        }

        var results = new List<RemediationResult>(candidates.Count);
        foreach (var item in candidates)
        {
            var annotated = Annotate(item);
            var refusal = TargetRefusal(annotated);
            if (refusal.Length > 0)
            {
                var refused = new RemediationResult
                {
                    Action = action,
                    Finding = item.Id,
                    Path = item.FilePath,
                    DryRun = dryRun,
                    Trigger = "bulk",
                    Severity = item.Severity,
                    Rules = item.RuleNames,
                };
                refused.Refuse(refusal,
                    "the latest target state is " + annotated.GetExtra<string>("target_state"));
                results.Add(Finish(refused, dryRun));
                continue;
            }
            results.Add(Act(item.Id, action, confirm, dryRun, trigger: "bulk"));
        }

        return new BulkResult
        {
            Matched = candidates.Count,
            Acted = results.Count(r => r.Ok && !r.DryRun),
            Actionable = results.Count(r => r.Refused is null && (r.Ok || r.DryRun)),
            Refused = results.Count(r => r.Refused is not null),
            DryRun = dryRun,
            Action = action,
            Severity = severity.Length > 0 ? severity : "all",
            Extensions = [.. wanted],
            Results = results,
        };
    }

    // ----------------------------------------------------------------- status
    public RemediationStatus Status()
    {
        lock (_gate)
        {
            return new RemediationStatus
            {
                QuarantineDir = QuarantineDir,
                Quarantined = _state.Values.Count(v => v.Action == RemediationActions.Quarantine),
                ActedOn = _state.Count,
                AutoRemediate = _cfg.AutoRemediate,
                AutoAction = _cfg.AutoRemediateAction,
                AutoSeverity = _cfg.AutoRemediateSeverity,
                PermittedRoots = PermittedRoots(),
                ProtectedRoots = SuiteOwnedRoots(),
                Recent = _store.Events(limit: 40, eventType: SuiteEvent.TypeRemediation),
            };
        }
    }

    // -------------------------------------------------------------- auto rule
    /// <summary>
    /// Why an unattended action is refused, or "" when it is permitted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An unattended action needs a much stronger signal than an operator
    /// clicking a button, because nobody is there to notice a false positive.
    /// So it requires one rule match that is simultaneously high-confidence,
    /// above the severity threshold, and not from a category known to produce
    /// false positives.
    /// </para>
    /// <para>
    /// The generated NVD rules are excluded by name, namespace, tag and
    /// generator metadata. All 931 of them were produced from CVE text and have
    /// never been validated against real malware, and they are exactly the
    /// rules that flagged this project's own book PDF. Letting them drive an
    /// unattended action would be the worst of both worlds.
    /// </para>
    /// <para>
    /// Confidence and severity are read from the <em>same</em> match. Taking
    /// the confidence from one rule and the severity from another would let two
    /// unrelated weak matches combine into an action neither justifies.
    /// </para>
    /// </remarks>
    internal string AutoRefusal(SuiteEvent finding, string action)
    {
        if (!_cfg.AutoRemediate) return "automatic remediation is disabled";
        if (!RemediationActions.IsAutoEligible(action)) return "automatic action must be quarantine";
        if (!finding.IsMatch) return "not a detection";

        var threshold = _cfg.AutoRemediateSeverity;
        if (!Severity.IsKnown(threshold)) return "invalid automatic severity threshold";

        foreach (var match in finding.Matches ?? [])
        {
            if (string.IsNullOrEmpty(match.Rule) || string.IsNullOrEmpty(match.Namespace)) continue;

            var tags = match.Tags.Select(t => t.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
            if (tags.Contains("test") || tags.Contains("vulnerable_component")) continue;

            var ns = match.Namespace.ToLowerInvariant();
            if (ns is "demo" or "builtin" or "nvd_components" or "generated") continue;

            var name = match.Rule.ToLowerInvariant();
            if (name.StartsWith("nvd_cve_") || name.StartsWith("demo_") ||
                name.StartsWith("eicar_") || name.StartsWith("securitysuite_fallback_")) continue;

            if (match.Meta.GetValueOrDefault("generator") == "nvd-rulegen") continue;

            var confidence = match.Confidence?.Trim().ToLowerInvariant();
            if (confidence != "high") continue;
            if (!Severity.IsKnown(match.Severity)) continue;
            if (!Severity.MeetsThreshold(match.Severity, threshold)) continue;

            return "";
        }
        return "no eligible high-confidence rule match";
    }

    /// <summary>Consider an opt-in detection; <see cref="Act"/> enforces the policy.</summary>
    public RemediationResult? ConsiderAuto(SuiteEvent finding)
    {
        if (!_cfg.AutoRemediate) return null;
        if (!finding.IsMatch) return null;
        return Act(finding.Id, _cfg.AutoRemediateAction, confirm: true, trigger: "auto");
    }
}
