using SecuritySuite.Configuration;
using SecuritySuite.Remediation;
using SecuritySuite.Storage;

namespace SecuritySuite.Tests;

/// <summary>
/// The rails, each tested by the way it can be defeated rather than the way it
/// succeeds. A remediation that is wrong destroys a file, so a refusal that
/// does not fire is the expensive bug here.
/// </summary>
public sealed class RemediationTests : IDisposable
{
    private readonly string _temp = Directory.CreateTempSubdirectory("suite-rem").FullName;

    private string Watched => Path.Combine(_temp, "uploads");
    private string Outside => Path.Combine(_temp, "elsewhere");

    private (Remediator Remediator, EventStore Store, SuiteConfig Config) Build(
        Action<SuiteConfig>? tweak = null)
    {
        Directory.CreateDirectory(Watched);
        Directory.CreateDirectory(Outside);

        var cfg = new SuiteConfig
        {
            WatchPaths = [Watched],
            FindingsLog = Path.Combine(_temp, "data", "findings.ndjson"),
            TriageFile = Path.Combine(_temp, "data", "triage.json"),
            RemediationFile = Path.Combine(_temp, "data", "remediation.json"),
            QuarantineDir = Path.Combine(_temp, "quarantine"),
            GuidanceCacheDir = Path.Combine(_temp, "data", "guidance"),
            NvdCacheDir = Path.Combine(_temp, "nvds"),
            OsvCacheDir = Path.Combine(_temp, "data", "osv"),
            VtCacheDir = Path.Combine(_temp, "data", "vt"),
            RulesDir = Path.Combine(_temp, "rules"),
        };
        tweak?.Invoke(cfg);

        Directory.CreateDirectory(Path.GetDirectoryName(cfg.FindingsLog)!);
        var store = new EventStore(cfg.FindingsLog, cfg.TriageFile);
        return (new Remediator(cfg, store, _ => { }), store, cfg);
    }

    /// <summary>Write a file and record a detection for it, as the monitor would.</summary>
    private static SuiteEvent Detect(EventStore store, string path, string content = "bad",
                                     string severity = Severity.Critical)
    {
        File.WriteAllText(path, content);
        return store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = path,
            FileName = Path.GetFileName(path),
            Severity = severity,
            Sha256 = Detection.YaraEngine.Sha256Of(path),
            RuleNames = ["Test_Rule"],
            Matches =
            [
                new RuleMatch
                {
                    Rule = "Test_Rule",
                    Namespace = "testing",
                    Severity = severity,
                    Meta = new Dictionary<string, string> { ["confidence"] = "high" },
                },
            ],
        });
    }

    // --------------------------------------------------------------- rail 1
    [Fact]
    public void Unknown_finding_is_refused_and_no_path_is_accepted_from_the_caller()
    {
        var (remediator, _, _) = Build();

        var result = remediator.Act("does-not-exist", RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("unknown finding", result.Refused);
    }

    [Fact]
    public void Non_detection_events_cannot_be_remediated()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "note.txt");
        File.WriteAllText(path, "x");

        var scan = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeScan,
            FilePath = path,
            Verdict = "clean",
        });

        var result = remediator.Act(scan.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("not a detection", result.Refused);
        Assert.True(File.Exists(path));
    }

    // --------------------------------------------------------------- rail 2
    [Fact]
    public void Hash_change_since_detection_is_refused()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "changed.txt");
        var finding = Detect(store, path);

        // The file is replaced after detection: it is no longer what was found.
        File.WriteAllText(path, "something else entirely");

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("hash mismatch", result.Refused);
        Assert.Contains("changed since detection", result.Detail);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void A_finding_with_no_recorded_hash_says_so_rather_than_refusing()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "nohash.txt");
        var finding = Detect(store, path);
        finding.Sha256 = null;

        var result = remediator.Act(finding.Id, RemediationActions.Delete, dryRun: true);

        Assert.True(result.Ok);
        Assert.Equal("no recorded hash on the finding", result.Checks!["hash"]);
    }

    // --------------------------------------------------------------- rail 3
    [Fact]
    public void Target_outside_every_permitted_root_is_refused()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Outside, "not-watched.txt");
        var finding = Detect(store, path);

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("outside permitted roots", result.Refused);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void An_extra_remediation_root_widens_the_permitted_set()
    {
        var (remediator, store, _) = Build(cfg => cfg.RemediationRoots = [Path.Combine(_temp, "elsewhere")]);
        var path = Path.Combine(Outside, "allowed.txt");
        var finding = Detect(store, path);

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.True(result.Ok);
        Assert.False(File.Exists(path));
    }

    /// <summary>
    /// A link inside the watch path pointing out of it must not grant access to
    /// its target. This is the escape rail 3 exists to stop.
    /// </summary>
    [SymlinkFact]
    public void Symlinked_target_outside_the_roots_is_refused()
    {
        var (remediator, store, _) = Build();

        var real = Path.Combine(Outside, "secret.txt");
        File.WriteAllText(real, "bad");

        var link = Path.Combine(Watched, "alias.txt");
        File.CreateSymbolicLink(link, real);

        var finding = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = link,
            FileName = "alias.txt",
            Severity = Severity.Critical,
            Sha256 = Detection.YaraEngine.Sha256Of(link),
            RuleNames = ["Test_Rule"],
        });

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("outside permitted roots", result.Refused);
        Assert.True(File.Exists(real));
    }

    // --------------------------------------------------------------- rail 4
    [Fact]
    public void Directory_is_refused_unless_explicitly_allowed()
    {
        var (remediator, store, _) = Build();
        var dir = Path.Combine(Watched, "folder");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "inner.txt"), "x");

        var finding = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = dir,
            FileName = "folder",
            Severity = Severity.Critical,
            RuleNames = ["Test_Rule"],
        });

        var refused = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);
        Assert.False(refused.Ok);
        Assert.Equal("target is a directory", refused.Refused);
        Assert.True(Directory.Exists(dir));

        var allowed = remediator.Act(finding.Id, RemediationActions.Delete,
            confirm: true, allowDirectory: true);
        Assert.True(allowed.Ok);
        Assert.False(Directory.Exists(dir));
    }

    // --------------------------------------------------------------- rail 5
    [Fact]
    public void Dry_run_reports_the_whole_decision_and_changes_nothing()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "dry.txt");
        var finding = Detect(store, path);

        var result = remediator.Act(finding.Id, RemediationActions.Delete, dryRun: true);

        Assert.True(result.Ok);
        Assert.Equal("would delete", result.Outcome);
        Assert.Equal("clear", result.Checks!["suite_owned"]);
        Assert.Equal("clear", result.Checks["confinement"]);
        Assert.Equal("matches the finding", result.Checks["hash"]);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void A_dry_run_is_not_written_to_the_audit_trail()
    {
        var (remediator, store, _) = Build();
        var finding = Detect(store, Path.Combine(Watched, "quiet.txt"));

        remediator.Act(finding.Id, RemediationActions.Delete, dryRun: true);

        Assert.Empty(store.Events(eventType: SuiteEvent.TypeRemediation));
    }

    [Fact]
    public void Confirmation_is_required_for_a_real_action()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "unconfirmed.txt");
        var finding = Detect(store, path);

        var result = remediator.Act(finding.Id, RemediationActions.Delete);

        Assert.False(result.Ok);
        Assert.Equal("confirmation required", result.Refused);
        Assert.True(File.Exists(path));
    }

    // --------------------------------------------------------------- rail 6
    /// <summary>
    /// The regression that matters. An earlier version of this rail enumerated
    /// the directories to protect, so a loose file in the project root matched
    /// no entry and a test pointed at the project deleted README.md.
    /// </summary>
    [Fact]
    public void Suite_owned_path_is_refused_even_with_a_watch_root_on_the_project()
    {
        var project = SuitePaths.Root;
        var (remediator, store, _) = Build(cfg => cfg.WatchPaths = [project]);

        foreach (var relative in (string[])["README.md", "SecuritySuite.sln", ".gitignore"])
        {
            var path = Path.Combine(project, relative);
            if (!File.Exists(path)) continue;

            var finding = store.Add(new SuiteEvent
            {
                EventType = SuiteEvent.TypeMatch,
                FilePath = path,
                FileName = relative,
                Severity = Severity.Critical,
                Sha256 = Detection.YaraEngine.Sha256Of(path),
                RuleNames = ["False_Positive"],
            });

            var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

            Assert.False(result.Ok);
            Assert.Equal("suite-owned path", result.Refused);
            Assert.True(File.Exists(path));
        }
    }

    [Theory]
    [InlineData("src")]
    [InlineData("tests")]
    [InlineData("web")]
    [InlineData("rules")]
    [InlineData("assets")]
    [InlineData("book")]
    [InlineData("data")]
    public void The_suites_own_directories_are_refused(string directory)
    {
        var project = SuitePaths.Root;
        var (remediator, store, _) = Build(cfg => cfg.WatchPaths = [project]);

        var finding = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = Path.Combine(project, directory, "anything.txt"),
            FileName = "anything.txt",
            Severity = Severity.Critical,
            RuleNames = ["False_Positive"],
        });

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("suite-owned path", result.Refused);
    }

    [Fact]
    public void A_rule_file_is_refused_even_when_the_rules_dir_is_a_watch_root()
    {
        var rules = Path.Combine(_temp, "rules");
        Directory.CreateDirectory(rules);
        var (remediator, store, _) = Build(cfg =>
        {
            cfg.RulesDir = rules;
            cfg.WatchPaths = [rules];
        });

        var path = Path.Combine(rules, "c2_network.yar");
        var finding = Detect(store, path, "rule X { condition: true }");

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("suite-owned path", result.Refused);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Quarantine_itself_is_never_remediable()
    {
        var (remediator, store, cfg) = Build(c => c.WatchPaths = [_temp]);

        Directory.CreateDirectory(cfg.QuarantineDir);
        var path = Path.Combine(cfg.QuarantineDir, "held.txt");
        var finding = Detect(store, path);

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("suite-owned path", result.Refused);
    }

    [Fact]
    public void The_findings_log_is_never_remediable()
    {
        var (remediator, store, cfg) = Build(c => c.WatchPaths = [_temp]);
        var finding = Detect(store, cfg.FindingsLog, "{}");

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("suite-owned path", result.Refused);
    }

    // ------------------------------------------------------------ happy paths
    [Fact]
    public void Delete_removes_the_file_and_appends_an_audit_record()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "gone.txt");
        var finding = Detect(store, path);

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.True(result.Ok);
        Assert.Equal("deleted", result.Outcome);
        Assert.False(File.Exists(path));

        var audit = Assert.Single(store.Events(eventType: SuiteEvent.TypeRemediation));
        Assert.Equal(finding.Id, audit.GetExtra<string>("finding"));
        Assert.Equal("deleted", audit.GetExtra<string>("outcome"));
        Assert.True(audit.GetExtra<bool>("ok"));
    }

    [Fact]
    public void A_refusal_is_audited_as_deliberately_as_a_success()
    {
        var (remediator, store, _) = Build();
        var finding = Detect(store, Path.Combine(Outside, "nope.txt"));

        remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        var audit = Assert.Single(store.Events(eventType: SuiteEvent.TypeRemediation));
        Assert.Equal("outside permitted roots", audit.GetExtra<string>("refused"));
        Assert.False(audit.GetExtra<bool>("ok"));
    }

    [Fact]
    public void Quarantine_moves_the_file_and_writes_a_sidecar()
    {
        var (remediator, store, cfg) = Build();
        var path = Path.Combine(Watched, "held.txt");
        var finding = Detect(store, path);

        var result = remediator.Act(finding.Id, RemediationActions.Quarantine, confirm: true);

        Assert.True(result.Ok);
        Assert.Equal("quarantined", result.Outcome);
        Assert.False(File.Exists(path));

        var holding = Path.Combine(cfg.QuarantineDir, finding.Id);
        Assert.True(File.Exists(Path.Combine(holding, "held.txt")));
        Assert.True(File.Exists(Path.Combine(holding, "held.txt.remediation.json")));
    }

    [Fact]
    public void Restore_returns_the_file_to_its_original_path()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "back.txt");
        var finding = Detect(store, path, "recoverable");

        Assert.True(remediator.Act(finding.Id, RemediationActions.Quarantine, confirm: true).Ok);
        Assert.False(File.Exists(path));

        var restored = remediator.Act(finding.Id, RemediationActions.Restore, confirm: true);

        Assert.True(restored.Ok);
        Assert.True(File.Exists(path));
        Assert.Equal("recoverable", File.ReadAllText(path));
        Assert.Null(remediator.StateFor(finding.Id));
    }

    [Fact]
    public void Restore_is_refused_when_something_is_already_at_the_target()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "clash.txt");
        var finding = Detect(store, path);

        Assert.True(remediator.Act(finding.Id, RemediationActions.Quarantine, confirm: true).Ok);
        File.WriteAllText(path, "a different file now lives here");

        var result = remediator.Act(finding.Id, RemediationActions.Restore, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("restore target exists", result.Refused);
    }

    [Fact]
    public void Purge_destroys_the_quarantined_copy()
    {
        var (remediator, store, cfg) = Build();
        var path = Path.Combine(Watched, "purged.txt");
        var finding = Detect(store, path);

        Assert.True(remediator.Act(finding.Id, RemediationActions.Quarantine, confirm: true).Ok);
        var result = remediator.Act(finding.Id, RemediationActions.Purge, confirm: true);

        Assert.True(result.Ok);
        Assert.False(File.Exists(Path.Combine(cfg.QuarantineDir, finding.Id, "purged.txt")));
        Assert.Equal("purged", remediator.StateFor(finding.Id)!.Action);
    }

    [Fact]
    public void Restore_and_purge_need_a_quarantined_file()
    {
        var (remediator, store, _) = Build();
        var finding = Detect(store, Path.Combine(Watched, "never.txt"));

        foreach (var action in (string[])[RemediationActions.Restore, RemediationActions.Purge])
        {
            var result = remediator.Act(finding.Id, action, confirm: true);
            Assert.False(result.Ok);
            Assert.Equal("not quarantined", result.Refused);
        }
    }

    [Fact]
    public void Acting_twice_on_one_finding_is_refused()
    {
        var (remediator, store, _) = Build();
        var finding = Detect(store, Path.Combine(Watched, "once.txt"));

        Assert.True(remediator.Act(finding.Id, RemediationActions.Delete, confirm: true).Ok);
        var again = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(again.Ok);
        Assert.Equal("already deleted", again.Refused);
    }

    [Fact]
    public void Unknown_action_is_refused()
    {
        var (remediator, store, _) = Build();
        var finding = Detect(store, Path.Combine(Watched, "x.txt"));

        var result = remediator.Act(finding.Id, "incinerate", confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("unknown action", result.Refused);
    }

    [Fact]
    public void A_target_that_vanished_is_refused_rather_than_reported_as_deleted()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "vanished.txt");
        var finding = Detect(store, path);
        File.Delete(path);

        var result = remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        Assert.False(result.Ok);
        Assert.Equal("target is gone", result.Refused);
    }

    // ------------------------------------------------------------------ bulk
    [Fact]
    public void Bulk_defaults_to_a_dry_run()
    {
        var (remediator, store, _) = Build();
        Detect(store, Path.Combine(Watched, "a.ps1"));
        Detect(store, Path.Combine(Watched, "b.exe"));

        var result = remediator.Bulk();

        Assert.True(result.DryRun);
        Assert.Equal(RemediationActions.Quarantine, result.Action);
        Assert.Equal(2, result.Matched);
        Assert.Equal(0, result.Acted);
        Assert.True(File.Exists(Path.Combine(Watched, "a.ps1")));
    }

    [Fact]
    public void Bulk_filters_by_extension()
    {
        var (remediator, store, _) = Build();
        Detect(store, Path.Combine(Watched, "script.ps1"));
        Detect(store, Path.Combine(Watched, "binary.exe"));
        Detect(store, Path.Combine(Watched, "notes.txt"));

        var result = remediator.Bulk(extensions: ["ps1", "exe"],
            action: RemediationActions.Delete, confirm: true, dryRun: false);

        Assert.Equal(2, result.Matched);
        Assert.Equal(2, result.Acted);
        Assert.False(File.Exists(Path.Combine(Watched, "script.ps1")));
        Assert.False(File.Exists(Path.Combine(Watched, "binary.exe")));
        Assert.True(File.Exists(Path.Combine(Watched, "notes.txt")));
    }

    [Fact]
    public void Bulk_filters_by_severity_threshold()
    {
        var (remediator, store, _) = Build();
        Detect(store, Path.Combine(Watched, "crit.txt"), severity: Severity.Critical);
        Detect(store, Path.Combine(Watched, "high.txt"), severity: Severity.High);
        Detect(store, Path.Combine(Watched, "low.txt"), severity: Severity.Low);

        var critical = remediator.Bulk(severity: Severity.Critical);
        Assert.Equal(1, critical.Matched);

        var highAndWorse = remediator.Bulk(severity: Severity.High);
        Assert.Equal(2, highAndWorse.Matched);
    }

    [Fact]
    public void Bulk_never_acts_twice_on_the_same_file()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "shared.txt");

        // Two findings naming one file, as a rescan produces.
        Detect(store, path);
        Detect(store, path);

        var result = remediator.Bulk(action: RemediationActions.Delete, confirm: true, dryRun: false);

        Assert.Equal(1, result.Matched);
        Assert.Equal(1, result.Acted);
    }

    [Fact]
    public void Bulk_respects_the_limit()
    {
        var (remediator, store, _) = Build();
        for (var i = 0; i < 10; i++) Detect(store, Path.Combine(Watched, "f" + i + ".txt"));

        Assert.Equal(3, remediator.Bulk(limit: 3).Matched);
    }

    // -------------------------------------------------------------- auto rule
    [Fact]
    public void Auto_remediation_does_nothing_when_it_is_off()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "auto-off.txt");
        var finding = Detect(store, path);

        Assert.Null(remediator.ConsiderAuto(finding));
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Auto_remediation_quarantines_a_high_confidence_critical_match()
    {
        var (remediator, store, _) = Build(cfg =>
        {
            cfg.AutoRemediate = true;
            cfg.AutoRemediateAction = RemediationActions.Quarantine;
            cfg.AutoRemediateSeverity = Severity.Critical;
        });
        var path = Path.Combine(Watched, "auto-on.txt");
        var finding = Detect(store, path);

        var result = remediator.ConsiderAuto(finding);

        Assert.NotNull(result);
        Assert.True(result.Ok);
        Assert.Equal("quarantined", result.Outcome);
        Assert.False(File.Exists(path));
    }

    /// <summary>
    /// The 931 generated rules were produced from CVE text and have never been
    /// validated against real malware. They are exactly the rules that flagged
    /// this project's own book PDF, so they must never drive an unattended
    /// action.
    /// </summary>
    [Theory]
    [InlineData("NVD_CVE_2021_30952_apple_safari", "generated", null)]
    [InlineData("Some_Rule", "nvd_components", null)]
    [InlineData("Demo_Rule", "demo", null)]
    [InlineData("Eicar_Test_File", "testing", null)]
    [InlineData("Plausible_Rule", "testing", "nvd-rulegen")]
    public void Auto_remediation_refuses_generated_and_demo_rules(
        string rule, string nameSpace, string? generator)
    {
        var (remediator, store, _) = Build(cfg =>
        {
            cfg.AutoRemediate = true;
            cfg.AutoRemediateSeverity = Severity.Critical;
        });

        var path = Path.Combine(Watched, "generated.txt");
        File.WriteAllText(path, "x");
        var meta = new Dictionary<string, string> { ["confidence"] = "high" };
        if (generator is not null) meta["generator"] = generator;

        var finding = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = path,
            Severity = Severity.Critical,
            Sha256 = Detection.YaraEngine.Sha256Of(path),
            RuleNames = [rule],
            Matches =
            [
                new RuleMatch
                {
                    Rule = rule,
                    Namespace = nameSpace,
                    Severity = Severity.Critical,
                    Meta = meta,
                },
            ],
        });

        var result = remediator.ConsiderAuto(finding);

        Assert.NotNull(result);
        Assert.False(result.Ok);
        Assert.Equal("no eligible high-confidence rule match", result.Refused);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Auto_remediation_refuses_a_match_without_high_confidence()
    {
        var (remediator, store, _) = Build(cfg =>
        {
            cfg.AutoRemediate = true;
            cfg.AutoRemediateSeverity = Severity.Critical;
        });

        var path = Path.Combine(Watched, "lowconf.txt");
        File.WriteAllText(path, "x");
        var finding = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = path,
            Severity = Severity.Critical,
            Sha256 = Detection.YaraEngine.Sha256Of(path),
            Matches =
            [
                new RuleMatch
                {
                    Rule = "Ordinary_Rule",
                    Namespace = "testing",
                    Severity = Severity.Critical,
                    Meta = new Dictionary<string, string> { ["confidence"] = "medium" },
                },
            ],
        });

        var result = remediator.ConsiderAuto(finding)!;

        Assert.False(result.Ok);
        Assert.True(File.Exists(path));
    }

    /// <summary>
    /// Confidence and severity must come from the same match, or two unrelated
    /// weak matches combine into an action neither justifies.
    /// </summary>
    [Fact]
    public void Auto_remediation_will_not_combine_confidence_and_severity_across_matches()
    {
        var (remediator, store, _) = Build(cfg =>
        {
            cfg.AutoRemediate = true;
            cfg.AutoRemediateSeverity = Severity.Critical;
        });

        var path = Path.Combine(Watched, "split.txt");
        File.WriteAllText(path, "x");
        var finding = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = path,
            Severity = Severity.Critical,
            Sha256 = Detection.YaraEngine.Sha256Of(path),
            Matches =
            [
                // High confidence, but only low severity.
                new RuleMatch
                {
                    Rule = "Confident_But_Minor",
                    Namespace = "testing",
                    Severity = Severity.Low,
                    Meta = new Dictionary<string, string> { ["confidence"] = "high" },
                },
                // Critical, but not confident.
                new RuleMatch
                {
                    Rule = "Severe_But_Unsure",
                    Namespace = "testing",
                    Severity = Severity.Critical,
                    Meta = new Dictionary<string, string> { ["confidence"] = "low" },
                },
            ],
        });

        var result = remediator.ConsiderAuto(finding)!;

        Assert.False(result.Ok);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Auto_remediation_refuses_delete_however_it_is_configured()
    {
        var (remediator, store, _) = Build(cfg =>
        {
            cfg.AutoRemediate = true;
            cfg.AutoRemediateAction = RemediationActions.Delete;
            cfg.AutoRemediateSeverity = Severity.Critical;
        });
        var path = Path.Combine(Watched, "no-auto-delete.txt");
        var finding = Detect(store, path);

        var result = remediator.ConsiderAuto(finding)!;

        Assert.False(result.Ok);
        Assert.Equal("automatic action must be quarantine", result.Refused);
        Assert.True(File.Exists(path));
    }

    // ---------------------------------------------------------------- status
    [Fact]
    public void Status_reports_the_protected_roots_and_the_auto_setting()
    {
        var (remediator, _, cfg) = Build();

        var status = remediator.Status();

        Assert.False(status.AutoRemediate);
        Assert.Contains(Watched, status.PermittedRoots);
        Assert.Contains(status.ProtectedRoots, r => PathUtil.IsWithin(cfg.RulesDir, r));
        Assert.Contains(status.ProtectedRoots, r => PathUtil.IsWithin(SuitePaths.Root, r));
    }

    [Fact]
    public void Annotate_reports_whether_the_target_still_exists()
    {
        var (remediator, store, _) = Build();
        var path = Path.Combine(Watched, "annotated.txt");
        var finding = Detect(store, path);

        Assert.Equal("present", remediator.Annotate(finding).GetExtra<string>("target_state"));

        remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);
        Assert.Equal("delete", remediator.Annotate(finding).GetExtra<string>("target_state"));
    }

    [Fact]
    public void State_survives_a_restart()
    {
        var (remediator, store, cfg) = Build();
        var finding = Detect(store, Path.Combine(Watched, "persisted.txt"));
        remediator.Act(finding.Id, RemediationActions.Delete, confirm: true);

        var reopened = new Remediator(cfg, store, _ => { });

        Assert.Equal(RemediationActions.Delete, reopened.StateFor(finding.Id)!.Action);
    }

    public void Dispose() => PathUtilTests.TryDelete(_temp);
}
