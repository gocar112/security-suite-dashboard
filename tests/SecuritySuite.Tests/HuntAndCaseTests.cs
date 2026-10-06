using SecuritySuite.Casework;
using SecuritySuite.Hunting;
using SecuritySuite.Intel;
using SecuritySuite.Storage;

namespace SecuritySuite.Tests;

public sealed class HuntQueryTests
{
    private static SuiteEvent Finding(string file, string severity = Severity.High,
                                      string rule = "Some_Rule", string ns = "windows_threats",
                                      string status = "new", string? mitre = null,
                                      params string[] tags)
    {
        var entry = new SuiteEvent
        {
            Id = EventStore.NewId(),
            EventType = SuiteEvent.TypeMatch,
            FileName = file,
            FilePath = @"C:\uploads\" + file,
            Severity = severity,
            Status = status,
            Sha256 = new string('a', 64),
            Matches =
            [
                new RuleMatch
                {
                    Rule = rule,
                    Namespace = ns,
                    Severity = severity,
                    Tags = [.. tags],
                    Meta = mitre is null
                        ? []
                        : new Dictionary<string, string> { ["mitre"] = mitre },
                },
            ],
        };
        return entry;
    }

    private static readonly List<SuiteEvent> Corpus =
    [
        Finding("ransom.txt", Severity.Critical, "Ransom_Note_Template", "ransomware",
            mitre: "T1486", tags: "malware"),
        Finding("ps.log", Severity.High, "PowerShell_Encoded_Command", "windows_threats",
            status: "resolved", mitre: "T1059.001"),
        Finding("shell.php", Severity.Critical, "Webshell_Generic", "webshell",
            mitre: "T1505.003", tags: "webshell"),
        Finding("notes.txt", Severity.Low, "Low_Signal", "demo"),
    ];

    private static List<string> Run(string query) =>
        [.. HuntQuery.Run(query, Corpus).Findings.Select(f => f.FileName!)];

    [Fact]
    public void A_blank_query_matches_everything()
    {
        Assert.Equal(Corpus.Count, HuntQuery.Run("", Corpus).Matched);
        Assert.Equal(Corpus.Count, HuntQuery.Run(null, Corpus).Matched);
    }

    [Fact]
    public void Field_terms_filter_on_the_right_field()
    {
        Assert.Equal(["ransom.txt", "shell.php"], Run("severity:critical"));
        Assert.Equal(["ps.log"], Run("status:resolved"));
        Assert.Equal(["shell.php"], Run("namespace:webshell"));
        Assert.Equal(["ransom.txt"], Run("rule:Ransom_Note*"));
        Assert.Equal(["shell.php"], Run("tag:webshell"));
        Assert.Equal(["notes.txt"], Run("file:notes.txt"));
    }

    /// <summary>
    /// The reason the language exists: a substring search for "critical" also
    /// hits a file literally named critical_report.txt.
    /// </summary>
    [Fact]
    public void A_field_term_does_not_match_a_file_merely_named_after_it()
    {
        var corpus = new List<SuiteEvent>
        {
            Finding("critical_report.txt", Severity.Low),
            Finding("real.bin", Severity.Critical),
        };

        var byField = HuntQuery.Run("severity:critical", corpus);
        Assert.Equal(["real.bin"], byField.Findings.Select(f => f.FileName));

        // Free text still behaves the old way, which is what operators expect
        // from a bare word in the box.
        Assert.Equal(2, HuntQuery.Run("critical", corpus).Matched);
    }

    [Fact]
    public void Adjacency_implies_and()
    {
        Assert.Equal(["shell.php"], Run("severity:critical namespace:webshell"));
        Assert.Equal(["shell.php"], Run("severity:critical AND namespace:webshell"));
    }

    [Fact]
    public void Or_and_not_work_including_the_shorthands()
    {
        Assert.Equal(["ransom.txt", "shell.php"], Run("namespace:ransomware OR namespace:webshell"));
        Assert.Equal(["ransom.txt", "shell.php"], Run("namespace:ransomware | namespace:webshell"));
        Assert.Equal(["ransom.txt", "shell.php", "notes.txt"], Run("NOT status:resolved"));
        Assert.Equal(["ransom.txt", "shell.php", "notes.txt"], Run("-status:resolved"));
    }

    [Fact]
    public void Parentheses_group()
    {
        Assert.Equal(["ransom.txt"],
            Run("(namespace:ransomware OR namespace:webshell) AND rule:Ransom*"));
    }

    [Fact]
    public void Wildcards_work_in_values()
    {
        Assert.Equal(["ps.log"], Run("rule:PowerShell_*"));
        Assert.Equal(["ransom.txt"], Run("file:ransom.?xt"));
    }

    [Fact]
    public void Quoted_values_may_contain_spaces()
    {
        var corpus = new List<SuiteEvent> { Finding("my report.txt") };
        Assert.Equal(1, HuntQuery.Run("file:\"my report\"", corpus).Matched);
    }

    /// <summary>
    /// Techniques are resolved from rule metadata on demand, so a hunt can ask
    /// for them without them being stored on every event.
    /// </summary>
    [Fact]
    public void Technique_and_tactic_terms_resolve_from_rule_metadata()
    {
        Assert.Equal(["ransom.txt"], Run("technique:T1486"));
        Assert.Equal(["ransom.txt"], Run("attack:T1486"));
        Assert.Equal(["ransom.txt"], Run("tactic:impact"));
        Assert.Equal(["ps.log"], Run("tactic:execution"));
    }

    /// <summary>
    /// A typo that quietly returns nothing is worse than one that says so.
    /// </summary>
    [Fact]
    public void An_unknown_field_is_a_parse_error_not_a_silent_no_match()
    {
        var result = HuntQuery.Run("sevrity:critical", Corpus);

        Assert.NotNull(result.Error);
        Assert.Contains("unknown field", result.Error);
        Assert.Contains("severity", result.Error);   // suggests the real ones
        Assert.Empty(result.Findings);
    }

    [Theory]
    [InlineData("(severity:critical")]
    [InlineData("severity:")]
    [InlineData("AND")]
    public void Malformed_queries_report_rather_than_throw(string query)
    {
        var result = HuntQuery.Run(query, Corpus);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void The_result_names_the_queryable_fields()
    {
        var result = HuntQuery.Run("severity:low", Corpus);
        Assert.Contains("technique", result.Fields);
        Assert.Contains("namespace", result.Fields);
    }

    [Fact]
    public void The_limit_is_respected()
    {
        Assert.Equal(2, HuntQuery.Run("", Corpus, limit: 2).Matched);
    }

    /// <summary>
    /// Serialising every event is the expensive case, so a field-only query
    /// must never pay for it.
    /// </summary>
    [Fact]
    public void Free_text_is_only_needed_when_a_text_term_is_present()
    {
        Assert.False(HuntQuery.NeedsText(HuntQuery.Parse("severity:critical")));
        Assert.True(HuntQuery.NeedsText(HuntQuery.Parse("something")));
        Assert.True(HuntQuery.NeedsText(HuntQuery.Parse("severity:high OR something")));
    }
}

public sealed class CaseStoreTests : IDisposable
{
    private readonly string _temp = Directory.CreateTempSubdirectory("suite-cases").FullName;

    private CaseStore New() => new(Path.Combine(_temp, "cases.json"), _ => { });

    [Fact]
    public void A_case_is_created_with_sensible_defaults()
    {
        var record = New().Create("Suspected intrusion");

        Assert.NotEmpty(record.Id);
        Assert.Equal("open", record.Status);
        Assert.Equal(Severity.Medium, record.Severity);
        Assert.Empty(record.FindingIds);
        Assert.NotEmpty(record.CreatedAt);
    }

    [Fact]
    public void A_case_needs_a_title()
    {
        var store = New();
        Assert.Throws<ArgumentException>(() => store.Create(""));
        Assert.Throws<ArgumentException>(() => store.Create("   "));
        Assert.Throws<ArgumentException>(() => store.Create(null));
    }

    [Fact]
    public void An_unknown_severity_falls_back_rather_than_being_stored()
    {
        Assert.Equal(Severity.Medium, New().Create("x", severity: "catastrophic").Severity);
    }

    /// <summary>
    /// A partial update must not blank the fields it did not mention.
    /// </summary>
    [Fact]
    public void Update_only_touches_the_fields_supplied()
    {
        var store = New();
        var record = store.Create("Original", owner: "alice", summary: "the summary");

        var updated = store.Update(record.Id, status: "contained");

        Assert.NotNull(updated);
        Assert.Equal("contained", updated.Status);
        Assert.Equal("Original", updated.Title);
        Assert.Equal("alice", updated.Owner);
        Assert.Equal("the summary", updated.Summary);
    }

    [Fact]
    public void An_unknown_status_is_ignored()
    {
        var store = New();
        var record = store.Create("x");

        Assert.Equal("open", store.Update(record.Id, status: "exploded")!.Status);
    }

    [Fact]
    public void Updating_an_unknown_case_returns_null()
    {
        Assert.Null(New().Update("nope", status: "closed"));
    }

    [Fact]
    public void Findings_attach_and_detach_without_duplicating()
    {
        var store = New();
        var record = store.Create("x");

        store.Link(record.Id, ["a", "b"]);
        var linked = store.Link(record.Id, ["b", "c"]);

        Assert.Equal(["a", "b", "c"], linked!.FindingIds);

        var detached = store.Link(record.Id, ["b"], detach: true);
        Assert.Equal(["a", "c"], detached!.FindingIds);
    }

    [Fact]
    public void Notes_accumulate_and_blank_notes_are_refused()
    {
        var store = New();
        var record = store.Create("x");

        Assert.Null(store.AddNote(record.Id, "   "));
        Assert.Null(store.AddNote(record.Id, null));

        var noted = store.AddNote(record.Id, "first finding confirmed", "alice");
        Assert.Equal("first finding confirmed", Assert.Single(noted!.Notes).Text);
        Assert.Equal("alice", noted.Notes[0].Author);
    }

    [Fact]
    public void Deleting_works_once()
    {
        var store = New();
        var record = store.Create("x");

        Assert.True(store.Delete(record.Id));
        Assert.False(store.Delete(record.Id));
        Assert.Null(store.Get(record.Id));
    }

    [Fact]
    public void Cases_are_listed_worst_severity_first()
    {
        var store = New();
        store.Create("low one", severity: Severity.Low);
        store.Create("critical one", severity: Severity.Critical);
        store.Create("medium one", severity: Severity.Medium);

        Assert.Equal(["critical one", "medium one", "low one"],
            store.All().Select(c => c.Title));
    }

    [Fact]
    public void Listing_filters_by_status()
    {
        var store = New();
        var first = store.Create("a");
        store.Create("b");
        store.Update(first.Id, status: "closed");

        Assert.Single(store.All("closed"));
        Assert.Equal(2, store.All("all").Count);
    }

    [Fact]
    public void Summary_counts_open_as_anything_not_closed()
    {
        var store = New();
        var first = store.Create("a");
        store.Create("b");
        store.Update(first.Id, status: "investigating");

        var summary = store.Summary();
        Assert.Equal(2, summary.Total);
        Assert.Equal(2, summary.Open);
        Assert.Equal(1, summary.ByStatus["investigating"]);
    }

    [Fact]
    public void Cases_survive_a_restart()
    {
        var record = New().Create("persisted", owner: "bob");
        Assert.Equal("bob", New().Get(record.Id)!.Owner);
    }

    [Fact]
    public void An_unreadable_case_file_is_reported_rather_than_silently_replaced()
    {
        var path = Path.Combine(_temp, "cases.json");
        File.WriteAllText(path, "{ not json");

        var warnings = new List<string>();
        var store = new CaseStore(path, warnings.Add);

        Assert.Empty(store.All());
        Assert.Contains(warnings, w => w.Contains("unreadable"));
    }

    public void Dispose() => PathUtilTests.TryDelete(_temp);
}

public sealed class SavedHuntTests : IDisposable
{
    private readonly string _temp = Directory.CreateTempSubdirectory("suite-hunts").FullName;

    private SavedHuntStore New() => new(Path.Combine(_temp, "saved-hunts.json"), _ => { });

    [Fact]
    public void A_hunt_saves_and_reloads()
    {
        New().Save("Unresolved criticals", "severity:critical AND NOT status:resolved");

        var saved = Assert.Single(New().All());
        Assert.Equal("Unresolved criticals", saved.Name);
    }

    /// <summary>
    /// Storing a query that does not parse moves the failure from the moment it
    /// is written to the moment it is needed.
    /// </summary>
    [Fact]
    public void A_query_that_does_not_parse_is_refused_at_save_time()
    {
        var store = New();
        Assert.Throws<HuntQueryException>(() => store.Save("bad", "nosuchfield:x"));
        Assert.Empty(store.All());
    }

    [Fact]
    public void Name_and_query_are_both_required()
    {
        var store = New();
        Assert.Throws<ArgumentException>(() => store.Save("", "severity:high"));
        Assert.Throws<ArgumentException>(() => store.Save("named", ""));
    }

    [Fact]
    public void Saving_the_same_name_updates_rather_than_duplicating()
    {
        var store = New();
        store.Save("Daily", "severity:high");
        store.Save("daily", "severity:critical");

        var saved = Assert.Single(store.All());
        Assert.Equal("severity:critical", saved.Query);
    }

    [Fact]
    public void Deleting_works_once()
    {
        var store = New();
        var saved = store.Save("x", "severity:low");

        Assert.True(store.Delete(saved.Id));
        Assert.False(store.Delete(saved.Id));
    }

    public void Dispose() => PathUtilTests.TryDelete(_temp);
}

public sealed class LinkGraphTests
{
    private static SuiteEvent WithIndicators(string id, string file, string severity,
                                             params (string Type, string Value)[] indicators)
    {
        var entry = new SuiteEvent
        {
            Id = id,
            EventType = SuiteEvent.TypeMatch,
            FileName = file,
            FilePath = @"C:\uploads\" + file,
            Severity = severity,
            Timestamp = "2026-01-0" + (id.Length % 9 + 1) + "T00:00:00+00:00",
            Matches = [new RuleMatch { Rule = "R_" + file, Namespace = "testing", Severity = severity }],
        };
        entry.SetExtra("iocs", new IocSummary
        {
            Indicators = [.. indicators.Select(i => new Indicator
            {
                Type = i.Type,
                Value = i.Value,
                Defanged = IocExtractor.Defang(i.Value, i.Type),
            })],
        });
        return entry;
    }

    [Fact]
    public void Findings_rules_and_indicators_all_become_nodes()
    {
        var graph = LinkGraph.Build(
            [WithIndicators("a", "one.txt", Severity.High, (IocKind.Domain, "evil.top"))]);

        Assert.Equal(1, graph.Counts.Findings);
        Assert.Equal(1, graph.Counts.Rules);
        Assert.Equal(1, graph.Counts.Indicators);
        Assert.Equal(2, graph.Counts.Edges);
    }

    /// <summary>
    /// The whole point: two files dropped apart are unrelated rows until you
    /// notice they beacon to the same host.
    /// </summary>
    [Fact]
    public void Findings_sharing_a_linking_indicator_form_a_campaign()
    {
        var graph = LinkGraph.Build(
        [
            WithIndicators("a", "one.txt", Severity.High, (IocKind.Domain, "shared.top")),
            WithIndicators("b", "two.txt", Severity.Critical, (IocKind.Domain, "shared.top")),
            WithIndicators("c", "three.txt", Severity.Low, (IocKind.Domain, "unrelated.top")),
        ]);

        var campaign = Assert.Single(graph.Campaigns);
        Assert.Equal(2, campaign.Size);
        Assert.Equal(Severity.Critical, campaign.Severity);   // worst member wins
        Assert.Contains("one.txt", campaign.Files);
        Assert.Contains("two.txt", campaign.Files);
        Assert.Equal("shared.top", Assert.Single(campaign.LinkedBy).Value.Replace("[.]", "."));
    }

    /// <summary>
    /// A shared CVE mention is not evidence of the same operation: half a
    /// corpus mentions CVE-2021-44228.
    /// </summary>
    [Fact]
    public void A_shared_non_linking_indicator_does_not_merge_findings()
    {
        var graph = LinkGraph.Build(
        [
            WithIndicators("a", "one.txt", Severity.High, (IocKind.Cve, "CVE-2021-44228")),
            WithIndicators("b", "two.txt", Severity.High, (IocKind.Cve, "CVE-2021-44228")),
        ]);

        Assert.Empty(graph.Campaigns);

        // But the indicator is still a node, because it is still a pivot.
        Assert.Equal(1, graph.Counts.Indicators);
    }

    [Fact]
    public void A_lone_finding_is_not_a_campaign()
    {
        var graph = LinkGraph.Build(
            [WithIndicators("a", "one.txt", Severity.High, (IocKind.Domain, "alone.top"))]);

        Assert.Empty(graph.Campaigns);
    }

    [Fact]
    public void Transitive_links_join_one_campaign()
    {
        // a-b share one host, b-c share another: all three are one operation.
        var graph = LinkGraph.Build(
        [
            WithIndicators("a", "one.txt", Severity.High, (IocKind.Domain, "first.top")),
            WithIndicators("b", "two.txt", Severity.High,
                (IocKind.Domain, "first.top"), (IocKind.Domain, "second.top")),
            WithIndicators("c", "three.txt", Severity.High, (IocKind.Domain, "second.top")),
        ]);

        Assert.Equal(3, Assert.Single(graph.Campaigns).Size);
    }

    [Fact]
    public void The_node_cap_keeps_the_most_connected_and_drops_dangling_edges()
    {
        var events = Enumerable.Range(0, 40)
            .Select(i => WithIndicators("f" + i, "file" + i + ".txt", Severity.Low,
                (IocKind.Domain, "host" + i + ".top")))
            .ToList();

        var graph = LinkGraph.Build(events, maxNodes: 20);

        Assert.True(graph.Truncated);
        Assert.True(graph.Nodes.Count <= 20);

        var ids = graph.Nodes.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        Assert.All(graph.Edges, e =>
        {
            Assert.Contains(e.Source, ids);
            Assert.Contains(e.Target, ids);
        });
    }

    [Fact]
    public void Linking_only_drops_non_linking_indicator_nodes()
    {
        var events = new[]
        {
            WithIndicators("a", "one.txt", Severity.High,
                (IocKind.Domain, "evil.top"), (IocKind.Cve, "CVE-2021-44228")),
        };

        Assert.Equal(2, LinkGraph.Build(events).Counts.Indicators);
        Assert.Equal(1, LinkGraph.Build(events, linkingOnly: true).Counts.Indicators);
    }
}

public sealed class AttackMappingTests
{
    [Theory]
    [InlineData("T1486", new[] { "T1486" })]
    [InlineData("T1486,T1490", new[] { "T1486", "T1490" })]
    [InlineData("T1486 T1490", new[] { "T1486", "T1490" })]
    [InlineData("t1003.001", new[] { "T1003.001" })]
    [InlineData("T1486,T1486", new[] { "T1486" })]
    [InlineData("not a technique", new string[0])]
    [InlineData("", new string[0])]
    public void Technique_ids_are_parsed_leniently_but_not_guessed(string raw, string[] expected)
    {
        Assert.Equal(expected, AttackMapping.ParseIds(raw));
    }

    [Fact]
    public void A_known_technique_carries_its_name_and_tactics()
    {
        var technique = AttackMapping.Describe("T1486");

        Assert.True(technique.Known);
        Assert.Equal("Data Encrypted for Impact", technique.Name);
        Assert.Equal(["impact"], technique.Tactics);
        Assert.Equal("https://attack.mitre.org/techniques/T1486/", technique.Url);
    }

    /// <summary>
    /// A rule author who adds a technique before the table knows about it
    /// should see their id in the UI, not silently lose the mapping.
    /// </summary>
    [Fact]
    public void An_unknown_technique_is_surfaced_rather_than_dropped()
    {
        var technique = AttackMapping.Describe("T9999");

        Assert.False(technique.Known);
        Assert.Equal("T9999", technique.Id);
        Assert.Equal("Unmapped technique", technique.Name);
    }

    [Fact]
    public void A_sub_technique_url_uses_the_slash_form()
    {
        Assert.Equal("https://attack.mitre.org/techniques/T1003/001/",
            AttackMapping.Describe("T1003.001").Url);
    }

    /// <summary>Tagging 931 generated rules individually would be noise.</summary>
    [Fact]
    public void The_generated_ruleset_is_mapped_by_its_file_rather_than_per_rule()
    {
        var resolved = AttackMapping.Resolve(new Dictionary<string, string>(), "nvd_components");
        Assert.Equal("T1190", Assert.Single(resolved).Id);
    }

    [Fact]
    public void A_rules_own_mapping_beats_the_file_default()
    {
        var meta = new Dictionary<string, string> { ["mitre"] = "T1486" };
        Assert.Equal("T1486", Assert.Single(AttackMapping.Resolve(meta, "nvd_components")).Id);
    }

    [Fact]
    public void Tactics_come_back_in_kill_chain_order()
    {
        var techniques = new[]
        {
            AttackMapping.Describe("T1486"),      // impact, last
            AttackMapping.Describe("T1566.001"),  // initial-access, early
            AttackMapping.Describe("T1059"),      // execution, middle
        };

        Assert.Equal(["initial-access", "execution", "impact"],
            AttackMapping.TacticsFor(techniques));
    }

    [Fact]
    public void Coverage_separates_what_rules_cover_from_what_has_fired()
    {
        var engine = new Detection.EngineInfo
        {
            Rules =
            [
                new Detection.RuleInfo
                {
                    Rule = "Covered_Only",
                    Namespace = "testing",
                    Meta = new Dictionary<string, string> { ["mitre"] = "T1490" },
                },
                new Detection.RuleInfo
                {
                    Rule = "Covered_And_Fired",
                    Namespace = "testing",
                    Meta = new Dictionary<string, string> { ["mitre"] = "T1486" },
                },
            ],
        };

        var findings = new[]
        {
            new SuiteEvent
            {
                EventType = SuiteEvent.TypeMatch,
                Severity = Severity.Critical,
                Matches =
                [
                    new RuleMatch
                    {
                        Rule = "Covered_And_Fired",
                        Namespace = "testing",
                        Meta = new Dictionary<string, string> { ["mitre"] = "T1486" },
                    },
                ],
            },
        };

        var coverage = AttackMapping.Coverage(engine, findings);

        Assert.Equal(2, coverage.TechniqueCount);
        Assert.Equal(2, coverage.CoveredTechniques);
        Assert.Equal(1, coverage.DetectedTechniques);
        Assert.Equal(1, coverage.TotalDetections);

        var impact = coverage.Tactics.Single(t => t.Id == "impact");
        Assert.Equal(2, impact.Covered);
        Assert.Equal(1, impact.Detected);

        // The gaps are named, not left for the reader to infer from an empty column.
        Assert.Contains("Reconnaissance", coverage.UncoveredTactics);
    }

    [Fact]
    public void One_finding_counts_once_per_technique_however_many_rules_mapped_to_it()
    {
        var findings = new[]
        {
            new SuiteEvent
            {
                EventType = SuiteEvent.TypeMatch,
                Severity = Severity.High,
                Matches =
                [
                    new RuleMatch { Rule = "A", Namespace = "t", Meta = new() { ["mitre"] = "T1486" } },
                    new RuleMatch { Rule = "B", Namespace = "t", Meta = new() { ["mitre"] = "T1486" } },
                ],
            },
        };

        var coverage = AttackMapping.Coverage(new Detection.EngineInfo(), findings);
        Assert.Equal(1, coverage.TotalDetections);
    }
}

public sealed class IncidentReportTests
{
    private static CaseRecord Case() => new()
    {
        Id = "case123",
        Title = "Test incident",
        Owner = "analyst",
        Status = "investigating",
        Severity = Severity.Critical,
        Summary = "A summary.",
        CreatedAt = "2026-01-01T00:00:00+00:00",
        UpdatedAt = "2026-01-02T00:00:00+00:00",
    };

    [Fact]
    public void The_report_is_self_contained()
    {
        var html = IncidentReport.Render(Case(), [], [], [], [], "2026-01-02T00:00:00+00:00", "2.0.0");

        Assert.Contains("<style>", html);
        Assert.DoesNotContain("<script", html);
        Assert.DoesNotContain("src=\"http", html);
        Assert.DoesNotContain("href=\"http", html);
        Assert.DoesNotContain("@import", html);
        Assert.Contains("makes no external requests", html);
    }

    /// <summary>
    /// Report content is drawn from file paths, rule matches and extracted
    /// indicators, all attacker-influenced. A report that executes markup from
    /// the thing it is reporting on is its own incident.
    /// </summary>
    [Fact]
    public void Attacker_influenced_text_is_escaped()
    {
        var hostile = "<script>alert('xss')</script>";
        var findings = new List<SuiteEvent>
        {
            new()
            {
                EventType = SuiteEvent.TypeMatch,
                FileName = hostile,
                FilePath = @"C:\uploads\" + hostile,
                Severity = Severity.Critical,
                Matches =
                [
                    new RuleMatch
                    {
                        Rule = hostile,
                        Namespace = "testing",
                        Meta = new Dictionary<string, string> { ["description"] = hostile },
                        Strings = [new MatchedString { Identifier = "$a", Preview = hostile }],
                    },
                ],
            },
        };

        var record = Case();
        record.Title = hostile;
        record.Notes.Add(new CaseNote { At = "now", Author = hostile, Text = hostile });

        var html = IncidentReport.Render(record, findings, [], [], [],
            "2026-01-02T00:00:00+00:00", "2.0.0");

        Assert.DoesNotContain("<script>alert", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void An_empty_case_says_so_rather_than_rendering_blank_sections()
    {
        var html = IncidentReport.Render(Case(), [], [], [], [], "now", "2.0.0");

        Assert.Contains("No findings are linked to this case.", html);
        Assert.Contains("No indicators were extracted", html);
        Assert.Contains("No remediation has been performed", html);
        Assert.Contains("No techniques mapped", html);
    }

    [Fact]
    public void Indicators_are_shown_defanged()
    {
        var indicators = new List<AggregatedIndicator>
        {
            new()
            {
                Type = IocKind.Url,
                Value = "http://evil.test/x",
                Defanged = "hxxp://evil[.]test/x",
                FileCount = 2,
                Occurrences = 3,
            },
        };

        var html = IncidentReport.Render(Case(), [], indicators, [], [], "now", "2.0.0");

        Assert.Contains("hxxp://evil[.]test/x", html);
        Assert.DoesNotContain(">http://evil.test/x<", html);
    }
}

public sealed class OutboundHardeningTests
{
    /// <summary>
    /// These requests carry API keys, so the target has to be an HTTPS URL to a
    /// named host with no credentials embedded in it.
    /// </summary>
    [Theory]
    [InlineData("https://services.nvd.nist.gov/rest/json/cves/2.0", true)]
    [InlineData("http://services.nvd.nist.gov/x", false)]
    [InlineData("file:///C:/Windows/win.ini", false)]
    [InlineData("https://user:pass@evil.test/x", false)]
    [InlineData("ftp://host/x", false)]
    public void Only_credential_free_https_urls_are_allowed(string url, bool allowed)
    {
        var uri = new Uri(url, UriKind.Absolute);

        if (allowed)
        {
            SecuritySuite.Net.SuiteHttp.RequireHttps(uri);
            return;
        }
        var failure = Assert.Throws<SecuritySuite.Net.HttpFailure>(
            () => SecuritySuite.Net.SuiteHttp.RequireHttps(uri));
        Assert.Contains("HTTPS", failure.Message);
    }

    [Fact]
    public void A_transient_failure_is_distinguishable_from_a_refusal()
    {
        Assert.True(new SecuritySuite.Net.HttpFailure(0, "dns").Transient);
        Assert.True(new SecuritySuite.Net.HttpFailure(429).Transient);
        Assert.True(new SecuritySuite.Net.HttpFailure(503).Transient);
        Assert.False(new SecuritySuite.Net.HttpFailure(403).Transient);
        Assert.False(new SecuritySuite.Net.HttpFailure(404).Transient);
    }
}
