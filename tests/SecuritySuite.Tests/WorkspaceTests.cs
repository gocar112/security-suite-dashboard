using System.Net;
using System.Text.Json.Nodes;
using SecuritySuite.Configuration;
using SecuritySuite.Connectors;
using SecuritySuite.Detection;
using SecuritySuite.Inventory;
using SecuritySuite.Jobs;
using SecuritySuite.Monitoring;
using SecuritySuite.Remediation;
using SecuritySuite.Storage;
using SecuritySuite.Telemetry;
using SecuritySuite.Workspace;

namespace SecuritySuite.Tests;

/// <summary>Shared scaffolding: a configured suite rooted in a temp directory.</summary>
internal sealed class SuiteFixture : IDisposable
{
    public string Temp { get; } = Directory.CreateTempSubdirectory("suite-fx").FullName;
    public SuiteConfig Config { get; }
    public EventStore Store { get; }
    public YaraEngine Engine { get; }

    private const string TestRule = """
        rule Fixture_Marker : malware
        {
            meta:
                severity = "critical"
                confidence = "high"
            strings:
                $a = "FIXTURE_BAD_MARKER"
            condition:
                $a
        }
        """;

    public SuiteFixture()
    {
        var rules = Path.Combine(Temp, "rules");
        Directory.CreateDirectory(rules);
        File.WriteAllText(Path.Combine(rules, "fixture.yar"), TestRule);

        Config = new SuiteConfig
        {
            WatchPaths = [Path.Combine(Temp, "uploads")],
            RulesDir = rules,
            FindingsLog = Path.Combine(Temp, "data", "findings.ndjson"),
            TriageFile = Path.Combine(Temp, "data", "triage.json"),
            RemediationFile = Path.Combine(Temp, "data", "remediation.json"),
            QuarantineDir = Path.Combine(Temp, "quarantine"),
            GuidanceCacheDir = Path.Combine(Temp, "data", "guidance"),
            NvdCacheDir = Path.Combine(Temp, "nvds"),
            OsvCacheDir = Path.Combine(Temp, "data", "osv"),
            VtCacheDir = Path.Combine(Temp, "data", "vt"),
            SettleSeconds = 0,
            PollInterval = 0.2,
        };

        Directory.CreateDirectory(Config.WatchPaths[0]);
        Directory.CreateDirectory(Path.Combine(Temp, "data"));
        Directory.CreateDirectory(Config.QuarantineDir);

        Store = new EventStore(Config.FindingsLog, Config.TriageFile);
        Engine = new YaraEngine(Config.RulesDir, Config.MaxFileBytes);
    }

    public string WatchDir => Config.WatchPaths[0];

    public SuiteEvent Detect(string name, string content = "FIXTURE_BAD_MARKER")
    {
        var path = Path.Combine(WatchDir, name);
        File.WriteAllText(path, content);

        return Store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = path,
            FileName = name,
            Severity = Severity.Critical,
            Sha256 = YaraEngine.Sha256Of(path),
            RuleNames = ["Fixture_Marker"],
            Matches =
            [
                new RuleMatch
                {
                    Rule = "Fixture_Marker",
                    Namespace = "fixture",
                    Severity = Severity.Critical,
                    Meta = new Dictionary<string, string> { ["confidence"] = "high" },
                },
            ],
        });
    }

    public void Dispose()
    {
        Engine.Dispose();
        PathUtilTests.TryDelete(Temp);
    }
}

public sealed class WorkbenchTests : IDisposable
{
    private readonly SuiteFixture _fx = new();
    private Workbench New() => new(_fx.Config, _fx.Engine, _fx.Store);

    /// <summary>
    /// An analyst pasting a suspicious command into a security tool needs to
    /// know the tool did not run it.
    /// </summary>
    [Fact]
    public void Analysis_never_executes_and_never_records_the_text()
    {
        var before = Directory.GetFiles(_fx.WatchDir).Length;
        var result = New().Analyze("powershell -enc FIXTURE_BAD_MARKER");

        Assert.False(result.Executed);
        Assert.False(result.Persisted);
        Assert.Equal("rule match", result.Verdict);
        Assert.NotEmpty(result.Sha256);
        Assert.Equal(before, Directory.GetFiles(_fx.WatchDir).Length);
    }

    [Fact]
    public void Analysis_rejects_empty_and_oversized_text()
    {
        var workbench = New();
        Assert.Throws<ArgumentException>(() => workbench.Analyze(""));
        Assert.Throws<ArgumentException>(() => workbench.Analyze("   "));
        Assert.Throws<ArgumentException>(() => workbench.Analyze(null));
        Assert.Throws<ArgumentException>(() => workbench.Analyze(new string('x', 48_001)));
    }

    /// <summary>
    /// The workbench toggle is a quarantine switch. Persisting an action would
    /// let a hand-edited sidecar turn it into auto-delete.
    /// </summary>
    [Fact]
    public void Policy_persists_only_the_flag_and_always_forces_quarantine()
    {
        var workbench = New();
        _fx.Config.AutoRemediateAction = RemediationActions.Delete;

        var policy = workbench.SetPolicy(true);

        Assert.True(policy.Enabled);
        Assert.Equal(RemediationActions.Quarantine, policy.Action);
        Assert.Equal(RemediationActions.Quarantine, _fx.Config.AutoRemediateAction);

        var saved = File.ReadAllText(workbench.PolicyPath);
        Assert.Contains("enabled", saved);
        Assert.DoesNotContain("delete", saved);
    }

    [Fact]
    public void Policy_reload_restores_the_flag_but_not_an_action()
    {
        New().SetPolicy(true);

        _fx.Config.AutoRemediate = false;
        _fx.Config.AutoRemediateAction = RemediationActions.Delete;
        var reopened = New();

        Assert.True(_fx.Config.AutoRemediate);
        Assert.Equal(RemediationActions.Quarantine, _fx.Config.AutoRemediateAction);
        Assert.True(reopened.Policy().Enabled);
    }

    [Fact]
    public void Policy_requires_an_explicit_boolean()
    {
        Assert.Throws<ArgumentException>(() => New().SetPolicy(null));
    }

    [Fact]
    public void Eve_import_validates_every_field_and_ignores_file_paths()
    {
        var workbench = New();
        var result = workbench.ImportEve(
            """{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","timestamp":"2026-01-01T00:00:00Z","alert":{"signature":"ET TROJAN x","severity":1,"action":"allowed"},"fileinfo":{"filename":"/etc/passwd"}}""");

        Assert.Equal(1, result.Imported);

        var alert = Assert.Single(_fx.Store.Events(eventType: "ids_alert"));
        Assert.Equal(Severity.High, alert.Severity);
        Assert.Equal("ET TROJAN x", alert.Message);
        Assert.Equal("10.0.0.1", alert.GetExtra<string>("src_ip"));

        // The record's own file path must never become something the suite acts on.
        Assert.Null(alert.FilePath);
    }

    [Fact]
    public void Eve_import_deduplicates_a_reimported_log()
    {
        var workbench = New();
        const string line =
            """{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"dup","severity":2}}""";

        Assert.Equal(1, workbench.ImportEve(line).Imported);

        var second = workbench.ImportEve(line);
        Assert.Equal(0, second.Imported);
        Assert.Equal(1, second.Duplicates);
    }

    [Fact]
    public void Eve_import_skips_non_alert_records_rather_than_failing()
    {
        var result = New().ImportEve(
            """{"event_type":"flow","src_ip":"10.0.0.1"}""" + "\n" +
            """{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"ok","severity":3}}""");

        Assert.Equal(1, result.Imported);
        Assert.Equal(1, result.Skipped);
    }

    /// <summary>A bad record must not leave half a batch imported.</summary>
    [Theory]
    [InlineData("""{"event_type":"alert","src_ip":"nope","dest_ip":"10.0.0.2","alert":{"signature":"x","severity":1}}""")]
    [InlineData("""{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"severity":1}}""")]
    [InlineData("""{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"x","severity":9}}""")]
    [InlineData("not json at all")]
    public void Eve_import_is_all_or_nothing(string bad)
    {
        var workbench = New();
        const string good =
            """{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"good","severity":1}}""";

        Assert.Throws<ArgumentException>(() => workbench.ImportEve(good + "\n" + bad));
        Assert.Empty(_fx.Store.Events(eventType: "ids_alert"));
    }

    [Fact]
    public void Eve_import_bounds_the_batch()
    {
        var workbench = New();
        Assert.Throws<ArgumentException>(() => workbench.ImportEve(""));
        Assert.Throws<ArgumentException>(() => workbench.ImportEve(
            string.Join("\n", Enumerable.Repeat(
                """{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"x","severity":1}}""",
                101))));
    }

    [Fact]
    public void Domains_are_validated_and_never_reported_as_enforced()
    {
        var result = New().SaveDomains("evil.test\n# a comment\nBAD-ACTOR.TOP.\n\n");

        Assert.False(result.Enforced);
        Assert.Equal(["bad-actor.top", "evil.test"], result.Domains);
    }

    /// <summary>
    /// Blocking either of these would be a way to break the host from a text
    /// box.
    /// </summary>
    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("printer.local")]
    [InlineData("api.internal")]
    [InlineData("host.localhost")]
    [InlineData("no-dot")]
    [InlineData("bad_underscore.test")]
    public void Domains_rejects_addresses_and_local_names(string entry)
    {
        Assert.Throws<ArgumentException>(() => New().SaveDomains(entry));
    }

    [Fact]
    public void Domains_round_trip_through_the_sidecar()
    {
        New().SaveDomains("evil.test");
        Assert.Equal(["evil.test"], New().Domains());
    }

    [Fact]
    public void Native_av_parses_both_single_and_multiple_products()
    {
        var one = Workbench.ParseAvProducts("""{"displayName":"Defender","productState":397568}""");
        Assert.Equal("Defender", Assert.Single(one).Name);

        var many = Workbench.ParseAvProducts(
            """[{"displayName":"A","productState":1},{"displayName":"B","productState":2}]""");
        Assert.Equal(2, many.Count);

        Assert.Empty(Workbench.ParseAvProducts(""));
    }

    public void Dispose() => _fx.Dispose();
}

public sealed class PlaybookTests : IDisposable
{
    private readonly SuiteFixture _fx = new();

    private (PlaybookService Service, Remediator Remediator) New()
    {
        var remediator = new Remediator(_fx.Config, _fx.Store, _ => { });
        return (new PlaybookService(_fx.Config, _fx.Store, remediator), remediator);
    }

    private static JsonNode Definition(string id, params string[] actions)
    {
        var steps = new JsonArray();
        foreach (var action in actions)
        {
            var step = new JsonObject { ["action"] = action };
            if (action == PlaybookService.ActionAnnotate) step["note"] = "handled by a playbook";
            steps.Add(step);
        }
        return new JsonObject
        {
            ["id"] = id,
            ["name"] = "Test playbook",
            ["version"] = 1,
            ["steps"] = steps,
        };
    }

    [Fact]
    public void A_valid_playbook_saves_and_lists()
    {
        var (service, _) = New();
        var saved = service.Save(Definition("triage-only", PlaybookService.ActionAnnotate));

        Assert.True(saved.Ok);
        Assert.Equal("triage-only", saved.Playbook!.Id);
        Assert.Single(service.List().Playbooks);
        Assert.Equal(3, service.List().Skills.Count);
    }

    [Fact]
    public void Unknown_fields_and_unknown_actions_are_refused()
    {
        var (service, _) = New();

        var extra = (JsonObject)Definition("x", PlaybookService.ActionGuidance);
        extra["command"] = "rm -rf /";
        Assert.False(service.Save(extra).Ok);

        Assert.False(service.Save(Definition("y", "execute")).Ok);
    }

    [Theory]
    [InlineData("")]
    [InlineData("has spaces")]
    [InlineData("-leading-dash")]
    public void A_bad_id_is_refused(string id)
    {
        var (service, _) = New();
        Assert.False(service.Save(Definition(id, PlaybookService.ActionGuidance)).Ok);
    }

    [Fact]
    public void Step_count_is_bounded()
    {
        var (service, _) = New();

        Assert.False(service.Save(Definition("empty")).Ok);
        Assert.False(service.Save(Definition("toomany",
            [.. Enumerable.Repeat(PlaybookService.ActionGuidance, 13)])).Ok);
    }

    [Fact]
    public void A_guidance_step_may_not_carry_a_note()
    {
        var (service, _) = New();
        var definition = (JsonObject)Definition("x", PlaybookService.ActionGuidance);
        ((JsonObject)definition["steps"]![0]!)["note"] = "looks like it does something";

        Assert.False(service.Save(definition).Ok);
    }

    /// <summary>A preview must not reach the network or change stored state.</summary>
    [Fact]
    public async Task A_dry_run_mutates_nothing_and_fetches_no_guidance()
    {
        var (service, _) = New();
        var finding = _fx.Detect("dry.txt");

        var run = await service.RunAsync(new PlaybookRunRequest
        {
            Playbook = Definition("dry", PlaybookService.ActionAnnotate, PlaybookService.ActionGuidance),
            FindingId = finding.Id,
            DryRun = true,
        });

        Assert.True(run.Ok);
        Assert.Equal("would annotate", run.Steps[0].Outcome);
        Assert.Equal("new", _fx.Store.Find(finding.Id)!.Status);

        var guidance = run.Steps[1].Guidance!.ToString();
        Assert.Contains("offline", guidance);
    }

    /// <summary>
    /// A live run that will be refused must be refused before an earlier step
    /// has already mutated state, because completed steps are not rolled back.
    /// </summary>
    [Fact]
    public async Task Confirmation_precedes_any_live_step()
    {
        var (service, _) = New();
        var finding = _fx.Detect("live.txt");

        var run = await service.RunAsync(new PlaybookRunRequest
        {
            Playbook = Definition("live", PlaybookService.ActionAnnotate, PlaybookService.ActionQuarantine),
            FindingId = finding.Id,
            DryRun = false,
            Confirm = false,
        });

        Assert.False(run.Ok);
        Assert.Equal("confirmation required", run.Refused);
        Assert.Empty(run.Steps);
        Assert.Equal("new", _fx.Store.Find(finding.Id)!.Status);
        Assert.True(File.Exists(Path.Combine(_fx.WatchDir, "live.txt")));
    }

    [Fact]
    public async Task A_confirmed_run_annotates_and_quarantines()
    {
        var (service, _) = New();
        var finding = _fx.Detect("acted.txt");

        var run = await service.RunAsync(new PlaybookRunRequest
        {
            Playbook = Definition("act", PlaybookService.ActionAnnotate, PlaybookService.ActionQuarantine),
            FindingId = finding.Id,
            DryRun = false,
            Confirm = true,
        });

        Assert.True(run.Ok);
        Assert.Equal("annotated", run.Steps[0].Outcome);
        Assert.Equal("quarantined", run.Steps[1].Outcome);
        Assert.False(File.Exists(Path.Combine(_fx.WatchDir, "acted.txt")));
    }

    [Fact]
    public async Task A_finding_without_a_recorded_hash_cannot_be_quarantined()
    {
        var (service, _) = New();
        var path = Path.Combine(_fx.WatchDir, "nohash.txt");
        File.WriteAllText(path, "FIXTURE_BAD_MARKER");

        var finding = _fx.Store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            FilePath = path,
            FileName = "nohash.txt",
            Severity = Severity.Critical,
        });

        var run = await service.RunAsync(new PlaybookRunRequest
        {
            Playbook = Definition("q", PlaybookService.ActionQuarantine),
            FindingId = finding.Id,
            DryRun = false,
            Confirm = true,
        });

        Assert.False(run.Ok);
        Assert.Equal("a recorded SHA-256 is required", run.Refused);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task Only_a_stored_detection_can_run_a_playbook()
    {
        var (service, _) = New();
        var scan = _fx.Store.Add(new SuiteEvent { EventType = SuiteEvent.TypeScan, Verdict = "clean" });

        foreach (var id in (string[])[scan.Id, "doesnotexist"])
        {
            var run = await service.RunAsync(new PlaybookRunRequest
            {
                Playbook = Definition("x", PlaybookService.ActionGuidance),
                FindingId = id,
                DryRun = true,
            });

            Assert.False(run.Ok);
        }
    }

    [Fact]
    public async Task A_saved_playbook_can_be_run_by_id()
    {
        var (service, _) = New();
        Assert.True(service.Save(Definition("by-id", PlaybookService.ActionGuidance)).Ok);
        var finding = _fx.Detect("byid.txt");

        var run = await service.RunAsync(new PlaybookRunRequest
        {
            PlaybookId = "by-id",
            FindingId = finding.Id,
            DryRun = true,
        });

        Assert.True(run.Ok);
        Assert.Equal("by-id", run.Playbook);
    }

    [Fact]
    public async Task An_unknown_saved_id_is_refused()
    {
        var (service, _) = New();
        var finding = _fx.Detect("unknown.txt");

        var run = await service.RunAsync(new PlaybookRunRequest
        {
            PlaybookId = "nope",
            FindingId = finding.Id,
            DryRun = true,
        });

        Assert.False(run.Ok);
        Assert.Equal("unknown saved playbook", run.Error);
    }

    /// <summary>
    /// Replacing corrupt storage with an apparently successful empty catalogue
    /// would silently destroy the operator's playbooks.
    /// </summary>
    [Fact]
    public void Corrupt_storage_is_preserved_and_saving_is_refused()
    {
        var (service, _) = New();
        File.WriteAllText(service.Path, "{ not valid playbook storage");

        var reopened = new PlaybookService(_fx.Config, _fx.Store, null);
        Assert.NotNull(reopened.List().Error);

        var saved = reopened.Save(Definition("new", PlaybookService.ActionGuidance));
        Assert.False(saved.Ok);
        Assert.Contains("Could not load playbooks", saved.Error);
        Assert.Contains("not valid", File.ReadAllText(service.Path));
    }

    [Fact]
    public void Saved_playbooks_survive_a_restart()
    {
        var (service, _) = New();
        Assert.True(service.Save(Definition("persisted", PlaybookService.ActionGuidance)).Ok);

        var reopened = new PlaybookService(_fx.Config, _fx.Store, null);
        Assert.Equal("persisted", Assert.Single(reopened.List().Playbooks).Id);
    }

    public void Dispose() => _fx.Dispose();
}

public sealed class TrainingTests
{
    private static readonly Training Bank = new();

    /// <summary>
    /// Every scenario needs exactly one correct choice, or the exercise teaches
    /// nothing and a score means nothing.
    /// </summary>
    [Fact]
    public void All_500_scenarios_have_exactly_one_correct_answer()
    {
        var catalogue = Bank.List();
        Assert.Equal(500, catalogue.Count);

        foreach (var scenario in catalogue.Scenarios)
        {
            Assert.Equal(4, scenario.Choices.Count);

            var correct = scenario.Choices.Count(c => Bank.Grade(scenario.Id, c.Id).Correct);
            Assert.Equal(1, correct);
        }
    }

    /// <summary>A fixed correct position would let someone score without reading.</summary>
    [Fact]
    public void The_correct_answer_is_not_always_in_the_same_position()
    {
        var positions = Bank.List().Scenarios
            .Select(s => Bank.Grade(s.Id, "A").CorrectAnswer)
            .Distinct()
            .ToList();

        Assert.Equal(4, positions.Count);
    }

    [Fact]
    public void Choices_never_carry_the_answer_key()
    {
        var scenario = Bank.List().Scenarios[0];
        Assert.All(scenario.Choices, c =>
        {
            Assert.NotEmpty(c.Id);
            Assert.NotEmpty(c.Label);
        });
    }

    [Fact]
    public void The_synthetic_disclaimer_is_in_the_payload()
    {
        var catalogue = Bank.List();
        Assert.True(catalogue.Synthetic);
        Assert.Contains("NOT 500 validated exploits", catalogue.Disclaimer);
        Assert.Equal("pass-and-play", catalogue.Mode);
    }

    [Theory]
    [InlineData(null, "A")]
    [InlineData("AP-001", "E")]
    [InlineData("AP-001", null)]
    [InlineData("nope", "A")]
    public void Invalid_grading_input_is_refused(string? id, string? answer)
    {
        var grade = Bank.Grade(id, answer);
        Assert.False(grade.Ok);
        Assert.NotNull(grade.Error);
    }

    [Fact]
    public void Grading_is_stateless_and_explains_itself()
    {
        var scenario = Bank.List().Scenarios[0];
        var expected = Bank.Grade(scenario.Id, "A").CorrectAnswer!;

        var first = Bank.Grade(scenario.Id, expected);
        var second = Bank.Grade(scenario.Id, expected);

        Assert.True(first.Correct);
        Assert.Equal(1, first.Score);
        Assert.Equal(first.Score, second.Score);
        Assert.Contains("synthetic planning exercise", first.Explanation);
    }
}

public sealed class InventoryTests
{
    /// <summary>Validation must happen before any socket or subprocess runs.</summary>
    [Theory]
    [InlineData("192.168.1.0/24")]
    [InlineData("10.0.0.0/24")]
    [InlineData("172.16.5.0/28")]
    [InlineData("192.168.1.7/32")]
    public void Explicit_rfc1918_cidrs_are_accepted(string cidr)
    {
        Assert.Equal(cidr, NetworkInventory.ValidateScope(cidr).ToString());
    }

    [Theory]
    [InlineData("8.8.8.0/24")]          // public
    [InlineData("192.168.1.0/16")]      // host bits set
    [InlineData("192.168.1.1")]         // bare address
    [InlineData("192.168.0.0/23")]      // wider than /24
    [InlineData("192.168.1.0/255.255.255.0")]
    [InlineData("fe80::/64")]
    [InlineData("127.0.0.0/24")]
    [InlineData("")]
    [InlineData(null)]
    public void Everything_else_is_rejected(string? cidr)
    {
        Assert.Throws<ArgumentException>(() => NetworkInventory.ValidateScope(cidr));
    }

    [Fact]
    public void A_fresh_inventory_is_idle_and_scans_nothing()
    {
        var status = new NetworkInventory(null).Status();

        Assert.Equal("idle", status.State);
        Assert.Null(status.Scope);
        Assert.Empty(status.Devices);
        Assert.Null(status.LastScan);
    }

    [Fact]
    public void Host_enumeration_excludes_network_and_broadcast()
    {
        var range = NetworkInventory.ValidateScope("192.168.1.0/30");
        var hosts = range.Hosts().Select(h => h.ToString()).ToList();

        Assert.Equal(["192.168.1.1", "192.168.1.2"], hosts);
    }

    /// <summary>A /31 or /32 has no network or broadcast address to exclude.</summary>
    [Fact]
    public void A_single_host_range_yields_that_host()
    {
        Assert.Equal(["192.168.1.7"],
            NetworkInventory.ValidateScope("192.168.1.7/32").Hosts().Select(h => h.ToString()));
    }

    [Fact]
    public void Neighbour_parsing_filters_scope_dead_and_multicast_entries()
    {
        var scope = NetworkInventory.ValidateScope("192.168.1.0/24");
        var parsed = NetworkInventory.ParseNeighbours("""
            192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic
            192.168.1.11          00-00-00-00-00-00     invalid
            192.168.1.12          01-00-5e-00-00-fb     static
            10.9.9.9              aa-bb-cc-dd-ee-00     dynamic
            192.168.1.13          INCOMPLETE
            192.168.1.14          12-22-33-44-55-66     dynamic
            """, scope);

        // 00-00-00-00-00-00 is not an address; 01-00-5e-... has the I/G bit set
        // and so is a group address, not a host's own hardware address;
        // 10.9.9.9 is outside the scope; INCOMPLETE has no MAC at all.

        Assert.Equal(["192.168.1.10", "192.168.1.14"], parsed.Select(p => p.Ip));
        Assert.Equal("aa:bb:cc:dd:ee:ff", parsed[0].Mac);
    }

    [Fact]
    public void Private_address_detection_matches_the_allowed_blocks()
    {
        Assert.True(NetworkInventory.IsPrivate(IPAddress.Parse("10.1.1.1")));
        Assert.True(NetworkInventory.IsPrivate(IPAddress.Parse("192.168.0.1")));
        Assert.True(NetworkInventory.IsPrivate(IPAddress.Parse("172.31.255.255")));
        Assert.False(NetworkInventory.IsPrivate(IPAddress.Parse("172.32.0.1")));
        Assert.False(NetworkInventory.IsPrivate(IPAddress.Parse("127.0.0.1")));
        Assert.False(NetworkInventory.IsPrivate(IPAddress.Parse("8.8.8.8")));
    }
}

public sealed class ConnectorTests
{
    /// <summary>
    /// This request carries credentials, so the endpoint is pinned to an HTTPS
    /// RFC1918 literal and one path. A DNS name would mean trusting whatever
    /// the resolver returned at that moment.
    /// </summary>
    [Theory]
    [InlineData("https://192.168.1.1", "https://192.168.1.1/api/ids/service/status")]
    [InlineData("https://192.168.1.1/", "https://192.168.1.1/api/ids/service/status")]
    [InlineData("https://10.0.0.5:8443", "https://10.0.0.5:8443/api/ids/service/status")]
    [InlineData("https://10.0.0.5/api/ids/service/status", "https://10.0.0.5/api/ids/service/status")]
    public void A_safe_endpoint_is_pinned_to_the_status_path(string input, string expected)
    {
        Assert.Equal(expected, OpnSenseConnector.PinEndpoint(input));
    }

    [Theory]
    [InlineData("http://192.168.1.1")]               // not HTTPS
    [InlineData("https://firewall.local")]           // DNS name
    [InlineData("https://127.0.0.1")]                // loopback
    [InlineData("https://8.8.8.8")]                  // public
    [InlineData("https://[fd00::1]")]                // IPv6
    [InlineData("https://user:pass@192.168.1.1")]    // userinfo
    [InlineData("https://192.168.1.1/other/path")]
    [InlineData("https://192.168.1.1?a=b")]
    [InlineData("https://192.168.1.1#frag")]
    [InlineData("https://192.168.1.1/api/ids/service/status/../../x")]
    [InlineData("")]
    public void Unsafe_endpoints_are_rejected_without_any_io(string input)
    {
        Assert.Throws<ArgumentException>(() => OpnSenseConnector.PinEndpoint(input));
    }

    [Fact]
    public void An_unconfigured_connector_reports_what_is_missing()
    {
        var status = new OpnSenseConnector(new Dictionary<string, string>()).Status();

        Assert.Equal("not_configured", status.State);
        Assert.False(status.Configured);
        Assert.Null(status.Operational);
        Assert.Equal(3, status.Missing.Count);
    }

    [Fact]
    public void A_bad_url_is_invalid_configuration_rather_than_missing()
    {
        var status = new OpnSenseConnector(new Dictionary<string, string>
        {
            ["OPNSENSE_URL"] = "http://evil.test",
            ["OPNSENSE_API_KEY"] = "key",
            ["OPNSENSE_API_SECRET"] = "secret",
        }).Status();

        Assert.Equal("invalid_configuration", status.State);
        Assert.False(status.Configured);
        Assert.NotNull(status.Error);
    }

    /// <summary>A colon would split the basic-auth pair.</summary>
    [Fact]
    public void A_credential_that_would_break_the_header_is_refused()
    {
        var status = new OpnSenseConnector(new Dictionary<string, string>
        {
            ["OPNSENSE_URL"] = "https://192.168.1.1",
            ["OPNSENSE_API_KEY"] = "has:colon",
            ["OPNSENSE_API_SECRET"] = "secret",
        }).Status();

        Assert.Equal("invalid_configuration", status.State);
        Assert.Contains("invalid format", status.Error);
    }

    [Fact]
    public void A_configured_connector_is_unchecked_until_health_runs()
    {
        var status = new OpnSenseConnector(new Dictionary<string, string>
        {
            ["OPNSENSE_URL"] = "https://192.168.1.1",
            ["OPNSENSE_API_KEY"] = "key",
            ["OPNSENSE_API_SECRET"] = "secret",
        }).Status();

        Assert.Equal("configured_unchecked", status.State);
        Assert.True(status.Configured);
        Assert.Null(status.Operational);
        Assert.Null(status.CheckedAt);
    }

    /// <summary>
    /// Configured means both settings are present. It is never operational and
    /// never implemented, because nothing is.
    /// </summary>
    [Fact]
    public void Bitdefender_is_a_setup_indicator_only()
    {
        var absent = new BitdefenderConnector(new Dictionary<string, string>()).Status();
        Assert.Equal("not_configured", absent.State);

        var present = new BitdefenderConnector(new Dictionary<string, string>
        {
            ["BITDEFENDER_API_URL"] = "https://cloud.test",
            ["BITDEFENDER_API_KEY"] = "key",
        }).Status();

        Assert.Equal("setup_only", present.State);
        Assert.True(present.Configured);
        Assert.False(present.Implemented);
        Assert.False(present.Operational);
    }
}

public sealed class ScanJobTests : IDisposable
{
    private readonly SuiteFixture _fx = new();

    private (DirectoryMonitor Monitor, ScanJobs Jobs) New()
    {
        var telemetry = new AuthTelemetry(_fx.Config.AuthLogPath, providers: []);
        var monitor = new DirectoryMonitor(_fx.Config, _fx.Engine, _fx.Store, telemetry, _ => { });
        return (monitor, monitor.Jobs);
    }

    [Fact]
    public void A_scan_walks_the_tree_and_counts_matches()
    {
        var (monitor, _) = New();
        var tree = Path.Combine(_fx.Temp, "tree", "deep");
        Directory.CreateDirectory(tree);
        File.WriteAllText(Path.Combine(tree, "bad.txt"), "FIXTURE_BAD_MARKER");
        File.WriteAllText(Path.Combine(tree, "good.txt"), "nothing here");

        var job = monitor.ScanPath(Path.Combine(_fx.Temp, "tree"));

        Assert.NotNull(job);
        Assert.Equal(ScanJobState.Completed, job.State);
        Assert.Equal(2, job.Scanned);
        Assert.Equal(1, job.Matches);
        Assert.Equal(0, job.Errors);
    }

    /// <summary>A failed root is not a successfully completed empty scan.</summary>
    [Fact]
    public void A_missing_root_is_an_error_not_an_empty_success()
    {
        var (monitor, _) = New();
        var job = monitor.ScanPath(Path.Combine(_fx.Temp, "does-not-exist"));

        Assert.NotNull(job);
        Assert.NotEqual(ScanJobState.Completed, job.State);
    }

    [Fact]
    public void An_empty_or_null_path_is_refused_before_a_job_starts()
    {
        var (_, jobs) = New();

        Assert.IsType<ScanJobError>(jobs.Start(""));
        Assert.IsType<ScanJobError>(jobs.Start(null));
        Assert.IsType<ScanJobError>(jobs.Start("has\0null"));
        Assert.Empty(jobs.Status());
    }

    /// <summary>
    /// The findings log contains the strings that tripped the rules, so
    /// scanning it would alert on itself.
    /// </summary>
    [Fact]
    public void Suite_owned_paths_are_excluded_from_a_scan()
    {
        var (monitor, _) = New();
        File.WriteAllText(_fx.Config.FindingsLog, "FIXTURE_BAD_MARKER\n");
        File.WriteAllText(Path.Combine(_fx.Config.QuarantineDir, "held.txt"), "FIXTURE_BAD_MARKER");

        var job = monitor.ScanPath(_fx.Temp);

        Assert.NotNull(job);
        Assert.True(job.SkipReasons.GetValueOrDefault("excluded") >= 2);
        Assert.DoesNotContain(_fx.Store.Events(limit: 500, eventType: SuiteEvent.TypeMatch),
            e => e.FilePath == _fx.Config.FindingsLog);
    }

    [Fact]
    public void Only_one_job_runs_at_a_time()
    {
        var (_, jobs) = New();
        var big = Directory.CreateDirectory(Path.Combine(_fx.Temp, "many")).FullName;
        for (var i = 0; i < 400; i++)
            File.WriteAllText(Path.Combine(big, "f" + i + ".txt"), "filler " + i);

        var first = jobs.Start(big);
        Assert.IsType<ScanJob>(first);

        // The second start lands while the first is still walking.
        var second = jobs.Start(big);
        if (second is ScanJobError error) Assert.Contains("already active", error.Error);

        jobs.Cancel(((ScanJob)first).Id);
        jobs.Wait(((ScanJob)first).Id);
    }

    [Fact]
    public void Cancelling_an_unknown_job_is_refused()
    {
        var (_, jobs) = New();
        var result = jobs.Cancel("nope");

        Assert.Equal("Unknown scan job", Assert.IsType<ScanJobError>(result).Error);
    }

    [Fact]
    public void Fixed_drives_are_offered_as_scan_roots()
    {
        var (_, jobs) = New();
        var drives = jobs.Drives();

        Assert.NotEmpty(drives);
        Assert.All(drives, d => Assert.NotEmpty(d.Path));
    }

    /// <summary>
    /// Links are never followed: it would turn a bounded walk into an unbounded
    /// one and pull in anything on the volume.
    /// </summary>
    [SymlinkFact]
    public void A_link_inside_the_tree_is_skipped()
    {
        var (monitor, _) = New();
        var tree = Directory.CreateDirectory(Path.Combine(_fx.Temp, "linked")).FullName;
        var outside = Directory.CreateDirectory(Path.Combine(_fx.Temp, "beyond")).FullName;
        File.WriteAllText(Path.Combine(outside, "bad.txt"), "FIXTURE_BAD_MARKER");
        Directory.CreateSymbolicLink(Path.Combine(tree, "escape"), outside);

        var job = monitor.ScanPath(tree);

        Assert.NotNull(job);
        Assert.Equal(1, job.SkipReasons.GetValueOrDefault("link"));
        Assert.Equal(0, job.Matches);
    }

    public void Dispose() => _fx.Dispose();
}
