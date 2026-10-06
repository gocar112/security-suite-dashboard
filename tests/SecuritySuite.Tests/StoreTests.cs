using System.Text.Json;
using SecuritySuite.Storage;

namespace SecuritySuite.Tests;

public sealed class StoreTests : IDisposable
{
    private readonly string _temp = Directory.CreateTempSubdirectory("suite-store").FullName;

    private EventStore New(int historyLimit = 2000) => new(
        Path.Combine(_temp, "findings.ndjson"),
        Path.Combine(_temp, "triage.json"),
        historyLimit);

    [Fact]
    public void Clean_scans_stay_in_memory_and_never_reach_the_log()
    {
        var store = New();
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeScan, Verdict = "clean" }, persist: false);

        Assert.Single(store.Events());
        Assert.False(File.Exists(store.Path));
    }

    /// <summary>
    /// The scanned counter must survive the ring buffer rolling over, and must
    /// not count files that were skipped rather than scanned.
    /// </summary>
    [Fact]
    public void Scan_total_outgrows_the_buffer_without_counting_skips()
    {
        var store = New(historyLimit: 10);

        for (var i = 0; i < 50; i++)
            store.Add(new SuiteEvent { EventType = SuiteEvent.TypeScan, Verdict = "clean" }, persist: false);

        for (var i = 0; i < 5; i++)
        {
            store.Add(new SuiteEvent
            {
                EventType = SuiteEvent.TypeScan,
                Skipped = "file larger than max_file_mb",
            }, persist: false);
        }

        var stats = store.Stats();
        Assert.Equal(50, stats.FilesScanned);
        Assert.Equal(10, store.Events(limit: 1000).Count);
    }

    [Fact]
    public void Triage_state_persists_and_is_reapplied_on_reload()
    {
        var store = New();
        var finding = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            Severity = Severity.High,
            FilePath = "x",
        });

        Assert.NotNull(store.SetStatus(finding.Id, "false_positive", "benign test file"));

        var reopened = New();
        var reloaded = Assert.Single(reopened.Events(eventType: SuiteEvent.TypeMatch));
        Assert.Equal("false_positive", reloaded.Status);
        Assert.Equal("benign test file", reloaded.TriageNote);
    }

    [Fact]
    public void Setting_status_on_an_unknown_id_returns_null()
    {
        Assert.Null(New().SetStatus("nope", "resolved"));
    }

    /// <summary>
    /// The findings log is the audit trail for every destructive action taken
    /// and refused. Clearing the dashboard must not be a way to erase it.
    /// </summary>
    [Fact]
    public void Clear_keeps_remediation_audit_records()
    {
        var store = New();
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, Severity = Severity.High });
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, Severity = Severity.Low });
        var audit = store.Add(new SuiteEvent { EventType = SuiteEvent.TypeRemediation });

        var result = store.Clear();

        Assert.True(result.Cleared);
        Assert.Equal(3, result.Events);
        Assert.Equal(1, result.AuditRetained);

        var kept = Assert.Single(store.Events(limit: 100));
        Assert.Equal(audit.Id, kept.Id);
        Assert.Equal(SuiteEvent.TypeRemediation, kept.EventType);

        // And it survives on disk, not just in memory.
        Assert.Single(New().Events(limit: 100));
    }

    /// <summary>
    /// The defect this guards against: retention was built from the in-memory
    /// ring buffer, so a remediation record older than <c>HistoryLimit</c>
    /// events was erased from the log by a "Clear lines" click — and the
    /// result reported a falsely low <c>audit_retained</c> without complaint.
    /// Retention now streams the log from disk.
    /// </summary>
    [Fact]
    public void Clear_keeps_remediation_records_older_than_the_memory_window()
    {
        var store = New(historyLimit: 5);

        // An audit record, then enough noise to push it out of the buffer.
        var audit = store.Add(new SuiteEvent { EventType = SuiteEvent.TypeRemediation });
        for (var i = 0; i < 40; i++)
            store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, Severity = Severity.Low });

        // It is genuinely out of memory by now...
        Assert.DoesNotContain(store.Events(limit: 1000), e => e.Id == audit.Id);

        var result = store.Clear();

        // ...but it must survive the clear, because it is on disk.
        Assert.True(result.Cleared);
        Assert.Equal(1, result.AuditRetained);

        var onDisk = File.ReadAllLines(store.Path);
        Assert.Single(onDisk);
        Assert.Contains(audit.Id, onDisk[0]);
        Assert.Contains(SuiteEvent.TypeRemediation, onDisk[0]);
    }

    [Fact]
    public void Clear_retains_every_audit_record_not_just_the_recent_ones()
    {
        var store = New(historyLimit: 5);

        var ids = new List<string>();
        for (var round = 0; round < 4; round++)
        {
            ids.Add(store.Add(new SuiteEvent { EventType = SuiteEvent.TypeRemediation }).Id);
            for (var i = 0; i < 10; i++)
                store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch });
        }

        var result = store.Clear();

        Assert.Equal(4, result.AuditRetained);
        var text = File.ReadAllText(store.Path);
        Assert.All(ids, id => Assert.Contains(id, text));
    }

    /// <summary>
    /// A log that cannot be read is a log that cannot safely be rewritten, so
    /// the clear aborts rather than truncating it.
    /// </summary>
    [Fact]
    public void Clear_refuses_rather_than_truncating_an_unreadable_log()
    {
        var store = New();
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeRemediation });
        var before = File.ReadAllText(store.Path);

        // Hold the log open for exclusive writing so the store cannot read it.
        using (new FileStream(store.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var result = store.Clear();

            Assert.False(result.Cleared);
            Assert.NotNull(result.Error);
        }

        Assert.Equal(before, File.ReadAllText(store.Path));
    }

    [Fact]
    public void Clear_fails_closed_when_the_backup_cannot_be_created()
    {
        var store = New();
        var finding = store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch });
        var before = File.ReadAllText(store.Path);

        // A file where the backup directory must be makes directory creation fail.
        File.WriteAllText(Path.Combine(_temp, "log-backups"), "blocked");

        var result = store.Clear();

        Assert.False(result.Cleared);
        Assert.NotNull(result.Error);
        Assert.Equal(before, File.ReadAllText(store.Path));
        Assert.Contains(store.Events(), item => item.Id == finding.Id);
    }

    [Fact]
    public void Clear_fails_closed_when_replacement_cannot_be_staged()
    {
        var store = New();
        var finding = store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch });
        var before = File.ReadAllText(store.Path);

        // A directory at the staging-file path makes File.WriteAllText fail.
        Directory.CreateDirectory(store.Path + ".clearing");

        var result = store.Clear();

        Assert.False(result.Cleared);
        Assert.NotNull(result.Error);
        Assert.NotEqual("", result.BackupDir);
        Assert.Equal(before, File.ReadAllText(store.Path));
        Assert.Contains(store.Events(), item => item.Id == finding.Id);
    }

    /// <summary>
    /// A finding that has scrolled out of the buffer is still a real finding,
    /// and triage used to 404 on it.
    /// </summary>
    [Fact]
    public void Triage_works_on_a_finding_outside_the_memory_window()
    {
        var store = New(historyLimit: 5);
        var finding = store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            Severity = Severity.High,
            FilePath = "old.txt",
        });
        for (var i = 0; i < 40; i++)
            store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch });

        Assert.DoesNotContain(store.Events(limit: 1000), e => e.Id == finding.Id);

        var updated = store.SetStatus(finding.Id, "false_positive", "aged out but still triaged");

        Assert.NotNull(updated);
        Assert.Equal("false_positive", updated.Status);
        Assert.True(updated.GetExtra<bool>("outside_memory_window"));
    }

    [Fact]
    public void Triage_still_refuses_an_id_that_exists_nowhere()
    {
        var store = New(historyLimit: 5);
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch });

        Assert.Null(store.SetStatus("0123456789ab", "resolved"));
    }

    /// <summary>
    /// A random id per load meant triage state filed against an id-less log
    /// line could never reattach, because the id it was filed under no longer
    /// existed after a restart.
    /// </summary>
    [Fact]
    public void Ids_for_idless_log_lines_are_stable_across_restarts()
    {
        var log = Path.Combine(_temp, "findings.ndjson");
        File.WriteAllLines(log,
        [
            """{"event_type":"yara_match","severity":"high","file_name":"a.txt"}""",
            """{"event_type":"yara_match","severity":"low","file_name":"b.txt"}""",
        ]);

        var first = New().Events(limit: 10).Select(e => e.Id).ToList();
        var second = New().Events(limit: 10).Select(e => e.Id).ToList();

        Assert.Equal(first, second);
        Assert.All(first, id => Assert.Equal(12, id.Length));
        Assert.Equal(2, first.Distinct().Count());

        // And triage filed against that id survives a restart.
        var store = New();
        var target = store.Events(limit: 10).First(e => e.FileName == "a.txt");
        store.SetStatus(target.Id, "acknowledged", "stable");

        var reopened = New();
        Assert.Equal("acknowledged",
            reopened.Events(limit: 10).First(e => e.FileName == "a.txt").Status);
    }

    /// <summary>
    /// A reader that falls behind must be told. Silently dropping its events
    /// left the dashboard showing a live dot and a ticking uptime while
    /// receiving no findings.
    /// </summary>
    [Fact]
    public void A_subscriber_that_falls_behind_is_marked_overflowed()
    {
        var store = New();
        var subscription = store.Subscribe();

        Assert.False(subscription.Overflowed);

        // The channel holds 256; push well past it without reading.
        for (var i = 0; i < 400; i++)
            store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch }, persist: false);

        Assert.True(subscription.Overflowed);

        // The subscriber is kept, not silently removed, so the stream handler
        // can report the overflow before closing.
        Assert.Equal(1, store.SubscriberCount);
        store.Unsubscribe(subscription);
    }

    [Fact]
    public void A_subscriber_that_keeps_up_is_never_marked_overflowed()
    {
        var store = New();
        var subscription = store.Subscribe();

        for (var i = 0; i < 400; i++)
        {
            store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch }, persist: false);
            subscription.Reader.TryRead(out _);
        }

        Assert.False(subscription.Overflowed);
        store.Unsubscribe(subscription);
    }

    [Fact]
    public void Clear_always_backs_up_first()
    {
        var store = New();
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch });

        var result = store.Clear();

        Assert.NotEqual("", result.BackupDir);
        Assert.True(File.Exists(Path.Combine(result.BackupDir, "findings.ndjson")));
    }

    [Fact]
    public void Events_filter_by_severity_type_and_status()
    {
        var store = New();
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, Severity = Severity.Critical });
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, Severity = Severity.Low });
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeError, Severity = Severity.Low });

        Assert.Equal(2, store.Events(eventType: SuiteEvent.TypeMatch).Count);
        Assert.Single(store.Events(severity: Severity.Critical));
        Assert.Equal(3, store.Events(eventType: "all", severity: "all").Count);
        Assert.Equal(3, store.Events(status: "new").Count);
    }

    [Fact]
    public void Events_are_returned_newest_first()
    {
        var store = New();
        var first = store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, Message = "one" });
        var second = store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, Message = "two" });

        var events = store.Events();
        Assert.Equal(second.Id, events[0].Id);
        Assert.Equal(first.Id, events[1].Id);
    }

    [Fact]
    public void Search_matches_anywhere_in_the_serialised_event()
    {
        var store = New();
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, FileName = "invoice.docm" });
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch, FileName = "notes.txt" });

        Assert.Single(store.Events(search: "docm"));
        Assert.Single(store.Events(search: "INVOICE"));   // case-insensitive
        Assert.Empty(store.Events(search: "nothing-here"));
    }

    [Fact]
    public void A_malformed_log_line_is_skipped_and_the_rest_load()
    {
        var log = Path.Combine(_temp, "findings.ndjson");
        File.WriteAllLines(log,
        [
            JsonSerializer.Serialize(new SuiteEvent { Id = "aaa", EventType = SuiteEvent.TypeMatch },
                SuiteJson.Options),
            "{ this is not json",
            JsonSerializer.Serialize(new SuiteEvent { Id = "bbb", EventType = SuiteEvent.TypeMatch },
                SuiteJson.Options),
        ]);

        var warnings = new List<string>();
        var store = new EventStore(log, Path.Combine(_temp, "triage.json"), warn: warnings.Add);

        Assert.Equal(2, store.Events().Count);
        Assert.Contains(warnings, w => w.Contains("malformed"));
    }

    /// <summary>
    /// The log grows without bound by design, so startup must not scale with
    /// its lifetime.
    /// </summary>
    [Fact]
    public void Only_the_tail_of_a_long_log_is_replayed()
    {
        var log = Path.Combine(_temp, "findings.ndjson");
        using (var writer = new StreamWriter(log))
        {
            for (var i = 0; i < 500; i++)
            {
                writer.WriteLine(JsonSerializer.Serialize(
                    new SuiteEvent { Id = "e" + i, EventType = SuiteEvent.TypeMatch },
                    SuiteJson.Options));
            }
        }

        var store = new EventStore(log, Path.Combine(_temp, "triage.json"), historyLimit: 20);
        var events = store.Events(limit: 1000);

        Assert.Equal(20, events.Count);
        Assert.Equal("e499", events[0].Id);   // newest kept
    }

    [Fact]
    public void Extension_data_round_trips_through_the_log()
    {
        var store = New();
        var entry = new SuiteEvent { EventType = SuiteEvent.TypeMatch };
        entry.SetExtra("entropy", 7.42);
        entry.SetExtra("custom", new { nested = "value" });
        store.Add(entry);

        var reloaded = Assert.Single(New().Events());
        Assert.Equal(7.42, reloaded.GetExtra<double>("entropy"));
        Assert.NotNull(reloaded.Extra);
        Assert.True(reloaded.Extra.ContainsKey("custom"));
    }

    [Fact]
    public void Subscribers_receive_added_and_broadcast_events()
    {
        var store = New();
        var subscription = store.Subscribe();

        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch }, persist: false);
        store.Broadcast("a notice");

        Assert.True(subscription.Reader.TryRead(out var first));
        Assert.Equal(SuiteEvent.TypeMatch, first!.EventType);
        Assert.True(subscription.Reader.TryRead(out var second));
        Assert.Equal("a notice", second!.Message);

        store.Unsubscribe(subscription);
        Assert.Equal(0, store.SubscriberCount);
    }

    /// <summary>
    /// A slow reader must never block a scan. It is kept and flagged, so the
    /// stream handler can tell it that it fell behind; see
    /// <see cref="A_subscriber_that_falls_behind_is_marked_overflowed"/>.
    /// </summary>
    [Fact]
    public void A_full_subscriber_never_blocks_the_writer()
    {
        var store = New();
        var subscription = store.Subscribe();

        for (var i = 0; i < 400; i++)
            store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch }, persist: false);

        Assert.Equal(1, store.SubscriberCount);
        Assert.True(subscription.Reader.TryRead(out _));
        store.Unsubscribe(subscription);
    }

    [Fact]
    public void Stats_counts_severities_open_alerts_and_top_rules()
    {
        var store = New();
        for (var i = 0; i < 3; i++)
        {
            store.Add(new SuiteEvent
            {
                EventType = SuiteEvent.TypeMatch,
                Severity = Severity.Critical,
                Matches = [new RuleMatch { Rule = "Hot_Rule" }],
            }, persist: false);
        }
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeError }, persist: false);

        var stats = store.Stats();
        Assert.Equal(3, stats.Matches);
        Assert.Equal(3, stats.OpenAlerts);
        Assert.Equal(1, stats.Errors);
        Assert.Equal(3, stats.BySeverity[Severity.Critical]);
        Assert.Equal(new RuleCount("Hot_Rule", 3), stats.TopRules[0]);
    }

    [Fact]
    public void Timeline_buckets_recent_matches_and_ignores_old_ones()
    {
        var store = New();
        store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch }, persist: false);
        store.Add(new SuiteEvent
        {
            EventType = SuiteEvent.TypeMatch,
            Epoch = EventStore.NowEpoch() - 7200,   // two hours old, outside the window
        }, persist: false);

        var timeline = store.Stats().Timeline;
        Assert.Equal(24, timeline.Count);
        Assert.Equal(1, timeline.Sum(b => b.Count));
    }

    [Fact]
    public void Severity_ranking_puts_critical_first_and_unknowns_last()
    {
        Assert.Equal(0, Severity.Rank(Severity.Critical));
        Assert.True(Severity.Rank(Severity.High) < Severity.Rank(Severity.Low));
        Assert.Equal(Severity.Unranked, Severity.Rank("made-up"));

        Assert.True(Severity.MeetsThreshold(Severity.Critical, Severity.High));
        Assert.False(Severity.MeetsThreshold(Severity.Low, Severity.High));
        Assert.False(Severity.MeetsThreshold(Severity.Critical, "made-up"));
    }

    public void Dispose() => PathUtilTests.TryDelete(_temp);
}
