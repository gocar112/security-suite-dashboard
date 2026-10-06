using System.Text;
using SecuritySuite.Detection;
using SecuritySuite.Storage;

namespace SecuritySuite.Tests;

/// <summary>
/// Exercises the real libyara.NET backend against rules written to a temp
/// directory. These are not mocked: the point is that the binding compiles,
/// matches, and reports metadata the way the suite assumes.
/// </summary>
public sealed class EngineTests : IDisposable
{
    private readonly string _rules = Directory.CreateTempSubdirectory("suite-rules").FullName;
    private readonly List<string> _temps = [];

    private const string DemoRule = """
        rule Demo_Critical_Marker : malware test
        {
            meta:
                description = "Marker used by the test suite"
                severity = "critical"
                author = "tests"
            strings:
                $a = "SUITE_TEST_MARKER_ALPHA"
            condition:
                $a
        }

        rule Demo_Untagged_NoSeverity
        {
            meta:
                description = "No severity, no tags"
            strings:
                $b = "SUITE_TEST_MARKER_BETA"
            condition:
                $b
        }

        rule Demo_Tag_Only : ransomware
        {
            strings:
                $c = "SUITE_TEST_MARKER_GAMMA"
            condition:
                $c
        }
        """;

    private YaraEngine NewEngine(long maxBytes = 64L * 1024 * 1024)
    {
        File.WriteAllText(Path.Combine(_rules, "demo.yar"), DemoRule);
        return new YaraEngine(_rules, maxBytes);
    }

    private string WriteTemp(string name, string content)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")[..8] + "-" + name);
        File.WriteAllText(path, content);
        _temps.Add(path);
        return path;
    }

    [Fact]
    public void Loads_rules_and_reports_what_compiled()
    {
        using var engine = NewEngine();
        var info = engine.Info();

        Assert.Equal(3, info.RuleCount);
        Assert.False(info.UsingFallback);
        Assert.Empty(info.LoadErrors);
        Assert.Contains("demo", info.RuleFiles);
        Assert.Contains(info.Rules, r => r.Rule == "Demo_Critical_Marker");
    }

    /// <summary>
    /// libyara.NET has no namespace parameter, so the engine attributes a match
    /// to its file via the compile-time ownership map. This is that mechanism.
    /// </summary>
    [Fact]
    public void Match_is_attributed_to_its_rule_file()
    {
        using var engine = NewEngine();
        var target = WriteTemp("hit.txt", "prefix SUITE_TEST_MARKER_ALPHA suffix");

        var result = engine.ScanFile(target);

        Assert.True(result.Hit);
        var match = Assert.Single(result.Matches);
        Assert.Equal("Demo_Critical_Marker", match.Rule);
        Assert.Equal("demo", match.Namespace);
    }

    [Fact]
    public void Severity_comes_from_rule_metadata()
    {
        using var engine = NewEngine();
        var result = engine.ScanFile(WriteTemp("a.txt", "SUITE_TEST_MARKER_ALPHA"));
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void Severity_falls_back_to_tags_then_to_medium()
    {
        using var engine = NewEngine();

        // Tagged "ransomware", no declared severity.
        var tagged = engine.ScanFile(WriteTemp("g.txt", "SUITE_TEST_MARKER_GAMMA"));
        Assert.Equal(Severity.Critical, tagged.Severity);

        // Neither severity nor a mappable tag.
        var plain = engine.ScanFile(WriteTemp("b.txt", "SUITE_TEST_MARKER_BETA"));
        Assert.Equal(Severity.Medium, plain.Severity);
    }

    [Fact]
    public void Worst_severity_wins_when_several_rules_fire()
    {
        using var engine = NewEngine();
        var result = engine.ScanFile(
            WriteTemp("both.txt", "SUITE_TEST_MARKER_BETA and SUITE_TEST_MARKER_ALPHA"));

        Assert.Equal(2, result.Matches.Count);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void Clean_file_produces_a_result_with_no_matches()
    {
        using var engine = NewEngine();
        var result = engine.ScanFile(WriteTemp("clean.txt", "nothing interesting at all"));

        Assert.False(result.Hit);
        Assert.Null(result.Severity);
        Assert.Empty(result.Matches);
        Assert.NotNull(result.Sha256);
    }

    [Fact]
    public void Matched_strings_carry_identifier_offset_and_preview()
    {
        using var engine = NewEngine();
        var result = engine.ScanFile(WriteTemp("off.txt", "0123456789SUITE_TEST_MARKER_ALPHA"));

        var hit = Assert.Single(Assert.Single(result.Matches).Strings);
        Assert.Equal("$a", hit.Identifier);
        Assert.Equal(10, hit.Offset);
        Assert.Contains("SUITE_TEST_MARKER_ALPHA", hit.Preview);
    }

    [Fact]
    public void Oversized_file_is_skipped_not_scanned()
    {
        using var engine = NewEngine(maxBytes: 16);
        var result = engine.ScanFile(WriteTemp("big.txt", new string('x', 200)));

        Assert.Equal("file larger than max_file_mb", result.Skipped);
        Assert.Empty(result.Matches);
    }

    /// <summary>
    /// Observables are only pulled from files that tripped a rule: a clean scan
    /// does not need them, and running every pattern over every file would
    /// dominate the scan budget.
    /// </summary>
    [Fact]
    public void Iocs_are_extracted_only_for_matches()
    {
        using var engine = NewEngine();

        var clean = engine.ScanFile(WriteTemp("c.txt", "see http://evil.test/payload"));
        Assert.Equal(0, clean.Iocs.Total);

        var hit = engine.ScanFile(
            WriteTemp("h.txt", "SUITE_TEST_MARKER_ALPHA see http://evil.test/payload"));
        Assert.True(hit.Iocs.Total > 0);
        Assert.Contains(hit.Iocs.Indicators, i => i.Defanged.Contains("hxxp://evil[.]test"));
    }

    [Fact]
    public void A_broken_rule_file_is_reported_and_the_rest_still_load()
    {
        File.WriteAllText(Path.Combine(_rules, "demo.yar"), DemoRule);
        File.WriteAllText(Path.Combine(_rules, "broken.yar"), "rule Nope { condition: this is not yara }");

        using var engine = new YaraEngine(_rules);
        var info = engine.Info();

        Assert.Equal(3, info.RuleCount);
        Assert.False(info.UsingFallback);
        var error = Assert.Single(info.LoadErrors);
        Assert.Contains("broken.yar", error.File);

        // And the good rules still match.
        Assert.True(engine.ScanFile(WriteTemp("s.txt", "SUITE_TEST_MARKER_ALPHA")).Hit);
    }

    [Fact]
    public void Empty_rules_directory_falls_back_rather_than_disarming()
    {
        var empty = Directory.CreateTempSubdirectory("suite-empty").FullName;
        try
        {
            using var engine = new YaraEngine(empty);
            var info = engine.Info();

            Assert.True(info.UsingFallback);
            Assert.True(info.RuleCount > 0);
        }
        finally
        {
            PathUtilTests.TryDelete(empty);
        }
    }

    /// <summary>
    /// Rules live in subdirectories: the 931 generated NVD rules are under
    /// <c>generated/</c>, and a non-recursive search would find none of them
    /// while appearing to work.
    /// </summary>
    [Fact]
    public void Rule_discovery_is_recursive()
    {
        File.WriteAllText(Path.Combine(_rules, "demo.yar"), DemoRule);
        var nested = Directory.CreateDirectory(Path.Combine(_rules, "generated")).FullName;
        File.WriteAllText(Path.Combine(nested, "extra.yar"), """
            rule Generated_Nested_Rule
            {
                meta:
                    severity = "low"
                strings:
                    $z = "SUITE_TEST_MARKER_DELTA"
                condition:
                    $z
            }
            """);

        using var engine = new YaraEngine(_rules);

        Assert.Equal(4, engine.Info().RuleCount);

        // The namespace label is the rule file's stem, not its directory, which
        // is what yara-python's path.stem produced too.
        var result = engine.ScanFile(WriteTemp("d.txt", "SUITE_TEST_MARKER_DELTA"));
        Assert.Equal("extra", Assert.Single(result.Matches).Namespace);
    }

    [Fact]
    public void Entropy_distinguishes_uniform_from_random()
    {
        Assert.Equal(0.0, YaraEngine.ShannonEntropy(new byte[256]));
        Assert.Equal(0.0, YaraEngine.ShannonEntropy([]));

        // Every byte value exactly once is maximum entropy for a byte stream.
        var all = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        Assert.Equal(8.0, YaraEngine.ShannonEntropy(all));

        Assert.InRange(YaraEngine.ShannonEntropy(Encoding.ASCII.GetBytes(new string('a', 100) + "bcdef")), 0.1, 2.0);
    }

    [Fact]
    public void Printable_replaces_nonprintable_bytes_with_dots()
    {
        Assert.Equal("ab.cd", YaraEngine.Printable([(byte)'a', (byte)'b', 0x00, (byte)'c', (byte)'d']));
        Assert.Equal(48, YaraEngine.Printable(new byte[200]).Length);
    }

    [Fact]
    public void Sha256_matches_a_known_value()
    {
        var path = WriteTemp("sha.txt", "abc");
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                     YaraEngine.Sha256Of(path));
    }

    [Fact]
    public void Reload_picks_up_a_new_rule_file()
    {
        using var engine = NewEngine();
        Assert.Equal(3, engine.Info().RuleCount);

        File.WriteAllText(Path.Combine(_rules, "added.yar"), """
            rule Added_Later { strings: $x = "SUITE_TEST_MARKER_EPSILON" condition: $x }
            """);

        Assert.Equal(4, engine.Reload().RuleCount);
        Assert.True(engine.ScanFile(WriteTemp("e.txt", "SUITE_TEST_MARKER_EPSILON")).Hit);
    }

    public void Dispose()
    {
        foreach (var path in _temps)
        {
            try { File.Delete(path); }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
        }
        PathUtilTests.TryDelete(_rules);
    }
}
