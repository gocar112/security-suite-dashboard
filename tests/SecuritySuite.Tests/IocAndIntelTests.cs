using System.Text;
using System.Text.Json;
using SecuritySuite.Intel;
using SecuritySuite.Net;
using SecuritySuite.Storage;

namespace SecuritySuite.Tests;

public sealed class IocExtractionTests
{
    private readonly IocExtractor _extractor = new();

    private IocSummary Extract(string text) => _extractor.Extract(Encoding.UTF8.GetBytes(text));

    [Fact]
    public void Urls_domains_and_addresses_are_extracted()
    {
        var result = Extract("contact http://evil.test/payload.bin or 203.0.113.9 or bad-actor.top");

        Assert.Contains(result.Indicators, i => i.Type == IocKind.Url);
        Assert.Contains(result.Indicators, i => i.Type == IocKind.Ipv4);
        Assert.Contains(result.Indicators, i => i.Type == IocKind.Domain);
    }

    /// <summary>
    /// A live link in an alert is how somebody ends up clicking the C2, so
    /// every displayed value is unclickable and the original is kept beside it.
    /// </summary>
    [Fact]
    public void Everything_displayed_is_defanged()
    {
        var result = Extract("see https://evil.test/x and mail bad@evil.test");

        var url = result.Indicators.First(i => i.Type == IocKind.Url);
        Assert.Equal("hxxps://evil[.]test/x", url.Defanged);
        Assert.Equal("https://evil.test/x", url.Value);

        var email = result.Indicators.First(i => i.Type == IocKind.Email);
        Assert.Contains("[at]", email.Defanged);
        Assert.DoesNotContain("@", email.Defanged);
    }

    /// <summary>
    /// Loopback is tested before private because 127.0.0.0/8 is both, and the
    /// two mean different things to an analyst.
    /// </summary>
    [Theory]
    [InlineData("127.0.0.1", "loopback")]
    [InlineData("10.1.2.3", "private")]
    [InlineData("192.168.1.1", "private")]
    [InlineData("172.16.0.1", "private")]
    [InlineData("8.8.8.8", "external")]
    [InlineData("169.254.1.1", "reserved")]
    [InlineData("224.0.0.1", "reserved")]
    [InlineData("0.0.0.0", "reserved")]
    [InlineData("1.2.3.400", "")]
    public void Addresses_are_classified_by_scope(string address, string expected)
    {
        Assert.Equal(expected, IocExtractor.ClassifyAddress(address));
    }

    [Fact]
    public void Address_scopes_are_counted_rather_than_dropped()
    {
        // "This file talks to 10.0.0.5" is sometimes exactly the finding.
        var result = Extract("beacons to 10.0.0.5 then 198.51.100.1 then 8.8.4.4");

        Assert.True(result.IpScopes.ContainsKey("private"));
        Assert.True(result.IpScopes.ContainsKey("external"));
        Assert.Equal(3, result.Indicators.Count(i => i.Type == IocKind.Ipv4));
    }

    [Fact]
    public void Benign_hosts_are_filtered_and_the_filtering_is_visible()
    {
        var result = Extract("xmlns=\"http://www.w3.org/1999/xhtml\" and http://schemas.microsoft.com/x");

        Assert.DoesNotContain(result.Indicators, i => i.Type == IocKind.Url);
        Assert.True(result.Dropped["known_benign_url"] >= 2);
    }

    /// <summary>
    /// Stripping one leading label and re-checking is what lets a single
    /// denylist entry cover every subdomain under it.
    /// </summary>
    [Theory]
    [InlineData("cdn.example.com", false)]
    [InlineData("deep.nested.example.com", false)]
    [InlineData("www.w3.org", false)]
    [InlineData("payload.exe", false)]
    [InlineData("evil-actor.top", true)]
    public void Subdomains_of_benign_hosts_are_also_filtered(string domain, bool plausible)
    {
        Assert.Equal(plausible, IocExtractor.PlausibleDomain(domain));
    }

    [Fact]
    public void Host_is_pulled_out_of_a_url_without_a_parser()
    {
        Assert.Equal("evil.test", IocExtractor.HostOf("https://user:pass@evil.test:8443/a?b#c"));
        Assert.Equal("evil.test", IocExtractor.HostOf("evil.test/path"));
    }

    [Fact]
    public void Wallets_cves_registry_and_paths_are_recognised()
    {
        var result = Extract(
            "pay bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh exploits CVE-2021-44228 " +
            @"via HKLM\Software\Microsoft\Windows\CurrentVersion\Run and C:\Windows\Temp\x.exe");

        Assert.Contains(result.Indicators, i => i.Type == IocKind.Btc);
        Assert.Contains(result.Indicators, i => i.Type == IocKind.Cve && i.Value == "CVE-2021-44228");
        Assert.Contains(result.Indicators, i => i.Type == IocKind.Registry);
        Assert.Contains(result.Indicators, i => i.Type == IocKind.FilePath);
    }

    /// <summary>
    /// The 32-hex pattern cannot match inside a 64-hex run, because there is no
    /// word boundary in the middle of one.
    /// </summary>
    [Fact]
    public void A_sha256_is_not_also_counted_as_two_md5s()
    {
        var result = Extract("hash ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad end");

        Assert.Single(result.Indicators, i => i.Type == IocKind.Sha256);
        Assert.DoesNotContain(result.Indicators, i => i.Type == IocKind.Md5);
    }

    /// <summary>
    /// Offsets must be byte offsets, which is why the buffer is decoded as
    /// Latin-1 rather than UTF-8.
    /// </summary>
    [Fact]
    public void Offsets_survive_non_utf8_bytes()
    {
        var prefix = new byte[] { 0xFF, 0xFE, 0x80, 0x81 };
        var payload = Encoding.ASCII.GetBytes("http://evil.test/x");
        var buffer = prefix.Concat(payload).ToArray();

        var result = _extractor.Extract(buffer);
        var url = result.Indicators.First(i => i.Type == IocKind.Url);

        Assert.Equal(prefix.Length, url.Offset);
    }

    [Fact]
    public void Repeat_occurrences_are_counted_not_duplicated()
    {
        var result = Extract("http://evil.test/a http://evil.test/a http://evil.test/a");

        var url = Assert.Single(result.Indicators, i => i.Type == IocKind.Url);
        Assert.Equal(3, url.Count);
    }

    [Fact]
    public void Context_is_printable_ascii_only()
    {
        var result = _extractor.Extract([0x00, 0x01, .. Encoding.ASCII.GetBytes("http://evil.test/x"), 0x02]);
        var url = result.Indicators.First(i => i.Type == IocKind.Url);

        Assert.NotNull(url.Context);
        Assert.All(url.Context!, c => Assert.InRange(c, (char)32, (char)126));
    }

    [Fact]
    public void An_empty_buffer_yields_nothing_rather_than_throwing()
    {
        var result = _extractor.Extract([]);
        Assert.Equal(0, result.Total);
    }
}

public sealed class IocAggregationTests
{
    private static SuiteEvent WithIocs(string id, string file, string stamp,
                                       params (string Type, string Value)[] indicators)
    {
        var entry = new SuiteEvent
        {
            Id = id,
            EventType = SuiteEvent.TypeMatch,
            FileName = file,
            Timestamp = stamp,
        };
        entry.SetExtra("iocs", new IocSummary
        {
            Indicators = [.. indicators.Select(i => new Indicator
            {
                Type = i.Type,
                Value = i.Value,
                Defanged = IocExtractor.Defang(i.Value, i.Type),
                Count = 1,
            })],
        });
        return entry;
    }

    /// <summary>
    /// One domain across six samples is a campaign; the same domain two hundred
    /// times in one file is a loop. File spread sorts first for that reason.
    /// </summary>
    [Fact]
    public void Indicators_seen_across_more_files_sort_first()
    {
        var events = new[]
        {
            WithIocs("a", "one.bin", "2026-01-01T00:00:00+00:00",
                (IocKind.Domain, "shared.top"), (IocKind.Domain, "loud.top")),
            WithIocs("b", "two.bin", "2026-01-02T00:00:00+00:00", (IocKind.Domain, "shared.top")),
            WithIocs("c", "three.bin", "2026-01-03T00:00:00+00:00", (IocKind.Domain, "shared.top")),
        };

        var aggregate = IocAggregator.Summarise(events);

        Assert.Equal("shared.top", aggregate.Indicators[0].Value);
        Assert.Equal(3, aggregate.Indicators[0].FileCount);
        Assert.Equal(3, aggregate.Indicators[0].Occurrences);
    }

    [Fact]
    public void First_and_last_seen_span_every_finding()
    {
        var aggregate = IocAggregator.Summarise(
        [
            WithIocs("a", "one", "2026-03-01T00:00:00+00:00", (IocKind.Domain, "x.top")),
            WithIocs("b", "two", "2026-01-01T00:00:00+00:00", (IocKind.Domain, "x.top")),
        ]);

        var indicator = Assert.Single(aggregate.Indicators);
        Assert.Equal("2026-01-01T00:00:00+00:00", indicator.FirstSeen);
        Assert.Equal("2026-03-01T00:00:00+00:00", indicator.LastSeen);
    }

    [Fact]
    public void A_cve_is_shown_plainly_and_linked_to_the_authority()
    {
        var aggregate = IocAggregator.Summarise(
            [WithIocs("a", "one", "2026-01-01T00:00:00+00:00", (IocKind.Cve, "cve-2021-44228"))]);

        var indicator = Assert.Single(aggregate.Indicators);
        Assert.Equal("CVE-2021-44228", indicator.Value);
        Assert.Equal("CVE-2021-44228", indicator.Defanged);   // an identifier, not a hostile value
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", indicator.NvdUrl);
    }

    /// <summary>
    /// The Python version kept the CSV header and the value tuple as two
    /// hardcoded lists, so a new field silently failed to export.
    /// </summary>
    [Fact]
    public void Csv_header_and_rows_always_have_the_same_column_count()
    {
        var aggregate = IocAggregator.Summarise(
            [WithIocs("a", "one.bin", "2026-01-01T00:00:00+00:00", (IocKind.Url, "http://evil.test/a,b"))]);

        var lines = aggregate.ToCsv().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);

        var columns = lines[0].Split(',').Length;
        Assert.Contains("defanged", lines[0]);
        Assert.Contains("nvd_url", lines[0]);

        // The value contains a comma, so it must be quoted rather than
        // splitting into an extra column.
        Assert.Contains("\"", lines[1]);
        Assert.Equal(columns, CountCsvFields(lines[1]));
    }

    private static int CountCsvFields(string line)
    {
        var fields = 1;
        var quoted = false;
        foreach (var c in line)
        {
            if (c == '"') quoted = !quoted;
            else if (c == ',' && !quoted) fields++;
        }
        return fields;
    }
}

public sealed class NvdNormalisationTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void Newest_cvss_version_wins()
    {
        var record = NvdClient.Normalise(Parse("""
        {"cve":{"id":"CVE-2026-0001","metrics":{
          "cvssMetricV2":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM","version":"2.0"}}],
          "cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","version":"3.1"}}]
        }}}
        """));

        Assert.Equal(9.8, record.Score);
        Assert.Equal("CRITICAL", record.CvssSeverity);
        Assert.Equal(Severity.Critical, record.Severity);
        Assert.Equal("3.1", record.CvssVersion);
    }

    /// <summary>
    /// The original collapsed references to a count at ingestion, discarding
    /// every vendor patch URL.
    /// </summary>
    [Fact]
    public void Patch_references_are_kept_alongside_the_count()
    {
        var record = NvdClient.Normalise(Parse("""
        {"cve":{"id":"CVE-2026-0002","references":[
          {"url":"https://vendor.test/advisory","tags":["Vendor Advisory","Patch"]},
          {"url":"https://blog.test/post","tags":["Third Party Advisory"]},
          {"url":"https://vendor.test/fix","tags":["Patch"]}
        ]}}
        """));

        Assert.Equal(3, record.References);
        Assert.Equal(2, record.PatchRefs.Count);
        Assert.All(record.PatchRefs, r => Assert.Contains("vendor.test", r.Url));
    }

    [Fact]
    public void Kev_fields_are_carried_through()
    {
        var record = NvdClient.Normalise(Parse("""
        {"cve":{"id":"CVE-2021-44228","cisaExploitAdd":"2021-12-10",
          "cisaVulnerabilityName":"Apache Log4j2 RCE",
          "cisaRequiredAction":"Apply updates per vendor instructions.",
          "cisaActionDue":"2021-12-24"}}
        """));

        Assert.True(record.Kev);
        Assert.Equal("Apache Log4j2 RCE", record.KevName);
        Assert.Equal("Apply updates per vendor instructions.", record.KevRequiredAction);
        Assert.Equal("2021-12-24", record.KevActionDue);
    }

    [Fact]
    public void A_record_with_nothing_useful_still_normalises()
    {
        var record = NvdClient.Normalise(Parse("""{"cve":{"id":"CVE-2026-0003"}}"""));

        Assert.Equal("CVE-2026-0003", record.Id);
        Assert.Null(record.Score);
        Assert.Equal(Severity.Info, record.Severity);
        Assert.False(record.Kev);
        Assert.Equal(CveRecord.CurrentSchema, record.Schema);
    }

    [Fact]
    public void English_description_is_selected_and_clipped()
    {
        var record = NvdClient.Normalise(Parse("""
        {"cve":{"id":"CVE-2026-0004","descriptions":[
          {"lang":"es","value":"no"},
          {"lang":"en","value":"the real description"}
        ]}}
        """));

        Assert.Equal("the real description", record.Description);
    }
}

public sealed class OsvNormalisationTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    [Theory]
    [InlineData("""{"database_specific":{"severity":"CRITICAL"}}""", "critical")]
    [InlineData("""{"database_specific":{"severity":"MODERATE"}}""", "medium")]
    [InlineData("""{"affected":[{"ecosystem_specific":{"severity":"HIGH"}}]}""", "high")]
    [InlineData("""{"severity":[{"score":"CVSS:3.1/AV:N/AC:L"}]}""", "medium")]
    [InlineData("""{"id":"OSV-1"}""", "info")]
    public void Severity_is_found_wherever_the_source_database_put_it(string json, string expected)
    {
        Assert.Equal(expected, OsvClient.Normalise(Parse(json)).Severity);
    }

    /// <summary>
    /// Scoring a vector properly is a real calculation, and a wrong number here
    /// would be worse than no number.
    /// </summary>
    [Fact]
    public void A_cvss_vector_is_kept_verbatim_and_never_turned_into_a_score()
    {
        var vuln = OsvClient.Normalise(Parse(
            """{"severity":[{"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}"""));

        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", vuln.Vector);
    }

    [Fact]
    public void Affected_packages_are_flattened()
    {
        var vuln = OsvClient.Normalise(Parse("""
        {"id":"GHSA-x","aliases":["CVE-2026-9999"],"summary":"bad thing",
         "affected":[{"package":{"name":"left-pad","ecosystem":"npm","purl":"pkg:npm/left-pad"}}]}
        """));

        Assert.Equal("GHSA-x", vuln.Id);
        Assert.Contains("CVE-2026-9999", vuln.Aliases);
        var package = Assert.Single(vuln.Packages);
        Assert.Equal("left-pad", package.Name);
        Assert.Equal("npm", package.Ecosystem);
    }
}

public sealed class HttpQueryTests
{
    /// <summary>
    /// NVD has valueless boolean parameters. Sent as <c>hasKev=true</c> they
    /// are rejected; sent as <c>hasKev=</c> they are silently ignored, which is
    /// how the filter once appeared to work while doing nothing.
    /// </summary>
    [Fact]
    public void A_true_flag_emits_a_bare_key()
    {
        Assert.Equal("hasKev", SuiteHttp.Query([new("hasKev", true)]));
        Assert.Equal("", SuiteHttp.Query([new("hasKev", false)]));
    }

    [Fact]
    public void Null_and_empty_values_are_dropped()
    {
        Assert.Equal("b=2", SuiteHttp.Query(
            [new("a", null), new("b", 2), new("c", "")]));
    }

    /// <summary>
    /// The Python version replaced two characters by hand, so a keyword
    /// containing &amp; or = could break out of its own parameter.
    /// </summary>
    [Fact]
    public void Values_are_fully_escaped()
    {
        var query = SuiteHttp.Query([new("keywordSearch", "a&b=c d:e")]);

        Assert.DoesNotContain("a&b", query);
        Assert.Contains("%26", query);
        Assert.Contains("%3A", query);
        Assert.Contains("%20", query);
    }

    [Fact]
    public void Timestamps_keep_their_colons_escaped()
    {
        var query = SuiteHttp.Query([new("lastModStartDate", "2026-01-01T00:00:00.000")]);
        Assert.Contains("2026-01-01T00%3A00%3A00.000", query);
    }
}

public sealed class VirusTotalTests
{
    [Theory]
    [InlineData(12, 0, "critical")]
    [InlineData(5, 0, "high")]
    [InlineData(1, 0, "medium")]
    [InlineData(0, 4, "medium")]
    [InlineData(0, 1, "low")]
    [InlineData(0, 0, "info")]
    public void Engine_consensus_maps_onto_the_triage_scale(int malicious, int suspicious, string expected)
    {
        Assert.Equal(expected, VirusTotalClient.SeverityFor(malicious, suspicious));
    }

    [Fact]
    public void A_report_is_flattened_with_only_flagged_engines_kept()
    {
        var report = VirusTotalClient.Normalise(JsonDocument.Parse("""
        {"data":{"attributes":{
          "sha256":"aa","md5":"bb","size":1024,"type_description":"Win32 EXE",
          "last_analysis_stats":{"malicious":4,"suspicious":1,"harmless":60,"undetected":5},
          "popular_threat_classification":{"suggested_threat_label":"trojan.x/y",
            "popular_threat_name":[{"value":"x"},{"value":"y"}]},
          "last_analysis_results":{
            "EngineA":{"category":"malicious","result":"Trojan.X"},
            "EngineB":{"category":"harmless","result":null},
            "EngineC":{"category":"suspicious","result":"Heur"}}
        }}}
        """).RootElement);

        Assert.Equal(4, report.Malicious);
        Assert.Equal(70, report.EnginesTotal);
        Assert.Equal("4/70", report.DetectionRatio);
        Assert.Equal("trojan.x/y", report.ThreatLabel);
        Assert.Equal(Severity.High, report.Severity);
        Assert.Equal(2, report.FlaggedBy.Count);
        Assert.DoesNotContain(report.FlaggedBy, e => e.Engine == "EngineB");
        Assert.Equal("https://www.virustotal.com/gui/file/aa", report.Permalink);
    }

    [Fact]
    public async Task An_unconfigured_client_refuses_without_making_a_request()
    {
        var temp = Directory.CreateTempSubdirectory("suite-vt").FullName;
        try
        {
            var client = new VirusTotalClient("", temp);
            Assert.False(client.Configured);

            var caps = client.Capabilities();
            Assert.Equal("none", caps.Tier);
            Assert.False(caps.Configured);

            var report = await client.LookupHashAsync(new string('a', 64));
            Assert.Equal("no VirusTotal API key configured", report.Error);
        }
        finally
        {
            PathUtilTests.TryDelete(temp);
        }
    }

    [Fact]
    public async Task A_malformed_hash_is_refused_before_any_request()
    {
        var temp = Directory.CreateTempSubdirectory("suite-vt2").FullName;
        try
        {
            var client = new VirusTotalClient("not-a-real-key", temp);
            var report = await client.LookupHashAsync("nope");

            Assert.Equal("not an md5/sha1/sha256 hash", report.Error);
        }
        finally
        {
            PathUtilTests.TryDelete(temp);
        }
    }

    /// <summary>
    /// The status payload states the no-upload guarantee, so it is visible in
    /// the dashboard and not only in a comment.
    /// </summary>
    [Fact]
    public void Status_states_that_files_are_never_uploaded()
    {
        var temp = Directory.CreateTempSubdirectory("suite-vt3").FullName;
        try
        {
            Assert.Contains("never", new VirusTotalClient("", temp).Status().Uploads);
        }
        finally
        {
            PathUtilTests.TryDelete(temp);
        }
    }
}
