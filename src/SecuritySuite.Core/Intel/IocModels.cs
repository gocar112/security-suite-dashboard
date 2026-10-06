using System.Reflection;
using System.Text;
using System.Text.Json.Serialization;

namespace SecuritySuite.Intel;

/// <summary>Indicator kinds, in the order the dashboard should show them.</summary>
public static class IocKind
{
    public const string Url = "url";
    public const string Onion = "onion";
    public const string Domain = "domain";
    public const string Ipv4 = "ipv4";
    public const string Btc = "btc";
    public const string Xmr = "xmr";
    public const string Eth = "eth";
    public const string Email = "email";
    public const string Cve = "cve";
    public const string Registry = "registry";
    public const string Sha256 = "sha256";
    public const string Md5 = "md5";
    public const string FilePath = "filepath";
    public const string PosixPath = "posixpath";

    /// <summary>
    /// Most pivotable first. A C2 URL is worth an analyst's attention before a
    /// file path is, so this drives the sort rather than raw frequency.
    /// </summary>
    public static readonly string[] Priority =
    [
        Url, Onion, Domain, Ipv4, Btc, Xmr, Eth, Email,
        Cve, Registry, Sha256, Md5, FilePath, PosixPath,
    ];

    private static readonly Dictionary<string, int> Ranks =
        Priority.Select((kind, i) => (kind, i)).ToDictionary(x => x.kind, x => x.i, StringComparer.Ordinal);

    public static int Rank(string kind) => Ranks.GetValueOrDefault(kind, 99);
}

/// <summary>One observable found in a file.</summary>
public sealed class Indicator
{
    [JsonPropertyName("type")] public string Type { get; set; } = "";

    /// <summary>The value as it appeared, for machine use.</summary>
    [JsonPropertyName("value")] public string Value { get; set; } = "";

    /// <summary>
    /// The same value rendered unclickable, for anything a human will read.
    /// </summary>
    /// <remarks>
    /// Analysts paste indicators into tickets, chat and spreadsheets that
    /// auto-link URLs. A live link in an alert is how somebody ends up clicking
    /// the C2, so display always uses this form and never <see cref="Value"/>.
    /// </remarks>
    [JsonPropertyName("defanged")] public string Defanged { get; set; } = "";

    [JsonPropertyName("count")] public int Count { get; set; } = 1;
    [JsonPropertyName("offset")] public long Offset { get; set; }

    /// <summary>For addresses: external, private, loopback or reserved.</summary>
    [JsonPropertyName("scope")] public string Scope { get; set; } = "";

    [JsonPropertyName("context")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Context { get; set; }
}

/// <summary>What one file's extraction produced.</summary>
public sealed class IocSummary
{
    [JsonPropertyName("indicators")] public List<Indicator> Indicators { get; set; } = [];
    [JsonPropertyName("counts")] public Dictionary<string, int> Counts { get; set; } = [];
    [JsonPropertyName("total")] public int Total { get; set; }

    /// <summary>Indicators removed as known-benign, by reason.</summary>
    [JsonPropertyName("dropped")] public Dictionary<string, int> Dropped { get; set; } = [];

    /// <summary>
    /// Address counts by scope. These are kept and labelled, not dropped:
    /// "this file talks to 10.0.0.5" is sometimes exactly the finding.
    /// </summary>
    [JsonPropertyName("ip_scopes")] public Dictionary<string, int> IpScopes { get; set; } = [];

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }

    public static IocSummary Empty => new();

    public static IocSummary Failed(string reason) => new() { Error = reason };
}

/// <summary>One indicator rolled up across every finding that contained it.</summary>
public sealed class AggregatedIndicator
{
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("value")] public string Value { get; set; } = "";
    [JsonPropertyName("defanged")] public string Defanged { get; set; } = "";
    [JsonPropertyName("scope")] public string Scope { get; set; } = "";
    [JsonPropertyName("occurrences")] public int Occurrences { get; set; }
    [JsonPropertyName("file_count")] public int FileCount { get; set; }
    [JsonPropertyName("files")] public List<string> Files { get; set; } = [];
    [JsonPropertyName("finding_ids")] public List<string> FindingIds { get; set; } = [];
    [JsonPropertyName("first_seen")] public string? FirstSeen { get; set; }
    [JsonPropertyName("last_seen")] public string? LastSeen { get; set; }

    [JsonPropertyName("nvd_url")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NvdUrl { get; set; }
}

/// <summary>The dashboard's indicator panel.</summary>
public sealed class IocAggregate
{
    [JsonPropertyName("indicators")] public List<AggregatedIndicator> Indicators { get; set; } = [];
    [JsonPropertyName("by_type")] public Dictionary<string, int> ByType { get; set; } = [];
    [JsonPropertyName("total")] public int Total { get; set; }

    /// <summary>
    /// Flat CSV for handing to a SIEM or a spreadsheet.
    /// </summary>
    /// <remarks>
    /// Columns are read from <see cref="AggregatedIndicator"/>'s JSON names
    /// rather than written out twice. The Python version kept a hardcoded tuple
    /// for the header and another for the values, so adding a field to one and
    /// not the other silently produced a CSV with a missing or misaligned
    /// column.
    /// </remarks>
    public string ToCsv()
    {
        var properties = typeof(AggregatedIndicator)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => (
                Name: p.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name ?? p.Name,
                Property: p))
            .ToList();

        var builder = new StringBuilder();
        builder.AppendLine(string.Join(",", properties.Select(p => p.Name)));

        foreach (var item in Indicators)
        {
            builder.AppendLine(string.Join(",", properties.Select(p => Cell(p.Property.GetValue(item)))));
        }
        return builder.ToString();
    }

    private static string Cell(object? value)
    {
        var text = value switch
        {
            null => "",
            IEnumerable<string> list => string.Join(";", list),
            _ => value.ToString() ?? "",
        };
        return text.Contains(',') || text.Contains('"') || text.Contains('\n')
            ? '"' + text.Replace("\"", "\"\"") + '"'
            : text;
    }
}
