using System.Text.Json.Serialization;
using SecuritySuite.Intel;
using SecuritySuite.Storage;

namespace SecuritySuite.Casework;

/// <summary>
/// Link analysis: findings, the indicators inside them, and the rules that fired.
/// </summary>
/// <remarks>
/// <para>
/// Detections arrive as a flat list ordered by time, which is the one view that
/// hides the thing an analyst most wants to see: that six of them are the same
/// intrusion. Two files dropped an hour apart are unrelated rows in a table, and
/// obviously related the moment you notice they beacon to the same host.
/// </para>
/// <para>
/// The edges are already in the data. Each indicator knows which findings it
/// appeared in; nothing walked that relation. This turns it into a graph and
/// groups it into campaigns — connected components over shared indicators — so a
/// set of findings linked by a common C2 address becomes one object with its own
/// severity, span and story.
/// </para>
/// <para>
/// <b>Indicators are aggregated here, not taken from
/// <see cref="IocAggregator"/>.</b> That truncates each indicator's finding list
/// to eight for display, so reusing it would silently cap every campaign at
/// eight members.
/// </para>
/// </remarks>
public static class LinkGraph
{
    /// <summary>
    /// Indicator types that mean "these two files are the same operation".
    /// </summary>
    /// <remarks>
    /// A shared SHA-256 or C2 host is evidence. A shared file path or CVE id
    /// usually is not — half a corpus mentions CVE-2021-44228 — so those stay in
    /// the graph as nodes but never merge two findings into one campaign on
    /// their own.
    /// </remarks>
    public static readonly HashSet<string> LinkingTypes = new(StringComparer.Ordinal)
    {
        IocKind.Url, IocKind.Domain, IocKind.Ipv4, IocKind.Onion,
        IocKind.Btc, IocKind.Xmr, IocKind.Eth, IocKind.Email,
        IocKind.Sha256, IocKind.Md5,
    };

    public const int DefaultMaxNodes = 600;

    public static GraphResult Build(IEnumerable<SuiteEvent> events,
                                    int maxNodes = DefaultMaxNodes,
                                    bool linkingOnly = false)
    {
        var nodes = new Dictionary<string, GraphNode>(StringComparer.Ordinal);
        var edges = new List<GraphEdge>();

        // Indicator key to the findings it appeared in, built here rather than
        // taken from the aggregator, which truncates for display.
        var indicatorFindings = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var indicatorMeta = new Dictionary<string, Indicator>(StringComparer.Ordinal);

        var findings = events.Where(e => e.IsMatch).ToList();

        foreach (var finding in findings)
        {
            var findingNode = "f:" + finding.Id;
            nodes[findingNode] = new GraphNode
            {
                Id = findingNode,
                Type = "finding",
                Label = !string.IsNullOrEmpty(finding.FileName)
                    ? finding.FileName
                    : BaseName(finding.FilePath),
                Severity = Severity.Normalise(finding.Severity),
                Status = finding.Status.Length > 0 ? finding.Status : "new",
                Timestamp = finding.Timestamp,
                FindingId = finding.Id,
                Path = finding.FilePath,
            };

            foreach (var match in finding.Matches ?? [])
            {
                if (match.Rule.Length == 0) continue;

                var ruleNode = "r:" + match.Rule;
                if (!nodes.TryGetValue(ruleNode, out var node))
                {
                    nodes[ruleNode] = node = new GraphNode
                    {
                        Id = ruleNode,
                        Type = "rule",
                        Label = match.Rule,
                        Severity = Severity.Normalise(match.Severity),
                        Namespace = match.Namespace,
                        Attack = [.. AttackMapping.Resolve(match).Select(t => t.Id)],
                    };
                }
                node.Count++;
                edges.Add(new GraphEdge(findingNode, ruleNode, "matched"));
            }

            var iocs = finding.GetExtra<IocSummary>("iocs");
            foreach (var indicator in iocs?.Indicators ?? [])
            {
                if (indicator.Type.Length == 0 || indicator.Value.Length == 0) continue;
                if (linkingOnly && !LinkingTypes.Contains(indicator.Type)) continue;

                var key = indicator.Type + ":" + indicator.Value.ToLowerInvariant();
                if (!indicatorFindings.TryGetValue(key, out var set))
                    indicatorFindings[key] = set = new HashSet<string>(StringComparer.Ordinal);
                set.Add(finding.Id);
                indicatorMeta.TryAdd(key, indicator);
            }
        }

        // A singleton indicator is kept: it is still a pivot the analyst may
        // want. Only shared ones merge findings below.
        foreach (var (key, findingIds) in indicatorFindings)
        {
            var meta = indicatorMeta[key];
            var indicatorNode = "i:" + key;

            nodes[indicatorNode] = new GraphNode
            {
                Id = indicatorNode,
                Type = "indicator",
                Label = meta.Defanged.Length > 0 ? meta.Defanged : meta.Value,
                IndicatorType = meta.Type,
                Scope = meta.Scope,
                Shared = findingIds.Count,
            };

            foreach (var findingId in findingIds)
                edges.Add(new GraphEdge("f:" + findingId, indicatorNode, "observed"));
        }

        var campaigns = Campaigns(findings, indicatorFindings, indicatorMeta);

        // Bound the payload: keep the most connected nodes, then drop edges
        // whose endpoints did not survive, so the client never renders a
        // dangling edge.
        var truncated = false;
        if (nodes.Count > maxNodes)
        {
            truncated = true;

            var degree = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var edge in edges)
            {
                degree[edge.Source] = degree.GetValueOrDefault(edge.Source) + 1;
                degree[edge.Target] = degree.GetValueOrDefault(edge.Target) + 1;
            }

            var keep = nodes.Keys
                .OrderByDescending(n => degree.GetValueOrDefault(n))
                .Take(maxNodes)
                .ToHashSet(StringComparer.Ordinal);

            nodes = nodes.Where(kv => keep.Contains(kv.Key))
                         .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            edges = [.. edges.Where(e => keep.Contains(e.Source) && keep.Contains(e.Target))];
        }

        return new GraphResult
        {
            Nodes = [.. nodes.Values],
            Edges = edges,
            Campaigns = campaigns,
            Truncated = truncated,
            Counts = new GraphCounts
            {
                Findings = nodes.Values.Count(n => n.Type == "finding"),
                Indicators = nodes.Values.Count(n => n.Type == "indicator"),
                Rules = nodes.Values.Count(n => n.Type == "rule"),
                Edges = edges.Count,
            },
        };
    }

    /// <summary>
    /// Group findings into clusters joined by shared linking indicators.
    /// </summary>
    /// <remarks>
    /// Union-find over the finding ids each shared indicator touches. Only
    /// <see cref="LinkingTypes"/> merge, so a shared C2 host means "same
    /// operation" while a shared mention of a CVE does not.
    /// </remarks>
    private static List<Campaign> Campaigns(List<SuiteEvent> findings,
                                            Dictionary<string, HashSet<string>> indicatorFindings,
                                            Dictionary<string, Indicator> indicatorMeta)
    {
        var parent = new Dictionary<string, string>(StringComparer.Ordinal);

        string Find(string x)
        {
            parent.TryAdd(x, x);
            while (parent[x] != x)
            {
                parent[x] = parent[parent[x]];   // path halving
                x = parent[x];
            }
            return x;
        }

        void Union(string a, string b)
        {
            var (rootA, rootB) = (Find(a), Find(b));
            if (rootA != rootB) parent[rootA] = rootB;
        }

        var byId = findings.ToDictionary(f => f.Id, f => f, StringComparer.Ordinal);
        foreach (var id in byId.Keys) Find(id);

        foreach (var (key, findingIds) in indicatorFindings)
        {
            if (!LinkingTypes.Contains(indicatorMeta[key].Type) || findingIds.Count < 2) continue;

            var members = findingIds.Where(byId.ContainsKey).ToList();
            foreach (var other in members.Skip(1)) Union(members[0], other);
        }

        var groups = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var id in byId.Keys)
        {
            var root = Find(id);
            if (!groups.TryGetValue(root, out var members))
                groups[root] = members = [];
            members.Add(id);
        }

        // Which indicators tie each group together, for the "why" line.
        var sharedByRoot = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        foreach (var (key, findingIds) in indicatorFindings)
        {
            if (!LinkingTypes.Contains(indicatorMeta[key].Type) || findingIds.Count < 2) continue;

            var members = findingIds.Where(byId.ContainsKey).ToList();
            if (members.Count == 0) continue;

            var root = Find(members[0]);
            if (!sharedByRoot.TryGetValue(root, out var set))
                sharedByRoot[root] = set = new SortedSet<string>(StringComparer.Ordinal);
            set.Add(key);
        }

        var campaigns = new List<Campaign>();
        foreach (var (root, members) in groups)
        {
            // A lone finding is not a campaign.
            if (members.Count < 2) continue;

            var events = members.Select(m => byId[m]).ToList();
            var stamps = events.Select(e => e.Timestamp ?? "").OrderBy(s => s, StringComparer.Ordinal).ToList();
            var links = sharedByRoot.GetValueOrDefault(root) ?? [];

            campaigns.Add(new Campaign
            {
                Id = "c:" + root,
                Size = members.Count,
                FindingIds = members,
                Severity = Worst(events.Select(e => e.Severity)),
                FirstSeen = stamps.Count > 0 ? stamps[0] : "",
                LastSeen = stamps.Count > 0 ? stamps[^1] : "",
                Files = [.. events.Select(e => BaseName(e.FilePath)).Distinct(StringComparer.Ordinal)
                                  .Order(StringComparer.Ordinal).Take(8)],
                Rules = [.. events.SelectMany(e => e.Matches ?? []).Select(m => m.Rule)
                                  .Where(r => r.Length > 0).Distinct(StringComparer.Ordinal)
                                  .Order(StringComparer.Ordinal).Take(8)],
                Attack = [.. events.SelectMany(e => e.Matches ?? [])
                                   .SelectMany(AttackMapping.Resolve).Select(t => t.Id)
                                   .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)],
                LinkedBy = [.. links.Take(8).Select(k => new CampaignLink(
                    indicatorMeta[k].Type,
                    indicatorMeta[k].Defanged.Length > 0 ? indicatorMeta[k].Defanged : indicatorMeta[k].Value))],
            });
        }

        return [.. campaigns
            .OrderBy(c => Severity.Rank(c.Severity))
            .ThenByDescending(c => c.Size)];
    }

    private static string Worst(IEnumerable<string?> severities)
    {
        var ranked = severities.Select(Severity.Normalise)
                               .OrderBy(Severity.Rank)
                               .FirstOrDefault();
        return ranked ?? Severity.Info;
    }

    internal static string BaseName(string? path)
    {
        var text = path ?? "";
        var cut = text.LastIndexOfAny(['\\', '/']);
        if (cut >= 0) text = text[(cut + 1)..];
        return text.Length > 0 ? text : "(unnamed)";
    }
}

public sealed class GraphNode
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";

    /// <summary>finding, rule or indicator.</summary>
    [JsonPropertyName("type")] public string Type { get; init; } = "";

    [JsonPropertyName("label")] public string Label { get; init; } = "";

    [JsonPropertyName("severity")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Severity { get; init; }

    [JsonPropertyName("status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Status { get; init; }

    [JsonPropertyName("timestamp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Timestamp { get; init; }

    [JsonPropertyName("finding_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FindingId { get; init; }

    [JsonPropertyName("path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Path { get; init; }

    [JsonPropertyName("namespace")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Namespace { get; init; }

    [JsonPropertyName("attack")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Attack { get; init; }

    /// <summary>How many findings a rule node fired on.</summary>
    [JsonPropertyName("count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int Count { get; set; }

    [JsonPropertyName("indicator_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IndicatorType { get; init; }

    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; init; }

    /// <summary>How many findings an indicator node appears in.</summary>
    [JsonPropertyName("shared")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int Shared { get; init; }
}

public sealed record GraphEdge(
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("target")] string Target,
    [property: JsonPropertyName("kind")] string Kind);

public sealed record CampaignLink(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("value")] string Value);

/// <summary>Findings joined by at least one shared linking indicator.</summary>
public sealed class Campaign
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("size")] public int Size { get; init; }
    [JsonPropertyName("finding_ids")] public List<string> FindingIds { get; init; } = [];
    [JsonPropertyName("severity")] public string Severity { get; init; } = "";
    [JsonPropertyName("first_seen")] public string FirstSeen { get; init; } = "";
    [JsonPropertyName("last_seen")] public string LastSeen { get; init; } = "";
    [JsonPropertyName("files")] public List<string> Files { get; init; } = [];
    [JsonPropertyName("rules")] public List<string> Rules { get; init; } = [];
    [JsonPropertyName("attack")] public List<string> Attack { get; init; } = [];

    /// <summary>The indicators that tied these findings together.</summary>
    [JsonPropertyName("linked_by")] public List<CampaignLink> LinkedBy { get; init; } = [];
}

public sealed class GraphCounts
{
    [JsonPropertyName("findings")] public int Findings { get; init; }
    [JsonPropertyName("indicators")] public int Indicators { get; init; }
    [JsonPropertyName("rules")] public int Rules { get; init; }
    [JsonPropertyName("edges")] public int Edges { get; init; }
}

public sealed class GraphResult
{
    [JsonPropertyName("nodes")] public List<GraphNode> Nodes { get; init; } = [];
    [JsonPropertyName("edges")] public List<GraphEdge> Edges { get; init; } = [];
    [JsonPropertyName("campaigns")] public List<Campaign> Campaigns { get; init; } = [];

    /// <summary>True when the node cap dropped the least-connected nodes.</summary>
    [JsonPropertyName("truncated")] public bool Truncated { get; init; }

    [JsonPropertyName("counts")] public GraphCounts Counts { get; init; } = new();
}
