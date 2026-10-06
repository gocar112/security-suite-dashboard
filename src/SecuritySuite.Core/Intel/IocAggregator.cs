using SecuritySuite.Storage;

namespace SecuritySuite.Intel;

/// <summary>
/// Rolls per-file indicators up across many findings for the dashboard panel.
/// </summary>
public static class IocAggregator
{
    /// <summary>Files and finding ids kept per indicator, to bound the payload.</summary>
    private const int MaxReferences = 8;

    /// <summary>
    /// Aggregate indicators across findings.
    /// </summary>
    /// <remarks>
    /// Sorted by how many distinct files an indicator appears in, before raw
    /// occurrence count. One domain in six unrelated samples is a campaign; the
    /// same domain two hundred times in one file is a loop.
    /// </remarks>
    public static IocAggregate Summarise(IEnumerable<SuiteEvent> events)
    {
        var aggregate = new Dictionary<(string Type, string Value), AggregatedIndicator>();
        var order = new List<(string Type, string Value)>();

        foreach (var item in events)
        {
            var block = item.GetExtra<IocSummary>("iocs");
            if (block?.Indicators is null) continue;

            foreach (var indicator in block.Indicators)
            {
                var key = (indicator.Type, indicator.Value.ToLowerInvariant());
                if (!aggregate.TryGetValue(key, out var record))
                {
                    record = new AggregatedIndicator
                    {
                        Type = indicator.Type,
                        Value = indicator.Value,
                        Defanged = indicator.Defanged,
                        Scope = indicator.Scope,
                        FirstSeen = item.Timestamp,
                        LastSeen = item.Timestamp,
                    };
                    if (indicator.Type == IocKind.Cve)
                    {
                        // A CVE is an identifier, not a hostile value: show it
                        // plainly and link it to the authority.
                        var cve = indicator.Value.ToUpperInvariant();
                        record.Value = cve;
                        record.Defanged = cve;
                        record.NvdUrl = "https://nvd.nist.gov/vuln/detail/" + cve;
                    }
                    aggregate[key] = record;
                    order.Add(key);
                }

                record.Occurrences += Math.Max(1, indicator.Count);

                var name = !string.IsNullOrEmpty(item.FileName) ? item.FileName : item.FilePath;
                if (!string.IsNullOrEmpty(name) && !record.Files.Contains(name)) record.Files.Add(name);
                if (!string.IsNullOrEmpty(item.Id) && !record.FindingIds.Contains(item.Id)) record.FindingIds.Add(item.Id);

                var stamp = item.Timestamp;
                if (!string.IsNullOrEmpty(stamp))
                {
                    if (string.IsNullOrEmpty(record.FirstSeen) ||
                        string.CompareOrdinal(stamp, record.FirstSeen) < 0) record.FirstSeen = stamp;
                    if (string.IsNullOrEmpty(record.LastSeen) ||
                        string.CompareOrdinal(stamp, record.LastSeen) > 0) record.LastSeen = stamp;
                }
            }
        }

        var items = order.Select(k => aggregate[k]).ToList();
        foreach (var item in items)
        {
            // Count before truncating, or the panel reports the cap instead of
            // the spread.
            item.FileCount = item.Files.Count;
            if (item.Files.Count > MaxReferences) item.Files = item.Files.Take(MaxReferences).ToList();
            if (item.FindingIds.Count > MaxReferences) item.FindingIds = item.FindingIds.Take(MaxReferences).ToList();
        }

        items = items
            .OrderByDescending(i => i.FileCount)
            .ThenByDescending(i => i.Occurrences)
            .ThenBy(i => IocKind.Rank(i.Type))
            .ThenBy(i => i.Value, StringComparer.Ordinal)
            .ToList();

        var byType = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var item in items) byType[item.Type] = byType.GetValueOrDefault(item.Type) + 1;

        return new IocAggregate { Indicators = items, ByType = byType, Total = items.Count };
    }
}
