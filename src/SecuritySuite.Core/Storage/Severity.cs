namespace SecuritySuite.Storage;

/// <summary>
/// The five severities, ordered worst first, and the ranking used by every
/// threshold comparison in the suite.
/// </summary>
/// <remarks>
/// Rank 0 is the worst. A threshold test is therefore
/// <c>Rank(finding) &lt;= Rank(threshold)</c>, which reads backwards the first
/// time and is the reason it lives in one place rather than being spelled out
/// at each call site.
/// </remarks>
public static class Severity
{
    public const string Critical = "critical";
    public const string High = "high";
    public const string Medium = "medium";
    public const string Low = "low";
    public const string Info = "info";

    /// <summary>Worst first. The dashboard renders severity breakdowns in this order.</summary>
    public static readonly string[] All = [Critical, High, Medium, Low, Info];

    private static readonly Dictionary<string, int> Ranks =
        All.Select((name, index) => (name, index))
           .ToDictionary(x => x.name, x => x.index, StringComparer.OrdinalIgnoreCase);

    /// <summary>Unknown severities sort last so they never clear a threshold.</summary>
    public const int Unranked = 99;

    public static int Rank(string? severity) =>
        severity is not null && Ranks.TryGetValue(severity, out var rank) ? rank : Unranked;

    public static bool IsKnown(string? severity) =>
        severity is not null && Ranks.ContainsKey(severity);

    /// <summary>True when <paramref name="severity"/> is as bad as, or worse than, the threshold.</summary>
    public static bool MeetsThreshold(string? severity, string? threshold) =>
        IsKnown(threshold) && Rank(severity) <= Rank(threshold);

    /// <summary>Normalise to a known severity, defaulting to <see cref="Info"/>.</summary>
    public static string Normalise(string? severity) =>
        IsKnown(severity) ? severity!.ToLowerInvariant() : Info;
}
