namespace SecuritySuite.Detection;

/// <summary>
/// The rule-matching engine, behind an interface.
/// </summary>
/// <remarks>
/// <para>
/// The shipping backend is <see cref="LibYaraBackend"/>, which binds Microsoft's
/// libyara.NET. That binding is C++/CLI, so it is Windows-only and the process
/// must be x64 or arm64; those constraints come from the binding, not from the
/// suite.
/// </para>
/// <para>
/// This interface exists so that stays true of one file. A P/Invoke backend for
/// Linux and macOS, or a backend that shells out to the <c>yara</c> binary, can
/// be added here without the monitor, the store, the HTTP layer or the
/// remediation rails knowing which one is loaded.
/// </para>
/// </remarks>
public interface IScanBackend : IDisposable
{
    /// <summary>Short name for the dashboard's engine panel, e.g. "libyara.NET 4.5.5".</summary>
    string Name { get; }

    /// <summary>True once a rule set is loaded and scanning is possible.</summary>
    bool HasRules { get; }

    /// <summary>
    /// Compile the given rule files, replacing anything already loaded.
    /// </summary>
    /// <remarks>
    /// Must not throw for a bad rule file: a broken rule is reported in
    /// <see cref="RuleLoad.Errors"/> and the remaining files still load. A
    /// detection tool that will not start because one rule has a typo is worse
    /// than one that starts and says which rule is broken.
    /// </remarks>
    RuleLoad Load(IReadOnlyList<string> ruleFiles);

    /// <summary>Scan a file on disk. Throws the usual IO exceptions if it cannot be read.</summary>
    IReadOnlyList<BackendMatch> ScanFile(string path);

    /// <summary>Scan an in-memory buffer.</summary>
    IReadOnlyList<BackendMatch> ScanBytes(byte[] data);
}

/// <summary>The outcome of compiling a rule directory.</summary>
public sealed class RuleLoad
{
    /// <summary>Every rule that compiled, with its metadata.</summary>
    public List<RuleInfo> Rules { get; init; } = [];

    /// <summary>Files that failed, each with the compiler's message.</summary>
    public List<RuleError> Errors { get; init; } = [];

    /// <summary>
    /// True when no rule file could be loaded and the built-in rule is standing
    /// in, so the dashboard can say the engine is not really armed.
    /// </summary>
    public bool UsingFallback { get; init; }
}

/// <summary>One rule in the loaded set.</summary>
public sealed class RuleInfo
{
    public string Rule { get; init; } = "";

    /// <summary>The rule file this came from, used where YARA namespaces were.</summary>
    public string Namespace { get; init; } = "";

    public List<string> Tags { get; init; } = [];
    public Dictionary<string, string> Meta { get; init; } = [];
}

public sealed record RuleError(string File, string Error);

/// <summary>A rule that fired, as the backend reports it.</summary>
public sealed class BackendMatch
{
    public string Rule { get; init; } = "";
    public string Namespace { get; init; } = "";
    public List<string> Tags { get; init; } = [];
    public Dictionary<string, string> Meta { get; init; } = [];

    /// <summary>Identifier to the offsets and bytes that matched it.</summary>
    public List<BackendString> Strings { get; init; } = [];
}

public sealed record BackendString(string Identifier, long Offset, byte[] Data, int TotalInstances);
