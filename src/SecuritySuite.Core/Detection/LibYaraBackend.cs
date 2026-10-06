using libyaraNET;

namespace SecuritySuite.Detection;

/// <summary>
/// The YARA backend, binding Microsoft's libyara.NET.
/// </summary>
/// <remarks>
/// <para>
/// Three properties of the binding shape this class:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="YaraContext"/> wraps <c>yr_initialize</c>/<c>yr_finalize</c> and
/// must bracket every other call, so exactly one is created here and held for
/// the life of the backend. Creating one per scan would re-initialise the
/// library underneath live <see cref="Rules"/> handles.
/// </description></item>
/// <item><description>
/// <see cref="Compiler"/> is documented as not thread safe, so compilation is
/// serialised. Scanning a shared <see cref="Rules"/> is safe in libyara, so
/// scans run in parallel against one compiled set with a fresh
/// <see cref="Scanner"/> each time.
/// </description></item>
/// <item><description>
/// There is no namespace parameter. yara-python took
/// <c>compile(sources={namespace: text})</c> and reported the namespace on each
/// match, which is how findings were attributed to a rule file. Here each file
/// is compiled on its own first (which the Python build also did, to get a
/// precise error per file) and the rule names it declares are recorded, giving
/// the same attribution from the compile step rather than from the match.
/// </description></item>
/// </list>
/// <para>
/// <b>No scan timeout.</b> yara-python accepted <c>timeout=</c> and libyara
/// supports it natively, but libyara.NET exposes only
/// <see cref="ScanFlags"/>.<c>None</c> and <c>Fast</c>, so a scan cannot be
/// bounded by time here. Exposure is bounded by size instead, through
/// <c>max_file_mb</c>, which the engine enforces before calling in. A rule
/// written to backtrack pathologically on a file under that limit would block
/// the calling thread; the monitor runs on its own thread, so that degrades
/// throughput rather than stopping the server.
/// </para>
/// </remarks>
public sealed class LibYaraBackend : IScanBackend
{
    /// <summary>Stands in when no rule file could be loaded, so the engine is never ruleless.</summary>
    internal const string FallbackRule = """
        rule SecuritySuite_Fallback_TestRule
        {
            meta:
                description = "Fallback rule used when no rule files are present"
                severity = "info"
                author = "security-suite"
            strings:
                $a = "malware" nocase
            condition:
                $a
        }
        """;

    private readonly Lock _compileGate = new();
    private readonly YaraContext _context;
    private Rules? _rules;
    private bool _disposed;

    public LibYaraBackend()
    {
        // Throws if the native libyara cannot be loaded at all, which is a real
        // startup failure and should not be swallowed: without it there is no
        // detection, and a scanner that silently stops detecting is the worst
        // possible outcome.
        _context = new YaraContext();
    }

    public string Name => "libyara.NET 4.5.5";

    public bool HasRules
    {
        get { lock (_compileGate) return _rules is not null; }
    }

    public RuleLoad Load(IReadOnlyList<string> ruleFiles)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var errors = new List<RuleError>();
        var infos = new List<RuleInfo>();
        var owners = new Dictionary<string, string>(StringComparer.Ordinal);
        var good = new List<string>();

        // Pass one: compile each file alone. This yields a precise error for the
        // offending file instead of one message for the whole directory, and it
        // is where the rule-name to file mapping comes from.
        foreach (var file in ruleFiles)
        {
            try
            {
                using var probe = new Compiler();
                probe.AddRuleFile(file);
                using var compiled = probe.GetRules();

                var name = Path.GetFileNameWithoutExtension(file);
                foreach (var rule in compiled.GetRules())
                {
                    owners[rule.Identifier] = name;
                    infos.Add(Describe(rule, name));
                }
                good.Add(file);
            }
            catch (CompilationException exc)
            {
                errors.Add(new RuleError(file, Flatten(exc)));
            }
            // libyara.NET also raises its own file_error, but that type is not
            // public, so it is caught by the YaraException/IOException arms or
            // not at all. Catching Exception here would hide a genuine bug in
            // this method behind a "bad rule file" message.
            catch (Exception exc) when (exc is YaraException or IOException
                                            or UnauthorizedAccessException)
            {
                errors.Add(new RuleError(file, exc.Message));
            }
        }

        Rules? built = null;
        var usingFallback = false;

        if (good.Count > 0)
        {
            try
            {
                using var compiler = new Compiler();
                foreach (var file in good) compiler.AddRuleFile(file);
                built = compiler.GetRules();
            }
            catch (Exception exc) when (exc is CompilationException or YaraException)
            {
                // Each file compiled alone, so this means the files conflict with
                // each other, most often a rule name declared in two of them.
                errors.Add(new RuleError("<combined>",
                    exc is CompilationException ce ? Flatten(ce) : exc.Message));
                built = null;
            }
        }

        if (built is null)
        {
            try
            {
                using var compiler = new Compiler();
                compiler.AddRuleString(FallbackRule);
                built = compiler.GetRules();
                usingFallback = true;
                infos.Clear();
                foreach (var rule in built.GetRules()) infos.Add(Describe(rule, "builtin"));
            }
            catch (Exception exc) when (exc is CompilationException or YaraException)
            {
                errors.Add(new RuleError("<fallback>", exc.Message));
            }
        }

        lock (_compileGate)
        {
            // Replace only once the new set is built, so a failed reload leaves
            // the previous rules armed rather than disarming the scanner. The
            // ownership map is swapped with the rules it describes: publishing
            // one without the other would attribute matches to the wrong file.
            if (built is not null)
            {
                _rules?.Dispose();
                _rules = built;
                _owners = owners;
            }
        }

        return new RuleLoad
        {
            Rules = infos.OrderBy(r => r.Namespace, StringComparer.Ordinal)
                         .ThenBy(r => r.Rule, StringComparer.Ordinal).ToList(),
            Errors = errors,
            UsingFallback = usingFallback,
        };
    }

    public IReadOnlyList<BackendMatch> ScanFile(string path)
    {
        var rules = Current();
        if (rules is null) return [];
        return Convert(new Scanner().ScanFile(path, rules));
    }

    public IReadOnlyList<BackendMatch> ScanBytes(byte[] data)
    {
        var rules = Current();
        if (rules is null || data.Length == 0) return [];
        return Convert(new Scanner().ScanMemory(data, rules));
    }

    private Rules? Current()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_compileGate) return _rules;
    }

    /// <summary>
    /// The rule file a rule came from, as recorded at compile time.
    /// </summary>
    /// <remarks>
    /// Rebuilt on every <see cref="Load"/>, and consulted by the engine rather
    /// than by matches directly, because <see cref="Rule"/> carries no
    /// provenance of its own.
    /// </remarks>
    private Dictionary<string, string> _owners = new(StringComparer.Ordinal);

    /// <summary>Rule name to rule file, for attributing a match to its source.</summary>
    public IReadOnlyDictionary<string, string> Owners
    {
        get { lock (_compileGate) return _owners; }
    }

    private static RuleInfo Describe(Rule rule, string owner) => new()
    {
        Rule = rule.Identifier,
        Namespace = owner,
        Tags = [.. rule.Tags],
        Meta = MetaOf(rule),
    };

    /// <summary>
    /// Flatten rule metadata to strings.
    /// </summary>
    /// <remarks>
    /// libyara.NET reports every meta value as a string, including the integer
    /// and boolean forms YARA allows. Callers that need a number parse it; the
    /// fields the suite reads (severity, description, cve, confidence) are
    /// strings in every rule file anyway.
    /// </remarks>
    private static Dictionary<string, string> MetaOf(Rule rule)
    {
        var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in rule.Metas)
        {
            if (string.IsNullOrEmpty(entry.Identifier)) continue;
            meta[entry.Identifier] = entry.Value ?? "";
        }
        return meta;
    }

    private List<BackendMatch> Convert(List<ScanResult> hits)
    {
        var owners = Owners;
        var results = new List<BackendMatch>(hits.Count);

        foreach (var hit in hits)
        {
            var rule = hit.MatchingRule;
            var strings = new List<BackendString>();

            foreach (var (identifier, instances) in hit.Matches)
            {
                // Cap per identifier: a rule hitting a string ten thousand times
                // says nothing more than one hitting it five times, and the whole
                // list is serialised into the findings log.
                foreach (var instance in instances.Take(5))
                {
                    strings.Add(new BackendString(
                        identifier,
                        (long)instance.Offset,
                        instance.Data ?? [],
                        instances.Count));
                }
            }

            results.Add(new BackendMatch
            {
                Rule = rule.Identifier,
                Namespace = owners.GetValueOrDefault(rule.Identifier, ""),
                Tags = [.. rule.Tags],
                Meta = MetaOf(rule),
                Strings = strings.Take(12).ToList(),
            });
        }
        return results;
    }

    private static string Flatten(CompilationException exc)
    {
        var parts = (exc.Errors ?? [])
            .Select(e => e?.ToString() ?? "")
            .Where(s => s.Length > 0)
            .Take(5)
            .ToList();
        return parts.Count > 0 ? string.Join(" | ", parts) : exc.Message;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        lock (_compileGate)
        {
            _rules?.Dispose();
            _rules = null;
        }
        _context.Dispose();
    }
}
