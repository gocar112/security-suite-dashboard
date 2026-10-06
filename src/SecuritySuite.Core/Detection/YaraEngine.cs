using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text.Json.Serialization;
using SecuritySuite.Intel;
using SecuritySuite.Storage;

namespace SecuritySuite.Detection;

/// <summary>
/// Holds the compiled rule set and turns a backend match into a finding.
/// Safe to share across threads.
/// </summary>
/// <remarks>
/// Severity comes from a rule's own metadata, so whoever writes a rule decides
/// its triage priority. Tags are the fallback, and only when neither says
/// anything does a match default to medium.
/// </remarks>
public sealed class YaraEngine : IDisposable
{
    /// <summary>Bytes of a matched string kept for the preview column.</summary>
    private const int PreviewBytes = 48;

    /// <summary>Entropy and previews are computed from the first MiB, not the whole file.</summary>
    private const int SampleBytes = 1 << 20;

    /// <summary>
    /// Severity for a rule that declares none, inferred from its tags.
    /// </summary>
    private static readonly Dictionary<string, string> SeverityByTag = new(StringComparer.OrdinalIgnoreCase)
    {
        ["critical"] = Severity.Critical,
        ["ransomware"] = Severity.Critical,
        ["malware"] = Severity.High,
        ["webshell"] = Severity.High,
        ["exploit"] = Severity.High,
        ["suspicious"] = Severity.Medium,
        ["pua"] = Severity.Low,
        ["test"] = Severity.Info,
    };

    private readonly Lock _gate = new();
    private readonly IScanBackend _backend;
    private readonly IocExtractor _iocs = new();

    public string RulesDir { get; }
    public long MaxFileBytes { get; }

    private List<RuleInfo> _index = [];
    private List<RuleError> _errors = [];
    private bool _usingFallback;
    private string? _loadedAt;
    private double _compileMs;

    public YaraEngine(string rulesDir, long maxFileBytes = 64L * 1024 * 1024,
                      IScanBackend? backend = null)
    {
        RulesDir = rulesDir;
        MaxFileBytes = maxFileBytes;
        _backend = backend ?? new LibYaraBackend();
        Reload();
    }

    // ------------------------------------------------------------------ rules
    /// <summary>
    /// Every rule file under the rules directory, recursively.
    /// </summary>
    /// <remarks>
    /// Recursive on purpose: the generated NVD rules live in a
    /// <c>generated/</c> subdirectory, and a non-recursive search finds 73 of
    /// the suite's 1,004 rules while looking like it worked.
    /// </remarks>
    public List<string> RuleFiles()
    {
        if (!Directory.Exists(RulesDir)) return [];
        try
        {
            return Directory
                .EnumerateFiles(RulesDir, "*.*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>Recompile the rule directory. Bad files are reported, not swallowed.</summary>
    public EngineInfo Reload()
    {
        var watch = Stopwatch.StartNew();
        var load = _backend.Load(RuleFiles());
        watch.Stop();

        lock (_gate)
        {
            _index = load.Rules;
            _errors = load.Errors;
            _usingFallback = load.UsingFallback;
            _loadedAt = EventStore.NowIso();
            _compileMs = Math.Round(watch.Elapsed.TotalMilliseconds, 1);
        }
        return Info();
    }

    public EngineInfo Info()
    {
        lock (_gate)
        {
            return new EngineInfo
            {
                Backend = _backend.Name,
                RulesDir = RulesDir,
                RuleCount = _index.Count,
                RuleFiles = _index.Select(r => r.Namespace).Distinct(StringComparer.Ordinal)
                                  .OrderBy(n => n, StringComparer.Ordinal).ToList(),
                Rules = _index,
                LoadErrors = _errors,
                UsingFallback = _usingFallback,
                LoadedAt = _loadedAt,
                CompileMs = _compileMs,
            };
        }
    }

    // ------------------------------------------------------------------ scans
    /// <summary>A rule's declared severity, its tags' implication, or medium.</summary>
    public static string SeverityOf(IDictionary<string, string> meta, IEnumerable<string> tags)
    {
        if (meta.TryGetValue("severity", out var declared))
        {
            var normalised = (declared ?? "").Trim().ToLowerInvariant();
            if (Severity.IsKnown(normalised)) return normalised;
        }
        foreach (var tag in tags)
        {
            if (SeverityByTag.TryGetValue(tag, out var mapped)) return mapped;
        }
        return Severity.Medium;
    }

    public ScanOutcome ScanBytes(byte[] data, string label = "<buffer>")
    {
        var watch = Stopwatch.StartNew();
        var hits = _backend.ScanBytes(data);
        return BuildResult(label, data, hits, watch, data.Length);
    }

    /// <summary>
    /// Scan one file. Returns an outcome even when nothing matches.
    /// </summary>
    /// <remarks>
    /// IO exceptions propagate. The caller distinguishes "this file is gone or
    /// locked", which is normal on a live endpoint where antivirus may have
    /// quarantined it mid-sweep, from "the scan failed", which is not.
    /// </remarks>
    public ScanOutcome ScanFile(string path)
    {
        var info = new FileInfo(path);
        var size = info.Length;

        if (size > MaxFileBytes)
        {
            return new ScanOutcome
            {
                FilePath = path,
                FileName = Path.GetFileName(path),
                FileSize = size,
                Skipped = "file larger than max_file_mb",
            };
        }

        var watch = Stopwatch.StartNew();
        var sample = ReadSample(path);
        var hits = _backend.ScanFile(path);

        var result = BuildResult(path, sample, hits, watch, size);
        result.FileName = Path.GetFileName(path);
        result.Sha256 = Sha256Of(path);
        result.Modified = info.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss");
        return result;
    }

    private static byte[] ReadSample(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var length = (int)Math.Min(SampleBytes, stream.Length);
        var buffer = new byte[length];
        var read = stream.ReadAtLeast(buffer, length, throwOnEndOfStream: false);
        return read == length ? buffer : buffer[..read];
    }

    private ScanOutcome BuildResult(string label, byte[] sample,
                                    IReadOnlyList<BackendMatch> hits,
                                    Stopwatch watch, long size)
    {
        var matches = new List<RuleMatch>(hits.Count);
        foreach (var hit in hits)
        {
            matches.Add(new RuleMatch
            {
                Rule = hit.Rule,
                Namespace = hit.Namespace,
                Tags = hit.Tags,
                Meta = hit.Meta,
                Severity = SeverityOf(hit.Meta, hit.Tags),
                Strings = hit.Strings.Select(s => new MatchedString
                {
                    Identifier = s.Identifier,
                    Offset = s.Offset,
                    Preview = Printable(s.Data),
                    Count = s.TotalInstances,
                }).ToList(),
            });
        }

        string? severity = null;
        IocSummary iocs = IocSummary.Empty;

        if (matches.Count > 0)
        {
            // The worst severity among the rules that fired drives the finding.
            severity = matches.MinBy(m => Severity.Rank(m.Severity))!.Severity;

            // Only extract for a file that tripped a rule. A clean scan needs no
            // observables, and running every pattern over every file would
            // dominate the scan budget on a busy watch path.
            // A timeout here is a slow pattern on a hostile buffer, not a
            // reason to lose the detection that already fired.
            try { iocs = _iocs.Extract(sample); }
            catch (RegexMatchTimeoutException)
            {
                iocs = IocSummary.Failed("extraction timed out");
            }
        }

        watch.Stop();
        return new ScanOutcome
        {
            FilePath = label,
            FileSize = size,
            Entropy = ShannonEntropy(sample),
            ScanMs = Math.Round(watch.Elapsed.TotalMilliseconds, 2),
            Matches = matches,
            Severity = severity,
            Iocs = iocs,
        };
    }

    // ------------------------------------------------------------- primitives
    public static string Sha256Of(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sha = SHA256.Create();
        return System.Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    /// <summary>
    /// Bits per byte. Above roughly 7.2 usually means packed, encrypted or
    /// compressed.
    /// </summary>
    public static double ShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;

        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;

        var total = (double)data.Length;
        var entropy = 0.0;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var p = count / total;
            entropy -= p * Math.Log2(p);
        }
        return Math.Round(entropy, 3);
    }

    /// <summary>Printable-ASCII preview of a matched string, dots for the rest.</summary>
    public static string Printable(ReadOnlySpan<byte> raw)
    {
        var length = Math.Min(raw.Length, PreviewBytes);
        var buffer = new char[length];
        for (var i = 0; i < length; i++)
        {
            var b = raw[i];
            buffer[i] = b is >= 32 and < 127 ? (char)b : '.';
        }
        return new string(buffer);
    }

    public void Dispose() => _backend.Dispose();
}

/// <summary>What the engine reports about its loaded rule set.</summary>
public sealed class EngineInfo
{
    [JsonPropertyName("backend")] public string Backend { get; init; } = "";
    [JsonPropertyName("rules_dir")] public string RulesDir { get; init; } = "";
    [JsonPropertyName("rule_count")] public int RuleCount { get; init; }
    [JsonPropertyName("rule_files")] public List<string> RuleFiles { get; init; } = [];
    [JsonPropertyName("rules")] public List<RuleInfo> Rules { get; init; } = [];
    [JsonPropertyName("load_errors")] public List<RuleError> LoadErrors { get; init; } = [];
    [JsonPropertyName("using_fallback")] public bool UsingFallback { get; init; }
    [JsonPropertyName("loaded_at")] public string? LoadedAt { get; init; }
    [JsonPropertyName("compile_ms")] public double CompileMs { get; init; }
}

/// <summary>One scan's result, before it becomes a stored event.</summary>
public sealed class ScanOutcome
{
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("file_name")] public string? FileName { get; set; }
    [JsonPropertyName("file_size")] public long FileSize { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("modified")] public string? Modified { get; set; }
    [JsonPropertyName("entropy")] public double Entropy { get; set; }
    [JsonPropertyName("scan_ms")] public double ScanMs { get; set; }
    [JsonPropertyName("skipped")] public string? Skipped { get; set; }
    [JsonPropertyName("matches")] public List<RuleMatch> Matches { get; set; } = [];
    [JsonPropertyName("severity")] public string? Severity { get; set; }
    [JsonPropertyName("iocs")] public IocSummary Iocs { get; set; } = IocSummary.Empty;

    [JsonIgnore] public bool Hit => Matches.Count > 0;
}
