using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace SecuritySuite.Intel;

/// <summary>
/// Pulls observables out of files that tripped a rule.
/// </summary>
/// <remarks>
/// <para>
/// A YARA match says <em>this file is bad</em>. It does not say what to hunt
/// for next. The strings that matched are the detection's own evidence; the
/// indicators an analyst pivots on — the C2 address, the exfil domain, the
/// wallet a ransom note demands payment to — are usually in the same bytes,
/// unmatched and unreported. This turns a detection into a starting point
/// rather than a dead end.
/// </para>
/// <para>
/// <b>Everything is defanged on output.</b> See <see cref="Indicator.Defanged"/>.
/// </para>
/// <para>
/// <b>Noise is filtered visibly.</b> Benign hosts are counted in
/// <see cref="IocSummary.Dropped"/> rather than silently discarded, and
/// addresses are labelled by scope rather than removed, because a file talking
/// to an internal address is sometimes the finding.
/// </para>
/// </remarks>
public sealed partial class IocExtractor
{
    /// <summary>Distinct values kept per indicator type, per file.</summary>
    private const int MaxPerType = 40;

    /// <summary>Characters of surrounding text kept with each hit.</summary>
    private const int ContextChars = 34;

    private static readonly TimeSpan PatternTimeout = TimeSpan.FromSeconds(5);

    // ------------------------------------------------------------- patterns
    // Source-generated so the patterns are validated at build time and carry no
    // startup compilation cost. All are ASCII-only by design: see Extract for
    // why the input is decoded as Latin-1.
    [GeneratedRegex(@"\b(?:h(?:tt|xx)ps?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,240}",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex UrlPattern();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex Ipv4Pattern();

    [GeneratedRegex(@"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,18}\b",
        RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex EmailPattern();

    [GeneratedRegex(@"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex OnionPattern();

    [GeneratedRegex(@"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|top|xyz|io|co|me|cc|su|tk|pw|click|link|live|online|site|shop|store|app|dev|gg|to|ws|cyou|monster)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex DomainPattern();

    [GeneratedRegex(@"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b",
        RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex BtcPattern();

    [GeneratedRegex(@"\b0x[a-fA-F0-9]{40}\b", RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex EthPattern();

    [GeneratedRegex(@"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex XmrPattern();

    [GeneratedRegex(@"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[A-Za-z0-9\\_\-. ]{3,140}",
        RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex RegistryPattern();

    [GeneratedRegex(@"\b[A-Za-z]:\\\\?[A-Za-z0-9\\_\-. ()]{4,140}", RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex FilePathPattern();

    // Only directories an intrusion actually touches, so ordinary prose
    // mentioning /home, or a URL's path component, does not qualify.
    [GeneratedRegex(@"(?:/etc/|/tmp/|/var/tmp/|/dev/shm/|/usr/local/bin/|/root/|/home/)[A-Za-z0-9._\-/]{1,120}",
        RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex PosixPathPattern();

    [GeneratedRegex(@"\bCVE-\d{4}-\d{4,7}\b", RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex CvePattern();

    // A 64-hex run cannot also match the 32-hex pattern: there is no word
    // boundary in the middle of it, so the two never double-count.
    [GeneratedRegex(@"\b[a-fA-F0-9]{64}\b", RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex(@"\b[a-fA-F0-9]{32}\b", RegexOptions.ExplicitCapture, 5000)]
    private static partial Regex Md5Pattern();

    private static readonly (string Kind, Func<Regex> Pattern)[] Patterns =
    [
        (IocKind.Url, UrlPattern),
        (IocKind.Ipv4, Ipv4Pattern),
        (IocKind.Email, EmailPattern),
        (IocKind.Onion, OnionPattern),
        (IocKind.Domain, DomainPattern),
        (IocKind.Btc, BtcPattern),
        (IocKind.Eth, EthPattern),
        (IocKind.Xmr, XmrPattern),
        (IocKind.Registry, RegistryPattern),
        (IocKind.FilePath, FilePathPattern),
        (IocKind.PosixPath, PosixPathPattern),
        (IocKind.Cve, CvePattern),
        (IocKind.Sha256, Sha256Pattern),
        (IocKind.Md5, Md5Pattern),
    ];

    /// <summary>Hosts that appear in almost every document and mean nothing alone.</summary>
    private static readonly HashSet<string> DomainDenylist = new(StringComparer.OrdinalIgnoreCase)
    {
        "w3.org", "www.w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
        "example.com", "example.org", "example.net", "localhost", "microsoft.com",
        "purl.org", "adobe.com", "ns.adobe.com", "iptc.org", "openoffice.org",
        "sun.com", "xml.org", "apache.org", "python.org", "github.com",
        "githubusercontent.com", "googleapis.com", "gstatic.com", "jquery.com",
        "cloudflare.com", "cdnjs.cloudflare.com", "mozilla.org", "gnu.org",
        "nist.gov", "virustotal.com", "osv.dev", "cisa.gov", "mitre.org",
    };

    /// <summary>File extensions that are not domains, however much they look like one.</summary>
    private static readonly string[] NotDomainSuffix =
    [
        ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
        ".zip", ".rar", ".7z", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".png",
        ".jpg", ".gif", ".svg", ".css", ".html", ".htm", ".php", ".asp", ".aspx",
        ".py", ".sh", ".txt", ".log", ".json", ".xml", ".yar", ".md", ".ini",
    ];

    /// <summary>
    /// Extract observables from a byte buffer. Never raises on binary input.
    /// </summary>
    /// <remarks>
    /// The buffer is decoded as Latin-1, not UTF-8. Latin-1 maps every byte to
    /// exactly one char, so a match offset is still a byte offset and the ASCII
    /// patterns behave exactly as they did against raw bytes. Decoding as UTF-8
    /// would collapse each invalid multi-byte sequence into a single
    /// replacement char and shift every subsequent offset, which matters because
    /// these offsets are what an analyst uses to find the indicator in the file.
    /// </remarks>
    public IocSummary Extract(byte[] raw, bool wantContext = true)
    {
        if (raw.Length == 0) return IocSummary.Empty;

        var text = Encoding.Latin1.GetString(raw);
        var found = new Dictionary<(string Kind, string Value), Indicator>();
        var order = new List<(string Kind, string Value)>();
        var dropped = new Dictionary<string, int>(StringComparer.Ordinal);
        var scopes = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var (kind, pattern) in Patterns)
        {
            var distinct = 0;
            foreach (var match in pattern().EnumerateMatches(text))
            {
                if (distinct >= MaxPerType) break;

                var value = text.Substring(match.Index, match.Length).Trim();
                if (value.Length == 0) continue;
                var scope = "";

                switch (kind)
                {
                    case IocKind.Ipv4:
                        scope = ClassifyAddress(value);
                        if (scope.Length == 0) continue;   // not a valid address
                        scopes[scope] = scopes.GetValueOrDefault(scope) + 1;
                        break;

                    case IocKind.Domain:
                        if (!PlausibleDomain(value))
                        {
                            dropped["known_benign_domain"] = dropped.GetValueOrDefault("known_benign_domain") + 1;
                            continue;
                        }
                        break;

                    case IocKind.Url:
                        // The denylist must apply to the host inside a URL too,
                        // or every XML namespace declaration is an indicator.
                        var host = HostOf(value);
                        if (host.Length > 0 && !PlausibleDomain(host) &&
                            !host.EndsWith(".onion", StringComparison.OrdinalIgnoreCase))
                        {
                            dropped["known_benign_url"] = dropped.GetValueOrDefault("known_benign_url") + 1;
                            continue;
                        }
                        break;

                    case IocKind.Cve:
                        value = value.ToUpperInvariant();
                        break;
                }

                var key = (kind, value.ToLowerInvariant());
                if (found.TryGetValue(key, out var existing))
                {
                    existing.Count++;
                    continue;
                }

                var indicator = new Indicator
                {
                    Type = kind,
                    Value = value,
                    Defanged = Defang(value, kind),
                    Count = 1,
                    Offset = match.Index,
                    Scope = scope,
                };
                if (wantContext)
                {
                    var start = Math.Max(0, match.Index - ContextChars);
                    var end = Math.Min(text.Length, match.Index + match.Length + ContextChars);
                    indicator.Context = PrintableOnly(text.AsSpan(start, end - start));
                }

                found[key] = indicator;
                order.Add(key);
                distinct++;
            }
        }

        var indicators = order.Select(k => found[k])
            .OrderBy(i => IocKind.Rank(i.Type))
            .ThenByDescending(i => i.Count)
            .ToList();

        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var item in indicators) counts[item.Type] = counts.GetValueOrDefault(item.Type) + 1;

        return new IocSummary
        {
            Indicators = indicators,
            Counts = counts,
            Total = indicators.Count,
            Dropped = dropped,
            IpScopes = scopes,
        };
    }

    /// <summary>Render an indicator unclickable for display.</summary>
    /// <remarks>
    /// Every dot is bracketed rather than only the host's. It is unambiguous,
    /// it cannot be re-linked by a client that is cleverer than expected, and
    /// the exact original is always available in <see cref="Indicator.Value"/>.
    /// </remarks>
    public static string Defang(string value, string kind)
    {
        if (kind is not (IocKind.Url or IocKind.Domain or IocKind.Onion
                         or IocKind.Email or IocKind.Ipv4))
        {
            return value;
        }

        var text = value
            .Replace("http://", "hxxp://", StringComparison.OrdinalIgnoreCase)
            .Replace("https://", "hxxps://", StringComparison.OrdinalIgnoreCase)
            .Replace("ftp://", "fxp://", StringComparison.OrdinalIgnoreCase);

        if (kind == IocKind.Email) text = text.Replace("@", "[at]");
        return text.Replace(".", "[.]");
    }

    /// <summary>
    /// Label an address by scope, or "" when it is not a valid address.
    /// </summary>
    /// <remarks>
    /// Loopback is tested before private because 127.0.0.0/8 is both, and
    /// "this file talks to localhost" means something different from "this file
    /// talks to the internal network". .NET has no equivalent of Python's
    /// <c>ip_address().is_private</c>, so the ranges are spelled out.
    /// </remarks>
    public static string ClassifyAddress(string value)
    {
        if (!IPAddress.TryParse(value, out var address)) return "";
        if (address.AddressFamily != AddressFamily.InterNetwork) return "";

        // Reject things the regex allows but an address is not, such as 1.2.3.400
        // being parsed leniently, by round-tripping the text.
        if (address.ToString() != value) return "";

        var octets = address.GetAddressBytes();

        if (octets[0] == 127) return "loopback";
        if (octets[0] == 0) return "reserved";                                   // 0.0.0.0/8
        if (octets[0] == 169 && octets[1] == 254) return "reserved";             // link-local
        if (octets[0] >= 224) return "reserved";                                 // multicast and 240/4
        if (octets[0] == 255) return "reserved";

        if (octets[0] == 10) return "private";
        if (octets[0] == 172 && octets[1] is >= 16 and <= 31) return "private";
        if (octets[0] == 192 && octets[1] == 168) return "private";
        if (octets[0] == 100 && octets[1] is >= 64 and <= 127) return "private"; // CGNAT
        if (octets[0] == 198 && octets[1] is 18 or 19) return "private";         // benchmarking

        // Documentation ranges. Not private in the routing sense, but equally
        // meaningless as an indicator, and grouping them here keeps them
        // visible in the scope breakdown rather than dropped.
        if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) return "private";
        if (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) return "private";
        if (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) return "private";
        if (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) return "private";

        return "external";
    }

    /// <summary>Best-effort host from a URL, without parsing bytes as a URI.</summary>
    public static string HostOf(string url)
    {
        var scheme = url.IndexOf("://", StringComparison.Ordinal);
        var rest = scheme >= 0 ? url[(scheme + 3)..] : url;

        var cut = rest.AsSpan().IndexOfAny('/', '?', '#');
        if (cut >= 0) rest = rest[..cut];

        var at = rest.LastIndexOf('@');          // drop user:pass@
        if (at >= 0) rest = rest[(at + 1)..];

        var port = rest.IndexOf(':');
        if (port >= 0) rest = rest[..port];

        return rest.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Whether a hostname is worth reporting.
    /// </summary>
    /// <remarks>
    /// Leading labels are stripped one at a time and re-checked, so
    /// <c>cdn.example.com</c> is filtered by the <c>example.com</c> entry
    /// instead of needing an entry of its own.
    /// </remarks>
    public static bool PlausibleDomain(string value)
    {
        var lowered = value.ToLowerInvariant().TrimEnd('.');
        if (lowered.Length == 0 || lowered.Length > 253) return false;
        if (DomainDenylist.Contains(lowered)) return false;
        if (NotDomainSuffix.Any(s => lowered.EndsWith(s, StringComparison.Ordinal))) return false;

        var parts = lowered.Split('.');
        for (var i = 1; i < parts.Length - 1; i++)
        {
            if (DomainDenylist.Contains(string.Join('.', parts[i..]))) return false;
        }
        return true;
    }

    private static string PrintableOnly(ReadOnlySpan<char> text)
    {
        var buffer = new char[text.Length];
        for (var i = 0; i < text.Length; i++)
        {
            buffer[i] = text[i] is >= (char)32 and < (char)127 ? text[i] : '.';
        }
        return new string(buffer);
    }
}
