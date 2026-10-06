using System.IO.Enumeration;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecuritySuite.Intel;
using SecuritySuite.Storage;

namespace SecuritySuite.Hunting;

/// <summary>
/// A small query language for hunting across findings.
/// </summary>
/// <remarks>
/// <para>
/// The dashboard's search box does a substring match over the whole JSON of an
/// event. That finds things, but it cannot express the questions an analyst
/// actually asks — "critical detections that aren't resolved, on PowerShell
/// techniques, excluding the samples folder" — and a substring match on
/// <c>critical</c> also hits a file literally named <c>critical_report.txt</c>.
/// </para>
/// <para>Grammar, the smallest thing that answers those questions:</para>
/// <code>
/// query   := or
/// or      := and ( ("OR" | "|") and )*
/// and     := not ( ("AND" | "&amp;")? not )*        // adjacency implies AND
/// not     := ("NOT" | "-")? primary
/// primary := "(" or ")" | term
/// term    := [field ":"] value                  // bare value = free text
/// </code>
/// <para>
/// Values support <c>*</c> and <c>?</c> wildcards and may be quoted to include
/// spaces. An unknown field is a parse error rather than a silent no-match,
/// because a typo that quietly returns nothing is worse than one that says so.
/// </para>
/// <para>
/// Evaluation runs against the events the store already holds, so hunting needs
/// no separate index and stays consistent with what the dashboard shows.
/// </para>
/// </remarks>
public static partial class HuntQuery
{
    /// <summary>Queryable fields. Anything else is a parse error.</summary>
    public static readonly string[] Fields =
    [
        "severity", "status", "type", "rule", "namespace", "tag", "file", "path",
        "sha256", "technique", "attack", "tactic", "note", "text",
    ];

    [GeneratedRegex("""
        \s*(?:
            (?<lparen>\()
          | (?<rparen>\))
          | (?<op>\bAND\b|\bOR\b|\bNOT\b|&&|\|\||&|\||(?<![\w*?])-(?=\S))
          | (?<term>(?:[A-Za-z_]+:)?(?:"[^"]*"|'[^']*'|[^\s()]+))
        )
        """, RegexOptions.IgnorePatternWhitespace | RegexOptions.IgnoreCase, 2000)]
    private static partial Regex TokenPattern();

    // ------------------------------------------------------------- tokenize
    internal enum TokenKind { LParen, RParen, Op, Term }

    internal readonly record struct Token(TokenKind Kind, string Value);

    internal static List<Token> Tokenize(string text)
    {
        var tokens = new List<Token>();
        var position = 0;

        while (position < text.Length)
        {
            if (char.IsWhiteSpace(text[position]))
            {
                position++;
                continue;
            }

            var match = TokenPattern().Match(text, position);
            if (!match.Success || match.Index != position || match.Length == 0)
            {
                throw new HuntQueryException("cannot parse from: " +
                    text[position..Math.Min(text.Length, position + 20)]);
            }
            position = match.Index + match.Length;

            if (match.Groups["lparen"].Success) tokens.Add(new Token(TokenKind.LParen, "("));
            else if (match.Groups["rparen"].Success) tokens.Add(new Token(TokenKind.RParen, ")"));
            else if (match.Groups["op"].Success)
            {
                var raw = match.Groups["op"].Value.ToUpperInvariant();
                var name = raw is "AND" or "&&" or "&" ? "AND"
                    : raw is "OR" or "||" or "|" ? "OR"
                    : "NOT";
                tokens.Add(new Token(TokenKind.Op, name));
            }
            else tokens.Add(new Token(TokenKind.Term, match.Groups["term"].Value));
        }
        return tokens;
    }

    // ----------------------------------------------------------------- parse
    /// <summary>Parse a query, or null when it is blank, meaning match everything.</summary>
    public static HuntNode? Parse(string? text)
    {
        var tokens = Tokenize(text ?? "");
        if (tokens.Count == 0) return null;

        var parser = new HuntParser(tokens);
        return parser.Parse();
    }

    internal static HuntNode MakeTerm(string raw)
    {
        var separator = raw.IndexOf(':');
        string field, value;

        if (separator < 0)
        {
            field = "text";
            value = raw;
        }
        else
        {
            field = raw[..separator].ToLowerInvariant();
            value = raw[(separator + 1)..];
        }

        if (!Fields.Contains(field, StringComparer.Ordinal))
        {
            throw new HuntQueryException("unknown field '" + field + "' - try: " +
                string.Join(", ", Fields.Order(StringComparer.Ordinal)));
        }

        value = value.Trim();
        if (value.Length >= 2 && value[0] == value[^1] && value[0] is '"' or '\'')
            value = value[1..^1];

        if (value.Length == 0)
            throw new HuntQueryException("empty value for field '" + field + "'");

        return new HuntTerm(field, value.ToLowerInvariant());
    }

    // ------------------------------------------------------------ evaluation
    /// <summary>Comparable strings for one field of one event.</summary>
    internal static List<string> ValuesFor(SuiteEvent item, string field)
    {
        var matches = item.Matches ?? [];

        switch (field)
        {
            case "severity": return [item.Severity ?? ""];
            case "status": return [item.Status.Length > 0 ? item.Status : "new"];
            case "type": return [item.EventType];
            case "rule": return [.. matches.Select(m => m.Rule)];
            case "namespace": return [.. matches.Select(m => m.Namespace)];
            case "tag": return [.. matches.SelectMany(m => m.Tags)];

            case "file":
            case "path":
                return [.. new[] { item.FilePath ?? "", item.FileName ?? "" }
                    .Where(v => v.Length > 0)];

            case "sha256": return [item.Sha256 ?? ""];

            // Resolved from rule metadata on demand, matching the rest of the
            // suite: techniques are not stored on the event.
            case "technique":
            case "attack":
                return [.. matches.SelectMany(AttackMapping.Resolve).Select(t => t.Id)];

            case "tactic":
                return [.. matches.SelectMany(AttackMapping.Resolve).SelectMany(t => t.Tactics)];

            case "note": return [item.TriageNote ?? ""];
            default: return [];
        }
    }

    private static bool MatchesValue(List<string> candidates, string needle)
    {
        var glob = needle.Contains('*') || needle.Contains('?');

        foreach (var candidate in candidates)
        {
            var low = candidate.ToLowerInvariant();
            if (glob)
            {
                if (FileSystemName.MatchesSimpleExpression(needle, low, ignoreCase: true)) return true;
            }
            else if (low.Contains(needle, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    public static bool Evaluate(HuntNode? node, SuiteEvent item, string blob) => node switch
    {
        null => true,
        HuntAnd and => Evaluate(and.Left, item, blob) && Evaluate(and.Right, item, blob),
        HuntOr or => Evaluate(or.Left, item, blob) || Evaluate(or.Right, item, blob),
        HuntNot not => !Evaluate(not.Child, item, blob),

        // Free text keeps the whole-event substring behaviour, so a bare word
        // in the box still works the way operators expect.
        HuntTerm { Field: "text" } term =>
            term.Value.Contains('*') || term.Value.Contains('?')
                ? FileSystemName.MatchesSimpleExpression("*" + term.Value + "*", blob, true)
                : blob.Contains(term.Value, StringComparison.Ordinal),

        HuntTerm term => MatchesValue(ValuesFor(item, term.Field), term.Value),
        _ => true,
    };

    /// <summary>Filter events by query, reporting what was understood.</summary>
    public static HuntResult Run(string? query, IEnumerable<SuiteEvent> events, int limit = 300)
    {
        HuntNode? tree;
        try
        {
            tree = Parse(query);
        }
        catch (HuntQueryException exc)
        {
            return new HuntResult
            {
                Error = exc.Message,
                Query = query ?? "",
                Fields = [.. Fields.Order(StringComparer.Ordinal)],
            };
        }

        // Only built when a free-text term needs it: serialising every event is
        // the expensive case, and field terms never pay for it.
        var needsText = NeedsText(tree);

        var results = new List<SuiteEvent>();
        var scanned = 0;

        foreach (var item in events)
        {
            scanned++;
            var blob = needsText ? Blob(item) : "";
            if (!Evaluate(tree, item, blob)) continue;

            results.Add(item);
            if (results.Count >= limit) break;
        }

        return new HuntResult
        {
            Findings = results,
            Matched = results.Count,
            Scanned = scanned,
            Query = query ?? "",
            Fields = [.. Fields.Order(StringComparer.Ordinal)],
        };
    }

    internal static bool NeedsText(HuntNode? node) => node switch
    {
        HuntTerm term => term.Field == "text",
        HuntNot not => NeedsText(not.Child),
        HuntAnd and => NeedsText(and.Left) || NeedsText(and.Right),
        HuntOr or => NeedsText(or.Left) || NeedsText(or.Right),
        _ => false,
    };

    private static string Blob(SuiteEvent item)
    {
        try
        {
            return JsonSerializer.Serialize(item, SuiteJson.Options).ToLowerInvariant();
        }
        catch (JsonException)
        {
            return "";
        }
    }
}

/// <summary>The query could not be parsed; the message is shown to the operator.</summary>
public sealed class HuntQueryException(string message) : Exception(message);

public abstract record HuntNode;

public sealed record HuntTerm(string Field, string Value) : HuntNode;

public sealed record HuntAnd(HuntNode Left, HuntNode Right) : HuntNode;

public sealed record HuntOr(HuntNode Left, HuntNode Right) : HuntNode;

public sealed record HuntNot(HuntNode Child) : HuntNode;

internal sealed class HuntParser(List<HuntQuery.Token> tokens)
{
    private int _position;

    private HuntQuery.Token? Peek =>
        _position < tokens.Count ? tokens[_position] : null;

    public HuntNode Parse()
    {
        var node = ParseOr();
        if (_position != tokens.Count)
            throw new HuntQueryException("unexpected " + Peek?.Value);
        return node;
    }

    private HuntNode ParseOr()
    {
        var node = ParseAnd();
        while (Peek is { Kind: HuntQuery.TokenKind.Op, Value: "OR" })
        {
            _position++;
            node = new HuntOr(node, ParseAnd());
        }
        return node;
    }

    private HuntNode ParseAnd()
    {
        var node = ParseNot();
        while (true)
        {
            if (Peek is not { } token) break;

            if (token is { Kind: HuntQuery.TokenKind.Op, Value: "AND" })
            {
                _position++;
            }
            else if (token.Kind is HuntQuery.TokenKind.Term or HuntQuery.TokenKind.LParen ||
                     token is { Kind: HuntQuery.TokenKind.Op, Value: "NOT" })
            {
                // Adjacency implies AND, so "severity:critical status:new" works.
            }
            else break;

            node = new HuntAnd(node, ParseNot());
        }
        return node;
    }

    private HuntNode ParseNot()
    {
        if (Peek is { Kind: HuntQuery.TokenKind.Op, Value: "NOT" })
        {
            _position++;
            return new HuntNot(ParseNot());
        }
        return ParsePrimary();
    }

    private HuntNode ParsePrimary()
    {
        if (Peek is not { } token)
            throw new HuntQueryException("expected a term, got end of query");

        if (token.Kind == HuntQuery.TokenKind.LParen)
        {
            _position++;
            var node = ParseOr();
            if (Peek?.Kind != HuntQuery.TokenKind.RParen)
                throw new HuntQueryException("unclosed (");
            _position++;
            return node;
        }

        if (token.Kind != HuntQuery.TokenKind.Term)
            throw new HuntQueryException("expected a term, got " + token.Value);

        _position++;
        return HuntQuery.MakeTerm(token.Value);
    }
}

public sealed class HuntResult
{
    [JsonPropertyName("findings")] public List<SuiteEvent> Findings { get; init; } = [];
    [JsonPropertyName("matched")] public int Matched { get; init; }
    [JsonPropertyName("scanned")] public int Scanned { get; init; }
    [JsonPropertyName("query")] public string Query { get; init; } = "";

    /// <summary>The queryable fields, so the UI can offer them without hardcoding.</summary>
    [JsonPropertyName("fields")] public List<string> Fields { get; init; } = [];

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}
