using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecuritySuite.Http;

/// <summary>
/// Request and response plumbing: security headers, body parsing, and the two
/// origin guards.
/// </summary>
public static class HttpPrimitives
{
    public const int MaxBodyBytes = 64 * 1024;

    private static readonly Dictionary<string, string> ContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        [".html"] = "text/html; charset=utf-8",
        [".js"] = "application/javascript; charset=utf-8",
        [".css"] = "text/css; charset=utf-8",
        [".svg"] = "image/svg+xml",
        [".ico"] = "image/x-icon",
        [".json"] = "application/json; charset=utf-8",
        [".png"] = "image/png",
        [".woff2"] = "font/woff2",
    };

    public static string ContentTypeFor(string path) =>
        ContentTypes.GetValueOrDefault(Path.GetExtension(path), "application/octet-stream");

    /// <summary>
    /// Headers applied to every response.
    /// </summary>
    /// <remarks>
    /// The CSP is restrictive because the dashboard needs nothing external:
    /// no CDN, no inline script, no framing. <c>style-src</c> allows inline
    /// styles only because the panels set computed widths for bar charts.
    /// </remarks>
    public static void ApplySecurityHeaders(HttpListenerResponse response)
    {
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["Cache-Control"] = "no-store";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["Content-Security-Policy"] =
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; " +
            "base-uri 'none'; form-action 'self'";
    }

    /// <summary>
    /// Block DNS rebinding: only loopback names, on our own port, may talk here.
    /// </summary>
    /// <remarks>
    /// The server binds loopback, but that alone does not stop a page on
    /// <c>evil.test</c> whose DNS resolves to 127.0.0.1 from reaching it. The
    /// browser sends <c>Host: evil.test</c>, so checking the Host header is
    /// what actually refuses that request.
    /// </remarks>
    public static bool HostAllowed(HttpListenerRequest request, int expectedPort)
    {
        var value = request.Headers["Host"];
        if (string.IsNullOrEmpty(value)) return false;

        if (!Uri.TryCreate("http://" + value, UriKind.Absolute, out var parsed)) return false;

        // Anything beyond a bare host and port means the header was crafted.
        if (!string.IsNullOrEmpty(parsed.UserInfo)) return false;
        if (parsed.AbsolutePath is not ("" or "/")) return false;
        if (!string.IsNullOrEmpty(parsed.Query) || !string.IsNullOrEmpty(parsed.Fragment)) return false;

        var host = parsed.Host.Trim('[', ']');
        if (host is not ("localhost" or "127.0.0.1" or "::1")) return false;

        var port = value.Contains(':') && parsed.Port > 0 ? parsed.Port : 80;
        return port == expectedPort || (!value.Contains(':') && expectedPort == 80);
    }

    /// <summary>
    /// Reject cross-origin writes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There is no CSRF token here; this is the replacement for one. Requiring
    /// <c>application/json</c> is the load-bearing part: a POST with
    /// <c>Content-Type: text/plain</c> is a CORS <em>simple request</em>, so it
    /// needs no preflight, and any page the operator had open could fire one at
    /// 127.0.0.1. It could not read the reply — but a deletion does not need a
    /// reply. Demanding <c>application/json</c> forces a preflight this server
    /// never answers, so the browser blocks the request before it arrives.
    /// </para>
    /// <para>
    /// The Origin and Sec-Fetch-Site checks are belt and braces for clients
    /// that send them.
    /// </para>
    /// </remarks>
    public static (bool Allowed, string Reason) CsrfOk(HttpListenerRequest request)
    {
        var contentType = (request.Headers["Content-Type"] ?? "").Split(';')[0].Trim();
        if (!contentType.Equals("application/json", StringComparison.OrdinalIgnoreCase))
            return (false, "Content-Type must be application/json");

        var origin = request.Headers["Origin"];
        if (!string.IsNullOrEmpty(origin))
        {
            var expected = "http://" + (request.Headers["Host"] ?? "");
            if (!string.Equals(origin, expected, StringComparison.OrdinalIgnoreCase))
                return (false, "cross-origin request refused");
        }

        var site = (request.Headers["Sec-Fetch-Site"] ?? "").ToLowerInvariant();
        if (site.Length > 0 && site is not ("same-origin" or "none"))
            return (false, "cross-site request refused");

        return (true, "");
    }

    /// <summary>
    /// Read and validate a JSON request body.
    /// </summary>
    /// <remarks>
    /// Types are checked here rather than at each route, because a route that
    /// reads <c>confirm</c> as truthy would treat the string <c>"false"</c> as
    /// a confirmation. The fields below are the ones that gate destructive
    /// behaviour, so each is required to be the type it looks like.
    /// </remarks>
    public static JsonObject ReadBody(HttpListenerRequest request)
    {
        if (!string.IsNullOrEmpty(request.Headers["Transfer-Encoding"]))
            throw new ArgumentException("Transfer-Encoding is not supported");

        var lengths = request.Headers.GetValues("Content-Length") ?? [];
        if (lengths.Length != 1)
            throw new ArgumentException("Exactly one Content-Length header is required");
        if (!int.TryParse(lengths[0], out var length) || length <= 0 || length > MaxBodyBytes)
            throw new ArgumentException("JSON body must be between 1 and 65536 bytes");

        var buffer = new byte[length];
        var read = request.InputStream.ReadAtLeast(buffer, length, throwOnEndOfStream: false);
        if (read != length) throw new ArgumentException("Incomplete JSON request body");

        JsonNode? parsed;
        try
        {
            parsed = JsonNode.Parse(Encoding.UTF8.GetString(buffer), documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
            });
        }
        catch (JsonException exc)
        {
            throw new ArgumentException("Invalid JSON: " + exc.Message);
        }

        if (parsed is not JsonObject body) throw new ArgumentException("JSON body must be an object");

        foreach (var field in (string[])["confirm", "dry_run", "allow_directory", "services", "enabled"])
        {
            if (body.TryGetPropertyValue(field, out var value) && value is not null &&
                value.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False))
            {
                throw new ArgumentException(field + " must be a boolean");
            }
        }

        foreach (var field in (string[])["path", "id", "action", "severity", "status", "note",
                                         "cidr", "text", "answer", "playbook", "finding_id"])
        {
            if (body.TryGetPropertyValue(field, out var value) && value is not null &&
                value.GetValueKind() is not JsonValueKind.String)
            {
                // "playbook" is allowed to be an object: it is either a saved id
                // or a whole definition.
                if (field == "playbook" && value.GetValueKind() == JsonValueKind.Object) continue;
                throw new ArgumentException(field + " must be a string");
            }
        }

        foreach (var field in (string[])["limit", "days"])
        {
            if (!body.TryGetPropertyValue(field, out var value) || value is null) continue;
            if (value.GetValueKind() != JsonValueKind.Number ||
                !value.AsValue().TryGetValue<int>(out var number) || number < 1)
            {
                throw new ArgumentException(field + " must be a positive integer");
            }
        }

        if (body.TryGetPropertyValue("extensions", out var extensions) && extensions is not null)
        {
            if (extensions is not JsonArray array || array.Count > 50 ||
                array.Any(item => item?.GetValueKind() != JsonValueKind.String))
            {
                throw new ArgumentException("extensions must be a list of at most 50 strings");
            }
        }
        return body;
    }

    // ------------------------------------------------------------- accessors
    public static string? Str(this JsonObject body, string key) =>
        body.TryGetPropertyValue(key, out var value) && value?.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;

    public static bool Flag(this JsonObject body, string key) =>
        body.TryGetPropertyValue(key, out var value) && value?.GetValueKind() == JsonValueKind.True;

    /// <summary>For flags that default to true, such as <c>dry_run</c> on a bulk sweep.</summary>
    public static bool FlagOrDefault(this JsonObject body, string key, bool fallback) =>
        body.TryGetPropertyValue(key, out var value) && value is not null
            ? value.GetValueKind() == JsonValueKind.True
            : fallback;

    public static int? Int(this JsonObject body, string key) =>
        body.TryGetPropertyValue(key, out var value) &&
        value?.GetValueKind() == JsonValueKind.Number &&
        value.AsValue().TryGetValue<int>(out var number)
            ? number
            : null;

    public static List<string> Strings(this JsonObject body, string key) =>
        body.TryGetPropertyValue(key, out var value) && value is JsonArray array
            ? [.. array.Select(item => item?.GetValue<string>() ?? "").Where(s => s.Length > 0)]
            : [];

    /// <summary>
    /// Clamp a query-string integer, rejecting anything that is not a plain
    /// positive number.
    /// </summary>
    public static int Integer(string? value, int fallback = 100, int maximum = 5000)
    {
        if (string.IsNullOrEmpty(value)) return fallback;
        if (!value.All(char.IsAsciiDigit)) throw new ArgumentException("Expected a positive integer");
        if (!int.TryParse(value, out var parsed)) throw new ArgumentException("Expected a positive integer");
        return Math.Clamp(parsed, 1, maximum);
    }
}
