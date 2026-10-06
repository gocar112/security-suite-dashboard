using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace SecuritySuite.Net;

/// <summary>An HTTP response that was not a success, with the status kept.</summary>
public sealed class HttpFailure(int status, string detail = "")
    : Exception("HTTP " + status + (detail.Length > 0 ? ": " + detail : ""))
{
    /// <summary>The status code, or 0 when the request never reached a server.</summary>
    public int Status { get; } = status;

    public string Detail { get; } = detail;

    /// <summary>Retrying later may work: rate limited, or a server-side fault.</summary>
    public bool Transient => Status is 0 or 429 or >= 500;
}

/// <summary>
/// Shared outbound HTTP for the intelligence adapters.
/// </summary>
/// <remarks>
/// <para>
/// One <see cref="HttpClient"/> for the process. Creating one per request
/// exhausts sockets under load, because each disposed client leaves its
/// connections in TIME_WAIT.
/// </para>
/// <para>
/// Certificate validation is never disabled. The Python build needed a bundled
/// CA list because Python on Windows reports <c>cafile: None</c> and fell back
/// to whatever the platform store held, which surfaced against
/// services.nvd.nist.gov as an expired-certificate error for a perfectly valid
/// certificate. .NET uses the Windows certificate store directly, so the
/// workaround is unnecessary — but the principle it was chosen under still
/// holds: a security tool that turns off certificate checking to make a request
/// succeed has traded a real control for a convenience.
/// </para>
/// </remarks>
public static class SuiteHttp
{
    public const string UserAgent =
        "security-suite/2.0 (+https://github.com/gocar112/security-suite-dashboard)";

    /// <summary>Redirect hops followed before giving up.</summary>
    private const int MaxRedirects = 5;

    private static readonly Lazy<HttpClient> ClientLazy = new(() =>
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            MaxConnectionsPerServer = 8,

            // Redirects are followed by hand instead. These requests carry API
            // keys in ordinary headers (NVD's apiKey, VirusTotal's x-apikey),
            // and .NET only strips Authorization across a host change, not
            // arbitrary headers. Automatic redirects would therefore hand the
            // key to whatever host the response pointed at.
            AllowAutoRedirect = false,
        };
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }, isThreadSafe: true);

    /// <summary>
    /// Reject anything that is not an absolute HTTPS URL to a named host.
    /// </summary>
    /// <remarks>
    /// Guards against a cleartext target, a <c>file://</c> read, and userinfo
    /// in the URL. Checked on the initial request and again on every redirect
    /// hop, so a 302 cannot downgrade a credentialed request to HTTP.
    /// </remarks>
    public static void RequireHttps(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrEmpty(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new HttpFailure(0, "outbound URL must be an absolute HTTPS URL without credentials");
        }
    }

    public static HttpClient Client => ClientLazy.Value;

    /// <summary>Where the trust anchors come from, for the status panel.</summary>
    public static string TrustStore =>
        OperatingSystem.IsWindows() ? "windows certificate store" : "system trust store";

    public static async Task<JsonDocument> GetJsonAsync(string url, IDictionary<string, string>? headers = null,
                                                        double timeoutSeconds = 30,
                                                        CancellationToken token = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        return await SendAsync(request, headers, timeoutSeconds, token).ConfigureAwait(false);
    }

    public static async Task<JsonDocument> PostJsonAsync(string url, object payload,
                                                         IDictionary<string, string>? headers = null,
                                                         double timeoutSeconds = 30,
                                                         CancellationToken token = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(payload),
        };
        return await SendAsync(request, headers, timeoutSeconds, token).ConfigureAwait(false);
    }

    private static async Task<JsonDocument> SendAsync(HttpRequestMessage request,
                                                      IDictionary<string, string>? headers,
                                                      double timeoutSeconds,
                                                      CancellationToken token)
    {
        RequireHttps(request.RequestUri!);

        foreach (var (key, value) in headers ?? new Dictionary<string, string>())
            request.Headers.TryAddWithoutValidation(key, value);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        var response = await SendFollowingRedirectsAsync(request, timeout.Token, token)
            .ConfigureAwait(false);

        using (response)
        {
            var body = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpFailure((int)response.StatusCode,
                    body.Length > 300 ? body[..300] : body);
            }
            try
            {
                return JsonDocument.Parse(body.Length == 0 ? "{}" : body);
            }
            catch (JsonException exc)
            {
                throw new HttpFailure((int)response.StatusCode,
                    "response was not JSON: " + exc.Message);
            }
        }
    }

    /// <summary>
    /// Send a request, following redirects by hand.
    /// </summary>
    /// <remarks>
    /// Every hop is re-checked with <see cref="RequireHttps"/>, and headers are
    /// carried forward only while the host is unchanged. A redirect to another
    /// host gets the request without its credentials, which is the behaviour
    /// automatic redirects do not give us for non-Authorization headers.
    /// </remarks>
    private static async Task<HttpResponseMessage> SendFollowingRedirectsAsync(
        HttpRequestMessage request, CancellationToken timeoutToken, CancellationToken callerToken)
    {
        var current = request;
        var origin = request.RequestUri!;

        for (var hop = 0; ; hop++)
        {
            HttpResponseMessage response;
            try
            {
                response = await Client.SendAsync(current, HttpCompletionOption.ResponseContentRead,
                    timeoutToken).ConfigureAwait(false);
            }
            catch (TaskCanceledException) when (!callerToken.IsCancellationRequested)
            {
                throw new HttpFailure(0, "request timed out");
            }
            catch (HttpRequestException exc)
            {
                // Status 0 means the request never got an answer: DNS, TLS, or
                // the network. Distinct from a server that answered with an error.
                throw new HttpFailure(0, exc.Message);
            }

            var status = (int)response.StatusCode;
            if (status is not (301 or 302 or 303 or 307 or 308)) return response;

            var location = response.Headers.Location;
            if (location is null) return response;

            if (hop >= MaxRedirects)
            {
                response.Dispose();
                throw new HttpFailure(status, "too many redirects");
            }

            var next = location.IsAbsoluteUri ? location : new Uri(current.RequestUri!, location);
            response.Dispose();

            RequireHttps(next);

            // 303, and 301/302 on a POST, become a GET; 307/308 preserve the
            // method and body.
            var method = status is 303 || (status is 301 or 302 && current.Method == HttpMethod.Post)
                ? HttpMethod.Get
                : current.Method;

            var forwarded = new HttpRequestMessage(method, next);
            if (method == current.Method) forwarded.Content = current.Content;

            var sameHost = string.Equals(next.Host, origin.Host, StringComparison.OrdinalIgnoreCase);
            foreach (var header in current.Headers)
            {
                if (!sameHost) break;
                forwarded.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (hop > 0) current.Dispose();
            current = forwarded;
        }
    }

    /// <summary>
    /// Build a query string, correctly escaped.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A value of <see langword="true"/> emits a bare key with no
    /// <c>=</c>. NVD has valueless boolean parameters — <c>hasKev</c>,
    /// <c>hasCert</c>, <c>isVulnerable</c> — which are rejected when sent as
    /// <c>hasKev=true</c> and, worse, silently ignored when sent as
    /// <c>hasKev=</c>. Null and empty values are dropped entirely.
    /// </para>
    /// <para>
    /// Escaping uses <see cref="Uri.EscapeDataString"/> rather than replacing a
    /// couple of characters by hand, so a keyword containing <c>&amp;</c> or
    /// <c>=</c> cannot break out of its own parameter.
    /// </para>
    /// </remarks>
    public static string Query(IEnumerable<KeyValuePair<string, object?>> parameters)
    {
        var builder = new StringBuilder();
        foreach (var (key, value) in parameters)
        {
            if (value is null) continue;
            if (value is bool flag)
            {
                if (!flag) continue;
                Separate();
                builder.Append(Uri.EscapeDataString(key));
                continue;
            }
            var text = value.ToString();
            if (string.IsNullOrEmpty(text)) continue;

            Separate();
            builder.Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(text));
        }
        return builder.ToString();

        void Separate()
        {
            if (builder.Length > 0) builder.Append('&');
        }
    }
}

/// <summary>
/// Minimum-interval limiter, safe to share across threads.
/// </summary>
/// <remarks>
/// Deliberately a floor on the gap between requests rather than a token
/// bucket. A bucket would let the suite spend its whole allowance in a burst
/// and then stall for the rest of the window, which against NVD means a sync
/// that starts fast and then appears to hang.
/// </remarks>
public sealed class RateLimiter(double minIntervalSeconds)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _lastTicks;

    public double MinIntervalSeconds { get; } = minIntervalSeconds;

    public async Task<TimeSpan> WaitAsync(CancellationToken token = default)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var now = Stopwatch.GetTimestamp();
            var elapsed = (now - _lastTicks) / (double)Stopwatch.Frequency;
            var delay = MinIntervalSeconds - elapsed;

            if (_lastTicks != 0 && delay > 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(delay), token).ConfigureAwait(false);
                _lastTicks = Stopwatch.GetTimestamp();
                return TimeSpan.FromSeconds(delay);
            }
            _lastTicks = now;
            return TimeSpan.Zero;
        }
        finally
        {
            _gate.Release();
        }
    }
}
