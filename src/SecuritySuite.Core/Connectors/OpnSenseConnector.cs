using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecuritySuite.Inventory;
using SecuritySuite.Net;
using SecuritySuite.Storage;

namespace SecuritySuite.Connectors;

/// <summary>
/// Read-only OPNsense IDS service health.
/// </summary>
/// <remarks>
/// <para>
/// OPNsense documents <c>GET /api/ids/service/status</c> and key/secret basic
/// auth at docs.opnsense.org. Nothing here writes policy.
/// </para>
/// <para>
/// The endpoint is pinned hard, because this request carries credentials:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>HTTPS to an RFC 1918 IPv4 literal only.</b> No DNS names, so there is
/// nothing to rebind and no resolved alias to send credentials to. No
/// loopback, no IPv6, no public addresses.
/// </description></item>
/// <item><description>
/// <b>One path.</b> The configured value may be an origin or exactly the status
/// URL; any other path, a query, a fragment, userinfo or an escape is rejected.
/// </description></item>
/// <item><description>
/// <b>No redirects.</b> A 3xx is refused rather than followed, so the appliance
/// cannot bounce the credentials somewhere else.
/// </description></item>
/// <item><description>
/// <b>No proxy.</b> Environment proxy settings are ignored, so an inherited
/// <c>HTTPS_PROXY</c> cannot intercept them.
/// </description></item>
/// <item><description>
/// <b>Verified TLS always.</b> Trust a private CA through the Windows store.
/// </description></item>
/// </list>
/// <para>
/// Credentials, response bodies and upstream exception messages are never
/// returned to a caller. Configuration is snapshotted at construction;
/// recreate the connector to change it.
/// </para>
/// </remarks>
public sealed class OpnSenseConnector
{
    private const string StatusPath = "/api/ids/service/status";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);
    private const int MaxResponseBytes = 65_536;

    /// <summary>
    /// A dedicated client: no proxy, no redirects, nothing shared.
    /// </summary>
    /// <remarks>
    /// Deliberately not <see cref="SuiteHttp.Client"/>. That one follows
    /// redirects and honours the ambient proxy, both of which are exactly what
    /// must not happen to a request carrying appliance credentials.
    /// </remarks>
    private static readonly Lazy<HttpClient> Pinned = new(() =>
        new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            ConnectTimeout = Timeout,
        })
        {
            Timeout = Timeout,
            MaxResponseContentBufferSize = MaxResponseBytes + 1,
        }, isThreadSafe: true);

    private readonly string _key;
    private readonly string _secret;
    private readonly ConnectorStatus _configuration;
    private readonly Lock _gate = new();
    private ConnectorStatus? _lastHealth;

    public OpnSenseConnector(IReadOnlyDictionary<string, string>? environment = null)
    {
        string Read(string name) => environment is not null
            ? environment.GetValueOrDefault(name, "")
            : Environment.GetEnvironmentVariable(name) ?? "";

        var url = Read("OPNSENSE_URL");
        _key = Read("OPNSENSE_API_KEY");
        _secret = Read("OPNSENSE_API_SECRET");

        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(url)) missing.Add("OPNSENSE_URL");
        if (string.IsNullOrWhiteSpace(_key)) missing.Add("OPNSENSE_API_KEY");
        if (string.IsNullOrWhiteSpace(_secret)) missing.Add("OPNSENSE_API_SECRET");

        string? endpoint = null;
        string? error = null;

        if (!string.IsNullOrWhiteSpace(url))
        {
            try { endpoint = PinEndpoint(url); }
            catch (ArgumentException exc) { error = exc.Message; }
        }

        // A colon in the key would split the basic-auth pair, and a control
        // character would let a header be injected.
        if (_key.Contains(':') ||
            (_key + _secret).Any(c => c < 32 || c == 127))
        {
            error = "OPNsense API credentials have an invalid format.";
        }

        var configured = missing.Count == 0 && error is null;
        _configuration = new ConnectorStatus
        {
            State = error is not null ? "invalid_configuration"
                : missing.Count > 0 ? "not_configured"
                : "configured_unchecked",
            Configured = configured,
            Operational = null,
            Endpoint = endpoint,
            Error = error,
            Missing = missing,
        };
    }

    /// <summary>
    /// Reduce a configured value to the one URL this connector may request.
    /// </summary>
    /// <remarks>
    /// Literal-only addressing is the point: resolving a name would mean
    /// sending credentials to whatever the resolver returned at that moment,
    /// which a DNS-rebinding attacker controls.
    /// </remarks>
    internal static string PinEndpoint(string value)
    {
        const string message =
            "OPNSENSE_URL must be an HTTPS RFC1918 IPv4 origin or the exact IDS status URL.";

        if (string.IsNullOrEmpty(value) || value.Any(c => c <= 32 || c >= 127))
            throw new ArgumentException(message);
        if (value.IndexOfAny(['\\', '@', '%', '?', '#']) >= 0)
            throw new ArgumentException(message);

        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed))
            throw new ArgumentException(message);
        if (parsed.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException(message);
        if (parsed.AbsolutePath is not ("" or "/" or StatusPath))
            throw new ArgumentException(message);
        if (!string.IsNullOrEmpty(parsed.UserInfo) ||
            !string.IsNullOrEmpty(parsed.Query) ||
            !string.IsNullOrEmpty(parsed.Fragment))
        {
            throw new ArgumentException(message);
        }

        if (!IPAddress.TryParse(parsed.Host, out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            !NetworkInventory.IsPrivate(address))
        {
            throw new ArgumentException(message);
        }

        var port = parsed.IsDefaultPort ? "" : ":" + parsed.Port;
        if (!parsed.IsDefaultPort && parsed.Port is < 1 or > 65535)
            throw new ArgumentException(message);

        return "https://" + address + port + StatusPath;
    }

    public ConnectorStatus ConfigurationStatus() => _configuration.Copy();

    /// <summary>The last health result, or the unchecked configuration. Performs no I/O.</summary>
    public ConnectorStatus Status()
    {
        lock (_gate) return (_lastHealth ?? _configuration).Copy();
    }

    /// <summary>One verified HTTPS GET against the pinned endpoint.</summary>
    public async Task<ConnectorStatus> HealthAsync(CancellationToken token = default)
    {
        var result = ConfigurationStatus();
        if (!result.Configured || result.Endpoint is null) return result;

        result.State = "error";
        result.Operational = false;
        result.CheckedAt = EventStore.NowIso();

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, result.Endpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.UserAgent.ParseAdd(SuiteHttp.UserAgent);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(_key + ":" + _secret)));

            using var response = await Pinned.Value
                .SendAsync(request, HttpCompletionOption.ResponseContentRead, token)
                .ConfigureAwait(false);

            var code = (int)response.StatusCode;
            if (code is >= 300 and < 400)
            {
                result.Error = "Redirect refused; configure the exact HTTPS endpoint.";
            }
            else if (code is 401 or 403)
            {
                result.Error = "OPNsense denied authentication or IDS status permission.";
            }
            else if (code != 200)
            {
                result.Error = "OPNsense returned an unsuccessful HTTP status.";
            }
            else
            {
                var body = await response.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false);
                if (body.Length > MaxResponseBytes)
                {
                    result.Error = "OPNsense returned an invalid or unsupported IDS status response.";
                    return Remember(result);
                }

                using var document = JsonDocument.Parse(body);
                var service = document.RootElement.ValueKind == JsonValueKind.Object &&
                              document.RootElement.TryGetProperty("status", out var value) &&
                              value.ValueKind == JsonValueKind.String
                    ? value.GetString()
                    : null;

                if (service is not ("running" or "stopped" or "disabled"))
                {
                    result.Error = "OPNsense returned an invalid or unsupported IDS status response.";
                }
                else
                {
                    result.State = service == "running" ? "operational" : "degraded";
                    result.Operational = service == "running";
                    result.ServiceStatus = service;
                    result.Error = null;
                }
            }
        }
        catch (Exception exc) when (exc is HttpRequestException or TaskCanceledException
                                        or SocketException or IOException)
        {
            // The upstream message is deliberately discarded: it can carry the
            // endpoint and internal detail into a response the dashboard shows.
            result.Error = "OPNsense connection failed; verify endpoint, trusted TLS " +
                           "certificate and reachability.";
        }
        catch (Exception exc) when (exc is JsonException or FormatException or DecoderFallbackException)
        {
            result.Error = "OPNsense returned an invalid or unsupported IDS status response.";
        }
        return Remember(result);
    }

    private ConnectorStatus Remember(ConnectorStatus result)
    {
        lock (_gate) _lastHealth = result.Copy();
        return result;
    }
}

/// <summary>
/// Offline setup indicator only. No Bitdefender integration is implemented.
/// </summary>
/// <remarks>
/// Reports whether both settings are present, never their values.
/// <c>Implemented</c> is always false and <c>Operational</c> always false, even
/// when configured: this tests nothing about endpoint validity, credentials,
/// agent installation or protection, and must not look as though it does.
/// </remarks>
public sealed class BitdefenderConnector
{
    private readonly List<string> _missing;

    public BitdefenderConnector(IReadOnlyDictionary<string, string>? environment = null)
    {
        string Read(string name) => environment is not null
            ? environment.GetValueOrDefault(name, "")
            : Environment.GetEnvironmentVariable(name) ?? "";

        _missing =
        [
            .. new[] { "BITDEFENDER_API_URL", "BITDEFENDER_API_KEY" }
                .Where(name => string.IsNullOrWhiteSpace(Read(name))),
        ];
    }

    public ConnectorStatus Status() => new()
    {
        State = _missing.Count == 0 ? "setup_only" : "not_configured",
        Configured = _missing.Count == 0,
        Implemented = false,
        Operational = false,
        Missing = [.. _missing],
    };
}

/// <summary>
/// One connector's state. <c>Operational</c> is null until a health check runs,
/// then true only for a recognised running service.
/// </summary>
/// <remarks>
/// A true <c>Operational</c> attests that the IDS service reports itself
/// running. It does not attest to IPS configuration or to network protection.
/// </remarks>
public sealed class ConnectorStatus
{
    /// <summary>
    /// not_configured, invalid_configuration, configured_unchecked,
    /// operational, degraded or error.
    /// </summary>
    [JsonPropertyName("state")] public string State { get; set; } = "not_configured";

    [JsonPropertyName("configured")] public bool Configured { get; set; }
    [JsonPropertyName("operational")] public bool? Operational { get; set; }
    [JsonPropertyName("endpoint")] public string? Endpoint { get; set; }
    [JsonPropertyName("service_status")] public string? ServiceStatus { get; set; }
    [JsonPropertyName("checked_at")] public string? CheckedAt { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("missing")] public List<string> Missing { get; set; } = [];

    [JsonPropertyName("implemented")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Implemented { get; set; }

    public ConnectorStatus Copy() => new()
    {
        State = State,
        Configured = Configured,
        Operational = Operational,
        Endpoint = Endpoint,
        ServiceStatus = ServiceStatus,
        CheckedAt = CheckedAt,
        Error = Error,
        Missing = [.. Missing],
        Implemented = Implemented,
    };
}
