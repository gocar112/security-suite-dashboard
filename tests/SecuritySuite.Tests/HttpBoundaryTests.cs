using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecuritySuite.Http;
using SecuritySuite.Monitoring;
using SecuritySuite.Storage;
using SecuritySuite.Telemetry;

namespace SecuritySuite.Tests;

/// <summary>
/// The dashboard's HTTP boundary, exercised over a real socket.
/// </summary>
/// <remarks>
/// Nothing here is authenticated, so these guards are the whole access
/// control: loopback binding, the Host check against DNS rebinding, and the
/// JSON content-type requirement that stands in for a CSRF token. They were
/// verified by hand with curl during the port; these make them regressions.
/// </remarks>
public sealed class HttpBoundaryTests : IDisposable
{
    private readonly SuiteFixture _fx = new();
    private readonly DashboardServer _server;
    private readonly HttpClient _client = new(new SocketsHttpHandler { UseProxy = false });
    private readonly string _base;

    public HttpBoundaryTests()
    {
        _fx.Config.Port = FreePort();
        var telemetry = new AuthTelemetry(_fx.Config.AuthLogPath, providers: []);
        var monitor = new DirectoryMonitor(_fx.Config, _fx.Engine, _fx.Store, telemetry, _ => { });
        var context = new SuiteContext(_fx.Config, _fx.Engine, _fx.Store, telemetry, monitor);

        _server = DashboardServer.Serve(context, _ => { });
        _base = "http://127.0.0.1:" + _fx.Config.Port;
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private Task<HttpResponseMessage> Post(string path, string body,
                                           string contentType = "application/json",
                                           Action<HttpRequestMessage>? tweak = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, _base + path)
        {
            Content = new StringContent(body, Encoding.UTF8, contentType),
        };
        tweak?.Invoke(request);
        return _client.SendAsync(request);
    }

    [Fact]
    public async Task A_loopback_read_is_allowed()
    {
        using var response = await _client.GetAsync(_base + "/api/instance");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// A page on evil.test whose DNS resolves to 127.0.0.1 can reach a loopback
    /// server; the Host header is what gives it away.
    /// </summary>
    [Fact]
    public async Task A_foreign_host_header_is_refused()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, _base + "/api/state");
        request.Headers.Host = "evil.test";

        using var response = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// text/plain is a CORS simple request: no preflight, so any open page could
    /// fire it. Requiring JSON forces a preflight this server never answers.
    /// </summary>
    [Fact]
    public async Task A_simple_text_plain_write_is_refused()
    {
        using var response = await Post("/api/monitor", "{\"action\":\"pause\"}", "text/plain");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_cross_origin_write_is_refused()
    {
        using var response = await Post("/api/monitor", "{\"action\":\"pause\"}",
            tweak: r => r.Headers.Add("Origin", "http://evil.test"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>A string "false" must not read as a confirmation.</summary>
    [Fact]
    public async Task A_non_boolean_confirm_is_rejected()
    {
        using var response = await Post("/api/findings/clear", "{\"confirm\":\"true\"}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Clearing_without_confirmation_is_refused()
    {
        using var response = await Post("/api/findings/clear", "{}");
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task A_confirmed_clear_succeeds_and_reports_what_it_kept()
    {
        _fx.Store.Add(new SuiteEvent { EventType = SuiteEvent.TypeRemediation });
        _fx.Store.Add(new SuiteEvent { EventType = SuiteEvent.TypeMatch });

        using var response = await Post("/api/findings/clear", "{\"confirm\":true}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.GetProperty("cleared").GetBoolean());
        Assert.Equal(1, body.RootElement.GetProperty("audit_retained").GetInt32());
    }

    /// <summary>
    /// The regression. A refused clear used to answer 200 with cleared=false,
    /// so the dashboard toasted "Cleared N line(s)" and wiped its live feed
    /// while the server had changed nothing. It must be a failure status.
    /// </summary>
    [Fact]
    public async Task A_clear_the_server_refuses_is_not_reported_as_success()
    {
        _fx.Store.Add(new SuiteEvent { EventType = SuiteEvent.TypeRemediation });

        using (new FileStream(_fx.Store.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            using var response = await Post("/api/findings/clear", "{\"confirm\":true}");

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(body.RootElement.GetProperty("cleared").GetBoolean());
            Assert.Contains("nothing was cleared", body.RootElement.GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task An_unknown_route_is_404()
    {
        using var response = await _client.GetAsync(_base + "/api/nope");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// Static files come from an allowlist, so a traversal path is never served.
    /// </summary>
    /// <remarks>
    /// Asserts that the file's contents do not come back, not a particular
    /// status. Different spellings are refused at different layers - some by
    /// the route's allowlist with 404, an encoded one before routing with 403 -
    /// and pinning one code would make the test about which layer refused
    /// rather than whether anything leaked.
    /// </remarks>
    [Theory]
    [InlineData("/..%2FDirectory.Build.props")]
    [InlineData("/../Directory.Build.props")]
    [InlineData("/web/../Directory.Build.props")]
    [InlineData("/%2e%2e/Directory.Build.props")]
    public async Task Path_traversal_does_not_reach_files_outside_web(string path)
    {
        using var response = await _client.GetAsync(_base + path);
        var body = await response.Content.ReadAsStringAsync();

        Assert.False(response.IsSuccessStatusCode, path + " answered " + (int)response.StatusCode);
        Assert.DoesNotContain("TargetFramework", body);
    }

    [Fact]
    public async Task Every_response_carries_the_security_headers()
    {
        using var response = await _client.GetAsync(_base + "/api/instance");

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'",
            response.Headers.GetValues("Content-Security-Policy").Single());
    }

    /// <summary>Nothing here is authenticated, so it must never face a network.</summary>
    [Fact]
    public void A_non_loopback_bind_is_refused_at_construction()
    {
        var telemetry = new AuthTelemetry(_fx.Config.AuthLogPath, providers: []);
        var monitor = new DirectoryMonitor(_fx.Config, _fx.Engine, _fx.Store, telemetry, _ => { });
        var context = new SuiteContext(_fx.Config, _fx.Engine, _fx.Store, telemetry, monitor);

        _fx.Config.Host = "0.0.0.0";
        try
        {
            Assert.Throws<ArgumentException>(() => new DashboardServer(context, _ => { }));
        }
        finally
        {
            _fx.Config.Host = "127.0.0.1";
        }
    }

    public void Dispose()
    {
        _client.Dispose();
        _server.Dispose();
        _fx.Dispose();
    }
}
