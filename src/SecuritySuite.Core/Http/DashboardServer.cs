using System.Collections.Specialized;
using System.Net;
using System.Text;
using System.Text.Json;
using SecuritySuite.Configuration;
using SecuritySuite.Storage;

namespace SecuritySuite.Http;

/// <summary>
/// The dashboard HTTP server: static files, a small JSON API, and a
/// Server-Sent Events stream that pushes findings as they are written.
/// </summary>
/// <remarks>
/// <para>
/// Built on <see cref="HttpListener"/> rather than ASP.NET Core, keeping the
/// Python build's property that the suite depends on nothing but its runtime
/// and its YARA binding. A detection tool with a dozen transitive web
/// dependencies has a dozen more things to patch.
/// </para>
/// <para>
/// Binds loopback only, and refuses to start otherwise: nothing here is
/// authenticated, so exposing it on a network interface would publish an
/// unauthenticated file-deletion API.
/// </para>
/// </remarks>
public sealed class DashboardServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly SuiteContext _ctx;
    private readonly RouteTable _routes;
    private readonly Action<string> _report;
    private readonly CancellationTokenSource _stop = new();
    private readonly string _webRoot;
    private Task? _accepting;

    public int Port { get; }
    public string Host { get; }
    public string Url => "http://" + Host + ":" + Port + "/";

    public DashboardServer(SuiteContext ctx, Action<string>? report = null)
    {
        _ctx = ctx;
        _report = report ?? (message => Console.Error.WriteLine(message));
        Host = ctx.Config.Host;
        Port = ctx.Config.Port;
        _webRoot = Path.GetFullPath(Path.Combine(SuitePaths.Root, "web"));

        if (Host is not ("127.0.0.1" or "localhost"))
        {
            throw new ArgumentException(
                "Dashboard must bind to loopback; remote control is not authenticated");
        }

        _routes = new RouteTable(ctx, _webRoot);
        _listener.Prefixes.Add("http://" + Host + ":" + Port + "/");
    }

    public void Start()
    {
        try
        {
            _listener.Start();
        }
        catch (HttpListenerException exc)
        {
            // 5 is access denied: an unelevated process cannot reserve a
            // prefix unless the URL ACL allows it. Say what to do about it.
            throw new InvalidOperationException(exc.ErrorCode == 5
                ? "Could not bind " + Url + ". Either run as Administrator once, or reserve " +
                  "the prefix with: netsh http add urlacl url=" + Url + " user=" +
                  Environment.UserName
                : "Could not bind " + Url + ": " + exc.Message, exc);
        }
        _accepting = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch (Exception exc) when (exc is HttpListenerException or ObjectDisposedException
                                            or InvalidOperationException)
            {
                return;   // the listener was stopped
            }

            // Fire and forget: one slow SSE client must not stall the accept
            // loop, and every handler catches its own failures.
            _ = Task.Run(() => HandleAsync(context));
        }
    }

    private async Task HandleAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;

        try
        {
            HttpPrimitives.ApplySecurityHeaders(response);

            if (!HttpPrimitives.HostAllowed(request, Port))
            {
                await Json(response, new { error = "host not allowed" }, 403).ConfigureAwait(false);
                return;
            }

            var method = request.HttpMethod.ToUpperInvariant();
            var route = (request.Url?.AbsolutePath ?? "/").TrimEnd('/');
            if (route.Length == 0) route = "/";

            switch (method)
            {
                case "GET":
                case "HEAD":
                    await _routes.GetAsync(route, request, response, method == "HEAD",
                        _stop.Token).ConfigureAwait(false);
                    break;

                case "POST":
                    await _routes.PostAsync(route, request, response, _stop.Token)
                        .ConfigureAwait(false);
                    break;

                default:
                    response.Headers["Allow"] = "GET, HEAD, POST";
                    await Json(response, new { error = "method not allowed" }, 405).ConfigureAwait(false);
                    break;
            }
        }
        catch (Exception exc) when (exc is ArgumentException or FormatException
                                        or JsonException or DecoderFallbackException)
        {
            await TryJson(response, new { error = exc.Message }, 400).ConfigureAwait(false);
        }
        catch (InvalidOperationException exc)
        {
            // Raised when a guarded resource is already busy, e.g. a second
            // inventory scan. A conflict, not a fault.
            await TryJson(response, new { error = exc.Message }, 409).ConfigureAwait(false);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException
                                        or HttpListenerException)
        {
            await TryJson(response,
                new { error = "Local operation failed; inspect permissions and disk space" }, 503)
                .ConfigureAwait(false);
        }
        catch (Exception exc)
        {
            _report("[-] Unhandled request error: " + exc);
            await TryJson(response, new { error = "internal error" }, 500).ConfigureAwait(false);
        }
        finally
        {
            try { response.Close(); }
            catch (Exception exc) when (exc is ObjectDisposedException or HttpListenerException) { }
        }
    }

    internal static async Task Json(HttpListenerResponse response, object payload, int status = 200)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(payload, SuiteJson.Options);
        response.StatusCode = status;
        response.ContentType = "application/json; charset=utf-8";
        response.ContentLength64 = body.Length;
        await response.OutputStream.WriteAsync(body).ConfigureAwait(false);
    }

    /// <summary>Send an error without letting the attempt itself throw.</summary>
    private static async Task TryJson(HttpListenerResponse response, object payload, int status)
    {
        try { await Json(response, payload, status).ConfigureAwait(false); }
        catch (Exception exc) when (exc is IOException or ObjectDisposedException
                                        or HttpListenerException or InvalidOperationException)
        {
            // The client is already gone, or headers were sent. Nothing to do.
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        try { _listener.Stop(); }
        catch (Exception exc) when (exc is ObjectDisposedException or HttpListenerException) { }

        try { _accepting?.Wait(TimeSpan.FromSeconds(3)); }
        catch (AggregateException) { }

        _listener.Close();
        _stop.Dispose();
    }

    /// <summary>Start a dashboard for the given context.</summary>
    public static DashboardServer Serve(SuiteContext ctx, Action<string>? report = null)
    {
        var server = new DashboardServer(ctx, report);
        server.Start();
        return server;
    }
}

/// <summary>Query-string helpers shared by the route table.</summary>
internal static class QueryExtensions
{
    public static string? Get(this NameValueCollection query, string key)
    {
        var value = query[key];
        return string.IsNullOrEmpty(value) ? null : value;
    }

    public static string GetOrEmpty(this NameValueCollection query, string key) =>
        (query[key] ?? "").Trim();
}
