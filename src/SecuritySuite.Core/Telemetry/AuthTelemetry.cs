using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SecuritySuite.Telemetry;

/// <summary>One source of authentication telemetry.</summary>
public interface ITelemetryProvider
{
    string Name { get; }

    /// <summary>
    /// Collect failures inside the window. Must not throw: a provider that
    /// fails returns a non-ok <see cref="TelemetryResult"/> saying why, so the
    /// chain can report what was tried.
    /// </summary>
    TelemetryResult Collect(int windowMinutes, int maxEvents);
}

/// <summary>
/// Collects recent authentication failures, correlated against a real time
/// window, with a short result cache.
/// </summary>
/// <remarks>
/// <para>
/// The original detector stamped every log line with the current time, so
/// nothing was actually time-filtered and every finding looked like it had
/// coincided with a logon failure. Each provider here parses its own
/// timestamps, and only events genuinely inside the lookback window are
/// returned.
/// </para>
/// <para>
/// Providers are tried in order until one answers, and which one answered is
/// reported. "No failed logons" and "nothing could read the logs" must never
/// look the same to an operator.
/// </para>
/// </remarks>
public sealed class AuthTelemetry
{
    private readonly Lock _gate = new();
    private readonly List<ITelemetryProvider> _providers;
    private readonly double _cacheSeconds;

    private TelemetrySnapshot? _cached;
    private long _cachedAtTicks;

    public int LookbackMinutes { get; }
    public int MaxEvents { get; }
    public string Platform { get; }

    /// <summary>The provider that last answered, or null when none could.</summary>
    public string? ProviderUsed { get; private set; }

    public AuthTelemetry(string authLogPath, int lookbackMinutes = 5,
                         double cacheSeconds = 15.0, int maxEvents = 25,
                         IEnumerable<ITelemetryProvider>? providers = null)
    {
        LookbackMinutes = Math.Max(1, lookbackMinutes);
        MaxEvents = Math.Max(1, maxEvents);
        _cacheSeconds = cacheSeconds;
        Platform = DescribePlatform();
        _providers = [.. providers ?? DefaultProviders(authLogPath)];
    }

    private static string DescribePlatform()
    {
        if (OperatingSystem.IsWindows()) return "windows";
        if (OperatingSystem.IsMacOS()) return "macos";
        if (OperatingSystem.IsLinux()) return "linux";
        return RuntimeInformation.OSDescription;
    }

    /// <summary>
    /// The provider chain for this host.
    /// </summary>
    /// <remarks>
    /// Windows-only in practice, because the YARA binding confines the suite to
    /// Windows. The chain is still a chain rather than a single call so that a
    /// host with a forwarded auth log is not reported as blind just because the
    /// Security log is unreadable, and so the macOS and Linux providers the
    /// Python build had can be restored alongside a cross-platform scan backend
    /// without reworking this class.
    /// </remarks>
    private static IEnumerable<ITelemetryProvider> DefaultProviders(string authLogPath)
    {
        if (OperatingSystem.IsWindows()) yield return new WindowsSecurityLogProvider();
        yield return new AuthLogFileProvider(authLogPath);
    }

    /// <summary>Recent failures, from cache unless it has expired.</summary>
    public TelemetrySnapshot Recent(bool force = false)
    {
        lock (_gate)
        {
            if (!force && _cached is not null)
            {
                var age = (Stopwatch.GetTimestamp() - _cachedAtTicks) / (double)Stopwatch.Frequency;
                if (age < _cacheSeconds) return _cached;
            }
        }

        var snapshot = Collect();
        lock (_gate)
        {
            _cached = snapshot;
            _cachedAtTicks = Stopwatch.GetTimestamp();
        }
        return snapshot;
    }

    /// <summary>Try each provider in turn, reporting what was tried and what answered.</summary>
    private TelemetrySnapshot Collect()
    {
        var attempts = new List<TelemetryAttempt>();
        TelemetryResult? firstFailure = null;

        foreach (var provider in _providers)
        {
            TelemetryResult result;
            try
            {
                result = provider.Collect(LookbackMinutes, MaxEvents);
            }
            catch (Exception exc)
            {
                // A provider must never take down the poll. Catching broadly is
                // deliberate here: these call into the event log and the file
                // system, and an unexpected failure should become a reported
                // "blind" rather than a crashed monitor thread.
                result = TelemetryResult.Fail(TelemetryStatus.Error, provider.Name, exc.Message);
            }

            attempts.Add(new TelemetryAttempt(provider.Name, result.Status, result.Detail));

            if (result.Usable)
            {
                ProviderUsed = provider.Name;
                return Finish(result, attempts);
            }
            firstFailure ??= result;
        }

        // Nothing worked. Report the first provider's diagnosis rather than an
        // empty success, so the dashboard says "blind" and not "quiet".
        ProviderUsed = null;
        return Finish(
            firstFailure ?? TelemetryResult.Fail(TelemetryStatus.Unavailable,
                _providers.FirstOrDefault()?.Name ?? "none",
                "no telemetry provider available"),
            attempts);
    }

    private TelemetrySnapshot Finish(TelemetryResult result, List<TelemetryAttempt> attempts) => new()
    {
        Status = result.Status,
        Source = result.Source,
        Detail = result.Detail,
        Events = result.Events,
        Count = result.Events.Count,
        Path = result.Path,
        WindowMinutes = LookbackMinutes,
        Platform = Platform,
        CollectedAt = DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:sszzz"),
        Attempts = attempts,
    };
}
