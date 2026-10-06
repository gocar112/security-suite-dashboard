using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace SecuritySuite.Telemetry;

/// <summary>
/// Reads authentication failures from the Windows Security event log.
/// </summary>
/// <remarks>
/// <para>
/// Needs Administrator: the Security log is readable only with
/// SeSecurityPrivilege, so an unelevated run reports <c>denied</c> rather than
/// an empty success.
/// </para>
/// <para>
/// The filtering happens in the log engine, not here. The Python build needed
/// the optional <c>pywin32</c> package and, lacking a query API, read records
/// backwards and discarded anything that was not one of the five event IDs,
/// capping the walk at 4,000 records to stop it running away. The XPath query
/// below pushes both the event-ID set and the time window into the log itself,
/// so the host returns only matching records and the 4,000-record safety valve
/// is unnecessary.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsSecurityLogProvider : ITelemetryProvider
{
    /// <summary>The logon-failure events worth correlating, and what each means.</summary>
    private static readonly Dictionary<int, string> Labels = new()
    {
        [4625] = "failed_logon",
        [4648] = "explicit_credential_logon",
        [4740] = "account_lockout",
        [4771] = "kerberos_preauth_failed",
        [4776] = "credential_validation_failed",
    };

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.ExplicitCapture, 2000)]
    private static partial Regex Ipv4();

    public string Name => "windows_security_log";

    public TelemetryResult Collect(int windowMinutes, int maxEvents)
    {
        var milliseconds = Math.Max(1, windowMinutes) * 60_000L;
        var ids = string.Join(" or ", Labels.Keys.Select(id => "EventID=" + id));
        var xpath = $"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]";

        var events = new List<AuthEvent>();
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, xpath)
            {
                ReverseDirection = true,   // newest first, so maxEvents keeps the recent ones
            };
            using var reader = new EventLogReader(query);

            while (events.Count < maxEvents)
            {
                using var record = reader.ReadEvent();
                if (record is null) break;

                var id = record.Id;
                if (!Labels.TryGetValue(id, out var label)) continue;

                var inserts = Inserts(record);
                events.Add(new AuthEvent
                {
                    Timestamp = (record.TimeCreated ?? DateTime.Now)
                        .ToString("yyyy-MM-ddTHH:mm:sszzz"),
                    Type = label,
                    EventId = id,
                    Account = PickAccount(inserts),
                    SourceIp = PickIp(inserts),
                    Raw = Truncate(string.Join(" | ", inserts.Where(i => i.Length > 0 && i != "-")), 400),
                });
            }
            return TelemetryResult.Ok(Name, events);
        }
        catch (UnauthorizedAccessException)
        {
            return TelemetryResult.Fail(TelemetryStatus.Denied, Name,
                "Access denied reading the Security log - relaunch the suite as " +
                "Administrator to enable logon correlation.");
        }
        catch (EventLogNotFoundException exc)
        {
            return TelemetryResult.Fail(TelemetryStatus.Unavailable, Name, exc.Message);
        }
        catch (EventLogException exc)
        {
            // EventLogException covers both "you may not read this" and real
            // failures, and only the message distinguishes them.
            var text = exc.Message;
            var denied = text.Contains("access", StringComparison.OrdinalIgnoreCase) &&
                         text.Contains("denied", StringComparison.OrdinalIgnoreCase);
            return TelemetryResult.Fail(
                denied ? TelemetryStatus.Denied : TelemetryStatus.Error, Name,
                denied
                    ? "Access denied reading the Security log - relaunch the suite as " +
                      "Administrator to enable logon correlation."
                    : text);
        }
    }

    private static List<string> Inserts(EventRecord record)
    {
        try
        {
            return [.. (record.Properties ?? []).Select(p => p.Value?.ToString() ?? "")];
        }
        catch (EventLogException)
        {
            return [];
        }
    }

    /// <summary>
    /// The account the failure was against.
    /// </summary>
    /// <remarks>
    /// In a 4625 the inserts are [0] subject SID, [1] subject user name, and
    /// [5] target user name. The target is the account someone tried to use, so
    /// it is preferred; the subject is the fallback.
    /// </remarks>
    private static string PickAccount(List<string> inserts)
    {
        foreach (var index in (int[])[5, 1])
        {
            if (inserts.Count > index && inserts[index].Length > 0 && inserts[index] != "-")
                return inserts[index];
        }
        return "unknown";
    }

    private static string PickIp(List<string> inserts)
    {
        foreach (var value in inserts)
        {
            var match = Ipv4().Match(value);
            if (match.Success) return match.Value;
        }
        return "";
    }

    internal static string Truncate(string value, int length) =>
        value.Length <= length ? value : value[..length];
}
