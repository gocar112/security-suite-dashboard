using System.Text.RegularExpressions;

namespace SecuritySuite.Telemetry;

/// <summary>
/// Reads authentication failures from a syslog-format text file.
/// </summary>
/// <remarks>
/// <para>
/// Secondary on Windows, where the Security log is the real source. It is kept
/// for two reasons: a host may ship an auth log from an agent or a forwarder,
/// and the tests need a telemetry source they can write to and assert on,
/// which the Security event log is not.
/// </para>
/// <para>
/// Only the tail of the file is read. A few-minute window cannot be anywhere
/// but the end, and an auth log on a busy host is large enough that reading it
/// whole on every poll would be the most expensive thing the suite does.
/// </para>
/// </remarks>
public sealed partial class AuthLogFileProvider(string configuredPath) : ITelemetryProvider
{
    /// <summary>Tail of the file considered, in bytes.</summary>
    private const int TailBytes = 512 * 1024;

    /// <summary>Text auth logs, in the order distributions tend to use them.</summary>
    private static readonly string[] Candidates =
        ["/var/log/auth.log", "/var/log/secure", "/var/log/authlog"];

    /// <summary>
    /// Message fragments meaning "an authentication attempt failed", across the
    /// wording used by sshd, sudo, PAM, loginwindow and opendirectoryd.
    /// </summary>
    private static readonly string[] FailureMarkers =
    [
        "failed password", "invalid user", "authentication failure",
        "failed to authenticate", "authentication failed", "failed publickey",
        "incorrect password", "auth failure", "failed keyboard-interactive",
        "sudo: pam_unix", "failed login",
    ];

    private static readonly string[] Months =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    // "Sep 11 14:23:01 host sshd[1234]: Failed password for invalid user root from 10.0.0.9"
    [GeneratedRegex(@"^(?<mon>[A-Z][a-z]{2})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<rest>.*)$",
        RegexOptions.None, 2000)]
    private static partial Regex SyslogLine();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.ExplicitCapture, 2000)]
    private static partial Regex Ipv4();

    [GeneratedRegex(@"(?:invalid user|user)\s+(?<user>[\w.\-$\\]+)", RegexOptions.IgnoreCase, 2000)]
    private static partial Regex UserName();

    public string Name => "auth_log";

    public TelemetryResult Collect(int windowMinutes, int maxEvents)
    {
        // The configured path first, then the usual names, because
        // distributions disagree about which one they use.
        var tried = new List<string> { configuredPath };
        tried.AddRange(Candidates.Where(c => c != configuredPath));

        var path = tried.FirstOrDefault(c => !string.IsNullOrEmpty(c) && File.Exists(c));
        if (path is null)
        {
            return TelemetryResult.Fail(TelemetryStatus.Unavailable, Name,
                "no text auth log found (tried " +
                string.Join(", ", tried.Where(t => !string.IsNullOrEmpty(t))) + ")");
        }

        var cutoff = DateTime.Now.AddMinutes(-Math.Max(1, windowMinutes));
        var events = new List<AuthEvent>();

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (stream.Length > TailBytes) stream.Seek(-TailBytes, SeekOrigin.End);

            using var reader = new StreamReader(stream);
            if (stream.Position > 0) reader.ReadLine();   // discard the partial first line

            while (reader.ReadLine() is { } line)
            {
                if (!FailureMarkers.Any(m => line.Contains(m, StringComparison.OrdinalIgnoreCase)))
                    continue;

                var when = ParseSyslogTime(line);
                if (when is null || when < cutoff) continue;

                var user = UserName().Match(line);
                var ip = Ipv4().Match(line);
                events.Add(new AuthEvent
                {
                    Timestamp = when.Value.ToString("yyyy-MM-ddTHH:mm:sszzz"),
                    Type = "failed_logon",
                    Account = user.Success ? user.Groups["user"].Value : "unknown",
                    SourceIp = ip.Success ? ip.Value : "",
                    Raw = WindowsSecurityLogProvider.Truncate(line.Trim(), 400),
                });
            }
        }
        catch (UnauthorizedAccessException)
        {
            return TelemetryResult.Fail(TelemetryStatus.Denied, Name,
                "No read permission on " + path);
        }
        catch (IOException exc)
        {
            return TelemetryResult.Fail(TelemetryStatus.Error, Name, exc.Message);
        }

        // Keep the newest when there are more than the cap.
        var result = TelemetryResult.Ok(Name,
            events.Count > maxEvents ? events[^maxEvents..] : events);
        result.Path = path;
        return result;
    }

    /// <summary>
    /// Parse a syslog timestamp, which omits the year.
    /// </summary>
    /// <remarks>
    /// A parsed date more than a day in the future means the log rolled over a
    /// new year and the line belongs to the previous one. Without that
    /// correction every December line looks like it is eleven months away and
    /// falls outside the window.
    /// </remarks>
    internal static DateTime? ParseSyslogTime(string line)
    {
        var match = SyslogLine().Match(line);
        if (!match.Success) return null;

        var month = Array.IndexOf(Months, match.Groups["mon"].Value) + 1;
        if (month == 0) return null;

        var parts = match.Groups["time"].Value.Split(':');
        if (parts.Length != 3) return null;

        var now = DateTime.Now;
        try
        {
            var when = new DateTime(now.Year, month, int.Parse(match.Groups["day"].Value),
                int.Parse(parts[0]), int.Parse(parts[1]), int.Parse(parts[2]), DateTimeKind.Local);
            return when > now.AddDays(1) ? when.AddYears(-1) : when;
        }
        catch (Exception exc) when (exc is ArgumentOutOfRangeException or FormatException)
        {
            return null;
        }
    }
}
