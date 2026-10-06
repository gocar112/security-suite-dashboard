using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecuritySuite.Storage;

namespace SecuritySuite.Inventory;

/// <summary>
/// Explicit, bounded household IPv4 inventory. No background or automatic scans.
/// </summary>
/// <remarks>
/// <para>
/// Only RFC 1918 address blocks are allowed, and only an explicit canonical CIDR
/// from /24 to /32. Discovery is an ARP/neighbour cache read plus one ICMP echo
/// per host; optional TCP connects send no application data. Service names are
/// port labels, not verified product identities, and nothing here attempts
/// authentication or configuration.
/// </para>
/// <para>
/// One scan at a time. A new scan replaces the device list; cancellation keeps
/// partial results and stops submitting work immediately, with the terminal
/// state following worker cleanup.
/// </para>
/// </remarks>
public sealed partial class NetworkInventory(EventStore? store)
{
    private const int MaxWorkers = 16;
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromMilliseconds(400);
    private static readonly TimeSpan PingTimeout = TimeSpan.FromMilliseconds(750);

    /// <summary>Only these blocks may ever be scanned. See RFC 1918.</summary>
    public static readonly (IPAddress Network, int Prefix)[] Rfc1918 =
    [
        (IPAddress.Parse("10.0.0.0"), 8),
        (IPAddress.Parse("172.16.0.0"), 12),
        (IPAddress.Parse("192.168.0.0"), 16),
    ];

    private static readonly (int Port, string Name)[] ServicePorts =
    [
        (22, "ssh"), (53, "dns"), (80, "http"), (443, "https"),
        (445, "smb"), (554, "rtsp"), (631, "ipp"), (3389, "rdp"),
    ];

    [GeneratedRegex(@"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:2[4-9]|3[0-2])$", RegexOptions.None, 2000)]
    private static partial Regex ScopeFormat();

    [GeneratedRegex(@"(?<![\w.:])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.:])", RegexOptions.None, 2000)]
    private static partial Regex Ipv4Token();

    [GeneratedRegex(@"(?<![\w:.-])(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}(?![\w:.-])",
        RegexOptions.None, 2000)]
    private static partial Regex MacToken();

    [GeneratedRegex(@"\b(?:FAILED|INCOMPLETE)\b", RegexOptions.IgnoreCase, 2000)]
    private static partial Regex DeadNeighbour();

    private readonly Lock _gate = new();
    private readonly Dictionary<string, InventoryDevice> _devices = new(StringComparer.Ordinal);
    private CancellationTokenSource? _cancel;
    private Task? _worker;
    private string _state = "idle";
    private string? _scope;
    private string? _lastScan;
    private string? _error;

    // ------------------------------------------------------------- validation
    /// <summary>
    /// Accept a canonical, explicit RFC 1918 IPv4 CIDR from /24 through /32.
    /// </summary>
    /// <remarks>
    /// Bare addresses, netmask notation, host bits, IPv6 and every other address
    /// class are rejected before any socket or subprocess runs. The format check
    /// comes first so a malformed string never reaches the parser.
    /// </remarks>
    public static IpRange ValidateScope(string? cidr)
    {
        if (cidr is null || !ScopeFormat().IsMatch(cidr))
            throw new ArgumentException("Use an explicit RFC1918 IPv4 CIDR from /24 through /32.");

        var parts = cidr.Split('/');
        if (!IPAddress.TryParse(parts[0], out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Use an explicit RFC1918 IPv4 CIDR from /24 through /32.");
        }

        var prefix = int.Parse(parts[1]);
        var range = new IpRange(address, prefix);

        if (!range.IsCanonical)
            throw new ArgumentException("Use a canonical IPv4 network address without host bits.");

        if (!Rfc1918.Any(block => range.IsSubnetOf(new IpRange(block.Network, block.Prefix))))
            throw new ArgumentException("Only RFC1918 private IPv4 networks are allowed.");

        return range;
    }

    public static bool IsPrivate(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork &&
        Rfc1918.Any(block => new IpRange(block.Network, block.Prefix).Contains(address));

    // ----------------------------------------------------------------- status
    public InventoryStatus Status()
    {
        lock (_gate)
        {
            return new InventoryStatus
            {
                State = _state,
                Scope = _scope,
                Devices = [.. _devices.Values
                    .OrderBy(d => IpRange.ToUInt(IPAddress.Parse(d.Ip)))
                    .Select(d => d.Copy())],
                LastScan = _lastScan,
                Error = _error,
            };
        }
    }

    /// <summary>
    /// Push a snapshot to live clients.
    /// </summary>
    /// <remarks>
    /// Broadcast, never stored: an inventory snapshot is UI state, not a
    /// detection, and writing it to the findings log would pollute the alert
    /// history with routine scans.
    /// </remarks>
    private void Broadcast()
    {
        if (store is null) return;
        try
        {
            var snapshot = Status();
            var entry = new SuiteEvent
            {
                EventType = "inventory_status",
                Timestamp = EventStore.NowIso(),
            };
            entry.SetExtra("state", snapshot.State);
            entry.SetExtra("scope", snapshot.Scope);
            entry.SetExtra("devices", snapshot.Devices);
            entry.SetExtra("last_scan", snapshot.LastScan);
            entry.SetExtra("error", snapshot.Error);
            store.Broadcast(entry);
        }
        catch (Exception exc) when (exc is IOException or InvalidOperationException)
        {
            // A failed UI event sink must not prevent worker cleanup.
        }
    }

    // ------------------------------------------------------------------ start
    public InventoryStatus Start(string cidr, bool services = false)
    {
        var scope = ValidateScope(cidr);

        lock (_gate)
        {
            if (_worker is not null && !_worker.IsCompleted)
                throw new InvalidOperationException("An inventory scan is already running or cancelling.");

            _scope = scope.ToString();
            _devices.Clear();
            _state = "running";
            _error = null;
            _cancel?.Dispose();
            _cancel = new CancellationTokenSource();
            var token = _cancel.Token;

            Broadcast();
            _worker = Task.Run(() => ScanAsync(scope, services, token), CancellationToken.None);
            return Status();
        }
    }

    public InventoryStatus Cancel()
    {
        lock (_gate)
        {
            if (_state == "running")
            {
                _cancel?.Cancel();
                _state = "cancelling";
                Broadcast();
            }
            return Status();
        }
    }

    private void Record(InventoryDevice device)
    {
        lock (_gate)
        {
            if (_devices.TryGetValue(device.Ip, out var existing))
            {
                // Merge rather than replace: the cache read supplies a MAC and
                // the probe supplies services, and whichever lands second must
                // not erase the other.
                device.Mac = device.Mac.Length > 0 ? device.Mac : existing.Mac;
                device.Hostname = device.Hostname.Length > 0 ? device.Hostname : existing.Hostname;
                if (device.Services.Count == 0) device.Services = existing.Services;
            }
            _devices[device.Ip] = device;
        }
    }

    private async Task ScanAsync(IpRange scope, bool services, CancellationToken token)
    {
        var deadline = Stopwatch.StartNew();
        var state = "complete";
        string? error = null;

        try
        {
            ReadNeighbourCache(scope, deadline, token);

            var hosts = scope.Hosts().GetEnumerator();
            var pending = new List<Task<InventoryDevice?>>(MaxWorkers);

            while (!Stopped(deadline, token))
            {
                while (pending.Count < MaxWorkers && !Stopped(deadline, token))
                {
                    if (!hosts.MoveNext()) break;
                    var ip = hosts.Current.ToString();
                    pending.Add(ProbeAsync(ip, services, deadline, token));
                }
                if (pending.Count == 0) break;

                var finished = await Task.WhenAny(pending).ConfigureAwait(false);
                pending.Remove(finished);

                var device = await finished.ConfigureAwait(false);
                if (device is not null && !Stopped(deadline, token)) Record(device);
            }

            // Drain what is already in flight: a cancelled scan keeps partial
            // results, and abandoning these tasks would leak sockets.
            foreach (var task in pending)
            {
                try
                {
                    var device = await task.ConfigureAwait(false);
                    if (device is not null && !token.IsCancellationRequested) Record(device);
                }
                catch (Exception exc) when (exc is SocketException or OperationCanceledException) { }
            }

            if (!Stopped(deadline, token)) ReadNeighbourCache(scope, deadline, token);

            if (token.IsCancellationRequested) state = "cancelled";
            else if (deadline.Elapsed >= ScanTimeout)
            {
                state = "error";
                error = "Inventory scan exceeded its time limit; results are partial.";
            }
        }
        catch (Exception)
        {
            state = "error";
            error = "Inventory scan failed; check local ICMP availability and permissions.";
        }
        finally
        {
            lock (_gate)
            {
                _state = state;
                _error = error;
                _lastScan = EventStore.NowIso();
            }
            Broadcast();
        }
    }

    private static bool Stopped(Stopwatch deadline, CancellationToken token) =>
        token.IsCancellationRequested || deadline.Elapsed >= ScanTimeout;

    /// <summary>
    /// One ICMP echo, then optional TCP connects.
    /// </summary>
    /// <remarks>
    /// Uses <see cref="Ping"/> rather than shelling out. The Python build ran
    /// <c>ping.exe</c> and then had to re-parse its output, because Windows
    /// returns exit code 0 for an ICMP destination-unreachable reply — so a
    /// router answering on behalf of an absent host looked alive. A managed
    /// <see cref="IPStatus"/> has no such ambiguity.
    /// </remarks>
    private static async Task<InventoryDevice?> ProbeAsync(string ip, bool services,
                                                            Stopwatch deadline, CancellationToken token)
    {
        if (Stopped(deadline, token)) return null;

        var alive = false;
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, PingTimeout).ConfigureAwait(false);
            alive = reply.Status == IPStatus.Success;
        }
        catch (Exception exc) when (exc is PingException or SocketException or InvalidOperationException)
        {
            // ICMP may be unavailable to an unprivileged process. If service
            // probing is on we can still learn something; if not, this host is
            // simply unknown.
            if (!services) return null;
        }

        var found = new List<InventoryService>();
        if (services)
        {
            foreach (var (port, name) in ServicePorts)
            {
                if (Stopped(deadline, token)) break;
                if (await ConnectAsync(ip, port, token).ConfigureAwait(false))
                    found.Add(new InventoryService(port, name));
            }
        }

        if (Stopped(deadline, token) || (!alive && found.Count == 0)) return null;

        return new InventoryDevice
        {
            Ip = ip,
            Services = found,
            LastSeen = EventStore.NowIso(),
        };
    }

    /// <summary>A bare TCP handshake. No application data is ever sent.</summary>
    private static async Task<bool> ConnectAsync(string ip, int port, CancellationToken token)
    {
        try
        {
            using var client = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(ConnectTimeout);

            await client.ConnectAsync(IPAddress.Parse(ip), port, timeout.Token).ConfigureAwait(false);
            return client.Connected;
        }
        catch (Exception exc) when (exc is SocketException or OperationCanceledException
                                        or ObjectDisposedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Read the OS neighbour cache for MAC addresses.
    /// </summary>
    /// <remarks>
    /// .NET exposes no managed neighbour table, so this shells out. A cached
    /// entry proves the host was seen, not that it is online now, which is why
    /// <see cref="InventoryDevice.LastSeen"/> is documented as an observation
    /// rather than a liveness claim.
    /// </remarks>
    private void ReadNeighbourCache(IpRange scope, Stopwatch deadline, CancellationToken token)
    {
        var commands = OperatingSystem.IsWindows()
            ? new[] { ("arp", "-a") }
            : OperatingSystem.IsMacOS()
                ? [("arp", "-an")]
                : [("ip", "-4 neigh show"), ("arp", "-an")];

        foreach (var (file, arguments) in commands)
        {
            if (Stopped(deadline, token)) return;

            string output;
            try
            {
                output = RunQuiet(file, arguments);
            }
            catch (Exception exc) when (exc is IOException or InvalidOperationException
                                            or System.ComponentModel.Win32Exception)
            {
                continue;
            }
            if (output.Length == 0) continue;

            foreach (var (ip, mac) in ParseNeighbours(output, scope))
            {
                Record(new InventoryDevice { Ip = ip, Mac = mac, LastSeen = EventStore.NowIso() });
            }
            return;
        }
    }

    private static string RunQuiet(string file, string arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(file, arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        process.Start();
        process.StandardInput.Close();

        var output = process.StandardOutput.ReadToEnd();
        if (!process.WaitForExit((int)ProcessTimeout.TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); }
            catch (Exception exc) when (exc is InvalidOperationException or NotSupportedException) { }
            return "";
        }
        return process.ExitCode == 0 ? output : "";
    }

    /// <summary>
    /// Pull (ip, mac) pairs out of neighbour-table output.
    /// </summary>
    /// <remarks>
    /// Entries marked FAILED or INCOMPLETE are skipped, as are all-zero MACs and
    /// any with the multicast bit set in the first octet — a multicast MAC is
    /// not a host's own hardware address, so reporting one as a device would be
    /// wrong.
    /// </remarks>
    internal static List<(string Ip, string Mac)> ParseNeighbours(string output, IpRange scope)
    {
        var results = new List<(string, string)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var line in output.Split('\n'))
        {
            if (DeadNeighbour().IsMatch(line)) continue;

            var ipMatch = Ipv4Token().Match(line);
            var macMatch = MacToken().Match(line);
            if (!ipMatch.Success || !macMatch.Success) continue;

            if (!IPAddress.TryParse(ipMatch.Value, out var address)) continue;
            if (!scope.Contains(address) || address.Equals(scope.NetworkAddress)) continue;
            if (!seen.Add(ipMatch.Value)) continue;

            var octets = macMatch.Value.Split(':', '-')
                .Select(part => Convert.ToInt32(part, 16)).ToArray();
            if (octets.All(o => o == 0)) continue;
            if ((octets[0] & 1) != 0) continue;

            results.Add((ipMatch.Value, string.Join(":", octets.Select(o => o.ToString("x2")))));
        }
        return results;
    }
}

/// <summary>An IPv4 CIDR range, with the arithmetic the scanner needs.</summary>
public readonly struct IpRange(IPAddress network, int prefix)
{
    public IPAddress NetworkAddress { get; } = network;
    public int Prefix { get; } = prefix;

    public static uint ToUInt(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static IPAddress FromUInt(uint value) => new IPAddress(
    [
        (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value,
    ]);

    public uint Mask => Prefix == 0 ? 0 : uint.MaxValue << (32 - Prefix);

    /// <summary>True when no host bits are set, i.e. this really is a network address.</summary>
    public bool IsCanonical => (ToUInt(NetworkAddress) & ~Mask) == 0;

    public bool Contains(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork &&
        (ToUInt(address) & Mask) == (ToUInt(NetworkAddress) & Mask);

    public bool IsSubnetOf(IpRange other) =>
        Prefix >= other.Prefix && other.Contains(NetworkAddress);

    /// <summary>
    /// The usable host addresses in this range.
    /// </summary>
    /// <remarks>
    /// A /31 or /32 has no network or broadcast address to exclude, so every
    /// address in it is a host. Treating them like a larger range would yield
    /// nothing to scan.
    /// </remarks>
    public IEnumerable<IPAddress> Hosts()
    {
        var first = ToUInt(NetworkAddress) & Mask;
        var last = first | ~Mask;

        if (Prefix >= 31)
        {
            for (var value = first; value <= last; value++) yield return FromUInt(value);
            yield break;
        }
        for (var value = first + 1; value < last; value++) yield return FromUInt(value);
    }

    public override string ToString() => NetworkAddress + "/" + Prefix;
}

public sealed record InventoryService(
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("name")] string Name);

public sealed class InventoryDevice
{
    [JsonPropertyName("ip")] public string Ip { get; set; } = "";

    /// <summary>
    /// Deliberately left empty. Reverse DNS cannot be allowed to hold up
    /// discovery, and a PTR record is not a trustworthy identity anyway.
    /// </summary>
    [JsonPropertyName("hostname")] public string Hostname { get; set; } = "";

    [JsonPropertyName("mac")] public string Mac { get; set; } = "";

    /// <summary>Port labels, not verified product identities.</summary>
    [JsonPropertyName("services")] public List<InventoryService> Services { get; set; } = [];

    /// <summary>
    /// When this host was observed by a probe or a cache read. Not proof that a
    /// cached neighbour is online now.
    /// </summary>
    [JsonPropertyName("last_seen")] public string LastSeen { get; set; } = "";

    public InventoryDevice Copy() => new()
    {
        Ip = Ip,
        Hostname = Hostname,
        Mac = Mac,
        Services = [.. Services],
        LastSeen = LastSeen,
    };
}

public sealed class InventoryStatus
{
    /// <summary>idle, running, cancelling, cancelled, complete or error.</summary>
    [JsonPropertyName("state")] public string State { get; set; } = "idle";

    [JsonPropertyName("scope")] public string? Scope { get; set; }
    [JsonPropertyName("devices")] public List<InventoryDevice> Devices { get; set; } = [];
    [JsonPropertyName("last_scan")] public string? LastScan { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}
