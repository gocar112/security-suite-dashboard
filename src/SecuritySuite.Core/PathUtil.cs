using System.Runtime.InteropServices;
using System.Text;

namespace SecuritySuite;

/// <summary>
/// Path canonicalisation for the remediation rails.
/// </summary>
/// <remarks>
/// <para>
/// Everything a destructive action is allowed to do is decided by comparing a
/// target path against a permitted root, so the comparison has to be honest
/// about the three ways a Windows path can lie about where it points:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Reparse points.</b> A symlink or junction inside a watch path can point
/// anywhere on the volume. The Python build called <c>os.path.realpath</c>;
/// .NET has no single equivalent, because <see cref="Path.GetFullPath(string)"/>
/// normalises <c>.</c> and <c>..</c> but does not follow links at all. So we
/// resolve component by component from the root down: resolving only the final
/// component would miss <c>C:\junction\sub\file</c>, where the link is an
/// ancestor and the leaf is an ordinary file.
/// </description></item>
/// <item><description>
/// <b>8.3 short names.</b> <c>C:\PROGRA~1\x</c> and <c>C:\Program Files\x</c>
/// are the same file but not the same string, and <c>GetFullPath</c> does not
/// expand one into the other. A prefix comparison against an unexpanded short
/// name silently fails to match its own protected root.
/// </description></item>
/// <item><description>
/// <b>Case.</b> Windows paths are case-insensitive, so the comparison must be.
/// </description></item>
/// </list>
/// <para>
/// <see cref="IsWithin"/> compares whole components: <c>C:\var\logs</c> must
/// not count as being inside <c>C:\var\log</c>.
/// </para>
/// </remarks>
public static class PathUtil
{
    private const int MaxLinkHops = 40;
    private static readonly char Sep = Path.DirectorySeparatorChar;

    /// <summary>
    /// Canonical form for comparison: absolute, links resolved, short names
    /// expanded, lower-cased, with no trailing separator.
    /// </summary>
    /// <remarks>
    /// Never throws. A path this cannot parse still has to produce
    /// <em>something</em> comparable, because the callers are security checks
    /// and an exception there would turn a refusal into a crash. An unparseable
    /// path normalises to a lower-cased trim of itself, which will not match any
    /// real root and so fails closed.
    /// </remarks>
    public static string Norm(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";

        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception exc) when (exc is ArgumentException or NotSupportedException
                                        or PathTooLongException or IOException
                                        or System.Security.SecurityException)
        {
            return TrimTrailing(path.Trim()).ToLowerInvariant();
        }

        var resolved = ResolveLinks(full);
        resolved = ExpandShortName(resolved);
        return TrimTrailing(resolved).ToLowerInvariant();
    }

    /// <summary>
    /// True when <paramref name="path"/> is <paramref name="root"/> or sits
    /// beneath it, comparing whole path components.
    /// </summary>
    public static bool IsWithin(string? path, string? root)
    {
        var p = Norm(path);
        var r = Norm(root);
        if (p.Length == 0 || r.Length == 0) return false;
        if (string.Equals(p, r, StringComparison.Ordinal)) return true;
        return p.StartsWith(r + Sep, StringComparison.Ordinal);
    }

    /// <summary>True when either path contains the other.</summary>
    public static bool Overlaps(string? a, string? b) => IsWithin(a, b) || IsWithin(b, a);

    /// <summary>
    /// Follow reparse points one component at a time, from the root down.
    /// </summary>
    /// <remarks>
    /// A path need not exist: remediation checks run against targets that may
    /// already be gone, and a restore target is expected not to exist. Missing
    /// components are simply appended to whatever the existing prefix resolved
    /// to.
    /// </remarks>
    private static string ResolveLinks(string full)
    {
        var root = Path.GetPathRoot(full);
        if (string.IsNullOrEmpty(root)) return full;

        var rest = full[root.Length..]
            .Split([Sep, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);

        var accumulated = root;
        var hops = 0;

        foreach (var segment in rest)
        {
            accumulated = Path.Combine(accumulated, segment);
            try
            {
                var isDir = Directory.Exists(accumulated);
                if (!isDir && !File.Exists(accumulated)) continue;

                // returnFinalTarget walks a whole chain of links for us; null
                // means this component is not a link.
                var target = isDir
                    ? Directory.ResolveLinkTarget(accumulated, returnFinalTarget: true)
                    : File.ResolveLinkTarget(accumulated, returnFinalTarget: true);

                if (target is null) continue;
                if (++hops > MaxLinkHops) break;   // pathological chain; stop here

                accumulated = Path.GetFullPath(target.FullName);
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException
                                            or ArgumentException or NotSupportedException
                                            or System.Security.SecurityException)
            {
                // A cyclic link, a denied directory, or a path we cannot stat.
                // Keep the unresolved form: it fails the confinement check
                // rather than being wrongly admitted.
            }
        }
        return accumulated;
    }

    /// <summary>
    /// Expand an 8.3 short path to its long form, best effort.
    /// </summary>
    /// <remarks>
    /// Only meaningful for a path that exists; <c>GetLongPathNameW</c> returns 0
    /// otherwise, and we keep the input. Short names can be disabled per volume,
    /// in which case this is a no-op, which is fine.
    /// </remarks>
    private static string ExpandShortName(string path)
    {
        if (!OperatingSystem.IsWindows()) return path;
        if (!path.Contains('~')) return path;   // no short component to expand

        try
        {
            var buffer = new StringBuilder(1024);
            var length = GetLongPathNameW(path, buffer, buffer.Capacity);
            if (length == 0) return path;
            if (length > buffer.Capacity)
            {
                buffer = new StringBuilder((int)length + 1);
                length = GetLongPathNameW(path, buffer, buffer.Capacity);
                if (length == 0) return path;
            }
            return buffer.ToString();
        }
        catch (Exception exc) when (exc is EntryPointNotFoundException or DllNotFoundException)
        {
            return path;
        }
    }

    private static string TrimTrailing(string path)
    {
        if (path.Length <= 1) return path;
        var trimmed = path.TrimEnd(Sep, Path.AltDirectorySeparatorChar);
        // "C:\" trims to "C:", which is still a usable prefix root. But do not
        // trim a bare UNC or POSIX root away to nothing.
        return trimmed.Length == 0 ? path[..1] : trimmed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetLongPathNameW(string shortPath, StringBuilder longPath, int bufferLength);
}
