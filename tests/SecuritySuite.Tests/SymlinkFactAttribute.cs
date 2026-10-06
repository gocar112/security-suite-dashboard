namespace SecuritySuite.Tests;

/// <summary>
/// A <see cref="FactAttribute"/> that skips when this process cannot create a
/// symbolic link.
/// </summary>
/// <remarks>
/// Creating a symlink on Windows needs Developer Mode or elevation, so the
/// tests covering link-escape resolution cannot run everywhere. Reporting them
/// as skipped is the honest outcome: passing them without exercising anything
/// would claim coverage of the escape that rail 3 exists to stop.
/// </remarks>
public sealed class SymlinkFactAttribute : FactAttribute
{
    private static readonly Lazy<string?> Reason = new(Probe, isThreadSafe: true);

    public SymlinkFactAttribute()
    {
        if (Reason.Value is { } why) Skip = why;
    }

    private static string? Probe()
    {
        string? dir = null;
        try
        {
            dir = Directory.CreateTempSubdirectory("suite-symprobe").FullName;
            var target = Path.Combine(dir, "target");
            Directory.CreateDirectory(target);
            Directory.CreateSymbolicLink(Path.Combine(dir, "link"), target);
            return null;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException
                                        or PlatformNotSupportedException)
        {
            return "symbolic links unavailable (needs Developer Mode or elevation): " + exc.Message;
        }
        finally
        {
            if (dir is not null)
            {
                try { Directory.Delete(dir, recursive: true); }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
            }
        }
    }
}
