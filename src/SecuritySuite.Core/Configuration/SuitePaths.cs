namespace SecuritySuite.Configuration;

/// <summary>
/// Where the suite lives on disk.
/// </summary>
/// <remarks>
/// The Python build derived the project root from <c>__file__</c>. A compiled
/// binary has no equivalent: <see cref="AppContext.BaseDirectory"/> is
/// <c>bin/Debug/net10.0-windows/win-x64</c> during development and the install
/// directory in production, and the two need different answers. So we walk up
/// looking for a marker that only the project root carries, and fall back to
/// the binary's own directory when there is none (a published, self-contained
/// layout, where the content sits beside the executable).
/// </remarks>
public static class SuitePaths
{
    private static readonly Lazy<string> RootLazy = new(Discover, isThreadSafe: true);

    /// <summary>Files that identify the project root and not a build output.</summary>
    private static readonly string[] Markers = ["SecuritySuite.sln", "rules", "web"];

    public static string Root => RootLazy.Value;

    public static string ConfigFile => Path.Combine(Root, "config.json");

    public static string EnvFile => Path.Combine(Root, ".env");

    private static string Discover()
    {
        var overridden = Environment.GetEnvironmentVariable("SECURITYSUITE_ROOT");
        if (!string.IsNullOrWhiteSpace(overridden) && Directory.Exists(overridden))
            return Path.GetFullPath(overridden);

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            // "rules" and "web" alone are too generic to trust on their own, so
            // require two of the three markers before accepting a directory.
            var hits = Markers.Count(m =>
                File.Exists(Path.Combine(dir.FullName, m)) ||
                Directory.Exists(Path.Combine(dir.FullName, m)));
            if (hits >= 2)
                return dir.FullName;
            dir = dir.Parent;
        }
        return AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
    }

    /// <summary>Resolve a path that may be relative to the project root.</summary>
    public static string Resolve(string path) =>
        Path.IsPathRooted(path) ? Path.GetFullPath(path) : Path.GetFullPath(Path.Combine(Root, path));
}
