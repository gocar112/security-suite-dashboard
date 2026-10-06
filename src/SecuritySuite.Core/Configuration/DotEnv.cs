namespace SecuritySuite.Configuration;

/// <summary>
/// Reads <c>KEY=value</c> pairs from a local <c>.env</c> so optional adapters
/// can find their credentials without a configuration library.
/// </summary>
/// <remarks>
/// Values already present in the real environment always win, which is what
/// lets a service definition or a CI secret override the developer's file.
/// Nothing here ever writes a key back to disk, and <c>.env</c> stays
/// gitignored: credentials must not reach <c>config.json</c> or a commit.
/// </remarks>
public static class DotEnv
{
    private static bool _loaded;
    private static readonly Lock Gate = new();

    public static void Load(string? path = null)
    {
        lock (Gate)
        {
            if (_loaded && path is null) return;
            _loaded = true;

            var file = path ?? SuitePaths.EnvFile;
            if (!File.Exists(file)) return;

            string[] lines;
            try { lines = File.ReadAllLines(file); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                var split = line.IndexOf('=');
                if (split <= 0) continue;

                var key = line[..split].Trim();
                var value = line[(split + 1)..].Trim().Trim('"', '\'');
                if (key.Length == 0) continue;
                if (Environment.GetEnvironmentVariable(key) is not null) continue;
                Environment.SetEnvironmentVariable(key, value);
            }
        }
    }
}
