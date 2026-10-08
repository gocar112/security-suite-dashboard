namespace SecuritySuite.Cli;

/// <summary>
/// Command-line options, parsed by hand.
/// </summary>
/// <remarks>
/// No parsing library. The whole surface is fourteen flags, and the suite's claim
/// to depend on nothing but its runtime and its YARA binding is worth more than
/// the fifty lines this saves.
/// </remarks>
internal sealed class CliOptions
{
    public string? Host { get; private set; }
    public int? Port { get; private set; }
    public List<string> Watch { get; } = [];
    public string? RulesDir { get; private set; }
    public string? ScanTarget { get; private set; }
    public bool Headless { get; private set; }
    public bool NoBrowser { get; private set; }
    public bool ScanExisting { get; private set; }
    public bool ShowHelp { get; private set; }
    public bool ShowVersion { get; private set; }

    /// <summary>Create the desktop (or startup) shortcut and exit.</summary>
    public bool InstallShortcut { get; private set; }

    /// <summary>Remove the shortcut and exit.</summary>
    public bool RemoveShortcut { get; private set; }

    /// <summary>Act on the Startup folder rather than the Desktop.</summary>
    public bool Startup { get; private set; }

    /// <summary>Append all output to this file instead of the console.</summary>
    public string? LogFile { get; private set; }

    public const string Usage = """
        securitysuite - YARA-backed SOC detection suite with a live dashboard

        Usage:
          securitysuite [options]

        Options:
          --host ADDRESS      bind address (default 127.0.0.1; loopback only)
          --port PORT         dashboard port (default 8787)
          --watch DIR         directory to monitor (repeatable, replaces config)
          --rules DIR         rules directory
          --scan PATH         scan a file or directory, print JSON to stdout, exit
          --headless          monitor only, no dashboard server
          --no-browser        do not open a browser window
          --scan-existing     scan files already present at startup
          --log FILE          append all output to FILE instead of the console
                              (relative paths are under the project root)

          --install-shortcut  create a desktop shortcut and exit
          --remove-shortcut   remove the shortcut and exit
          --startup           with the two above, act on the Startup folder
                              instead, so the suite runs at sign-in

          -h, --help          show this help
          -v, --version       show the version

        Diagnostics are written to stderr, so --scan output can be piped:
          securitysuite --scan C:\\Users\\me\\Downloads > report.json
        """;

    public static CliOptions Parse(string[] args)
    {
        var options = new CliOptions();

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "-h" or "--help":
                    options.ShowHelp = true;
                    return options;

                case "-v" or "--version":
                    options.ShowVersion = true;
                    return options;

                case "--headless":
                    options.Headless = true;
                    break;

                case "--no-browser":
                    options.NoBrowser = true;
                    break;

                case "--scan-existing":
                    options.ScanExisting = true;
                    break;

                case "--install-shortcut":
                    options.InstallShortcut = true;
                    break;

                case "--remove-shortcut":
                    options.RemoveShortcut = true;
                    break;

                case "--startup":
                    options.Startup = true;
                    break;

                case "--host":
                    options.Host = Next(args, ref i, "--host");
                    break;

                case "--rules":
                    options.RulesDir = Next(args, ref i, "--rules");
                    break;

                case "--scan":
                    options.ScanTarget = Next(args, ref i, "--scan");
                    break;

                case "--log":
                    options.LogFile = Next(args, ref i, "--log");
                    break;

                case "--watch":
                    options.Watch.Add(Next(args, ref i, "--watch"));
                    break;

                case "--port":
                    {
                        var value = Next(args, ref i, "--port");
                        if (!int.TryParse(value, out var port) || port is < 1 or > 65535)
                            throw new CliUsageException("--port must be a number between 1 and 65535");
                        options.Port = port;
                        break;
                    }

                default:
                    throw new CliUsageException("Unknown option: " + arg);
            }
        }
        return options;
    }

    private static string Next(string[] args, ref int index, string flag)
    {
        if (index + 1 >= args.Length) throw new CliUsageException(flag + " needs a value");

        var value = args[++index];

        // A following flag almost always means the value was forgotten, and
        // silently consuming it produces a baffling failure later.
        if (value.StartsWith("--", StringComparison.Ordinal))
            throw new CliUsageException(flag + " needs a value, got " + value);

        return value;
    }
}
