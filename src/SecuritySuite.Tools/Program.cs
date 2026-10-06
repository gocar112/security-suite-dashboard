namespace SecuritySuite.Tools;

/// <summary>
/// Repository and maintenance commands, kept out of the suite executable.
/// </summary>
/// <remarks>
/// These replace the Python scripts in <c>tools/</c> and
/// <c>generate_rules.py</c>. They live in a separate assembly because none of
/// them belong in a detector: nobody running the suite should have a
/// repository-mirroring command one typo away.
/// </remarks>
internal static class Program
{
    private const string Usage = """
        suite-tools - maintenance commands for the Security Suite repository

        Usage:
          suite-tools <command> [options]

        Commands:
          generate-rules       build vulnerable-component rules from NVD, gated
                               against a benign corpus
          summarize-database   write a Markdown report of local suite state
          sync-mirror          refresh the read-only mirror repository

        Run a command with --help for its own options.
        """;

    private static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            Console.WriteLine(Usage);
            return args.Length == 0 ? 2 : 0;
        }

        var rest = args[1..];
        try
        {
            return args[0] switch
            {
                "generate-rules" => GenerateRulesCommand.Run(rest),
                "summarize-database" => SummarizeDatabaseCommand.Run(rest),
                "sync-mirror" => SyncMirrorCommand.Run(rest),
                _ => Unknown(args[0]),
            };
        }
        catch (ToolUsageException exc)
        {
            Console.Error.WriteLine("[-] " + exc.Message);
            return 2;
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("[-] " + exc.Message);
            return 1;
        }
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine("[-] Unknown command: " + command);
        Console.Error.WriteLine();
        Console.Error.WriteLine(Usage);
        return 2;
    }
}

internal sealed class ToolUsageException(string message) : Exception(message);
