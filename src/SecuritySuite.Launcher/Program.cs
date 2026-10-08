using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SecuritySuite.Launcher;

/// <summary>
/// Start the suite without a console window.
/// </summary>
/// <remarks>
/// <para>
/// <c>securitysuite.exe</c> is a console program, and has to stay one: <c>--scan</c>
/// prints JSON for a pipe, and Ctrl-C is how a terminal stops it. But a console
/// program started from a shortcut gets a window, and on Windows 11 that window
/// is a Windows Terminal tab, which the shortcut's "run minimised" setting does
/// not reach and which hiding after the fact cannot reliably close.
/// </para>
/// <para>
/// So this launcher is a Windows-subsystem program, which is never given a
/// console, and it starts the suite with <c>CREATE_NO_WINDOW</c>: the suite gets
/// a console that has no window, so nothing appears at all. Its status lines
/// go to <c>data/securitysuite.log</c> instead. The launcher exits as soon as
/// the suite has started, so the suite is the only process left running and the
/// one to end in Task Manager.
/// </para>
/// </remarks>
internal static class Program
{
    private const string Suite = "securitysuite.exe";
    private const string DefaultLog = "data/securitysuite.log";

    private static int Main(string[] args)
    {
        var suite = Path.Combine(AppContext.BaseDirectory, Suite);
        if (!File.Exists(suite))
        {
            // With no window there is nowhere else to say it, and a shortcut
            // that silently does nothing is worse than one that complains.
            Fail(Suite + " was not found next to the launcher:\n" + AppContext.BaseDirectory);
            return 1;
        }

        var start = new ProcessStartInfo(suite)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.CurrentDirectory,
        };
        foreach (var arg in args) start.ArgumentList.Add(arg);

        // Without a window, the log is the only place a failure to start -
        // a busy port, a held workspace lock - can be read afterwards.
        if (!args.Contains("--log"))
        {
            start.ArgumentList.Add("--log");
            start.ArgumentList.Add(DefaultLog);
        }

        try
        {
            using var process = Process.Start(start);
            return process is null ? 1 : 0;
        }
        catch (System.ComponentModel.Win32Exception exc)
        {
            Fail("Could not start " + suite + ":\n" + exc.Message);
            return 1;
        }
    }

    private static void Fail(string message) =>
        _ = MessageBoxW(0, message, "Security Suite", MessageBoxIconError);

    private const uint MessageBoxIconError = 0x10;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(nint owner, string text, string caption, uint type);
}
