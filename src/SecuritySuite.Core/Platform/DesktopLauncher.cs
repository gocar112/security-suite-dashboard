using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Text;
using SecuritySuite.Configuration;

namespace SecuritySuite.Platform;

/// <summary>
/// Creates and removes the desktop and startup shortcuts.
/// </summary>
/// <remarks>
/// <para>
/// Windows only, because the suite is: the YARA binding is a C++/CLI assembly
/// with no Linux or macOS runtime assets. The Python build created a
/// <c>.desktop</c> entry and a macOS <c>.app</c> too, and those are dropped
/// rather than kept as launchers that would start something unable to load its
/// scanner.
/// </para>
/// <para>
/// Nothing is installed system-wide and nothing needs elevation. Shortcuts go
/// in the per-user Desktop or Startup folder.
/// </para>
/// <para>
/// They point at <c>securitysuitew.exe</c>, the windowless launcher, when it
/// sits beside the suite. <c>securitysuite.exe</c> is a console program, so a
/// shortcut aimed straight at it opens a terminal window that stays for as long
/// as the suite runs - at every sign-in, for the startup shortcut.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class DesktopLauncher
{
    private const string ShortcutName = "Security Suite.lnk";

    private const string Description =
        "Security Suite - YARA SOC detector with a live dashboard";

    /// <summary>Where the shortcut should point, preferring a published executable.</summary>
    public static string ExecutablePath
    {
        get
        {
            var current = Environment.ProcessPath;

            // Running under `dotnet run` the process is dotnet.exe, which would
            // make a shortcut that launches the SDK rather than the suite.
            if (current is not null &&
                !Path.GetFileName(current).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
            {
                return current;
            }

            var guess = Path.Combine(AppContext.BaseDirectory, "securitysuite.exe");
            return File.Exists(guess) ? guess : current ?? guess;
        }
    }

    /// <summary>
    /// What the shortcut launches: the windowless launcher when it is present,
    /// otherwise the suite itself, console window and all.
    /// </summary>
    public static string LaunchPath
    {
        get
        {
            var launcher = Path.Combine(Path.GetDirectoryName(ExecutablePath) ?? AppContext.BaseDirectory,
                                        LauncherName);
            return File.Exists(launcher) ? launcher : ExecutablePath;
        }
    }

    private const string LauncherName = "securitysuitew.exe";

    /// <summary>
    /// The startup shortcut runs quietly at sign-in. The desktop one opens the
    /// dashboard: with no window, a double-click that opened nothing would look
    /// like it had failed. A second click finds the running instance and opens
    /// that instead of starting another.
    /// </summary>
    public static string Arguments(bool startup) => startup ? "--no-browser" : "";

    public static string DesktopDirectory =>
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    public static string StartupDirectory =>
        Environment.GetFolderPath(Environment.SpecialFolder.Startup);

    public static string IconPath
    {
        get
        {
            // A .lnk needs a real .ico; the PNG and SVG are for other surfaces.
            var ico = Path.Combine(SuitePaths.Root, "assets", "securitysuite.ico");
            return File.Exists(ico) ? ico : ExecutablePath;
        }
    }

    public static string TargetPath(bool startup) =>
        Path.Combine(startup ? StartupDirectory : DesktopDirectory, ShortcutName);

    /// <summary>Create the shortcut, returning where it was written.</summary>
    public static string Install(bool startup = false)
    {
        var target = TargetPath(startup);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);

        var instance = Activator.CreateInstance(Type.GetTypeFromCLSID(ShellLinkClsid)!)
            ?? throw new COMException("Could not create a shell link object");
        try
        {
            var link = (IShellLinkW)instance;
            link.SetPath(LaunchPath);
            link.SetArguments(Arguments(startup));
            link.SetWorkingDirectory(SuitePaths.Root);
            link.SetDescription(Description);
            link.SetIconLocation(IconPath, 0);

            ((IPersistFile)instance).Save(target, fRemember: true);
            return target;
        }
        finally
        {
            Marshal.FinalReleaseComObject(instance);
        }
    }

    /// <summary>Remove the shortcut. Returns true when one was actually there.</summary>
    public static bool Remove(bool startup = false)
    {
        var target = TargetPath(startup);
        if (!File.Exists(target)) return false;

        File.Delete(target);
        return true;
    }

    /// <summary>Where a shortcut currently exists, for the status report.</summary>
    public static (bool Desktop, bool Startup) Installed() =>
        (File.Exists(TargetPath(false)), File.Exists(TargetPath(true)));

    // ------------------------------------------------------------------- COM
    // The shell's own shortcut interfaces. The alternative is shelling out to
    // PowerShell to drive WScript.Shell, which is what the Python build had to
    // do; calling the interface directly needs no child process and no
    // dependency.
    /// <summary>CLSID_ShellLink. The object is created from this, not from a coclass type.</summary>
    private static readonly Guid ShellLinkClsid = new("00021401-0000-0000-C000-000000000046");

    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder file,
                     int maxPath, nint findData, int flags);
        void GetIDList(out nint idList);
        void SetIDList(nint idList);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder name, int maxName);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string name);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder dir, int maxPath);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string dir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder args, int maxArgs);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string args);
        void GetHotkey(out short hotkey);
        void SetHotkey(short hotkey);
        void GetShowCmd(out int showCmd);
        void SetShowCmd(int showCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder iconPath,
                             int iconPathLength, out int iconIndex);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string iconPath, int iconIndex);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string relative, int reserved);
        void Resolve(nint window, int flags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string file);
    }
}
