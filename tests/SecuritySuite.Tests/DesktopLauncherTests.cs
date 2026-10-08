using SecuritySuite.Platform;

namespace SecuritySuite.Tests;

/// <summary>What the desktop and startup shortcuts launch, and with which arguments.</summary>
public sealed class DesktopLauncherTests
{
    /// <summary>The startup shortcut runs at every sign-in and must not open a tab each time.</summary>
    [Fact]
    public void The_startup_shortcut_does_not_open_a_browser() =>
        Assert.Equal("--no-browser", DesktopLauncher.Arguments(startup: true));

    /// <summary>
    /// With no console window, a desktop double-click that also opened no
    /// browser would look exactly like a failure to start.
    /// </summary>
    [Fact]
    public void The_desktop_shortcut_opens_the_dashboard() =>
        Assert.Equal("", DesktopLauncher.Arguments(startup: false));

    /// <summary>
    /// The shortcut targets the windowless launcher when it is published beside
    /// the suite, and otherwise falls back to the suite rather than to nothing.
    /// </summary>
    [Fact]
    public void The_shortcut_prefers_the_windowless_launcher_when_present()
    {
        var beside = Path.Combine(Path.GetDirectoryName(DesktopLauncher.ExecutablePath)!,
                                  "securitysuitew.exe");

        Assert.Equal(File.Exists(beside) ? beside : DesktopLauncher.ExecutablePath,
                     DesktopLauncher.LaunchPath);
    }
}
