using System.Reflection;
using SecuritySuite.Configuration;

namespace SecuritySuite.Tests;

/// <summary>
/// The release version lives in one place, Directory.Build.props, and reaches
/// everything else through the compiled assembly.
/// </summary>
/// <remarks>
/// These assert the plumbing rather than a literal. Asserting the number itself
/// would put the version back in two places: every bump would break a test and
/// have to be edited alongside the property, which is the duplication this
/// single source of truth exists to remove.
/// </remarks>
public sealed class VersionTests
{
    [Fact]
    public void The_version_is_read_from_the_assembly_rather_than_hardcoded()
    {
        var assembly = typeof(SuiteVersion).Assembly.GetName().Version;

        Assert.NotNull(assembly);
        Assert.Equal(assembly.ToString(3), SuiteVersion.Current);
    }

    /// <summary>
    /// "0.0.0" is the fallback for an assembly with no version stamped. Seeing
    /// it means Directory.Build.props stopped reaching this project.
    /// </summary>
    [Fact]
    public void The_assembly_actually_carries_a_version()
    {
        Assert.NotEqual("0.0.0", SuiteVersion.Current);

        var parts = SuiteVersion.Current.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.All(parts, part => Assert.True(int.TryParse(part, out _), part + " is not numeric"));
    }

    /// <summary>
    /// Every assembly in the suite ships the same version, because the launcher
    /// refuses to reuse a running instance whose version differs from its own.
    /// A Core and a Cli that disagreed would make that check always fail.
    /// </summary>
    [Fact]
    public void Core_and_the_test_assembly_agree_on_the_version()
    {
        var core = typeof(SuiteVersion).Assembly.GetName().Version!.ToString(3);
        var tests = Assembly.GetExecutingAssembly().GetName().Version!.ToString(3);

        Assert.Equal(core, tests);
    }
}
