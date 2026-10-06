using SecuritySuite;

namespace SecuritySuite.Tests;

/// <summary>
/// <see cref="PathUtil"/> decides what a destructive action is allowed to
/// touch, so these cover the ways a path comparison can be fooled rather than
/// just the happy path.
/// </summary>
public sealed class PathUtilTests
{
    [Fact]
    public void Identical_paths_are_within_each_other()
    {
        var dir = Path.GetTempPath();
        Assert.True(PathUtil.IsWithin(dir, dir));
    }

    [Fact]
    public void Child_is_within_parent()
    {
        var parent = Path.Combine(Path.GetTempPath(), "suite-parent");
        var child = Path.Combine(parent, "a", "b", "c.txt");
        Assert.True(PathUtil.IsWithin(child, parent));
    }

    /// <summary>
    /// The bug a naive <c>StartsWith</c> has: a sibling whose name begins with
    /// the root's name is not inside it.
    /// </summary>
    [Theory]
    [InlineData(@"C:\var\logsomething", @"C:\var\log")]
    [InlineData(@"C:\watcher\file.txt", @"C:\watch")]
    [InlineData(@"C:\uploads-old\x", @"C:\uploads")]
    public void Sibling_with_shared_prefix_is_not_within(string path, string root)
    {
        Assert.False(PathUtil.IsWithin(path, root));
    }

    [Fact]
    public void Parent_is_not_within_child()
    {
        var parent = Path.Combine(Path.GetTempPath(), "suite-p");
        Assert.False(PathUtil.IsWithin(parent, Path.Combine(parent, "child")));
    }

    [Fact]
    public void Case_is_ignored_on_windows()
    {
        Assert.True(PathUtil.IsWithin(@"C:\Watch\FILE.TXT", @"c:\watch"));
    }

    [Fact]
    public void Dot_segments_are_resolved_before_comparing()
    {
        // Without normalisation this escapes the root while still looking like
        // a child of it.
        Assert.False(PathUtil.IsWithin(@"C:\watch\..\elsewhere\x", @"C:\watch"));
        Assert.True(PathUtil.IsWithin(@"C:\watch\sub\..\ok.txt", @"C:\watch"));
    }

    [Fact]
    public void Trailing_separators_do_not_change_the_answer()
    {
        Assert.True(PathUtil.IsWithin(@"C:\watch\a.txt", @"C:\watch\"));
        Assert.True(PathUtil.IsWithin(@"C:\watch\", @"C:\watch"));
    }

    [Fact]
    public void Empty_and_null_never_match()
    {
        Assert.False(PathUtil.IsWithin("", @"C:\watch"));
        Assert.False(PathUtil.IsWithin(@"C:\watch", ""));
        Assert.False(PathUtil.IsWithin(null, null));
    }

    /// <summary>
    /// A directory symlink inside a watch path must not grant access to its
    /// target. This is the escape rail 3 exists to stop.
    /// </summary>
    [SymlinkFact]
    public void Symlink_resolves_to_its_target_not_its_location()
    {
        var root = Directory.CreateTempSubdirectory("suite-link").FullName;
        try
        {
            var watched = Path.Combine(root, "watched");
            var outside = Path.Combine(root, "outside");
            Directory.CreateDirectory(watched);
            Directory.CreateDirectory(outside);
            File.WriteAllText(Path.Combine(outside, "secret.txt"), "x");

            var link = Path.Combine(watched, "escape");
            Directory.CreateSymbolicLink(link, outside);

            var viaLink = Path.Combine(link, "secret.txt");

            // It looks like it is inside the watch path...
            Assert.StartsWith(watched, viaLink, StringComparison.OrdinalIgnoreCase);
            // ...but it is not, once the link is resolved.
            Assert.False(PathUtil.IsWithin(viaLink, watched));
            Assert.True(PathUtil.IsWithin(viaLink, outside));
        }
        finally
        {
            TryDelete(root);
        }
    }

    /// <summary>
    /// The ancestor case: resolving only the last component would miss this,
    /// because <c>secret.txt</c> is an ordinary file and the link is above it.
    /// </summary>
    [SymlinkFact]
    public void Link_in_an_ancestor_component_is_resolved()
    {
        var root = Directory.CreateTempSubdirectory("suite-anc").FullName;
        try
        {
            var real = Path.Combine(root, "real", "deep");
            Directory.CreateDirectory(real);
            File.WriteAllText(Path.Combine(real, "secret.txt"), "x");

            var link = Path.Combine(root, "alias");
            Directory.CreateSymbolicLink(link, Path.Combine(root, "real"));

            var viaLink = Path.Combine(link, "deep", "secret.txt");
            Assert.True(PathUtil.IsWithin(viaLink, Path.Combine(root, "real")));
            Assert.False(PathUtil.IsWithin(viaLink, link));
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Nonexistent_paths_still_normalise()
    {
        // Remediation checks run against targets that may already be gone, and
        // a restore target is expected not to exist.
        var missing = Path.Combine(Path.GetTempPath(), "suite-not-here", "x", "y.txt");
        Assert.True(PathUtil.IsWithin(missing, Path.Combine(Path.GetTempPath(), "suite-not-here")));
    }

    [Fact]
    public void Overlaps_is_symmetric()
    {
        var parent = Path.Combine(Path.GetTempPath(), "suite-ov");
        var child = Path.Combine(parent, "c");
        Assert.True(PathUtil.Overlaps(parent, child));
        Assert.True(PathUtil.Overlaps(child, parent));
        Assert.False(PathUtil.Overlaps(parent, Path.Combine(Path.GetTempPath(), "suite-other")));
    }

    internal static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { }
    }
}
