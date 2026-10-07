namespace SecuritySuite.Configuration;

/// <summary>The release version stamped into the compiled Core assembly.</summary>
public static class SuiteVersion
{
    public static string Current { get; } =
        typeof(SuiteVersion).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}
