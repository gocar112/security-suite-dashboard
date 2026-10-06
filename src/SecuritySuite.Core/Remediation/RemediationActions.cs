namespace SecuritySuite.Remediation;

/// <summary>
/// The four remediation actions, and which of them an unattended rule may use.
/// </summary>
public static class RemediationActions
{
    public const string Delete = "delete";
    public const string Quarantine = "quarantine";
    public const string Restore = "restore";
    public const string Purge = "purge";

    public static readonly string[] All = [Delete, Quarantine, Restore, Purge];

    /// <summary>
    /// What the automatic rule is allowed to do, which is quarantine and
    /// nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An unattended delete is a different risk class from one an operator
    /// chose: there is no one to notice the false positive, and the file is
    /// gone. Quarantine is reversible, so it is the only action the auto-rule
    /// can take however <c>auto_remediate_action</c> is configured.
    /// </para>
    /// <para>
    /// <see cref="Restore"/> and <see cref="Purge"/> are excluded for a
    /// different reason: both operate on something already quarantined, so
    /// neither is a meaningful response to a fresh detection.
    /// </para>
    /// </remarks>
    public static readonly string[] AutoEligible = [Quarantine];

    public static bool IsKnown(string? action) =>
        action is not null && All.Contains(action, StringComparer.OrdinalIgnoreCase);

    public static bool IsAutoEligible(string? action) =>
        action is not null && AutoEligible.Contains(action, StringComparer.OrdinalIgnoreCase);

    /// <summary>Acts on a file already in quarantine rather than in place.</summary>
    public static bool IsQuarantineAction(string? action) =>
        string.Equals(action, Restore, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(action, Purge, StringComparison.OrdinalIgnoreCase);

    /// <summary>Past tense, for the audit record and the dashboard.</summary>
    public static string PastTense(string action) => action.ToLowerInvariant() switch
    {
        Delete => "deleted",
        Quarantine => "quarantined",
        Restore => "restored",
        Purge => "purged",
        _ => action + "d",
    };
}
