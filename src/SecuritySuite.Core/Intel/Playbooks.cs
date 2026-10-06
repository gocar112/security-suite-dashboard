using System.Text.Json.Serialization;

namespace SecuritySuite.Intel;

/// <summary>A response shape for a class of finding.</summary>
public sealed class Playbook
{
    [JsonPropertyName("summary")] public string Summary { get; init; } = "";

    /// <summary>Ordered. Step one is step one.</summary>
    [JsonPropertyName("steps")] public List<string> Steps { get; init; } = [];

    /// <summary>How this playbook was chosen, so the UI can show the reasoning.</summary>
    [JsonPropertyName("source")] public string Source { get; set; } = "";

    public Playbook With(string source) => new()
    {
        Summary = Summary,
        Steps = Steps,
        Source = source,
    };
}

/// <summary>
/// Response playbooks for findings that have no CVE.
/// </summary>
/// <remarks>
/// <para>
/// A malware finding has no CVE and no vendor patch. What it has is a response
/// shape that depends on what was found: a web shell means credentials are
/// suspect and web logs need reading; ransomware means isolate before anything
/// else. Those are written here rather than fetched, because they do not change
/// per incident.
/// </para>
/// <para>
/// Nothing here is generated prose presented as advice. Where an authoritative
/// answer exists it is quoted from its source with attribution (see
/// <see cref="GuidanceService"/>); where it does not, a playbook says what
/// class of response applies and leaves the judgement to the analyst.
/// </para>
/// </remarks>
public static class Playbooks
{
    public static readonly Playbook WebShell = new()
    {
        Summary = "A server-side backdoor gives an attacker command execution " +
                  "as the web server user. Assume the host is compromised.",
        Steps =
        [
            "Preserve the file and its timestamps before removing anything.",
            "Read the web server access log for requests to this path - the source " +
            "addresses are the operator, and the response sizes show what was taken.",
            "Rotate every credential the web server can reach: database, API keys, " +
            "cloud roles, connection strings in config files.",
            "Look for siblings. A web shell is rarely alone; scan the whole document " +
            "root, not just the upload directory.",
            "Find the upload path that allowed it and fix the validation.",
        ],
    };

    public static readonly Playbook Ransomware = new()
    {
        Summary = "Encryption tooling or an extortion artifact. Time matters more " +
                  "than analysis here.",
        Steps =
        [
            "Isolate the host from the network before investigating further.",
            "Do not reboot - keys occasionally survive in memory.",
            "Check whether volume shadow copies still exist and protect them.",
            "Identify the scope of encrypted files before restoring anything.",
            "Preserve the ransom note and any wallet addresses as evidence.",
        ],
    };

    public static readonly Playbook CredentialTheft = new()
    {
        Summary = "Tooling aimed at stored or in-memory credentials. Treat every " +
                  "credential reachable from this host as exposed.",
        Steps =
        [
            "Rotate credentials for every account used on this host, prioritising " +
            "domain and service accounts.",
            "Invalidate active sessions and refresh tokens.",
            "Review authentication logs for use of those credentials elsewhere.",
            "Check for persistence - credential theft is rarely the first step.",
        ],
    };

    public static readonly Playbook C2Network = new()
    {
        Summary = "Command-and-control capability. The indicators extracted from " +
                  "this file are the hunt.",
        Steps =
        [
            "Block the extracted addresses and domains at the egress point.",
            "Search proxy, firewall and DNS logs for prior contact with them.",
            "Establish first-contact time - that is the intrusion's start, not the " +
            "detection time.",
            "Look for persistence mechanisms on any host that talked to them.",
        ],
    };

    public static readonly Playbook InfoStealer = new()
    {
        Summary = "Data theft or hands-on-keyboard remote access.",
        Steps =
        [
            "Assume browser-stored credentials, cookies and session tokens on this " +
            "host are exfiltrated.",
            "Rotate credentials and invalidate sessions, including cloud consoles " +
            "reachable from the browser profile.",
            "Check for cryptocurrency wallet files if any were present.",
        ],
    };

    public static readonly Playbook SupplyChain = new()
    {
        Summary = "A package or build artifact that runs code at install time.",
        Steps =
        [
            "Quarantine the artifact and stop any pipeline consuming it.",
            "Identify every build that consumed this version.",
            "Rotate CI secrets - install hooks run with the pipeline's environment, " +
            "including tokens.",
            "Pin the dependency to a known-good version and rebuild.",
        ],
    };

    public static readonly Playbook RmmTunnel = new()
    {
        Summary = "Remote access or tunnelling tooling configured for unattended " +
                  "use. This may be legitimate - confirm first.",
        Steps =
        [
            "Confirm with the owning team whether this deployment is sanctioned. " +
            "Plenty of organisations run these deliberately.",
            "If unsanctioned: terminate active sessions and remove the service.",
            "Check the configured password or token - a preset unattended credential " +
            "means anyone holding it has access.",
            "Review outbound connections for the tunnel's destination.",
        ],
    };

    public static readonly Playbook OfficeMacro = new()
    {
        Summary = "A document that executes on open.",
        Steps =
        [
            "Identify the delivery path - mail, upload, or share.",
            "Find other recipients of the same document.",
            "Check whether the macro ran: look for spawned processes and child " +
            "script interpreters around the open time.",
        ],
    };

    public static readonly Playbook CryptoMiner = new()
    {
        Summary = "Resource abuse. Lower urgency, but it means someone had enough " +
                  "access to run code.",
        Steps =
        [
            "Terminate the miner and remove its persistence.",
            "Treat the access path as the real finding - mining is a symptom.",
            "Check the configured pool address against outbound connections.",
        ],
    };

    public static readonly Playbook ReconPersistence = new()
    {
        Summary = "Discovery activity or a persistence mechanism.",
        Steps =
        [
            "Enumerate and remove the persistence entry itself.",
            "Establish what else ran under it and when it was created.",
            "Persistence implies prior access - find the initial vector.",
        ],
    };

    /// <summary>
    /// A known-vulnerable component, which is exposure rather than compromise.
    /// </summary>
    /// <remarks>
    /// The distinction matters enough to be the first sentence an analyst
    /// reads. Every generated NVD rule lands here, and none of them say the
    /// vulnerability was exploited — only that a matching version string is
    /// present on disk.
    /// </remarks>
    public static readonly Playbook VulnerableComponent = new()
    {
        Summary = "A known-vulnerable component is present. This is exposure, not " +
                  "compromise - nothing here says it has been exploited.",
        Steps =
        [
            "Confirm the component is actually in use, not merely present on disk " +
            "in an unused artifact.",
            "Apply the vendor patch named below, or upgrade past the affected " +
            "version range.",
            "If it is a KEV entry, treat the CISA due date as the deadline.",
        ],
    };

    public static readonly Playbook HostTradecraft = new()
    {
        Summary = "Host tradecraft - encoded commands, defence evasion, or " +
                  "credential tooling.",
        Steps =
        [
            "Establish what ran and under which account.",
            "Check for persistence created around the same time.",
            "Rotate credentials used on this host if anything credential-adjacent fired.",
            "Preserve the file before deleting it - the command line is evidence.",
        ],
    };

    public static readonly Playbook Phishing = new()
    {
        Summary = "A lure aimed at a person rather than the system.",
        Steps =
        [
            "Identify who received it and whether anyone interacted.",
            "Pull the same lure from other mailboxes or upload paths.",
            "If credentials may have been entered, rotate them and check for logins " +
            "from unfamiliar addresses.",
        ],
    };

    public static readonly Playbook Default = new()
    {
        Summary = "No specific playbook for this rule category.",
        Steps =
        [
            "Review the matched strings to understand what fired.",
            "Check the extracted indicators for infrastructure worth hunting.",
            "If this is a false positive, mark it as such - that feeds rule tuning.",
        ],
    };

    /// <summary>Keyed by rule-file name, matching the suite's rule layout.</summary>
    public static readonly Dictionary<string, Playbook> ByNamespace = new(StringComparer.OrdinalIgnoreCase)
    {
        ["webshell"] = WebShell,
        ["ransomware"] = Ransomware,
        ["credential_theft"] = CredentialTheft,
        ["c2_network"] = C2Network,
        ["info_stealer_rat"] = InfoStealer,
        ["supply_chain"] = SupplyChain,
        ["rmm_tunnel_abuse"] = RmmTunnel,
        ["office_macro_malware"] = OfficeMacro,
        ["cryptominer"] = CryptoMiner,
        ["recon_persistence"] = ReconPersistence,
        ["vulnerable_component"] = VulnerableComponent,
        ["windows_threats"] = HostTradecraft,
        ["linux_threats"] = HostTradecraft,
        ["macos_threats"] = HostTradecraft,
        ["web_fraud_skimmer"] = WebShell,
        ["phishing_social_engineering"] = Phishing,
    };

    /// <summary>
    /// Rule-name fragments, checked before namespaces and tags.
    /// </summary>
    /// <remarks>
    /// Ordered, and the first match wins, so the specific terms come first. A
    /// rule's <em>subject</em> is a better guide than its category:
    /// <c>Ransom_Note_Template</c> lives in the <c>windows_threats</c> file and
    /// carries the tag <c>malware</c>, neither of which says ransomware.
    /// </remarks>
    public static readonly (string Keyword, Playbook Playbook)[] ByRuleKeyword =
    [
        ("ransom", Ransomware),
        ("lockbit", Ransomware),
        ("conti", Ransomware),
        ("revil", Ransomware),
        ("sodinokibi", Ransomware),
        ("webshell", WebShell),
        ("skimmer", WebShell),
        ("lsass", CredentialTheft),
        ("credential", CredentialTheft),
        ("keylog", CredentialTheft),
        ("miner", CryptoMiner),
        ("xmrig", CryptoMiner),
        ("stratum", CryptoMiner),
        ("beacon", C2Network),
        ("cobalt", C2Network),
        ("reverse_shell", C2Network),
        ("tunnel", RmmTunnel),
        ("stealer", InfoStealer),
        ("macro", OfficeMacro),
        ("persistence", ReconPersistence),
    ];

    /// <summary>Tags that imply a playbook without naming one.</summary>
    public static readonly Dictionary<string, Playbook> ByTag = new(StringComparer.OrdinalIgnoreCase)
    {
        ["kev"] = VulnerableComponent,
        ["vulnerable_component"] = VulnerableComponent,
        ["phishing"] = Phishing,
        ["ransomware"] = Ransomware,
        ["webshell"] = WebShell,
        ["malware"] = HostTradecraft,
        ["suspicious"] = HostTradecraft,
        ["exploit"] = VulnerableComponent,
    };
}
