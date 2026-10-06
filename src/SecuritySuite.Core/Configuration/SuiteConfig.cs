using System.Text.Json;
using System.Text.Json.Serialization;
using SecuritySuite.Remediation;

namespace SecuritySuite.Configuration;

/// <summary>
/// Every tunable the suite has. Loaded from <c>config.json</c> when present,
/// otherwise the defaults below, which work with no configuration at all.
/// </summary>
/// <remarks>
/// Property names serialise to snake_case so a <c>config.json</c> written by
/// the Python build still loads unchanged.
/// </remarks>
public sealed class SuiteConfig
{
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
    };

    // ------------------------------------------------------------ monitoring
    public List<string> WatchPaths { get; set; } = [Path.Combine(SuitePaths.Root, "uploads")];
    public bool Recursive { get; set; } = true;
    public double PollInterval { get; set; } = 2.0;

    /// <summary>
    /// A file must stop changing for this long before it is scanned, so a
    /// half-written upload is never scanned mid-write.
    /// </summary>
    public double SettleSeconds { get; set; } = 1.0;

    public double MaxFileMb { get; set; } = 64.0;
    public List<string> IgnoreSuffixes { get; set; } = [".tmp", ".part", ".crdownload", ".swp"];
    public bool ScanExistingOnStart { get; set; }

    // ------------------------------------------------------------- detection
    public string RulesDir { get; set; } = Path.Combine(SuitePaths.Root, "rules");

    // ------------------------------------------------- telemetry correlation
    public int LookbackMinutes { get; set; } = 5;

    /// <summary>
    /// Only consulted by the file-based telemetry provider, which exists for
    /// tests and for hosts that ship an auth log. Kept so a Python-era
    /// <c>config.json</c> does not report an unknown key.
    /// </summary>
    public string AuthLogPath { get; set; } = "/var/log/auth.log";

    public double TelemetryCacheSeconds { get; set; } = 15.0;
    public int MaxTelemetryEvents { get; set; } = 25;

    // --------------------------------------------------------------- storage
    public string FindingsLog { get; set; } = Path.Combine(SuitePaths.Root, "data", "findings.ndjson");
    public string TriageFile { get; set; } = Path.Combine(SuitePaths.Root, "data", "triage.json");
    public int HistoryLimit { get; set; } = 2000;

    // ---------------------------------------------------------------- server
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 8787;

    // ------------------------------------------ optional external intelligence
    [JsonIgnore]
    public string VirustotalApiKey { get; set; } =
        Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY") ?? "";

    /// <summary>NVD needs no credential; a key only raises the rate limit (5/30s to 50/30s).</summary>
    [JsonIgnore]
    public string NvdApiKey { get; set; } =
        Environment.GetEnvironmentVariable("NVD_API_KEY") ?? "";

    public string NvdCacheDir { get; set; } = Path.Combine(SuitePaths.Root, "nvds");
    public int NvdSyncDays { get; set; } = 3;
    public int NvdMaxRecords { get; set; } = 4000;
    public string OsvCacheDir { get; set; } = Path.Combine(SuitePaths.Root, "data", "osv");
    public string VtCacheDir { get; set; } = Path.Combine(SuitePaths.Root, "data", "vt");

    // ------------------------------ remediation (destructive; see Remediator)
    /// <summary>
    /// MUST sit outside every watch path, or a quarantined file is re-detected
    /// forever. <see cref="Validate"/> says so at startup.
    /// </summary>
    public string QuarantineDir { get; set; } = Path.Combine(SuitePaths.Root, "quarantine");

    public string RemediationFile { get; set; } = Path.Combine(SuitePaths.Root, "data", "remediation.json");
    public string GuidanceCacheDir { get; set; } = Path.Combine(SuitePaths.Root, "data", "guidance");

    /// <summary>Extra roots a remediation may act within, beyond the watch paths.</summary>
    public List<string> RemediationRoots { get; set; } = [];

    /// <summary>
    /// Automatic remediation is opt-in and defaults to the non-destructive
    /// action. An unattended delete is a different risk class from one an
    /// operator chose.
    /// </summary>
    public bool AutoRemediate { get; set; }

    public string AutoRemediateSeverity { get; set; } = "critical";
    public string AutoRemediateAction { get; set; } = "quarantine";

    [JsonIgnore]
    public long MaxFileBytes => (long)(MaxFileMb * 1024 * 1024);

    /// <summary>The project root, so callers need not reach for SuitePaths.</summary>
    [JsonIgnore]
    public string ProjectRoot => SuitePaths.Root;

    // ------------------------------------------------------------------ load
    /// <summary>
    /// Load configuration, reporting anything ignored rather than failing. A
    /// bad config file must not stop a detection tool from starting.
    /// </summary>
    public static SuiteConfig Load(string? path = null, Action<string>? warn = null)
    {
        DotEnv.Load();
        warn ??= _ => { };
        var file = path ?? SuitePaths.ConfigFile;
        var cfg = new SuiteConfig();

        if (File.Exists(file))
        {
            try
            {
                using var document = JsonDocument.Parse(
                    File.ReadAllText(file),
                    new JsonDocumentOptions
                    {
                        CommentHandling = JsonCommentHandling.Skip,
                        AllowTrailingCommas = true,
                    });
                cfg.ApplyOverrides(document.RootElement, warn);
            }
            catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
            {
                warn("[!] Ignoring unreadable " + Path.GetFileName(file) + ": " + exc.Message);
                return cfg.EnsureDirectories(warn);
            }
        }
        return cfg.EnsureDirectories(warn);
    }

    /// <summary>
    /// Apply only recognised keys, naming anything dropped.
    /// </summary>
    /// <remarks>
    /// Deserialising the whole object would silently discard an unknown key and
    /// reset every absent one to its default. Walking the document instead lets
    /// a partial config file override three settings and leave the rest alone,
    /// and lets a typo be reported rather than ignored.
    /// </remarks>
    private void ApplyOverrides(JsonElement root, Action<string> warn)
    {
        if (root.ValueKind != JsonValueKind.Object) return;

        var writable = typeof(SuiteConfig)
            .GetProperties()
            .Where(p => p.CanWrite &&
                        p.GetCustomAttributes(typeof(JsonIgnoreAttribute), true).Length == 0)
            .ToDictionary(
                p => JsonNamingPolicy.SnakeCaseLower.ConvertName(p.Name),
                p => p,
                StringComparer.OrdinalIgnoreCase);

        foreach (var member in root.EnumerateObject())
        {
            if (!writable.TryGetValue(member.Name, out var property))
            {
                // Credentials were hand-added to some config files. Say plainly
                // that they are ignored rather than looking like a typo.
                warn(member.Name is "virustotal_api_key" or "nvd_api_key"
                    ? "[!] " + member.Name + " in config.json is ignored; put it in .env or the environment"
                    : "[!] Unknown config key ignored: " + member.Name);
                continue;
            }
            try
            {
                var value = member.Value.Deserialize(property.PropertyType, Json);
                if (value is not null) property.SetValue(this, value);
            }
            catch (JsonException exc)
            {
                warn("[!] Bad value for " + member.Name + ", keeping default: " + exc.Message);
            }
        }
    }

    /// <summary>Create every directory the suite writes to.</summary>
    private SuiteConfig EnsureDirectories(Action<string> warn)
    {
        var dirs = new List<string>
        {
            Path.GetDirectoryName(SuitePaths.Resolve(FindingsLog)) ?? "",
            Path.GetDirectoryName(SuitePaths.Resolve(TriageFile)) ?? "",
            Path.GetDirectoryName(SuitePaths.Resolve(RemediationFile)) ?? "",
            SuitePaths.Resolve(RulesDir),
            SuitePaths.Resolve(NvdCacheDir),
            SuitePaths.Resolve(OsvCacheDir),
            SuitePaths.Resolve(VtCacheDir),
            SuitePaths.Resolve(QuarantineDir),
            SuitePaths.Resolve(GuidanceCacheDir),
        };
        dirs.AddRange(WatchPaths.Select(SuitePaths.Resolve));

        foreach (var dir in dirs.Where(d => !string.IsNullOrWhiteSpace(d)).Distinct())
        {
            try
            {
                Directory.CreateDirectory(dir);
            }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
            {
                warn("[!] Could not create " + dir + ": " + exc.Message);
            }
        }
        foreach (var problem in Validate()) warn(problem);
        return this;
    }

    /// <summary>
    /// Configuration mistakes worth saying out loud at startup.
    /// </summary>
    /// <remarks>
    /// The quarantine check is the important one. A quarantine directory inside
    /// a watch path means every quarantined file is re-detected on the next
    /// sweep: the findings.ndjson feedback loop again, with a file someone
    /// deliberately set aside. The monitor excludes the directory so this is no
    /// longer fatal, but a configuration relying on that exclusion is still one
    /// worth fixing.
    /// </remarks>
    public IEnumerable<string> Validate()
    {
        var quarantine = SuitePaths.Resolve(QuarantineDir);
        foreach (var watched in WatchPaths.Select(SuitePaths.Resolve))
        {
            if (PathUtil.IsWithin(quarantine, watched))
            {
                yield return "[!] quarantine_dir (" + quarantine + ") sits inside watch path " +
                             watched + "; move it outside so quarantined files are not re-detected";
            }
        }

        if (PollInterval <= 0)
            yield return "[!] poll_interval must be above zero or the monitor will spin";
        if (SettleSeconds < 0)
            yield return "[!] settle_seconds cannot be negative";
        if (Port is < 1 or > 65535)
            yield return "[!] port " + Port + " is outside 1-65535";

        if (AutoRemediate)
        {
            yield return "[!] AUTO-REMEDIATION IS ON: " + AutoRemediateAction + " at severity " +
                         AutoRemediateSeverity + " and above, with no operator confirming";
            if (!RemediationActions.IsAutoEligible(AutoRemediateAction))
            {
                yield return "[!] auto_remediate_action '" + AutoRemediateAction +
                             "' is not valid for unattended use; expected " +
                             string.Join(" or ", RemediationActions.AutoEligible);
            }
        }
    }

    // ------------------------------------------------------------------ save
    /// <summary>
    /// Serialise to JSON. Credentials carry <see cref="JsonIgnoreAttribute"/>
    /// and so cannot be written to disk by this path.
    /// </summary>
    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public string Save(string? path = null)
    {
        var target = path ?? SuitePaths.ConfigFile;
        var parent = Path.GetDirectoryName(target);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        File.WriteAllText(target, ToJson());
        return target;
    }
}
