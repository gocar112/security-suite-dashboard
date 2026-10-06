using SecuritySuite.Casework;
using SecuritySuite.Configuration;
using SecuritySuite.Hunting;
using SecuritySuite.Connectors;
using SecuritySuite.Detection;
using SecuritySuite.Intel;
using SecuritySuite.Inventory;
using SecuritySuite.Jobs;
using SecuritySuite.Monitoring;
using SecuritySuite.Remediation;
using SecuritySuite.Storage;
using SecuritySuite.Telemetry;
using SecuritySuite.Workspace;

namespace SecuritySuite.Http;

/// <summary>
/// Everything the request handler needs, assembled once.
/// </summary>
/// <remarks>
/// The optional adapters are nullable rather than always-present stubs, so a
/// route can answer 503 with "adapter not enabled" instead of pretending to
/// work. A dashboard that silently shows empty intel panels is worse than one
/// that says the adapter is off.
/// </remarks>
public sealed class SuiteContext : IDisposable
{
    public SuiteConfig Config { get; }
    public YaraEngine Engine { get; }
    public EventStore Store { get; }
    public AuthTelemetry Telemetry { get; }
    public DirectoryMonitor Monitor { get; }

    public NvdClient? Nvd { get; }
    public OsvClient? Osv { get; }
    public VirusTotalClient? VirusTotal { get; }
    public Remediator? Remediator { get; }
    public GuidanceService? Guidance { get; }

    public ScanJobs Jobs { get; }
    public NetworkInventory Inventory { get; }
    public Workbench Workbench { get; }
    public PlaybookService Playbooks { get; }
    public Training Training { get; }
    public OpnSenseConnector OpnSense { get; }
    public BitdefenderConnector Bitdefender { get; }

    /// <summary>Casework and saved hunts, filed beside the other sidecars.</summary>
    public CaseStore Cases { get; }

    public SavedHuntStore SavedHunts { get; }

    public SuiteContext(SuiteConfig cfg, YaraEngine engine, EventStore store,
                        AuthTelemetry telemetry, DirectoryMonitor monitor,
                        NvdClient? nvd = null, OsvClient? osv = null,
                        VirusTotalClient? vt = null, Remediator? remediator = null,
                        GuidanceService? guidance = null)
    {
        Config = cfg;
        Engine = engine;
        Store = store;
        Telemetry = telemetry;
        Monitor = monitor;
        Nvd = nvd;
        Osv = osv;
        VirusTotal = vt;
        Remediator = remediator;
        Guidance = guidance;

        // Share the monitor's job owner rather than making a second one: two
        // owners would each allow one "active" job, so the single-job guard
        // would admit two concurrent tree walks.
        Jobs = monitor.Jobs;
        Inventory = new NetworkInventory(store);
        Workbench = new Workbench(cfg, engine, store);
        Playbooks = new PlaybookService(cfg, store, remediator, guidance);
        Training = new Training();
        OpnSense = new OpnSenseConnector();
        Bitdefender = new BitdefenderConnector();

        var sidecars = Path.GetDirectoryName(Path.GetFullPath(cfg.TriageFile)) ?? ".";
        Cases = new CaseStore(Path.Combine(sidecars, "cases.json"));
        SavedHunts = new SavedHuntStore(Path.Combine(sidecars, "saved-hunts.json"));
    }

    public void Dispose() => Engine.Dispose();
}
