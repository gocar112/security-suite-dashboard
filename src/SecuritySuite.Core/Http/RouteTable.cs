using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecuritySuite.Configuration;
using SecuritySuite.Casework;
using SecuritySuite.Hunting;
using SecuritySuite.Intel;
using SecuritySuite.Jobs;
using SecuritySuite.Remediation;
using SecuritySuite.Shield;
using SecuritySuite.Storage;
using SecuritySuite.Workspace;

namespace SecuritySuite.Http;

/// <summary>
/// Every route the dashboard serves.
/// </summary>
/// <remarks>
/// A flat dispatch rather than attribute routing, so the whole API surface of a
/// tool that can delete files is readable in one pass.
/// </remarks>
internal sealed class RouteTable(SuiteContext ctx, string webRoot)
{
    public static string Version => SuiteVersion.Current;

    /// <summary>Static files the dashboard is allowed to request by name.</summary>
    private static readonly HashSet<string> StaticFiles = new(StringComparer.Ordinal)
    {
        "app.js", "console.js", "views.js", "lucide.js", "styles.css", "favicon.ico",
        "playbook.schema.json",
    };

    private static readonly string[] IntelSources =
    [
        "vuls", "nvd", "kev", "osv", "github", "clawfire", "virustotal",
    ];

    private static readonly Dictionary<string, (string Url, string Status)> IntelMeta = new(StringComparer.Ordinal)
    {
        ["vuls"] = ("https://github.com/future-architect/vuls", "bridge"),
        ["nvd"] = ("https://nvd.nist.gov/", "catalog"),
        ["kev"] = ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "catalog"),
        ["osv"] = ("https://osv.dev/", "catalog"),
        ["github"] = ("https://github.com/advisories", "catalog"),
        ["clawfire"] = ("https://clawfire.ai/", "reference"),
        ["virustotal"] = ("https://www.virustotal.com/", "optional"),
    };

    private static readonly string[] TriageStatuses =
        ["new", "acknowledged", "resolved", "false_positive"];

    // ------------------------------------------------------------------- GET
    public async Task GetAsync(string route, HttpListenerRequest request,
                               HttpListenerResponse response, bool headOnly,
                               CancellationToken token)
    {
        var query = request.QueryString;

        switch (route)
        {
            case "/":
                await StaticAsync(response, "index.html", headOnly).ConfigureAwait(false);
                return;

            case "/api/state":
                await Json(response, State()).ConfigureAwait(false);
                return;

            case "/api/instance":
                await Json(response, new
                {
                    version = Version,
                    findings_log = ctx.Config.FindingsLog,
                    backend = ctx.Engine.Info().Backend,
                }).ConfigureAwait(false);
                return;

            case "/api/jobs":
                await Json(response, new { jobs = ctx.Jobs.Status() }).ConfigureAwait(false);
                return;

            case "/api/drives":
                await Json(response, new { drives = ctx.Jobs.Drives() }).ConfigureAwait(false);
                return;

            case "/api/inventory":
                await Json(response, ctx.Inventory.Status()).ConfigureAwait(false);
                return;

            case "/api/inventory/export":
                await InventoryCsvAsync(response).ConfigureAwait(false);
                return;

            case "/api/workspace":
                await Json(response, new
                {
                    policy = ctx.Workbench.Policy(),
                    native_av = ctx.Workbench.NativeAv,
                    domains = ctx.Workbench.Domains(),
                }).ConfigureAwait(false);
                return;

            case "/api/ids":
                await Json(response, new
                {
                    alerts = ctx.Store.Events(limit: 300, eventType: "ids_alert"),
                }).ConfigureAwait(false);
                return;

            case "/api/connectors":
                await Json(response, new
                {
                    opnsense = ctx.OpnSense.Status(),
                    bitdefender = ctx.Bitdefender.Status(),
                }).ConfigureAwait(false);
                return;

            case "/api/domains/export":
                await DomainsExportAsync(response).ConfigureAwait(false);
                return;

            case "/api/playbooks":
                await Json(response, ctx.Playbooks.List()).ConfigureAwait(false);
                return;

            case "/api/training":
                await Json(response, ctx.Training.List()).ConfigureAwait(false);
                return;

            case "/api/findings":
                {
                    var findings = ctx.Store.Events(
                        limit: HttpPrimitives.Integer(query.Get("limit"), 200),
                        severity: query.Get("severity"),
                        eventType: query.Get("type"),
                        status: query.Get("status"),
                        search: query.Get("q"));

                    if (ctx.Remediator is not null) findings = ctx.Remediator.AnnotateMany(findings);

                    // Resolved ATT&CK techniques are attached here rather than
                    // stored, so a correction to the technique table reaches old
                    // findings instead of only new ones.
                    foreach (var finding in findings)
                    {
                        var techniques = (finding.Matches ?? [])
                            .SelectMany(AttackMapping.Resolve)
                            .GroupBy(t => t.Id, StringComparer.Ordinal)
                            .Select(g => g.First())
                            .ToList();

                        if (techniques.Count == 0) continue;
                        finding.SetExtra("attack", techniques);
                        finding.SetExtra("attack_tactics", AttackMapping.TacticsFor(techniques));
                    }
                    await Json(response, new { findings }).ConfigureAwait(false);
                    return;
                }

            case "/api/rules":
                await Json(response, ctx.Engine.Info()).ConfigureAwait(false);
                return;

            case "/api/telemetry":
                await Json(response, ctx.Telemetry.Recent(query.GetOrEmpty("force") == "1"))
                    .ConfigureAwait(false);
                return;

            case "/api/intel":
                await Json(response, Intel()).ConfigureAwait(false);
                return;

            case "/api/attack/coverage":
                await Json(response, AttackMapping.Coverage(
                    ctx.Engine.Info(),
                    ctx.Store.Events(limit: 2000, eventType: SuiteEvent.TypeMatch)))
                    .ConfigureAwait(false);
                return;

            case "/api/attack/techniques":
                await Json(response, new
                {
                    tactics = AttackMapping.Tactics.Select(t => new { id = t.Id, name = t.Name }),
                    techniques = AttackMapping.Techniques
                        .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                        .Select(kv => AttackMapping.Describe(kv.Key)),
                }).ConfigureAwait(false);
                return;

            case "/api/hunt":
                {
                    var hunt = HuntQuery.Run(
                        query.Get("q"),
                        ctx.Store.Events(limit: 5000, eventType: "all"),
                        HttpPrimitives.Integer(query.Get("limit"), 300));

                    // A query that did not parse is the operator's typo, not a
                    // server fault, so it is 400 carrying the parser's own message.
                    await Json(response, hunt, hunt.Error is null ? 200 : 400).ConfigureAwait(false);
                    return;
                }

            case "/api/hunt/saved":
                await Json(response, new { hunts = ctx.SavedHunts.All() }).ConfigureAwait(false);
                return;

            case "/api/graph":
                await Json(response, LinkGraph.Build(
                    ctx.Store.Events(limit: 2000, eventType: SuiteEvent.TypeMatch),
                    HttpPrimitives.Integer(query.Get("max_nodes"), LinkGraph.DefaultMaxNodes, 5000),
                    query.GetOrEmpty("linking_only") == "1")).ConfigureAwait(false);
                return;

            case "/api/cases":
                await Json(response, new
                {
                    cases = ctx.Cases.All(query.GetOrEmpty("status")),
                    summary = ctx.Cases.Summary(),
                    statuses = CaseStore.Statuses,
                }).ConfigureAwait(false);
                return;

            case "/api/cases/detail":
                {
                    var record = ctx.Cases.Get(query.GetOrEmpty("id"));
                    if (record is null)
                    {
                        await Json(response, new { error = "unknown case" }, 404).ConfigureAwait(false);
                        return;
                    }
                    await Json(response, new { @case = record, findings = CaseFindings(record) })
                        .ConfigureAwait(false);
                    return;
                }

            case "/api/report":
                await ReportAsync(response, query, headOnly).ConfigureAwait(false);
                return;

            case "/api/shield":
                await Json(response,
                    ShieldPosture.Build(ctx.Config, ctx.Engine, ctx.Store, ctx.Remediator))
                    .ConfigureAwait(false);
                return;

            case "/api/iocs":
                await IocsAsync(response, query).ConfigureAwait(false);
                return;

            case "/api/remediate":
                if (ctx.Remediator is null)
                {
                    await Json(response, new { error = "remediation not enabled" }, 503).ConfigureAwait(false);
                    return;
                }
                await Json(response, ctx.Remediator.Status()).ConfigureAwait(false);
                return;

            case "/api/remediate/guidance":
                await GuidanceAsync(response, query, token).ConfigureAwait(false);
                return;

            case "/api/vt":
                await Json(response, ctx.VirusTotal is not null
                    ? ctx.VirusTotal.Status()
                    : (object)new { source = "virustotal", status = "disabled" }).ConfigureAwait(false);
                return;

            case "/api/vt/capabilities":
                {
                    if (ctx.VirusTotal is null)
                    {
                        await Json(response, new { error = "virustotal adapter not enabled" }, 503)
                            .ConfigureAwait(false);
                        return;
                    }
                    // An explicit refresh may block for about a minute on the public
                    // tier; the dashboard's own poll never does.
                    var refresh = query.GetOrEmpty("refresh") == "1";
                    var caps = refresh
                        ? await ctx.VirusTotal.CapabilitiesBlockingAsync(token).ConfigureAwait(false)
                        : ctx.VirusTotal.Capabilities();
                    await Json(response, caps).ConfigureAwait(false);
                    return;
                }

            case "/api/vt/file":
                {
                    if (ctx.VirusTotal is null)
                    {
                        await Json(response, new { error = "virustotal adapter not enabled" }, 503)
                            .ConfigureAwait(false);
                        return;
                    }
                    var digest = query.GetOrEmpty("hash");
                    if (digest.Length == 0)
                    {
                        await Json(response, new { error = "hash is required" }, 400).ConfigureAwait(false);
                        return;
                    }
                    await Json(response,
                        await ctx.VirusTotal.LookupHashAsync(digest, token: token).ConfigureAwait(false))
                        .ConfigureAwait(false);
                    return;
                }

            case "/api/vt/livehunt":
            case "/api/vt/retrohunt":
                {
                    if (ctx.VirusTotal is null)
                    {
                        await Json(response, new { error = "virustotal adapter not enabled" }, 503)
                            .ConfigureAwait(false);
                        return;
                    }
                    var feature = route.EndsWith("livehunt", StringComparison.Ordinal)
                        ? "livehunt" : "retrohunt";
                    var result = await ctx.VirusTotal.HuntingAsync(feature, token).ConfigureAwait(false);

                    // 402 Payment Required is the honest status for "your tier
                    // cannot reach this", rather than 403 which reads as a bug.
                    await Json(response, result, result.Available ? 200 : 402).ConfigureAwait(false);
                    return;
                }

            case "/api/osv":
                await Json(response, ctx.Osv is not null
                    ? ctx.Osv.Status()
                    : (object)new { source = "osv", status = "disabled" }).ConfigureAwait(false);
                return;

            case "/api/osv/query":
                {
                    if (ctx.Osv is null)
                    {
                        await Json(response, new { error = "osv adapter not enabled" }, 503).ConfigureAwait(false);
                        return;
                    }
                    await Json(response, await ctx.Osv.QueryAsync(
                        query.Get("commit"), query.Get("purl"), query.Get("package"),
                        query.Get("ecosystem"), query.Get("version"), token).ConfigureAwait(false))
                        .ConfigureAwait(false);
                    return;
                }

            case "/api/nvd":
                await Json(response, ctx.Nvd is not null
                    ? ctx.Nvd.Status()
                    : (object)new { source = "nvd", status = "disabled" }).ConfigureAwait(false);
                return;

            case "/api/nvd/cves":
                {
                    if (ctx.Nvd is null)
                    {
                        await Json(response, new { error = "nvd adapter not enabled" }, 503).ConfigureAwait(false);
                        return;
                    }
                    await Json(response, new
                    {
                        cves = ctx.Nvd.CachedRecords(
                            HttpPrimitives.Integer(query.Get("limit"), 100),
                            query.GetOrEmpty("severity")),
                    }).ConfigureAwait(false);
                    return;
                }

            case "/api/nvd/cve":
                {
                    if (ctx.Nvd is null)
                    {
                        await Json(response, new { error = "nvd adapter not enabled" }, 503).ConfigureAwait(false);
                        return;
                    }
                    var id = query.GetOrEmpty("id");
                    if (id.Length == 0)
                    {
                        await Json(response, new { error = "id is required" }, 400).ConfigureAwait(false);
                        return;
                    }
                    await Json(response, await ctx.Nvd.FetchCveAsync(id, token: token).ConfigureAwait(false))
                        .ConfigureAwait(false);
                    return;
                }

            case "/api/nvd/search":
                {
                    if (ctx.Nvd is null)
                    {
                        await Json(response, new { error = "nvd adapter not enabled" }, 503).ConfigureAwait(false);
                        return;
                    }
                    var q = query.GetOrEmpty("q");
                    if (q.Length == 0)
                    {
                        await Json(response, new { error = "q is required" }, 400).ConfigureAwait(false);
                        return;
                    }
                    await Json(response, await ctx.Nvd.SearchAsync(
                        q, HttpPrimitives.Integer(query.Get("limit"), 20, 100), token).ConfigureAwait(false))
                        .ConfigureAwait(false);
                    return;
                }

            case "/api/stream":
                if (headOnly)
                {
                    response.ContentType = "text/event-stream";
                    response.ContentLength64 = 0;
                    return;
                }
                await StreamAsync(response, token).ConfigureAwait(false);
                return;

            default:
                // Static assets by name only; never a path from the request.
                var name = route.TrimStart('/');

                // The icon lives in assets/, beside the desktop shortcut's copy.
                // Serving it only from web/ meant /favicon.ico always 404'd and
                // every dashboard load logged a missing-icon request.
                if (name == "favicon.ico")
                {
                    await IconAsync(response, headOnly).ConfigureAwait(false);
                    return;
                }
                if (StaticFiles.Contains(name))
                {
                    await StaticAsync(response, name, headOnly).ConfigureAwait(false);
                    return;
                }
                await Json(response, new { error = "not found" }, 404).ConfigureAwait(false);
                return;
        }
    }

    // ------------------------------------------------------------------ POST
    public async Task PostAsync(string route, HttpListenerRequest request,
                                HttpListenerResponse response, CancellationToken token)
    {
        var (allowed, why) = HttpPrimitives.CsrfOk(request);
        if (!allowed)
        {
            await Json(response, new { error = why }, 403).ConfigureAwait(false);
            return;
        }

        var body = HttpPrimitives.ReadBody(request);

        switch (route)
        {
            case "/api/jobs":
            case "/api/scan":
                {
                    var target = (body.Str("path") ?? "").Trim();
                    if (route == "/api/scan" && target.Length == 0)
                    {
                        await Json(response, new { error = "path is required" }, 400).ConfigureAwait(false);
                        return;
                    }
                    var started = ctx.Jobs.Start(target);
                    await Json(response, started, started is ScanJobError ? 409 : 202).ConfigureAwait(false);
                    return;
                }

            case "/api/jobs/cancel":
                {
                    var result = ctx.Jobs.Cancel(body.Str("id") ?? "");
                    await Json(response, result, result is ScanJobError ? 404 : 200).ConfigureAwait(false);
                    return;
                }

            case "/api/inventory":
                await Json(response,
                    ctx.Inventory.Start(body.Str("cidr") ?? "", body.Flag("services")), 202)
                    .ConfigureAwait(false);
                return;

            case "/api/inventory/cancel":
                await Json(response, ctx.Inventory.Cancel()).ConfigureAwait(false);
                return;

            case "/api/policy":
                await Json(response, ctx.Workbench.SetPolicy(
                    body.TryGetPropertyValue("enabled", out var enabled) && enabled is not null
                        ? enabled.GetValueKind() == JsonValueKind.True
                        : null)).ConfigureAwait(false);
                return;

            case "/api/native-av":
                await Json(response, ctx.Workbench.CheckNativeAv()).ConfigureAwait(false);
                return;

            case "/api/analysis":
                await Json(response, ctx.Workbench.Analyze(body.Str("text"))).ConfigureAwait(false);
                return;

            case "/api/ids/import":
                await Json(response, ctx.Workbench.ImportEve(body.Str("text"))).ConfigureAwait(false);
                return;

            case "/api/connectors/check":
                await Json(response, new
                {
                    opnsense = await ctx.OpnSense.HealthAsync(token).ConfigureAwait(false),
                    bitdefender = ctx.Bitdefender.Status(),
                }).ConfigureAwait(false);
                return;

            case "/api/domains":
                await Json(response, ctx.Workbench.SaveDomains(body.Str("text"))).ConfigureAwait(false);
                return;

            case "/api/playbooks/save":
                {
                    var saved = ctx.Playbooks.Save(body);
                    await Json(response, saved, saved.Ok ? 200 : 409).ConfigureAwait(false);
                    return;
                }

            case "/api/playbooks/run":
                {
                    var playbook = body.TryGetPropertyValue("playbook", out var selected) ? selected : null;
                    var run = await ctx.Playbooks.RunAsync(new PlaybookRunRequest
                    {
                        PlaybookId = playbook?.GetValueKind() == JsonValueKind.String
                            ? playbook.GetValue<string>()
                            : null,
                        Playbook = playbook?.GetValueKind() == JsonValueKind.Object ? playbook : null,
                        FindingId = body.Str("finding_id"),
                        DryRun = body.FlagOrDefault("dry_run", true),
                        Confirm = body.Flag("confirm"),
                    }, token).ConfigureAwait(false);
                    await Json(response, run, run.Ok ? 200 : 409).ConfigureAwait(false);
                    return;
                }

            case "/api/training/grade":
                {
                    var grade = ctx.Training.Grade(body.Str("id"), body.Str("answer"));
                    await Json(response, grade, grade.Ok ? 200 : 400).ConfigureAwait(false);
                    return;
                }

            case "/api/monitor":
                {
                    var action = (body.Str("action") ?? "").ToLowerInvariant();
                    if (action == "pause") ctx.Monitor.Pause();
                    else if (action is "resume" or "start") ctx.Monitor.Resume();
                    else
                    {
                        await Json(response, new { error = "action must be pause or resume" }, 400)
                            .ConfigureAwait(false);
                        return;
                    }
                    var status = ctx.Monitor.Status();
                    ctx.Store.Broadcast("Monitor " + (status.Paused ? "paused" : "resumed"));
                    await Json(response, status).ConfigureAwait(false);
                    return;
                }

            case "/api/rules/reload":
                {
                    var info = ctx.Engine.Reload();
                    ctx.Store.Broadcast("Reloaded " + info.RuleCount + " rules");
                    await Json(response, info).ConfigureAwait(false);
                    return;
                }

            case "/api/findings/clear":
                // Every other destructive route demands an explicit confirm.
                // This one wipes the whole dashboard, so it does too.
                if (!body.Flag("confirm"))
                {
                    await Json(response, new
                    {
                        error = "confirmation required",
                        detail = "resend with confirm=true",
                    }, 409).ConfigureAwait(false);
                    return;
                }
                {
                    // A refused clear is not a success. Answering 200 with
                    // cleared=false let the dashboard toast "Cleared N line(s)"
                    // and wipe its live feed while the server had changed
                    // nothing, so the refusal has to be a failure status for
                    // every client, not a field each one must remember to check.
                    var cleared = ctx.Store.Clear();
                    await Json(response, cleared, cleared.Cleared ? 200 : 503).ConfigureAwait(false);
                }
                return;

            case "/api/osv/query":
                {
                    if (ctx.Osv is null)
                    {
                        await Json(response, new { error = "osv adapter not enabled" }, 503).ConfigureAwait(false);
                        return;
                    }
                    await Json(response, await ctx.Osv.QueryAsync(
                        body.Str("commit"), body.Str("purl"), body.Str("package"),
                        body.Str("ecosystem"), body.Str("version"), token).ConfigureAwait(false))
                        .ConfigureAwait(false);
                    return;
                }

            case "/api/nvd/sync":
                {
                    if (ctx.Nvd is null)
                    {
                        await Json(response, new { error = "nvd adapter not enabled" }, 503).ConfigureAwait(false);
                        return;
                    }
                    var days = Math.Clamp(body.Int("days") ?? ctx.Config.NvdSyncDays, 1, 120);
                    var result = await ctx.Nvd.SyncAsync(days, ctx.Config.NvdMaxRecords, token)
                        .ConfigureAwait(false);

                    ctx.Store.Broadcast(result.Error is null
                        ? "NVD sync: " + result.Cached + " CVEs cached"
                        : "NVD sync failed: " + result.Error);
                    await Json(response, result).ConfigureAwait(false);
                    return;
                }

            case "/api/remediate":
                {
                    if (ctx.Remediator is null)
                    {
                        await Json(response, new { error = "remediation not enabled" }, 503).ConfigureAwait(false);
                        return;
                    }
                    var id = (body.Str("id") ?? "").Trim();
                    if (id.Length == 0)
                    {
                        await Json(response, new { error = "id is required" }, 400).ConfigureAwait(false);
                        return;
                    }

                    var result = ctx.Remediator.Act(
                        id,
                        body.Str("action") ?? RemediationActions.Quarantine,
                        confirm: body.Flag("confirm"),
                        dryRun: body.Flag("dry_run"),
                        allowDirectory: body.Flag("allow_directory"));

                    // A refusal is a considered answer, not a server fault, so it
                    // is 409 rather than 500.
                    var status = result.Ok ? 200
                        : result.Refused == "unknown finding" ? 404
                        : result.Refused == "unknown action" ? 400
                        : 409;
                    await Json(response, result, status).ConfigureAwait(false);
                    return;
                }

            case "/api/remediate/bulk":
                {
                    if (ctx.Remediator is null)
                    {
                        await Json(response, new { error = "remediation not enabled" }, 503).ConfigureAwait(false);
                        return;
                    }
                    await Json(response, ctx.Remediator.Bulk(
                        severity: body.Str("severity") ?? "",
                        extensions: body.Strings("extensions"),
                        action: body.Str("action") ?? RemediationActions.Quarantine,
                        confirm: body.Flag("confirm"),
                        // Defaults to true: a sweep must not become destructive
                        // because a field was omitted.
                        dryRun: body.FlagOrDefault("dry_run", true),
                        limit: Math.Clamp(body.Int("limit") ?? 50, 1, 500)))
                        .ConfigureAwait(false);
                    return;
                }

            case "/api/hunt/saved":
                {
                    if (body.Str("delete") is { Length: > 0 } huntId)
                    {
                        await Json(response, new { deleted = ctx.SavedHunts.Delete(huntId) })
                            .ConfigureAwait(false);
                        return;
                    }
                    try
                    {
                        await Json(response, ctx.SavedHunts.Save(
                            body.Str("name"), body.Str("query"), body.Str("description")))
                            .ConfigureAwait(false);
                    }
                    catch (HuntQueryException exc)
                    {
                        await Json(response, new { error = exc.Message }, 400).ConfigureAwait(false);
                    }
                    return;
                }

            case "/api/cases":
                await Json(response, ctx.Cases.Create(
                    body.Str("title"), body.Str("owner"),
                    body.Str("severity") ?? Severity.Medium,
                    body.Strings("finding_ids"), body.Str("summary")), 201).ConfigureAwait(false);
                return;

            case "/api/cases/update":
                await CaseResultAsync(response, ctx.Cases.Update(
                    body.Str("id") ?? "", body.Str("title"), body.Str("owner"),
                    body.Str("summary"), body.Str("status"), body.Str("severity")))
                    .ConfigureAwait(false);
                return;

            case "/api/cases/link":
                await CaseResultAsync(response, ctx.Cases.Link(
                    body.Str("id") ?? "", body.Strings("finding_ids"), body.Flag("detach")))
                    .ConfigureAwait(false);
                return;

            case "/api/cases/note":
                {
                    var noted = ctx.Cases.AddNote(body.Str("id") ?? "", body.Str("text"), body.Str("author"));
                    if (noted is null)
                    {
                        // Either the case is gone or the note was blank. Both are
                        // the caller's problem, not a server fault.
                        await Json(response, new { error = "unknown case, or empty note" }, 404)
                            .ConfigureAwait(false);
                        return;
                    }
                    await Json(response, noted).ConfigureAwait(false);
                    return;
                }

            case "/api/cases/delete":
                {
                    var deleted = ctx.Cases.Delete(body.Str("id") ?? "");
                    await Json(response, new { deleted }, deleted ? 200 : 404).ConfigureAwait(false);
                    return;
                }

            case "/api/triage":
                {
                    var status = body.Str("status") ?? "acknowledged";
                    if (!TriageStatuses.Contains(status))
                        throw new ArgumentException("Unknown triage status");

                    var updated = ctx.Store.SetStatus(body.Str("id") ?? "", status, body.Str("note") ?? "");
                    if (updated is null)
                    {
                        await Json(response, new { error = "finding not found" }, 404).ConfigureAwait(false);
                        return;
                    }
                    await Json(response, updated).ConfigureAwait(false);
                    return;
                }

            default:
                await Json(response, new { error = "not found" }, 404).ConfigureAwait(false);
                return;
        }
    }

    // ------------------------------------------------------------- responses
    private static Task Json(HttpListenerResponse response, object payload, int status = 200) =>
        DashboardServer.Json(response, payload, status);

    /// <summary>
    /// Serve one static file from the web directory.
    /// </summary>
    /// <remarks>
    /// The name comes from an allowlist, not from the request path, and the
    /// resolved path is still checked to be inside the web root. Either check
    /// alone would do; both together mean a traversal needs two bugs.
    /// </remarks>
    private async Task StaticAsync(HttpListenerResponse response, string name, bool headOnly)
    {
        var target = Path.GetFullPath(Path.Combine(webRoot, name));
        if (!PathUtil.IsWithin(target, webRoot) || !File.Exists(target))
        {
            await Json(response, new { error = "not found" }, 404).ConfigureAwait(false);
            return;
        }

        var body = await File.ReadAllBytesAsync(target).ConfigureAwait(false);
        response.StatusCode = 200;
        response.ContentType = HttpPrimitives.ContentTypeFor(target);
        response.ContentLength64 = body.Length;
        if (!headOnly) await response.OutputStream.WriteAsync(body).ConfigureAwait(false);
    }

    /// <summary>The findings a case points at, resolved from their ids.</summary>
    private List<SuiteEvent> CaseFindings(CaseRecord record)
    {
        var wanted = record.FindingIds.ToHashSet(StringComparer.Ordinal);
        if (wanted.Count == 0) return [];

        var found = ctx.Store.Events(limit: 5000, eventType: "all")
            .Where(e => wanted.Contains(e.Id))
            .ToList();

        return ctx.Remediator is not null ? ctx.Remediator.AnnotateMany(found) : found;
    }

    private static async Task CaseResultAsync(HttpListenerResponse response, CaseRecord? record)
    {
        if (record is null)
        {
            await Json(response, new { error = "unknown case" }, 404).ConfigureAwait(false);
            return;
        }
        await Json(response, record).ConfigureAwait(false);
    }

    /// <summary>
    /// Render one case as a self-contained incident report.
    /// </summary>
    /// <remarks>
    /// Served as a download rather than inline. The report is built from
    /// attacker-influenced text, and although every value in it is escaped,
    /// rendering it inline would put it on the dashboard's own origin.
    /// Content-Disposition keeps it a document the operator saves.
    /// </remarks>
    private async Task ReportAsync(HttpListenerResponse response,
                                   System.Collections.Specialized.NameValueCollection query,
                                   bool headOnly)
    {
        var record = ctx.Cases.Get(query.GetOrEmpty("id"));
        if (record is null)
        {
            await Json(response, new { error = "unknown case" }, 404).ConfigureAwait(false);
            return;
        }

        var findings = CaseFindings(record);
        var indicators = IocAggregator.Summarise(findings).Indicators;
        var campaigns = LinkGraph.Build(findings).Campaigns;

        var linked = record.FindingIds.ToHashSet(StringComparer.Ordinal);
        var remediation = ctx.Store.Events(limit: 500, eventType: SuiteEvent.TypeRemediation)
            .Where(e => e.GetExtra<string>("finding") is { } id && linked.Contains(id))
            .ToList();

        var html = IncidentReport.Render(record, findings, indicators, campaigns,
            remediation, EventStore.NowIso(), Version);

        var body = Encoding.UTF8.GetBytes(html);
        response.StatusCode = 200;
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength64 = body.Length;
        response.Headers["Content-Disposition"] =
            "attachment; filename=" + '"' + "incident-" + record.Id + ".html" + '"';

        if (!headOnly) await response.OutputStream.WriteAsync(body).ConfigureAwait(false);
    }

    /// <summary>Serve the application icon, wherever it actually lives.</summary>
    private async Task IconAsync(HttpListenerResponse response, bool headOnly)
    {
        foreach (var candidate in (string[])
                 [
                     Path.Combine(webRoot, "favicon.ico"),
                     Path.Combine(SuitePaths.Root, "assets", "securitysuite.ico"),
                 ])
        {
            if (!File.Exists(candidate)) continue;

            var body = await File.ReadAllBytesAsync(candidate).ConfigureAwait(false);
            response.StatusCode = 200;
            response.ContentType = "image/x-icon";
            response.ContentLength64 = body.Length;
            if (!headOnly) await response.OutputStream.WriteAsync(body).ConfigureAwait(false);
            return;
        }
        await Json(response, new { error = "not found" }, 404).ConfigureAwait(false);
    }

    private async Task SendTextAsync(HttpListenerResponse response, string content,
                                     string contentType, string filename)
    {
        var body = Encoding.UTF8.GetBytes(content);
        response.StatusCode = 200;
        response.ContentType = contentType;
        response.ContentLength64 = body.Length;
        response.Headers["Content-Disposition"] = "attachment; filename=\"" + filename + "\"";
        await response.OutputStream.WriteAsync(body).ConfigureAwait(false);
    }

    private async Task InventoryCsvAsync(HttpListenerResponse response)
    {
        var builder = new StringBuilder("ip,mac,services,last_seen\n");
        foreach (var device in ctx.Inventory.Status().Devices)
        {
            builder.Append(device.Ip).Append(',')
                   .Append(device.Mac).Append(',')
                   .Append(string.Join(";", device.Services.Select(s => s.Port))).Append(',')
                   .Append(device.LastSeen).Append('\n');
        }
        await SendTextAsync(response, builder.ToString(), "text/csv; charset=utf-8",
            "network-inventory.csv").ConfigureAwait(false);
    }

    private async Task DomainsExportAsync(HttpListenerResponse response)
    {
        var builder = new StringBuilder(
            "# Reviewed DNS hosts list. Import into your DNS filter to enforce.\n");
        foreach (var domain in ctx.Workbench.Domains()) builder.Append("0.0.0.0 ").Append(domain).Append('\n');

        await SendTextAsync(response, builder.ToString(), "text/plain; charset=utf-8",
            "reviewed-blocklist.txt").ConfigureAwait(false);
    }

    private async Task IocsAsync(HttpListenerResponse response, System.Collections.Specialized.NameValueCollection query)
    {
        var events = ctx.Store.Events(limit: 2000, eventType: SuiteEvent.TypeMatch);
        var data = IocAggregator.Summarise(events);

        var kind = query.GetOrEmpty("type");
        if (kind.Length > 0 && kind != "all")
            data.Indicators = [.. data.Indicators.Where(i => i.Type == kind)];

        if (query.GetOrEmpty("scope") == "external")
        {
            // Only addresses carry a scope, so other indicator types pass
            // through rather than being filtered out for lacking one.
            data.Indicators = [.. data.Indicators
                .Where(i => i.Type != IocKind.Ipv4 || i.Scope == "external")];
        }

        var limit = HttpPrimitives.Integer(query.Get("limit"), 300);
        var total = data.Indicators.Count;
        data.Indicators = [.. data.Indicators.Take(limit)];

        if (query.GetOrEmpty("format") == "csv")
        {
            await SendTextAsync(response, data.ToCsv(), "text/csv; charset=utf-8", "iocs.csv")
                .ConfigureAwait(false);
            return;
        }

        await Json(response, new
        {
            indicators = data.Indicators,
            by_type = data.ByType,
            total = data.Total,
            shown = Math.Min(limit, total),
            source_findings = events.Count,
        }).ConfigureAwait(false);
    }

    private async Task GuidanceAsync(HttpListenerResponse response,
                                     System.Collections.Specialized.NameValueCollection query,
                                     CancellationToken token)
    {
        if (ctx.Guidance is null)
        {
            await Json(response, new { error = "guidance not enabled" }, 503).ConfigureAwait(false);
            return;
        }

        var id = query.GetOrEmpty("id");
        if (id.Length == 0)
        {
            await Json(response, new { error = "id is required" }, 400).ConfigureAwait(false);
            return;
        }

        var finding = ctx.Store.Find(id);
        if (finding is null)
        {
            await Json(response, new { error = "unknown finding" }, 404).ConfigureAwait(false);
            return;
        }
        await Json(response, await ctx.Guidance.ForFindingAsync(finding, token).ConfigureAwait(false))
            .ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ state
    private object State() => new
    {
        version = Version,
        stats = ctx.Store.Stats(),
        monitor = ctx.Monitor.Status(),
        engine = ctx.Engine.Info(),
        telemetry = ctx.Telemetry.Recent(),
        config = new
        {
            watch_paths = ctx.Config.WatchPaths,
            lookback_minutes = ctx.Config.LookbackMinutes,
            max_file_mb = ctx.Config.MaxFileMb,
            poll_interval = ctx.Config.PollInterval,
            findings_log = ctx.Config.FindingsLog,
        },
        server_time = EventStore.NowIso(),
    };

    /// <summary>
    /// The intel source lattice. Never returns a credential, only whether one
    /// is configured.
    /// </summary>
    private object Intel()
    {
        var vtKey = ctx.Config.VirustotalApiKey.Trim();
        var vtState = ctx.VirusTotal?.Status();
        var vtStatus = vtState?.LastError is not null ? "offline"
            : vtKey.Length > 0 ? "ready"
            : "optional";

        var nvdState = ctx.Nvd?.Status();
        var nvdCached = nvdState?.Sync?.Cached ?? 0;
        var nvdStatus = nvdState is null ? "catalog"
            : nvdState.LastError is not null ? "offline"
            : nvdState.Syncing ? "syncing"
            : nvdCached > 0 ? "online"
            : "catalog";

        var sources = new List<Dictionary<string, object?>>();
        foreach (var id in IntelSources)
        {
            var (url, defaultStatus) = IntelMeta[id];
            var entry = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["id"] = id,
                ["url"] = url,
                ["status"] = id == "virustotal" ? vtStatus : defaultStatus,
                ["configured"] = id != "virustotal" || vtKey.Length > 0,
            };

            if (id == "virustotal" && vtState is not null)
            {
                entry["tier"] = vtState.Tier;
                entry["hunting"] = vtState.HuntingAvailable;
                entry["detail"] = vtState.HuntingAvailable ? "enterprise: hunting available"
                    : vtState.Configured ? "public tier: hash lookups only"
                    : "no key configured";
            }

            if (id == "osv" && ctx.Osv is not null)
            {
                var osvState = ctx.Osv.Status();
                entry["status"] = osvState.LastError is not null ? "offline"
                    : osvState.CachedQueries > 0 ? "online"
                    : "ready";
                entry["cached"] = osvState.CachedQueries;
                entry["detail"] = osvState.CachedQueries + " queries cached";
            }

            if (id == "nvd")
            {
                entry["status"] = nvdStatus;
                entry["cached"] = nvdCached;
                entry["last_sync"] = nvdState?.Sync?.LastSync;
                entry["detail"] = nvdCached > 0 ? nvdCached + " CVEs cached" : "not synced yet";
            }
            sources.Add(entry);
        }

        return new
        {
            status = vtStatus == "online" ? "live" : "linked",
            synced_at = EventStore.NowIso(),
            sources,
        };
    }

    // -------------------------------------------------------------------- SSE
    /// <summary>
    /// Server-Sent Events: push stored findings plus a periodic stats tick.
    /// </summary>
    /// <remarks>
    /// The stats tick exists so a quiet dashboard still updates its uptime and
    /// counters, and so a dead connection is noticed within a couple of seconds
    /// rather than whenever the next detection happens.
    /// </remarks>
    private async Task StreamAsync(HttpListenerResponse response, CancellationToken token)
    {
        var subscription = ctx.Store.Subscribe();

        response.StatusCode = 200;
        response.ContentType = "text/event-stream";
        response.Headers["Cache-Control"] = "no-cache";
        response.Headers["X-Accel-Buffering"] = "no";
        response.SendChunked = true;

        var stream = response.OutputStream;
        try
        {
            await SendEventAsync(stream, "hello", new { server_time = EventStore.NowIso() })
                .ConfigureAwait(false);

            var nextStats = DateTimeOffset.UtcNow;
            while (!token.IsCancellationRequested)
            {
                // Tell the client it fell behind, then close. Carrying on
                // would keep sending stats frames to a dashboard that has
                // silently missed findings, so it would look live while being
                // wrong. EventSource reconnects onto a fresh subscription.
                if (subscription.Overflowed)
                {
                    await SendEventAsync(stream, "overflow", new
                    {
                        message = "This stream fell behind and missed events; reconnecting.",
                        server_time = EventStore.NowIso(),
                    }).ConfigureAwait(false);
                    return;
                }

                using var tick = CancellationTokenSource.CreateLinkedTokenSource(token);
                tick.CancelAfter(TimeSpan.FromSeconds(1));

                try
                {
                    var item = await subscription.Reader.ReadAsync(tick.Token).ConfigureAwait(false);
                    await SendEventAsync(stream, "event", item).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    // Idle second; fall through to the stats tick.
                }

                if (DateTimeOffset.UtcNow >= nextStats)
                {
                    await SendEventAsync(stream, "stats", new
                    {
                        stats = ctx.Store.Stats(),
                        monitor = ctx.Monitor.Status(),
                    }).ConfigureAwait(false);
                    nextStats = DateTimeOffset.UtcNow.AddSeconds(2);
                }
            }
        }
        catch (Exception exc) when (exc is IOException or HttpListenerException
                                        or ObjectDisposedException or OperationCanceledException
                                        or InvalidOperationException)
        {
            // The browser closed the tab. Normal.
        }
        finally
        {
            ctx.Store.Unsubscribe(subscription);
        }
    }

    private static async Task SendEventAsync(Stream stream, string name, object payload)
    {
        var data = JsonSerializer.Serialize(payload, SuiteJson.Options);
        var frame = Encoding.UTF8.GetBytes("event: " + name + "\ndata: " + data + "\n\n");
        await stream.WriteAsync(frame).ConfigureAwait(false);
        await stream.FlushAsync().ConfigureAwait(false);
    }
}
