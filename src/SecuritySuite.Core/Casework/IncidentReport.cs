using System.Net;
using System.Reflection;
using System.Text;
using SecuritySuite.Intel;
using SecuritySuite.Storage;

namespace SecuritySuite.Casework;

/// <summary>
/// Render a case as a self-contained incident report.
/// </summary>
/// <remarks>
/// <para>
/// The report has to survive leaving this machine — mailed to a client,
/// attached to a ticket, filed as the record of what happened. So it is one
/// HTML file with no external stylesheet, no script, no webfont and no image
/// request: everything is inline, and print CSS gives a PDF through the browser
/// rather than through a new dependency.
/// </para>
/// <para>
/// <b>Every value that reaches the page is escaped.</b> Report content is drawn
/// from file paths, rule matches and extracted indicators, all of which are
/// attacker-influenced text. A report that executes markup from the thing it is
/// reporting on is its own incident.
/// </para>
/// </remarks>
public static class IncidentReport
{
    private static readonly Lazy<string> Stylesheet = new(LoadCss, isThreadSafe: true);

    private static string LoadCss()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var name = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("report.css", StringComparison.Ordinal));

        if (name is null) return "";
        using var stream = assembly.GetManifestResourceStream(name);
        if (stream is null) return "";

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>Escape for HTML text and attribute content alike.</summary>
    private static string E(object? value) =>
        WebUtility.HtmlEncode(value?.ToString() ?? "");

    /// <summary>Escape, then allow only the line breaks we introduce ourselves.</summary>
    private static string Lines(string? value) =>
        E(value).Replace("\n", "<br>");

    private static string SeverityChip(string? severity)
    {
        var name = Severity.Normalise(severity);
        return "<span class=\"sev sev-" + name + "\">" + E(name) + "</span>";
    }

    private static string Row(params string[] cells) =>
        "<tr>" + string.Concat(cells.Select(c => "<td>" + c + "</td>")) + "</tr>";

    public static string Render(CaseRecord caseRecord, List<SuiteEvent> findings,
                                List<AggregatedIndicator> indicators,
                                List<Campaign> campaigns, List<SuiteEvent> remediation,
                                string generatedAt, string suiteVersion = "")
    {
        var techniques = new Dictionary<string, AttackTechnique>(StringComparer.Ordinal);
        foreach (var finding in findings)
        {
            foreach (var match in finding.Matches ?? [])
            {
                foreach (var technique in AttackMapping.Resolve(match))
                    techniques[technique.Id] = technique;
            }
        }

        var tacticNames = AttackMapping.Tactics.ToDictionary(t => t.Id, t => t.Name, StringComparer.Ordinal);
        var tactics = AttackMapping.TacticsFor(techniques.Values);

        var severityCounts = Severity.All.ToDictionary(s => s, _ => 0, StringComparer.Ordinal);
        foreach (var finding in findings)
        {
            var name = Severity.Normalise(finding.Severity);
            severityCounts[name] = severityCounts.GetValueOrDefault(name) + 1;
        }

        var html = new StringBuilder();

        html.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
            .Append("<title>Incident report - ").Append(E(caseRecord.Title)).Append("</title>")
            .Append("<style>").Append(Stylesheet.Value).Append("</style></head><body>");

        html.Append("<h1>").Append(E(caseRecord.Title)).Append("</h1>")
            .Append("<div class=\"sub\">Incident report &middot; case ")
            .Append(E(caseRecord.Id)).Append(" &middot; generated ")
            .Append(E(generatedAt)).Append("</div>");

        html.Append("<div class=\"meta\">");
        foreach (var (label, value) in new (string, object?)[]
                 {
                     ("Status", caseRecord.Status),
                     ("Severity", caseRecord.Severity),
                     ("Owner", caseRecord.Owner.Length > 0 ? caseRecord.Owner : "unassigned"),
                     ("Findings", findings.Count),
                     ("Indicators", indicators.Count),
                     ("Techniques", techniques.Count),
                     ("Opened", caseRecord.CreatedAt),
                     ("Updated", caseRecord.UpdatedAt),
                 })
        {
            html.Append("<div><span>").Append(E(label)).Append("</span><b>")
                .Append(E(value)).Append("</b></div>");
        }
        html.Append("</div>");

        if (caseRecord.Summary.Length > 0)
            html.Append("<h2>Summary</h2><p>").Append(Lines(caseRecord.Summary)).Append("</p>");

        // ---------------------------------------------------------- ATT&CK
        html.Append("<h2>ATT&amp;CK</h2>");
        if (techniques.Count > 0)
        {
            html.Append("<p>Tactics observed: ")
                .Append(tactics.Count > 0
                    ? string.Join(", ", tactics.Select(t => E(tacticNames.GetValueOrDefault(t, t))))
                    : "none")
                .Append("</p>");

            html.Append("<table><thead><tr><th>Technique</th><th>Name</th><th>Tactics</th>")
                .Append("</tr></thead><tbody>");

            foreach (var id in techniques.Keys.Order(StringComparer.Ordinal))
            {
                var technique = techniques[id];
                html.Append(Row(
                    "<code>" + E(id) + "</code>",
                    E(technique.Name),
                    string.Join(", ", technique.Tactics.Select(x => E(tacticNames.GetValueOrDefault(x, x))))));
            }
            html.Append("</tbody></table>");
        }
        else
        {
            html.Append("<div class=\"empty\">No techniques mapped to the findings in this case.</div>");
        }

        // ------------------------------------------------------- correlation
        if (campaigns.Count > 0)
        {
            html.Append("<h2>Correlation</h2>");
            foreach (var campaign in campaigns)
            {
                var linked = string.Join(", ",
                    campaign.LinkedBy.Select(l => E(l.Type) + " " + E(l.Value)));

                html.Append("<h3>").Append(campaign.Size).Append(" findings linked ")
                    .Append(linked.Length > 0 ? "by " + linked : "by shared indicators")
                    .Append("</h3>");

                html.Append("<div class=\"muted\">").Append(E(campaign.FirstSeen))
                    .Append(" &rarr; ").Append(E(campaign.LastSeen))
                    .Append(" &middot; files: ")
                    .Append(string.Join(", ", campaign.Files.Select(E)))
                    .Append("</div>");
            }
        }

        // ---------------------------------------------------------- evidence
        html.Append("<h2>Evidence</h2>");
        if (findings.Count == 0)
            html.Append("<div class=\"empty\">No findings are linked to this case.</div>");

        foreach (var finding in findings)
        {
            html.Append("<div class=\"evidence\">")
                .Append(SeverityChip(finding.Severity)).Append(" <b>")
                .Append(E(!string.IsNullOrEmpty(finding.FileName)
                    ? finding.FileName
                    : LinkGraph.BaseName(finding.FilePath)))
                .Append("</b>");

            html.Append("<div class=\"path muted\">").Append(E(finding.FilePath)).Append("</div>");

            html.Append("<div class=\"mono muted\">sha256 ")
                .Append(E(finding.Sha256 ?? "-")).Append(" &middot; ")
                .Append(E(finding.FileSize?.ToString() ?? "-")).Append(" bytes &middot; entropy ")
                .Append(E(finding.GetExtra<double?>("entropy")?.ToString() ?? "-"))
                .Append(" &middot; ").Append(E(finding.Timestamp)).Append("</div>");

            foreach (var match in finding.Matches ?? [])
            {
                var chips = string.Concat(AttackMapping.Resolve(match)
                    .Select(t => "<span class=\"chip\">" + E(t.Id) + "</span>"));

                html.Append("<h3><code>").Append(E(match.Rule)).Append("</code> ")
                    .Append(chips).Append("</h3>");

                if (match.Description is { Length: > 0 } description)
                    html.Append("<div class=\"muted\">").Append(E(description)).Append("</div>");

                if (match.Strings.Count > 0)
                {
                    html.Append("<div class=\"strings\">")
                        .Append(string.Join("<br>", match.Strings.Take(8).Select(s =>
                            E(s.Identifier) + " @ 0x" + s.Offset.ToString("x") + "  " + E(s.Preview))))
                        .Append("</div>");
                }
            }
            html.Append("</div>");
        }

        // -------------------------------------------------------- indicators
        html.Append("<h2>Indicators</h2>");
        if (indicators.Count > 0)
        {
            html.Append("<table><thead><tr><th>Type</th><th>Indicator (defanged)</th>")
                .Append("<th>Files</th><th>Seen</th></tr></thead><tbody>");

            foreach (var item in indicators.Take(200))
            {
                html.Append(Row(
                    E(item.Type),

                    // Defanged, as everywhere else a human reads an indicator.
                    "<code>" + E(item.Defanged.Length > 0 ? item.Defanged : item.Value) + "</code>",
                    E(item.FileCount > 0 ? item.FileCount : item.Files.Count),
                    E(item.Occurrences > 0 ? item.Occurrences.ToString() : "-")));
            }
            html.Append("</tbody></table>");
        }
        else
        {
            html.Append("<div class=\"empty\">No indicators were extracted from these findings.</div>");
        }

        // ------------------------------------------------------- remediation
        html.Append("<h2>Remediation ledger</h2>");
        if (remediation.Count > 0)
        {
            html.Append("<table><thead><tr><th>When</th><th>Action</th><th>Target</th>")
                .Append("<th>Result</th></tr></thead><tbody>");

            foreach (var record in remediation.Take(100))
            {
                var ok = record.GetExtra<bool>("ok");
                var refused = record.GetExtra<string>("refused");

                html.Append(Row(
                    E(record.Timestamp),
                    "<code>" + E(record.GetExtra<string>("action")) + "</code>",
                    "<span class=\"mono\">" + E(record.FilePath) + "</span>",
                    E(ok ? "completed" : refused ?? "refused")));
            }
            html.Append("</tbody></table>");
        }
        else
        {
            html.Append("<div class=\"empty\">No remediation has been performed for this case.</div>");
        }

        // ------------------------------------------------------------- notes
        if (caseRecord.Notes.Count > 0)
        {
            html.Append("<h2>Case notes</h2>");
            foreach (var note in caseRecord.Notes)
            {
                html.Append("<div class=\"note\"><b>").Append(E(note.At))
                    .Append(note.Author.Length > 0 ? " &middot; " + E(note.Author) : "")
                    .Append("</b><br>").Append(Lines(note.Text)).Append("</div>");
            }
        }

        html.Append("<h2>Severity breakdown</h2><p>")
            .Append(string.Join(" &middot; ", Severity.All
                .Where(name => severityCounts.GetValueOrDefault(name) > 0)
                .Select(name => E(name) + " " + severityCounts[name])))
            .Append("</p>");

        html.Append("<div class=\"footer\">Generated by Security Suite ")
            .Append(E(suiteVersion)).Append(" on ").Append(E(generatedAt))
            .Append(". Self-contained: this file makes no external requests.</div>")
            .Append("</body></html>");

        return html.ToString();
    }
}
