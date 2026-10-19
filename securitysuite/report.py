"""Render a case as a self-contained incident report.

The report has to survive leaving this machine - mailed to a client, attached
to a ticket, filed as the record of what happened. So it is one HTML file with
no external stylesheet, no script, no webfont and no image request: everything
is inline, and print CSS gives a PDF through the browser rather than through a
new dependency.

Every value that reaches the page is escaped. Report content is drawn from file
paths, rule matches and extracted indicators - all attacker-influenced text -
and a report that executes markup from the thing it is reporting on is its own
incident.
"""
from __future__ import annotations

from html import escape

from . import attack
from .store import SEVERITIES

CSS = """
:root{--ink:#10161f;--dim:#5b6472;--line:#dfe3e9;--bg:#fff;--accent:#0f766e;
--critical:#b91c1c;--high:#c2410c;--medium:#a16207;--low:#3f6212;--info:#475569}
*{box-sizing:border-box}
body{margin:0;padding:38px 46px;background:var(--bg);color:var(--ink);
font:14px/1.62 "Segoe UI",system-ui,-apple-system,sans-serif;max-width:1000px}
h1{font-size:25px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:15px;margin:30px 0 10px;padding-bottom:6px;
border-bottom:1px solid var(--line);letter-spacing:.02em;text-transform:uppercase}
h3{font-size:13.5px;margin:18px 0 6px}
.sub{color:var(--dim);font-size:13px;margin-bottom:20px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:12px;margin:18px 0;padding:14px 16px;border:1px solid var(--line);border-radius:8px}
.meta div span{display:block;font-size:10.5px;text-transform:uppercase;
letter-spacing:.06em;color:var(--dim);margin-bottom:2px}
.meta div b{font-size:14px;font-weight:600}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:12.5px}
th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;
color:var(--dim);border-bottom:1px solid var(--line);padding:6px 8px}
td{padding:7px 8px;border-bottom:1px solid #f1f3f6;vertical-align:top}
code,.mono{font-family:"Cascadia Mono",Consolas,monospace;font-size:11.5px}
.sev{display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;
letter-spacing:.05em;padding:1px 7px;border-radius:3px;color:#fff}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}
.sev-medium{background:var(--medium)}.sev-low{background:var(--low)}
.sev-info{background:var(--info)}
.chip{display:inline-block;font-family:"Cascadia Mono",Consolas,monospace;
font-size:10.5px;border:1px solid var(--accent);color:var(--accent);
border-radius:3px;padding:0 5px;margin:0 3px 3px 0}
.note{border-left:3px solid var(--line);padding:2px 0 2px 12px;margin:9px 0}
.note b{font-size:11.5px;color:var(--dim);font-weight:600}
.muted{color:var(--dim)}
.empty{color:var(--dim);font-style:italic;font-size:12.5px}
.evidence{border:1px solid var(--line);border-radius:7px;padding:11px 13px;margin:9px 0}
.evidence .path{font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;
word-break:break-all;margin-bottom:5px}
.strings{background:#f7f8fa;border-radius:5px;padding:8px 10px;margin-top:7px;
font-family:"Cascadia Mono",Consolas,monospace;font-size:11px;color:#374151}
.footer{margin-top:34px;padding-top:12px;border-top:1px solid var(--line);
font-size:11px;color:var(--dim)}
@media print{body{padding:0;max-width:none}h2{page-break-after:avoid}
.evidence{page-break-inside:avoid}.meta{page-break-inside:avoid}}
"""


def _e(value) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _sev(severity) -> str:
    name = str(severity or "info")
    if name not in SEVERITIES:
        name = "info"
    return '<span class="sev sev-%s">%s</span>' % (name, _e(name))


def _rows(cells: list[str]) -> str:
    return "<tr>" + "".join("<td>%s</td>" % c for c in cells) + "</tr>"


def render(case: dict, findings: list[dict], indicators: list[dict],
           campaigns: list[dict], remediation: list[dict],
           generated_at: str, suite_version: str = "") -> str:
    """One self-contained HTML document. No external requests, ever."""
    techniques: dict[str, dict] = {}
    for finding in findings:
        for match in finding.get("matches") or []:
            for technique in match.get("attack") or []:
                if technique.get("id"):
                    techniques[technique["id"]] = technique

    tactics = attack.tactics_for(list(techniques.values()))
    sev_counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        name = finding.get("severity") or "info"
        sev_counts[name] = sev_counts.get(name, 0) + 1

    parts: list[str] = []
    add = parts.append

    add("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    add("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    add("<title>Incident report - %s</title>" % _e(case.get("title")))
    add("<style>%s</style></head><body>" % CSS)

    add("<h1>%s</h1>" % _e(case.get("title")))
    add('<div class="sub">Incident report &middot; case %s &middot; generated %s</div>'
        % (_e(case.get("id")), _e(generated_at)))

    add('<div class="meta">')
    for label, value in (
        ("Status", case.get("status", "open")),
        ("Severity", case.get("severity", "medium")),
        ("Owner", case.get("owner") or "unassigned"),
        ("Findings", len(findings)),
        ("Indicators", len(indicators)),
        ("Techniques", len(techniques)),
        ("Opened", case.get("created_at")),
        ("Updated", case.get("updated_at")),
    ):
        add("<div><span>%s</span><b>%s</b></div>" % (_e(label), _e(value)))
    add("</div>")

    if case.get("summary"):
        add("<h2>Summary</h2><p>%s</p>" % _e(case["summary"]).replace("\n", "<br>"))

    # ------------------------------------------------------------- ATT&CK
    add("<h2>ATT&amp;CK</h2>")
    if techniques:
        add("<p>Tactics observed: %s</p>" % ", ".join(
            _e(attack.TACTIC_NAMES.get(t, t)) for t in tactics) or "none")
        add("<table><thead><tr><th>Technique</th><th>Name</th><th>Tactics</th>"
            "</tr></thead><tbody>")
        for tid in sorted(techniques):
            technique = techniques[tid]
            add(_rows(["<code>%s</code>" % _e(tid), _e(technique.get("name")),
                       ", ".join(_e(attack.TACTIC_NAMES.get(x, x))
                                 for x in technique.get("tactics") or [])]))
        add("</tbody></table>")
    else:
        add('<div class="empty">No techniques mapped to the findings in this case.</div>')

    # ---------------------------------------------------------- campaigns
    if campaigns:
        add("<h2>Correlation</h2>")
        for campaign in campaigns:
            linked = ", ".join("%s %s" % (_e(l["type"]), _e(l["value"]))
                               for l in campaign.get("linked_by") or [])
            add("<h3>%s findings linked %s</h3>" % (
                campaign.get("size"), ("by " + linked) if linked else "by shared indicators"))
            add('<div class="muted">%s &rarr; %s &middot; files: %s</div>' % (
                _e(campaign.get("first_seen")), _e(campaign.get("last_seen")),
                ", ".join(_e(f) for f in campaign.get("files") or [])))

    # ----------------------------------------------------------- evidence
    add("<h2>Evidence</h2>")
    if not findings:
        add('<div class="empty">No findings are linked to this case.</div>')
    for finding in findings:
        add('<div class="evidence">')
        add("%s <b>%s</b>" % (_sev(finding.get("severity")),
                              _e(finding.get("file_name")
                                 or (finding.get("file_path") or "").split("\\")[-1])))
        add('<div class="path muted">%s</div>' % _e(finding.get("file_path")))
        add('<div class="mono muted">sha256 %s &middot; %s bytes &middot; entropy %s '
            '&middot; %s</div>' % (
                _e(finding.get("sha256") or "-"), _e(finding.get("file_size") or "-"),
                _e(finding.get("entropy") if finding.get("entropy") is not None else "-"),
                _e(finding.get("timestamp"))))
        for match in finding.get("matches") or []:
            chips = "".join('<span class="chip">%s</span>' % _e(t.get("id"))
                            for t in match.get("attack") or [])
            add("<h3><code>%s</code> %s</h3>" % (_e(match.get("rule")), chips))
            if match.get("description"):
                add('<div class="muted">%s</div>' % _e(match["description"]))
            strings = match.get("strings") or []
            if strings:
                add('<div class="strings">' + "<br>".join(
                    "%s @ 0x%x  %s" % (_e(s.get("identifier")),
                                       int(s.get("offset") or 0), _e(s.get("preview")))
                    for s in strings[:8]) + "</div>")
        add("</div>")

    # --------------------------------------------------------- indicators
    add("<h2>Indicators</h2>")
    if indicators:
        add("<table><thead><tr><th>Type</th><th>Indicator (defanged)</th>"
            "<th>Files</th><th>Seen</th></tr></thead><tbody>")
        for item in indicators[:200]:
            add(_rows([_e(item.get("type")),
                       "<code>%s</code>" % _e(item.get("defanged") or item.get("value")),
                       _e(item.get("file_count") or len(item.get("files") or [])),
                       _e(item.get("occurrences") or "-")]))
        add("</tbody></table>")
    else:
        add('<div class="empty">No indicators were extracted from these findings.</div>')

    # -------------------------------------------------------- remediation
    add("<h2>Remediation ledger</h2>")
    if remediation:
        add("<table><thead><tr><th>When</th><th>Action</th><th>Target</th>"
            "<th>Result</th></tr></thead><tbody>")
        for record in remediation[:100]:
            ok = record.get("ok")
            add(_rows([_e(record.get("timestamp") or record.get("at")),
                       "<code>%s</code>" % _e(record.get("action")),
                       '<span class="mono">%s</span>' % _e(record.get("file_path")),
                       _e("completed" if ok else (record.get("refused") or "refused"))]))
        add("</tbody></table>")
    else:
        add('<div class="empty">No remediation has been performed for this case.</div>')

    # --------------------------------------------------------------- notes
    if case.get("notes"):
        add("<h2>Case notes</h2>")
        for note in case["notes"]:
            add('<div class="note"><b>%s%s</b><br>%s</div>' % (
                _e(note.get("at")),
                (" &middot; " + _e(note.get("author"))) if note.get("author") else "",
                _e(note.get("text")).replace("\n", "<br>")))

    add("<h2>Severity breakdown</h2><p>" + " &middot; ".join(
        "%s %d" % (_e(name), sev_counts.get(name, 0))
        for name in SEVERITIES if sev_counts.get(name)) + "</p>")

    add('<div class="footer">Generated by Security Suite %s on %s. '
        "Self-contained: this file makes no external requests.</div>"
        % (_e(suite_version), _e(generated_at)))
    add("</body></html>")
    return "".join(parts)
