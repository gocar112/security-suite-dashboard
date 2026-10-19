# Security Suite

<p align="center">
  <img src="assets/securitysuite.png" alt="Security Suite logo" width="112">
</p>

<p align="center">
  <strong>A local SOC signal room for YARA detections, IOC pivots, CVE context, triage, and guarded remediation.</strong>
</p>

![Security Suite dashboard overview](docs/images/dashboard.png)

Security Suite watches local folders, scans files against **1,004 YARA rules**,
correlates detections with authentication telemetry, extracts indicators,
enriches CVE findings with NVD/CISA context, and streams everything into a live
browser dashboard.

## Quick Links

- Operator guide: [book/Security-Suite-Operator-Guide.md](book/Security-Suite-Operator-Guide.md)
- Detection engineering field guide: [book/Detection-Engineering-in-Practice.pdf](book/Detection-Engineering-in-Practice.pdf)
- Database summary: [docs/database-summary.md](docs/database-summary.md)
- Main dashboard screenshot: [docs/images/dashboard.png](docs/images/dashboard.png)

## At A Glance

| Capability | What it does |
| --- | --- |
| Detect | Scans files with 1,004 YARA rules across malware, web shell, ransomware, credential theft, C2, supply-chain, Linux, Windows, and vulnerable-component namespaces. |
| Correlate | Pulls nearby failed-logon telemetry from Windows Security log, macOS unified log, Linux auth logs, or journald. |
| Pivot | Extracts URLs, domains, IPs, wallets, CVEs, hashes, registry keys, and file paths; dashboard values are defanged. |
| Enrich | Uses NVD, OSV, CISA KEV, and optional VirusTotal hash lookups for context. |
| Triage | Acknowledge, resolve, mark false positive, reopen, and clear dashboard lines with backup. |
| Remediate | Quarantine, restore, delete, and purge detection targets behind hash checks, path confinement, and an audit trail. |
| Map | Resolves every rule to MITRE ATT&CK techniques and renders a tactic-column coverage matrix, shaded by detection volume. |
| Hunt | A query language over findings - `severity:critical AND NOT status:resolved` - with saved hunts and a Ctrl-K command palette. |
| Correlate further | Link analysis over findings, indicators, and rules, clustering findings that share a C2 address or wallet into campaigns. |
| Case | Groups findings into cases with an owner, status, and notes, and exports a self-contained HTML incident report. |

## Quick Start

```powershell
python run.py
```

Then open:

```text
http://127.0.0.1:8787
```

The server is built on Python's standard `http.server`, and the dashboard is
plain HTML/CSS/JS. There is no frontend build step.

Fresh machine setup:

```powershell
pip install -r requirements.txt
python run.py
```

Recommended verification before release:

```powershell
python -m compileall securitysuite tools tests
python tests\smoke.py
python tests\test_api.py
python tests\test_hunt.py
python tests\test_cases.py
node --check web\app.js
python tools\summarize_database.py
```

## Requirements

| Package | Status | Needed for |
| --- | --- | --- |
| `yara-python` | Required | YARA compile and scan engine |
| `certifi` | Recommended | Current CA bundle for NVD TLS requests |
| `pywin32` | Optional, Windows only | Windows Security event-log telemetry |

Python 3.10 or newer is recommended.

## How To Use It

### 1. Start The Console

```powershell
python run.py
```

The console prints the loaded rule count, watched folders, telemetry source, and
whether auto-remediation is armed.

### 2. Drop A Test File

```powershell
copy samples\README_RESTORE.txt uploads\
```

On macOS or Linux:

```bash
cp samples/README_RESTORE.txt uploads/
```

The finding should appear in the dashboard within a few seconds.

![Findings table](docs/images/findings.png)

### 3. Open The Finding

Click the row to inspect the detection.

The drawer shows:

- Verdict, severity, and trigger.
- File path, SHA-256, size, entropy, and target state.
- Every matched rule and matched string offset.
- CVE, KEV, and patch guidance when available.
- Extracted indicators.
- Triage and remediation actions.

![Finding detail drawer](docs/images/finding-drawer.png)

### 4. Pivot Indicators

The indicator panel aggregates observables across all detected files.

![Extracted indicators](docs/images/indicators.png)

Use **Export CSV** when you want to hand the observable set to a SIEM or ticket.

### 5. Remediate Carefully

![Remediation panel](docs/images/remediation-panel.png)

Use **Quarantine** first when evidence might matter. Use **Delete** only when
the file is confirmed malicious or disposable.

## The Console

The dashboard is nine views behind a hash router, reachable from the rail or
with **Ctrl-K**. Switching views shows and hides blocks rather than
re-rendering them, so the event stream keeps feeding the findings table while
you are looking at something else.

| View | What it is for |
| --- | --- |
| Overview | Posture, KPIs, live feed, source lattice |
| Findings | The detection stream, filters, triage drawer |
| Hunt | Query language over findings, saved hunts |
| Indicators | Extracted observables, defanged, CSV export |
| ATT&CK | Coverage matrix by tactic; click a technique to filter the stream |
| Graph | Link analysis and campaign clusters |
| Cases | Casework and incident reports |
| Containment | Remediation rails and ledger |
| Intel | Source adapters |

The frontend is native ES modules under `web/js/`. There is still no build
step, no bundler, and no CDN.

## Hunting

The findings search box matches a substring against the whole event. That finds
things, but it cannot express the questions an analyst actually asks - and
matching `critical` as a substring also hits a file named
`critical_report.txt`. The Hunt view parses a real query:

```text
severity:critical AND NOT status:resolved
technique:T1486 OR technique:T1490
rule:PowerShell* -file:*samples*
severity:critical AND (rule:LockBit* OR rule:Conti*)
```

Fields: `severity status type rule namespace tag file path sha256 technique
tactic note`. Combine with `AND` / `OR` / `NOT` and parentheses; `*` and `?`
are wildcards; `-` is shorthand for `NOT`; adjacency implies `AND`; a bare word
is still free text. An unknown field is a parse error, not a silent no-match.

## ATT&CK Mapping

Every handwritten rule carries its techniques in its own metadata, beside
severity:

```text
meta:
    description = "Text that reads like a ransom note"
    severity = "critical"
    mitre = "T1486"
```

The technique table in [securitysuite/attack.py](securitysuite/attack.py) is
embedded, not fetched. This suite is loopback-bound and may run with no
outbound network; a coverage matrix that needs `attack.mitre.org` to render
fails closed in exactly the environment it is built for.

The 931 generated vulnerable-component rules map to `T1190` by namespace.
`Demo_TestKeyword` and `EICAR_Test_File` are deliberately unmapped: they are
test fixtures, not adversary behaviour, and tagging them would put phantom
coverage in the matrix.

**Reconnaissance and Resource Development show no coverage, and that is
correct.** A file scanner cannot observe them, and a matrix that implied
otherwise would be worth less than no matrix.

## Campaigns

Detections arrive as a flat list ordered by time, which is the one view that
hides the thing you most want to see: that six of them are the same intrusion.
The Graph view groups findings that share a *linking* indicator - a C2 address,
a wallet, a hash - into campaigns.

Indicator types that are merely common, such as a CVE id, stay in the graph as
nodes but do not merge findings. Half a corpus can mention `CVE-2021-44228`; if
that counted as evidence, every campaign would collapse into one blob.

## Cases And Reports

Triage marks one finding acknowledged. An intrusion is not one finding, and
"resolved" on six rows says nothing about whether anyone understood how they
were related. A case holds findings together with an owner, a status, and the
notes that make the decision reviewable later. Cases reference findings by id
and never copy them, so a case cannot drift out of date with its evidence.

`GET /api/report?case=<id>` renders one self-contained HTML file - summary,
ATT&CK mapping, evidence with hashes and matched offsets, indicators,
correlation, remediation ledger and notes. No external stylesheet, script,
webfont, or image request; print CSS gives a PDF through the browser rather
than through a new dependency. Every value is escaped: report content comes
from file paths, rule matches and extracted indicators, and a report that
executes markup from the thing it is reporting on is its own incident.

## Remediation Safety

Remediation is the destructive part of the suite. Everything else is read-first.

| Action | Meaning | Reversible? |
| --- | --- | --- |
| `quarantine` | Move the detected file into quarantine with metadata. | Yes |
| `restore` | Move a quarantined file back to its original path. | Usually |
| `delete` | Permanently remove the detected file. | No |
| `purge` | Permanently remove a quarantined copy. | No |

A remediation action proceeds only when the safety rails pass:

1. Target path comes from the stored finding, not from the browser request.
2. SHA-256 is re-checked immediately before action.
3. Resolved path must stay inside permitted roots.
4. Suite-owned paths are refused.
5. Directories are refused unless explicitly allowed.
6. Confirmation is required.
7. Already-handled targets are refused.
8. Attempts and refusals are written to the audit trail.

Auto-remediation is off by default. If enabled, the default action should remain
`quarantine`, not delete.

### Why rail 4 exists

Pointed at this repository, the current ruleset flags **27 of 55 tracked files,
16 of them critical** — including `rules/c2_network.yar` and
`rules/credential_theft.yar`. A rule that hunts for `sekurlsa::logonpasswords`
necessarily contains that string. Without the suite-owned-path rail, an
auto-delete-at-critical run would delete the detector's own ruleset.

An earlier version of that rail listed protected directories instead of
protecting the tree, and a test deleted this README. Enumerating what to protect
produces a list that is never complete.

> **Expect false positives.** 1,004 rules, 931 of them generated and never run
> against your data. One rule in this repo raised *critical* on a reading list
> containing the word *Exodus*. Prefer `quarantine` until a rule has earned your
> trust; `delete` cannot be undone.

## Clear Lines

**Clear lines** resets the active dashboard stream after backing it up.

It clears:

- `data/findings.ndjson`
- `data/triage.json`
- the live dashboard table/feed state

It does not clear:

- watched files
- quarantined files
- YARA rules
- Git history
- secrets or environment variables

Backups are written under:

```text
data/log-backups/
```

## Samples

Each sample is harmless text and is designed to trip one rule.

| Sample | Rule | Severity |
| --- | --- | --- |
| `README_RESTORE.txt` | `Ransom_Note_Template` | critical |
| `cleanup_commands.txt` | `Defense_Evasion_Commands` | critical |
| `dump_notes.txt` | `Credential_Dumper_Indicators` | critical |
| `task_setup.log` | `PowerShell_Encoded_Command` | high |
| `update_helper.txt` | `PowerShell_Download_Cradle` | high |
| `mail_body.txt` | `Suspicious_Double_Extension` | medium |
| `report_q3.txt` | clean scan | none |

## Intelligence And Database

The source lattice separates live adapters from reference links.

| Source | Credential | Purpose |
| --- | --- | --- |
| NVD | Optional | CVE lookup, keyword search, modification-window sync |
| OSV | None | Commit, package, version, and purl vulnerability lookup |
| VirusTotal | Required | Hash reputation; no file upload |
| CISA KEV | None | Known exploited vulnerability context |
| GitHub Advisories | None | Reference link |
| Vuls | None | Reference link |
| ClawFire | None | Reference link |

Summarize the local database:

```powershell
python tools\summarize_database.py
```

Sync a trailing NVD window while the server is running:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/api/nvd/sync -ContentType "application/json" -Body '{"days":3}'
```

## CLI

```powershell
python run.py
python run.py --watch D:\ftp --watch E:\inbox
python run.py --port 9000 --no-browser
python run.py --scan .\uploads
python run.py --headless
python run.py --scan-existing
```

## Configuration

Defaults live in [securitysuite/config.py](securitysuite/config.py). To override
them, create `config.json` in the project root.

```json
{
  "watch_paths": ["uploads"],
  "recursive": true,
  "poll_interval": 2.0,
  "settle_seconds": 1.0,
  "max_file_mb": 64,
  "lookback_minutes": 5,
  "host": "127.0.0.1",
  "port": 8787,
  "auto_remediate": false,
  "auto_remediate_action": "quarantine"
}
```

## API Snapshot

All endpoints are intended for localhost use. The server rejects non-loopback
`Host` headers.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/state` | Current stats, monitor status, engine info, telemetry, config |
| GET | `/api/findings` | Filtered findings |
| POST | `/api/findings/clear` | Back up and clear active dashboard lines |
| GET | `/api/rules` | Loaded rules and compile errors |
| POST | `/api/rules/reload` | Recompile the YARA ruleset |
| POST | `/api/scan` | Scan a file or directory |
| POST | `/api/monitor` | Pause or resume monitoring |
| POST | `/api/triage` | Acknowledge, resolve, false-positive, or reopen a finding |
| GET | `/api/iocs` | Extracted indicators, JSON or CSV |
| GET | `/api/remediate` | Remediation status and recent actions |
| GET | `/api/remediate/guidance` | Guidance for a finding |
| POST | `/api/remediate` | Quarantine, restore, delete, or purge one finding |
| POST | `/api/remediate/bulk` | Preview or execute bulk remediation |
| GET | `/api/nvd` | NVD cache status |
| POST | `/api/nvd/sync` | Sync a trailing NVD modification window |
| GET / POST | `/api/osv/query` | OSV lookup |
| GET | `/api/vt/file` | VirusTotal hash reputation |
| GET | `/api/attack/coverage` | ATT&CK coverage matrix: techniques, tactics, detections |
| GET | `/api/attack/techniques` | The embedded technique table |
| GET | `/api/hunt` | Run a hunt query (`?q=`) |
| GET / POST | `/api/hunt/saved` | List or save named hunts |
| GET | `/api/graph` | Findings/indicator/rule graph plus campaign clusters |
| GET / POST | `/api/cases` | List or create cases |
| GET | `/api/cases/detail` | One case with its findings resolved |
| POST | `/api/cases/{update,link,note,delete}` | Case mutations |
| GET | `/api/report` | Self-contained HTML incident report for a case |
| GET | `/api/stream` | Server-Sent Events stream |

## Project Layout

```text
run.py                         launcher
config.json                    optional local overrides
securitysuite/                 scanner, store, server, APIs
rules/                         YARA rules
rules/generated/               generated vulnerable-component rules
samples/                       harmless test files
uploads/                       default watched folder
web/                           dashboard HTML/CSS
web/js/                        ES modules: router, hunt, attack, graph, cases
assets/                        app logo and desktop icon
book/                          operator and field-guide documentation
docs/images/                   README screenshots
docs/database-summary.md       generated local database summary
data/findings.ndjson           active finding log
data/triage.json               active triage state
data/remediation.json          remediation audit/state
data/cases.json                cases and their notes
data/hunts.json                saved hunt queries
data/log-backups/              Clear lines backups
quarantine/                    quarantined files and metadata
nvds/                          local NVD cache
```

## Documentation

Use the README for setup and release checks. Use the operator guide for daily
workflow:

- [Security Suite Operator Guide](book/Security-Suite-Operator-Guide.md)
- [Detection Engineering In Practice PDF](book/Detection-Engineering-in-Practice.pdf)
- [Detection Engineering In Practice DOCX](book/Detection-Engineering-in-Practice.docx)

## Security Notes

- Keep the server bound to `127.0.0.1` unless you add authentication.
- Run as Administrator on Windows only if you need Security event-log telemetry.
- Never paste API keys, GitHub tokens, passwords, or private keys into commits,
  issues, README files, or chat.
- This client never uploads files to VirusTotal. Hash reputation is lookup-only.
- Remediation is manual by default. Leave auto-remediation off until rules are
  tested against your own data.

## What Changed From `YARA_scanning.py`

| Original | Security Suite |
| --- | --- |
| One directory, non-recursive scan loop | Recursive watcher with settle checks |
| Rule compile failure could hide behind fallback behavior | Compile errors are surfaced by rule file |
| Rule matches were just names | Full rule metadata, strings, offsets, severity, and namespace |
| No file identity | SHA-256, size, mtime, entropy, and target state |
| Own logs could be rescanned | Suite output and protected paths are excluded |
| No pause or reload | Pause/resume monitor and hot-reload rules |
| Print/log output | Live dashboard, triage workflow, IOC panel, JSON API |
| Detection only | Guarded quarantine, restore, delete, purge, and clear lines |
