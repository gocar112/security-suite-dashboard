# Security Suite

<p align="center">
  <img src="assets/securitysuite.png" alt="Security Suite logo" width="112">
</p>

<p align="center">
  <strong>A local SOC signal room for YARA detections, IOC pivots, CVE context, triage, and guarded remediation.</strong>
</p>

![Security Suite tabbed console](docs/images/console-1440.png)

Security Suite watches local folders, scans files against **1,004 YARA rules**,
correlates detections with authentication telemetry, extracts indicators,
enriches CVE findings with NVD/CISA context, models AV/IDS/IPS posture, and
streams everything into a live browser dashboard. The tabbed console adds
background drive scans, household device inventory, Suricata alert import,
visual playbooks, a text-analysis lab, and local two-player training.

This is a defensive workbench that supplements installed endpoint protection.
It is not NSA affiliated or certified, and a low alert count does not establish
that a computer or network is safe.

## Quick Links

- Operator guide: [book/Security-Suite-Operator-Guide.md](book/Security-Suite-Operator-Guide.md)
- Detection engineering field guide: [book/Detection-Engineering-in-Practice.pdf](book/Detection-Engineering-in-Practice.pdf)
- Database summary: [docs/database-summary.md](docs/database-summary.md)
- Release summary: [docs/release-summary.md](docs/release-summary.md)
- Main dashboard screenshot: [docs/images/console-1440.png](docs/images/console-1440.png)

## At A Glance

| Capability | What it does |
| --- | --- |
| Detect | Scans files with 1,004 YARA rules across malware, web shell, ransomware, credential theft, C2, supply-chain, Linux, Windows, and vulnerable-component namespaces. |
| Correlate | Pulls nearby failed-logon telemetry from Windows Security log, macOS unified log, Linux auth logs, or journald. |
| Pivot | Extracts URLs, domains, IPs, wallets, CVEs, hashes, registry keys, and file paths; dashboard values are defanged. |
| Enrich | Uses NVD, OSV, CISA KEV, and optional VirusTotal hash lookups for context. |
| Shield | Shows local AV, IDS, IPS, Bitdefender-ready, NVD, and CISA KEV defensive layers. |
| Triage | Acknowledge, resolve, mark false positive, reopen, and clear dashboard lines with backup. |
| Remediate | Quarantine, restore, delete, and purge detection targets behind hash checks, path confinement, and an audit trail. |
| Drive scan | Walks a local drive in a background job without a file-count limit; shows progress, skips, errors and cancellation. |
| Inventory | Discovers devices on an explicitly selected RFC1918 IPv4 subnet (/24 through /32), with optional checks of eight service ports. |
| Playbooks | Drag or select skills, attach a stored finding, simulate, save, import/export JSON, and run approved actions. |
| Analysis lab | Matches pasted text against YARA and extracts indicators without executing or storing the text. |
| Training | Offers 500 synthetic defensive scenarios for two people sharing the same browser. These are tabletop questions, not validated exploit tests. |

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
If the default port is occupied, the launcher tries the next nine ports. It
reuses a running console only when its version and workspace match. An explicit
`--port` does not fall back. Use the URL printed by the launcher.

Fresh machine setup:

```powershell
pip install -r requirements.txt
python run.py
```

Recommended verification before release:

```powershell
python -m compileall securitysuite tools tests
node --check web\app.js
node --check web\console.js
python -m unittest discover -s tests -p 'test_*.py' -v
python tests\smoke.py
python tools\summarize_database.py --output docs\database-summary.md
```

## Requirements

| Package | Status | Needed for |
| --- | --- | --- |
| `yara-python` | Required | YARA compile and scan engine |
| `certifi` | Recommended | Current CA bundle for NVD TLS requests |
| `pywin32` | Optional, Windows only | Windows Security event-log telemetry |

Python 3.10 or newer is recommended.

## Workspace Tabs

Overview keeps findings, indicator pivots, activity and logs together. Antivirus
contains local-drive selection, scan jobs, and a Windows Security Center product
check. Registered products are reported as registered; that check does not prove
current protection or fresh signatures.

IDS accepts up to 100 Suricata EVE NDJSON records per import. Only alert records
are stored, and imported file paths cannot become remediation targets. IPS /
Response contains the existing guarded containment controls and a persistent
automatic-quarantine toggle. Automatic response requires an eligible matched
rule with `confidence = "high"`, the configured severity threshold, a recorded
hash that still matches, and a permitted root. Generated component rules and
test rules never authorize automatic response. Rule authors should add this
metadata only after tuning against benign samples. Deletion stays manual.

Inventory checks one selected private IPv4 subnet at a time. Devices that block
ping and expose none of the selected TCP ports may be missed; neighbor-cache
entries may be stale. Port labels do not establish device identity or vulnerability.
Run a local scanner on each computer to inspect its files. TVs and IoT devices
can appear in inventory; their firmware is not scanned by this program.

Playbooks accepts only the checked-in [schema](web/playbook.schema.json): annotate,
guidance, and quarantine. Select a finding, build a sequence, and simulate it
before running. External coding agents can generate matching JSON for import;
the server validates every plan. Arbitrary generated scripts are not executed.
Live steps stop on failure, and successful earlier steps are not rolled back.

![Visual playbook builder with reviewed response steps](docs/images/console-playbooks.png)

To use it: choose a stored detection, add skills, fill any annotation, then
Validate and Simulate. Review the results before Execute. Every edit requires
a fresh simulation. Start with guidance and annotation before adding quarantine.

The analysis lab is static text analysis, not a virtual machine or malware
execution sandbox. Training is local pass-and-play; it has no online multiplayer
service. Display density can be increased for a TV, and every tab adapts to
desktop, tablet and narrow screens.

## OPNsense And DNS Filters

Set `OPNSENSE_URL`, `OPNSENSE_API_KEY`, and `OPNSENSE_API_SECRET` in the local
`.env`. Use an HTTPS private IPv4 origin with a trusted certificate. The
Integrations tab performs a read-only IDS service-status check. A running service
does not verify that IPS drop rules are enabled or that every network interface
is covered. See [OPNsense IDS/IPS setup](https://docs.opnsense.org/manual/ips.html).

The reviewed domain list can be saved and exported for import into a DNS filter.
Saving a list does not block ads or spyware by itself. Use your gateway's DNS
filter settings to enforce a reviewed list; see
[OPNsense Unbound blocklists](https://docs.opnsense.org/manual/unbound.html).
Rules should target malicious behavior and evidence, not country of origin.
The Bitdefender panel reports setup only; the GravityZone control API is not
implemented. Keep your installed antivirus enabled.

## Repository Security

[SECURITY.md](SECURITY.md) documents reporting and deployment boundaries.
Dependabot configuration checks Python and Actions dependencies weekly; CodeQL
analyzes Python and JavaScript on pushes, pull requests and its weekly schedule.
CI runs the boundary and smoke checks on Windows, Linux and macOS. These checks
do not certify malware-detection accuracy or test live household devices.

Administrators should verify dependency graph, Dependabot security alerts,
secret scanning, push protection and private vulnerability reporting under the
repository's Security / Advanced Security settings. Configuration files alone
do not enable those account-level settings. Follow the
[GitHub repository-security quickstart](https://docs.github.com/en/code-security/getting-started/quickstart-for-securing-your-repository).
Keep `.env`, runtime logs, device inventories and quarantine contents out of git.

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

### 5. Use The Shield Fabric

The **Antivirus / IDS / IPS** panel summarizes the defensive stack:

- AV: local YARA scanner, quarantine, hash identity, and guarded delete.
- IDS: finding stream, live alerts, IOC extraction, and auth telemetry.
- IPS: manual containment actions after preview and confirmation.
- Patch: NVD, CISA KEV, vendor advisory links, and remediation playbooks.
- Connector-ready: Bitdefender GravityZone can be bridged later through its
  official HTTPS JSON-RPC API by setting `BITDEFENDER_API_KEY` and
  `BITDEFENDER_API_URL` in `.env`.

The attack pressure library maps **500 defensive attack reasons** to safe
responses. It is for training, triage, and coverage planning; it does not
include exploit steps.

### 6. Remediate Carefully

![Remediation panel](docs/images/remediation-panel.png)

Use **Quarantine** first when evidence might matter. Use **Delete** only when
the file is confirmed malicious or disposable.

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

## Launcher And Startup

Create a quiet desktop launcher:

```powershell
python install_shortcut.py
```

Start Security Suite automatically when you sign in:

```powershell
python install_shortcut.py --startup
```

Windows shortcuts use `pythonw.exe` when it is available, which avoids the black
PowerShell/console window. Linux desktop entries use `Terminal=false`, and macOS
gets a quiet `.app` bundle.

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
| Bitdefender GravityZone | Required for live connector | Connector-ready policy, report, quarantine, sandbox, and network API map |
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
| POST | `/api/scan` | Start a background file/directory scan (202; poll `/api/jobs`) |
| GET / POST | `/api/jobs` | Scan progress / start a job |
| POST | `/api/jobs/cancel` | Request cooperative scan cancellation |
| GET | `/api/drives` | List local fixed drives |
| GET / POST | `/api/inventory` | Inventory snapshot / start explicit private-subnet discovery |
| GET | `/api/inventory/export` | Export observed devices as CSV |
| POST | `/api/ids/import` | Import validated Suricata EVE alerts |
| GET | `/api/workspace` | Read response policy, native AV registration and reviewed domains |
| POST | `/api/policy` | Update automatic-quarantine policy |
| POST | `/api/analysis` | Analyze text without execution or persistence |
| GET | `/api/playbooks` | Saved plans and allowed skills |
| POST | `/api/playbooks/save` | Save a schema-validated plan |
| POST | `/api/playbooks/run` | Simulate or execute approved steps on a stored finding |
| GET | `/api/training` | Synthetic defensive scenarios |
| POST | `/api/training/grade` | Grade one tabletop response |
| POST | `/api/monitor` | Pause or resume monitoring |
| POST | `/api/triage` | Acknowledge, resolve, false-positive, or reopen a finding |
| GET | `/api/shield` | AV/IDS/IPS posture, attack-pressure library, and file split groups |
| GET | `/api/iocs` | Extracted indicators, JSON or CSV |
| GET | `/api/remediate` | Remediation status and recent actions |
| GET | `/api/remediate/guidance` | Guidance for a finding |
| POST | `/api/remediate` | Quarantine, restore, delete, or purge one finding |
| POST | `/api/remediate/bulk` | Preview or execute bulk remediation |
| GET | `/api/nvd` | NVD cache status |
| POST | `/api/nvd/sync` | Sync a trailing NVD modification window |
| GET / POST | `/api/osv/query` | OSV lookup |
| GET | `/api/vt/file` | VirusTotal hash reputation |
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
web/                           dashboard HTML/CSS/JS
assets/                        app logo and desktop icon
book/                          operator and field-guide documentation
docs/images/                   README screenshots
docs/database-summary.md       generated local database summary
data/findings.ndjson           active finding log
data/triage.json               active triage state
data/remediation.json          remediation audit/state
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

- Keep the console on loopback; this release rejects non-local bind addresses.
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
