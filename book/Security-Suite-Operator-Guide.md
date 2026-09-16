# Security Suite Operator Guide

Version: 2026-09-16

This book explains how to run the Security Suite, read the dashboard, triage
findings, pivot indicators, update the local vulnerability database, understand
the AV/IDS/IPS shield layer, and use remediation without turning a false
positive into data loss.

The suite is a local defensive SOC console. It watches files, scans them with
YARA, extracts indicators, enriches CVE signals, maps common attack pressure to
safe playbooks, and gives the operator guarded actions such as quarantine,
restore, delete, purge, and clear lines.

## Table of contents

1. What this tool is
2. Quick start
3. Dashboard map
4. Running scans
5. Reading a finding
6. Indicator pivots
7. Shield fabric
8. Triage workflow
9. Remediation workflow
10. Clear lines and log backups
11. Database and NVD updates
12. Release and GitHub workflow
13. Troubleshooting
14. Operator checklist
15. Tabbed workspace and release upgrade

## 1. What this tool is

Security Suite is built for local defensive testing and small SOC-style
operations. It is not an antivirus replacement. It is a signal room: the tool
shows what matched, why it matched, what indicators were found, and what action
an operator can safely take.

Core jobs:

- Watch configured folders for new or changed files.
- Scan files with the local YARA ruleset.
- Record findings in `data/findings.ndjson`.
- Track triage state in `data/triage.json`.
- Extract URLs, domains, IP addresses, hashes, registry paths, file paths,
  wallets, and CVEs.
- Enrich CVE findings with local NVD/CISA context when available.
- Map AV, IDS, IPS, patch, and connector-ready controls in the dashboard.
- Remediate only verified detection targets.
- Back up active dashboard lines before clearing the live view.

Important rule: remediation must act on a stored finding, not on a random path
typed by a browser client. That is what keeps the delete and quarantine buttons
from becoming arbitrary file tools.

The current release also provides whole-drive scan jobs, private-network device
inventory, Suricata alert import, visual response playbooks, static text analysis,
and local two-player training. A rule hit can identify a vulnerable component or
a suspicious string; review evidence before treating it as confirmed malware.

## 2. Quick start

From the project root:

```powershell
python run.py
```

Then open:

```text
http://127.0.0.1:8787
```

The browser usually opens automatically. The console should report the loaded
rule count, the watched paths, and whether monitor mode is running.

Recommended first check:

```powershell
python -m compileall securitysuite tools
node --check web\app.js
```

If this is a fresh machine, install dependencies first:

```powershell
pip install -r requirements.txt
```

The required dependency is `yara-python`. `certifi` helps with TLS for online
NVD calls. `pywin32` is optional and only helps Windows event-log collection.

## 3. Dashboard map

The dashboard is arranged for fast operator work.

Top bar:

- Stream status shows whether the browser is connected.
- Monitor status shows whether the file watcher is active.
- Rules pill shows the loaded YARA rule count.
- Pause stops monitoring without closing the server.
- Reload rules recompiles the rule set.

Mission area:

- Posture index summarizes current risk.
- Source cards show whether enrichment sources are linked, ready, or online.
- Operator controls let you tune sensitivity, focus mode, and event tone.

KPI row:

- Files scanned is the session total.
- Detections counts YARA hits.
- Open alerts counts findings still needing triage.
- Critical / high shows priority detections.
- Auth failures shows authentication correlation.
- Uptime shows how long the watcher has been running.

Main work area:

- Findings is the live detection stream.
- Extracted indicators is the pivot table.
- Shield Fabric shows AV/IDS/IPS layers, Bitdefender-ready connector state,
  defensive attack pressure, patch playbooks, and file split groups.
- Detection activity shows recent activity.
- Live feed shows compact event lines.
- Containment handles bulk remediation previews and actions.

Right sidebar:

- On-demand scan accepts a local path.
- Namespaces and severity panels summarize the current dataset.
- Recent sources summarize scan origins.

## 4. Running scans

There are two normal ways to scan.

Monitor mode:

1. Start the suite.
2. Put a file inside a watched folder such as `uploads`.
3. Wait for the finding to appear.

On-demand mode:

1. Paste a local file path into the on-demand scan box.
2. Click Scan.
3. Open the finding from the table if a rule matches.

For testing PowerShell detections, use a disposable file under the project
`uploads` folder. Do not test delete on valuable files. A detection test should
be easy to recreate.

## 5. Reading a finding

Click a finding row to open the detail drawer.

Look at these fields first:

- Verdict: severity, trigger, and time.
- Path: the target file that was scanned.
- SHA-256: the hash recorded at detection time.
- Status: new, acknowledged, resolved, false positive, or reopened.
- Target state: whether the file is present, missing, quarantined, deleted, or
  purged.
- Rule matches: rule names, namespaces, tags, descriptions, and matched strings.
- Guidance: playbook notes, patch references, and CVE/KEV action when available.
- Extracted indicators: safe, defanged values that can be copied into tickets.

The hash is important. Delete and quarantine re-check the file hash immediately
before acting. If the file changed after detection, remediation refuses the
action instead of touching the wrong content.

## 6. Indicator pivots

The indicator table is for fast investigation.

Use it to answer:

- What URLs or domains appeared in detected files?
- Which IPs or onion addresses were embedded?
- Which CVEs were referenced?
- Which hashes are repeated across multiple detections?
- Which file paths or registry keys were present?

Values in the dashboard are defanged so they are safer to paste into a ticket.
Use Export CSV when you need the raw values for a controlled workflow.

For CVE indicators, the tool adds NVD pivot links when the local database has
context. Use those links to confirm vendor guidance before patching production
systems.

## 7. Shield fabric

The Shield Fabric panel is the defensive control map. It does not run exploits
and it does not pretend to be a commercial EDR console. It tells the operator
which controls are local, which controls are connector-ready, and which response
playbooks should be used first.

Layers:

- AV: local YARA scanning, hash identity, quarantine, guarded delete, and purge.
- IDS: live finding stream, alert sound, auth telemetry, and IOC pivots.
- IPS: manual containment actions after dry-run preview and confirmation.
- Patch: NVD, CISA KEV, vendor patch references, and remediation guidance.
- Connector-ready: Bitdefender GravityZone can be bridged later through its
  official HTTPS JSON-RPC API when `BITDEFENDER_API_KEY` and
  `BITDEFENDER_API_URL` are present in `.env`.

The panel includes a **500-item defensive attack pressure library**. Each item
combines a motive, entry point, severity, and safe defense such as patching,
quarantine, credential reset, or evidence preservation. It is training material
for coverage planning, not a hacking manual.

File split groups help bulk remediation decisions:

- Scripts: `.ps1`, `.py`, `.js`, `.vbs`, `.sh`, `.bat`, `.cmd`
- Executables: `.exe`, `.dll`, `.scr`, `.msi`, `.elf`, `.dylib`
- Documents: `.doc`, `.docm`, `.xls`, `.xlsm`, `.pdf`, `.rtf`
- Archives: `.zip`, `.rar`, `.7z`, `.iso`, `.img`, `.tar`, `.gz`

## 8. Triage workflow

Use this order:

1. Acknowledge the finding when you have started looking at it.
2. Read the matched rule names and strings.
3. Check whether the target file is still present.
4. Review indicators and CVE guidance.
5. Decide whether the finding is malicious, benign, or uncertain.
6. Use Resolve only after you have contained or documented the issue.
7. Use False positive only when the rule match is understood and safe.
8. Use Reopen if new evidence changes the decision.

Status changes are triage notes. They do not delete files by themselves.

## 9. Remediation workflow

Remediation actions are intentionally guarded.

Available actions:

- Quarantine moves the detected file into the quarantine area and records sidecar
  metadata so it can be restored later.
- Restore moves a quarantined file back to its original location when safe.
- Delete permanently removes the detected file.
- Purge permanently removes a quarantined copy.

Safety rails:

- The target path comes from the stored finding.
- The current SHA-256 must match the finding hash.
- The resolved path must be inside permitted roots.
- Suite-owned paths are refused.
- Directories are refused unless explicitly allowed by server-side logic.
- Missing confirmation is refused.
- Repeated actions on an already-handled target are refused.
- Every attempt is written to the audit trail.

Recommended action order:

1. Prefer Quarantine when you may need evidence later.
2. Use Delete only when the finding is confirmed and the file is disposable.
3. Use Restore only when the quarantined object is known safe or needed for
   controlled analysis.
4. Use Purge when the quarantined copy no longer needs to be preserved.

Why delete used to fail:

The tool must refuse delete if the target is already gone, if the finding is not
a YARA detection, if the hash changed, if the file is outside allowed roots, or
if the file is part of the suite itself. Those refusals are correct. A working
delete button should remove eligible detected files and explain every refusal.

## 10. Clear lines and log backups

Clear lines is a dashboard maintenance action. It clears the active finding
stream and triage lines so the room is clean for the next run.

What Clear lines does:

- Backs up active logs under `data/log-backups/`.
- Clears the live findings file.
- Clears live triage state.
- Refreshes the dashboard counters.

What Clear lines does not do:

- It does not delete watched files.
- It does not delete quarantined files.
- It does not delete the YARA rules.
- It does not revoke or rotate secrets.
- It does not clean Git history.

Use Clear lines after a test run, after a demo, or before a focused scan window.
Do not use it as incident response evidence handling. If evidence matters, copy
the backup folder into your case record first.

## 11. Database and NVD updates

The local database summary is generated into:

```text
docs/database-summary.md
```

To summarize the current local database:

```powershell
python tools\summarize_database.py
```

When the server is running, the dashboard can sync source cards and the API can
refresh NVD data. If the NVD sync reports `truncated: true`, the time window has
more records than the current request limit. Run smaller windows when you need a
complete import.

Operational pattern:

1. Sync NVD for the time window you care about.
2. Generate `docs/database-summary.md`.
3. Commit the code and summary together.
4. Let GitHub Actions run the Python YAML workflow.

## 12. Release and GitHub workflow

Before a release:

```powershell
python -m compileall securitysuite tools tests
node --check web\app.js
python tests\smoke.py
python tools\summarize_database.py --output docs\database-summary.md
git status --short
```

Use GitHub Actions to check Windows Python versions. The repository includes a
workflow at:

```text
.github/workflows/python.yml
```

Security rule: never paste GitHub tokens, API keys, passwords, or private keys
into chat, commits, README files, or issue text. If a token was pasted anywhere
public or semi-public, revoke it and create a new one with minimum permissions.

Release checklist:

- README screenshot is current.
- `docs/database-summary.md` is current.
- Delete and quarantine have been tested with disposable files.
- Clear lines has been tested and created a backup.
- Compile, smoke, and JavaScript checks pass.
- No secrets appear in tracked files.

## 13. Troubleshooting

Delete button does nothing:

- Confirm the finding is a YARA detection.
- Confirm the target file still exists.
- Confirm the target hash has not changed.
- Confirm the file is inside a watched or permitted remediation root.
- Open the drawer and read the returned refusal reason.

Quarantine does nothing:

- Confirm the quarantine directory exists.
- Confirm the file has not already been quarantined, deleted, or purged.
- Confirm the target is not part of the suite itself.
- Check the remediation audit trail.

Clear lines does not clear the table:

- Confirm the server is running.
- Confirm the browser is connected to `127.0.0.1:8787`.
- Refresh the page after the clear action.
- Check for a new folder under `data/log-backups/`.

Rules do not reload:

- Run `python -m compileall securitysuite tools`.
- Check for YARA syntax errors in recently edited rule files.
- Restart the server if the browser status does not recover.

NVD sync fails:

- Confirm the machine has network access.
- Install or update `certifi`.
- Retry with a smaller date range.
- Keep the existing local cache if you are offline.

Dashboard looks stale:

- Click Reload rules only for rule changes.
- Click Sync source cards for enrichment status.
- Use Clear lines only when you want to wipe active lines.
- Restart the server after backend code changes.

Startup launcher shows a black console window:

- Recreate the shortcut with `python install_shortcut.py`.
- Add sign-in startup with `python install_shortcut.py --startup`.
- On Windows, confirm the shortcut target is `pythonw.exe` when available.
- On Linux, confirm the desktop entry says `Terminal=false`.

## 14. Operator checklist

Start of session:

- Start with `python run.py`.
- Confirm monitor status is live.
- Confirm rule count is expected.
- Confirm watched path is the folder you intend to test.
- Keep test files disposable.

During triage:

- Open the finding drawer.
- Read rule names and matched strings.
- Check target state.
- Check hash and indicators.
- Preserve suspicious files before delete when evidence matters.

Before remediation:

- Prefer quarantine first.
- Use delete only for confirmed disposable targets.
- Read every refusal message.
- Do not disable safety rails to make a button green.

After session:

- Export indicators if needed.
- Generate the database summary.
- Use Clear lines to reset the dashboard.
- Confirm the backup folder exists.
- Run compile and JavaScript checks before committing.

The goal is simple: move fast, keep evidence, and make every destructive action
explain itself.

## 15. Tabbed workspace and release upgrade

The sidebar separates Overview, Antivirus, IDS, IPS / Response, Inventory,
Playbooks, Analysis lab, Training, Integrations and Audit. Choose a work area without
losing the live findings stream. The display-density setting supports larger
screens; it does not change detection logic.

### Scan a Drive

In Antivirus, select a local drive or enter a file/folder path and start a job.
The scanner streams entries instead of collecting a large file list. It has no
5,000-file limit. Progress reports scanned files, matches, skipped entries,
errors, and the current path. Cancellation takes effect after the current
engine or operating-system call finishes.

Large files above `max_file_mb` are reported as skipped. Permission failures,
links/junctions, special files, Linux pseudo-filesystems, suite caches, quarantine,
and generated state are excluded or reported. A completed walk does not mean
every byte on the drive was inspected. Review skips and errors before deciding
whether another scan is necessary. Scanning a drive never broadens remediation
roots. The command-line `--scan` path uses the same traversal.

### Inventory a Household Subnet

In Inventory, enter the private IPv4 CIDR you manage, for example
`192.168.1.0/24`. Choose discovery alone or enable the optional service checks.
The scan accepts RFC1918 ranges, /24 through /32, with bounded concurrency and
timeouts. It does not guess passwords, exploit devices, or change their settings.

Each record shows an IP, an observed MAC where available, service-port labels
and an observation timestamp. Unknown names remain unknown. A neighbor cache
can be stale, and devices can refuse ping and service connections. The CSV is
an inventory snapshot, not a list of certified safe devices. Each computer
needs its own local endpoint scanner for file inspection. Router/TV/IoT firmware
requires vendor-specific update checks.

### Import Network Alerts

IDS accepts Suricata EVE NDJSON exported from your sensor. Paste up to 100
records / 48 KB and import. Only alert records are stored; repeated records are
deduplicated within the running session. Invalid batches are rejected before
any record is written. Imported file paths and hashes are deliberately not
trusted as local remediation targets.

### Build a Playbook Without Coding

Select or drag a stored YARA finding into Playbooks. Select or drag skills into
the sequence: annotate, guidance, and quarantine. Reorder or remove steps,
name the plan, save it, and simulate it. Simulation does not annotate a finding,
move a file, or perform external CVE lookups. Review any refusal before running.

Plans use `web/playbook.schema.json`, version 1, with at most 12 steps. Export
JSON to share a plan, or import schema-compatible JSON produced by a coding
agent. Unknown fields and actions are refused. Generated JavaScript, PowerShell,
Python and shell commands are not executed by this tool. Live quarantine needs
confirmation and uses the same stored-finding, current-hash, protected-path and
permitted-root checks as manual containment. A live sequence stops on failure;
successful earlier steps are not rolled back.

### Analyze Text and Practice

Analysis lab runs YARA and indicator extraction on pasted text without executing
or persisting it. A match needs review; no match does not establish safety. This
is static analysis, not a malware-execution VM. Use an isolated external lab for
behavioral malware research rather than executing samples on your workstation.

Training offers 500 synthetic defensive tabletop questions for two players
sharing a browser. Scores reflect chosen responses. These questions are not
500 exploit reproductions or 500 validated antivirus tests. They do not touch
the finding log or remediation state.

### Automatic Response and DNS Lists

The response toggle persists an automatic-quarantine policy. Automatic actions
require `confidence = "high"` in an eligible matched rule, the configured severity
threshold, a recorded hash, and a permitted file path. Component/version markers
and test rules cannot authorize automatic response. The shipped heuristic rules
are not automatically promoted to high-confidence: tune against benign evidence
before adding that metadata. Automatic deletion is refused; use recoverable
quarantine. All action attempts and refusals are audited.

The IPS / Response tab saves a reviewed domain list and exports DNS hosts entries.
It does not enforce ad or spyware blocking. Import and activate the list in a
DNS filter you administer. Do not assume nationality identifies malicious code.
OPNsense's Unbound documentation covers DNS filtering:
https://docs.opnsense.org/manual/unbound.html.

For OPNsense IDS status, put `OPNSENSE_URL`, `OPNSENSE_API_KEY`, and
`OPNSENSE_API_SECRET` in the local `.env`. Use a private IPv4 HTTPS origin and
a trusted certificate. The connection check is read-only, refuses redirects,
and does not return credentials. A running IDS service does not attest to IPS
drop rules or full household coverage. See https://docs.opnsense.org/manual/ips.html.
GravityZone remains an offline setup indicator; keep installed endpoint
protection enabled.

### Repository Security and Release Checks

The repo includes `SECURITY.md`, weekly Dependabot configuration, Python and
JavaScript CodeQL analysis, and a Windows/Linux/macOS CI matrix. Before release:

```powershell
python -m compileall securitysuite tools tests
node --check web/app.js
node --check web/console.js
python -m unittest discover -s tests -p 'test_*.py' -v
python tests/smoke.py
```

Administrators must separately verify dependency graph, security alerts, secret
scanning, push protection, and private vulnerability reporting in GitHub.
Account-level feature availability varies; adding workflows does not activate
every setting. Keep secrets and local evidence out of commits. Review the
repo security quickstart provided with this release and `SECURITY.md`.

The Windows shortcut uses `pythonw.exe` and an absolute script path so no
PowerShell console appears. Recreate it with `python install_shortcut.py`; add
per-user sign-in startup with `python install_shortcut.py --startup`. Startup
does not arm automatic remediation. When the default port is busy, the launcher
tries nine alternatives; an explicit `--port` never falls back. A second launch
reuses only the same-version console for the same workspace.

See [console overview](../docs/images/console-1440.png),
[drive scan controls](../docs/images/console-antivirus.png) and
[playbook builder](../docs/images/console-playbooks.png) for the actual layout.

This release has no NSA affiliation or certification and does not guarantee
complete malware detection. Screenshots in `docs/images` show the actual console.
