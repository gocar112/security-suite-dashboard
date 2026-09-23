# Security Suite Operator Guide

Version: 2026-09-12

This book explains how to run the Security Suite, read the dashboard, triage
findings, pivot indicators, update the local vulnerability database, and use
remediation without turning a false positive into data loss.

The suite is a local defensive SOC console. It watches files, scans them with
YARA, extracts indicators, enriches CVE signals, and gives the operator guarded
actions such as quarantine, restore, delete, purge, and clear lines.

## Table of contents

1. What this tool is
2. Quick start
3. Dashboard map
4. Running scans
5. Reading a finding
6. Indicator pivots
7. Triage workflow
8. Remediation workflow
9. Clear lines and log backups
10. Database and NVD updates
11. Behavior, firewall, and server logs
12. Home security system strategy
13. Release and GitHub workflow
14. Troubleshooting
15. Operator checklist

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
- Remediate only verified detection targets.
- Back up active dashboard lines before clearing the live view.

Important rule: remediation must act on a stored finding, not on a random path
typed by a browser client. That is what keeps the delete and quarantine buttons
from becoming arbitrary file tools.

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
- Detection activity shows recent activity.
- Live feed shows compact event lines.
- Containment handles bulk remediation previews and actions.

Right sidebar:

- On-demand scan accepts a local path.
- Namespaces and severity panels summarize the current dataset.
- Auth telemetry summarizes failed-logon correlation.
- Behavior logs show local server requests, firewall log status, and destructive
  action counters.
- Ruleset and sensor panels show loaded rules and watched paths.

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

## 7. Triage workflow

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

## 8. Remediation workflow

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

## 9. Clear lines and log backups

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

## 10. Database and NVD updates

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

## 11. Behavior, firewall, and server logs

The dashboard includes a Behavior logs panel for the parts of a home SOC that
are easy to miss when you only look at detections.

It shows:

- Total recent events from the local finding store.
- Detections, clean scans, errors, remediation actions, destructive actions,
  and refused actions.
- Firewall allow/block lines when a supported firewall log exists.
- Recent local dashboard/API requests.

The firewall lane checks common local log paths:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
/var/log/ufw.log
/var/log/kern.log
```

If no firewall log is present, the dashboard reports that honestly. It does not
invent firewall data. Enable Windows Firewall logging or UFW logging, restart
the suite, and the panel will begin showing parsed allow/block lines.

Windows firewall logging, run as Administrator:

```powershell
netsh advfirewall set currentprofile logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
netsh advfirewall set currentprofile logging allowedconnections enable
```

Read the server request tail for:

- Unexpected non-local clients.
- API errors from stale browser tabs.
- Repeated remediation or clear requests.

Security rule: keep the server bound to `127.0.0.1` unless authentication and a
real deployment plan are added.

## 12. Home security system strategy

Use the suite as one layer in a home security system:

1. Router: secure admin password, WPA2/WPA3, no WPS, guest Wi-Fi for IoT.
2. Accounts: password manager, unique passwords, MFA on critical accounts.
3. Devices: automatic updates, disk encryption, built-in endpoint protection.
4. Backups: cloud backup plus one offline backup that is unplugged after use.
5. Monitoring: Security Suite watches suspicious downloads and shows logs.
6. Response: quarantine first, delete only after confirmation, restore from a
   clean backup when needed.

Use the full home book for family-facing strategy:

```text
book/Home-SOC-Defense-Guide.md
```

Use the short checklist for setup:

```text
docs/Home-User-Security-System-Quickstart.md
```

## 13. Release and GitHub workflow

Before a release:

```powershell
python -m compileall securitysuite tools
node --check web\app.js
python tools\summarize_database.py
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
- Compile and JavaScript checks pass.
- No secrets appear in tracked files.

## 14. Troubleshooting

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

Behavior logs show no firewall data:

- Confirm firewall logging is enabled.
- Confirm the log path exists.
- Restart Security Suite.
- Remember that blocked inbound noise is normal; repeated outbound traffic from
  an unknown device matters more.

## 15. Operator checklist

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
