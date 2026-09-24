# Testing System Read-Only Briefing

## Purpose

The read-only briefing at `/briefing` provides a safe status view for someone
who needs visibility but is not authorized to change sensor settings, launch a
scan, clear findings, or take remediation actions.

## What It Shows

- Whether the local monitor is watching, paused, or unavailable.
- Files scanned, rule matches, open alerts, and configured context sources.
- Recent YARA detections with their severity and triage state.
- The configured watch path, loaded rule count, and firewall-log availability.
- A containment audit showing destructive remediation activity and firewall
  blocks already recorded by the local dashboard.

## What It Does Not Do

The briefing has no write controls. It does not send files to a third party,
change configuration, clear findings, start scans, quarantine files, restore
files, or delete files. The page makes only local GET requests to the existing
dashboard API.

## Safe Sharing

Keep the server bound to `127.0.0.1`. The briefing is intended for a local
screen or a trusted screen-share. Do not expose the dashboard to the internet
without authentication and a proper access-control layer.

## Operator Handoff

1. Open `http://127.0.0.1:8787/briefing` for a concise status check.
2. Review any open alerts and the recent detection table.
3. Open the control room only when an authorized operator needs to investigate
   or respond.
4. Use quarantine before delete, and keep the remediation audit trail intact.
