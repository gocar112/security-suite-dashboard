# Security Suite

A YARA-backed SOC detector with a live web dashboard. It watches directories,
scans new files in memory, correlates hits against authentication telemetry from
the same time window, and streams every finding to a browser console in real time.

Built from `YARA_scanning.py`, restructured into a service with a UI.

```bash
python run.py
```

Then open <http://127.0.0.1:8787> (it opens automatically).

---

## Requirements

| Package | Status | Needed for |
| --- | --- | --- |
| `yara-python` | **required** | the detection engine |
| `pywin32` | optional (Windows) | reading failed logons from the Security event log |

Both are already installed on this machine. There is no web framework
dependency: the server is `http.server` from the standard library, and the
dashboard is plain HTML/CSS/JS. Nothing to `pip install`, nothing to build.

```bash
pip install -r requirements.txt   # only if you move this to another machine
```

---

## What it does

```
uploads/  ──▶  settle check  ──▶  YARA engine  ──▶  hit?  ──▶  auth telemetry
(watched)      (file stopped        (in-memory,              (last 5 min,
                changing)            13 rules)                real timestamps)
                                                                    │
                                        data/findings.ndjson  ◀─────┤
                                        SSE ──▶ dashboard     ◀─────┘
```

**Dashboard** (`http://127.0.0.1:8787`)

- Six live KPIs: files scanned, detections, open alerts, critical/high, auth failures, uptime
- Findings table with severity / status / type filters and full-text search
- Click any row for a detail drawer: SHA-256, size, entropy, every matched rule with
  the actual matched strings and their file offsets, plus the correlated logon failures
- Triage in place — acknowledge, resolve, mark false positive, reopen (persisted to `data/triage.json`)
- 60-minute detection activity chart, severity breakdown, top rules, live event feed
- On-demand scan of any file or directory tree
- Pause/resume the monitor and hot-reload rules without restarting
- Convergence source lattice linking Vuls, NVD, CISA KEV, OSV, GitHub Advisories,
  ClawFire, and an optional server-side VirusTotal adapter
- Posture dial, source health cards, focus mode, operator sensitivity control,
  and an opt-in Web Audio alert tone for new detections

---

## Layout

```
run.py                  launcher (python run.py)
config.json             optional; created only if you write one
securitysuite/
  config.py             defaults + config.json loading
  engine.py             YARA compile/reload, scan, SHA-256, entropy, severity
  telemetry.py          Windows Security log + Linux auth.log, time-windowed
  watcher.py            polling monitor with settle detection
  store.py              NDJSON store, in-memory index, SSE pub/sub, triage
  server.py             HTTP API + SSE + static files
  net.py                shared TLS context (certifi) + JSON helpers
  nvd.py                NVD CVE API 2.0 client + local cache
  osv.py                OSV.dev lookup by commit / package / purl
  virustotal.py         hash reputation + Enterprise capability probe
assets/securitysuite.ico  desktop shortcut icon
book/                   the field guide (pdf + docx)
nvds/                   NVD cache (contents gitignored)
rules/                  73 rules; each file is one YARA namespace
  c2_network.yar          beacons, reverse shells, DNS tunnelling
  credential_theft.yar    LSASS dumping, browser stores, keylogging
  cryptominer.yar         miner config, stratum pools, browser mining
  demo.yar                test keyword, EICAR, high-entropy PE
  info_stealer_rat.yar    commodity stealers and remote-access trojans
  linux_threats.yar       reverse shells, cron/systemd persistence,
                          LD_PRELOAD rootkits, container escape
  office_macro_malware.yar  auto-exec macros, droppers, obfuscated VBA
  phishing_social_engineering.yar  credential harvesting and lures
  ransomware.yar          family indicators and extortion artifacts
  recon_persistence.yar   discovery chains, scheduled tasks, WMI, LOLBins
  rmm_tunnel_abuse.yar    silent RMM installs, unattended passwords,
                          ngrok/cloudflared tunnels, RDP exposure
  supply_chain.yar        npm/pip install hooks, CI secret theft,
                          build-pipeline tampering
  web_fraud_skimmer.yar   card skimming and formjacking
  webshell.yar            PHP / ASPX / JSP backdoors
  windows_threats.yar     encoded PowerShell, download cradles, credential
                          dumpers, shadow-copy deletion, ransom notes
samples/                harmless text files that trip specific rules
uploads/                the watched folder (starts empty)
data/findings.ndjson    append-only alert log
data/triage.json        triage state
web/                    dashboard
```

---

## Try it

Start the suite, then copy a sample into the watched folder:

```bash
copy samples\README_RESTORE.txt uploads\
```

The row appears in the dashboard within about two seconds — no refresh — as a
**critical** `Ransom_Note_Template` hit. Each sample fires a different rule:

| Sample | Rule | Severity |
| --- | --- | --- |
| `README_RESTORE.txt` | Ransom_Note_Template | critical |
| `cleanup_commands.txt` | Defense_Evasion_Commands | critical |
| `dump_notes.txt` | Credential_Dumper_Indicators | critical |
| `task_setup.log` | PowerShell_Encoded_Command | high |
| `update_helper.txt` | PowerShell_Download_Cradle | high |
| `mail_body.txt` | Suspicious_Double_Extension | medium |
| `report_q3.txt` | *(nothing — clean scan)* | — |

> Windows Defender will quarantine a genuine `.php` webshell or a real PE sample
> before the scanner can read it. That is expected and handled: the file is
> recorded as "unavailable at scan time", not as an error. The samples above are
> plain text so they survive.

---

## CLI

```bash
python run.py                          # monitor + dashboard
python run.py --watch D:\ftp --watch E:\inbox
python run.py --port 9000 --no-browser
python run.py --scan C:\Users\me\Downloads   # one-shot scan, JSON to stdout, exit
python run.py --headless               # monitor only, no web server
python run.py --scan-existing          # also scan files already present at startup
```

---

## Writing rules

Drop any `.yar` / `.yara` file into `rules/` and hit **Reload rules** in the
dashboard. Severity is read from rule metadata, so rule authors set triage priority:

```yara
rule My_Detection : malware
{
    meta:
        description = "Shown in the dashboard drawer"
        severity    = "critical"     // critical | high | medium | low | info
    strings:
        $a = "indicator" nocase
    condition:
        $a
}
```

Without `meta.severity` the tag is used (`malware` → high, `suspicious` → medium,
`test` → info); with neither, the finding defaults to medium. Each file becomes its
own YARA namespace, so rule names only need to be unique within a file. A rule file
that fails to compile is reported by name in the Ruleset panel — the rest still load.

---

## Vulnerability intelligence

Three of the seven lattice sources are live adapters that make real requests;
the rest are labelled links. A card only shows `online` once a request has
actually succeeded.

| Source | Credential | What it answers |
| --- | --- | --- |
| **NVD** | optional | Browse CVEs by id, keyword, or modification window. ~390,000 records. |
| **OSV** | none | "Is *this* artifact vulnerable?" — query by commit, package, or purl. |
| **VirusTotal** | required | Hash reputation. Hunting is Enterprise-only — see below. |

```bash
# Sync the trailing 3 days of CVEs into ./nvds
curl -s -X POST http://127.0.0.1:8787/api/nvd/sync \
     -H "Content-Type: application/json" -d '{"days": 3}'

# Is a source commit affected by anything known?
curl -s -X POST http://127.0.0.1:8787/api/osv/query \
     -H "Content-Type: application/json" \
     -d '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}'

# One CVE
curl -s "http://127.0.0.1:8787/api/nvd/cve?id=CVE-2021-44228"
```

NVD works with no key at 5 requests per 30 s; a free key raises that to 50.
OSV needs no credential at all. VirusTotal does no work without one.

### VirusTotal tiers, and what Hunting needs

VT Hunting — **Livehunt**, **Retrohunt** and **VTDIFF** — runs YARA across
VirusTotal's own stream and 600 TB historical corpus. All three are **Enterprise
features**. On the public API tier every Hunting and Intelligence endpoint
returns `403 ForbiddenError`, so the adapter probes the key on startup and
reports what it found rather than shipping panels that cannot work:

```bash
curl -s http://127.0.0.1:8787/api/vt/capabilities
```

```json
{ "tier": "public",
  "allowed": { "file_lookup": true, "livehunt": false,
               "retrohunt": false, "intelligence_search": false },
  "detail": "Public API tier: hash lookups only. Livehunt, Retrohunt, VTDIFF
             and Intelligence search require a VT Enterprise account." }
```

`/api/vt/livehunt` and `/api/vt/retrohunt` return **402** with that explanation
on a public key, and start working by themselves if the key is later upgraded —
the gate is a live capability probe, not a hardcoded assumption.

What the public tier *does* give you is the useful half for this tool: turning a
local YARA hit into a second opinion from ~75 engines.

```bash
curl -s "http://127.0.0.1:8787/api/vt/file?hash=<sha256 from a finding>"
```

Public tier allows 4 requests/minute and 500/day, so lookups are rate limited to
match and cached by hash. Enrichment is deliberately **on demand** rather than
automatic on every scan — a busy watched directory would exhaust the daily quota
in minutes.

> **This client never uploads files.** Submitting a file to VirusTotal publishes
> it, and other users can download it. Auto-submitting whatever lands in a
> watched folder would leak customer data and credentials in config files.
> Hashes only; uploading stays a human decision in the VT web interface.

### Credentials

Copy `.env.example` to `.env` and fill in what you have. `.env` is gitignored,
credentials are stripped from `config.json` on save, and no endpoint ever
returns a key — `/api/intel` reports only whether one is *configured* and
whether it *works*.

```
VIRUSTOTAL_API_KEY=      # required for the VirusTotal card
NVD_API_KEY=             # optional; only raises the rate limit
```

### A note on TLS

Python on Windows often has no CA file of its own (`ssl.get_default_verify_paths()`
returns `cafile: None`) and fails to verify `services.nvd.nist.gov` with a
misleading `certificate has expired`. The server certificate is fine — the local
trust store is not. `securitysuite/net.py` carries `certifi`'s bundle instead.
Verification is never disabled.

---

## Desktop shortcut (Windows)

`assets/securitysuite.ico` is a six-resolution icon for a desktop shortcut.
Point the shortcut at your Python, with this folder as the working directory:

```powershell
$ws = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\Security Suite.lnk")
$lnk.TargetPath       = (Get-Command python).Source
$lnk.Arguments        = 'run.py'
$lnk.WorkingDirectory = $PWD.Path
$lnk.IconLocation     = "$($PWD.Path)\assets\securitysuite.ico,0"
$lnk.Save()
```

---

## The book

`book/Detection-Engineering-in-Practice.{pdf,docx}` is a field guide to SOC
detection engineering that uses this repository as its running case study —
YARA rule design, the race conditions in the file watcher, telemetry
correlation, triage economics, and the intel adapters above. Second edition,
~18,000 words.

---

## Configuration

Defaults live in `securitysuite/config.py`. To override, create `config.json` in
this folder with only the keys you want to change:

```json
{
  "watch_paths": ["C:\\inetpub\\uploads", "D:\\ftp\\incoming"],
  "lookback_minutes": 10,
  "poll_interval": 1.0,
  "max_file_mb": 128,
  "port": 8787
}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `watch_paths` | `["uploads"]` | directories to monitor |
| `recursive` | `true` | include subdirectories |
| `poll_interval` | `2.0` | seconds between sweeps |
| `settle_seconds` | `1.0` | a file must stop changing this long before it is scanned |
| `max_file_mb` | `64` | files above this are skipped, not scanned |
| `lookback_minutes` | `5` | telemetry correlation window |
| `auth_log_path` | `/var/log/auth.log` | Linux/macOS only |
| `host` / `port` | `127.0.0.1` / `8787` | dashboard bind address |

---

## API

All endpoints are localhost-only and reject requests whose `Host` header is not a
loopback name (DNS-rebinding guard).

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/state` | stats, monitor status, engine info, telemetry, config |
| GET | `/api/findings?severity=&status=&type=&q=&limit=` | filtered findings |
| GET | `/api/rules` | loaded rules and any compile errors |
| GET | `/api/telemetry?force=1` | recent auth failures |
| GET | `/api/intel` | source lattice health (no credential is ever returned) |
| GET | `/api/nvd` | NVD cache status: records cached, window, rate limit, TLS bundle |
| GET | `/api/nvd/cves?limit=&severity=` | cached CVEs, highest CVSS first |
| GET | `/api/nvd/cve?id=CVE-...` | one CVE, cached on disk after first fetch |
| GET | `/api/nvd/search?q=&limit=` | live keyword search against the NVD API |
| POST | `/api/nvd/sync` | `{"days": 3}` — sync the trailing window into the cache |
| GET&nbsp;/&nbsp;POST | `/api/osv/query` | lookup by `commit`, `purl`, or `package`+`ecosystem`+`version` |
| GET | `/api/osv` | OSV adapter status |
| GET | `/api/vt` | VirusTotal adapter status and detected tier |
| GET | `/api/vt/capabilities` | what the key may actually reach (probed, cached) |
| GET | `/api/vt/file?hash=` | hash reputation: engine verdicts, family label, permalink |
| GET | `/api/vt/livehunt` `…/retrohunt` | Enterprise-gated; returns 402 with the reason on public tier |
| GET | `/api/stream` | Server-Sent Events: `hello`, `event`, `stats` |
| POST | `/api/scan` | `{"path": "..."}` — scan a file or tree |
| POST | `/api/monitor` | `{"action": "pause"\|"resume"}` |
| POST | `/api/rules/reload` | recompile the ruleset |
| POST | `/api/triage` | `{"id": "...", "status": "...", "note": "..."}` |

`findings.ndjson` stays newline-delimited JSON, one alert per line, so it pipes
straight into a SIEM:

```bash
type data\findings.ndjson | jq -c "select(.severity==\"critical\")"
```

Clean scans are **not** written to disk — they are in-memory only, so the file
remains an alert log rather than an audit trail of every file ever seen.

### External intelligence

The dashboard keeps the scanner local and treats external sources as adapters.
The source lattice links to the Vuls project, NVD, CISA's Known Exploited
Vulnerabilities catalog, OSV, GitHub Advisories, and ClawFire fleet guardrails.
VirusTotal is optional and is checked server-side from `/api/intel` when a key is
available. Put the key in the process environment or a local, ignored `.env`:

```text
VIRUSTOTAL_API_KEY=your-key-here
```

The key is never sent to the browser or included in `/api/state` responses.

---

## What changed from `YARA_scanning.py`

| Original | Now |
| --- | --- |
| `get_recent_auth_events()` stamped every line with `datetime.now()` and returned the last 5 regardless of age — nothing was actually time-filtered | Each source parses its own timestamps; only events inside the window are returned. Syslog's missing year is inferred with rollover handling |
| Linux-only (`/var/log/auth.log`) | Windows Security event log (4625/4648/4740/4771/4776) with a graceful "run as Administrator" message, plus the Linux path |
| New files scanned the instant they appeared, so a large upload was scanned half-written | A file must stop changing for `settle_seconds` before it is scanned — verified by test: a file written in two pieces is scanned once, after the second write |
| `os.listdir` on one directory, non-recursive | Recursive walk with size/mtime change detection, so modified files are rescanned |
| Deleted files stayed in `seen_files` forever | Disappearing files are forgotten, so a re-upload is scanned again |
| Rule compile failure silently fell back to a dummy rule | Each rule file is validated individually; failures are surfaced by name in the UI, working rules still load |
| `matches` recorded as `[str(m)]` — just rule names | Rule, namespace, tags, metadata, severity, and each matched string with its file offset |
| No file identity | SHA-256, size, mtime, and Shannon entropy (flags packed/encrypted content) |
| Alert on a file bigger than RAM would try anyway | `max_file_mb` cap, files above it recorded as skipped |
| Scanned its own `findings.ndjson` if it sat in the watched folder — every alert re-alerting forever | The monitor excludes its own output files |
| `KeyboardInterrupt` caught inside the loop, `while True` with no way to pause | Clean shutdown, plus pause/resume and rule hot-reload from the UI |
| Output: one print line and a log file | Live dashboard with triage workflow, filters, charts, and a JSON API |

The original file is unchanged; nothing here overwrites it.

---

## Notes

- **Run as Administrator** to enable logon correlation on Windows. Without it the
  dashboard shows `denied` with an explanation and detection still works fully —
  only the telemetry panel is empty.
- The server binds `127.0.0.1` and has no authentication. It is a local console;
  do not bind it to `0.0.0.0` on an untrusted network.
- `POST /api/scan` will read any path the running user can read. That is the point
  of an on-demand scanner, but it is also why the listener stays on loopback.
- Detection is read-only. Nothing is quarantined, moved, or deleted.
