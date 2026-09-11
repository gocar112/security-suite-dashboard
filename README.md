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
rules/
  demo.yar              test keyword, EICAR, high-entropy PE
  webshell.yar          PHP / ASPX / JSP backdoors
  windows_threats.yar   encoded PowerShell, download cradles, credential
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
