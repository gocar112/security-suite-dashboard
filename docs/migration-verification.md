# C# Migration Verification

Reverified for release **2.0.1** on **2026-10-07** on a working tree based on
canonical `main` commit `ed4ca2e` (`One monitor per workspace, enforced by a
lock file`). The legacy Python
implementation remains available through Git history; it is not required by the
current runtime.

## Migration boundary

Version 2.0 moves executable application code, tests, release tooling, and the
command-line entry point to C# on .NET 10. Static dashboard files, YARA rules,
sample data, images, and operator documents remain in their native formats.
The supported target is **Windows x64** (`net10.0-windows`, `win-x64`).

| Project | Responsibility |
| --- | --- |
| `SecuritySuite.Core` | Configuration, storage, YARA detection, monitoring, jobs, telemetry, intelligence adapters, inventory, HTTP/API, playbooks, and guarded remediation |
| `SecuritySuite.Cli` | Dashboard host, monitor, one-shot scan, headless operation, and Windows shortcut commands |
| `SecuritySuite.Tools` | Rule generation, database summary, and controlled mirror synchronization |
| `SecuritySuite.Tests` | xUnit coverage for detection, storage, network scope, intelligence normalization, playbooks, and remediation safety rails |

The rewrite preserves the snake_case configuration and JSON/NDJSON/API
contracts. It also preserves the deployment boundary: the dashboard is
loopback-only and has no remote-authentication layer; private-network discovery
requires an explicit RFC1918 IPv4 scope; automated response is quarantine-only.

## Verification results

The following release checks were run from the repository root:

```powershell
dotnet --version
dotnet restore SecuritySuite.slnx
dotnet build SecuritySuite.slnx --no-restore --configuration Release
dotnet test SecuritySuite.slnx --no-build --configuration Release
node --check web\app.js
node --check web\console.js
npm ci
npx playwright install chromium
$env:SUITE_URL="http://127.0.0.1:18787" # with the suite running there
npm run test:ui
src\SecuritySuite.Cli\bin\x64\Release\net10.0-windows\win-x64\securitysuite.exe --scan samples
```

Results:

- SDK selection: stable .NET 10 selected through `global.json`.
- Restore and Release build: passed with zero warnings and zero errors.
- Version consistency: CLI, compiled assembly, API, package metadata, and dashboard report `2.0.1`.
- Test suite: 333 total, 329 passed, 4 skipped, 0 failed.
- JavaScript syntax: `app.js`, `console.js`, and `views.js` passed.
- Rule-load/sample smoke: 1,004 YARA rules loaded; 7 sample files scanned, 6 expected matches, 0 skipped, and 0 scan errors.
- Localhost boundary smoke: loopback API access returned 200; a hostile `Host` header, a hostile `Origin`, and a simple `text/plain` write each returned 403; a non-loopback bind was refused with exit code 1.
- Secret/runtime hygiene: `.env`, runtime data, uploaded files, NVD cache payloads, and quarantine contents remain excluded from Git.
- Dependency review: npm and NuGet reported no known vulnerable packages from their configured advisory sources.
- Browser QA: passed with pinned Playwright 1.63.0 and its matching Chromium build. All 14 tabs were checked at 390, 768, 1440, and 1920 pixels; analysis, playbook validation, training, TV density, version display, and the no-automatic-scan invariant passed.

The repository-wide `dotnet format --verify-no-changes` check also exposed
pre-existing whitespace-only drift in legacy C# files. The isolated release
files added or directly edited for versioning passed the scoped formatter check;
the broader formatting backlog remains intentionally unmodified to avoid a
large unrelated rewrite in this patch release.

The four skipped tests exercise symbolic-link escape handling. Windows refused
test symlink creation because Developer Mode or elevation was unavailable; the
tests reported `skipped` rather than passing without executing their assertions.
Run them on a controlled Windows x64 runner with symbolic-link creation enabled
before treating that environment-specific path as exercised.

## Release conclusion

The repository is a complete C# application rather than a mixed Python/C#
transition tree. Release 2.0.1 now includes repeatable, lockfile-backed browser
QA in addition to the C# test suite. A clean test run does not certify malware
detection accuracy or prove protection of live network devices.
