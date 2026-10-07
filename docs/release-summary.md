# Security Suite 2.0.1

Release date: 2026-10-07

Security Suite 2.0.1 is the verified C# patch release of the local SOC console.
The runtime, CLI, tools, HTTP API, detection engine, storage, monitoring,
casework, hunt, graph, ATT&CK coverage, intelligence adapters, inventory,
playbooks, and remediation controls are implemented on .NET 10 for Windows x64.
Static HTML, CSS, JavaScript, YARA rules, documentation, and image assets remain
in their native formats.

## Release identity

The release number is stamped into the compiled Core assembly and reused by the
CLI, API, running-instance check, and dashboard. The dashboard displays
`v2.0.1`; `securitysuite --version` prints `securitysuite 2.0.1`.

## Included work

- Complete Python-to-C# runtime migration with a Core/CLI/Tools solution layout.
- 14 dashboard workspaces: overview, antivirus, IDS, response, inventory,
  playbooks, analysis, training, integrations, audit, hunt, ATT&CK, graph, and
  cases.
- 1,004 YARA rules with recursive monitoring, scan jobs, IOC extraction,
  NVD/OSV/CISA/VirusTotal context, Suricata import, and read-only OPNsense status.
- Guarded quarantine, restore, delete, purge, bulk preview, and quarantine-only
  high-confidence automatic response.
- Complete remediation-audit retention, fail-closed clear operations, stable
  triage outside the memory window, and visible SSE overflow recovery.
- One monitor per workspace, clean cancellation, loopback/Host/origin controls,
  and explicit RFC1918-only inventory scope.
- Stable .NET 10 SDK selection and pinned Playwright browser QA.

## Verification

- Release build: zero warnings and zero errors.
- xUnit: 333 total, 329 passed, 4 environment-dependent symlink skips, 0 failed.
- JavaScript syntax: all three dashboard scripts passed.
- Browser QA: all 14 tabs at four viewport widths passed; interactive analysis,
  playbook validation, training, TV density, and version display passed; no
  automatic scans were triggered.
- Scanner smoke: 1,004 rules loaded; 7 samples scanned; 6 expected matches;
  zero scan errors.
- HTTP boundary smoke: allowed loopback returned 200; hostile Host/origin and
  unsafe simple writes returned 403; non-loopback binding was refused.
- Dependency advisory checks: no known npm or NuGet vulnerabilities reported.
- Publish smoke: the `win-x64` release executable reported version 2.0.1 and
  completed the sample scan.
- Formatting: `dotnet format --verify-no-changes` reports no changes across the
  solution, and CI now gates on it.

The four skipped tests require Windows symbolic-link creation through Developer
Mode or elevation. They are reported as skipped rather than passing without
executing their assertions.

## Scope

The console is loopback-only and has no remote-authentication layer. Do not
publish it through port forwarding, a reverse proxy, or a public tunnel.
Security Suite supplements installed endpoint protection; passing tests and a
low alert count do not certify malware-detection accuracy or prove that live
network devices are protected.

See the [migration verification](migration-verification.md),
[operator guide](../book/Security-Suite-Operator-Guide.md), and
[security policy](../SECURITY.md) for the full evidence and operating boundary.
