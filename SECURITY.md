# Security Policy

Security fixes target the current `main` branch. Older snapshots may contain
unfixed issues and should be updated before use.

## Report a Vulnerability

Use GitHub's private vulnerability reporting on this repository's Security tab
when available: https://github.com/gocar112/security-suite-dashboard/security.
If private reporting is unavailable, open an issue requesting a private contact
method without posting exploit details, API credentials, or malicious files.

Include the affected commit, platform, expected behavior, and a harmless
reproduction. Keep findings, host inventories, usernames and API keys private.
There is no guaranteed response time or third-party security certification.

## Deployment Boundary

The dashboard binds to loopback and has no remote authentication. Do not expose
it through port forwarding, a reverse proxy or a public tunnel. The scanner
supplements installed endpoint protection. Rule matches are evidence to review,
not proof that a file is malware or that a device is protected.

Playbooks use a fixed action schema. The analysis lab never executes submitted
code and is not an operating-system malware sandbox. Network discovery is an
explicit scan of a private IPv4 subnet; it does not inspect remote files or
install agents. Reviewed domain lists are exports, not active DNS enforcement.

Automatic response supports recoverable quarantine inside permitted roots and
requires eligible high-confidence rule metadata. Manual deletion is irreversible.
Quarantine contents, secrets and local logs are excluded from git.
