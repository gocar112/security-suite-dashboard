#!/usr/bin/env python3
"""Refresh the read-only mirror from this repository.

    python tools/sync_mirror.py --dry-run     # show what would change
    python tools/sync_mirror.py               # push the refresh

This repository is canonical. `soc-yara-scanner` is a mirror kept for the
project's history: it is where the 2021 single-file `YARA_scanning.py` started,
and it still carries the original `install.sh`, `docker-compose.yml` and manual
installer alongside the current suite.

Two copies of a codebase drift the moment someone edits the wrong one, so this
script makes refreshing the mirror a single command rather than a manual copy,
and stamps the mirror's README with a banner saying where the real work happens.
Nothing here edits the canonical repo.

Only committed, tracked files are mirrored - the export runs `git archive HEAD`,
so an uncommitted change, a `.env`, a cache directory or a quarantined file
cannot reach the mirror even by accident.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIRROR = "https://github.com/gocar112/soc-yara-scanner.git"
MIRROR_NAME = "gocar112/soc-yara-scanner"
CANONICAL = "https://github.com/gocar112/security-suite-dashboard"

# Files that belong to the mirror's own history and must survive a refresh.
KEEP = (
    "YARA_scanning.py",
    "install.sh",
    "docker-compose.yml",
    "manual installer",
    "rules_test_rule.yar",
)

BANNER = """> ### This is a mirror
>
> The canonical repository is **[security-suite-dashboard]({canonical})**.
> Open issues and send changes there; anything committed here is overwritten by
> the next sync.
>
> This repo is kept because the project started here as a single file. The
> original `YARA_scanning.py`, `install.sh`, `docker-compose.yml` and manual
> installer are still present alongside the current suite. Run `run.py`, not
> `YARA_scanning.py`.
>
> _Last synced from {sha} on {date}._

"""


def run(args: list, cwd: Path | None = None, check: bool = True) -> str:
    result = subprocess.run(args, cwd=str(cwd) if cwd else None,
                            capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SystemExit("[-] %s failed:\n%s" % (" ".join(args[:3]),
                                                 (result.stderr or "").strip()[:400]))
    return (result.stdout or "").strip()


def add_banner(readme: Path, sha: str, date: str) -> None:
    """Put the mirror notice above the first heading, replacing any previous one."""
    text = readme.read_text(encoding="utf-8") if readme.exists() else "# Security Suite\n"
    lines = [l for l in text.splitlines(keepends=True)]

    # Drop a banner from an earlier sync so they do not stack up.
    if any("This is a mirror" in l for l in lines[:40]):
        start = next(i for i, l in enumerate(lines) if "This is a mirror" in l)
        start = max(0, start - 1)
        end = start
        while end < len(lines) and (lines[end].startswith(">") or not lines[end].strip()):
            end += 1
        del lines[start:end]

    banner = BANNER.format(canonical=CANONICAL, sha=sha, date=date)
    for i, line in enumerate(lines):
        if line.startswith("# "):
            lines.insert(i + 1, "\n" + banner)
            break
    else:
        lines.insert(0, banner)
    readme.write_text("".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would change without pushing")
    parser.add_argument("--message", default="", help="override the commit message")
    args = parser.parse_args()

    dirty = run(["git", "status", "--porcelain"], ROOT)
    if dirty:
        print("[!] This repository has uncommitted changes. Only committed work is")
        print("    mirrored, so the mirror would not match your working tree:")
        for line in dirty.splitlines()[:8]:
            print("      " + line)
        print()

    sha = run(["git", "rev-parse", "--short", "HEAD"], ROOT)
    date = run(["git", "log", "-1", "--format=%cs"], ROOT)
    subject = run(["git", "log", "-1", "--format=%s"], ROOT)
    print("[*] Canonical : %s at %s (%s)" % (ROOT.name, sha, date))
    print("[*] Mirror    : %s" % MIRROR_NAME)

    work = Path(tempfile.mkdtemp(prefix="mirror-"))
    clone = work / "mirror"
    try:
        print("[*] Cloning the mirror...")
        run(["git", "clone", "--quiet", MIRROR, str(clone)])

        preserved = {}
        for name in KEEP:
            source = clone / name
            if source.is_file():
                preserved[name] = source.read_bytes()

        for child in clone.iterdir():
            if child.name == ".git":
                continue
            shutil.rmtree(child) if child.is_dir() else child.unlink()

        print("[*] Exporting tracked files from HEAD...")
        archive = work / "export.tar"
        with archive.open("wb") as handle:
            proc = subprocess.run(["git", "archive", "HEAD"], cwd=str(ROOT),
                                  stdout=handle, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise SystemExit("[-] git archive failed: " +
                             (proc.stderr or b"").decode("utf-8", "replace")[:200])
        shutil.unpack_archive(str(archive), str(clone), format="tar")

        for name, blob in preserved.items():
            (clone / name).write_bytes(blob)
        print("[*] Preserved : " + ", ".join(sorted(preserved)) if preserved
              else "[*] Preserved : nothing (mirror had none of the originals)")

        add_banner(clone / "README.md", sha, date)

        run(["git", "add", "-A"], clone)
        status = run(["git", "status", "--porcelain"], clone)
        if not status:
            print("[*] Mirror is already up to date. Nothing to do.")
            return 0

        changed = len(status.splitlines())
        print("[*] Changes   : %d file(s)" % changed)
        for line in status.splitlines()[:10]:
            print("      " + line)
        if changed > 10:
            print("      ... and %d more" % (changed - 10))

        if args.dry_run:
            print("\n[*] --dry-run: nothing pushed.")
            return 0

        message = args.message or (
            "Sync from security-suite-dashboard %s\n\n%s\n\n"
            "Mirrored with tools/sync_mirror.py. The canonical repository is\n"
            "%s - changes made here are overwritten by the next sync."
            % (sha, subject, CANONICAL))
        run(["git", "commit", "--quiet", "-m", message], clone)
        print("[*] Pushing...")
        run(["git", "push", "--quiet", "origin", "HEAD"], clone)
        print("[*] Mirror updated to %s" % sha)
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
