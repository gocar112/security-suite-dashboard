#!/usr/bin/env python3
"""Create a desktop launcher for the Security Suite on any OS.

    python install_shortcut.py            # create it
    python install_shortcut.py --startup  # also start when you sign in
    python install_shortcut.py --remove   # take it away again

Windows gets a .lnk, Linux a .desktop entry (registered in the applications
menu as well as on the desktop), and macOS a double-clickable .command file.
Nothing is installed system-wide and nothing needs elevation. Launchers are
created in quiet mode by default so Windows does not flash a PowerShell console
when the suite starts.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAME = "Security Suite"
ICON_ICO = ROOT / "assets" / "securitysuite.ico"
ICON_PNG = ROOT / "assets" / "securitysuite.png"
ICON_SVG = ROOT / "assets" / "securitysuite.svg"


def desktop_dir() -> Path:
    """Best effort at the user's desktop, including localised Linux names."""
    if os.name == "nt":
        try:
            import winreg
            key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                return Path(winreg.QueryValueEx(handle, "Desktop")[0])
        except Exception:
            return Path.home() / "Desktop"

    config = Path.home() / ".config" / "user-dirs.dirs"
    if config.exists():
        try:
            for line in config.read_text(encoding="utf-8").splitlines():
                if line.startswith("XDG_DESKTOP_DIR"):
                    value = line.split("=", 1)[1].strip().strip('"')
                    return Path(os.path.expandvars(value.replace("$HOME", str(Path.home()))))
        except OSError:
            pass
    return Path.home() / "Desktop"


def startup_dir() -> Path:
    """Per-user startup/autostart folder for the current OS."""
    if os.name == "nt":
        appdata = os.getenv("APPDATA", "")
        if appdata:
            return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        return Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    if sys.platform == "darwin":
        return Path.home() / "Applications"
    return Path.home() / ".config" / "autostart"


def quiet_python() -> Path:
    """Use pythonw on Windows when it exists, otherwise the current Python."""
    current = Path(sys.executable)
    if os.name == "nt":
        candidate = current.with_name("pythonw.exe")
        if candidate.exists():
            return candidate
    return current


def best_icon() -> Path | None:
    for candidate in (ICON_PNG, ICON_SVG, ICON_ICO):
        if candidate.exists():
            return candidate
    return None


# ------------------------------------------------------------------ windows
def install_windows(remove: bool, startup: bool) -> Path:
    target = (startup_dir() if startup else desktop_dir()) / (NAME + ".lnk")
    if remove:
        target.unlink(missing_ok=True)
        return target
    icon = ICON_ICO if ICON_ICO.exists() else None   # .lnk needs a real .ico
    target.parent.mkdir(parents=True, exist_ok=True)
    script = (
        "$ws = New-Object -ComObject WScript.Shell; "
        "$l = $ws.CreateShortcut(%s); "
        "$l.TargetPath = %s; "
        "$l.Arguments = 'run.py'; "
        "$l.WorkingDirectory = %s; "
        "$l.Description = 'Security Suite - YARA SOC detector with live dashboard'; "
        % (ps_quote(str(target)), ps_quote(str(quiet_python())), ps_quote(str(ROOT)))
    )
    if icon:
        script += "$l.IconLocation = %s; " % ps_quote(str(icon) + ",0")
    script += "$l.Save()"
    subprocess.run(["powershell", "-NoProfile", "-Command", script], check=True,
                   capture_output=True)
    return target


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# -------------------------------------------------------------------- linux
def install_linux(remove: bool, startup: bool) -> Path:
    entry = NAME.lower().replace(" ", "-") + ".desktop"
    apps_dir = Path.home() / ".local" / "share" / "applications"
    targets = [startup_dir() / entry] if startup else [apps_dir / entry, desktop_dir() / entry]
    if remove:
        for target in targets:
            target.unlink(missing_ok=True)
        return targets[0]

    icon = best_icon()
    content = "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        "Name=" + NAME,
        "Comment=YARA SOC detector with a live dashboard",
        "Exec=" + shell_quote(sys.executable) + " run.py",
        "Path=" + str(ROOT),
        "Icon=" + (str(icon) if icon else "security-high"),
        "Terminal=false",
        "Categories=Security;System;Monitor;",
        "StartupNotify=false",
        "",
    ])
    for target in targets:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            target.chmod(0o755)          # GNOME refuses to launch a non-executable entry
        except OSError as exc:
            print("  could not write " + str(target) + ": " + str(exc))
    return targets[0]


def shell_quote(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"' if " " in value else value


# -------------------------------------------------------------------- macOS
def install_macos(remove: bool, startup: bool) -> Path:
    target = (startup_dir() if startup else desktop_dir()) / (NAME + ".app")
    if remove:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink(missing_ok=True)
        return target
    script_dir = target / "Contents" / "MacOS"
    script_dir.mkdir(parents=True, exist_ok=True)
    (target / "Contents" / "Info.plist").write_text("\n".join([
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"",
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
        "<plist version=\"1.0\"><dict>",
        "<key>CFBundleName</key><string>Security Suite</string>",
        "<key>CFBundleExecutable</key><string>security-suite</string>",
        "<key>CFBundleIdentifier</key><string>local.securitysuite.dashboard</string>",
        "<key>LSBackgroundOnly</key><string>1</string>",
        "</dict></plist>",
        "",
    ]), encoding="utf-8")
    script = "\n".join([
        "#!/bin/bash",
        "cd " + shell_quote(str(ROOT)),
        "exec " + shell_quote(sys.executable) + " run.py",
        "",
    ])
    executable = script_dir / "security-suite"
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a desktop launcher.")
    parser.add_argument("--remove", action="store_true", help="remove the launcher")
    parser.add_argument("--startup", action="store_true",
                        help="install/remove the per-user startup launcher")
    args = parser.parse_args()

    if os.name == "nt":
        platform, install = "Windows", install_windows
    elif sys.platform == "darwin":
        platform, install = "macOS", install_macos
    else:
        platform, install = "Linux", install_linux

    try:
        target = install(args.remove, args.startup)
    except subprocess.CalledProcessError as exc:
        print("[-] Launcher creation failed: " + (exc.stderr or b"").decode("utf-8", "replace")[:200])
        return 1
    except OSError as exc:
        print("[-] Launcher creation failed: " + str(exc))
        return 1

    verb = "Removed" if args.remove else "Created"
    print("[*] " + platform + (" startup" if args.startup else " desktop") + " launcher")
    print("[*] " + verb + ": " + str(target))
    if not args.remove:
        # Windows shortcuts need a genuine .ico; the others take PNG or SVG.
        if platform == "Windows":
            icon = ICON_ICO if ICON_ICO.exists() else None
        else:
            icon = best_icon()
        print("[*] Icon    : " + (str(icon) if icon else "system default"))
        runner = quiet_python() if platform == "Windows" else Path(sys.executable)
        print("[*] Runs    : " + str(runner) + " run.py")
        print("[*] From    : " + str(ROOT))
        if platform == "macOS":
            print("[*] Created a quiet .app bundle.")
        if platform == "Linux":
            print("[*] The launcher uses Terminal=false to avoid opening a shell window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
