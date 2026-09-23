# Home User Security System Quickstart

Version: 2026-09-17

This is the short version of the home SOC plan. It is designed for a normal
household: laptops, phones, a router, cloud accounts, smart devices, and a few
important files you cannot afford to lose.

## What to build

Build five layers:

1. Router defense
2. Account defense
3. Device defense
4. Backup and recovery
5. Security Suite monitoring

## Day one

Do these today:

- Update Windows/macOS, phones, browsers, and password manager.
- Turn on automatic updates.
- Change router admin password.
- Use WPA2/WPA3 Wi-Fi encryption.
- Disable WPS.
- Turn on MFA for email, banking, cloud storage, and password manager.
- Turn on full-disk encryption.
- Turn on cloud backup.
- Make one offline backup and unplug the drive.
- Start Security Suite.

## Run Security Suite

From the repository root:

```powershell
python run.py
```

Open:

```text
http://127.0.0.1:8787
```

Use it this way:

- Put suspicious files in `uploads`.
- Watch the Findings table.
- Open detections before acting.
- Prefer Quarantine.
- Use Delete only for confirmed malicious or disposable files.
- Use Clear lines after a test session.

## Enable firewall logs

Windows, from Administrator PowerShell or Command Prompt:

```powershell
netsh advfirewall set currentprofile logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
netsh advfirewall set currentprofile logging allowedconnections enable
```

Linux with UFW:

```bash
sudo ufw logging on
```

Restart Security Suite. The Behavior logs panel will show firewall status and
recent server requests. If no firewall log exists, it will say so plainly.

## Weekly routine

- Confirm updates installed.
- Check backup status.
- Scan the watched folder.
- Review Security Suite findings.
- Clear lines after testing.
- Ask: "Did anything ask for a password or payment unexpectedly?"

## Monthly routine

- Plug in offline backup drive.
- Back up important files.
- Restore one test file.
- Unplug the drive.
- Review router connected devices.
- Remove unused apps and browser extensions.
- Review password manager security warnings.

## Family rules

- No password or one-time code goes to a caller.
- Money requests get verified by another channel.
- Unexpected attachments wait.
- Unknown downloads go to the watched folder.
- Report weird behavior early.
- Quarantine first, delete later.

## Emergency playbooks

### Suspicious file

1. Do not open it.
2. Move it to `uploads`.
3. Let Security Suite scan.
4. If detected, open the finding.
5. Quarantine if unsure.
6. Delete only when confirmed malicious or disposable.

### Stolen password

1. Use a clean device.
2. Change the password.
3. Sign out all sessions.
4. Turn on MFA.
5. Change reused passwords.
6. Check recovery email and phone settings.

### Ransomware

1. Disconnect from Wi-Fi/Ethernet.
2. Do not plug in backup drives.
3. Photograph ransom notes.
4. Change critical passwords from a clean device.
5. Rebuild or clean the machine.
6. Restore from offline or cloud backup.

## Minimum safe setup

If you only do five things:

1. Password manager with unique passwords.
2. MFA on email and financial accounts.
3. Automatic updates.
4. Cloud backup plus unplugged offline backup.
5. Security Suite watching suspicious downloads.
