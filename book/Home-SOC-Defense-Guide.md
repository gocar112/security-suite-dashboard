# Home SOC Defense Guide

Version: 2026-09-17

This book is for home users who want a practical security system without
pretending a house is a corporate data center. The goal is simple: know what you
own, reduce the easy ways in, notice suspicious behavior sooner, keep backups
safe, and recover without panic.

Testing System is the local signal room in this plan. It watches folders, scans
files with YARA, extracts indicators, correlates authentication telemetry,
shows firewall and server log status, and gives guarded remediation actions.
It is not a replacement for your operating system security tools, router
firewall, password manager, backups, or common sense. It is the place where a
home defender can inspect suspicious files and keep a small audit trail.

## Table of contents

1. The home-defense model
2. The security system stack
3. Day-one hardening
4. Router and firewall logging
5. Accounts, passwords, and MFA
6. Backups and ransomware recovery
7. Device hardening
8. Email, browser, and download strategy
9. Using Testing System
10. Reading behavior logs
11. Triage and remediation
12. Incident playbooks
13. Weekly and monthly routines
14. Family operating rules
15. References

## 1. The home-defense model

Most home incidents begin in a small set of places:

- A reused password is stolen and tried against email, banking, social media, or
  cloud storage.
- A phishing message tricks someone into entering a password or installing a
  remote-access tool.
- A device misses updates and keeps a known vulnerability.
- A malicious attachment, script, browser download, or cracked installer lands
  in Downloads.
- A router or camera keeps a default password or outdated firmware.
- Ransomware encrypts files and tries to destroy connected backups.

The home-defense model is layered:

- Prevent: reduce the easy paths in.
- Detect: make suspicious behavior visible.
- Contain: isolate the affected file, account, or device.
- Recover: restore clean files and rebuild trust.
- Learn: update the rule, backup, or family habit that failed.

Do not chase movie-style perfection. Home security gets strong when the basics
are boring and repeatable.

## 2. The security system stack

Use this stack for a home or small office:

| Layer | Job | Home tool |
| --- | --- | --- |
| Router | Keep strangers out and segment guests/IoT | Router firewall, guest Wi-Fi, firmware updates |
| Identity | Stop stolen passwords from becoming stolen accounts | Password manager, MFA, recovery codes |
| Endpoint | Block common malware and bad scripts | Windows Security, macOS security, browser protections |
| Backup | Survive ransomware, theft, and hardware failure | Cloud backup plus offline drive |
| Monitoring | Keep suspicious files and logs visible | Testing System dashboard |
| Response | Make decisions without guessing | Playbooks, quarantine first, restore plan |

Testing System fits in the monitoring and response layers. It is useful when
you need to inspect suspicious files, watch a download/drop folder, keep a
small remediation ledger, or teach family members what a detection looks like.

## 3. Day-one hardening

Do these first.

1. Update every computer, phone, browser, and password manager.
2. Turn on automatic updates.
3. Change router admin password and Wi-Fi password.
4. Use WPA2 or WPA3 encryption on Wi-Fi.
5. Create a guest Wi-Fi network for visitors and smart devices.
6. Install or enable a password manager.
7. Turn on MFA for email, banking, cloud storage, social media, and the
   password manager.
8. Turn on full-disk encryption.
9. Turn on cloud backup.
10. Create one offline backup on a drive that is unplugged afterward.
11. Start Testing System and monitor Downloads or a dedicated `uploads` folder.
12. Enable firewall logging if you want firewall lines inside the dashboard.

The most important account is email. Whoever controls email can often reset
passwords for everything else. Protect email first.

## 4. Router and firewall logging

The router is the front door. Secure it like one.

Router checklist:

- Change the router admin username/password if the router allows it.
- Use a unique Wi-Fi name that does not reveal your family name, address, or
  router model.
- Use WPA2/WPA3, not WEP.
- Disable WPS.
- Turn off remote administration unless you have a clear need.
- Update router firmware.
- Put cameras, TVs, assistants, and smart plugs on guest/IoT Wi-Fi.
- Review the connected-device list monthly.
- Replace unsupported routers that no longer receive updates.

Windows Firewall log setup:

Run PowerShell or Command Prompt as Administrator:

```powershell
netsh advfirewall set currentprofile logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
netsh advfirewall set currentprofile logging allowedconnections enable
```

Restart Testing System after enabling logging. The dashboard checks:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

Linux UFW logging:

```bash
sudo ufw logging on
sudo tail -f /var/log/ufw.log
```

Firewall logs are context, not automatic proof. A blocked inbound connection
can be normal internet noise. A repeated outbound connection from a machine you
do not recognize deserves investigation.

## 5. Accounts, passwords, and MFA

Password strategy:

- Use a password manager.
- Use a unique password for every account.
- Make the master password long and memorable.
- Store recovery codes offline.
- Remove old accounts you no longer need.
- Do not share passwords in text messages or email.

MFA strategy:

- Use app-based MFA or security keys when available.
- Prefer push approval only when it shows location and device details.
- Do not approve prompts you did not initiate.
- Keep backup codes in a safe place.
- Add a second trusted recovery method before you lose a phone.

Priority order:

1. Email
2. Password manager
3. Banking and payment apps
4. Cloud storage and photo libraries
5. Social media
6. Phone carrier account
7. Router and smart-home accounts

The phone carrier account matters because attackers may try SIM-swap attacks to
receive text codes.

## 6. Backups and ransomware recovery

Use the 3-2-1 idea:

- 3 copies of important data.
- 2 different media or services.
- 1 copy offline or otherwise protected from modification.

Home version:

- Computer copy: the files you use every day.
- Cloud backup: OneDrive, iCloud, Google Drive, Backblaze, or similar.
- Offline drive: plugged in only during backup, then unplugged.

Backup strategy:

- Back up documents, photos, tax files, password manager recovery material, and
  project folders.
- Test restore, not just backup.
- Keep at least one backup disconnected from the computer.
- Use cloud version history when available.
- Do not leave the only external backup plugged in all month.

Ransomware response:

1. Disconnect the machine from Wi-Fi/Ethernet.
2. Do not delete evidence yet.
3. Photograph ransom notes or suspicious windows.
4. Shut down only if encryption is still actively spreading or you need to stop
   damage.
5. Use a clean device to change critical passwords.
6. Restore from backup only after the infected system is cleaned or rebuilt.
7. Do not plug in offline backup drives until you trust the machine.

## 7. Device hardening

Windows:

- Keep Windows Security enabled.
- Turn on SmartScreen.
- Keep Controlled Folder Access in mind for high-risk users.
- Use a standard account for daily work when practical.
- Run as Administrator only when needed.
- Turn on BitLocker where available.
- Keep PowerShell script execution conservative.

macOS:

- Keep Gatekeeper enabled.
- Allow apps only from trusted sources.
- Keep FileVault enabled.
- Review Login Items.
- Remove unused browser extensions.

Phones:

- Use a strong passcode.
- Keep OS updates current.
- Remove apps you do not use.
- Deny permissions that do not make sense.
- Turn on Find My Device/Find My iPhone.

Smart devices:

- Change default passwords.
- Update firmware.
- Disable cloud features you do not need.
- Put devices on guest/IoT Wi-Fi.
- Replace devices that are abandoned by the vendor.

## 8. Email, browser, and download strategy

Email rules:

- Treat urgency as a warning signal.
- Do not open attachments you did not expect.
- Verify payment, gift card, password reset, and account-lock messages by going
  directly to the real site.
- Never give a one-time code to someone who called or messaged you.
- Use spam reporting so the mail provider learns.

Browser rules:

- Keep browser updates automatic.
- Use a reputable ad/tracker blocker if it does not break needed sites.
- Remove extensions you do not actively use.
- Do not install "codec", "driver", "cleaner", "optimizer", or cracked software
  from random websites.

Download handling:

1. Save unknown files to a watched folder.
2. Let Testing System scan them.
3. Open the finding if there is a hit.
4. Quarantine first when unsure.
5. Delete only after you confirm it is malicious or disposable.

## 9. Using Testing System

Start:

```powershell
python run.py
```

Open:

```text
http://127.0.0.1:8787
```

Recommended home setup:

- Watch `Downloads` only if you understand that normal installers may trigger.
- A safer pattern is to create a dedicated folder named `SecurityDrop` and copy
  suspicious files there.
- Keep `auto_remediate` on for critical findings and set its action to `quarantine`.
- Use `quarantine` before `delete`.
- Use Clear lines after a test run to reset the room.

Example `config.json`:

```json
{
  "watch_paths": ["SecurityDrop"],
  "recursive": true,
  "host": "127.0.0.1",
  "port": 8787,
  "auto_remediate": true,
  "auto_remediate_severity": "critical",
  "auto_remediate_action": "quarantine"
}
```

Run an on-demand scan:

```powershell
python run.py --scan .\SecurityDrop
```

Use the dashboard for:

- Findings
- Rule matches
- Extracted indicators
- Auth telemetry
- Firewall/server log status
- Remediation audit
- NVD/OSV/VirusTotal context when configured

## 10. Reading behavior logs

The Behavior logs panel has three jobs:

- Behavior counters summarize detections, remediation actions, destructive
  actions, refused actions, and firewall blocks.
- Firewall shows allow/block lines when a supported firewall log exists.
- Server requests show recent local dashboard/API traffic.

What to investigate:

- Destructive actions greater than zero: confirm who clicked delete/purge and
  whether the file was disposable.
- Refused actions: read the refusal because it often protects you from a bad
  delete.
- Firewall blocks from unusual internal addresses: identify the device.
- Server requests from anything other than `127.0.0.1`: keep the dashboard bound
  to localhost unless you add authentication.
- Repeated API errors: check whether a browser tab or script is stale.

What not to overreact to:

- A few blocked inbound firewall lines from the internet.
- A dashboard request every refresh interval.
- A detection in a YARA rule file or security book that contains malware words
  for teaching.

## 11. Triage and remediation

Triage order:

1. Open the finding.
2. Read the rule name, namespace, severity, and matched strings.
3. Confirm the file path.
4. Check the SHA-256 and target state.
5. Review extracted indicators.
6. Look at auth/firewall/server context.
7. Decide: malicious, benign, or uncertain.
8. Quarantine if uncertain.
9. Delete only if confirmed malicious or disposable.
10. Resolve or mark false positive with a short note.

Use false positive when:

- The file is a rule, guide, test sample, or research note.
- The matched string appears because you intentionally wrote about malware.
- You understand the rule and the file's purpose.

Use quarantine when:

- The file may be evidence.
- You need more time.
- A family member needs the file reviewed.
- You are not sure if it is a false positive.

Use delete when:

- The file is confirmed malicious.
- The file is a duplicate or disposable.
- Backups are safe.
- You do not need evidence.

## 12. Incident playbooks

### Suspicious download

1. Do not open it.
2. Move it into the watched folder.
3. Let Testing System scan it.
4. If clean but still suspicious, upload only the hash or use another sandboxed
   workflow; do not upload private files to public services.
5. If detected, quarantine.
6. Search browser history for where it came from.
7. Delete the original message or download source.

### Password stolen

1. Use a clean device.
2. Change the password for the affected account.
3. Sign out of all sessions.
4. Turn on MFA.
5. Change any reused passwords elsewhere.
6. Check recovery email/phone settings.
7. Review account activity.

### Ransomware note appears

1. Disconnect the device from the network.
2. Preserve photos of the note and filenames.
3. Do not plug in backup drives.
4. Use another device to change critical passwords.
5. Rebuild or clean the infected machine.
6. Restore from offline/cloud backup.
7. Review how the first file arrived.

### Unknown device on Wi-Fi

1. Change Wi-Fi password.
2. Reboot router.
3. Review router client list.
4. Move smart devices to guest Wi-Fi.
5. Update router firmware.
6. Disable WPS.

### Dashboard shows destructive actions

1. Open Behavior logs.
2. Open Containment recent actions.
3. Confirm the path and timestamp.
4. Check whether the action was delete, purge, quarantine, restore, or refused.
5. If delete/purge was wrong, stop using the machine and restore from backup if
   needed.

## 13. Weekly and monthly routines

Weekly:

- Check OS/browser updates.
- Review password manager warnings.
- Confirm cloud backup completed.
- Scan the watched folder.
- Clear lines after test activity.

Monthly:

- Plug in offline backup drive, back up, then unplug.
- Test restore one file.
- Review router connected devices.
- Remove unused apps and browser extensions.
- Review Testing System logs and remediation ledger.
- Update this repository and rerun smoke tests.

Quarterly:

- Replace weak/reused passwords.
- Review MFA recovery methods.
- Review family rules.
- Export or archive important case logs.
- Update router firmware.

## 14. Family operating rules

Write these down where everyone can see them:

- No one gives a password or one-time code to a caller.
- Money movement gets a second channel verification.
- Unexpected attachments wait.
- Unknown downloads go to the watched folder.
- If a device acts strange, tell someone early.
- Do not shame the person who clicked; fast reporting matters more.
- Backups are part of the household, not a nerd hobby.

## 15. References

These public resources informed this guide:

- CISA, "#StopRansomware Guide": https://www.cisa.gov/stopransomware/ransomware-guide
- CISA, "How to Protect the Data that is Stored on Your Devices":
  https://www.cisa.gov/resources-tools/training/how-protect-data-stored-your-devices
- FTC, "Securing Your Internet-Connected Devices at Home":
  https://consumer.ftc.gov/articles/securing-your-internet-connected-devices-home
- FTC, "Protect Your Personal Information From Hackers and Scammers":
  https://consumer.ftc.gov/articles/protect-your-personal-information-hackers-and-scammers
- NIST, "Multi-Factor Authentication":
  https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/multi-factor-authentication
