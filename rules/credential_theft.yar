/*
 * credential_theft.yar - tools and tradecraft aimed at harvesting
 * passwords, tokens, and secrets from a live host.
 */

rule LSASS_Memory_Dump_Indicators : malware
{
    meta:
        description = "Command or API pattern used to dump LSASS process memory"
        severity = "critical"
        mitre = "T1003.001"
        author = "security-suite"
    strings:
        $a1 = "lsass.exe" nocase
        $a2 = "MiniDumpWriteDump" nocase
        $a3 = "procdump" nocase
        $a4 = "comsvcs.dll" nocase
        $a5 = "MiniDump" nocase
    condition:
        $a1 and any of ($a2, $a3, $a4, $a5)
}

rule Browser_Credential_Store_Access : suspicious
{
    meta:
        description = "Code reading a browser's saved-password or cookie database"
        severity = "high"
        mitre = "T1555.003"
    strings:
        $p1 = "Login Data" nocase
        $p2 = "Cookies" nocase
        $p3 = "Web Data" nocase
        $b1 = "\\Google\\Chrome\\User Data" nocase
        $b2 = "\\Mozilla\\Firefox\\Profiles" nocase
        $b3 = "\\Microsoft\\Edge\\User Data" nocase
    condition:
        any of ($p*) and any of ($b*)
}

rule Keylogger_API_Hooking : malware
{
    meta:
        description = "Keyboard hooking or polling APIs combined with local logging"
        severity = "high"
        mitre = "T1056.001"
    strings:
        $h1 = "SetWindowsHookEx" nocase
        $h2 = "GetAsyncKeyState" nocase
        $h3 = "GetForegroundWindow" nocase
        $l1 = "keylog" nocase
        $l2 = ".klg" nocase
        $l3 = "keystrokes" nocase
    condition:
        any of ($h*) and any of ($l*)
}

rule SAM_Registry_Hive_Dump : malware
{
    meta:
        description = "Command sequence used to export the SAM/SYSTEM/SECURITY registry hives"
        severity = "critical"
        mitre = "T1003.002"
    strings:
        $r1 = "reg save hklm\\sam" nocase
        $r2 = "reg save hklm\\system" nocase
        $r3 = "reg save hklm\\security" nocase
        $r4 = "reg.exe save" nocase
    condition:
        any of them
}

rule Credential_Harvest_Clipboard_Config : suspicious
{
    meta:
        description = "Clipboard scraping or config-file scanning aimed at stored secrets"
        severity = "high"
        mitre = "T1115,T1552.001"
    strings:
        $c1 = "GetClipboardData" nocase
        $c2 = "clipboard" nocase
        $f1 = "password" nocase
        $f2 = "api_key" nocase
        $f3 = "secret_key" nocase
        $f4 = ".env" nocase
        $f5 = "credentials.json" nocase
    condition:
        any of ($c*) and any of ($f*)
}
