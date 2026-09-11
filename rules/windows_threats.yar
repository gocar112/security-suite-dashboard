/*
 * windows_threats.yar - host-side tradecraft commonly seen on Windows.
 * Detection content only: these rules match on indicators, they do not
 * reproduce anything executable.
 */

rule PowerShell_Encoded_Command : suspicious
{
    meta:
        description = "PowerShell launched with a base64 encoded command block"
        severity = "high"
        author = "security-suite"
    strings:
        $ps = "powershell" nocase
        $e1 = "-encodedcommand" nocase
        $e2 = " -enc " nocase
        $e3 = "-e JAB" nocase
        $e4 = "FromBase64String" nocase
    condition:
        $ps and any of ($e*)
}

rule PowerShell_Download_Cradle : suspicious
{
    meta:
        description = "Fileless download-and-run pattern"
        severity = "high"
    strings:
        $d1 = "DownloadString" nocase
        $d2 = "DownloadFile" nocase
        $d3 = "Invoke-WebRequest" nocase
        $d4 = "Net.WebClient" nocase
        $r1 = "Invoke-Expression" nocase
        $r2 = "IEX(" nocase
        $r3 = "| iex" nocase
    condition:
        any of ($d*) and any of ($r*)
}

rule Credential_Dumper_Indicators : malware
{
    meta:
        description = "Strings associated with LSASS credential dumping tools"
        severity = "critical"
    strings:
        $a1 = "sekurlsa::logonpasswords" nocase
        $a2 = "privilege::debug" nocase
        $a3 = "lsadump::sam" nocase
        $a4 = "mimikatz" nocase
        $a5 = "gentilkiwi" nocase
    condition:
        any of them
}

rule Defense_Evasion_Commands : suspicious
{
    meta:
        description = "Shadow copy deletion or security tooling being disabled"
        severity = "critical"
    strings:
        $v1 = "vssadmin delete shadows" nocase
        $v2 = "wbadmin delete catalog" nocase
        $v3 = "bcdedit /set {default} recoveryenabled no" nocase
        $d1 = "Set-MpPreference -DisableRealtimeMonitoring" nocase
        $d2 = "netsh advfirewall set allprofiles state off" nocase
    condition:
        any of them
}

rule Ransom_Note_Template : malware
{
    meta:
        description = "Text that reads like a ransom note left beside encrypted files"
        severity = "critical"
    strings:
        $a1 = "your files have been encrypted" nocase
        $a2 = "all your files are encrypted" nocase
        $b1 = "bitcoin" nocase
        $b2 = "monero" nocase
        $b3 = ".onion" nocase
        $c1 = "decryption key" nocase
        $c2 = "decrypt your files" nocase
    condition:
        any of ($a*) and (any of ($b*) or any of ($c*))
}

rule Suspicious_Double_Extension : suspicious
{
    meta:
        description = "Archive or document name masquerading with a double extension"
        severity = "medium"
    strings:
        $a1 = ".pdf.exe" nocase
        $a2 = ".doc.exe" nocase
        $a3 = ".jpg.exe" nocase
        $a4 = ".txt.vbs" nocase
        $a5 = ".pdf.scr" nocase
    condition:
        any of them
}
