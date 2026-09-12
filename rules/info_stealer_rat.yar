/*
 * info_stealer_rat.yar - commodity infostealers and remote access trojans:
 * bulk credential/wallet harvesting and remote-hands-on-keyboard access.
 */

rule Commodity_Stealer_Strings : malware
{
    meta:
        description = "Strings associated with common commodity infostealer families"
        severity = "critical"
        author = "security-suite"
    strings:
        $a1 = "RedLine" nocase
        $a2 = "Raccoon Stealer" nocase
        $a3 = "Vidar" nocase
        $a4 = "AZORult" nocase
        $a5 = "\\Telegram Desktop\\tdata" nocase
    condition:
        any of them
}

rule RAT_Persistence_Run_Key : suspicious
{
    meta:
        description = "Registry Run key persistence combined with remote-access naming"
        severity = "high"
    strings:
        $r1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $r2 = "RegSetValueEx" nocase
        $n1 = "remote" nocase
        $n2 = "rat.exe" nocase
        $n3 = "client.exe" nocase
    condition:
        any of ($r*) and any of ($n*)
}

rule Screen_Webcam_Capture_With_Exfil : malware
{
    meta:
        description = "Screenshot or webcam capture APIs combined with network exfiltration"
        severity = "critical"
    strings:
        $c1 = "BitBlt" nocase
        $c2 = "CopyFromScreen" nocase
        $c3 = "capCreateCaptureWindow" nocase
        $e1 = "multipart/form-data" nocase
        $e2 = "ftp://" nocase
        $e3 = "sendto" nocase
        $e4 = "HttpWebRequest" nocase
    condition:
        any of ($c*) and any of ($e*)
}

rule Browser_Autofill_Wallet_File_Targeting : malware
{
    meta:
        description = "Code enumerating browser autofill data or cryptocurrency wallet files"
        severity = "critical"
    strings:
        $w1 = "wallet.dat" nocase
        $w2 = "Local Storage\\leveldb" nocase
        $w3 = "MetaMask" nocase
        $w4 = "Exodus" nocase
        $f1 = "Autofill" nocase
        $f2 = "Web Data" nocase
    condition:
        any of ($w*) or any of ($f*)
}

rule RAT_C2_Handshake_Strings : malware
{
    meta:
        description = "Fixed handshake or beacon strings used by common RAT families to register a new victim"
        severity = "critical"
    strings:
        $a1 = "njRAT" nocase
        $a2 = "DarkComet" nocase
        $a3 = "AsyncRAT" nocase
        $a4 = "QuasarRAT" nocase
        $a5 = "|'|'|" nocase
    condition:
        any of them
}
