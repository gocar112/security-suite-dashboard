/*
 * info_stealer_rat.yar - commodity infostealers and remote access trojans:
 * bulk credential/wallet harvesting and remote-hands-on-keyboard access.
 */

rule Commodity_Stealer_Strings : malware
{
    meta:
        description = "Strings associated with common commodity infostealer families"
        severity = "critical"
        mitre = "T1555,T1005"
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
        mitre = "T1547.001"
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
        mitre = "T1113,T1125,T1041"
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
        mitre = "T1555.003,T1005"
    strings:
        // Wallet artifacts. Each is specific enough to mean something on its
        // own - a bare product name like "Exodus" is not, so it is qualified
        // by the on-disk path the stealer actually reaches for.
        $w1 = "wallet.dat" nocase
        $w2 = "Local Storage\\leveldb" nocase
        $w3 = "MetaMask" nocase
        $w4 = "Exodus\\exodus.wallet" nocase
        $w5 = "\\Ethereum\\keystore" nocase

        // Browser credential/autofill artifacts, named as they appear on disk
        // rather than as UI vocabulary.
        $f1 = "autofill_profiles" nocase     // table inside Chrome's Web Data
        $f2 = "\\Web Data" nocase
        $f3 = "\\Login Data" nocase
        $f4 = "credit_cards" nocase

        // Context: the file must also do something with those artifacts.
        // Naming an artifact is documentation; opening or copying it is theft.
        $c1 = "sqlite3_open" nocase
        $c2 = "CopyFile" nocase
        $c3 = "CreateFileW" nocase
        $c4 = "shutil.copy" nocase
        $c5 = "ReadFile" nocase
        $c6 = "SELECT * FROM" nocase
        $c7 = "multipart/form-data" nocase
    condition:
        // The OR between wallet and browser artifacts is deliberate - a
        // wallet-only stealer should still match - but either family now has
        // to appear alongside an access or exfiltration primitive.
        (any of ($w*) or any of ($f*)) and any of ($c*)
}

rule RAT_C2_Handshake_Strings : malware
{
    meta:
        description = "Fixed handshake or beacon strings used by common RAT families to register a new victim"
        severity = "critical"
        mitre = "T1071.001"
    strings:
        $a1 = "njRAT" nocase
        $a2 = "DarkComet" nocase
        $a3 = "AsyncRAT" nocase
        $a4 = "QuasarRAT" nocase
        $a5 = "|'|'|" nocase
    condition:
        any of them
}
