/*
 * ransomware.yar - named ransomware families and generic encryption-extortion
 * tradecraft. Complements the generic Ransom_Note_Template rule in
 * windows_threats.yar with family-specific and behavioral indicators.
 */

rule LockBit_Indicators : malware
{
    meta:
        description = "Strings and note filenames associated with LockBit ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "security-suite"
    strings:
        $a1 = "LockBit" nocase
        $a2 = ".lockbit" nocase
        $n1 = "Restore-My-Files.txt" nocase
        $n2 = "LockBit_Ransomware.hta" nocase
    condition:
        any of ($a*) and any of ($n*)
}

rule Conti_Indicators : malware
{
    meta:
        description = "Strings and note filenames associated with Conti ransomware"
        severity = "critical"
        mitre = "T1486"
    strings:
        $a1 = "CONTI_LOG" nocase
        $a2 = "conti_readme" nocase
        $n1 = "R3ADM3.txt" nocase
        $n2 = "readme.txt" nocase
        $b1 = "fixed_ext" nocase
    condition:
        any of ($a*) or ($b1 and any of ($n*))
}

rule Sodinokibi_REvil_Indicators : malware
{
    meta:
        description = "Strings associated with Sodinokibi / REvil ransomware"
        severity = "critical"
        mitre = "T1486"
    strings:
        $a1 = "Sodinokibi" nocase
        $a2 = "REvil" nocase
        $n1 = "-readme.txt" nocase
        $c1 = "sub_key" nocase
        $c2 = "pk_str" nocase
    condition:
        any of ($a*) or (any of ($n*) and any of ($c*))
}

rule Ransom_Note_Filename_Reference : suspicious
{
    meta:
        description = "Code that writes a file using a well known ransom note filename"
        severity = "high"
        mitre = "T1486"
    strings:
        $w1 = "CreateFile" nocase
        $w2 = "WriteFile" nocase
        $w3 = "fopen" nocase
        $w4 = "File.WriteAllText" nocase
        $n1 = "HOW_TO_DECRYPT" nocase
        $n2 = "DECRYPT_INSTRUCTIONS" nocase
        $n3 = "RECOVERY_FILES" nocase
        $n4 = "_readme.txt" nocase
    condition:
        any of ($w*) and any of ($n*)
}

rule Cryptocurrency_Wallet_Near_Extortion_Text : malware
{
    meta:
        description = "A cryptocurrency wallet reference alongside file-encryption extortion language"
        severity = "critical"
        mitre = "T1486"
    strings:
        $w1 = "bitcoin wallet" nocase
        $w2 = "monero wallet" nocase
        $w3 = "btc address" nocase
        $w4 = "send payment to" nocase
        $e1 = "your files have been encrypted" nocase
        $e2 = "all your files are encrypted" nocase
        $e3 = "pay the ransom" nocase
        $e4 = "decrypt your files" nocase
    condition:
        any of ($w*) and any of ($e*)
}
