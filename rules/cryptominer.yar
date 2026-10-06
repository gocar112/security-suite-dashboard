/*
 * cryptominer.yar - unauthorized cryptocurrency mining, both native
 * miner binaries/configs and browser-based mining scripts.
 */

rule XMRig_Stratum_Config_Strings : suspicious
{
    meta:
        description = "XMRig-style miner configuration or stratum pool connection strings"
        severity = "high"
        mitre = "T1496"
        author = "security-suite"
    strings:
        $a1 = "xmrig" nocase
        $a2 = "stratum+tcp://" nocase
        $a3 = "stratum+ssl://" nocase
        $a4 = "donate-level" nocase
        $a5 = "rx/0" nocase
    condition:
        any of them
}

rule Mining_Process_Commandline_Flags : suspicious
{
    meta:
        description = "Process command line built with typical cryptomining flags"
        severity = "high"
        mitre = "T1496"
    strings:
        $f1 = "--donate-level" nocase
        $f2 = "--cpu-priority" nocase
        $f3 = "-o pool." nocase
        $f4 = "--url=stratum" nocase
        $f5 = "-a randomx" nocase
    condition:
        any of them
}

rule Browser_Based_Mining_Script : suspicious
{
    meta:
        description = "Web page embedding a browser cryptomining script"
        severity = "medium"
        mitre = "T1496"
    strings:
        $a1 = "coinhive" nocase
        $a2 = "CoinHive.Anonymous" nocase
        $a3 = "cryptonight" nocase
        $a4 = "webminepool" nocase
        $a5 = "authedmine" nocase
    condition:
        any of them
}
