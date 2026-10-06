/*
 * recon_persistence.yar - post-compromise discovery commands and the
 * mechanisms attackers use to survive a reboot.
 */

rule Discovery_Command_Chain : suspicious
{
    meta:
        description = "Multiple host/network discovery commands chained together"
        severity = "medium"
        mitre = "T1082,T1016"
        author = "security-suite"
    strings:
        $a1 = "whoami /all" nocase
        $a2 = "net user /domain" nocase
        $a3 = "systeminfo" nocase
        $a4 = "net group \"domain admins\"" nocase
        $a5 = "nltest /domain_trusts" nocase
        $a6 = "ipconfig /all" nocase
    condition:
        2 of them
}

rule Scheduled_Task_Registry_Run_Persistence : suspicious
{
    meta:
        description = "Scheduled task or registry Run-key creation used to persist a payload"
        severity = "high"
        mitre = "T1053.005,T1547.001"
    strings:
        $a1 = "schtasks /create" nocase
        $a2 = "reg add" nocase
        $a3 = "\\CurrentVersion\\Run" nocase
        $a4 = "New-ScheduledTask" nocase
    condition:
        any of them
}

rule WMI_Event_Subscription_Persistence : malware
{
    meta:
        description = "WMI permanent event subscription used as a fileless persistence mechanism"
        severity = "critical"
        mitre = "T1546.003"
    strings:
        $a1 = "__EventFilter" nocase
        $a2 = "CommandLineEventConsumer" nocase
        $a3 = "__FilterToConsumerBinding" nocase
        $a4 = "Register-WmiEvent" nocase
    condition:
        any of them
}

rule Service_Creation_For_Persistence : suspicious
{
    meta:
        description = "New Windows service created to run an attacker binary at startup"
        severity = "high"
        mitre = "T1543.003"
    strings:
        $a1 = "sc create" nocase
        $a2 = "sc.exe create" nocase
        $a3 = "New-Service" nocase
        $b1 = "binPath=" nocase
        $b2 = "-BinaryPathName" nocase
    condition:
        any of ($a*) and any of ($b*)
}

rule LOLBin_Chaining : suspicious
{
    meta:
        description = "Living-off-the-land binaries chained together to proxy execution or downloads"
        severity = "high"
        mitre = "T1218"
    strings:
        $a1 = "certutil -urlcache" nocase
        $a2 = "certutil -decode" nocase
        $a3 = "regsvr32 /s /u /i:" nocase
        $a4 = "mshta http" nocase
        $a5 = "rundll32.exe javascript:" nocase
        $a6 = "bitsadmin /transfer" nocase
    condition:
        any of them
}
