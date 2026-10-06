/*
 * rmm_tunnel_abuse.yar - legitimate remote-access and tunnelling tools used
 * as an intrusion's remote access.
 *
 * These products are not malware, and their presence alone is not a finding -
 * plenty of organisations run them deliberately. What is suspicious is the
 * unattended-install shape: silent flags, a preset access password, or a
 * tunnel pointed outbound from a host that has no business exposing one.
 * Every rule therefore requires the automation context, never the tool name
 * on its own.
 */

rule RMM_Silent_Unattended_Install : suspicious
{
    meta:
        description = "Remote access tool installed silently with no operator present"
        severity = "high"
        mitre = "T1219"
        author = "security-suite"
    strings:
        $t1 = "AnyDesk" nocase
        $t2 = "ScreenConnect" nocase
        $t3 = "TeamViewer" nocase
        $t4 = "atera" nocase
        $t5 = "SplashtopStreamer" nocase
        $t6 = "RustDesk" nocase
        $t7 = "Supremo" nocase
        $s1 = "--silent" nocase
        $s2 = "/silent" nocase
        $s3 = "/quiet" nocase
        $s4 = "/S /install" nocase
        $s5 = "--install" nocase
        $s6 = "msiexec /i" nocase
        $s7 = "/verysilent" nocase
    condition:
        any of ($t*) and any of ($s*)
}

rule RMM_Unattended_Access_Password : malware
{
    meta:
        description = "Remote access tool given a preset password for unattended entry"
        severity = "critical"
        mitre = "T1219"
    strings:
        $a1 = "--set-password" nocase
        $a2 = "anydesk.exe --set-password" nocase
        $a3 = "unattended_password" nocase
        $a4 = "UnattendedAccess" nocase
        $a5 = "SetPassword" nocase
        $t1 = "AnyDesk" nocase
        $t2 = "TeamViewer" nocase
        $t3 = "RustDesk" nocase
        $t4 = "ScreenConnect" nocase
        $p1 = "echo " nocase
        $p2 = "| "
        $p3 = "cmd /c" nocase
        $p4 = "powershell" nocase
    condition:
        any of ($a*) and (any of ($t*) or any of ($p*))
}

rule Outbound_Tunnel_Tool_Configured : suspicious
{
    meta:
        description = "Tunnelling client configured to expose a local service outbound"
        severity = "high"
        mitre = "T1572"
    strings:
        $t1 = "ngrok" nocase
        $t2 = "cloudflared" nocase
        $t3 = "frpc" nocase
        $t4 = "localtunnel" nocase
        $t5 = "chisel" nocase
        $t6 = "gost " nocase
        $c1 = "authtoken" nocase
        $c2 = "tunnel --url" nocase
        $c3 = "tcp 3389" nocase
        $c4 = "tcp 22" nocase
        $c5 = "server_addr" nocase
        $c6 = "remote_port" nocase
        $c7 = "--reverse" nocase
    condition:
        any of ($t*) and any of ($c*)
}

rule RDP_Exposure_Tampering : suspicious
{
    meta:
        description = "Remote Desktop enabled and firewalled open from the command line"
        severity = "high"
        mitre = "T1021.001,T1562.004"
    strings:
        $r1 = "fDenyTSConnections" nocase
        $r2 = "Terminal Server\\WinStations" nocase
        $r3 = "UserAuthentication" nocase
        $e1 = "reg add" nocase
        $e2 = "Set-ItemProperty" nocase
        $f1 = "netsh advfirewall firewall" nocase
        $f2 = "Enable-NetFirewallRule" nocase
        $f3 = "Remote Desktop" nocase
        $f4 = "portproxy" nocase
    condition:
        any of ($r*) and (any of ($e*) or any of ($f*))
}

rule Remote_Access_Service_Persistence : suspicious
{
    meta:
        description = "Remote access tooling wired to start automatically at boot"
        severity = "high"
        mitre = "T1219,T1543.003"
    strings:
        $t1 = "AnyDesk" nocase
        $t2 = "ScreenConnect" nocase
        $t3 = "RustDesk" nocase
        $t4 = "ngrok" nocase
        $t5 = "cloudflared" nocase
        $t6 = "TeamViewer" nocase
        $p1 = "sc create" nocase
        $p2 = "New-Service" nocase
        $p3 = "schtasks /create" nocase
        $p4 = "CurrentVersion\\Run" nocase
        $p5 = "systemctl enable" nocase
        $p6 = "launchctl load" nocase
    condition:
        any of ($t*) and any of ($p*)
}
