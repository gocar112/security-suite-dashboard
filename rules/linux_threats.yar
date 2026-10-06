/*
 * linux_threats.yar - Linux and container host tradecraft.
 *
 * The existing ruleset is Windows-heavy, which leaves the machines most likely
 * to be running an upload directory uncovered. Every rule here pairs a
 * capability with a context, so a system administration script that merely
 * mentions cron or ssh does not alert.
 */

rule Linux_Reverse_Shell_OneLiner : malware
{
    meta:
        description = "Reverse shell one-liner using bash, nc, or a scripting runtime"
        severity = "critical"
        mitre = "T1059.004"
        author = "security-suite"
    strings:
        $b1 = "/dev/tcp/" nocase
        $b2 = "/dev/udp/" nocase
        $n1 = "nc -e" nocase
        $n2 = "ncat -e" nocase
        $n3 = "mkfifo /tmp/" nocase
        $p1 = "socket.SOCK_STREAM" nocase
        $p2 = "pty.spawn" nocase
        $s1 = "sh -i" nocase
        $s2 = "bash -i" nocase
        $s3 = "/bin/sh" nocase
        $s4 = "/bin/bash" nocase
    condition:
        // A transport primitive plus an interactive shell. Either alone is
        // ordinary; together they are a reverse shell.
        (any of ($b*) or any of ($n*) or all of ($p*)) and any of ($s*)
}

rule Cron_Persistence_With_Download : suspicious
{
    meta:
        description = "Cron entry that fetches and runs remote content on a schedule"
        severity = "high"
        mitre = "T1053.003,T1105"
    strings:
        $c1 = "crontab -" nocase
        $c2 = "/etc/cron.d/" nocase
        $c3 = "/var/spool/cron/" nocase
        $c4 = "* * * * *"
        $d1 = "curl -" nocase
        $d2 = "wget -" nocase
        $d3 = "* /dev/null" nocase
        $x1 = "| sh" nocase
        $x2 = "| bash" nocase
        $x3 = "-O - |" nocase
    condition:
        any of ($c*) and any of ($d*) and any of ($x*)
}

rule LD_PRELOAD_Userland_Rootkit : malware
{
    meta:
        description = "Userland rootkit hooking libc through the dynamic linker"
        severity = "critical"
        mitre = "T1574.006,T1014"
    strings:
        $p1 = "/etc/ld.so.preload" nocase
        $p2 = "LD_PRELOAD" nocase
        $h1 = "dlsym(RTLD_NEXT" nocase
        $h2 = "readdir64" nocase
        $h3 = "__xstat" nocase
        $h4 = "getdents64" nocase
    condition:
        any of ($p*) and 2 of ($h*)
}

rule SSH_Credential_And_Key_Theft : malware
{
    meta:
        description = "Code collecting SSH private keys, known hosts, or shell history"
        severity = "critical"
        mitre = "T1552.004"
    strings:
        $k1 = ".ssh/id_rsa" nocase
        $k2 = ".ssh/id_ed25519" nocase
        $k3 = ".ssh/authorized_keys" nocase
        $k4 = ".ssh/known_hosts" nocase
        $k5 = ".bash_history" nocase
        $a1 = "tar -cz" nocase
        $a2 = "base64 -w" nocase
        $a3 = "curl -F" nocase
        $a4 = "scp " nocase
        $a5 = "shutil.copy" nocase
        $a6 = "cat " nocase
    condition:
        2 of ($k*) and any of ($a*)
}

rule Systemd_Service_Persistence : suspicious
{
    meta:
        description = "Systemd unit launching a payload from a world-writable path"
        severity = "high"
        mitre = "T1543.002"
    strings:
        $u1 = "[Service]"
        $u2 = "ExecStart="
        $u3 = "WantedBy=multi-user.target"
        $l1 = "/tmp/" nocase
        $l2 = "/dev/shm/" nocase
        $l3 = "/var/tmp/" nocase
        $l4 = "curl " nocase
        $l5 = "wget " nocase
    condition:
        $u1 and $u2 and ($u3 or any of ($l*)) and any of ($l*)
}

rule Linux_Log_And_History_Wiping : suspicious
{
    meta:
        description = "Anti-forensics: truncating logs or disabling shell history"
        severity = "high"
        mitre = "T1070.002,T1070.003"
    strings:
        $h1 = "unset HISTFILE" nocase
        $h2 = "HISTSIZE=0" nocase
        $h3 = "history -c" nocase
        $l1 = "/var/log/wtmp" nocase
        $l2 = "/var/log/btmp" nocase
        $l3 = "/var/log/auth.log" nocase
        $l4 = "/var/log/secure" nocase
        $w1 = "shred -u" nocase
        $w2 = "> /var/log/" nocase
        $w3 = "truncate -s 0" nocase
        $w4 = "rm -rf /var/log" nocase
    condition:
        any of ($h*) or (any of ($l*) and any of ($w*))
}

rule Container_Escape_Attempt : malware
{
    meta:
        description = "Container breakout via docker socket, privileged mount, or release_agent"
        severity = "critical"
        mitre = "T1611"
    strings:
        $c1 = "/var/run/docker.sock" nocase
        $c2 = "release_agent" nocase
        $c3 = "/proc/self/cgroup" nocase
        $c4 = "nsenter --target 1" nocase
        $c5 = "--privileged" nocase
        $a1 = "mount -o bind" nocase
        $a2 = "chroot /host" nocase
        $a3 = "docker run" nocase
        $a4 = "notify_on_release" nocase
        $a5 = "curl --unix-socket" nocase
    condition:
        any of ($c*) and any of ($a*)
}
