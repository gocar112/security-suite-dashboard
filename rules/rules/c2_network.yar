/*
 * c2_network.yar - command-and-control frameworks and network beaconing
 * tradecraft: config artifacts, beacon shapes, and tunneling patterns.
 */

rule Cobalt_Strike_Beacon_Indicators : malware
{
    meta:
        description = "Strings associated with Cobalt Strike beacon payloads and configs"
        severity = "critical"
        author = "security-suite"
    strings:
        $a1 = "cobaltstrike" nocase
        $a2 = "beacon.dll" nocase
        $a3 = "%s.%s.%s.%s" nocase
        $a4 = "ReflectiveLoader" nocase
        $a5 = "InternetOpenA" nocase
        $a6 = "InternetConnectA" nocase
    condition:
        $a1 or $a2 or $a3 or ($a4 and any of ($a5, $a6))
}

rule DNS_Tunneling_Pattern : suspicious
{
    meta:
        description = "Excessive TXT/NULL record lookups or base32-style subdomain encoding typical of DNS tunneling"
        severity = "high"
    strings:
        $a1 = "TXT" nocase
        $a2 = "dns-query" nocase
        $b1 = "base32" nocase
        $b2 = "nslookup" nocase
        $b3 = "dig +short" nocase
    condition:
        any of ($a*) and any of ($b*)
}

rule HTTP_C2_Beacon_Markers : suspicious
{
    meta:
        description = "HTTP client built with fixed, unusual beacon-style headers or URIs"
        severity = "high"
    strings:
        $u1 = "/api/v1/checkin" nocase
        $u2 = "/gate.php" nocase
        $u3 = "/submit.php" nocase
        $h1 = "User-Agent: Mozilla/4.0 (compatible; MSIE" nocase
        $h2 = "X-Session-ID:" nocase
    condition:
        any of ($u*) or any of ($h*)
}

rule Reverse_Shell_OneLiner : malware
{
    meta:
        description = "Common reverse shell one-liners across scripting languages"
        severity = "critical"
    strings:
        $a1 = "/bin/sh -i" nocase
        $a2 = "socket.socket(socket.AF_INET" nocase
        $a3 = "New-Object System.Net.Sockets.TCPClient" nocase
        $a4 = "bash -i >&" nocase
        $a5 = "nc -e /bin/sh" nocase
    condition:
        any of them
}

rule Known_C2_Framework_Strings : malware
{
    meta:
        description = "Strings referencing publicly known C2 frameworks or their default artifacts"
        severity = "high"
    strings:
        $a1 = "Meterpreter" nocase
        $a2 = "Sliver" nocase
        $a3 = "Empire" nocase
        $a4 = "Mythic" nocase
        $a5 = "havoc" nocase
    condition:
        any of them
}
