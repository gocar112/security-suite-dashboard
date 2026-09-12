import "math"

/*
 * demo.yar - safe rules for verifying the pipeline end to end.
 * Each rule sets meta.severity, which drives triage priority in the dashboard.
 */

rule Demo_TestKeyword : test
{
    meta:
        description = "Literal test keyword - used by the README smoke test"
        severity = "info"
        author = "security-suite"
    strings:
        $a = "malware" nocase
    condition:
        $a
}

rule EICAR_Test_File : test
{
    meta:
        description = "EICAR anti-malware test string (harmless by design)"
        severity = "low"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule High_Entropy_Executable : suspicious
{
    meta:
        description = "PE file whose body looks packed or encrypted"
        severity = "medium"
        mitre = "T1027.002"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and math.entropy(0, filesize) > 7.2 and filesize < 20MB
}
