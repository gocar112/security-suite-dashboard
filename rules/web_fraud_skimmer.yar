/*
 * web_fraud_skimmer.yar - client-side payment fraud: JavaScript card
 * skimmers and formjacking code injected into checkout pages.
 */

rule JS_Payment_Card_Skimmer : malware
{
    meta:
        description = "JavaScript reading payment card fields and exfiltrating them off-page"
        severity = "critical"
        mitre = "T1056.003"
        author = "security-suite"
    strings:
        $f1 = "cardnumber" nocase
        $f2 = "cc-number" nocase
        $f3 = "cvv" nocase
        $f4 = "cardExpiry" nocase
        $x1 = "new Image().src" nocase
        $x2 = "navigator.sendBeacon" nocase
        $x3 = "XMLHttpRequest" nocase
        $x4 = "fetch(" nocase
    condition:
        any of ($f*) and any of ($x*)
}

rule Formjacking_Exfil_Domain_Pattern : malware
{
    meta:
        description = "Checkout form submit handler redirecting captured data to a third-party domain"
        severity = "critical"
        mitre = "T1056.003"
    strings:
        $a1 = "addEventListener(\"submit\"" nocase
        $a2 = "onsubmit" nocase
        $a3 = "checkout" nocase
        $b1 = ".appspot.com" nocase
        $b2 = "-cdn-analytics" nocase
        $b3 = "atob(" nocase
    condition:
        any of ($a*) and any of ($b*)
}

rule Fake_Payment_Gateway_Iframe : phishing
{
    meta:
        description = "Injected iframe overlay mimicking a payment gateway on a checkout page"
        severity = "high"
        mitre = "T1056.003"
    strings:
        $i1 = "<iframe" nocase
        $i2 = "position:absolute" nocase
        $i3 = "z-index:9999" nocase
        $p1 = "secure-payment" nocase
        $p2 = "payment-verify" nocase
        $p3 = "billing-confirm" nocase
    condition:
        $i1 and any of ($i2, $i3) and any of ($p*)
}

rule Obfuscated_Skimmer_Exfil_Beacon : malware
{
    meta:
        description = "Obfuscated JavaScript beaconing captured form data to a hardcoded endpoint"
        severity = "critical"
        mitre = "T1056.003,T1027"
    strings:
        $o1 = "eval(atob(" nocase
        $o2 = "String.fromCharCode(" nocase
        $o3 = "unescape(" nocase
        $e1 = "sendBeacon" nocase
        $e2 = "new Image().src" nocase
        $e3 = "XMLHttpRequest" nocase
    condition:
        any of ($o*) and any of ($e*)
}
