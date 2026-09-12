/*
 * phishing_social_engineering.yar - lure pages and messages built to trick
 * a human into handing over credentials or moving money.
 */

rule Credential_Harvesting_Form : phishing
{
    meta:
        description = "HTML login form that posts credentials to a non-relative, attacker-controlled endpoint"
        severity = "high"
        author = "security-suite"
    strings:
        $f1 = "<input type=\"password\"" nocase
        $f2 = "<form" nocase
        $a1 = "action=\"http" nocase
        $a2 = "formsubmit.co" nocase
        $a3 = "docs.google.com/forms" nocase
    condition:
        $f1 and $f2 and any of ($a*)
}

rule Brand_Impersonation_Lookalike_Markup : phishing
{
    meta:
        description = "Page markup referencing a well known brand while hosted off-brand"
        severity = "medium"
    strings:
        $b1 = "PayPal" nocase
        $b2 = "Microsoft 365" nocase
        $b3 = "Apple ID" nocase
        $b4 = "Netflix" nocase
        $u1 = "verify your account" nocase
        $u2 = "unusual sign-in activity" nocase
        $u3 = "confirm your identity" nocase
    condition:
        any of ($b*) and any of ($u*)
}

rule Urgency_Lure_With_Redirect : phishing
{
    meta:
        description = "Urgency-themed lure language paired with a link redirect or shortener"
        severity = "medium"
    strings:
        $u1 = "account will be suspended" nocase
        $u2 = "act now" nocase
        $u3 = "immediate action required" nocase
        $u4 = "your account has been locked" nocase
        $r1 = "bit.ly" nocase
        $r2 = "tinyurl.com" nocase
        $r3 = "window.location.href" nocase
        $r4 = "meta http-equiv=\"refresh\"" nocase
    condition:
        any of ($u*) and any of ($r*)
}

rule QR_Code_Phishing_Lure : phishing
{
    meta:
        description = "Message instructing the recipient to scan a QR code to \"verify\" or \"reactivate\" an account"
        severity = "medium"
    strings:
        $q1 = "scan the QR code" nocase
        $q2 = "scan this code" nocase
        $q3 = "qr-code" nocase
        $l1 = "verify your account" nocase
        $l2 = "reactivate your account" nocase
        $l3 = "update your payment" nocase
    condition:
        any of ($q*) and any of ($l*)
}

rule Invoice_Finance_Themed_Lure : phishing
{
    meta:
        description = "Finance-themed lure attachment or message pressuring quick payment action"
        severity = "medium"
    strings:
        $s1 = "invoice attached" nocase
        $s2 = "outstanding balance" nocase
        $s3 = "wire transfer" nocase
        $s4 = "remittance advice" nocase
        $p1 = "open the attachment" nocase
        $p2 = "enable content" nocase
        $p3 = "enable editing" nocase
    condition:
        any of ($s*) and any of ($p*)
}
