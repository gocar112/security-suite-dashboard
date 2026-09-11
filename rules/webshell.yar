/*
 * webshell.yar - server-side script backdoors dropped into upload folders.
 * This is the classic reason to YARA-scan an uploads directory.
 */

rule PHP_Webshell_Eval_Input : webshell
{
    meta:
        description = "PHP one-liner passing request data straight to an evaluator"
        severity = "critical"
        author = "security-suite"
    strings:
        $php = "<?php"
        $e1 = "eval(" nocase
        $e2 = "assert(" nocase
        $e3 = "preg_replace" nocase
        $src1 = "$_POST" nocase
        $src2 = "$_GET" nocase
        $src3 = "$_REQUEST" nocase
        $src4 = "php://input" nocase
    condition:
        $php and any of ($e*) and any of ($src*)
}

rule PHP_Webshell_Command_Exec : webshell
{
    meta:
        description = "PHP file invoking a shell with attacker-controlled input"
        severity = "critical"
    strings:
        $php = "<?php"
        $f1 = "shell_exec" nocase
        $f2 = "passthru" nocase
        $f3 = "proc_open" nocase
        $f4 = "popen" nocase
        $f5 = "system(" nocase
        $src1 = "$_POST" nocase
        $src2 = "$_GET" nocase
        $src3 = "$_REQUEST" nocase
    condition:
        $php and any of ($f*) and any of ($src*)
}

rule ASPX_Webshell : webshell
{
    meta:
        description = "ASP.NET page compiling or executing request-supplied code"
        severity = "critical"
    strings:
        $page = "<%@ Page" nocase
        $a1 = "Request.Item" nocase
        $a2 = "Request.Form" nocase
        $b1 = "System.Diagnostics.Process" nocase
        $b2 = "CreateObject" nocase
        $b3 = "ExecuteReader" nocase
    condition:
        $page and any of ($a*) and any of ($b*)
}

rule JSP_Webshell : webshell
{
    meta:
        description = "JSP page running an OS command from a request parameter"
        severity = "critical"
    strings:
        $jsp = "<%"
        $req = "request.getParameter" nocase
        $exec1 = "Runtime.getRuntime().exec" nocase
        $exec2 = "ProcessBuilder" nocase
    condition:
        $jsp and $req and any of ($exec*)
}
