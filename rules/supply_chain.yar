/*
 * supply_chain.yar - malicious packages and build-pipeline tampering.
 *
 * An upload directory that receives archives, package tarballs, or CI
 * artifacts is a supply-chain ingress point. These rules target the install
 * hooks and secret-harvesting patterns that make a package malicious, rather
 * than the name of any particular bad package.
 */

rule NPM_Install_Hook_Executes_Code : malware
{
    meta:
        description = "Package manifest running code from an install lifecycle hook"
        severity = "critical"
        author = "security-suite"
    strings:
        $m1 = "\"scripts\""
        $m2 = "\"dependencies\""
        $h1 = "\"preinstall\"" nocase
        $h2 = "\"postinstall\"" nocase
        $h3 = "\"prepare\"" nocase
        $x1 = "child_process" nocase
        $x2 = "node -e" nocase
        $x3 = "curl " nocase
        $x4 = "wget " nocase
        $x5 = "eval(" nocase
        $x6 = "Buffer.from(" nocase
    condition:
        any of ($m*) and any of ($h*) and any of ($x*)
}

rule Python_Setup_Executes_On_Install : malware
{
    meta:
        description = "setup.py or pyproject hook running commands during installation"
        severity = "critical"
    strings:
        $s1 = "setuptools" nocase
        $s2 = "from distutils" nocase
        $s3 = "setup(" nocase
        $h1 = "cmdclass" nocase
        $h2 = "class PostInstall" nocase
        $h3 = "install.run(self)" nocase
        $h4 = "build_py" nocase
        $x1 = "os.system(" nocase
        $x2 = "subprocess.Popen" nocase
        $x3 = "urllib.request.urlopen" nocase
        $x4 = "exec(" nocase
        $x5 = "b64decode" nocase
    condition:
        any of ($s*) and any of ($h*) and any of ($x*)
}

rule Package_Obfuscated_Payload : suspicious
{
    meta:
        description = "Package file hiding its payload behind encoding or a long literal"
        severity = "high"
    strings:
        $p1 = "package.json" nocase
        $p2 = "setup.py" nocase
        $p3 = "__init__.py" nocase
        $p4 = "index.js" nocase
        $o1 = "atob(" nocase
        $o2 = "b64decode" nocase
        $o3 = "fromCharCode" nocase
        $o4 = "codecs.decode" nocase
        $o5 = "rot13" nocase
        $e1 = "eval(" nocase
        $e2 = "exec(" nocase
        $e3 = "Function(" nocase
        $e4 = "child_process" nocase
    condition:
        any of ($p*) and any of ($o*) and any of ($e*)
}

rule CI_Secret_Harvesting : malware
{
    meta:
        description = "Build-time code reading CI secrets and sending them outbound"
        severity = "critical"
    strings:
        $v1 = "GITHUB_TOKEN" nocase
        $v2 = "AWS_SECRET_ACCESS_KEY" nocase
        $v3 = "NPM_TOKEN" nocase
        $v4 = "DOCKERHUB_TOKEN" nocase
        $v5 = "CI_JOB_TOKEN" nocase
        $v6 = "process.env" nocase
        $v7 = "os.environ" nocase
        $x1 = "requests.post" nocase
        $x2 = "fetch(" nocase
        $x3 = "https://api.telegram.org" nocase
        $x4 = "webhook" nocase
        $x5 = "curl -X POST" nocase
        $x6 = "XMLHttpRequest" nocase
    condition:
        2 of ($v*) and any of ($x*)
}

rule Build_Pipeline_Tampering : suspicious
{
    meta:
        description = "Workflow or build file modified to fetch and run remote content"
        severity = "high"
    strings:
        $w1 = ".github/workflows" nocase
        $w2 = "gitlab-ci.yml" nocase
        $w3 = "Jenkinsfile" nocase
        $w4 = "azure-pipelines" nocase
        $w5 = "Dockerfile" nocase
        $r1 = "curl -s" nocase
        $r2 = "wget -q" nocase
        $r3 = "ADD http" nocase
        $r4 = "RUN curl" nocase
        $p1 = "| sh" nocase
        $p2 = "| bash" nocase
        $p3 = "| python" nocase
        $p4 = "iex" nocase
    condition:
        any of ($w*) and any of ($r*) and any of ($p*)
}

rule Typosquat_Install_Beacon : suspicious
{
    meta:
        description = "Install-time script beaconing host details to a remote collector"
        severity = "high"
    strings:
        $i1 = "postinstall" nocase
        $i2 = "setup.py" nocase
        $i3 = "install_requires" nocase
        $h1 = "hostname" nocase
        $h2 = "os.getlogin" nocase
        $h3 = "getpass.getuser" nocase
        $h4 = "platform.node" nocase
        $h5 = "whoami" nocase
        $h6 = "os.userInfo" nocase
        $n1 = "http://" nocase
        $n2 = "https://" nocase
        $n3 = "dns.resolve" nocase
        $n4 = "nslookup" nocase
    condition:
        any of ($i*) and 2 of ($h*) and any of ($n*)
}
