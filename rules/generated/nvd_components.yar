/*
 * nvd_components.yar - GENERATED, do not hand-edit.
 *
 * Built from NVD CPE data by securitysuite/rulegen.py. Each rule detects a
 * known-vulnerable component present in a scanned artifact - exposure, not
 * compromise. Severity reflects that: KEV entries are high, everything else
 * is medium or low, because a vulnerable library is a review item and not
 * an interrupt.
 *
 * 931 rules, 931 of them for CISA KEV entries.
 *
 */

rule NVD_CVE_2004_0210_microsoft_interix : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft interix, affected by CVE-2004-0210"
        severity = "high"
        cve = "CVE-2004-0210"
        cvss = "7.8"
        vendor = "microsoft"
        product = "interix"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2004-0210"
    strings:
        $p = "interix" nocase
        $v0 = "2.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2005_2773_hp_openview_network_node_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp openview network node manager, affected by CVE-2005-2773"
        severity = "high"
        cve = "CVE-2005-2773"
        cvss = "9.8"
        vendor = "hp"
        product = "openview_network_node_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2005-2773"
    strings:
        $p = "openview network node manager" nocase
        $p2 = "openview-network-node-manager" nocase
        $p3 = "openview_network_node_manager" nocase
        $v0 = "6.2"
        $v1 = "7.50"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2006_1547_apache_struts : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache struts, affected by CVE-2006-1547"
        severity = "high"
        cve = "CVE-2006-1547"
        cvss = "7.5"
        vendor = "apache"
        product = "struts"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2006-1547"
    strings:
        $p = "struts" nocase
        $v0 = "1.2.9"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2007_3010_al_enterprise_omnipcx_enterprise_communication : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain al-enterprise omnipcx enterprise communication server, affected by CVE-2007-3010"
        severity = "high"
        cve = "CVE-2007-3010"
        cvss = "9.8"
        vendor = "al-enterprise"
        product = "omnipcx_enterprise_communication_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2007-3010"
    strings:
        $p = "omnipcx enterprise communication server" nocase
        $p2 = "omnipcx-enterprise-communication-server" nocase
        $p3 = "omnipcx_enterprise_communication_server" nocase
        $v0 = "7.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2008_0655_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2008-0655"
        severity = "high"
        cve = "CVE-2008-0655"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-0655"
    strings:
        $p = "acrobat" nocase
        $v0 = "8.1.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2008_0655_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2008-0655"
        severity = "high"
        cve = "CVE-2008-0655"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-0655"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "8.1.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2007_5659_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2007-5659"
        severity = "high"
        cve = "CVE-2007-5659"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2007-5659"
    strings:
        $p = "acrobat" nocase
        $v0 = "8.1.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2007_5659_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2007-5659"
        severity = "high"
        cve = "CVE-2007-5659"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2007-5659"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "8.1.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2008_3431_oracle_virtualbox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle virtualbox, affected by CVE-2008-3431"
        severity = "high"
        cve = "CVE-2008-3431"
        cvss = "8.8"
        vendor = "oracle"
        product = "virtualbox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-3431"
    strings:
        $p = "virtualbox" nocase
        $v0 = "1.6.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2008_2992_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2008-2992"
        severity = "high"
        cve = "CVE-2008-2992"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-2992"
    strings:
        $p = "acrobat" nocase
        $v0 = "8.1.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2008_2992_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2008-2992"
        severity = "high"
        cve = "CVE-2008-2992"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2008-2992"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "8.1.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_0927_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2009-0927"
        severity = "high"
        cve = "CVE-2009-0927"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-0927"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "7.0"
        $v1 = "7.1.1"
        $v2 = "8.0"
        $v3 = "8.1.3"
        $v4 = "9.0"
        $v5 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_1151_phpmyadmin_phpmyadmin : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain phpmyadmin phpmyadmin, affected by CVE-2009-1151"
        severity = "high"
        cve = "CVE-2009-1151"
        cvss = "9.8"
        vendor = "phpmyadmin"
        product = "phpmyadmin"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1151"
    strings:
        $p = "phpmyadmin" nocase
        $v0 = "2.11.0"
        $v1 = "2.11.9.5"
        $v2 = "3.0.0"
        $v3 = "3.1.3.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_1537_microsoft_directx : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft directx, affected by CVE-2009-1537"
        severity = "high"
        cve = "CVE-2009-1537"
        cvss = "8.8"
        vendor = "microsoft"
        product = "directx"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1537"
    strings:
        $p = "directx" nocase
        $v0 = "7.0"
        $v1 = "7.1"
        $v2 = "8.1"
        $v3 = "9.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_1862_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2009-1862"
        severity = "high"
        cve = "CVE-2009-1862"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1862"
    strings:
        $p = "acrobat" nocase
        $v0 = "9.0"
        $v1 = "9.1.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_1862_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2009-1862"
        severity = "high"
        cve = "CVE-2009-1862"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1862"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "9.0"
        $v1 = "9.1.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_1862_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2009-1862"
        severity = "high"
        cve = "CVE-2009-1862"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-1862"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "10.0"
        $v1 = "10.0.22.87"
        $v2 = "9.0"
        $v3 = "9.0.159.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_3459_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2009-3459"
        severity = "high"
        cve = "CVE-2009-3459"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3459"
    strings:
        $p = "acrobat" nocase
        $v0 = "7.0"
        $v1 = "7.1.4"
        $v2 = "8.0"
        $v3 = "8.1.7"
        $v4 = "9.0"
        $v5 = "9.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_3459_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2009-3459"
        severity = "high"
        cve = "CVE-2009-3459"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3459"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "7.0"
        $v1 = "7.1.4"
        $v2 = "8.0"
        $v3 = "8.1.7"
        $v4 = "9.0"
        $v5 = "9.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_4324_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2009-4324"
        severity = "high"
        cve = "CVE-2009-4324"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-4324"
    strings:
        $p = "acrobat" nocase
        $v0 = "8.0"
        $v1 = "8.2"
        $v2 = "9.0"
        $v3 = "9.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_4324_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2009-4324"
        severity = "high"
        cve = "CVE-2009-4324"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-4324"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "8.0"
        $v1 = "8.2"
        $v2 = "9.0"
        $v3 = "9.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_3953_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2009-3953"
        severity = "high"
        cve = "CVE-2009-3953"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3953"
    strings:
        $p = "acrobat" nocase
        $v0 = "7.0"
        $v1 = "7.1.4"
        $v2 = "8.0"
        $v3 = "8.2"
        $v4 = "9.0"
        $v5 = "9.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_0249_microsoft_internet_explorer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft internet explorer, affected by CVE-2010-0249"
        severity = "high"
        cve = "CVE-2010-0249"
        cvss = "8.8"
        vendor = "microsoft"
        product = "internet_explorer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0249"
    strings:
        $p = "internet explorer" nocase
        $p2 = "internet-explorer" nocase
        $p3 = "internet_explorer" nocase
        $v0 = "5.0.1"
        $v1 = "7.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_3960_adobe_blazeds : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe blazeds, affected by CVE-2009-3960"
        severity = "high"
        cve = "CVE-2009-3960"
        cvss = "6.5"
        vendor = "adobe"
        product = "blazeds"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3960"
    strings:
        $p = "blazeds" nocase
        $v0 = "3.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_3960_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2009-3960"
        severity = "high"
        cve = "CVE-2009-3960"
        cvss = "6.5"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3960"
    strings:
        $p = "coldfusion" nocase
        $v0 = "7.0.2"
        $v1 = "8.0"
        $v2 = "8.0.1"
        $v3 = "9.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_3960_adobe_flex_data_services : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flex data services, affected by CVE-2009-3960"
        severity = "high"
        cve = "CVE-2009-3960"
        cvss = "6.5"
        vendor = "adobe"
        product = "flex_data_services"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3960"
    strings:
        $p = "flex data services" nocase
        $p2 = "flex-data-services" nocase
        $p3 = "flex_data_services" nocase
        $v0 = "2.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_3960_adobe_livecycle : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe livecycle, affected by CVE-2009-3960"
        severity = "high"
        cve = "CVE-2009-3960"
        cvss = "6.5"
        vendor = "adobe"
        product = "livecycle"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3960"
    strings:
        $p = "livecycle" nocase
        $v0 = "8.0.1"
        $v1 = "8.2.1"
        $v2 = "9.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2009_3960_adobe_livecycle_data_services : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe livecycle data services, affected by CVE-2009-3960"
        severity = "high"
        cve = "CVE-2009-3960"
        cvss = "6.5"
        vendor = "adobe"
        product = "livecycle_data_services"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2009-3960"
    strings:
        $p = "livecycle data services" nocase
        $p2 = "livecycle-data-services" nocase
        $p3 = "livecycle_data_services" nocase
        $v0 = "2.5.1"
        $v1 = "2.6.1"
        $v2 = "3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_0188_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2010-0188"
        severity = "high"
        cve = "CVE-2010-0188"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0188"
    strings:
        $p = "acrobat" nocase
        $v0 = "8.0"
        $v1 = "8.2.1"
        $v2 = "9.0"
        $v3 = "9.3.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_0188_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2010-0188"
        severity = "high"
        cve = "CVE-2010-0188"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0188"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "8.0"
        $v1 = "8.2.1"
        $v2 = "9.0"
        $v3 = "9.3.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_0806_microsoft_internet_explorer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft internet explorer, affected by CVE-2010-0806"
        severity = "high"
        cve = "CVE-2010-0806"
        cvss = "8.8"
        vendor = "microsoft"
        product = "internet_explorer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0806"
    strings:
        $p = "internet explorer" nocase
        $p2 = "internet-explorer" nocase
        $p3 = "internet_explorer" nocase
        $v0 = "5.01"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_0738_redhat_jboss_enterprise_application_pla : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss enterprise application platform, affected by CVE-2010-0738"
        severity = "high"
        cve = "CVE-2010-0738"
        cvss = "5.3"
        vendor = "redhat"
        product = "jboss_enterprise_application_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-0738"
    strings:
        $p = "jboss enterprise application platform" nocase
        $p2 = "jboss-enterprise-application-platform" nocase
        $p3 = "jboss_enterprise_application_platform" nocase
        $v0 = "4.2.0"
        $v1 = "4.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_1428_redhat_jboss_enterprise_application_pla : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss enterprise application platform, affected by CVE-2010-1428"
        severity = "high"
        cve = "CVE-2010-1428"
        cvss = "7.5"
        vendor = "redhat"
        product = "jboss_enterprise_application_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1428"
    strings:
        $p = "jboss enterprise application platform" nocase
        $p2 = "jboss-enterprise-application-platform" nocase
        $p3 = "jboss_enterprise_application_platform" nocase
        $v0 = "4.2.0"
        $v1 = "4.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_1297_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2010-1297"
        severity = "high"
        cve = "CVE-2010-1297"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1297"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "10.0"
        $v1 = "10.1.53.64"
        $v2 = "9.0.277.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_1297_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2010-1297"
        severity = "high"
        cve = "CVE-2010-1297"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1297"
    strings:
        $p = "acrobat" nocase
        $v0 = "8.0"
        $v1 = "8.2.3"
        $v2 = "9.0"
        $v3 = "9.3.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_1871_redhat_jboss_enterprise_application_pla : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss enterprise application platform, affected by CVE-2010-1871"
        severity = "high"
        cve = "CVE-2010-1871"
        cvss = "8.8"
        vendor = "redhat"
        product = "jboss_enterprise_application_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-1871"
    strings:
        $p = "jboss enterprise application platform" nocase
        $p2 = "jboss-enterprise-application-platform" nocase
        $p3 = "jboss_enterprise_application_platform" nocase
        $v0 = "4.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_2861_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2010-2861"
        severity = "high"
        cve = "CVE-2010-2861"
        cvss = "9.8"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2861"
    strings:
        $p = "coldfusion" nocase
        $v0 = "9.0.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_2883_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2010-2883"
        severity = "high"
        cve = "CVE-2010-2883"
        cvss = "7.3"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2883"
    strings:
        $p = "acrobat" nocase
        $v0 = "8.0"
        $v1 = "8.2.5"
        $v2 = "9.0"
        $v3 = "9.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_2883_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2010-2883"
        severity = "high"
        cve = "CVE-2010-2883"
        cvss = "7.3"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-2883"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "8.0"
        $v1 = "8.2.5"
        $v2 = "9.0"
        $v3 = "9.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_3765_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2010-3765"
        severity = "high"
        cve = "CVE-2010-3765"
        cvss = "9.8"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-3765"
    strings:
        $p = "firefox" nocase
        $v0 = "3.5"
        $v1 = "3.5.1"
        $v2 = "3.5.10"
        $v3 = "3.5.11"
        $v4 = "3.5.12"
        $v5 = "3.5.13"
        $v6 = "3.5.14"
        $v7 = "3.5.2"
        $v8 = "3.5.3"
        $v9 = "3.5.4"
        $v10 = "3.5.5"
        $v11 = "3.5.6"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_3765_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2010-3765"
        severity = "high"
        cve = "CVE-2010-3765"
        cvss = "9.8"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-3765"
    strings:
        $p = "thunderbird" nocase
        $v0 = "3.0.1"
        $v1 = "3.0.2"
        $v2 = "3.0.3"
        $v3 = "3.0.4"
        $v4 = "3.0.5"
        $v5 = "3.0.6"
        $v6 = "3.0.7"
        $v7 = "3.0.8"
        $v8 = "3.0.9"
        $v9 = "3.1.1"
        $v10 = "3.1.2"
        $v11 = "3.1.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_3765_mozilla_seamonkey : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla seamonkey, affected by CVE-2010-3765"
        severity = "high"
        cve = "CVE-2010-3765"
        cvss = "9.8"
        vendor = "mozilla"
        product = "seamonkey"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-3765"
    strings:
        $p = "seamonkey" nocase
        $v0 = "2.0"
        $v1 = "2.0.1"
        $v2 = "2.0.2"
        $v3 = "2.0.3"
        $v4 = "2.0.4"
        $v5 = "2.0.5"
        $v6 = "2.0.6"
        $v7 = "2.0.7"
        $v8 = "2.0.8"
        $v9 = "2.0.9"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0609_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2011-0609"
        severity = "high"
        cve = "CVE-2011-0609"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0609"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "10.1.106.16"
        $v1 = "10.2.154.13"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0609_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2011-0609"
        severity = "high"
        cve = "CVE-2011-0609"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0609"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.0"
        $v1 = "10.0.1"
        $v2 = "9.0"
        $v3 = "9.4.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0609_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2011-0609"
        severity = "high"
        cve = "CVE-2011-0609"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0609"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "10.0"
        $v1 = "10.0.1"
        $v2 = "9.0"
        $v3 = "9.4.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0609_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2011-0609"
        severity = "high"
        cve = "CVE-2011-0609"
        cvss = "7.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0609"
    strings:
        $p = "chrome" nocase
        $v0 = "10.0.648.134"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0611_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2011-0611"
        severity = "high"
        cve = "CVE-2011-0611"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0611"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "10.2.154.27"
        $v1 = "10.2.156.12"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0611_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2011-0611"
        severity = "high"
        cve = "CVE-2011-0611"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0611"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "10.0"
        $v1 = "10.0.1"
        $v2 = "10.0.3"
        $v3 = "9.0"
        $v4 = "9.4.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0611_adobe_adobe_air : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe adobe air, affected by CVE-2011-0611"
        severity = "high"
        cve = "CVE-2011-0611"
        cvss = "8.8"
        vendor = "adobe"
        product = "adobe_air"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0611"
    strings:
        $p = "adobe air" nocase
        $p2 = "adobe-air" nocase
        $p3 = "adobe_air" nocase
        $v0 = "2.6.19140"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0611_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2011-0611"
        severity = "high"
        cve = "CVE-2011-0611"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0611"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.0"
        $v1 = "10.0.3"
        $v2 = "9.0"
        $v3 = "9.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_0611_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2011-0611"
        severity = "high"
        cve = "CVE-2011-0611"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-0611"
    strings:
        $p = "chrome" nocase
        $v0 = "10.0.648.205"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_3544_redhat_satellite_with_embedded_oracle : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat satellite with embedded oracle, affected by CVE-2011-3544"
        severity = "high"
        cve = "CVE-2011-3544"
        cvss = "9.8"
        vendor = "redhat"
        product = "satellite_with_embedded_oracle"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-3544"
    strings:
        $p = "satellite with embedded oracle" nocase
        $p2 = "satellite-with-embedded-oracle" nocase
        $p3 = "satellite_with_embedded_oracle" nocase
        $v0 = "5.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_2462_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2011-2462"
        severity = "high"
        cve = "CVE-2011-2462"
        cvss = "9.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-2462"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.1.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2011_2462_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2011-2462"
        severity = "high"
        cve = "CVE-2011-2462"
        cvss = "9.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2011-2462"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "10.1.1"
        $v1 = "9.0"
        $v2 = "9.4.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_0391_apache_struts : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache struts, affected by CVE-2012-0391"
        severity = "high"
        cve = "CVE-2012-0391"
        cvss = "9.8"
        vendor = "apache"
        product = "struts"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0391"
    strings:
        $p = "struts" nocase
        $v0 = "2.2.3.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_0754_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2012-0754"
        severity = "high"
        cve = "CVE-2012-0754"
        cvss = "8.1"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0754"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "10.3.183.15"
        $v1 = "11.0"
        $v2 = "11.1.102.62"
        $v3 = "11.1.111.6"
        $v4 = "11.1.115.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_0767_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2012-0767"
        severity = "high"
        cve = "CVE-2012-0767"
        cvss = "6.1"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0767"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "10.3.183.15"
        $v1 = "11.0"
        $v2 = "11.1.102.62"
        $v3 = "11.1.111.6"
        $v4 = "11.1.115.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_0158_microsoft_visual_basic : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft visual basic, affected by CVE-2012-0158"
        severity = "high"
        cve = "CVE-2012-0158"
        cvss = "8.8"
        vendor = "microsoft"
        product = "visual_basic"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0158"
    strings:
        $p = "visual basic" nocase
        $p2 = "visual-basic" nocase
        $p3 = "visual_basic" nocase
        $v0 = "6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_0158_microsoft_visual_foxpro : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft visual foxpro, affected by CVE-2012-0158"
        severity = "high"
        cve = "CVE-2012-0158"
        cvss = "8.8"
        vendor = "microsoft"
        product = "visual_foxpro"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0158"
    strings:
        $p = "visual foxpro" nocase
        $p2 = "visual-foxpro" nocase
        $p3 = "visual_foxpro" nocase
        $v0 = "8.0"
        $v1 = "9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1710_oracle_fusion_middleware : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle fusion middleware, affected by CVE-2012-1710"
        severity = "high"
        cve = "CVE-2012-1710"
        cvss = "9.8"
        vendor = "oracle"
        product = "fusion_middleware"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1710"
    strings:
        $p = "fusion middleware" nocase
        $p2 = "fusion-middleware" nocase
        $p3 = "fusion_middleware" nocase
        $v0 = "10.1.3.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1823_redhat_application_stack : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat application stack, affected by CVE-2012-1823"
        severity = "high"
        cve = "CVE-2012-1823"
        cvss = "9.8"
        vendor = "redhat"
        product = "application_stack"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1823"
    strings:
        $p = "application stack" nocase
        $p2 = "application-stack" nocase
        $p3 = "application_stack" nocase
        $v0 = "2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1823_redhat_gluster_storage_server_for_on_pr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat gluster storage server for on-premise, affected by CVE-2012-1823"
        severity = "high"
        cve = "CVE-2012-1823"
        cvss = "9.8"
        vendor = "redhat"
        product = "gluster_storage_server_for_on-premise"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1823"
    strings:
        $p = "gluster storage server for on-premise" nocase
        $p2 = "gluster-storage-server-for-on-premise" nocase
        $p3 = "gluster_storage_server_for_on-premise" nocase
        $v0 = "2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1823_redhat_storage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat storage, affected by CVE-2012-1823"
        severity = "high"
        cve = "CVE-2012-1823"
        cvss = "9.8"
        vendor = "redhat"
        product = "storage"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1823"
    strings:
        $p = "storage" nocase
        $v0 = "2.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1823_redhat_storage_for_public_cloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat storage for public cloud, affected by CVE-2012-1823"
        severity = "high"
        cve = "CVE-2012-1823"
        cvss = "9.8"
        vendor = "redhat"
        product = "storage_for_public_cloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1823"
    strings:
        $p = "storage for public cloud" nocase
        $p2 = "storage-for-public-cloud" nocase
        $p3 = "storage_for_public_cloud" nocase
        $v0 = "2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_2034_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2012-2034"
        severity = "high"
        cve = "CVE-2012-2034"
        cvss = "7.5"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-2034"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.1.111.9"
        $v1 = "11.1.115.8"
        $v2 = "11.2.202.235"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1889_microsoft_xml_core_services : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft xml core services, affected by CVE-2012-1889"
        severity = "high"
        cve = "CVE-2012-1889"
        cvss = "8.8"
        vendor = "microsoft"
        product = "xml_core_services"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1889"
    strings:
        $p = "xml core services" nocase
        $p2 = "xml-core-services" nocase
        $p3 = "xml_core_services" nocase
        $v0 = "3.0"
        $v1 = "4.0"
        $v2 = "5.0"
        $v3 = "6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1723_redhat_icedtea6 : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat icedtea6, affected by CVE-2012-1723"
        severity = "high"
        cve = "CVE-2012-1723"
        cvss = "9.8"
        vendor = "redhat"
        product = "icedtea6"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1723"
    strings:
        $p = "icedtea6" nocase
        $v0 = "1.10.8"
        $v1 = "1.11.0"
        $v2 = "1.11.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1856_microsoft_visual_basic : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft visual basic, affected by CVE-2012-1856"
        severity = "high"
        cve = "CVE-2012-1856"
        cvss = "8.8"
        vendor = "microsoft"
        product = "visual_basic"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1856"
    strings:
        $p = "visual basic" nocase
        $p2 = "visual-basic" nocase
        $p3 = "visual_basic" nocase
        $v0 = "6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1856_microsoft_visual_foxpro : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft visual foxpro, affected by CVE-2012-1856"
        severity = "high"
        cve = "CVE-2012-1856"
        cvss = "8.8"
        vendor = "microsoft"
        product = "visual_foxpro"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1856"
    strings:
        $p = "visual foxpro" nocase
        $p2 = "visual-foxpro" nocase
        $p3 = "visual_foxpro" nocase
        $v0 = "8.0"
        $v1 = "9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_1535_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2012-1535"
        severity = "high"
        cve = "CVE-2012-1535"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-1535"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.238"
        $v1 = "11.3.300.271"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_5054_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2012-5054"
        severity = "high"
        cve = "CVE-2012-5054"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-5054"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.4.402.265"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_0518_oracle_fusion_middleware : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle fusion middleware, affected by CVE-2012-0518"
        severity = "high"
        cve = "CVE-2012-0518"
        cvss = "4.7"
        vendor = "oracle"
        product = "fusion_middleware"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-0518"
    strings:
        $p = "fusion middleware" nocase
        $p2 = "fusion-middleware" nocase
        $p3 = "fusion_middleware" nocase
        $v0 = "10.1.4.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2012_3152_oracle_fusion_middleware : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle fusion middleware, affected by CVE-2012-3152"
        severity = "high"
        cve = "CVE-2012-3152"
        cvss = "9.1"
        vendor = "oracle"
        product = "fusion_middleware"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2012-3152"
    strings:
        $p = "fusion middleware" nocase
        $p2 = "fusion-middleware" nocase
        $p3 = "fusion_middleware" nocase
        $v0 = "11.1.1.4.0"
        $v1 = "11.1.1.6.0"
        $v2 = "11.1.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0625_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2013-0625"
        severity = "high"
        cve = "CVE-2013-0625"
        cvss = "9.8"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0625"
    strings:
        $p = "coldfusion" nocase
        $v0 = "9.0"
        $v1 = "9.0.1"
        $v2 = "9.0.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0629_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2013-0629"
        severity = "high"
        cve = "CVE-2013-0629"
        cvss = "7.5"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0629"
    strings:
        $p = "coldfusion" nocase
        $v0 = "10.0"
        $v1 = "9.0"
        $v2 = "9.0.1"
        $v3 = "9.0.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0631_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2013-0631"
        severity = "high"
        cve = "CVE-2013-0631"
        cvss = "7.5"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0631"
    strings:
        $p = "coldfusion" nocase
        $v0 = "9.0"
        $v1 = "9.0.1"
        $v2 = "9.0.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0632_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2013-0632"
        severity = "high"
        cve = "CVE-2013-0632"
        cvss = "9.8"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0632"
    strings:
        $p = "coldfusion" nocase
        $v0 = "10.0"
        $v1 = "9.0"
        $v2 = "9.0.1"
        $v3 = "9.0.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0640_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2013-0640"
        severity = "high"
        cve = "CVE-2013-0640"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0640"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.0"
        $v1 = "10.1.6"
        $v2 = "11.0"
        $v3 = "11.0.02"
        $v4 = "9.0"
        $v5 = "9.5.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0640_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2013-0640"
        severity = "high"
        cve = "CVE-2013-0640"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0640"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "10.0"
        $v1 = "10.1.6"
        $v2 = "11.0"
        $v3 = "11.0.02"
        $v4 = "9.0"
        $v5 = "9.5.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0641_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2013-0641"
        severity = "high"
        cve = "CVE-2013-0641"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0641"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.0"
        $v1 = "10.1.6"
        $v2 = "11.0"
        $v3 = "11.0.02"
        $v4 = "9.0"
        $v5 = "9.5.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0641_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2013-0641"
        severity = "high"
        cve = "CVE-2013-0641"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0641"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "10.0"
        $v1 = "10.1.6"
        $v2 = "11.0"
        $v3 = "11.0.02"
        $v4 = "9.0"
        $v5 = "9.5.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0643_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2013-0643"
        severity = "high"
        cve = "CVE-2013-0643"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0643"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "10.3.183.67"
        $v1 = "11.0"
        $v2 = "11.2.202.273"
        $v3 = "11.6.602.171"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0648_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2013-0648"
        severity = "high"
        cve = "CVE-2013-0648"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0648"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "10.3.183.67"
        $v1 = "11.0"
        $v2 = "11.2.202.273"
        $v3 = "11.6.602.171"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_0074_microsoft_silverlight : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft silverlight, affected by CVE-2013-0074"
        severity = "high"
        cve = "CVE-2013-0074"
        cvss = "7.8"
        vendor = "microsoft"
        product = "silverlight"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-0074"
    strings:
        $p = "silverlight" nocase
        $v0 = "5.0"
        $v1 = "5.1.20125.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_1675_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2013-1675"
        severity = "high"
        cve = "CVE-2013-1675"
        cvss = "6.5"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-1675"
    strings:
        $p = "firefox" nocase
        $v0 = "17.0"
        $v1 = "17.0.6"
        $v2 = "21.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_1675_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2013-1675"
        severity = "high"
        cve = "CVE-2013-1675"
        cvss = "6.5"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-1675"
    strings:
        $p = "thunderbird" nocase
        $v0 = "17.0.6"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_1675_mozilla_thunderbird_esr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird esr, affected by CVE-2013-1675"
        severity = "high"
        cve = "CVE-2013-1675"
        cvss = "6.5"
        vendor = "mozilla"
        product = "thunderbird_esr"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-1675"
    strings:
        $p = "thunderbird esr" nocase
        $p2 = "thunderbird-esr" nocase
        $p3 = "thunderbird_esr" nocase
        $v0 = "17.0"
        $v1 = "17.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_1675_redhat_gluster_storage_server_for_on_pr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat gluster storage server for on-premise, affected by CVE-2013-1675"
        severity = "high"
        cve = "CVE-2013-1675"
        cvss = "6.5"
        vendor = "redhat"
        product = "gluster_storage_server_for_on-premise"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-1675"
    strings:
        $p = "gluster storage server for on-premise" nocase
        $p2 = "gluster-storage-server-for-on-premise" nocase
        $p3 = "gluster_storage_server_for_on-premise" nocase
        $v0 = "2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_2729_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2013-2729"
        severity = "high"
        cve = "CVE-2013-2729"
        cvss = "9.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2729"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.0"
        $v1 = "10.1.7"
        $v2 = "11.0"
        $v3 = "11.0.03"
        $v4 = "9.0"
        $v5 = "9.5.5"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_2729_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2013-2729"
        severity = "high"
        cve = "CVE-2013-2729"
        cvss = "9.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2729"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "10.0"
        $v1 = "10.1.7"
        $v2 = "11.0"
        $v3 = "11.0.03"
        $v4 = "9.0"
        $v5 = "9.5.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_1690_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2013-1690"
        severity = "high"
        cve = "CVE-2013-1690"
        cvss = "8.8"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-1690"
    strings:
        $p = "firefox" nocase
        $v0 = "17.0"
        $v1 = "17.0.7"
        $v2 = "22.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_1690_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2013-1690"
        severity = "high"
        cve = "CVE-2013-1690"
        cvss = "8.8"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-1690"
    strings:
        $p = "thunderbird" nocase
        $v0 = "17.0.7"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_1690_mozilla_thunderbird_esr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird esr, affected by CVE-2013-1690"
        severity = "high"
        cve = "CVE-2013-1690"
        cvss = "8.8"
        vendor = "mozilla"
        product = "thunderbird_esr"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-1690"
    strings:
        $p = "thunderbird esr" nocase
        $p2 = "thunderbird-esr" nocase
        $p3 = "thunderbird_esr" nocase
        $v0 = "17.0"
        $v1 = "17.0.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_1690_redhat_gluster_storage_server_for_on_pr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat gluster storage server for on-premise, affected by CVE-2013-1690"
        severity = "high"
        cve = "CVE-2013-1690"
        cvss = "8.8"
        vendor = "redhat"
        product = "gluster_storage_server_for_on-premise"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-1690"
    strings:
        $p = "gluster storage server for on-premise" nocase
        $p2 = "gluster-storage-server-for-on-premise" nocase
        $p3 = "gluster_storage_server_for_on-premise" nocase
        $v0 = "2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_2251_apache_archiva : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache archiva, affected by CVE-2013-2251"
        severity = "high"
        cve = "CVE-2013-2251"
        cvss = "9.8"
        vendor = "apache"
        product = "archiva"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2251"
    strings:
        $p = "archiva" nocase
        $v0 = "1.2"
        $v1 = "1.2.2"
        $v2 = "1.3"
        $v3 = "1.3.8"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_2251_apache_struts : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache struts, affected by CVE-2013-2251"
        severity = "high"
        cve = "CVE-2013-2251"
        cvss = "9.8"
        vendor = "apache"
        product = "struts"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2251"
    strings:
        $p = "struts" nocase
        $v0 = "2.0.0"
        $v1 = "2.3.15"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_2251_fujitsu_interstage_business_process_mana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain fujitsu interstage business process manager analytics, affected by CVE-2013-2251"
        severity = "high"
        cve = "CVE-2013-2251"
        cvss = "9.8"
        vendor = "fujitsu"
        product = "interstage_business_process_manager_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2251"
    strings:
        $p = "interstage business process manager analytics" nocase
        $p2 = "interstage-business-process-manager-analytics" nocase
        $p3 = "interstage_business_process_manager_analytics" nocase
        $v0 = "12.0"
        $v1 = "12.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_2251_oracle_siebel_apps_e_billing : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle siebel apps - e-billing, affected by CVE-2013-2251"
        severity = "high"
        cve = "CVE-2013-2251"
        cvss = "9.8"
        vendor = "oracle"
        product = "siebel_apps_-_e-billing"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-2251"
    strings:
        $p = "siebel apps - e-billing" nocase
        $p2 = "siebel-apps---e-billing" nocase
        $p3 = "siebel_apps_-_e-billing" nocase
        $v0 = "6.1"
        $v1 = "6.1.1"
        $v2 = "6.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_3346_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2013-3346"
        severity = "high"
        cve = "CVE-2013-3346"
        cvss = "9.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-3346"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.0"
        $v1 = "10.1.7"
        $v2 = "11.0"
        $v3 = "11.0.03"
        $v4 = "9.0"
        $v5 = "9.5.5"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_3346_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2013-3346"
        severity = "high"
        cve = "CVE-2013-3346"
        cvss = "9.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-3346"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "10.0"
        $v1 = "10.1.7"
        $v2 = "11.0"
        $v3 = "11.0.03"
        $v4 = "9.0"
        $v5 = "9.5.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_4810_hp_procurve_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp procurve manager, affected by CVE-2013-4810"
        severity = "high"
        cve = "CVE-2013-4810"
        cvss = "9.8"
        vendor = "hp"
        product = "procurve_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-4810"
    strings:
        $p = "procurve manager" nocase
        $p2 = "procurve-manager" nocase
        $p3 = "procurve_manager" nocase
        $v0 = "3.20"
        $v1 = "4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_3896_microsoft_silverlight : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft silverlight, affected by CVE-2013-3896"
        severity = "high"
        cve = "CVE-2013-3896"
        cvss = "5.5"
        vendor = "microsoft"
        product = "silverlight"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-3896"
    strings:
        $p = "silverlight" nocase
        $v0 = "5.0"
        $v1 = "5.1.20913.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0496_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2014-0496"
        severity = "high"
        cve = "CVE-2014-0496"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0496"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.0"
        $v1 = "10.1.9"
        $v2 = "11.0"
        $v3 = "11.0.6"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0497_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2014-0497"
        severity = "high"
        cve = "CVE-2014-0497"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0497"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.336"
        $v1 = "11.7.700.261"
        $v2 = "11.8.800.94"
        $v3 = "12.0.0.44"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0497_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2014-0497"
        severity = "high"
        cve = "CVE-2014-0497"
        cvss = "9.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0497"
    strings:
        $p = "chrome" nocase
        $v0 = "32.0.1700.107"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0502_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2014-0502"
        severity = "high"
        cve = "CVE-2014-0502"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0502"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.341"
        $v1 = "11.7.700.269"
        $v2 = "11.8.800.94"
        $v3 = "12.0.0.70"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0502_adobe_adobe_air_sdk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe adobe air sdk, affected by CVE-2014-0502"
        severity = "high"
        cve = "CVE-2014-0502"
        cvss = "8.8"
        vendor = "adobe"
        product = "adobe_air_sdk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0502"
    strings:
        $p = "adobe air sdk" nocase
        $p2 = "adobe-air-sdk" nocase
        $p3 = "adobe_air_sdk" nocase
        $v0 = "4.0.0.1628"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0502_adobe_adobe_air : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe adobe air, affected by CVE-2014-0502"
        severity = "high"
        cve = "CVE-2014-0502"
        cvss = "8.8"
        vendor = "adobe"
        product = "adobe_air"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0502"
    strings:
        $p = "adobe air" nocase
        $p2 = "adobe-air" nocase
        $p3 = "adobe_air" nocase
        $v0 = "4.0.0.1628"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_openssl_openssl : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain openssl openssl, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "openssl"
        product = "openssl"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "openssl" nocase
        $v0 = "1.0.1"
        $v1 = "1.0.1g"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_filezilla_project_filezilla_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain filezilla-project filezilla server, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "filezilla-project"
        product = "filezilla_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "filezilla server" nocase
        $p2 = "filezilla-server" nocase
        $p3 = "filezilla_server" nocase
        $v0 = "0.9.44"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_siemens_elan_8_2 : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain siemens elan-8.2, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "siemens"
        product = "elan-8.2"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "elan-8.2" nocase
        $v0 = "8.3.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_siemens_wincc_open_architecture : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain siemens wincc open architecture, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "siemens"
        product = "wincc_open_architecture"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "wincc open architecture" nocase
        $p2 = "wincc-open-architecture" nocase
        $p3 = "wincc_open_architecture" nocase
        $v0 = "3.12"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_mitel_micollab : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mitel micollab, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "mitel"
        product = "micollab"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "micollab" nocase
        $v0 = "6.0"
        $v1 = "7.0"
        $v2 = "7.1"
        $v3 = "7.2"
        $v4 = "7.3"
        $v5 = "7.3.0.104"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_mitel_mivoice : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mitel mivoice, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "mitel"
        product = "mivoice"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "mivoice" nocase
        $v0 = "1.1.2.5"
        $v1 = "1.1.3.3"
        $v2 = "1.2.0.11"
        $v3 = "1.3.2.2"
        $v4 = "1.4.0.102"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_redhat_gluster_storage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat gluster storage, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "redhat"
        product = "gluster_storage"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "gluster storage" nocase
        $p2 = "gluster-storage" nocase
        $p3 = "gluster_storage" nocase
        $v0 = "2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_redhat_storage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat storage, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "redhat"
        product = "storage"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "storage" nocase
        $v0 = "2.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_redhat_virtualization : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat virtualization, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "redhat"
        product = "virtualization"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "virtualization" nocase
        $v0 = "6.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_broadcom_symantec_messaging_gateway : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain broadcom symantec messaging gateway, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "broadcom"
        product = "symantec_messaging_gateway"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "symantec messaging gateway" nocase
        $p2 = "symantec-messaging-gateway" nocase
        $p3 = "symantec_messaging_gateway" nocase
        $v0 = "10.6.0"
        $v1 = "10.6.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0160_splunk_splunk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain splunk splunk, affected by CVE-2014-0160"
        severity = "high"
        cve = "CVE-2014-0160"
        cvss = "7.5"
        vendor = "splunk"
        product = "splunk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    strings:
        $p = "splunk" nocase
        $v0 = "6.0.0"
        $v1 = "6.0.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0780_indusoft_web_studio : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain indusoft web studio, affected by CVE-2014-0780"
        severity = "high"
        cve = "CVE-2014-0780"
        cvss = "9.8"
        vendor = "indusoft"
        product = "web_studio"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0780"
    strings:
        $p = "web studio" nocase
        $p2 = "web-studio" nocase
        $p3 = "web_studio" nocase
        $v0 = "7.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0130_redhat_subscription_asset_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat subscription asset manager, affected by CVE-2014-0130"
        severity = "high"
        cve = "CVE-2014-0130"
        cvss = "7.5"
        vendor = "redhat"
        product = "subscription_asset_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0130"
    strings:
        $p = "subscription asset manager" nocase
        $p2 = "subscription-asset-manager" nocase
        $p3 = "subscription_asset_manager" nocase
        $v0 = "1.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0130_rubyonrails_rails : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain rubyonrails rails, affected by CVE-2014-0130"
        severity = "high"
        cve = "CVE-2014-0130"
        cvss = "7.5"
        vendor = "rubyonrails"
        product = "rails"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0130"
    strings:
        $p = "rails" nocase
        $v0 = "3.2.18"
        $v1 = "4.0.0"
        $v2 = "4.0.5"
        $v3 = "4.1.0"
        $v4 = "4.1.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_access_policy_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip access policy manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_access_policy_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip access policy manager" nocase
        $p2 = "big-ip-access-policy-manager" nocase
        $p3 = "big-ip_access_policy_manager" nocase
        $v0 = "11.1.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_advanced_firewall_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced firewall manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_advanced_firewall_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip advanced firewall manager" nocase
        $p2 = "big-ip-advanced-firewall-manager" nocase
        $p3 = "big-ip_advanced_firewall_manager" nocase
        $v0 = "11.3.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip analytics, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip analytics" nocase
        $p2 = "big-ip-analytics" nocase
        $p3 = "big-ip_analytics" nocase
        $v0 = "11.1.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_application_acceleration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application acceleration manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_application_acceleration_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip application acceleration manager" nocase
        $p2 = "big-ip-application-acceleration-manager" nocase
        $p3 = "big-ip_application_acceleration_manager" nocase
        $v0 = "11.4.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_application_security_mana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application security manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_application_security_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip application security manager" nocase
        $p2 = "big-ip-application-security-manager" nocase
        $p3 = "big-ip_application_security_manager" nocase
        $v0 = "11.1.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_edge_gateway : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip edge gateway, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_edge_gateway"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip edge gateway" nocase
        $p2 = "big-ip-edge-gateway" nocase
        $p3 = "big-ip_edge_gateway" nocase
        $v0 = "11.1.0"
        $v1 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_global_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip global traffic manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_global_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip global traffic manager" nocase
        $p2 = "big-ip-global-traffic-manager" nocase
        $p3 = "big-ip_global_traffic_manager" nocase
        $v0 = "11.1.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_link_controller : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip link controller, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_link_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip link controller" nocase
        $p2 = "big-ip-link-controller" nocase
        $p3 = "big-ip_link_controller" nocase
        $v0 = "11.1.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_local_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip local traffic manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_local_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip local traffic manager" nocase
        $p2 = "big-ip-local-traffic-manager" nocase
        $p3 = "big-ip_local_traffic_manager" nocase
        $v0 = "11.1.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_policy_enforcement_manage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip policy enforcement manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_policy_enforcement_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip policy enforcement manager" nocase
        $p2 = "big-ip-policy-enforcement-manager" nocase
        $p3 = "big-ip_policy_enforcement_manager" nocase
        $v0 = "11.3.0"
        $v1 = "11.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_protocol_security_module : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip protocol security module, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_protocol_security_module"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip protocol security module" nocase
        $p2 = "big-ip-protocol-security-module" nocase
        $p3 = "big-ip_protocol_security_module" nocase
        $v0 = "11.1.0"
        $v1 = "11.4.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_wan_optimization_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip wan optimization manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_wan_optimization_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip wan optimization manager" nocase
        $p2 = "big-ip-wan-optimization-manager" nocase
        $p3 = "big-ip_wan_optimization_manager" nocase
        $v0 = "11.1.0"
        $v1 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_ip_webaccelerator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip webaccelerator, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-ip_webaccelerator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-ip webaccelerator" nocase
        $p2 = "big-ip-webaccelerator" nocase
        $p3 = "big-ip_webaccelerator" nocase
        $v0 = "11.1.0"
        $v1 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_iq_application_delivery_cont : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq application delivery controller, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-iq_application_delivery_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-iq application delivery controller" nocase
        $p2 = "big-iq-application-delivery-controller" nocase
        $p3 = "big-iq_application_delivery_controller" nocase
        $v0 = "4.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_iq_centralized_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq centralized management, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-iq_centralized_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-iq centralized management" nocase
        $p2 = "big-iq-centralized-management" nocase
        $p3 = "big-iq_centralized_management" nocase
        $v0 = "4.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_iq_cloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq cloud, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-iq_cloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-iq cloud" nocase
        $p2 = "big-iq-cloud" nocase
        $p3 = "big-iq_cloud" nocase
        $v0 = "4.0.0"
        $v1 = "4.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_iq_cloud_and_orchestration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq cloud and orchestration, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-iq_cloud_and_orchestration"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-iq cloud and orchestration" nocase
        $p2 = "big-iq-cloud-and-orchestration" nocase
        $p3 = "big-iq_cloud_and_orchestration" nocase
        $v0 = "1.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_iq_device : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq device, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-iq_device"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-iq device" nocase
        $p2 = "big-iq-device" nocase
        $p3 = "big-iq_device" nocase
        $v0 = "4.2.0"
        $v1 = "4.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_big_iq_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq security, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "big-iq_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "big-iq security" nocase
        $p2 = "big-iq-security" nocase
        $p3 = "big-iq_security" nocase
        $v0 = "4.0.0"
        $v1 = "4.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0196_f5_enterprise_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 enterprise manager, affected by CVE-2014-0196"
        severity = "high"
        cve = "CVE-2014-0196"
        cvss = "5.5"
        vendor = "f5"
        product = "enterprise_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0196"
    strings:
        $p = "enterprise manager" nocase
        $p2 = "enterprise-manager" nocase
        $p3 = "enterprise_manager" nocase
        $v0 = "3.1.0"
        $v1 = "3.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2013_3993_ibm_infosphere_biginsights : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm infosphere biginsights, affected by CVE-2013-3993"
        severity = "high"
        cve = "CVE-2013-3993"
        cvss = "6.5"
        vendor = "ibm"
        product = "infosphere_biginsights"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2013-3993"
    strings:
        $p = "infosphere biginsights" nocase
        $p2 = "infosphere-biginsights" nocase
        $p3 = "infosphere_biginsights" nocase
        $v0 = "2.1.0.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_3120_elastic_elasticsearch : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain elastic elasticsearch, affected by CVE-2014-3120"
        severity = "high"
        cve = "CVE-2014-3120"
        cvss = "8.1"
        vendor = "elastic"
        product = "elasticsearch"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-3120"
    strings:
        $p = "elasticsearch" nocase
        $v0 = "1.2.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0546_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2014-0546"
        severity = "high"
        cve = "CVE-2014-0546"
        cvss = "9.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0546"
    strings:
        $p = "acrobat" nocase
        $v0 = "10.0"
        $v1 = "10.1.11"
        $v2 = "11.0"
        $v3 = "11.0.08"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_0546_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2014-0546"
        severity = "high"
        cve = "CVE-2014-0546"
        cvss = "9.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-0546"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "10.0"
        $v1 = "10.1.11"
        $v2 = "11.0"
        $v3 = "11.0.08"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_redhat_gluster_storage_server_for_on_pr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat gluster storage server for on-premise, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "redhat"
        product = "gluster_storage_server_for_on-premise"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "gluster storage server for on-premise" nocase
        $p2 = "gluster-storage-server-for-on-premise" nocase
        $p3 = "gluster_storage_server_for_on-premise" nocase
        $v0 = "2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_redhat_virtualization : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat virtualization, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "redhat"
        product = "virtualization"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "virtualization" nocase
        $v0 = "3.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_suse_studio_onsite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain suse studio onsite, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "suse"
        product = "studio_onsite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "studio onsite" nocase
        $p2 = "studio-onsite" nocase
        $p3 = "studio_onsite" nocase
        $v0 = "1.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_infosphere_guardium_database_act : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm infosphere guardium database activity monitoring, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "infosphere_guardium_database_activity_monitoring"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "infosphere guardium database activity monitoring" nocase
        $p2 = "infosphere-guardium-database-activity-monitoring" nocase
        $p3 = "infosphere_guardium_database_activity_monitoring" nocase
        $v0 = "8.2"
        $v1 = "9.0"
        $v2 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_pureapplication_system : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm pureapplication system, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "pureapplication_system"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "pureapplication system" nocase
        $p2 = "pureapplication-system" nocase
        $p3 = "pureapplication_system" nocase
        $v0 = "1.0.0.0"
        $v1 = "1.0.0.4"
        $v2 = "1.1.0.0"
        $v3 = "1.1.0.4"
        $v4 = "2.0.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_qradar_risk_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm qradar risk manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "qradar_risk_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "qradar risk manager" nocase
        $p2 = "qradar-risk-manager" nocase
        $p3 = "qradar_risk_manager" nocase
        $v0 = "7.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_qradar_security_information_and : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm qradar security information and event manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "qradar_security_information_and_event_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "qradar security information and event manager" nocase
        $p2 = "qradar-security-information-and-event-manager" nocase
        $p3 = "qradar_security_information_and_event_manager" nocase
        $v0 = "7.1.0"
        $v1 = "7.1.1"
        $v2 = "7.1.2"
        $v3 = "7.2"
        $v4 = "7.2.0"
        $v5 = "7.2.1"
        $v6 = "7.2.2"
        $v7 = "7.2.3"
        $v8 = "7.2.4"
        $v9 = "7.2.5"
        $v10 = "7.2.6"
        $v11 = "7.2.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_qradar_vulnerability_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm qradar vulnerability manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "qradar_vulnerability_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "qradar vulnerability manager" nocase
        $p2 = "qradar-vulnerability-manager" nocase
        $p3 = "qradar_vulnerability_manager" nocase
        $v0 = "7.2.0"
        $v1 = "7.2.1"
        $v2 = "7.2.2"
        $v3 = "7.2.3"
        $v4 = "7.2.4"
        $v5 = "7.2.6"
        $v6 = "7.2.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_smartcloud_entry_appliance : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm smartcloud entry appliance, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "smartcloud_entry_appliance"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "smartcloud entry appliance" nocase
        $p2 = "smartcloud-entry-appliance" nocase
        $p3 = "smartcloud_entry_appliance" nocase
        $v0 = "2.3.0"
        $v1 = "2.4.0"
        $v2 = "3.1.0"
        $v3 = "3.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_smartcloud_provisioning : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm smartcloud provisioning, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "smartcloud_provisioning"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "smartcloud provisioning" nocase
        $p2 = "smartcloud-provisioning" nocase
        $p3 = "smartcloud_provisioning" nocase
        $v0 = "2.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_software_defined_network_for_vir : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm software defined network for virtual environments, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "software_defined_network_for_virtual_environments"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "software defined network for virtual environments" nocase
        $p2 = "software-defined-network-for-virtual-environments" nocase
        $p3 = "software_defined_network_for_virtual_environments" nocase
        $v0 = "1.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_starter_kit_for_cloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm starter kit for cloud, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "starter_kit_for_cloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "starter kit for cloud" nocase
        $p2 = "starter-kit-for-cloud" nocase
        $p3 = "starter_kit_for_cloud" nocase
        $v0 = "2.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_ibm_workload_deployer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm workload deployer, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "ibm"
        product = "workload_deployer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "workload deployer" nocase
        $p2 = "workload-deployer" nocase
        $p3 = "workload_deployer" nocase
        $v0 = "3.1.0"
        $v1 = "3.1.0.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_novell_zenworks_configuration_managemen : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain novell zenworks configuration management, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "novell"
        product = "zenworks_configuration_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "zenworks configuration management" nocase
        $p2 = "zenworks-configuration-management" nocase
        $p3 = "zenworks_configuration_management" nocase
        $v0 = "10.3"
        $v1 = "11.1"
        $v2 = "11.2"
        $v3 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_access_policy_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip access policy manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_access_policy_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip access policy manager" nocase
        $p2 = "big-ip-access-policy-manager" nocase
        $p3 = "big-ip_access_policy_manager" nocase
        $v0 = "10.1.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_advanced_firewall_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced firewall manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_advanced_firewall_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip advanced firewall manager" nocase
        $p2 = "big-ip-advanced-firewall-manager" nocase
        $p3 = "big-ip_advanced_firewall_manager" nocase
        $v0 = "11.3.0"
        $v1 = "11.5.1"
        $v2 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip analytics, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip analytics" nocase
        $p2 = "big-ip-analytics" nocase
        $p3 = "big-ip_analytics" nocase
        $v0 = "11.0.0"
        $v1 = "11.5.1"
        $v2 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_application_acceleration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application acceleration manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_acceleration_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip application acceleration manager" nocase
        $p2 = "big-ip-application-acceleration-manager" nocase
        $p3 = "big-ip_application_acceleration_manager" nocase
        $v0 = "11.4.0"
        $v1 = "11.5.1"
        $v2 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_application_security_mana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application security manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_security_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip application security manager" nocase
        $p2 = "big-ip-application-security-manager" nocase
        $p3 = "big-ip_application_security_manager" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_edge_gateway : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip edge gateway, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_edge_gateway"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip edge gateway" nocase
        $p2 = "big-ip-edge-gateway" nocase
        $p3 = "big-ip_edge_gateway" nocase
        $v0 = "10.1.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_global_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip global traffic manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_global_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip global traffic manager" nocase
        $p2 = "big-ip-global-traffic-manager" nocase
        $p3 = "big-ip_global_traffic_manager" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_link_controller : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip link controller, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_link_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip link controller" nocase
        $p2 = "big-ip-link-controller" nocase
        $p3 = "big-ip_link_controller" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_local_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip local traffic manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_local_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip local traffic manager" nocase
        $p2 = "big-ip-local-traffic-manager" nocase
        $p3 = "big-ip_local_traffic_manager" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_policy_enforcement_manage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip policy enforcement manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_policy_enforcement_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip policy enforcement manager" nocase
        $p2 = "big-ip-policy-enforcement-manager" nocase
        $p3 = "big-ip_policy_enforcement_manager" nocase
        $v0 = "11.3.0"
        $v1 = "11.5.1"
        $v2 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_protocol_security_module : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip protocol security module, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_protocol_security_module"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip protocol security module" nocase
        $p2 = "big-ip-protocol-security-module" nocase
        $p3 = "big-ip_protocol_security_module" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.4.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_wan_optimization_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip wan optimization manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_wan_optimization_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip wan optimization manager" nocase
        $p2 = "big-ip-wan-optimization-manager" nocase
        $p3 = "big-ip_wan_optimization_manager" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_ip_webaccelerator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip webaccelerator, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_webaccelerator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-ip webaccelerator" nocase
        $p2 = "big-ip-webaccelerator" nocase
        $p3 = "big-ip_webaccelerator" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_iq_cloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq cloud, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-iq_cloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-iq cloud" nocase
        $p2 = "big-iq-cloud" nocase
        $p3 = "big-iq_cloud" nocase
        $v0 = "4.0.0"
        $v1 = "4.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_iq_device : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq device, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-iq_device"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-iq device" nocase
        $p2 = "big-iq-device" nocase
        $p3 = "big-iq_device" nocase
        $v0 = "4.2.0"
        $v1 = "4.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_big_iq_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq security, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "big-iq_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "big-iq security" nocase
        $p2 = "big-iq-security" nocase
        $p3 = "big-iq_security" nocase
        $v0 = "4.0.0"
        $v1 = "4.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_enterprise_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 enterprise manager, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "enterprise_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "enterprise manager" nocase
        $p2 = "enterprise-manager" nocase
        $p3 = "enterprise_manager" nocase
        $v0 = "2.1.0"
        $v1 = "2.3.0"
        $v2 = "3.0.0"
        $v3 = "3.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_f5_traffix_signaling_delivery_contr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 traffix signaling delivery controller, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "f5"
        product = "traffix_signaling_delivery_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "traffix signaling delivery controller" nocase
        $p2 = "traffix-signaling-delivery-controller" nocase
        $p3 = "traffix_signaling_delivery_controller" nocase
        $v0 = "3.3.2"
        $v1 = "3.4.1"
        $v2 = "3.5.1"
        $v3 = "4.0.0"
        $v4 = "4.0.5"
        $v5 = "4.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6271_vmware_vcenter_server_appliance : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vcenter server appliance, affected by CVE-2014-6271"
        severity = "high"
        cve = "CVE-2014-6271"
        cvss = "9.8"
        vendor = "vmware"
        product = "vcenter_server_appliance"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    strings:
        $p = "vcenter server appliance" nocase
        $p2 = "vcenter-server-appliance" nocase
        $p3 = "vcenter_server_appliance" nocase
        $v0 = "5.0"
        $v1 = "5.1"
        $v2 = "5.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_redhat_gluster_storage_server_for_on_pr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat gluster storage server for on-premise, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "redhat"
        product = "gluster_storage_server_for_on-premise"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "gluster storage server for on-premise" nocase
        $p2 = "gluster-storage-server-for-on-premise" nocase
        $p3 = "gluster_storage_server_for_on-premise" nocase
        $v0 = "2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_redhat_virtualization : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat virtualization, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "redhat"
        product = "virtualization"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "virtualization" nocase
        $v0 = "3.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_suse_studio_onsite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain suse studio onsite, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "suse"
        product = "studio_onsite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "studio onsite" nocase
        $p2 = "studio-onsite" nocase
        $p3 = "studio_onsite" nocase
        $v0 = "1.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_infosphere_guardium_database_act : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm infosphere guardium database activity monitoring, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "infosphere_guardium_database_activity_monitoring"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "infosphere guardium database activity monitoring" nocase
        $p2 = "infosphere-guardium-database-activity-monitoring" nocase
        $p3 = "infosphere_guardium_database_activity_monitoring" nocase
        $v0 = "8.2"
        $v1 = "9.0"
        $v2 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_pureapplication_system : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm pureapplication system, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "pureapplication_system"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "pureapplication system" nocase
        $p2 = "pureapplication-system" nocase
        $p3 = "pureapplication_system" nocase
        $v0 = "1.0.0.0"
        $v1 = "1.0.0.4"
        $v2 = "1.1.0.0"
        $v3 = "1.1.0.4"
        $v4 = "2.0.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_qradar_risk_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm qradar risk manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "qradar_risk_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "qradar risk manager" nocase
        $p2 = "qradar-risk-manager" nocase
        $p3 = "qradar_risk_manager" nocase
        $v0 = "7.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_qradar_security_information_and : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm qradar security information and event manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "qradar_security_information_and_event_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "qradar security information and event manager" nocase
        $p2 = "qradar-security-information-and-event-manager" nocase
        $p3 = "qradar_security_information_and_event_manager" nocase
        $v0 = "7.1.0"
        $v1 = "7.1.1"
        $v2 = "7.1.2"
        $v3 = "7.2"
        $v4 = "7.2.0"
        $v5 = "7.2.1"
        $v6 = "7.2.2"
        $v7 = "7.2.3"
        $v8 = "7.2.4"
        $v9 = "7.2.5"
        $v10 = "7.2.6"
        $v11 = "7.2.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_qradar_vulnerability_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm qradar vulnerability manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "qradar_vulnerability_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "qradar vulnerability manager" nocase
        $p2 = "qradar-vulnerability-manager" nocase
        $p3 = "qradar_vulnerability_manager" nocase
        $v0 = "7.2.0"
        $v1 = "7.2.1"
        $v2 = "7.2.2"
        $v3 = "7.2.3"
        $v4 = "7.2.4"
        $v5 = "7.2.6"
        $v6 = "7.2.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_smartcloud_entry_appliance : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm smartcloud entry appliance, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "smartcloud_entry_appliance"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "smartcloud entry appliance" nocase
        $p2 = "smartcloud-entry-appliance" nocase
        $p3 = "smartcloud_entry_appliance" nocase
        $v0 = "2.3.0"
        $v1 = "2.4.0"
        $v2 = "3.1.0"
        $v3 = "3.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_smartcloud_provisioning : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm smartcloud provisioning, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "smartcloud_provisioning"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "smartcloud provisioning" nocase
        $p2 = "smartcloud-provisioning" nocase
        $p3 = "smartcloud_provisioning" nocase
        $v0 = "2.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_software_defined_network_for_vir : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm software defined network for virtual environments, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "software_defined_network_for_virtual_environments"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "software defined network for virtual environments" nocase
        $p2 = "software-defined-network-for-virtual-environments" nocase
        $p3 = "software_defined_network_for_virtual_environments" nocase
        $v0 = "1.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_starter_kit_for_cloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm starter kit for cloud, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "starter_kit_for_cloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "starter kit for cloud" nocase
        $p2 = "starter-kit-for-cloud" nocase
        $p3 = "starter_kit_for_cloud" nocase
        $v0 = "2.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_ibm_workload_deployer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm workload deployer, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "ibm"
        product = "workload_deployer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "workload deployer" nocase
        $p2 = "workload-deployer" nocase
        $p3 = "workload_deployer" nocase
        $v0 = "3.1.0"
        $v1 = "3.1.0.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_novell_zenworks_configuration_managemen : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain novell zenworks configuration management, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "novell"
        product = "zenworks_configuration_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "zenworks configuration management" nocase
        $p2 = "zenworks-configuration-management" nocase
        $p3 = "zenworks_configuration_management" nocase
        $v0 = "10.3"
        $v1 = "11.1"
        $v2 = "11.2"
        $v3 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_access_policy_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip access policy manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_access_policy_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip access policy manager" nocase
        $p2 = "big-ip-access-policy-manager" nocase
        $p3 = "big-ip_access_policy_manager" nocase
        $v0 = "10.1.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_advanced_firewall_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced firewall manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_advanced_firewall_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip advanced firewall manager" nocase
        $p2 = "big-ip-advanced-firewall-manager" nocase
        $p3 = "big-ip_advanced_firewall_manager" nocase
        $v0 = "11.3.0"
        $v1 = "11.5.1"
        $v2 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip analytics, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip analytics" nocase
        $p2 = "big-ip-analytics" nocase
        $p3 = "big-ip_analytics" nocase
        $v0 = "11.0.0"
        $v1 = "11.5.1"
        $v2 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_application_acceleration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application acceleration manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_acceleration_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip application acceleration manager" nocase
        $p2 = "big-ip-application-acceleration-manager" nocase
        $p3 = "big-ip_application_acceleration_manager" nocase
        $v0 = "11.4.0"
        $v1 = "11.5.1"
        $v2 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_application_security_mana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application security manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_security_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip application security manager" nocase
        $p2 = "big-ip-application-security-manager" nocase
        $p3 = "big-ip_application_security_manager" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_edge_gateway : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip edge gateway, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_edge_gateway"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip edge gateway" nocase
        $p2 = "big-ip-edge-gateway" nocase
        $p3 = "big-ip_edge_gateway" nocase
        $v0 = "10.1.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_global_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip global traffic manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_global_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip global traffic manager" nocase
        $p2 = "big-ip-global-traffic-manager" nocase
        $p3 = "big-ip_global_traffic_manager" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_link_controller : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip link controller, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_link_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip link controller" nocase
        $p2 = "big-ip-link-controller" nocase
        $p3 = "big-ip_link_controller" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_local_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip local traffic manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_local_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip local traffic manager" nocase
        $p2 = "big-ip-local-traffic-manager" nocase
        $p3 = "big-ip_local_traffic_manager" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.5.1"
        $v4 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_policy_enforcement_manage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip policy enforcement manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_policy_enforcement_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip policy enforcement manager" nocase
        $p2 = "big-ip-policy-enforcement-manager" nocase
        $p3 = "big-ip_policy_enforcement_manager" nocase
        $v0 = "11.3.0"
        $v1 = "11.5.1"
        $v2 = "11.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_protocol_security_module : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip protocol security module, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_protocol_security_module"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip protocol security module" nocase
        $p2 = "big-ip-protocol-security-module" nocase
        $p3 = "big-ip_protocol_security_module" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.4.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_wan_optimization_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip wan optimization manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_wan_optimization_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip wan optimization manager" nocase
        $p2 = "big-ip-wan-optimization-manager" nocase
        $p3 = "big-ip_wan_optimization_manager" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_ip_webaccelerator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip webaccelerator, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_webaccelerator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-ip webaccelerator" nocase
        $p2 = "big-ip-webaccelerator" nocase
        $p3 = "big-ip_webaccelerator" nocase
        $v0 = "10.0.0"
        $v1 = "10.2.4"
        $v2 = "11.0.0"
        $v3 = "11.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_iq_cloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq cloud, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-iq_cloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-iq cloud" nocase
        $p2 = "big-iq-cloud" nocase
        $p3 = "big-iq_cloud" nocase
        $v0 = "4.0.0"
        $v1 = "4.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_iq_device : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq device, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-iq_device"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-iq device" nocase
        $p2 = "big-iq-device" nocase
        $p3 = "big-iq_device" nocase
        $v0 = "4.2.0"
        $v1 = "4.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_big_iq_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq security, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "big-iq_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "big-iq security" nocase
        $p2 = "big-iq-security" nocase
        $p3 = "big-iq_security" nocase
        $v0 = "4.0.0"
        $v1 = "4.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_enterprise_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 enterprise manager, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "enterprise_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "enterprise manager" nocase
        $p2 = "enterprise-manager" nocase
        $p3 = "enterprise_manager" nocase
        $v0 = "2.1.0"
        $v1 = "2.3.0"
        $v2 = "3.0.0"
        $v3 = "3.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_f5_traffix_signaling_delivery_contr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 traffix signaling delivery controller, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "f5"
        product = "traffix_signaling_delivery_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "traffix signaling delivery controller" nocase
        $p2 = "traffix-signaling-delivery-controller" nocase
        $p3 = "traffix_signaling_delivery_controller" nocase
        $v0 = "3.3.2"
        $v1 = "3.4.1"
        $v2 = "3.5.1"
        $v3 = "4.0.0"
        $v4 = "4.0.5"
        $v5 = "4.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_7169_vmware_vcenter_server_appliance : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vcenter server appliance, affected by CVE-2014-7169"
        severity = "high"
        cve = "CVE-2014-7169"
        cvss = "9.8"
        vendor = "vmware"
        product = "vcenter_server_appliance"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-7169"
    strings:
        $p = "vcenter server appliance" nocase
        $p2 = "vcenter-server-appliance" nocase
        $p3 = "vcenter_server_appliance" nocase
        $v0 = "5.0"
        $v1 = "5.1"
        $v2 = "5.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_6287_rejetto_http_file_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain rejetto http file server, affected by CVE-2014-6287"
        severity = "high"
        cve = "CVE-2014-6287"
        cvss = "9.8"
        vendor = "rejetto"
        product = "http_file_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-6287"
    strings:
        $p = "http file server" nocase
        $p2 = "http-file-server" nocase
        $p3 = "http_file_server" nocase
        $v0 = "2.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_8439_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2014-8439"
        severity = "high"
        cve = "CVE-2014-8439"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-8439"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.418"
        $v1 = "13.0.0.252"
        $v2 = "15.0.0.223"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_8439_adobe_air_sdk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe air sdk, affected by CVE-2014-8439"
        severity = "high"
        cve = "CVE-2014-8439"
        cvss = "8.8"
        vendor = "adobe"
        product = "air_sdk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-8439"
    strings:
        $p = "air sdk" nocase
        $p2 = "air-sdk" nocase
        $p3 = "air_sdk" nocase
        $v0 = "15.0.0.301"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_9163_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2014-9163"
        severity = "high"
        cve = "CVE-2014-9163"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-9163"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.0"
        $v1 = "11.2.202.425"
        $v2 = "13.0"
        $v3 = "13.0.0.259"
        $v4 = "14.0"
        $v5 = "14.0.0.179"
        $v6 = "15.0"
        $v7 = "15.0.0.246"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_0310_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-0310"
        severity = "high"
        cve = "CVE-2015-0310"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-0310"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.438"
        $v1 = "13.0.0.262"
        $v2 = "14.0"
        $v3 = "16.0.0.287"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_0311_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-0311"
        severity = "high"
        cve = "CVE-2015-0311"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-0311"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.438"
        $v1 = "13.0.0.262"
        $v2 = "14.0.0.125"
        $v3 = "16.0.0.287"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_0313_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-0313"
        severity = "high"
        cve = "CVE-2015-0313"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-0313"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.442"
        $v1 = "13.0.0.269"
        $v2 = "14.0.0.125"
        $v3 = "16.0.0.305"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_1427_elastic_elasticsearch : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain elastic elasticsearch, affected by CVE-2015-1427"
        severity = "high"
        cve = "CVE-2015-1427"
        cvss = "9.8"
        vendor = "elastic"
        product = "elasticsearch"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1427"
    strings:
        $p = "elasticsearch" nocase
        $v0 = "1.3.8"
        $v1 = "1.4.0"
        $v2 = "1.4.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3043_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-3043"
        severity = "high"
        cve = "CVE-2015-3043"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3043"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.457"
        $v1 = "13.0.0.281"
        $v2 = "14.0.0.125"
        $v3 = "17.0.0.169"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_1671_microsoft_net_framework : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft .net framework, affected by CVE-2015-1671"
        severity = "high"
        cve = "CVE-2015-1671"
        cvss = "7.8"
        vendor = "microsoft"
        product = ".net_framework"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1671"
    strings:
        $p = ".net framework" nocase
        $p2 = ".net-framework" nocase
        $p3 = ".net_framework" nocase
        $v0 = "3.0"
        $v1 = "3.5"
        $v2 = "3.5.1"
        $v3 = "4.0"
        $v4 = "4.5"
        $v5 = "4.5.1"
        $v6 = "4.5.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_1671_microsoft_silverlight : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft silverlight, affected by CVE-2015-1671"
        severity = "high"
        cve = "CVE-2015-1671"
        cvss = "7.8"
        vendor = "microsoft"
        product = "silverlight"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-1671"
    strings:
        $p = "silverlight" nocase
        $v0 = "5.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3113_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-3113"
        severity = "high"
        cve = "CVE-2015-3113"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3113"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.468"
        $v1 = "13.0.0.296"
        $v2 = "14.0.0.125"
        $v3 = "18.0.0.194"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3113_hp_insight_orchestration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp insight orchestration, affected by CVE-2015-3113"
        severity = "high"
        cve = "CVE-2015-3113"
        cvss = "9.8"
        vendor = "hp"
        product = "insight_orchestration"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3113"
    strings:
        $p = "insight orchestration" nocase
        $p2 = "insight-orchestration" nocase
        $p3 = "insight_orchestration" nocase
        $v0 = "7.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3113_hp_system_management_homepage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp system management homepage, affected by CVE-2015-3113"
        severity = "high"
        cve = "CVE-2015-3113"
        cvss = "9.8"
        vendor = "hp"
        product = "system_management_homepage"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3113"
    strings:
        $p = "system management homepage" nocase
        $p2 = "system-management-homepage" nocase
        $p3 = "system_management_homepage" nocase
        $v0 = "7.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3113_hp_systems_insight_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp systems insight manager, affected by CVE-2015-3113"
        severity = "high"
        cve = "CVE-2015-3113"
        cvss = "9.8"
        vendor = "hp"
        product = "systems_insight_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3113"
    strings:
        $p = "systems insight manager" nocase
        $p2 = "systems-insight-manager" nocase
        $p3 = "systems_insight_manager" nocase
        $v0 = "7.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3113_hp_version_control_agent : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp version control agent, affected by CVE-2015-3113"
        severity = "high"
        cve = "CVE-2015-3113"
        cvss = "9.8"
        vendor = "hp"
        product = "version_control_agent"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3113"
    strings:
        $p = "version control agent" nocase
        $p2 = "version-control-agent" nocase
        $p3 = "version_control_agent" nocase
        $v0 = "7.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3113_hp_version_control_repository_manag : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp version control repository manager, affected by CVE-2015-3113"
        severity = "high"
        cve = "CVE-2015-3113"
        cvss = "9.8"
        vendor = "hp"
        product = "version_control_repository_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3113"
    strings:
        $p = "version control repository manager" nocase
        $p2 = "version-control-repository-manager" nocase
        $p3 = "version_control_repository_manager" nocase
        $v0 = "7.5.0"
        $v1 = "7.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3113_hp_virtual_connect_enterprise_manag : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp virtual connect enterprise manager, affected by CVE-2015-3113"
        severity = "high"
        cve = "CVE-2015-3113"
        cvss = "9.8"
        vendor = "hp"
        product = "virtual_connect_enterprise_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3113"
    strings:
        $p = "virtual connect enterprise manager" nocase
        $p2 = "virtual-connect-enterprise-manager" nocase
        $p3 = "virtual_connect_enterprise_manager" nocase
        $v0 = "7.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_5119_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-5119"
        severity = "high"
        cve = "CVE-2015-5119"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5119"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.468"
        $v1 = "13.0.0.182"
        $v2 = "13.0.0296"
        $v3 = "14.0.0.125"
        $v4 = "18.0.0.194"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_5122_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-5122"
        severity = "high"
        cve = "CVE-2015-5122"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5122"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.0"
        $v1 = "11.2.202.481"
        $v2 = "13.0"
        $v3 = "13.0.0.302"
        $v4 = "18.0"
        $v5 = "18.0.0.203"
        $v6 = "18.0.0.204"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_5122_adobe_flash_player_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player desktop runtime, affected by CVE-2015-5122"
        severity = "high"
        cve = "CVE-2015-5122"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5122"
    strings:
        $p = "flash player desktop runtime" nocase
        $p2 = "flash-player-desktop-runtime" nocase
        $p3 = "flash_player_desktop_runtime" nocase
        $v0 = "18.0"
        $v1 = "18.0.0.203"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_5123_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-5123"
        severity = "high"
        cve = "CVE-2015-5123"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5123"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.0"
        $v1 = "11.2.202.481"
        $v2 = "13.0"
        $v3 = "13.0.0.302"
        $v4 = "18.0"
        $v5 = "18.0.0.203"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_5123_adobe_flash_player_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player desktop runtime, affected by CVE-2015-5123"
        severity = "high"
        cve = "CVE-2015-5123"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5123"
    strings:
        $p = "flash player desktop runtime" nocase
        $p2 = "flash-player-desktop-runtime" nocase
        $p3 = "flash_player_desktop_runtime" nocase
        $v0 = "18.0"
        $v1 = "18.0.0.203"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_2590_redhat_satellite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat satellite, affected by CVE-2015-2590"
        severity = "high"
        cve = "CVE-2015-2590"
        cvss = "9.8"
        vendor = "redhat"
        product = "satellite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2590"
    strings:
        $p = "satellite" nocase
        $v0 = "5.6"
        $v1 = "5.7"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_4495_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2015-4495"
        severity = "high"
        cve = "CVE-2015-4495"
        cvss = "8.8"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4495"
    strings:
        $p = "firefox" nocase
        $v0 = "38.0"
        $v1 = "38.1.1"
        $v2 = "39.0.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_3246_libuser_project_libuser : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain libuser project libuser, affected by CVE-2015-3246"
        severity = "high"
        cve = "CVE-2015-3246"
        cvss = "5.1"
        vendor = "libuser_project"
        product = "libuser"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-3246"
    strings:
        $p = "libuser" nocase
        $v0 = "0.56.13-8"
        $v1 = "0.60"
        $v2 = "0.60-7"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_7645_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-7645"
        severity = "high"
        cve = "CVE-2015-7645"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7645"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.535"
        $v1 = "18.0.0.160"
        $v2 = "18.0.0.252"
        $v3 = "19.0.0.185"
        $v4 = "19.0.0.207"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_4902_redhat_satellite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat satellite, affected by CVE-2015-4902"
        severity = "high"
        cve = "CVE-2015-4902"
        cvss = "5.3"
        vendor = "redhat"
        product = "satellite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4902"
    strings:
        $p = "satellite" nocase
        $v0 = "5.6"
        $v1 = "5.7"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_4852_oracle_virtual_desktop_infrastructure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle virtual desktop infrastructure, affected by CVE-2015-4852"
        severity = "high"
        cve = "CVE-2015-4852"
        cvss = "9.8"
        vendor = "oracle"
        product = "virtual_desktop_infrastructure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4852"
    strings:
        $p = "virtual desktop infrastructure" nocase
        $p2 = "virtual-desktop-infrastructure" nocase
        $p3 = "virtual_desktop_infrastructure" nocase
        $v0 = "3.5.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_4852_oracle_storagetek_tape_analytics_sw_too : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle storagetek tape analytics sw tool, affected by CVE-2015-4852"
        severity = "high"
        cve = "CVE-2015-4852"
        cvss = "9.8"
        vendor = "oracle"
        product = "storagetek_tape_analytics_sw_tool"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4852"
    strings:
        $p = "storagetek tape analytics sw tool" nocase
        $p2 = "storagetek-tape-analytics-sw-tool" nocase
        $p3 = "storagetek_tape_analytics_sw_tool" nocase
        $v0 = "2.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_4852_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2015-4852"
        severity = "high"
        cve = "CVE-2015-4852"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-4852"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.2.0.0"
        $v2 = "12.1.3.0.0"
        $v3 = "12.2.1.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_5317_jenkins_jenkins : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain jenkins jenkins, affected by CVE-2015-5317"
        severity = "high"
        cve = "CVE-2015-5317"
        cvss = "7.5"
        vendor = "jenkins"
        product = "jenkins"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5317"
    strings:
        $p = "jenkins" nocase
        $v0 = "1.625.1"
        $v1 = "1.637"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_5317_redhat_openshift : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat openshift, affected by CVE-2015-5317"
        severity = "high"
        cve = "CVE-2015-5317"
        cvss = "7.5"
        vendor = "redhat"
        product = "openshift"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5317"
    strings:
        $p = "openshift" nocase
        $v0 = "2.0"
        $v1 = "3.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_5287_redhat_automatic_bug_reporting_tool : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat automatic bug reporting tool, affected by CVE-2015-5287"
        severity = "high"
        cve = "CVE-2015-5287"
        cvss = "7.8"
        vendor = "redhat"
        product = "automatic_bug_reporting_tool"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-5287"
    strings:
        $p = "automatic bug reporting tool" nocase
        $p2 = "automatic-bug-reporting-tool" nocase
        $p3 = "automatic_bug_reporting_tool" nocase
        $v0 = "2.7.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_8651_adobe_air_sdk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe air sdk, affected by CVE-2015-8651"
        severity = "high"
        cve = "CVE-2015-8651"
        cvss = "8.8"
        vendor = "adobe"
        product = "air_sdk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8651"
    strings:
        $p = "air sdk" nocase
        $p2 = "air-sdk" nocase
        $p3 = "air_sdk" nocase
        $v0 = "20.0.0.233"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_8651_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2015-8651"
        severity = "high"
        cve = "CVE-2015-8651"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8651"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.559"
        $v1 = "18.0.0.324"
        $v2 = "19.0.0.185"
        $v3 = "20.0.0.267"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_8651_hp_insight_control : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp insight control, affected by CVE-2015-8651"
        severity = "high"
        cve = "CVE-2015-8651"
        cvss = "8.8"
        vendor = "hp"
        product = "insight_control"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8651"
    strings:
        $p = "insight control" nocase
        $p2 = "insight-control" nocase
        $p3 = "insight_control" nocase
        $v0 = "7.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_8651_hp_insight_control_server_provision : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp insight control server provisioning, affected by CVE-2015-8651"
        severity = "high"
        cve = "CVE-2015-8651"
        cvss = "8.8"
        vendor = "hp"
        product = "insight_control_server_provisioning"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8651"
    strings:
        $p = "insight control server provisioning" nocase
        $p2 = "insight-control-server-provisioning" nocase
        $p3 = "insight_control_server_provisioning" nocase
        $v0 = "7.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_8651_hp_matrix_operating_environment : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp matrix operating environment, affected by CVE-2015-8651"
        severity = "high"
        cve = "CVE-2015-8651"
        cvss = "8.8"
        vendor = "hp"
        product = "matrix_operating_environment"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8651"
    strings:
        $p = "matrix operating environment" nocase
        $p2 = "matrix-operating-environment" nocase
        $p3 = "matrix_operating_environment" nocase
        $v0 = "7.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_8651_hp_system_management_homepage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp system management homepage, affected by CVE-2015-8651"
        severity = "high"
        cve = "CVE-2015-8651"
        cvss = "8.8"
        vendor = "hp"
        product = "system_management_homepage"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8651"
    strings:
        $p = "system management homepage" nocase
        $p2 = "system-management-homepage" nocase
        $p3 = "system_management_homepage" nocase
        $v0 = "7.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_8651_hp_systems_insight_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp systems insight manager, affected by CVE-2015-8651"
        severity = "high"
        cve = "CVE-2015-8651"
        cvss = "8.8"
        vendor = "hp"
        product = "systems_insight_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8651"
    strings:
        $p = "systems insight manager" nocase
        $p2 = "systems-insight-manager" nocase
        $p3 = "systems_insight_manager" nocase
        $v0 = "7.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_8651_hp_version_control_repository_manag : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp version control repository manager, affected by CVE-2015-8651"
        severity = "high"
        cve = "CVE-2015-8651"
        cvss = "8.8"
        vendor = "hp"
        product = "version_control_repository_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-8651"
    strings:
        $p = "version control repository manager" nocase
        $p2 = "version-control-repository-manager" nocase
        $p3 = "version_control_repository_manager" nocase
        $v0 = "7.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_7450_ibm_sterling_b2b_integrator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm sterling b2b integrator, affected by CVE-2015-7450"
        severity = "high"
        cve = "CVE-2015-7450"
        cvss = "9.8"
        vendor = "ibm"
        product = "sterling_b2b_integrator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7450"
    strings:
        $p = "sterling b2b integrator" nocase
        $p2 = "sterling-b2b-integrator" nocase
        $p3 = "sterling_b2b_integrator" nocase
        $v0 = "5.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_7450_ibm_sterling_integrator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm sterling integrator, affected by CVE-2015-7450"
        severity = "high"
        cve = "CVE-2015-7450"
        cvss = "9.8"
        vendor = "ibm"
        product = "sterling_integrator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7450"
    strings:
        $p = "sterling integrator" nocase
        $p2 = "sterling-integrator" nocase
        $p3 = "sterling_integrator" nocase
        $v0 = "5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_7450_ibm_tivoli_common_reporting : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm tivoli common reporting, affected by CVE-2015-7450"
        severity = "high"
        cve = "CVE-2015-7450"
        cvss = "9.8"
        vendor = "ibm"
        product = "tivoli_common_reporting"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7450"
    strings:
        $p = "tivoli common reporting" nocase
        $p2 = "tivoli-common-reporting" nocase
        $p3 = "tivoli_common_reporting" nocase
        $v0 = "2.1"
        $v1 = "2.1.1"
        $v2 = "2.1.1.2"
        $v3 = "3.1"
        $v4 = "3.1.0.1"
        $v5 = "3.1.0.2"
        $v6 = "3.1.2"
        $v7 = "3.1.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_7450_ibm_watson_content_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm watson content analytics, affected by CVE-2015-7450"
        severity = "high"
        cve = "CVE-2015-7450"
        cvss = "9.8"
        vendor = "ibm"
        product = "watson_content_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7450"
    strings:
        $p = "watson content analytics" nocase
        $p2 = "watson-content-analytics" nocase
        $p3 = "watson_content_analytics" nocase
        $v0 = "3.0"
        $v1 = "3.0.0.6"
        $v2 = "3.5"
        $v3 = "3.5.0.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_7450_ibm_watson_explorer_analytical_compo : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm watson explorer analytical components, affected by CVE-2015-7450"
        severity = "high"
        cve = "CVE-2015-7450"
        cvss = "9.8"
        vendor = "ibm"
        product = "watson_explorer_analytical_components"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7450"
    strings:
        $p = "watson explorer analytical components" nocase
        $p2 = "watson-explorer-analytical-components" nocase
        $p3 = "watson_explorer_analytical_components" nocase
        $v0 = "10.0"
        $v1 = "10.0.0.2"
        $v2 = "11.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_7450_ibm_watson_explorer_annotation_admin : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm watson explorer annotation administration console, affected by CVE-2015-7450"
        severity = "high"
        cve = "CVE-2015-7450"
        cvss = "9.8"
        vendor = "ibm"
        product = "watson_explorer_annotation_administration_console"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7450"
    strings:
        $p = "watson explorer annotation administration console" nocase
        $p2 = "watson-explorer-annotation-administration-console" nocase
        $p3 = "watson_explorer_annotation_administration_console" nocase
        $v0 = "10.0"
        $v1 = "10.0.0.2"
        $v2 = "11.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_7450_ibm_websphere_application_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm websphere application server, affected by CVE-2015-7450"
        severity = "high"
        cve = "CVE-2015-7450"
        cvss = "9.8"
        vendor = "ibm"
        product = "websphere_application_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-7450"
    strings:
        $p = "websphere application server" nocase
        $p2 = "websphere-application-server" nocase
        $p3 = "websphere_application_server" nocase
        $v0 = "7.0.0.0"
        $v1 = "8.0.0.0"
        $v2 = "8.5"
        $v3 = "8.5.0.0"
        $v4 = "8.5.5.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0034_microsoft_silverlight : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft silverlight, affected by CVE-2016-0034"
        severity = "high"
        cve = "CVE-2016-0034"
        cvss = "8.8"
        vendor = "microsoft"
        product = "silverlight"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0034"
    strings:
        $p = "silverlight" nocase
        $v0 = "5.0"
        $v1 = "5.1.41212.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0984_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2016-0984"
        severity = "high"
        cve = "CVE-2016-0984"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0984"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.559"
        $v1 = "18.0.0.326"
        $v2 = "20.0.0.272"
        $v3 = "20.0.0.286"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0984_adobe_flash_player_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player desktop runtime, affected by CVE-2016-0984"
        severity = "high"
        cve = "CVE-2016-0984"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0984"
    strings:
        $p = "flash player desktop runtime" nocase
        $p2 = "flash-player-desktop-runtime" nocase
        $p3 = "flash_player_desktop_runtime" nocase
        $v0 = "20.0.0.286"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0984_adobe_air_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe air desktop runtime, affected by CVE-2016-0984"
        severity = "high"
        cve = "CVE-2016-0984"
        cvss = "8.8"
        vendor = "adobe"
        product = "air_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0984"
    strings:
        $p = "air desktop runtime" nocase
        $p2 = "air-desktop-runtime" nocase
        $p3 = "air_desktop_runtime" nocase
        $v0 = "20.0.0.233"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0984_adobe_air_sdk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe air sdk, affected by CVE-2016-0984"
        severity = "high"
        cve = "CVE-2016-0984"
        cvss = "8.8"
        vendor = "adobe"
        product = "air_sdk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0984"
    strings:
        $p = "air sdk" nocase
        $p2 = "air-sdk" nocase
        $p3 = "air_sdk" nocase
        $v0 = "20.0.0.233"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0752_rubyonrails_rails : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain rubyonrails rails, affected by CVE-2016-0752"
        severity = "high"
        cve = "CVE-2016-0752"
        cvss = "7.5"
        vendor = "rubyonrails"
        product = "rails"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0752"
    strings:
        $p = "rails" nocase
        $v0 = "3.2.22.1"
        $v1 = "4.0.0"
        $v2 = "4.1.14.1"
        $v3 = "4.2.0"
        $v4 = "4.2.5.1"
        $v5 = "5.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0752_redhat_software_collections : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat software collections, affected by CVE-2016-0752"
        severity = "high"
        cve = "CVE-2016-0752"
        cvss = "7.5"
        vendor = "redhat"
        product = "software_collections"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0752"
    strings:
        $p = "software collections" nocase
        $p2 = "software-collections" nocase
        $p3 = "software_collections" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_2386_sap_netweaver_application_server_jav : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap netweaver application server java, affected by CVE-2016-2386"
        severity = "high"
        cve = "CVE-2016-2386"
        cvss = "9.8"
        vendor = "sap"
        product = "netweaver_application_server_java"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-2386"
    strings:
        $p = "netweaver application server java" nocase
        $p2 = "netweaver-application-server-java" nocase
        $p3 = "netweaver_application_server_java" nocase
        $v0 = "7.40"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_2388_sap_netweaver_application_server_jav : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap netweaver application server java, affected by CVE-2016-2388"
        severity = "high"
        cve = "CVE-2016-2388"
        cvss = "5.3"
        vendor = "sap"
        product = "netweaver_application_server_java"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-2388"
    strings:
        $p = "netweaver application server java" nocase
        $p2 = "netweaver-application-server-java" nocase
        $p3 = "netweaver_application_server_java" nocase
        $v0 = "7.10"
        $v1 = "7.50"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1010_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2016-1010"
        severity = "high"
        cve = "CVE-2016-1010"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1010"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.569"
        $v1 = "20.0.0.306"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1010_adobe_air_sdk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe air sdk, affected by CVE-2016-1010"
        severity = "high"
        cve = "CVE-2016-1010"
        cvss = "8.8"
        vendor = "adobe"
        product = "air_sdk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1010"
    strings:
        $p = "air sdk" nocase
        $p2 = "air-sdk" nocase
        $p3 = "air_sdk" nocase
        $v0 = "20.0.0.260"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1010_adobe_flash_player_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player desktop runtime, affected by CVE-2016-1010"
        severity = "high"
        cve = "CVE-2016-1010"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1010"
    strings:
        $p = "flash player desktop runtime" nocase
        $p2 = "flash-player-desktop-runtime" nocase
        $p3 = "flash_player_desktop_runtime" nocase
        $v0 = "20.2.2.306"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1010_adobe_air_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe air desktop runtime, affected by CVE-2016-1010"
        severity = "high"
        cve = "CVE-2016-1010"
        cvss = "8.8"
        vendor = "adobe"
        product = "air_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1010"
    strings:
        $p = "air desktop runtime" nocase
        $p2 = "air-desktop-runtime" nocase
        $p3 = "air_desktop_runtime" nocase
        $v0 = "20.0.0.260"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1646_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2016-1646"
        severity = "high"
        cve = "CVE-2016-1646"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1646"
    strings:
        $p = "chrome" nocase
        $v0 = "49.0.2623.108"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1019_adobe_flash_player_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player desktop runtime, affected by CVE-2016-1019"
        severity = "high"
        cve = "CVE-2016-1019"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1019"
    strings:
        $p = "flash player desktop runtime" nocase
        $p2 = "flash-player-desktop-runtime" nocase
        $p3 = "flash_player_desktop_runtime" nocase
        $v0 = "21.0.0.197"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1019_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2016-1019"
        severity = "high"
        cve = "CVE-2016-1019"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1019"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.577"
        $v1 = "18.0.0.333"
        $v2 = "21.0.0.197"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1019_adobe_air_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe air desktop runtime, affected by CVE-2016-1019"
        severity = "high"
        cve = "CVE-2016-1019"
        cvss = "9.8"
        vendor = "adobe"
        product = "air_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1019"
    strings:
        $p = "air desktop runtime" nocase
        $p2 = "air-desktop-runtime" nocase
        $p3 = "air_desktop_runtime" nocase
        $v0 = "21.0.0.176"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_1019_adobe_air_sdk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe air sdk, affected by CVE-2016-1019"
        severity = "high"
        cve = "CVE-2016-1019"
        cvss = "9.8"
        vendor = "adobe"
        product = "air_sdk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-1019"
    strings:
        $p = "air sdk" nocase
        $p2 = "air-sdk" nocase
        $p3 = "air_sdk" nocase
        $v0 = "21.0.0.176"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3976_sap_netweaver_application_server_jav : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap netweaver application server java, affected by CVE-2016-3976"
        severity = "high"
        cve = "CVE-2016-3976"
        cvss = "7.5"
        vendor = "sap"
        product = "netweaver_application_server_java"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3976"
    strings:
        $p = "netweaver application server java" nocase
        $p2 = "netweaver-application-server-java" nocase
        $p3 = "netweaver_application_server_java" nocase
        $v0 = "7.10"
        $v1 = "7.50"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3427_netapp_storagegrid : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain netapp storagegrid, affected by CVE-2016-3427"
        severity = "high"
        cve = "CVE-2016-3427"
        cvss = "9.8"
        vendor = "netapp"
        product = "storagegrid"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3427"
    strings:
        $p = "storagegrid" nocase
        $v0 = "9.0.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3427_netapp_vasa_provider_for_clustered_data : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain netapp vasa provider for clustered data ontap, affected by CVE-2016-3427"
        severity = "high"
        cve = "CVE-2016-3427"
        cvss = "9.8"
        vendor = "netapp"
        product = "vasa_provider_for_clustered_data_ontap"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3427"
    strings:
        $p = "vasa provider for clustered data ontap" nocase
        $p2 = "vasa-provider-for-clustered-data-ontap" nocase
        $p3 = "vasa_provider_for_clustered_data_ontap" nocase
        $v0 = "7.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3427_netapp_virtual_storage_console : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain netapp virtual storage console, affected by CVE-2016-3427"
        severity = "high"
        cve = "CVE-2016-3427"
        cvss = "9.8"
        vendor = "netapp"
        product = "virtual_storage_console"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3427"
    strings:
        $p = "virtual storage console" nocase
        $p2 = "virtual-storage-console" nocase
        $p3 = "virtual_storage_console" nocase
        $v0 = "7.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3427_apache_cassandra : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache cassandra, affected by CVE-2016-3427"
        severity = "high"
        cve = "CVE-2016-3427"
        cvss = "9.8"
        vendor = "apache"
        product = "cassandra"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3427"
    strings:
        $p = "cassandra" nocase
        $v0 = "2.1.0"
        $v1 = "2.1.22"
        $v2 = "2.2.0"
        $v3 = "2.2.18"
        $v4 = "3.0.0"
        $v5 = "3.0.22"
        $v6 = "3.11.0"
        $v7 = "3.11.8"
        $v8 = "4.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3427_redhat_satellite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat satellite, affected by CVE-2016-3427"
        severity = "high"
        cve = "CVE-2016-3427"
        cvss = "9.8"
        vendor = "redhat"
        product = "satellite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3427"
    strings:
        $p = "satellite" nocase
        $v0 = "5.6"
        $v1 = "5.7"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3427_suse_manager_proxy : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain suse manager proxy, affected by CVE-2016-3427"
        severity = "high"
        cve = "CVE-2016-3427"
        cvss = "9.8"
        vendor = "suse"
        product = "manager_proxy"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3427"
    strings:
        $p = "manager proxy" nocase
        $p2 = "manager-proxy" nocase
        $p3 = "manager_proxy" nocase
        $v0 = "2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3714_imagemagick_imagemagick : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain imagemagick imagemagick, affected by CVE-2016-3714"
        severity = "high"
        cve = "CVE-2016-3714"
        cvss = "8.4"
        vendor = "imagemagick"
        product = "imagemagick"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3714"
    strings:
        $p = "imagemagick" nocase
        $v0 = "6.9.3-9"
        $v1 = "7.0.0-0"
        $v2 = "7.0.1-0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3715_imagemagick_imagemagick : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain imagemagick imagemagick, affected by CVE-2016-3715"
        severity = "high"
        cve = "CVE-2016-3715"
        cvss = "5.5"
        vendor = "imagemagick"
        product = "imagemagick"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3715"
    strings:
        $p = "imagemagick" nocase
        $v0 = "6.9.3-10"
        $v1 = "7.0.0-0"
        $v2 = "7.0.1-0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3715_suse_manager_proxy : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain suse manager proxy, affected by CVE-2016-3715"
        severity = "high"
        cve = "CVE-2016-3715"
        cvss = "5.5"
        vendor = "suse"
        product = "manager_proxy"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3715"
    strings:
        $p = "manager proxy" nocase
        $p2 = "manager-proxy" nocase
        $p3 = "manager_proxy" nocase
        $v0 = "2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3718_imagemagick_imagemagick : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain imagemagick imagemagick, affected by CVE-2016-3718"
        severity = "high"
        cve = "CVE-2016-3718"
        cvss = "5.5"
        vendor = "imagemagick"
        product = "imagemagick"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3718"
    strings:
        $p = "imagemagick" nocase
        $v0 = "6.9.3-10"
        $v1 = "7.0.0-0"
        $v2 = "7.0.1-0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3718_suse_manager_proxy : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain suse manager proxy, affected by CVE-2016-3718"
        severity = "high"
        cve = "CVE-2016-3718"
        cvss = "5.5"
        vendor = "suse"
        product = "manager_proxy"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3718"
    strings:
        $p = "manager proxy" nocase
        $p2 = "manager-proxy" nocase
        $p3 = "manager_proxy" nocase
        $v0 = "2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0189_microsoft_jscript : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft jscript, affected by CVE-2016-0189"
        severity = "high"
        cve = "CVE-2016-0189"
        cvss = "7.5"
        vendor = "microsoft"
        product = "jscript"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0189"
    strings:
        $p = "jscript" nocase
        $v0 = "5.8"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_0189_microsoft_vbscript : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft vbscript, affected by CVE-2016-0189"
        severity = "high"
        cve = "CVE-2016-0189"
        cvss = "7.5"
        vendor = "microsoft"
        product = "vbscript"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-0189"
    strings:
        $p = "vbscript" nocase
        $v0 = "5.7"
        $v1 = "5.8"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_4117_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2016-4117"
        severity = "high"
        cve = "CVE-2016-4117"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-4117"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "21.0.0.226"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2010_5326_sap_netweaver_application_server_jav : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap netweaver application server java, affected by CVE-2010-5326"
        severity = "high"
        cve = "CVE-2010-5326"
        cvss = "10.0"
        vendor = "sap"
        product = "netweaver_application_server_java"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2010-5326"
    strings:
        $p = "netweaver application server java" nocase
        $p2 = "netweaver-application-server-java" nocase
        $p3 = "netweaver_application_server_java" nocase
        $v0 = "7.30"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3088_apache_activemq : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache activemq, affected by CVE-2016-3088"
        severity = "high"
        cve = "CVE-2016-3088"
        cvss = "9.8"
        vendor = "apache"
        product = "activemq"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3088"
    strings:
        $p = "activemq" nocase
        $v0 = "5.0.0"
        $v1 = "5.14.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_4437_apache_aurora : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache aurora, affected by CVE-2016-4437"
        severity = "high"
        cve = "CVE-2016-4437"
        cvss = "9.8"
        vendor = "apache"
        product = "aurora"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-4437"
    strings:
        $p = "aurora" nocase
        $v0 = "0.10.0"
        $v1 = "0.18.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_4437_apache_shiro : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache shiro, affected by CVE-2016-4437"
        severity = "high"
        cve = "CVE-2016-4437"
        cvss = "9.8"
        vendor = "apache"
        product = "shiro"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-4437"
    strings:
        $p = "shiro" nocase
        $v0 = "1.2.5"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_4437_redhat_jboss_middleware_text_only_advis : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss middleware text-only advisories, affected by CVE-2016-4437"
        severity = "high"
        cve = "CVE-2016-4437"
        cvss = "9.8"
        vendor = "redhat"
        product = "jboss_middleware_text-only_advisories"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-4437"
    strings:
        $p = "jboss middleware text-only advisories" nocase
        $p2 = "jboss-middleware-text-only-advisories" nocase
        $p3 = "jboss_middleware_text-only_advisories" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_4523_trihedral_vtscada : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain trihedral vtscada, affected by CVE-2016-4523"
        severity = "high"
        cve = "CVE-2016-4523"
        cvss = "7.5"
        vendor = "trihedral"
        product = "vtscada"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-4523"
    strings:
        $p = "vtscada" nocase
        $v0 = "11.2.02"
        $v1 = "8.0.05"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_4171_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2016-4171"
        severity = "high"
        cve = "CVE-2016-4171"
        cvss = "9.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-4171"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.621"
        $v1 = "18.0.0.352"
        $v2 = "21.0.0.242"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_3643_solarwinds_virtualization_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain solarwinds virtualization manager, affected by CVE-2016-3643"
        severity = "high"
        cve = "CVE-2016-3643"
        cvss = "7.8"
        vendor = "solarwinds"
        product = "virtualization_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-3643"
    strings:
        $p = "virtualization manager" nocase
        $p2 = "virtualization-manager" nocase
        $p3 = "virtualization_manager" nocase
        $v0 = "6.3.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_7855_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2016-7855"
        severity = "high"
        cve = "CVE-2016-7855"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-7855"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.637"
        $v1 = "23.0.0.185"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_9563_sap_netweaver_application_server_jav : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap netweaver application server java, affected by CVE-2016-9563"
        severity = "high"
        cve = "CVE-2016-9563"
        cvss = "6.5"
        vendor = "sap"
        product = "netweaver_application_server_java"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-9563"
    strings:
        $p = "netweaver application server java" nocase
        $p2 = "netweaver-application-server-java" nocase
        $p3 = "netweaver_application_server_java" nocase
        $v0 = "7.50"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_7892_adobe_flash_player_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player desktop runtime, affected by CVE-2016-7892"
        severity = "high"
        cve = "CVE-2016-7892"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-7892"
    strings:
        $p = "flash player desktop runtime" nocase
        $p2 = "flash-player-desktop-runtime" nocase
        $p3 = "flash_player_desktop_runtime" nocase
        $v0 = "23.0.0.207"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_7892_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2016-7892"
        severity = "high"
        cve = "CVE-2016-7892"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-7892"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "11.2.202.644"
        $v1 = "23.0.0.207"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_10033_phpmailer_project_phpmailer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain phpmailer project phpmailer, affected by CVE-2016-10033"
        severity = "high"
        cve = "CVE-2016-10033"
        cvss = "9.8"
        vendor = "phpmailer_project"
        product = "phpmailer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10033"
    strings:
        $p = "phpmailer" nocase
        $v0 = "5.2.18"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_10033_wordpress_wordpress : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain wordpress wordpress, affected by CVE-2016-10033"
        severity = "high"
        cve = "CVE-2016-10033"
        cvss = "9.8"
        vendor = "wordpress"
        product = "wordpress"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-10033"
    strings:
        $p = "wordpress" nocase
        $v0 = "4.7"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_5198_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2016-5198"
        severity = "high"
        cve = "CVE-2016-5198"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-5198"
    strings:
        $p = "chrome" nocase
        $v0 = "54.0.2840.85"
        $v1 = "54.0.2840.87"
        $v2 = "54.0.2840.90"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_5638_apache_struts : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache struts, affected by CVE-2017-5638"
        severity = "high"
        cve = "CVE-2017-5638"
        cvss = "9.8"
        vendor = "apache"
        product = "struts"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
    strings:
        $p = "struts" nocase
        $v0 = "2.2.3"
        $v1 = "2.3.32"
        $v2 = "2.5.0"
        $v3 = "2.5.10.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_5638_hp_server_automation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain hp server automation, affected by CVE-2017-5638"
        severity = "high"
        cve = "CVE-2017-5638"
        cvss = "9.8"
        vendor = "hp"
        product = "server_automation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
    strings:
        $p = "server automation" nocase
        $p2 = "server-automation" nocase
        $p3 = "server_automation" nocase
        $v0 = "10.0.0"
        $v1 = "10.1.0"
        $v2 = "10.2.0"
        $v3 = "10.5.0"
        $v4 = "9.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_5638_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2017-5638"
        severity = "high"
        cve = "CVE-2017-5638"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.1.0"
        $v3 = "12.2.1.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_5638_arubanetworks_clearpass_policy_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain arubanetworks clearpass policy manager, affected by CVE-2017-5638"
        severity = "high"
        cve = "CVE-2017-5638"
        cvss = "9.8"
        vendor = "arubanetworks"
        product = "clearpass_policy_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
    strings:
        $p = "clearpass policy manager" nocase
        $p2 = "clearpass-policy-manager" nocase
        $p3 = "clearpass_policy_manager" nocase
        $v0 = "6.6.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_0022_microsoft_xml_core_services : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft xml core services, affected by CVE-2017-0022"
        severity = "high"
        cve = "CVE-2017-0022"
        cvss = "6.5"
        vendor = "microsoft"
        product = "xml_core_services"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0022"
    strings:
        $p = "xml core services" nocase
        $p2 = "xml-core-services" nocase
        $p3 = "xml_core_services" nocase
        $v0 = "3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_0143_microsoft_server_message_block : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft server message block, affected by CVE-2017-0143"
        severity = "high"
        cve = "CVE-2017-0143"
        cvss = "8.8"
        vendor = "microsoft"
        product = "server_message_block"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0143"
    strings:
        $p = "server message block" nocase
        $p2 = "server-message-block" nocase
        $p3 = "server_message_block" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_0143_philips_intellispace_portal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain philips intellispace portal, affected by CVE-2017-0143"
        severity = "high"
        cve = "CVE-2017-0143"
        cvss = "8.8"
        vendor = "philips"
        product = "intellispace_portal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0143"
    strings:
        $p = "intellispace portal" nocase
        $p2 = "intellispace-portal" nocase
        $p3 = "intellispace_portal" nocase
        $v0 = "7.0"
        $v1 = "8.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_0144_microsoft_server_message_block : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft server message block, affected by CVE-2017-0144"
        severity = "high"
        cve = "CVE-2017-0144"
        cvss = "8.8"
        vendor = "microsoft"
        product = "server_message_block"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"
    strings:
        $p = "server message block" nocase
        $p2 = "server-message-block" nocase
        $p3 = "server_message_block" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_0145_microsoft_server_message_block : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft server message block, affected by CVE-2017-0145"
        severity = "high"
        cve = "CVE-2017-0145"
        cvss = "8.8"
        vendor = "microsoft"
        product = "server_message_block"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0145"
    strings:
        $p = "server message block" nocase
        $p2 = "server-message-block" nocase
        $p3 = "server_message_block" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_0146_microsoft_server_message_block : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft server message block, affected by CVE-2017-0146"
        severity = "high"
        cve = "CVE-2017-0146"
        cvss = "8.8"
        vendor = "microsoft"
        product = "server_message_block"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0146"
    strings:
        $p = "server message block" nocase
        $p2 = "server-message-block" nocase
        $p3 = "server_message_block" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_0148_microsoft_server_message_block : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft server message block, affected by CVE-2017-0148"
        severity = "high"
        cve = "CVE-2017-0148"
        cvss = "8.1"
        vendor = "microsoft"
        product = "server_message_block"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0148"
    strings:
        $p = "server message block" nocase
        $p2 = "server-message-block" nocase
        $p3 = "server_message_block" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_7269_microsoft_internet_information_services : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft internet information services, affected by CVE-2017-7269"
        severity = "high"
        cve = "CVE-2017-7269"
        cvss = "9.8"
        vendor = "microsoft"
        product = "internet_information_services"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-7269"
    strings:
        $p = "internet information services" nocase
        $p2 = "internet-information-services" nocase
        $p3 = "internet_information_services" nocase
        $v0 = "6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2014_3931_multi_router_looking_gla_multi_router_looking_glass : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain multi-router looking glass project multi-router looking glass, affected by CVE-2014-3931"
        severity = "high"
        cve = "CVE-2014-3931"
        cvss = "9.8"
        vendor = "multi-router_looking_glass_project"
        product = "multi-router_looking_glass"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2014-3931"
    strings:
        $p = "multi-router looking glass" nocase
        $p2 = "multi-router-looking-glass" nocase
        $p3 = "multi-router_looking_glass" nocase
        $v0 = "5.4.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_apache_tomcat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache tomcat, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "apache"
        product = "tomcat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "tomcat" nocase
        $v0 = "6.0.48"
        $v1 = "7.0.0"
        $v2 = "7.0.73"
        $v3 = "8.0"
        $v4 = "8.0.39"
        $v5 = "8.5.0"
        $v6 = "8.5.7"
        $v7 = "9.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_redhat_jboss_enterprise_web_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss enterprise web server, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "redhat"
        product = "jboss_enterprise_web_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "jboss enterprise web server" nocase
        $p2 = "jboss-enterprise-web-server" nocase
        $p3 = "jboss_enterprise_web_server" nocase
        $v0 = "3.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_agile_engineering_data_managemen : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle agile engineering data management, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "agile_engineering_data_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "agile engineering data management" nocase
        $p2 = "agile-engineering-data-management" nocase
        $p3 = "agile_engineering_data_management" nocase
        $v0 = "6.1.3"
        $v1 = "6.2.0"
        $v2 = "6.2.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_agile_product_lifecycle_manageme : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle agile product lifecycle management, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "agile_product_lifecycle_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "agile product lifecycle management" nocase
        $p2 = "agile-product-lifecycle-management" nocase
        $p3 = "agile_product_lifecycle_management" nocase
        $v0 = "9.3.5"
        $v1 = "9.3.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_communications_application_sessi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications application session controller, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_application_session_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "communications application session controller" nocase
        $p2 = "communications-application-session-controller" nocase
        $p3 = "communications_application_session_controller" nocase
        $v0 = "3.7.1"
        $v1 = "3.8.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_communications_instant_messaging : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications instant messaging server, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_instant_messaging_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "communications instant messaging server" nocase
        $p2 = "communications-instant-messaging-server" nocase
        $p3 = "communications_instant_messaging_server" nocase
        $v0 = "10.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_communications_interactive_sessi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications interactive session recorder, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_interactive_session_recorder"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "communications interactive session recorder" nocase
        $p2 = "communications-interactive-session-recorder" nocase
        $p3 = "communications_interactive_session_recorder" nocase
        $v0 = "6.0"
        $v1 = "6.1"
        $v2 = "6.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_hospitality_guest_access : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle hospitality guest access, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "hospitality_guest_access"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "hospitality guest access" nocase
        $p2 = "hospitality-guest-access" nocase
        $p3 = "hospitality_guest_access" nocase
        $v0 = "4.2.0"
        $v1 = "4.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_micros_relate_crm_software : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle micros relate crm software, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "micros_relate_crm_software"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "micros relate crm software" nocase
        $p2 = "micros-relate-crm-software" nocase
        $p3 = "micros_relate_crm_software" nocase
        $v0 = "10.8"
        $v1 = "11.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_micros_retail_xbri_loss_preventi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle micros retail xbri loss prevention, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "micros_retail_xbri_loss_prevention"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "micros retail xbri loss prevention" nocase
        $p2 = "micros-retail-xbri-loss-prevention" nocase
        $p3 = "micros_retail_xbri_loss_prevention" nocase
        $v0 = "10.0.1"
        $v1 = "10.5.0"
        $v2 = "10.6.0"
        $v3 = "10.7.7"
        $v4 = "10.8.0"
        $v5 = "10.8.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_mysql_enterprise_monitor : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle mysql enterprise monitor, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "mysql_enterprise_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "mysql enterprise monitor" nocase
        $p2 = "mysql-enterprise-monitor" nocase
        $p3 = "mysql_enterprise_monitor" nocase
        $v0 = "3.2.8.2223"
        $v1 = "3.3.0"
        $v2 = "3.3.4.3247"
        $v3 = "3.4.0"
        $v4 = "3.4.2.4181"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_retail_convenience_and_fuel_pos : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail convenience and fuel pos software, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "retail_convenience_and_fuel_pos_software"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "retail convenience and fuel pos software" nocase
        $p2 = "retail-convenience-and-fuel-pos-software" nocase
        $p3 = "retail_convenience_and_fuel_pos_software" nocase
        $v0 = "2.1.132"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_8735_oracle_transportation_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle transportation management, affected by CVE-2016-8735"
        severity = "high"
        cve = "CVE-2016-8735"
        cvss = "9.8"
        vendor = "oracle"
        product = "transportation_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    strings:
        $p = "transportation management" nocase
        $p2 = "transportation-management" nocase
        $p3 = "transportation_management" nocase
        $v0 = "6.3.0"
        $v1 = "6.3.1"
        $v2 = "6.3.2"
        $v3 = "6.3.3"
        $v4 = "6.3.4"
        $v5 = "6.3.5"
        $v6 = "6.3.6"
        $v7 = "6.3.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_0199_philips_intellispace_portal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain philips intellispace portal, affected by CVE-2017-0199"
        severity = "high"
        cve = "CVE-2017-0199"
        cvss = "7.8"
        vendor = "philips"
        product = "intellispace_portal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0199"
    strings:
        $p = "intellispace portal" nocase
        $p2 = "intellispace-portal" nocase
        $p3 = "intellispace_portal" nocase
        $v0 = "7.0"
        $v1 = "8.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_3506_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2017-3506"
        severity = "high"
        cve = "CVE-2017-3506"
        cvss = "7.4"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-3506"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.0.0"
        $v3 = "12.2.1.1.0"
        $v4 = "12.2.1.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_5030_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2017-5030"
        severity = "high"
        cve = "CVE-2017-5030"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5030"
    strings:
        $p = "chrome" nocase
        $v0 = "57.0.2987.108"
        $v1 = "57.0.2987.98"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_8291_artifex_ghostscript : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain artifex ghostscript, affected by CVE-2017-8291"
        severity = "high"
        cve = "CVE-2017-8291"
        cvss = "7.8"
        vendor = "artifex"
        product = "ghostscript"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-8291"
    strings:
        $p = "ghostscript" nocase
        $v0 = "9.21"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_3066_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2017-3066"
        severity = "high"
        cve = "CVE-2017-3066"
        cvss = "9.8"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-3066"
    strings:
        $p = "coldfusion" nocase
        $v0 = "10.0"
        $v1 = "11.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_8540_microsoft_malware_protection_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft malware protection engine, affected by CVE-2017-8540"
        severity = "high"
        cve = "CVE-2017-8540"
        cvss = "7.8"
        vendor = "microsoft"
        product = "malware_protection_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-8540"
    strings:
        $p = "malware protection engine" nocase
        $p2 = "malware-protection-engine" nocase
        $p3 = "malware_protection_engine" nocase
        $v0 = "1.1.13701.0"
        $v1 = "1.1.13704.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_7494_samba_samba : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain samba samba, affected by CVE-2017-7494"
        severity = "high"
        cve = "CVE-2017-7494"
        cvss = "9.8"
        vendor = "samba"
        product = "samba"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-7494"
    strings:
        $p = "samba" nocase
        $v0 = "3.5.0"
        $v1 = "4.4.0"
        $v2 = "4.4.14"
        $v3 = "4.5.0"
        $v4 = "4.5.10"
        $v5 = "4.6.0"
        $v6 = "4.6.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_7836_skygroup_skysea_client_view : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain skygroup skysea client view, affected by CVE-2016-7836"
        severity = "high"
        cve = "CVE-2016-7836"
        cvss = "9.8"
        vendor = "skygroup"
        product = "skysea_client_view"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-7836"
    strings:
        $p = "skysea client view" nocase
        $p2 = "skysea-client-view" nocase
        $p3 = "skysea_client_view" nocase
        $v0 = "11.221.03"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_9841_phpunit_project_phpunit : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain phpunit project phpunit, affected by CVE-2017-9841"
        severity = "high"
        cve = "CVE-2017-9841"
        cvss = "9.8"
        vendor = "phpunit_project"
        product = "phpunit"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9841"
    strings:
        $p = "phpunit" nocase
        $v0 = "4.8.27"
        $v1 = "5.0.0"
        $v2 = "5.6.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_9841_oracle_communications_diameter_signalin : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications diameter signaling router, affected by CVE-2017-9841"
        severity = "high"
        cve = "CVE-2017-9841"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_diameter_signaling_router"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9841"
    strings:
        $p = "communications diameter signaling router" nocase
        $p2 = "communications-diameter-signaling-router" nocase
        $p3 = "communications_diameter_signaling_router" nocase
        $v0 = "8.0.0"
        $v1 = "8.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_9248_progress_sitefinity : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain progress sitefinity, affected by CVE-2017-9248"
        severity = "high"
        cve = "CVE-2017-9248"
        cvss = "9.8"
        vendor = "progress"
        product = "sitefinity"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9248"
    strings:
        $p = "sitefinity" nocase
        $v0 = "10.0.6412.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_9248_telerik_ui_for_asp_net_ajax : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain telerik ui for asp.net ajax, affected by CVE-2017-9248"
        severity = "high"
        cve = "CVE-2017-9248"
        cvss = "9.8"
        vendor = "telerik"
        product = "ui_for_asp.net_ajax"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9248"
    strings:
        $p = "ui for asp.net ajax" nocase
        $p2 = "ui-for-asp.net-ajax" nocase
        $p3 = "ui_for_asp.net_ajax" nocase
        $v0 = "2017.2.503"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_9791_apache_struts : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache struts, affected by CVE-2017-9791"
        severity = "high"
        cve = "CVE-2017-9791"
        cvss = "9.8"
        vendor = "apache"
        product = "struts"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9791"
    strings:
        $p = "struts" nocase
        $v0 = "2.3.1"
        $v1 = "2.3.1.1"
        $v2 = "2.3.1.2"
        $v3 = "2.3.12"
        $v4 = "2.3.14"
        $v5 = "2.3.14.1"
        $v6 = "2.3.14.2"
        $v7 = "2.3.14.3"
        $v8 = "2.3.15"
        $v9 = "2.3.15.1"
        $v10 = "2.3.15.2"
        $v11 = "2.3.15.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_6316_citrix_netscaler_sd_wan : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain citrix netscaler sd-wan, affected by CVE-2017-6316"
        severity = "high"
        cve = "CVE-2017-6316"
        cvss = "9.8"
        vendor = "citrix"
        product = "netscaler_sd-wan"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-6316"
    strings:
        $p = "netscaler sd-wan" nocase
        $p2 = "netscaler-sd-wan" nocase
        $p3 = "netscaler_sd-wan" nocase
        $v0 = "9.1.2.26.561201"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_9822_dnnsoftware_dotnetnuke : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain dnnsoftware dotnetnuke, affected by CVE-2017-9822"
        severity = "high"
        cve = "CVE-2017-9822"
        cvss = "8.8"
        vendor = "dnnsoftware"
        product = "dotnetnuke"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9822"
    strings:
        $p = "dotnetnuke" nocase
        $v0 = "9.1.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12637_sap_netweaver_application_server_jav : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap netweaver application server java, affected by CVE-2017-12637"
        severity = "high"
        cve = "CVE-2017-12637"
        cvss = "7.5"
        vendor = "sap"
        product = "netweaver_application_server_java"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12637"
    strings:
        $p = "netweaver application server java" nocase
        $p2 = "netweaver-application-server-java" nocase
        $p3 = "netweaver_application_server_java" nocase
        $v0 = "7.50"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2015_2291_intel_ethernet_diagnostics_driver_iqvw : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain intel ethernet diagnostics driver iqvw32.sys, affected by CVE-2015-2291"
        severity = "high"
        cve = "CVE-2015-2291"
        cvss = "7.8"
        vendor = "intel"
        product = "ethernet_diagnostics_driver_iqvw32.sys"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2015-2291"
    strings:
        $p = "ethernet diagnostics driver iqvw32.sys" nocase
        $p2 = "ethernet-diagnostics-driver-iqvw32.sys" nocase
        $p3 = "ethernet_diagnostics_driver_iqvw32.sys" nocase
        $v0 = "1.03.0.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_6327_symantec_message_gateway : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain symantec message gateway, affected by CVE-2017-6327"
        severity = "high"
        cve = "CVE-2017-6327"
        cvss = "8.8"
        vendor = "symantec"
        product = "message_gateway"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-6327"
    strings:
        $p = "message gateway" nocase
        $p2 = "message-gateway" nocase
        $p3 = "message_gateway" nocase
        $v0 = "10.6.3-267"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_11317_telerik_ui_for_asp_net_ajax : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain telerik ui for asp.net ajax, affected by CVE-2017-11317"
        severity = "high"
        cve = "CVE-2017-11317"
        cvss = "9.8"
        vendor = "telerik"
        product = "ui_for_asp.net_ajax"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11317"
    strings:
        $p = "ui for asp.net ajax" nocase
        $p2 = "ui-for-asp.net-ajax" nocase
        $p3 = "ui_for_asp.net_ajax" nocase
        $v0 = "2016.3.1027"
        $v1 = "2017.2.503"
        $v2 = "2017.2.621"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_11357_progress_telerik_ui_for_asp_net_ajax : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain progress telerik ui for asp.net ajax, affected by CVE-2017-11357"
        severity = "high"
        cve = "CVE-2017-11357"
        cvss = "9.8"
        vendor = "progress"
        product = "telerik_ui_for_asp.net_ajax"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11357"
    strings:
        $p = "telerik ui for asp.net ajax" nocase
        $p2 = "telerik-ui-for-asp.net-ajax" nocase
        $p3 = "telerik_ui_for_asp.net_ajax" nocase
        $v0 = "2020.1.114"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_8759_microsoft_net_framework : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft .net framework, affected by CVE-2017-8759"
        severity = "high"
        cve = "CVE-2017-8759"
        cvss = "7.8"
        vendor = "microsoft"
        product = ".net_framework"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-8759"
    strings:
        $p = ".net framework" nocase
        $p2 = ".net-framework" nocase
        $p3 = ".net_framework" nocase
        $v0 = "2.0"
        $v1 = "3.5"
        $v2 = "3.5.1"
        $v3 = "4.5.2"
        $v4 = "4.6"
        $v5 = "4.6.1"
        $v6 = "4.6.2"
        $v7 = "4.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_9805_apache_struts : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache struts, affected by CVE-2017-9805"
        severity = "high"
        cve = "CVE-2017-9805"
        cvss = "8.1"
        vendor = "apache"
        product = "struts"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9805"
    strings:
        $p = "struts" nocase
        $v0 = "2.1.2"
        $v1 = "2.3.34"
        $v2 = "2.5.0"
        $v3 = "2.5.13"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_9805_cisco_media_experience_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cisco media experience engine, affected by CVE-2017-9805"
        severity = "high"
        cve = "CVE-2017-9805"
        cvss = "8.1"
        vendor = "cisco"
        product = "media_experience_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-9805"
    strings:
        $p = "media experience engine" nocase
        $p2 = "media-experience-engine" nocase
        $p3 = "media_experience_engine" nocase
        $v0 = "3.5"
        $v1 = "3.5.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12615_apache_tomcat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache tomcat, affected by CVE-2017-12615"
        severity = "high"
        cve = "CVE-2017-12615"
        cvss = "8.1"
        vendor = "apache"
        product = "tomcat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12615"
    strings:
        $p = "tomcat" nocase
        $v0 = "7.0.0"
        $v1 = "7.0.79"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12615_redhat_enterprise_linux_server_update_s : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat enterprise linux server update services for sap solutions, affected by CVE-2017-12615"
        severity = "high"
        cve = "CVE-2017-12615"
        cvss = "8.1"
        vendor = "redhat"
        product = "enterprise_linux_server_update_services_for_sap_solutions"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12615"
    strings:
        $p = "enterprise linux server update services for sap solutions" nocase
        $p2 = "enterprise-linux-server-update-services-for-sap-solutions" nocase
        $p3 = "enterprise_linux_server_update_services_for_sap_solutions" nocase
        $v0 = "7.4"
        $v1 = "7.6"
        $v2 = "7.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12615_redhat_jboss_enterprise_web_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss enterprise web server, affected by CVE-2017-12615"
        severity = "high"
        cve = "CVE-2017-12615"
        cvss = "8.1"
        vendor = "redhat"
        product = "jboss_enterprise_web_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12615"
    strings:
        $p = "jboss enterprise web server" nocase
        $p2 = "jboss-enterprise-web-server" nocase
        $p3 = "jboss_enterprise_web_server" nocase
        $v0 = "2.0.0"
        $v1 = "3.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_apache_tomcat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache tomcat, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "apache"
        product = "tomcat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "tomcat" nocase
        $v0 = "7.0.0"
        $v1 = "7.0.82"
        $v2 = "8.0"
        $v3 = "8.0.47"
        $v4 = "8.5.0"
        $v5 = "8.5.23"
        $v6 = "9.0.0"
        $v7 = "9.0.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_agile_product_lifecycle_manageme : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle agile product lifecycle management, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "agile_product_lifecycle_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "agile product lifecycle management" nocase
        $p2 = "agile-product-lifecycle-management" nocase
        $p3 = "agile_product_lifecycle_management" nocase
        $v0 = "9.3.3"
        $v1 = "9.3.4"
        $v2 = "9.3.5"
        $v3 = "9.3.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_communications_instant_messaging : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications instant messaging server, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "communications_instant_messaging_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "communications instant messaging server" nocase
        $p2 = "communications-instant-messaging-server" nocase
        $p3 = "communications_instant_messaging_server" nocase
        $v0 = "10.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_endeca_information_discovery_int : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle endeca information discovery integrator, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "endeca_information_discovery_integrator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "endeca information discovery integrator" nocase
        $p2 = "endeca-information-discovery-integrator" nocase
        $p3 = "endeca_information_discovery_integrator" nocase
        $v0 = "3.1.0"
        $v1 = "3.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_enterprise_manager_for_mysql_dat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle enterprise manager for mysql database, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "enterprise_manager_for_mysql_database"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "enterprise manager for mysql database" nocase
        $p2 = "enterprise-manager-for-mysql-database" nocase
        $p3 = "enterprise_manager_for_mysql_database" nocase
        $v0 = "12.1.0.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_financial_services_analytical_ap : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle financial services analytical applications infrastructure, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "financial_services_analytical_applications_infrastructure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "financial services analytical applications infrastructure" nocase
        $p2 = "financial-services-analytical-applications-infrastructure" nocase
        $p3 = "financial_services_analytical_applications_infrastructure" nocase
        $v0 = "7.3.3.0.0"
        $v1 = "7.3.5.3.0"
        $v2 = "8.0.0.0.0"
        $v3 = "8.0.9.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_fmw_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle fmw platform, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "fmw_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "fmw platform" nocase
        $p2 = "fmw-platform" nocase
        $p3 = "fmw_platform" nocase
        $v0 = "12.2.1.2.0"
        $v1 = "12.2.1.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_health_sciences_empirica_inspect : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle health sciences empirica inspections, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "health_sciences_empirica_inspections"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "health sciences empirica inspections" nocase
        $p2 = "health-sciences-empirica-inspections" nocase
        $p3 = "health_sciences_empirica_inspections" nocase
        $v0 = "1.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_hospitality_guest_access : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle hospitality guest access, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "hospitality_guest_access"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "hospitality guest access" nocase
        $p2 = "hospitality-guest-access" nocase
        $p3 = "hospitality_guest_access" nocase
        $v0 = "4.2.0"
        $v1 = "4.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_instantis_enterprisetrack : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle instantis enterprisetrack, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "instantis_enterprisetrack"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "instantis enterprisetrack" nocase
        $p2 = "instantis-enterprisetrack" nocase
        $p3 = "instantis_enterprisetrack" nocase
        $v0 = "17.1"
        $v1 = "17.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_management_pack : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle management pack, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "management_pack"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "management pack" nocase
        $p2 = "management-pack" nocase
        $p3 = "management_pack" nocase
        $v0 = "11.2.1.0.13"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_micros_lucas : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle micros lucas, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "micros_lucas"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "micros lucas" nocase
        $p2 = "micros-lucas" nocase
        $p3 = "micros_lucas" nocase
        $v0 = "2.9.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_micros_retail_xbri_loss_preventi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle micros retail xbri loss prevention, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "micros_retail_xbri_loss_prevention"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "micros retail xbri loss prevention" nocase
        $p2 = "micros-retail-xbri-loss-prevention" nocase
        $p3 = "micros_retail_xbri_loss_prevention" nocase
        $v0 = "10.0.1"
        $v1 = "10.5.0"
        $v2 = "10.6.0"
        $v3 = "10.7.0"
        $v4 = "10.8.0"
        $v5 = "10.8.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_mysql_enterprise_monitor : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle mysql enterprise monitor, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "mysql_enterprise_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "mysql enterprise monitor" nocase
        $p2 = "mysql-enterprise-monitor" nocase
        $p3 = "mysql_enterprise_monitor" nocase
        $v0 = "3.3.6.3293"
        $v1 = "3.4.0"
        $v2 = "3.4.4.4226"
        $v3 = "4.0.0"
        $v4 = "4.0.0.5135"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_advanced_inventory_planni : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail advanced inventory planning, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_advanced_inventory_planning"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail advanced inventory planning" nocase
        $p2 = "retail-advanced-inventory-planning" nocase
        $p3 = "retail_advanced_inventory_planning" nocase
        $v0 = "13.2"
        $v1 = "13.4"
        $v2 = "14.1"
        $v3 = "15.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_back_office : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail back office, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_back_office"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail back office" nocase
        $p2 = "retail-back-office" nocase
        $p3 = "retail_back_office" nocase
        $v0 = "14.0.4"
        $v1 = "14.1.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_central_office : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail central office, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_central_office"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail central office" nocase
        $p2 = "retail-central-office" nocase
        $p3 = "retail_central_office" nocase
        $v0 = "14.0.4"
        $v1 = "14.1.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_convenience_and_fuel_pos : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail convenience and fuel pos software, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_convenience_and_fuel_pos_software"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail convenience and fuel pos software" nocase
        $p2 = "retail-convenience-and-fuel-pos-software" nocase
        $p3 = "retail_convenience_and_fuel_pos_software" nocase
        $v0 = "2.1.132"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_eftlink : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail eftlink, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_eftlink"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail eftlink" nocase
        $p2 = "retail-eftlink" nocase
        $p3 = "retail_eftlink" nocase
        $v0 = "1.1.124"
        $v1 = "15.0.1"
        $v2 = "16.0.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_insights : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail insights, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_insights"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail insights" nocase
        $p2 = "retail-insights" nocase
        $p3 = "retail_insights" nocase
        $v0 = "14.0"
        $v1 = "14.1"
        $v2 = "15.0"
        $v3 = "16.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_invoice_matching : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail invoice matching, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_invoice_matching"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail invoice matching" nocase
        $p2 = "retail-invoice-matching" nocase
        $p3 = "retail_invoice_matching" nocase
        $v0 = "12.0"
        $v1 = "13.0"
        $v2 = "13.1"
        $v3 = "13.2"
        $v4 = "14.0"
        $v5 = "14.1"
        $v6 = "15.0"
        $v7 = "16.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_order_broker : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail order broker, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_order_broker"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail order broker" nocase
        $p2 = "retail-order-broker" nocase
        $p3 = "retail_order_broker" nocase
        $v0 = "15.0"
        $v1 = "16.0"
        $v2 = "5.0"
        $v3 = "5.1"
        $v4 = "5.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_order_management_system : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail order management system, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_order_management_system"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail order management system" nocase
        $p2 = "retail-order-management-system" nocase
        $p3 = "retail_order_management_system" nocase
        $v0 = "4.0"
        $v1 = "4.5"
        $v2 = "4.7"
        $v3 = "5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_point_of_service : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail point-of-service, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_point-of-service"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail point-of-service" nocase
        $p2 = "retail-point-of-service" nocase
        $p3 = "retail_point-of-service" nocase
        $v0 = "14.0.4"
        $v1 = "14.1.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_price_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail price management, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_price_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail price management" nocase
        $p2 = "retail-price-management" nocase
        $p3 = "retail_price_management" nocase
        $v0 = "12.0"
        $v1 = "13.0"
        $v2 = "13.1"
        $v3 = "13.2"
        $v4 = "14.0"
        $v5 = "14.1"
        $v6 = "15.0"
        $v7 = "16.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_returns_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail returns management, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_returns_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail returns management" nocase
        $p2 = "retail-returns-management" nocase
        $p3 = "retail_returns_management" nocase
        $v0 = "14.0.4"
        $v1 = "14.1.3"
        $v2 = "2.3.8"
        $v3 = "2.4.9"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_store_inventory_managemen : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail store inventory management, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_store_inventory_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail store inventory management" nocase
        $p2 = "retail-store-inventory-management" nocase
        $p3 = "retail_store_inventory_management" nocase
        $v0 = "12.0.12"
        $v1 = "13.0.7"
        $v2 = "13.1.9"
        $v3 = "13.2.9"
        $v4 = "14.0.4"
        $v5 = "14.1.3"
        $v6 = "15.0.2"
        $v7 = "16.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_retail_xstore_point_of_service : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail xstore point of service, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "retail_xstore_point_of_service"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "retail xstore point of service" nocase
        $p2 = "retail-xstore-point-of-service" nocase
        $p3 = "retail_xstore_point_of_service" nocase
        $v0 = "15.0.1"
        $v1 = "6.0.11"
        $v2 = "7.0.6"
        $v3 = "7.1.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_transportation_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle transportation management, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "transportation_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "transportation management" nocase
        $p2 = "transportation-management" nocase
        $p3 = "transportation_management" nocase
        $v0 = "6.3.1"
        $v1 = "6.3.2"
        $v2 = "6.3.3"
        $v3 = "6.3.4"
        $v4 = "6.3.5"
        $v5 = "6.3.6"
        $v6 = "6.3.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_tuxedo_system_and_applications_m : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle tuxedo system and applications monitor, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "tuxedo_system_and_applications_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "tuxedo system and applications monitor" nocase
        $p2 = "tuxedo-system-and-applications-monitor" nocase
        $p3 = "tuxedo_system_and_applications_monitor" nocase
        $v0 = "12.1.3.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_webcenter_sites : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle webcenter sites, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "webcenter_sites"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "webcenter sites" nocase
        $p2 = "webcenter-sites" nocase
        $p3 = "webcenter_sites" nocase
        $v0 = "11.1.1.8.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_oracle_workload_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle workload manager, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "oracle"
        product = "workload_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "workload manager" nocase
        $p2 = "workload-manager" nocase
        $p3 = "workload_manager" nocase
        $v0 = "12.2.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_netapp_active_iq_unified_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain netapp active iq unified manager, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "netapp"
        product = "active_iq_unified_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "active iq unified manager" nocase
        $p2 = "active-iq-unified-manager" nocase
        $p3 = "active_iq_unified_manager" nocase
        $v0 = "7.3"
        $v1 = "9.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_redhat_jboss_enterprise_application_pla : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss enterprise application platform, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "redhat"
        product = "jboss_enterprise_application_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "jboss enterprise application platform" nocase
        $p2 = "jboss-enterprise-application-platform" nocase
        $p3 = "jboss_enterprise_application_platform" nocase
        $v0 = "6.0.0"
        $v1 = "6.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12617_redhat_jboss_enterprise_web_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss enterprise web server, affected by CVE-2017-12617"
        severity = "high"
        cve = "CVE-2017-12617"
        cvss = "8.1"
        vendor = "redhat"
        product = "jboss_enterprise_web_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"
    strings:
        $p = "jboss enterprise web server" nocase
        $p2 = "jboss-enterprise-web-server" nocase
        $p3 = "jboss_enterprise_web_server" nocase
        $v0 = "2.0.0"
        $v1 = "3.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_12149_redhat_jboss_enterprise_application_pla : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss enterprise application platform, affected by CVE-2017-12149"
        severity = "high"
        cve = "CVE-2017-12149"
        cvss = "9.8"
        vendor = "redhat"
        product = "jboss_enterprise_application_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-12149"
    strings:
        $p = "jboss enterprise application platform" nocase
        $p2 = "jboss-enterprise-application-platform" nocase
        $p3 = "jboss_enterprise_application_platform" nocase
        $v0 = "5.0.0"
        $v1 = "5.0.1"
        $v2 = "5.1.0"
        $v3 = "5.1.1"
        $v4 = "5.1.2"
        $v5 = "5.2.0"
        $v6 = "5.2.1"
        $v7 = "5.2.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_10271_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2017-10271"
        severity = "high"
        cve = "CVE-2017-10271"
        cvss = "7.5"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-10271"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.1.0"
        $v3 = "12.2.1.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_11292_adobe_flash_player_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player desktop runtime, affected by CVE-2017-11292"
        severity = "high"
        cve = "CVE-2017-11292"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11292"
    strings:
        $p = "flash player desktop runtime" nocase
        $p2 = "flash-player-desktop-runtime" nocase
        $p3 = "flash_player_desktop_runtime" nocase
        $v0 = "27.0.0.159"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_11292_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2017-11292"
        severity = "high"
        cve = "CVE-2017-11292"
        cvss = "8.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11292"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "27.0.0.130"
        $v1 = "27.0.0.159"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_5070_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2017-5070"
        severity = "high"
        cve = "CVE-2017-5070"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-5070"
    strings:
        $p = "chrome" nocase
        $v0 = "59.0.3071.86"
        $v1 = "59.0.3071.92"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_16651_roundcube_webmail : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain roundcube webmail, affected by CVE-2017-16651"
        severity = "high"
        cve = "CVE-2017-16651"
        cvss = "7.8"
        vendor = "roundcube"
        product = "webmail"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-16651"
    strings:
        $p = "webmail" nocase
        $v0 = "1.1.9"
        $v1 = "1.2.0"
        $v2 = "1.2.1"
        $v3 = "1.2.2"
        $v4 = "1.2.3"
        $v5 = "1.2.4"
        $v6 = "1.2.5"
        $v7 = "1.2.6"
        $v8 = "1.3.0"
        $v9 = "1.3.1"
        $v10 = "1.3.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_17562_embedthis_goahead : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain embedthis goahead, affected by CVE-2017-17562"
        severity = "high"
        cve = "CVE-2017-17562"
        cvss = "8.1"
        vendor = "embedthis"
        product = "goahead"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17562"
    strings:
        $p = "goahead" nocase
        $v0 = "3.6.5"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_17562_oracle_integrated_lights_out_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle integrated lights out manager, affected by CVE-2017-17562"
        severity = "high"
        cve = "CVE-2017-17562"
        cvss = "8.1"
        vendor = "oracle"
        product = "integrated_lights_out_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-17562"
    strings:
        $p = "integrated lights out manager" nocase
        $p2 = "integrated-lights-out-manager" nocase
        $p3 = "integrated_lights_out_manager" nocase
        $v0 = "3.0"
        $v1 = "4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_1000486_primetek_primefaces : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain primetek primefaces, affected by CVE-2017-1000486"
        severity = "high"
        cve = "CVE-2017-1000486"
        cvss = "9.8"
        vendor = "primetek"
        product = "primefaces"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-1000486"
    strings:
        $p = "primefaces" nocase
        $v0 = "4.0"
        $v1 = "4.0.24"
        $v2 = "5.0"
        $v3 = "5.2.21"
        $v4 = "5.3"
        $v5 = "5.3.8"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_1000353_jenkins_jenkins : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain jenkins jenkins, affected by CVE-2017-1000353"
        severity = "high"
        cve = "CVE-2017-1000353"
        cvss = "9.8"
        vendor = "jenkins"
        product = "jenkins"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-1000353"
    strings:
        $p = "jenkins" nocase
        $v0 = "2.46.1"
        $v1 = "2.56"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2017_1000353_oracle_communications_cloud_native_core : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications cloud native core automated test suite, affected by CVE-2017-1000353"
        severity = "high"
        cve = "CVE-2017-1000353"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_cloud_native_core_automated_test_suite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-1000353"
    strings:
        $p = "communications cloud native core automated test suite" nocase
        $p2 = "communications-cloud-native-core-automated-test-suite" nocase
        $p3 = "communications_cloud_native_core_automated_test_suite" nocase
        $v0 = "1.9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_4878_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2018-4878"
        severity = "high"
        cve = "CVE-2018-4878"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-4878"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "28.0.0.161"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_2380_sap_customer_relationship_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap customer relationship management, affected by CVE-2018-2380"
        severity = "high"
        cve = "CVE-2018-2380"
        cvss = "6.6"
        vendor = "sap"
        product = "customer_relationship_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-2380"
    strings:
        $p = "customer relationship management" nocase
        $p2 = "customer-relationship-management" nocase
        $p3 = "customer_relationship_management" nocase
        $v0 = "7.01"
        $v1 = "7.02"
        $v2 = "7.30"
        $v3 = "7.31"
        $v4 = "7.33"
        $v5 = "7.54"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_6882_synacor_zimbra_collaboration_suite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain synacor zimbra collaboration suite, affected by CVE-2018-6882"
        severity = "high"
        cve = "CVE-2018-6882"
        cvss = "6.1"
        vendor = "synacor"
        product = "zimbra_collaboration_suite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6882"
    strings:
        $p = "zimbra collaboration suite" nocase
        $p2 = "zimbra-collaboration-suite" nocase
        $p3 = "zimbra_collaboration_suite" nocase
        $v0 = "8.7.0"
        $v1 = "8.8.0"
        $v2 = "8.8.1"
        $v3 = "8.8.2"
        $v4 = "8.8.3"
        $v5 = "8.8.4"
        $v6 = "8.8.5"
        $v7 = "8.8.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_7600_drupal_drupal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain drupal drupal, affected by CVE-2018-7600"
        severity = "high"
        cve = "CVE-2018-7600"
        cvss = "9.8"
        vendor = "drupal"
        product = "drupal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"
    strings:
        $p = "drupal" nocase
        $v0 = "7.57"
        $v1 = "8.0.0"
        $v2 = "8.3.9"
        $v3 = "8.4.0"
        $v4 = "8.4.6"
        $v5 = "8.5.0"
        $v6 = "8.5.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_1273_broadcom_spring_data_commons : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain broadcom spring data commons, affected by CVE-2018-1273"
        severity = "high"
        cve = "CVE-2018-1273"
        cvss = "9.8"
        vendor = "broadcom"
        product = "spring_data_commons"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1273"
    strings:
        $p = "spring data commons" nocase
        $p2 = "spring-data-commons" nocase
        $p3 = "spring_data_commons" nocase
        $v0 = "1.12.10"
        $v1 = "1.13.0"
        $v2 = "1.13.10"
        $v3 = "2.0.0"
        $v4 = "2.0.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_1273_pivotal_software_spring_data_rest : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain pivotal software spring data rest, affected by CVE-2018-1273"
        severity = "high"
        cve = "CVE-2018-1273"
        cvss = "9.8"
        vendor = "pivotal_software"
        product = "spring_data_rest"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1273"
    strings:
        $p = "spring data rest" nocase
        $p2 = "spring-data-rest" nocase
        $p3 = "spring_data_rest" nocase
        $v0 = "3.0.0"
        $v1 = "3.0.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_1273_vmware_spring_data_rest : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware spring data rest, affected by CVE-2018-1273"
        severity = "high"
        cve = "CVE-2018-1273"
        cvss = "9.8"
        vendor = "vmware"
        product = "spring_data_rest"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1273"
    strings:
        $p = "spring data rest" nocase
        $p2 = "spring-data-rest" nocase
        $p3 = "spring_data_rest" nocase
        $v0 = "2.5.10"
        $v1 = "2.6.0"
        $v2 = "2.6.10"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_1273_apache_ignite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache ignite, affected by CVE-2018-1273"
        severity = "high"
        cve = "CVE-2018-1273"
        cvss = "9.8"
        vendor = "apache"
        product = "ignite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1273"
    strings:
        $p = "ignite" nocase
        $v0 = "1.0.0"
        $v1 = "1.0.1"
        $v2 = "2.5.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_1273_oracle_financial_services_crime_and_com : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle financial services crime and compliance management studio, affected by CVE-2018-1273"
        severity = "high"
        cve = "CVE-2018-1273"
        cvss = "9.8"
        vendor = "oracle"
        product = "financial_services_crime_and_compliance_management_studio"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1273"
    strings:
        $p = "financial services crime and compliance management studio" nocase
        $p2 = "financial-services-crime-and-compliance-management-studio" nocase
        $p3 = "financial_services_crime_and_compliance_management_studio" nocase
        $v0 = "8.0.8.2.0"
        $v1 = "8.0.8.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_5430_tibco_jasperreports_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tibco jasperreports server, affected by CVE-2018-5430"
        severity = "high"
        cve = "CVE-2018-5430"
        cvss = "8.8"
        vendor = "tibco"
        product = "jasperreports_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-5430"
    strings:
        $p = "jasperreports server" nocase
        $p2 = "jasperreports-server" nocase
        $p3 = "jasperreports_server" nocase
        $v0 = "6.2.4"
        $v1 = "6.3.0"
        $v2 = "6.3.2"
        $v3 = "6.3.3"
        $v4 = "6.4.0"
        $v5 = "6.4.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_5430_tibco_jaspersoft : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tibco jaspersoft, affected by CVE-2018-5430"
        severity = "high"
        cve = "CVE-2018-5430"
        cvss = "8.8"
        vendor = "tibco"
        product = "jaspersoft"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-5430"
    strings:
        $p = "jaspersoft" nocase
        $v0 = "6.4.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_5430_tibco_jaspersoft_reporting_and_analyti : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tibco jaspersoft reporting and analytics, affected by CVE-2018-5430"
        severity = "high"
        cve = "CVE-2018-5430"
        cvss = "8.8"
        vendor = "tibco"
        product = "jaspersoft_reporting_and_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-5430"
    strings:
        $p = "jaspersoft reporting and analytics" nocase
        $p2 = "jaspersoft-reporting-and-analytics" nocase
        $p3 = "jaspersoft_reporting_and_analytics" nocase
        $v0 = "6.4.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_2628_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2018-2628"
        severity = "high"
        cve = "CVE-2018-2628"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-2628"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.2.0"
        $v3 = "12.2.1.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_4939_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2018-4939"
        severity = "high"
        cve = "CVE-2018-4939"
        cvss = "9.8"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-4939"
    strings:
        $p = "coldfusion" nocase
        $v0 = "11.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_11138_quest_kace_system_management_appliance : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain quest kace system management appliance, affected by CVE-2018-11138"
        severity = "high"
        cve = "CVE-2018-11138"
        cvss = "9.8"
        vendor = "quest"
        product = "kace_system_management_appliance"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11138"
    strings:
        $p = "kace system management appliance" nocase
        $p2 = "kace-system-management-appliance" nocase
        $p3 = "kace_system_management_appliance" nocase
        $v0 = "8.0.318"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_0296_cisco_firepower_threat_defense : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cisco firepower threat defense, affected by CVE-2018-0296"
        severity = "high"
        cve = "CVE-2018-0296"
        cvss = "7.5"
        vendor = "cisco"
        product = "firepower_threat_defense"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-0296"
    strings:
        $p = "firepower threat defense" nocase
        $p2 = "firepower-threat-defense" nocase
        $p3 = "firepower_threat_defense" nocase
        $v0 = "6.2.3-851"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_0296_cisco_secure_firewall_threat_defense : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cisco secure firewall threat defense, affected by CVE-2018-0296"
        severity = "high"
        cve = "CVE-2018-0296"
        cvss = "7.5"
        vendor = "cisco"
        product = "secure_firewall_threat_defense"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-0296"
    strings:
        $p = "secure firewall threat defense" nocase
        $p2 = "secure-firewall-threat-defense" nocase
        $p3 = "secure_firewall_threat_defense" nocase
        $v0 = "6.0"
        $v1 = "6.1.0"
        $v2 = "6.2.1"
        $v3 = "6.2.2.3"
        $v4 = "6.2.3"
        $v5 = "6.2.3.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_9079_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2016-9079"
        severity = "high"
        cve = "CVE-2016-9079"
        cvss = "7.5"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-9079"
    strings:
        $p = "thunderbird" nocase
        $v0 = "45.5.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2016_9079_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2016-9079"
        severity = "high"
        cve = "CVE-2016-9079"
        cvss = "7.5"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2016-9079"
    strings:
        $p = "firefox" nocase
        $v0 = "45.5.1"
        $v1 = "50.0.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_6961_vmware_nsx_sd_wan_by_velocloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware nsx sd-wan by velocloud, affected by CVE-2018-6961"
        severity = "high"
        cve = "CVE-2018-6961"
        cvss = "8.1"
        vendor = "vmware"
        product = "nsx_sd-wan_by_velocloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6961"
    strings:
        $p = "nsx sd-wan by velocloud" nocase
        $p2 = "nsx-sd-wan-by-velocloud" nocase
        $p3 = "nsx_sd-wan_by_velocloud" nocase
        $v0 = "3.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_9276_paessler_prtg_network_monitor : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain paessler prtg network monitor, affected by CVE-2018-9276"
        severity = "high"
        cve = "CVE-2018-9276"
        cvss = "7.2"
        vendor = "paessler"
        product = "prtg_network_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-9276"
    strings:
        $p = "prtg network monitor" nocase
        $p2 = "prtg-network-monitor" nocase
        $p3 = "prtg_network_monitor" nocase
        $v0 = "18.2.39"
        $v1 = "19.3.52"
        $v2 = "21.2.68"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_4990_adobe_acrobat_dc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat dc, affected by CVE-2018-4990"
        severity = "high"
        cve = "CVE-2018-4990"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_dc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-4990"
    strings:
        $p = "acrobat dc" nocase
        $p2 = "acrobat-dc" nocase
        $p3 = "acrobat_dc" nocase
        $v0 = "15.006.30060"
        $v1 = "15.006.30417"
        $v2 = "15.008.20082"
        $v3 = "17.011.30059"
        $v4 = "17.011.30079"
        $v5 = "18.011.20038"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_4990_adobe_acrobat_reader_dc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader dc, affected by CVE-2018-4990"
        severity = "high"
        cve = "CVE-2018-4990"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader_dc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-4990"
    strings:
        $p = "acrobat reader dc" nocase
        $p2 = "acrobat-reader-dc" nocase
        $p3 = "acrobat_reader_dc" nocase
        $v0 = "15.006.30060"
        $v1 = "15.006.30417"
        $v2 = "15.008.20082"
        $v3 = "17.011.30059"
        $v4 = "17.011.30079"
        $v5 = "18.011.20038"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_5002_adobe_flash_player_desktop_runtime : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player desktop runtime, affected by CVE-2018-5002"
        severity = "high"
        cve = "CVE-2018-5002"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player_desktop_runtime"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-5002"
    strings:
        $p = "flash player desktop runtime" nocase
        $p2 = "flash-player-desktop-runtime" nocase
        $p3 = "flash_player_desktop_runtime" nocase
        $v0 = "29.0.0.171"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_5002_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2018-5002"
        severity = "high"
        cve = "CVE-2018-5002"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-5002"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "29.0.0.171"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_8298_microsoft_chakracore : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft chakracore, affected by CVE-2018-8298"
        severity = "high"
        cve = "CVE-2018-8298"
        cvss = "7.5"
        vendor = "microsoft"
        product = "chakracore"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-8298"
    strings:
        $p = "chakracore" nocase
        $v0 = "1.10.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_7602_drupal_drupal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain drupal drupal, affected by CVE-2018-7602"
        severity = "high"
        cve = "CVE-2018-7602"
        cvss = "9.8"
        vendor = "drupal"
        product = "drupal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7602"
    strings:
        $p = "drupal" nocase
        $v0 = "7.0"
        $v1 = "7.59"
        $v2 = "8.4.0"
        $v3 = "8.4.8"
        $v4 = "8.5.0"
        $v5 = "8.5.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_15133_laravel_laravel : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain laravel laravel, affected by CVE-2018-15133"
        severity = "high"
        cve = "CVE-2018-15133"
        cvss = "8.1"
        vendor = "laravel"
        product = "laravel"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15133"
    strings:
        $p = "laravel" nocase
        $v0 = "5.5.40"
        $v1 = "5.6.0"
        $v2 = "5.6.29"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_11776_apache_struts : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache struts, affected by CVE-2018-11776"
        severity = "high"
        cve = "CVE-2018-11776"
        cvss = "8.1"
        vendor = "apache"
        product = "struts"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11776"
    strings:
        $p = "struts" nocase
        $v0 = "2.0.4"
        $v1 = "2.3.35"
        $v2 = "2.5.0"
        $v3 = "2.5.17"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_11776_netapp_active_iq_unified_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain netapp active iq unified manager, affected by CVE-2018-11776"
        severity = "high"
        cve = "CVE-2018-11776"
        cvss = "8.1"
        vendor = "netapp"
        product = "active_iq_unified_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11776"
    strings:
        $p = "active iq unified manager" nocase
        $p2 = "active-iq-unified-manager" nocase
        $p3 = "active_iq_unified_manager" nocase
        $v0 = "7.3"
        $v1 = "9.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_11776_oracle_communications_policy_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications policy management, affected by CVE-2018-11776"
        severity = "high"
        cve = "CVE-2018-11776"
        cvss = "8.1"
        vendor = "oracle"
        product = "communications_policy_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11776"
    strings:
        $p = "communications policy management" nocase
        $p2 = "communications-policy-management" nocase
        $p3 = "communications_policy_management" nocase
        $v0 = "12.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_11776_oracle_enterprise_manager_base_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle enterprise manager base platform, affected by CVE-2018-11776"
        severity = "high"
        cve = "CVE-2018-11776"
        cvss = "8.1"
        vendor = "oracle"
        product = "enterprise_manager_base_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11776"
    strings:
        $p = "enterprise manager base platform" nocase
        $p2 = "enterprise-manager-base-platform" nocase
        $p3 = "enterprise_manager_base_platform" nocase
        $v0 = "13.3.0.0"
        $v1 = "13.4.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_11776_oracle_mysql_enterprise_monitor : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle mysql enterprise monitor, affected by CVE-2018-11776"
        severity = "high"
        cve = "CVE-2018-11776"
        cvss = "8.1"
        vendor = "oracle"
        product = "mysql_enterprise_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-11776"
    strings:
        $p = "mysql enterprise monitor" nocase
        $p2 = "mysql-enterprise-monitor" nocase
        $p3 = "mysql_enterprise_monitor" nocase
        $v0 = "3.4.9.4237"
        $v1 = "4.0.0"
        $v2 = "4.0.6.5281"
        $v3 = "8.0.0"
        $v4 = "8.0.2.8191"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_15961_adobe_coldfusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe coldfusion, affected by CVE-2018-15961"
        severity = "high"
        cve = "CVE-2018-15961"
        cvss = "9.8"
        vendor = "adobe"
        product = "coldfusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15961"
    strings:
        $p = "coldfusion" nocase
        $v0 = "11.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_access_policy_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip access policy manager, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_access_policy_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip access policy manager" nocase
        $p2 = "big-ip-access-policy-manager" nocase
        $p3 = "big-ip_access_policy_manager" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_advanced_firewall_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced firewall manager, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_advanced_firewall_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip advanced firewall manager" nocase
        $p2 = "big-ip-advanced-firewall-manager" nocase
        $p3 = "big-ip_advanced_firewall_manager" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip analytics, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip analytics" nocase
        $p2 = "big-ip-analytics" nocase
        $p3 = "big-ip_analytics" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_application_acceleration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application acceleration manager, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_application_acceleration_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip application acceleration manager" nocase
        $p2 = "big-ip-application-acceleration-manager" nocase
        $p3 = "big-ip_application_acceleration_manager" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_application_security_mana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application security manager, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_application_security_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip application security manager" nocase
        $p2 = "big-ip-application-security-manager" nocase
        $p3 = "big-ip_application_security_manager" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_domain_name_system : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip domain name system, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_domain_name_system"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip domain name system" nocase
        $p2 = "big-ip-domain-name-system" nocase
        $p3 = "big-ip_domain_name_system" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_edge_gateway : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip edge gateway, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_edge_gateway"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip edge gateway" nocase
        $p2 = "big-ip-edge-gateway" nocase
        $p3 = "big-ip_edge_gateway" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_fraud_protection_service : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip fraud protection service, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_fraud_protection_service"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip fraud protection service" nocase
        $p2 = "big-ip-fraud-protection-service" nocase
        $p3 = "big-ip_fraud_protection_service" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_global_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip global traffic manager, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_global_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip global traffic manager" nocase
        $p2 = "big-ip-global-traffic-manager" nocase
        $p3 = "big-ip_global_traffic_manager" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_link_controller : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip link controller, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_link_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip link controller" nocase
        $p2 = "big-ip-link-controller" nocase
        $p3 = "big-ip_link_controller" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_local_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip local traffic manager, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_local_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip local traffic manager" nocase
        $p2 = "big-ip-local-traffic-manager" nocase
        $p3 = "big-ip_local_traffic_manager" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_policy_enforcement_manage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip policy enforcement manager, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_policy_enforcement_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip policy enforcement manager" nocase
        $p2 = "big-ip-policy-enforcement-manager" nocase
        $p3 = "big-ip_policy_enforcement_manager" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_ip_webaccelerator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip webaccelerator, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-ip_webaccelerator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-ip webaccelerator" nocase
        $p2 = "big-ip-webaccelerator" nocase
        $p3 = "big-ip_webaccelerator" nocase
        $v0 = "11.2.1"
        $v1 = "11.6.4"
        $v2 = "12.1.0"
        $v3 = "12.1.5"
        $v4 = "13.0.0"
        $v5 = "13.1.1.5"
        $v6 = "14.0.0"
        $v7 = "14.0.1.1"
        $v8 = "14.1.0"
        $v9 = "14.1.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_iq_centralized_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq centralized management, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-iq_centralized_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-iq centralized management" nocase
        $p2 = "big-iq-centralized-management" nocase
        $p3 = "big-iq_centralized_management" nocase
        $v0 = "4.6.0"
        $v1 = "5.0.0"
        $v2 = "5.4.0"
        $v3 = "6.0.0"
        $v4 = "6.0.1"
        $v5 = "7.0.0"
        $v6 = "7.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_big_iq_cloud_and_orchestration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq cloud and orchestration, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "big-iq_cloud_and_orchestration"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "big-iq cloud and orchestration" nocase
        $p2 = "big-iq-cloud-and-orchestration" nocase
        $p3 = "big-iq_cloud_and_orchestration" nocase
        $v0 = "1.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_enterprise_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 enterprise manager, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "enterprise_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "enterprise manager" nocase
        $p2 = "enterprise-manager" nocase
        $p3 = "enterprise_manager" nocase
        $v0 = "3.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_iworkflow : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 iworkflow, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "iworkflow"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "iworkflow" nocase
        $v0 = "2.2.0"
        $v1 = "2.3.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14634_f5_traffix_signaling_delivery_contr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 traffix signaling delivery controller, affected by CVE-2018-14634"
        severity = "high"
        cve = "CVE-2018-14634"
        cvss = "7.8"
        vendor = "f5"
        product = "traffix_signaling_delivery_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14634"
    strings:
        $p = "traffix signaling delivery controller" nocase
        $p2 = "traffix-signaling-delivery-controller" nocase
        $p3 = "traffix_signaling_delivery_controller" nocase
        $v0 = "4.4.0"
        $v1 = "5.0.0"
        $v2 = "5.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_14667_redhat_richfaces : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat richfaces, affected by CVE-2018-14667"
        severity = "high"
        cve = "CVE-2018-14667"
        cvss = "9.8"
        vendor = "redhat"
        product = "richfaces"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-14667"
    strings:
        $p = "richfaces" nocase
        $v0 = "3.1.0"
        $v1 = "3.3.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_17463_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2018-17463"
        severity = "high"
        cve = "CVE-2018-17463"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17463"
    strings:
        $p = "chrome" nocase
        $v0 = "70.0.3538.67"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_6065_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2018-6065"
        severity = "high"
        cve = "CVE-2018-6065"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-6065"
    strings:
        $p = "chrome" nocase
        $v0 = "65.0.3325.146"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19410_paessler_prtg_network_monitor : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain paessler prtg network monitor, affected by CVE-2018-19410"
        severity = "high"
        cve = "CVE-2018-19410"
        cvss = "9.8"
        vendor = "paessler"
        product = "prtg_network_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19410"
    strings:
        $p = "prtg network monitor" nocase
        $p2 = "prtg-network-monitor" nocase
        $p3 = "prtg_network_monitor" nocase
        $v0 = "18.2.40.1683"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_1000861_jenkins_jenkins : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain jenkins jenkins, affected by CVE-2018-1000861"
        severity = "high"
        cve = "CVE-2018-1000861"
        cvss = "9.8"
        vendor = "jenkins"
        product = "jenkins"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1000861"
    strings:
        $p = "jenkins" nocase
        $v0 = "2.138.3"
        $v1 = "2.153"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_1000861_redhat_openshift_container_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat openshift container platform, affected by CVE-2018-1000861"
        severity = "high"
        cve = "CVE-2018-1000861"
        cvss = "9.8"
        vendor = "redhat"
        product = "openshift_container_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-1000861"
    strings:
        $p = "openshift container platform" nocase
        $p2 = "openshift-container-platform" nocase
        $p3 = "openshift_container_platform" nocase
        $v0 = "3.11"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_17480_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2018-17480"
        severity = "high"
        cve = "CVE-2018-17480"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-17480"
    strings:
        $p = "chrome" nocase
        $v0 = "71.0.3578.80"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_20062_5none_nonecms : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain 5none nonecms, affected by CVE-2018-20062"
        severity = "high"
        cve = "CVE-2018-20062"
        cvss = "9.8"
        vendor = "5none"
        product = "nonecms"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20062"
    strings:
        $p = "nonecms" nocase
        $v0 = "1.3.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19320_gigabyte_aorus_graphics_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte aorus graphics engine, affected by CVE-2018-19320"
        severity = "high"
        cve = "CVE-2018-19320"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "aorus_graphics_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19320"
    strings:
        $p = "aorus graphics engine" nocase
        $p2 = "aorus-graphics-engine" nocase
        $p3 = "aorus_graphics_engine" nocase
        $v0 = "1.57"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19320_gigabyte_app_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte app center, affected by CVE-2018-19320"
        severity = "high"
        cve = "CVE-2018-19320"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "app_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19320"
    strings:
        $p = "app center" nocase
        $p2 = "app-center" nocase
        $p3 = "app_center" nocase
        $v0 = "19.0422.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19320_gigabyte_oc_guru_ii : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte oc guru ii, affected by CVE-2018-19320"
        severity = "high"
        cve = "CVE-2018-19320"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "oc_guru_ii"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19320"
    strings:
        $p = "oc guru ii" nocase
        $p2 = "oc-guru-ii" nocase
        $p3 = "oc_guru_ii" nocase
        $v0 = "2.08"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19320_gigabyte_xtreme_gaming_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte xtreme gaming engine, affected by CVE-2018-19320"
        severity = "high"
        cve = "CVE-2018-19320"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "xtreme_gaming_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19320"
    strings:
        $p = "xtreme gaming engine" nocase
        $p2 = "xtreme-gaming-engine" nocase
        $p3 = "xtreme_gaming_engine" nocase
        $v0 = "1.26"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19321_gigabyte_aorus_graphics_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte aorus graphics engine, affected by CVE-2018-19321"
        severity = "high"
        cve = "CVE-2018-19321"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "aorus_graphics_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19321"
    strings:
        $p = "aorus graphics engine" nocase
        $p2 = "aorus-graphics-engine" nocase
        $p3 = "aorus_graphics_engine" nocase
        $v0 = "1.57"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19321_gigabyte_app_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte app center, affected by CVE-2018-19321"
        severity = "high"
        cve = "CVE-2018-19321"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "app_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19321"
    strings:
        $p = "app center" nocase
        $p2 = "app-center" nocase
        $p3 = "app_center" nocase
        $v0 = "19.0422.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19321_gigabyte_oc_guru_ii : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte oc guru ii, affected by CVE-2018-19321"
        severity = "high"
        cve = "CVE-2018-19321"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "oc_guru_ii"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19321"
    strings:
        $p = "oc guru ii" nocase
        $p2 = "oc-guru-ii" nocase
        $p3 = "oc_guru_ii" nocase
        $v0 = "2.08"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19321_gigabyte_xtreme_gaming_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte xtreme gaming engine, affected by CVE-2018-19321"
        severity = "high"
        cve = "CVE-2018-19321"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "xtreme_gaming_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19321"
    strings:
        $p = "xtreme gaming engine" nocase
        $p2 = "xtreme-gaming-engine" nocase
        $p3 = "xtreme_gaming_engine" nocase
        $v0 = "1.26"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19322_gigabyte_aorus_graphics_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte aorus graphics engine, affected by CVE-2018-19322"
        severity = "high"
        cve = "CVE-2018-19322"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "aorus_graphics_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19322"
    strings:
        $p = "aorus graphics engine" nocase
        $p2 = "aorus-graphics-engine" nocase
        $p3 = "aorus_graphics_engine" nocase
        $v0 = "1.57"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19322_gigabyte_app_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte app center, affected by CVE-2018-19322"
        severity = "high"
        cve = "CVE-2018-19322"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "app_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19322"
    strings:
        $p = "app center" nocase
        $p2 = "app-center" nocase
        $p3 = "app_center" nocase
        $v0 = "1.05.21"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19322_gigabyte_oc_guru_ii : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte oc guru ii, affected by CVE-2018-19322"
        severity = "high"
        cve = "CVE-2018-19322"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "oc_guru_ii"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19322"
    strings:
        $p = "oc guru ii" nocase
        $p2 = "oc-guru-ii" nocase
        $p3 = "oc_guru_ii" nocase
        $v0 = "2.08"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19322_gigabyte_xtreme_gaming_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte xtreme gaming engine, affected by CVE-2018-19322"
        severity = "high"
        cve = "CVE-2018-19322"
        cvss = "7.8"
        vendor = "gigabyte"
        product = "xtreme_gaming_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19322"
    strings:
        $p = "xtreme gaming engine" nocase
        $p2 = "xtreme-gaming-engine" nocase
        $p3 = "xtreme_gaming_engine" nocase
        $v0 = "1.26"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19323_gigabyte_aorus_graphics_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte aorus graphics engine, affected by CVE-2018-19323"
        severity = "high"
        cve = "CVE-2018-19323"
        cvss = "9.8"
        vendor = "gigabyte"
        product = "aorus_graphics_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19323"
    strings:
        $p = "aorus graphics engine" nocase
        $p2 = "aorus-graphics-engine" nocase
        $p3 = "aorus_graphics_engine" nocase
        $v0 = "1.57"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19323_gigabyte_gigabyte_app_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte gigabyte app center, affected by CVE-2018-19323"
        severity = "high"
        cve = "CVE-2018-19323"
        cvss = "9.8"
        vendor = "gigabyte"
        product = "gigabyte_app_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19323"
    strings:
        $p = "gigabyte app center" nocase
        $p2 = "gigabyte-app-center" nocase
        $p3 = "gigabyte_app_center" nocase
        $v0 = "1.05.21"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19323_gigabyte_oc_guru_ii : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte oc guru ii, affected by CVE-2018-19323"
        severity = "high"
        cve = "CVE-2018-19323"
        cvss = "9.8"
        vendor = "gigabyte"
        product = "oc_guru_ii"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19323"
    strings:
        $p = "oc guru ii" nocase
        $p2 = "oc-guru-ii" nocase
        $p3 = "oc_guru_ii" nocase
        $v0 = "2.08"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_19323_gigabyte_xtreme_gaming_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gigabyte xtreme gaming engine, affected by CVE-2018-19323"
        severity = "high"
        cve = "CVE-2018-19323"
        cvss = "9.8"
        vendor = "gigabyte"
        product = "xtreme_gaming_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-19323"
    strings:
        $p = "xtreme gaming engine" nocase
        $p2 = "xtreme-gaming-engine" nocase
        $p3 = "xtreme_gaming_engine" nocase
        $v0 = "1.26"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_15982_adobe_flash_player : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player, affected by CVE-2018-15982"
        severity = "high"
        cve = "CVE-2018-15982"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15982"
    strings:
        $p = "flash player" nocase
        $p2 = "flash-player" nocase
        $p3 = "flash_player" nocase
        $v0 = "31.0.0.153"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_15982_adobe_flash_player_installer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe flash player installer, affected by CVE-2018-15982"
        severity = "high"
        cve = "CVE-2018-15982"
        cvss = "7.8"
        vendor = "adobe"
        product = "flash_player_installer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15982"
    strings:
        $p = "flash player installer" nocase
        $p2 = "flash-player-installer" nocase
        $p3 = "flash_player_installer" nocase
        $v0 = "31.0.0.108"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_13374_fortinet_fortiadc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain fortinet fortiadc, affected by CVE-2018-13374"
        severity = "high"
        cve = "CVE-2018-13374"
        cvss = "4.3"
        vendor = "fortinet"
        product = "fortiadc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-13374"
    strings:
        $p = "fortiadc" nocase
        $v0 = "5.4.0"
        $v1 = "5.4.5"
        $v2 = "6.0.0"
        $v3 = "6.0.2"
        $v4 = "6.1.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_20753_kaseya_virtual_system_administrator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain kaseya virtual system administrator, affected by CVE-2018-20753"
        severity = "high"
        cve = "CVE-2018-20753"
        cvss = "9.8"
        vendor = "kaseya"
        product = "virtual_system_administrator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20753"
    strings:
        $p = "virtual system administrator" nocase
        $p2 = "virtual-system-administrator" nocase
        $p3 = "virtual_system_administrator" nocase
        $v0 = "9.3"
        $v1 = "9.3.0.35"
        $v2 = "9.4"
        $v3 = "9.4.0.36"
        $v4 = "9.5"
        $v5 = "9.5.0.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_20250_rarlab_winrar : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain rarlab winrar, affected by CVE-2018-20250"
        severity = "high"
        cve = "CVE-2018-20250"
        cvss = "7.8"
        vendor = "rarlab"
        product = "winrar"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-20250"
    strings:
        $p = "winrar" nocase
        $v0 = "5.61"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_8394_zohocorp_manageengine_servicedesk_plus : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain zohocorp manageengine servicedesk plus, affected by CVE-2019-8394"
        severity = "high"
        cve = "CVE-2019-8394"
        cvss = "6.5"
        vendor = "zohocorp"
        product = "manageengine_servicedesk_plus"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8394"
    strings:
        $p = "manageengine servicedesk plus" nocase
        $p2 = "manageengine-servicedesk-plus" nocase
        $p3 = "manageengine_servicedesk_plus" nocase
        $v0 = "10.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_6340_drupal_drupal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain drupal drupal, affected by CVE-2019-6340"
        severity = "high"
        cve = "CVE-2019-6340"
        cvss = "8.1"
        vendor = "drupal"
        product = "drupal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-6340"
    strings:
        $p = "drupal" nocase
        $v0 = "8.5.0"
        $v1 = "8.5.11"
        $v2 = "8.6.0"
        $v3 = "8.6.10"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_9082_thinkphp_thinkphp : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain thinkphp thinkphp, affected by CVE-2019-9082"
        severity = "high"
        cve = "CVE-2019-9082"
        cvss = "8.8"
        vendor = "thinkphp"
        product = "thinkphp"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9082"
    strings:
        $p = "thinkphp" nocase
        $v0 = "3.2.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_9082_opensourcebms_open_source_background_managemen : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain opensourcebms open source background management system, affected by CVE-2019-9082"
        severity = "high"
        cve = "CVE-2019-9082"
        cvss = "8.8"
        vendor = "opensourcebms"
        product = "open_source_background_management_system"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9082"
    strings:
        $p = "open source background management system" nocase
        $p2 = "open-source-background-management-system" nocase
        $p3 = "open_source_background_management_system" nocase
        $v0 = "1.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_9082_zzzcms_zzzphp : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain zzzcms zzzphp, affected by CVE-2019-9082"
        severity = "high"
        cve = "CVE-2019-9082"
        cvss = "8.8"
        vendor = "zzzcms"
        product = "zzzphp"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9082"
    strings:
        $p = "zzzphp" nocase
        $v0 = "1.6.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_18809_tibco_jasperreports_library : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tibco jasperreports library, affected by CVE-2018-18809"
        severity = "high"
        cve = "CVE-2018-18809"
        cvss = "6.5"
        vendor = "tibco"
        product = "jasperreports_library"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18809"
    strings:
        $p = "jasperreports library" nocase
        $p2 = "jasperreports-library" nocase
        $p3 = "jasperreports_library" nocase
        $v0 = "6.4.21"
        $v1 = "6.7.0"
        $v2 = "7.1.0"
        $v3 = "7.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_18809_tibco_jasperreports_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tibco jasperreports server, affected by CVE-2018-18809"
        severity = "high"
        cve = "CVE-2018-18809"
        cvss = "6.5"
        vendor = "tibco"
        product = "jasperreports_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18809"
    strings:
        $p = "jasperreports server" nocase
        $p2 = "jasperreports-server" nocase
        $p3 = "jasperreports_server" nocase
        $v0 = "6.4.3"
        $v1 = "7.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_18809_tibco_jaspersoft : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tibco jaspersoft, affected by CVE-2018-18809"
        severity = "high"
        cve = "CVE-2018-18809"
        cvss = "6.5"
        vendor = "tibco"
        product = "jaspersoft"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18809"
    strings:
        $p = "jaspersoft" nocase
        $v0 = "7.1.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_18809_tibco_jaspersoft_reporting_and_analyti : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tibco jaspersoft reporting and analytics, affected by CVE-2018-18809"
        severity = "high"
        cve = "CVE-2018-18809"
        cvss = "6.5"
        vendor = "tibco"
        product = "jaspersoft_reporting_and_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18809"
    strings:
        $p = "jaspersoft reporting and analytics" nocase
        $p2 = "jaspersoft-reporting-and-analytics" nocase
        $p3 = "jaspersoft_reporting_and_analytics" nocase
        $v0 = "7.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_1003029_jenkins_script_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain jenkins script security, affected by CVE-2019-1003029"
        severity = "high"
        cve = "CVE-2019-1003029"
        cvss = "9.9"
        vendor = "jenkins"
        product = "script_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1003029"
    strings:
        $p = "script security" nocase
        $p2 = "script-security" nocase
        $p3 = "script_security" nocase
        $v0 = "1.53"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_1003029_redhat_openshift_container_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat openshift container platform, affected by CVE-2019-1003029"
        severity = "high"
        cve = "CVE-2019-1003029"
        cvss = "9.9"
        vendor = "redhat"
        product = "openshift_container_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1003029"
    strings:
        $p = "openshift container platform" nocase
        $p2 = "openshift-container-platform" nocase
        $p3 = "openshift_container_platform" nocase
        $v0 = "3.11"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_1003030_redhat_openshift_container_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat openshift container platform, affected by CVE-2019-1003030"
        severity = "high"
        cve = "CVE-2019-1003030"
        cvss = "9.9"
        vendor = "redhat"
        product = "openshift_container_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1003030"
    strings:
        $p = "openshift container platform" nocase
        $p2 = "openshift-container-platform" nocase
        $p3 = "openshift_container_platform" nocase
        $v0 = "3.11"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_7238_sonatype_nexus_repository_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonatype nexus repository manager, affected by CVE-2019-7238"
        severity = "high"
        cve = "CVE-2019-7238"
        cvss = "9.8"
        vendor = "sonatype"
        product = "nexus_repository_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7238"
    strings:
        $p = "nexus repository manager" nocase
        $p2 = "nexus-repository-manager" nocase
        $p3 = "nexus_repository_manager" nocase
        $v0 = "3.0.0"
        $v1 = "3.15.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_9978_warfareplugins_social_warfare : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain warfareplugins social warfare, affected by CVE-2019-9978"
        severity = "high"
        cve = "CVE-2019-9978"
        cvss = "6.1"
        vendor = "warfareplugins"
        product = "social_warfare"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9978"
    strings:
        $p = "social warfare" nocase
        $p2 = "social-warfare" nocase
        $p3 = "social_warfare" nocase
        $v0 = "3.5.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_9978_warfareplugins_social_warfare_pro : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain warfareplugins social warfare pro, affected by CVE-2019-9978"
        severity = "high"
        cve = "CVE-2019-9978"
        cvss = "6.1"
        vendor = "warfareplugins"
        product = "social_warfare_pro"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9978"
    strings:
        $p = "social warfare pro" nocase
        $p2 = "social-warfare-pro" nocase
        $p3 = "social_warfare_pro" nocase
        $v0 = "3.5.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_3396_atlassian_confluence_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian confluence server, affected by CVE-2019-3396"
        severity = "high"
        cve = "CVE-2019-3396"
        cvss = "9.8"
        vendor = "atlassian"
        product = "confluence_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3396"
    strings:
        $p = "confluence server" nocase
        $p2 = "confluence-server" nocase
        $p3 = "confluence_server" nocase
        $v0 = "6.12.3"
        $v1 = "6.13.0"
        $v2 = "6.13.3"
        $v3 = "6.14.0"
        $v4 = "6.14.2"
        $v5 = "6.6.12"
        $v6 = "6.7.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_7609_elastic_kibana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain elastic kibana, affected by CVE-2019-7609"
        severity = "high"
        cve = "CVE-2019-7609"
        cvss = "10.0"
        vendor = "elastic"
        product = "kibana"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7609"
    strings:
        $p = "kibana" nocase
        $v0 = "5.6.15"
        $v1 = "6.0.0"
        $v2 = "6.6.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_7609_redhat_openshift_container_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat openshift container platform, affected by CVE-2019-7609"
        severity = "high"
        cve = "CVE-2019-7609"
        cvss = "10.0"
        vendor = "redhat"
        product = "openshift_container_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7609"
    strings:
        $p = "openshift container platform" nocase
        $p2 = "openshift-container-platform" nocase
        $p3 = "openshift_container_platform" nocase
        $v0 = "3.11"
        $v1 = "4.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_10068_kentico_xperience : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain kentico xperience, affected by CVE-2019-10068"
        severity = "high"
        cve = "CVE-2019-10068"
        cvss = "9.8"
        vendor = "kentico"
        product = "xperience"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-10068"
    strings:
        $p = "xperience" nocase
        $v0 = "10.0.0"
        $v1 = "10.0.52"
        $v2 = "11.0.0"
        $v3 = "11.0.48"
        $v4 = "12.0.0"
        $v5 = "12.0.15"
        $v6 = "9.0.0"
        $v7 = "9.0.51"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_5418_rubyonrails_rails : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain rubyonrails rails, affected by CVE-2019-5418"
        severity = "high"
        cve = "CVE-2019-5418"
        cvss = "7.5"
        vendor = "rubyonrails"
        product = "rails"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5418"
    strings:
        $p = "rails" nocase
        $v0 = "3.0.0"
        $v1 = "4.2.11.1"
        $v2 = "5.0.0"
        $v3 = "5.0.7.2"
        $v4 = "5.1.0"
        $v5 = "5.1.6.2"
        $v6 = "5.2.0"
        $v7 = "5.2.2.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_5418_redhat_cloudforms : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat cloudforms, affected by CVE-2019-5418"
        severity = "high"
        cve = "CVE-2019-5418"
        cvss = "7.5"
        vendor = "redhat"
        product = "cloudforms"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5418"
    strings:
        $p = "cloudforms" nocase
        $v0 = "4.6"
        $v1 = "4.7"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_5418_redhat_software_collections : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat software collections, affected by CVE-2019-5418"
        severity = "high"
        cve = "CVE-2019-5418"
        cvss = "7.5"
        vendor = "redhat"
        product = "software_collections"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5418"
    strings:
        $p = "software collections" nocase
        $p2 = "software-collections" nocase
        $p3 = "software_collections" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_apache_http_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache http server, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "apache"
        product = "http_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "http server" nocase
        $p2 = "http-server" nocase
        $p3 = "http_server" nocase
        $v0 = "2.4.17"
        $v1 = "2.4.38"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_redhat_jboss_core_services : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss core services, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "redhat"
        product = "jboss_core_services"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "jboss core services" nocase
        $p2 = "jboss-core-services" nocase
        $p3 = "jboss_core_services" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_redhat_openshift_container_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat openshift container platform, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "redhat"
        product = "openshift_container_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "openshift container platform" nocase
        $p2 = "openshift-container-platform" nocase
        $p3 = "openshift_container_platform" nocase
        $v0 = "3.11"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_redhat_openshift_container_platform_for : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat openshift container platform for power, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "redhat"
        product = "openshift_container_platform_for_power"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "openshift container platform for power" nocase
        $p2 = "openshift-container-platform-for-power" nocase
        $p3 = "openshift_container_platform_for_power" nocase
        $v0 = "3.11_ppc64le"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_redhat_software_collections : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat software collections, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "redhat"
        product = "software_collections"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "software collections" nocase
        $p2 = "software-collections" nocase
        $p3 = "software_collections" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_oracle_communications_session_report_ma : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications session report manager, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "oracle"
        product = "communications_session_report_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "communications session report manager" nocase
        $p2 = "communications-session-report-manager" nocase
        $p3 = "communications_session_report_manager" nocase
        $v0 = "8.0.0"
        $v1 = "8.1.0"
        $v2 = "8.1.1"
        $v3 = "8.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_oracle_communications_session_route_man : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications session route manager, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "oracle"
        product = "communications_session_route_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "communications session route manager" nocase
        $p2 = "communications-session-route-manager" nocase
        $p3 = "communications_session_route_manager" nocase
        $v0 = "8.0.0"
        $v1 = "8.1.0"
        $v2 = "8.1.1"
        $v3 = "8.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_oracle_enterprise_manager_ops_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle enterprise manager ops center, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "oracle"
        product = "enterprise_manager_ops_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "enterprise manager ops center" nocase
        $p2 = "enterprise-manager-ops-center" nocase
        $p3 = "enterprise_manager_ops_center" nocase
        $v0 = "12.3.3"
        $v1 = "12.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_oracle_http_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle http server, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "oracle"
        product = "http_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "http server" nocase
        $p2 = "http-server" nocase
        $p3 = "http_server" nocase
        $v0 = "12.2.1.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_oracle_instantis_enterprisetrack : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle instantis enterprisetrack, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "oracle"
        product = "instantis_enterprisetrack"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "instantis enterprisetrack" nocase
        $p2 = "instantis-enterprisetrack" nocase
        $p3 = "instantis_enterprisetrack" nocase
        $v0 = "17.1"
        $v1 = "17.2"
        $v2 = "17.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0211_oracle_retail_xstore_point_of_service : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail xstore point of service, affected by CVE-2019-0211"
        severity = "high"
        cve = "CVE-2019-0211"
        cvss = "7.8"
        vendor = "oracle"
        product = "retail_xstore_point_of_service"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0211"
    strings:
        $p = "retail xstore point of service" nocase
        $p2 = "retail-xstore-point-of-service" nocase
        $p3 = "retail_xstore_point_of_service" nocase
        $v0 = "7.0"
        $v1 = "7.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_3398_atlassian_confluence_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian confluence server, affected by CVE-2019-3398"
        severity = "high"
        cve = "CVE-2019-3398"
        cvss = "8.8"
        vendor = "atlassian"
        product = "confluence_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3398"
    strings:
        $p = "confluence server" nocase
        $p2 = "confluence-server" nocase
        $p3 = "confluence_server" nocase
        $v0 = "2.0"
        $v1 = "6.12.4"
        $v2 = "6.13.0"
        $v3 = "6.13.4"
        $v4 = "6.14.0"
        $v5 = "6.14.3"
        $v6 = "6.15.0"
        $v7 = "6.15.2"
        $v8 = "6.6.13"
        $v9 = "6.7.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2616_oracle_business_intelligence_publisher : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle business intelligence publisher, affected by CVE-2019-2616"
        severity = "high"
        cve = "CVE-2019-2616"
        cvss = "7.2"
        vendor = "oracle"
        product = "business_intelligence_publisher"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2616"
    strings:
        $p = "business intelligence publisher" nocase
        $p2 = "business-intelligence-publisher" nocase
        $p3 = "business_intelligence_publisher" nocase
        $v0 = "11.1.1.9.0"
        $v1 = "12.2.1.3.0"
        $v2 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11539_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2019-11539"
        severity = "high"
        cve = "CVE-2019-11539"
        cvss = "7.2"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11539"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "8.1"
        $v1 = "8.2"
        $v2 = "8.3"
        $v3 = "9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11539_ivanti_policy_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti policy secure, affected by CVE-2019-11539"
        severity = "high"
        cve = "CVE-2019-11539"
        cvss = "7.2"
        vendor = "ivanti"
        product = "policy_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11539"
    strings:
        $p = "policy secure" nocase
        $p2 = "policy-secure" nocase
        $p3 = "policy_secure" nocase
        $v0 = "9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2725_oracle_agile_product_lifecycle_manageme : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle agile product lifecycle management, affected by CVE-2019-2725"
        severity = "high"
        cve = "CVE-2019-2725"
        cvss = "9.8"
        vendor = "oracle"
        product = "agile_product_lifecycle_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $p = "agile product lifecycle management" nocase
        $p2 = "agile-product-lifecycle-management" nocase
        $p3 = "agile_product_lifecycle_management" nocase
        $v0 = "9.3.3"
        $v1 = "9.3.4"
        $v2 = "9.3.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2725_oracle_communications_converged_applica : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications converged application server, affected by CVE-2019-2725"
        severity = "high"
        cve = "CVE-2019-2725"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_converged_application_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $p = "communications converged application server" nocase
        $p2 = "communications-converged-application-server" nocase
        $p3 = "communications_converged_application_server" nocase
        $v0 = "5.1"
        $v1 = "7.0"
        $v2 = "7.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2725_oracle_peoplesoft_enterprise_peopletool : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle peoplesoft enterprise peopletools, affected by CVE-2019-2725"
        severity = "high"
        cve = "CVE-2019-2725"
        cvss = "9.8"
        vendor = "oracle"
        product = "peoplesoft_enterprise_peopletools"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $p = "peoplesoft enterprise peopletools" nocase
        $p2 = "peoplesoft-enterprise-peopletools" nocase
        $p3 = "peoplesoft_enterprise_peopletools" nocase
        $v0 = "8.56"
        $v1 = "8.57"
        $v2 = "8.58"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2725_oracle_storagetek_tape_analytics_sw_too : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle storagetek tape analytics sw tool, affected by CVE-2019-2725"
        severity = "high"
        cve = "CVE-2019-2725"
        cvss = "9.8"
        vendor = "oracle"
        product = "storagetek_tape_analytics_sw_tool"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $p = "storagetek tape analytics sw tool" nocase
        $p2 = "storagetek-tape-analytics-sw-tool" nocase
        $p3 = "storagetek_tape_analytics_sw_tool" nocase
        $v0 = "2.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2725_oracle_tape_library_acsls : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle tape library acsls, affected by CVE-2019-2725"
        severity = "high"
        cve = "CVE-2019-2725"
        cvss = "9.8"
        vendor = "oracle"
        product = "tape_library_acsls"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $p = "tape library acsls" nocase
        $p2 = "tape-library-acsls" nocase
        $p3 = "tape_library_acsls" nocase
        $v0 = "8.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2725_oracle_tape_virtual_storage_manager_gui : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle tape virtual storage manager gui, affected by CVE-2019-2725"
        severity = "high"
        cve = "CVE-2019-2725"
        cvss = "9.8"
        vendor = "oracle"
        product = "tape_virtual_storage_manager_gui"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $p = "tape virtual storage manager gui" nocase
        $p2 = "tape-virtual-storage-manager-gui" nocase
        $p3 = "tape_virtual_storage_manager_gui" nocase
        $v0 = "6.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2725_oracle_vm_virtualbox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle vm virtualbox, affected by CVE-2019-2725"
        severity = "high"
        cve = "CVE-2019-2725"
        cvss = "9.8"
        vendor = "oracle"
        product = "vm_virtualbox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $p = "vm virtualbox" nocase
        $p2 = "vm-virtualbox" nocase
        $p3 = "vm_virtualbox" nocase
        $v0 = "5.2.36"
        $v1 = "6.0.0"
        $v2 = "6.0.16"
        $v3 = "6.1.0"
        $v4 = "6.1.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_2725_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2019-2725"
        severity = "high"
        cve = "CVE-2019-2725"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2725"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_9621_synacor_zimbra_collaboration_suite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain synacor zimbra collaboration suite, affected by CVE-2019-9621"
        severity = "high"
        cve = "CVE-2019-9621"
        cvss = "7.5"
        vendor = "synacor"
        product = "zimbra_collaboration_suite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9621"
    strings:
        $p = "zimbra collaboration suite" nocase
        $p2 = "zimbra-collaboration-suite" nocase
        $p3 = "zimbra_collaboration_suite" nocase
        $v0 = "8.6.0"
        $v1 = "8.7.0"
        $v2 = "8.7.11"
        $v3 = "8.8.0"
        $v4 = "8.8.10"
        $v5 = "8.8.11"
        $v6 = "8.8.9"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11510_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2019-11510"
        severity = "high"
        cve = "CVE-2019-11510"
        cvss = "10.0"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11510"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "8.2"
        $v1 = "8.3"
        $v2 = "9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_3568_whatsapp_whatsapp : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain whatsapp whatsapp, affected by CVE-2019-3568"
        severity = "high"
        cve = "CVE-2019-3568"
        cvss = "9.8"
        vendor = "whatsapp"
        product = "whatsapp"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3568"
    strings:
        $p = "whatsapp" nocase
        $v0 = "2.18.15"
        $v1 = "2.18.348"
        $v2 = "2.19.134"
        $v3 = "2.19.51"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_3568_whatsapp_whatsapp_business : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain whatsapp whatsapp business, affected by CVE-2019-3568"
        severity = "high"
        cve = "CVE-2019-3568"
        cvss = "9.8"
        vendor = "whatsapp"
        product = "whatsapp_business"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3568"
    strings:
        $p = "whatsapp business" nocase
        $p2 = "whatsapp-business" nocase
        $p3 = "whatsapp_business" nocase
        $v0 = "2.19.44"
        $v1 = "2.19.51"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11634_citrix_receiver : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain citrix receiver, affected by CVE-2019-11634"
        severity = "high"
        cve = "CVE-2019-11634"
        cvss = "9.8"
        vendor = "citrix"
        product = "receiver"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11634"
    strings:
        $p = "receiver" nocase
        $v0 = "4.9"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_7841_schneider_electric_u_motion_builder : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain schneider-electric u.motion builder, affected by CVE-2018-7841"
        severity = "high"
        cve = "CVE-2018-7841"
        cvss = "9.8"
        vendor = "schneider-electric"
        product = "u.motion_builder"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-7841"
    strings:
        $p = "u.motion builder" nocase
        $p2 = "u.motion-builder" nocase
        $p3 = "u.motion_builder" nocase
        $v0 = "1.3.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_13383_fortinet_fortiproxy : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain fortinet fortiproxy, affected by CVE-2018-13383"
        severity = "high"
        cve = "CVE-2018-13383"
        cvss = "4.3"
        vendor = "fortinet"
        product = "fortiproxy"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-13383"
    strings:
        $p = "fortiproxy" nocase
        $v0 = "1.2.9"
        $v1 = "2.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_9670_synacor_zimbra_collaboration_suite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain synacor zimbra collaboration suite, affected by CVE-2019-9670"
        severity = "high"
        cve = "CVE-2019-9670"
        cvss = "9.8"
        vendor = "synacor"
        product = "zimbra_collaboration_suite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9670"
    strings:
        $p = "zimbra collaboration suite" nocase
        $p2 = "zimbra-collaboration-suite" nocase
        $p3 = "zimbra_collaboration_suite" nocase
        $v0 = "8.7.0"
        $v1 = "8.7.11"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_9874_sitecore_experience_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sitecore experience platform, affected by CVE-2019-9874"
        severity = "high"
        cve = "CVE-2019-9874"
        cvss = "9.8"
        vendor = "sitecore"
        product = "experience_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9874"
    strings:
        $p = "experience platform" nocase
        $p2 = "experience-platform" nocase
        $p3 = "experience_platform" nocase
        $v0 = "7.5"
        $v1 = "8.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11580_atlassian_crowd : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian crowd, affected by CVE-2019-11580"
        severity = "high"
        cve = "CVE-2019-11580"
        cvss = "9.8"
        vendor = "atlassian"
        product = "crowd"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11580"
    strings:
        $p = "crowd" nocase
        $v0 = "2.1.0"
        $v1 = "3.0.5"
        $v2 = "3.1.0"
        $v3 = "3.1.6"
        $v4 = "3.2.0"
        $v5 = "3.2.8"
        $v6 = "3.3.0"
        $v7 = "3.3.5"
        $v8 = "3.4.0"
        $v9 = "3.4.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_13379_fortinet_fortiproxy : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain fortinet fortiproxy, affected by CVE-2018-13379"
        severity = "high"
        cve = "CVE-2018-13379"
        cvss = "9.1"
        vendor = "fortinet"
        product = "fortiproxy"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-13379"
    strings:
        $p = "fortiproxy" nocase
        $v0 = "1.2.9"
        $v1 = "2.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_13382_fortinet_fortiproxy : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain fortinet fortiproxy, affected by CVE-2018-13382"
        severity = "high"
        cve = "CVE-2018-13382"
        cvss = "9.1"
        vendor = "fortinet"
        product = "fortiproxy"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-13382"
    strings:
        $p = "fortiproxy" nocase
        $v0 = "1.2.9"
        $v1 = "2.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_5786_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2019-5786"
        severity = "high"
        cve = "CVE-2019-5786"
        cvss = "6.5"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5786"
    strings:
        $p = "chrome" nocase
        $v0 = "72.0.3626.121"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_15811_dnnsoftware_dotnetnuke : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain dnnsoftware dotnetnuke, affected by CVE-2018-15811"
        severity = "high"
        cve = "CVE-2018-15811"
        cvss = "7.5"
        vendor = "dnnsoftware"
        product = "dotnetnuke"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-15811"
    strings:
        $p = "dotnetnuke" nocase
        $v0 = "9.2"
        $v1 = "9.2.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2018_18325_dnnsoftware_dotnetnuke : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain dnnsoftware dotnetnuke, affected by CVE-2018-18325"
        severity = "high"
        cve = "CVE-2018-18325"
        cvss = "7.5"
        vendor = "dnnsoftware"
        product = "dotnetnuke"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-18325"
    strings:
        $p = "dotnetnuke" nocase
        $v0 = "9.2"
        $v1 = "9.2.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_1068_microsoft_sql_server_2016 : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft sql server 2016, affected by CVE-2019-1068"
        severity = "high"
        cve = "CVE-2019-1068"
        cvss = "8.8"
        vendor = "microsoft"
        product = "sql_server_2016"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1068"
    strings:
        $p = "sql server 2016" nocase
        $p2 = "sql-server-2016" nocase
        $p3 = "sql_server_2016" nocase
        $v0 = "13.0.4001.0"
        $v1 = "13.0.4259.0"
        $v2 = "13.0.4411.0"
        $v3 = "13.0.4604.0"
        $v4 = "13.0.5026.0"
        $v5 = "13.0.5101.9"
        $v6 = "13.0.5149.0"
        $v7 = "13.0.5366.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_1068_microsoft_sql_server_2017 : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft sql server 2017, affected by CVE-2019-1068"
        severity = "high"
        cve = "CVE-2019-1068"
        cvss = "8.8"
        vendor = "microsoft"
        product = "sql_server_2017"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1068"
    strings:
        $p = "sql server 2017" nocase
        $p2 = "sql-server-2017" nocase
        $p3 = "sql_server_2017" nocase
        $v0 = "14.0.1000.169"
        $v1 = "14.0.2027.2"
        $v2 = "14.0.3006.16"
        $v3 = "14.0.3192.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_12989_citrix_netscaler_sd_wan : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain citrix netscaler sd-wan, affected by CVE-2019-12989"
        severity = "high"
        cve = "CVE-2019-12989"
        cvss = "9.8"
        vendor = "citrix"
        product = "netscaler_sd-wan"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12989"
    strings:
        $p = "netscaler sd-wan" nocase
        $p2 = "netscaler-sd-wan" nocase
        $p3 = "netscaler_sd-wan" nocase
        $v0 = "10.0.0"
        $v1 = "10.0.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_12989_citrix_sd_wan : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain citrix sd-wan, affected by CVE-2019-12989"
        severity = "high"
        cve = "CVE-2019-12989"
        cvss = "9.8"
        vendor = "citrix"
        product = "sd-wan"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12989"
    strings:
        $p = "sd-wan" nocase
        $v0 = "10.2.0"
        $v1 = "10.2.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_12991_citrix_netscaler_sd_wan : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain citrix netscaler sd-wan, affected by CVE-2019-12991"
        severity = "high"
        cve = "CVE-2019-12991"
        cvss = "8.8"
        vendor = "citrix"
        product = "netscaler_sd-wan"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12991"
    strings:
        $p = "netscaler sd-wan" nocase
        $p2 = "netscaler-sd-wan" nocase
        $p3 = "netscaler_sd-wan" nocase
        $v0 = "10.0.0"
        $v1 = "10.0.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_12991_citrix_sd_wan : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain citrix sd-wan, affected by CVE-2019-12991"
        severity = "high"
        cve = "CVE-2019-12991"
        cvss = "8.8"
        vendor = "citrix"
        product = "sd-wan"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12991"
    strings:
        $p = "sd-wan" nocase
        $v0 = "10.2.0"
        $v1 = "10.2.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_13272_netapp_e_series_santricity_os_controlle : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain netapp e-series santricity os controller, affected by CVE-2019-13272"
        severity = "high"
        cve = "CVE-2019-13272"
        cvss = "7.8"
        vendor = "netapp"
        product = "e-series_santricity_os_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-13272"
    strings:
        $p = "e-series santricity os controller" nocase
        $p2 = "e-series-santricity-os-controller" nocase
        $p3 = "e-series_santricity_os_controller" nocase
        $v0 = "11.0.0"
        $v1 = "11.60.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11707_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2019-11707"
        severity = "high"
        cve = "CVE-2019-11707"
        cvss = "8.8"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11707"
    strings:
        $p = "firefox" nocase
        $v0 = "60.7.1"
        $v1 = "67.0.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11707_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2019-11707"
        severity = "high"
        cve = "CVE-2019-11707"
        cvss = "8.8"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11707"
    strings:
        $p = "thunderbird" nocase
        $v0 = "60.7.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11708_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2019-11708"
        severity = "high"
        cve = "CVE-2019-11708"
        cvss = "10.0"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11708"
    strings:
        $p = "firefox" nocase
        $v0 = "60.7.2"
        $v1 = "67.0.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11708_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2019-11708"
        severity = "high"
        cve = "CVE-2019-11708"
        cvss = "10.0"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11708"
    strings:
        $p = "thunderbird" nocase
        $v0 = "60.7.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11581_atlassian_jira_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian jira server, affected by CVE-2019-11581"
        severity = "high"
        cve = "CVE-2019-11581"
        cvss = "9.8"
        vendor = "atlassian"
        product = "jira_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11581"
    strings:
        $p = "jira server" nocase
        $p2 = "jira-server" nocase
        $p3 = "jira_server" nocase
        $v0 = "4.4"
        $v1 = "7.13.5"
        $v2 = "7.6.14"
        $v3 = "7.7.0"
        $v4 = "8.0.0"
        $v5 = "8.0.3"
        $v6 = "8.1.0"
        $v7 = "8.1.2"
        $v8 = "8.2.0"
        $v9 = "8.2.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_0344_sap_commerce_cloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap commerce cloud, affected by CVE-2019-0344"
        severity = "high"
        cve = "CVE-2019-0344"
        cvss = "9.8"
        vendor = "sap"
        product = "commerce_cloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0344"
    strings:
        $p = "commerce cloud" nocase
        $p2 = "commerce-cloud" nocase
        $p3 = "commerce_cloud" nocase
        $v0 = "6.4"
        $v1 = "6.5"
        $v2 = "6.6"
        $v3 = "6.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_15107_webmin_webmin : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain webmin webmin, affected by CVE-2019-15107"
        severity = "high"
        cve = "CVE-2019-15107"
        cvss = "9.8"
        vendor = "webmin"
        product = "webmin"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15107"
    strings:
        $p = "webmin" nocase
        $v0 = "1.920"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_15752_docker_docker : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain docker docker, affected by CVE-2019-15752"
        severity = "high"
        cve = "CVE-2019-15752"
        cvss = "7.8"
        vendor = "docker"
        product = "docker"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15752"
    strings:
        $p = "docker" nocase
        $v0 = "2.1.0.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_15752_apache_geode : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache geode, affected by CVE-2019-15752"
        severity = "high"
        cve = "CVE-2019-15752"
        cvss = "7.8"
        vendor = "apache"
        product = "geode"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15752"
    strings:
        $p = "geode" nocase
        $v0 = "1.12.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_13608_citrix_storefront_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain citrix storefront server, affected by CVE-2019-13608"
        severity = "high"
        cve = "CVE-2019-13608"
        cvss = "7.5"
        vendor = "citrix"
        product = "storefront_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-13608"
    strings:
        $p = "storefront server" nocase
        $p2 = "storefront-server" nocase
        $p3 = "storefront_server" nocase
        $v0 = "3.0.8000"
        $v1 = "3.12.4000"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_15949_nagios_nagios_xi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain nagios nagios xi, affected by CVE-2019-15949"
        severity = "high"
        cve = "CVE-2019-15949"
        cvss = "8.8"
        vendor = "nagios"
        product = "nagios_xi"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15949"
    strings:
        $p = "nagios xi" nocase
        $p2 = "nagios-xi" nocase
        $p3 = "nagios_xi" nocase
        $v0 = "5.6.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_16759_vbulletin_vbulletin : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vbulletin vbulletin, affected by CVE-2019-16759"
        severity = "high"
        cve = "CVE-2019-16759"
        cvss = "9.8"
        vendor = "vbulletin"
        product = "vbulletin"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16759"
    strings:
        $p = "vbulletin" nocase
        $v0 = "5.0.0"
        $v1 = "5.5.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_16278_nazgul_nostromo_nhttpd : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain nazgul nostromo nhttpd, affected by CVE-2019-16278"
        severity = "high"
        cve = "CVE-2019-16278"
        cvss = "9.8"
        vendor = "nazgul"
        product = "nostromo_nhttpd"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16278"
    strings:
        $p = "nostromo nhttpd" nocase
        $p2 = "nostromo-nhttpd" nocase
        $p3 = "nostromo_nhttpd" nocase
        $v0 = "1.9.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11043_tenable_tenable_sc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tenable tenable.sc, affected by CVE-2019-11043"
        severity = "high"
        cve = "CVE-2019-11043"
        cvss = "8.7"
        vendor = "tenable"
        product = "tenable.sc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"
    strings:
        $p = "tenable.sc" nocase
        $v0 = "5.19.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_11043_redhat_software_collections : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat software collections, affected by CVE-2019-11043"
        severity = "high"
        cve = "CVE-2019-11043"
        cvss = "8.7"
        vendor = "redhat"
        product = "software_collections"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"
    strings:
        $p = "software collections" nocase
        $p2 = "software-collections" nocase
        $p3 = "software_collections" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_18187_trendmicro_officescan : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain trendmicro officescan, affected by CVE-2019-18187"
        severity = "high"
        cve = "CVE-2019-18187"
        cvss = "7.5"
        vendor = "trendmicro"
        product = "officescan"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18187"
    strings:
        $p = "officescan" nocase
        $v0 = "11.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_19006_sangoma_freepbx : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sangoma freepbx, affected by CVE-2019-19006"
        severity = "high"
        cve = "CVE-2019-19006"
        cvss = "9.8"
        vendor = "sangoma"
        product = "freepbx"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-19006"
    strings:
        $p = "freepbx" nocase
        $v0 = "13.0.0.0"
        $v1 = "13.0.197.13"
        $v2 = "14.0.0.0"
        $v3 = "14.0.13.11"
        $v4 = "15.0.0.0"
        $v5 = "15.0.16.26"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_13720_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2019-13720"
        severity = "high"
        cve = "CVE-2019-13720"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-13720"
    strings:
        $p = "chrome" nocase
        $v0 = "78.0.3904.87"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_5825_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2019-5825"
        severity = "high"
        cve = "CVE-2019-5825"
        cvss = "6.5"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5825"
    strings:
        $p = "chrome" nocase
        $v0 = "73.0.3683.86"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_7192_qnap_photo_station : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain qnap photo station, affected by CVE-2019-7192"
        severity = "high"
        cve = "CVE-2019-7192"
        cvss = "9.8"
        vendor = "qnap"
        product = "photo_station"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7192"
    strings:
        $p = "photo station" nocase
        $p2 = "photo-station" nocase
        $p3 = "photo_station" nocase
        $v0 = "5.2.11"
        $v1 = "5.4.9"
        $v2 = "5.7.10"
        $v3 = "6.0.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_7194_qnap_photo_station : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain qnap photo station, affected by CVE-2019-7194"
        severity = "high"
        cve = "CVE-2019-7194"
        cvss = "9.8"
        vendor = "qnap"
        product = "photo_station"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7194"
    strings:
        $p = "photo station" nocase
        $p2 = "photo-station" nocase
        $p3 = "photo_station" nocase
        $v0 = "5.2.11"
        $v1 = "5.4.9"
        $v2 = "5.7.10"
        $v3 = "6.0.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_7195_qnap_photo_station : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain qnap photo station, affected by CVE-2019-7195"
        severity = "high"
        cve = "CVE-2019-7195"
        cvss = "9.8"
        vendor = "qnap"
        product = "photo_station"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7195"
    strings:
        $p = "photo station" nocase
        $p2 = "photo-station" nocase
        $p3 = "photo_station" nocase
        $v0 = "5.2.11"
        $v1 = "5.4.9"
        $v2 = "5.7.10"
        $v3 = "6.0.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_5544_vmware_horizon_daas : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware horizon daas, affected by CVE-2019-5544"
        severity = "high"
        cve = "CVE-2019-5544"
        cvss = "9.8"
        vendor = "vmware"
        product = "horizon_daas"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5544"
    strings:
        $p = "horizon daas" nocase
        $p2 = "horizon-daas" nocase
        $p3 = "horizon_daas" nocase
        $v0 = "8.0.0"
        $v1 = "9.0.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_5544_openslp_openslp : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain openslp openslp, affected by CVE-2019-5544"
        severity = "high"
        cve = "CVE-2019-5544"
        cvss = "9.8"
        vendor = "openslp"
        product = "openslp"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5544"
    strings:
        $p = "openslp" nocase
        $v0 = "2.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_18935_telerik_ui_for_asp_net_ajax : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain telerik ui for asp.net ajax, affected by CVE-2019-18935"
        severity = "high"
        cve = "CVE-2019-18935"
        cvss = "9.8"
        vendor = "telerik"
        product = "ui_for_asp.net_ajax"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18935"
    strings:
        $p = "ui for asp.net ajax" nocase
        $p2 = "ui-for-asp.net-ajax" nocase
        $p3 = "ui_for_asp.net_ajax" nocase
        $v0 = "2011.1.315"
        $v1 = "2020.1.114"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_4716_ibm_planning_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm planning analytics, affected by CVE-2019-4716"
        severity = "high"
        cve = "CVE-2019-4716"
        cvss = "9.8"
        vendor = "ibm"
        product = "planning_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-4716"
    strings:
        $p = "planning analytics" nocase
        $p2 = "planning-analytics" nocase
        $p3 = "planning_analytics" nocase
        $v0 = "2.0"
        $v1 = "2.0.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_8506_apple_icloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apple icloud, affected by CVE-2019-8506"
        severity = "high"
        cve = "CVE-2019-8506"
        cvss = "8.8"
        vendor = "apple"
        product = "icloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8506"
    strings:
        $p = "icloud" nocase
        $v0 = "7.11"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_8506_apple_itunes : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apple itunes, affected by CVE-2019-8506"
        severity = "high"
        cve = "CVE-2019-8506"
        cvss = "8.8"
        vendor = "apple"
        product = "itunes"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8506"
    strings:
        $p = "itunes" nocase
        $v0 = "12.9.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_8506_apple_safari : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apple safari, affected by CVE-2019-8506"
        severity = "high"
        cve = "CVE-2019-8506"
        cvss = "8.8"
        vendor = "apple"
        product = "safari"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8506"
    strings:
        $p = "safari" nocase
        $v0 = "12.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_10758_mongo_express_project_mongo_express : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mongo-express project mongo-express, affected by CVE-2019-10758"
        severity = "high"
        cve = "CVE-2019-10758"
        cvss = "9.9"
        vendor = "mongo-express_project"
        product = "mongo-express"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-10758"
    strings:
        $p = "mongo-express" nocase
        $v0 = "0.54.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_17558_oracle_primavera_unifier : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle primavera unifier, affected by CVE-2019-17558"
        severity = "high"
        cve = "CVE-2019-17558"
        cvss = "7.5"
        vendor = "oracle"
        product = "primavera_unifier"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17558"
    strings:
        $p = "primavera unifier" nocase
        $p2 = "primavera-unifier" nocase
        $p3 = "primavera_unifier" nocase
        $v0 = "16.1"
        $v1 = "16.2"
        $v2 = "17.12"
        $v3 = "17.7"
        $v4 = "18.8"
        $v5 = "19.12"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_0646_microsoft_net_framework : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft .net framework, affected by CVE-2020-0646"
        severity = "high"
        cve = "CVE-2020-0646"
        cvss = "9.8"
        vendor = "microsoft"
        product = ".net_framework"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-0646"
    strings:
        $p = ".net framework" nocase
        $p2 = ".net-framework" nocase
        $p3 = ".net_framework" nocase
        $v0 = "3.0"
        $v1 = "3.5"
        $v2 = "3.5.1"
        $v3 = "4.5.2"
        $v4 = "4.6"
        $v5 = "4.6.1"
        $v6 = "4.6.2"
        $v7 = "4.7"
        $v8 = "4.7.1"
        $v9 = "4.7.2"
        $v10 = "4.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2551_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2020-2551"
        severity = "high"
        cve = "CVE-2020-2551"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2551"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.3.0"
        $v3 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_access_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle access manager, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "access_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "access manager" nocase
        $p2 = "access-manager" nocase
        $p3 = "access_manager" nocase
        $v0 = "11.1.2.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_coherence : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle coherence, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "coherence"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "coherence" nocase
        $v0 = "12.1.3.0.0"
        $v1 = "12.2.1.3.0"
        $v2 = "12.2.1.4.0"
        $v3 = "3.7.1.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_commerce_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle commerce platform, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "commerce_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "commerce platform" nocase
        $p2 = "commerce-platform" nocase
        $p3 = "commerce_platform" nocase
        $v0 = "11.0.0"
        $v1 = "11.1.0"
        $v2 = "11.2.0"
        $v3 = "11.3.0"
        $v4 = "11.3.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_communications_diameter_signalin : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications diameter signaling router, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_diameter_signaling_router"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "communications diameter signaling router" nocase
        $p2 = "communications-diameter-signaling-router" nocase
        $p3 = "communications_diameter_signaling_router" nocase
        $v0 = "8.0.0"
        $v1 = "8.2.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_healthcare_data_repository : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle healthcare data repository, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "healthcare_data_repository"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "healthcare data repository" nocase
        $p2 = "healthcare-data-repository" nocase
        $p3 = "healthcare_data_repository" nocase
        $v0 = "7.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_rapid_planning : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle rapid planning, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "rapid_planning"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "rapid planning" nocase
        $p2 = "rapid-planning" nocase
        $p3 = "rapid_planning" nocase
        $v0 = "12.1"
        $v1 = "12.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_retail_assortment_planning : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail assortment planning, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "retail_assortment_planning"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "retail assortment planning" nocase
        $p2 = "retail-assortment-planning" nocase
        $p3 = "retail_assortment_planning" nocase
        $v0 = "15.0"
        $v1 = "16.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_utilities_framework : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle utilities framework, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "utilities_framework"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "utilities framework" nocase
        $p2 = "utilities-framework" nocase
        $p3 = "utilities_framework" nocase
        $v0 = "4.2.0.2.0"
        $v1 = "4.2.0.3.0"
        $v2 = "4.3.0.1.0"
        $v3 = "4.3.0.6.0"
        $v4 = "4.4.0.0.0"
        $v5 = "4.4.0.2.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2555_oracle_webcenter_portal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle webcenter portal, affected by CVE-2020-2555"
        severity = "high"
        cve = "CVE-2020-2555"
        cvss = "9.8"
        vendor = "oracle"
        product = "webcenter_portal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2555"
    strings:
        $p = "webcenter portal" nocase
        $p2 = "webcenter-portal" nocase
        $p3 = "webcenter_portal" nocase
        $v0 = "12.2.1.3.0"
        $v1 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_18426_whatsapp_whatsapp : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain whatsapp whatsapp, affected by CVE-2019-18426"
        severity = "high"
        cve = "CVE-2019-18426"
        cvss = "8.2"
        vendor = "whatsapp"
        product = "whatsapp"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18426"
    strings:
        $p = "whatsapp" nocase
        $v0 = "0.3.9309"
        $v1 = "2.20.10"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_7247_openbsd_opensmtpd : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain openbsd opensmtpd, affected by CVE-2020-7247"
        severity = "high"
        cve = "CVE-2020-7247"
        cvss = "9.8"
        vendor = "openbsd"
        product = "opensmtpd"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7247"
    strings:
        $p = "opensmtpd" nocase
        $v0 = "6.6"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8644_playsms_playsms : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain playsms playsms, affected by CVE-2020-8644"
        severity = "high"
        cve = "CVE-2020-8644"
        cvss = "9.8"
        vendor = "playsms"
        product = "playsms"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8644"
    strings:
        $p = "playsms" nocase
        $v0 = "1.4.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8657_eyesofnetwork_eyesofnetwork : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain eyesofnetwork eyesofnetwork, affected by CVE-2020-8657"
        severity = "high"
        cve = "CVE-2020-8657"
        cvss = "9.8"
        vendor = "eyesofnetwork"
        product = "eyesofnetwork"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8657"
    strings:
        $p = "eyesofnetwork" nocase
        $v0 = "5.3-0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8655_eyesofnetwork_eyesofnetwork : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain eyesofnetwork eyesofnetwork, affected by CVE-2020-8655"
        severity = "high"
        cve = "CVE-2020-8655"
        cvss = "7.8"
        vendor = "eyesofnetwork"
        product = "eyesofnetwork"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8655"
    strings:
        $p = "eyesofnetwork" nocase
        $v0 = "5.3-0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_18988_teamviewer_teamviewer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain teamviewer teamviewer, affected by CVE-2019-18988"
        severity = "high"
        cve = "CVE-2019-18988"
        cvss = "7.0"
        vendor = "teamviewer"
        product = "teamviewer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18988"
    strings:
        $p = "teamviewer" nocase
        $v0 = "14.7.1965"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_7796_synacor_zimbra_collaboration_suite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain synacor zimbra collaboration suite, affected by CVE-2020-7796"
        severity = "high"
        cve = "CVE-2020-7796"
        cvss = "9.8"
        vendor = "synacor"
        product = "zimbra_collaboration_suite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7796"
    strings:
        $p = "zimbra collaboration suite" nocase
        $p2 = "zimbra-collaboration-suite" nocase
        $p3 = "zimbra_collaboration_suite" nocase
        $v0 = "8.8.15"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3153_cisco_anyconnect_secure_mobility_clien : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cisco anyconnect secure mobility client, affected by CVE-2020-3153"
        severity = "high"
        cve = "CVE-2020-3153"
        cvss = "6.5"
        vendor = "cisco"
        product = "anyconnect_secure_mobility_client"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3153"
    strings:
        $p = "anyconnect secure mobility client" nocase
        $p2 = "anyconnect-secure-mobility-client" nocase
        $p3 = "anyconnect_secure_mobility_client" nocase
        $v0 = "4.8.02042"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_apache_geode : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache geode, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "apache"
        product = "geode"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "geode" nocase
        $v0 = "1.12.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_apache_tomcat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache tomcat, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "apache"
        product = "tomcat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "tomcat" nocase
        $v0 = "7.0.0"
        $v1 = "7.0.100"
        $v2 = "8.5.0"
        $v3 = "8.5.51"
        $v4 = "9.0.0"
        $v5 = "9.0.31"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_agile_engineering_data_managemen : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle agile engineering data management, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "agile_engineering_data_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "agile engineering data management" nocase
        $p2 = "agile-engineering-data-management" nocase
        $p3 = "agile_engineering_data_management" nocase
        $v0 = "6.2.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_agile_product_lifecycle_manageme : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle agile product lifecycle management, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "agile_product_lifecycle_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "agile product lifecycle management" nocase
        $p2 = "agile-product-lifecycle-management" nocase
        $p3 = "agile_product_lifecycle_management" nocase
        $v0 = "9.3.3"
        $v1 = "9.3.5"
        $v2 = "9.3.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_communications_element_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications element manager, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_element_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "communications element manager" nocase
        $p2 = "communications-element-manager" nocase
        $p3 = "communications_element_manager" nocase
        $v0 = "8.1.1"
        $v1 = "8.2.0"
        $v2 = "8.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_communications_instant_messaging : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications instant messaging server, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_instant_messaging_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "communications instant messaging server" nocase
        $p2 = "communications-instant-messaging-server" nocase
        $p3 = "communications_instant_messaging_server" nocase
        $v0 = "10.0.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_health_sciences_empirica_inspect : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle health sciences empirica inspections, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "health_sciences_empirica_inspections"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "health sciences empirica inspections" nocase
        $p2 = "health-sciences-empirica-inspections" nocase
        $p3 = "health_sciences_empirica_inspections" nocase
        $v0 = "1.0.1.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_health_sciences_empirica_signal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle health sciences empirica signal, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "health_sciences_empirica_signal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "health sciences empirica signal" nocase
        $p2 = "health-sciences-empirica-signal" nocase
        $p3 = "health_sciences_empirica_signal" nocase
        $v0 = "7.3.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_hospitality_guest_access : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle hospitality guest access, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "hospitality_guest_access"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "hospitality guest access" nocase
        $p2 = "hospitality-guest-access" nocase
        $p3 = "hospitality_guest_access" nocase
        $v0 = "4.2.0"
        $v1 = "4.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_instantis_enterprisetrack : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle instantis enterprisetrack, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "instantis_enterprisetrack"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "instantis enterprisetrack" nocase
        $p2 = "instantis-enterprisetrack" nocase
        $p3 = "instantis_enterprisetrack" nocase
        $v0 = "17.1"
        $v1 = "17.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_mysql_enterprise_monitor : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle mysql enterprise monitor, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "mysql_enterprise_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "mysql enterprise monitor" nocase
        $p2 = "mysql-enterprise-monitor" nocase
        $p3 = "mysql_enterprise_monitor" nocase
        $v0 = "4.0.12"
        $v1 = "8.0.0"
        $v2 = "8.0.20"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_siebel_ui_framework : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle siebel ui framework, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "siebel_ui_framework"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "siebel ui framework" nocase
        $p2 = "siebel-ui-framework" nocase
        $p3 = "siebel_ui_framework" nocase
        $v0 = "20.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_transportation_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle transportation management, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "transportation_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "transportation management" nocase
        $p2 = "transportation-management" nocase
        $p3 = "transportation_management" nocase
        $v0 = "6.3.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_oracle_workload_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle workload manager, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "oracle"
        product = "workload_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "workload manager" nocase
        $p2 = "workload-manager" nocase
        $p3 = "workload_manager" nocase
        $v0 = "12.2.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_blackberry_good_control : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain blackberry good control, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "blackberry"
        product = "good_control"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "good control" nocase
        $p2 = "good-control" nocase
        $p3 = "good_control" nocase
        $v0 = "5.2.58.38"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_blackberry_workspaces_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain blackberry workspaces server, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "blackberry"
        product = "workspaces_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "workspaces server" nocase
        $p2 = "workspaces-server" nocase
        $p3 = "workspaces_server" nocase
        $v0 = "7.0.1"
        $v1 = "7.1.2"
        $v2 = "8.1.0"
        $v3 = "9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1938_netapp_oncommand_system_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain netapp oncommand system manager, affected by CVE-2020-1938"
        severity = "high"
        cve = "CVE-2020-1938"
        cvss = "9.8"
        vendor = "netapp"
        product = "oncommand_system_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    strings:
        $p = "oncommand system manager" nocase
        $p2 = "oncommand-system-manager" nocase
        $p3 = "oncommand_system_manager" nocase
        $v0 = "3.0.0"
        $v1 = "3.1.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_6418_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2020-6418"
        severity = "high"
        cve = "CVE-2020-6418"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6418"
    strings:
        $p = "chrome" nocase
        $v0 = "80.0.3987.122"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_17026_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2019-17026"
        severity = "high"
        cve = "CVE-2019-17026"
        cvss = "8.8"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17026"
    strings:
        $p = "firefox" nocase
        $v0 = "68.4.1"
        $v1 = "72.0.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2019_17026_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2019-17026"
        severity = "high"
        cve = "CVE-2019-17026"
        cvss = "8.8"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17026"
    strings:
        $p = "thunderbird" nocase
        $v0 = "68.4.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_10189_zohocorp_manageengine_desktop_central : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain zohocorp manageengine desktop central, affected by CVE-2020-10189"
        severity = "high"
        cve = "CVE-2020-10189"
        cvss = "9.8"
        vendor = "zohocorp"
        product = "manageengine_desktop_central"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10189"
    strings:
        $p = "manageengine desktop central" nocase
        $p2 = "manageengine-desktop-central" nocase
        $p3 = "manageengine_desktop_central" nocase
        $v0 = "10.0.479"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_10221_rconfig_rconfig : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain rconfig rconfig, affected by CVE-2020-10221"
        severity = "high"
        cve = "CVE-2020-10221"
        cvss = "8.8"
        vendor = "rconfig"
        product = "rconfig"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10221"
    strings:
        $p = "rconfig" nocase
        $v0 = "3.9.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_6207_sap_solution_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap solution manager, affected by CVE-2020-6207"
        severity = "high"
        cve = "CVE-2020-6207"
        cvss = "9.8"
        vendor = "sap"
        product = "solution_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6207"
    strings:
        $p = "solution manager" nocase
        $p2 = "solution-manager" nocase
        $p3 = "solution_manager" nocase
        $v0 = "7.20"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3950_vmware_fusion : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware fusion, affected by CVE-2020-3950"
        severity = "high"
        cve = "CVE-2020-3950"
        cvss = "7.8"
        vendor = "vmware"
        product = "fusion"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3950"
    strings:
        $p = "fusion" nocase
        $v0 = "11.0.0"
        $v1 = "11.5.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3950_vmware_horizon_client : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware horizon client, affected by CVE-2020-3950"
        severity = "high"
        cve = "CVE-2020-3950"
        cvss = "7.8"
        vendor = "vmware"
        product = "horizon_client"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3950"
    strings:
        $p = "horizon client" nocase
        $p2 = "horizon-client" nocase
        $p3 = "horizon_client" nocase
        $v0 = "5.0.0"
        $v1 = "5.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3950_vmware_remote_console : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware remote console, affected by CVE-2020-3950"
        severity = "high"
        cve = "CVE-2020-3950"
        cvss = "7.8"
        vendor = "vmware"
        product = "remote_console"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3950"
    strings:
        $p = "remote console" nocase
        $p2 = "remote-console" nocase
        $p3 = "remote_console" nocase
        $v0 = "11.0.0"
        $v1 = "11.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8468_trendmicro_worry_free_business_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain trendmicro worry-free business security, affected by CVE-2020-8468"
        severity = "high"
        cve = "CVE-2020-8468"
        cvss = "8.8"
        vendor = "trendmicro"
        product = "worry-free_business_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8468"
    strings:
        $p = "worry-free business security" nocase
        $p2 = "worry-free-business-security" nocase
        $p3 = "worry-free_business_security" nocase
        $v0 = "10.0"
        $v1 = "9.0"
        $v2 = "9.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_7961_liferay_liferay_portal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain liferay liferay portal, affected by CVE-2020-7961"
        severity = "high"
        cve = "CVE-2020-7961"
        cvss = "9.8"
        vendor = "liferay"
        product = "liferay_portal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7961"
    strings:
        $p = "liferay portal" nocase
        $p2 = "liferay-portal" nocase
        $p3 = "liferay_portal" nocase
        $v0 = "7.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_10199_sonatype_nexus : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonatype nexus, affected by CVE-2020-10199"
        severity = "high"
        cve = "CVE-2020-10199"
        cvss = "8.8"
        vendor = "sonatype"
        product = "nexus"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10199"
    strings:
        $p = "nexus" nocase
        $v0 = "3.21.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3952_vmware_vcenter_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vcenter server, affected by CVE-2020-3952"
        severity = "high"
        cve = "CVE-2020-3952"
        cvss = "9.8"
        vendor = "vmware"
        product = "vcenter_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3952"
    strings:
        $p = "vcenter server" nocase
        $p2 = "vcenter-server" nocase
        $p3 = "vcenter_server" nocase
        $v0 = "6.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11738_awesomemotive_duplicator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain awesomemotive duplicator, affected by CVE-2020-11738"
        severity = "high"
        cve = "CVE-2020-11738"
        cvss = "7.5"
        vendor = "awesomemotive"
        product = "duplicator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11738"
    strings:
        $p = "duplicator" nocase
        $v0 = "1.3.28"
        $v1 = "3.8.7.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2883_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2020-2883"
        severity = "high"
        cve = "CVE-2020-2883"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2883"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.3.0"
        $v3 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_6819_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2020-6819"
        severity = "high"
        cve = "CVE-2020-6819"
        cvss = "8.1"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6819"
    strings:
        $p = "firefox" nocase
        $v0 = "68.6.1"
        $v1 = "74.0.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_6819_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2020-6819"
        severity = "high"
        cve = "CVE-2020-6819"
        cvss = "8.1"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6819"
    strings:
        $p = "thunderbird" nocase
        $v0 = "68.7.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_6820_mozilla_firefox : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla firefox, affected by CVE-2020-6820"
        severity = "high"
        cve = "CVE-2020-6820"
        cvss = "8.1"
        vendor = "mozilla"
        product = "firefox"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6820"
    strings:
        $p = "firefox" nocase
        $v0 = "68.6.1"
        $v1 = "74.0.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_6820_mozilla_thunderbird : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mozilla thunderbird, affected by CVE-2020-6820"
        severity = "high"
        cve = "CVE-2020-6820"
        cvss = "8.1"
        vendor = "mozilla"
        product = "thunderbird"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6820"
    strings:
        $p = "thunderbird" nocase
        $v0 = "68.7.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_jquery_jquery : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain jquery jquery, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "jquery"
        product = "jquery"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "jquery" nocase
        $v0 = "1.0.3"
        $v1 = "3.5.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_drupal_drupal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain drupal drupal, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "drupal"
        product = "drupal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "drupal" nocase
        $v0 = "7.0"
        $v1 = "7.70"
        $v2 = "8.7.0"
        $v3 = "8.7.14"
        $v4 = "8.8.0"
        $v5 = "8.8.6"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_application_express : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle application express, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "application_express"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "application express" nocase
        $p2 = "application-express" nocase
        $p3 = "application_express" nocase
        $v0 = "20.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_application_testing_suite : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle application testing suite, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "application_testing_suite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "application testing suite" nocase
        $p2 = "application-testing-suite" nocase
        $p3 = "application_testing_suite" nocase
        $v0 = "13.3.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_banking_enterprise_collections : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle banking enterprise collections, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "banking_enterprise_collections"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "banking enterprise collections" nocase
        $p2 = "banking-enterprise-collections" nocase
        $p3 = "banking_enterprise_collections" nocase
        $v0 = "2.7.0"
        $v1 = "2.8.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_banking_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle banking platform, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "banking_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "banking platform" nocase
        $p2 = "banking-platform" nocase
        $p3 = "banking_platform" nocase
        $v0 = "2.10.0"
        $v1 = "2.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_blockchain_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle blockchain platform, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "blockchain_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "blockchain platform" nocase
        $p2 = "blockchain-platform" nocase
        $p3 = "blockchain_platform" nocase
        $v0 = "21.1.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_business_intelligence : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle business intelligence, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "business_intelligence"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "business intelligence" nocase
        $p2 = "business-intelligence" nocase
        $p3 = "business_intelligence" nocase
        $v0 = "5.9.0.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_communications_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications analytics, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "communications_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "communications analytics" nocase
        $p2 = "communications-analytics" nocase
        $p3 = "communications_analytics" nocase
        $v0 = "12.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_communications_eagle_application : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications eagle application processor, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "communications_eagle_application_processor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "communications eagle application processor" nocase
        $p2 = "communications-eagle-application-processor" nocase
        $p3 = "communications_eagle_application_processor" nocase
        $v0 = "16.1.0"
        $v1 = "16.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_communications_element_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications element manager, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "communications_element_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "communications element manager" nocase
        $p2 = "communications-element-manager" nocase
        $p3 = "communications_element_manager" nocase
        $v0 = "8.1.1"
        $v1 = "8.2.0"
        $v2 = "8.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_communications_interactive_sessi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications interactive session recorder, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "communications_interactive_session_recorder"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "communications interactive session recorder" nocase
        $p2 = "communications-interactive-session-recorder" nocase
        $p3 = "communications_interactive_session_recorder" nocase
        $v0 = "6.1"
        $v1 = "6.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_communications_operations_monito : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications operations monitor, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "communications_operations_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "communications operations monitor" nocase
        $p2 = "communications-operations-monitor" nocase
        $p3 = "communications_operations_monitor" nocase
        $v0 = "3.4"
        $v1 = "4.1"
        $v2 = "4.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_communications_services_gatekeep : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications services gatekeeper, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "communications_services_gatekeeper"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "communications services gatekeeper" nocase
        $p2 = "communications-services-gatekeeper" nocase
        $p3 = "communications_services_gatekeeper" nocase
        $v0 = "7.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_communications_session_report_ma : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications session report manager, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "communications_session_report_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "communications session report manager" nocase
        $p2 = "communications-session-report-manager" nocase
        $p3 = "communications_session_report_manager" nocase
        $v0 = "8.1.1"
        $v1 = "8.2.0"
        $v2 = "8.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_communications_session_route_man : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications session route manager, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "communications_session_route_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "communications session route manager" nocase
        $p2 = "communications-session-route-manager" nocase
        $p3 = "communications_session_route_manager" nocase
        $v0 = "8.1.1"
        $v1 = "8.2.0"
        $v2 = "8.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_financial_services_regulatory_re : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle financial services regulatory reporting for de nederlandsche bank, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "financial_services_regulatory_reporting_for_de_nederlandsche_bank"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "financial services regulatory reporting for de nederlandsche bank" nocase
        $p2 = "financial-services-regulatory-reporting-for-de-nederlandsche-bank" nocase
        $p3 = "financial_services_regulatory_reporting_for_de_nederlandsche_bank" nocase
        $v0 = "8.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_financial_services_revenue_manag : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle financial services revenue management and billing analytics, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "financial_services_revenue_management_and_billing_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "financial services revenue management and billing analytics" nocase
        $p2 = "financial-services-revenue-management-and-billing-analytics" nocase
        $p3 = "financial_services_revenue_management_and_billing_analytics" nocase
        $v0 = "2.7"
        $v1 = "2.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_health_sciences_inform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle health sciences inform, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "health_sciences_inform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "health sciences inform" nocase
        $p2 = "health-sciences-inform" nocase
        $p3 = "health_sciences_inform" nocase
        $v0 = "6.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_healthcare_translational_researc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle healthcare translational research, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "healthcare_translational_research"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "healthcare translational research" nocase
        $p2 = "healthcare-translational-research" nocase
        $p3 = "healthcare_translational_research" nocase
        $v0 = "3.2.1"
        $v1 = "3.3.1"
        $v2 = "3.3.2"
        $v3 = "3.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_hyperion_financial_reporting : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle hyperion financial reporting, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "hyperion_financial_reporting"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "hyperion financial reporting" nocase
        $p2 = "hyperion-financial-reporting" nocase
        $p3 = "hyperion_financial_reporting" nocase
        $v0 = "11.1.2.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_jd_edwards_enterpriseone_orchest : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle jd edwards enterpriseone orchestrator, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "jd_edwards_enterpriseone_orchestrator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "jd edwards enterpriseone orchestrator" nocase
        $p2 = "jd-edwards-enterpriseone-orchestrator" nocase
        $p3 = "jd_edwards_enterpriseone_orchestrator" nocase
        $v0 = "9.2.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_jd_edwards_enterpriseone_tools : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle jd edwards enterpriseone tools, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "jd_edwards_enterpriseone_tools"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "jd edwards enterpriseone tools" nocase
        $p2 = "jd-edwards-enterpriseone-tools" nocase
        $p3 = "jd_edwards_enterpriseone_tools" nocase
        $v0 = "9.2.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_oss_support_tools : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle oss support tools, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "oss_support_tools"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "oss support tools" nocase
        $p2 = "oss-support-tools" nocase
        $p3 = "oss_support_tools" nocase
        $v0 = "2.12.41"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_peoplesoft_enterprise_human_capi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle peoplesoft enterprise human capital management resources, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "peoplesoft_enterprise_human_capital_management_resources"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "peoplesoft enterprise human capital management resources" nocase
        $p2 = "peoplesoft-enterprise-human-capital-management-resources" nocase
        $p3 = "peoplesoft_enterprise_human_capital_management_resources" nocase
        $v0 = "9.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_primavera_gateway : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle primavera gateway, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "primavera_gateway"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "primavera gateway" nocase
        $p2 = "primavera-gateway" nocase
        $p3 = "primavera_gateway" nocase
        $v0 = "16.2"
        $v1 = "16.2.11"
        $v2 = "17.12.0"
        $v3 = "17.12.7"
        $v4 = "18.8.0"
        $v5 = "18.8.9"
        $v6 = "19.12.0"
        $v7 = "19.12.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_rest_data_services : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle rest data services, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "rest_data_services"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "rest data services" nocase
        $p2 = "rest-data-services" nocase
        $p3 = "rest_data_services" nocase
        $v0 = "11.2.0.4"
        $v1 = "12.1.0.2"
        $v2 = "12.2.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_siebel_mobile : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle siebel mobile, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "siebel_mobile"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "siebel mobile" nocase
        $p2 = "siebel-mobile" nocase
        $p3 = "siebel_mobile" nocase
        $v0 = "20.12"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_storagetek_acsls : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle storagetek acsls, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "storagetek_acsls"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "storagetek acsls" nocase
        $p2 = "storagetek-acsls" nocase
        $p3 = "storagetek_acsls" nocase
        $v0 = "8.5.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_storagetek_tape_analytics_sw_too : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle storagetek tape analytics sw tool, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "storagetek_tape_analytics_sw_tool"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "storagetek tape analytics sw tool" nocase
        $p2 = "storagetek-tape-analytics-sw-tool" nocase
        $p3 = "storagetek_tape_analytics_sw_tool" nocase
        $v0 = "2.3.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_webcenter_sites : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle webcenter sites, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "webcenter_sites"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "webcenter sites" nocase
        $p2 = "webcenter-sites" nocase
        $p3 = "webcenter_sites" nocase
        $v0 = "12.2.1.3.0"
        $v1 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "12.1.3.0.0"
        $v1 = "12.2.1.3.0"
        $v2 = "12.2.1.4.0"
        $v3 = "14.1.1.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_netapp_oncommand_system_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain netapp oncommand system manager, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "netapp"
        product = "oncommand_system_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "oncommand system manager" nocase
        $p2 = "oncommand-system-manager" nocase
        $p3 = "oncommand_system_manager" nocase
        $v0 = "3.0"
        $v1 = "3.1.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11023_tenable_log_correlation_engine : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tenable log correlation engine, affected by CVE-2020-11023"
        severity = "high"
        cve = "CVE-2020-11023"
        cvss = "6.9"
        vendor = "tenable"
        product = "log_correlation_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11023"
    strings:
        $p = "log correlation engine" nocase
        $p2 = "log-correlation-engine" nocase
        $p3 = "log_correlation_engine" nocase
        $v0 = "6.0.9"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11651_vmware_application_remote_collector : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware application remote collector, affected by CVE-2020-11651"
        severity = "high"
        cve = "CVE-2020-11651"
        cvss = "9.8"
        vendor = "vmware"
        product = "application_remote_collector"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11651"
    strings:
        $p = "application remote collector" nocase
        $p2 = "application-remote-collector" nocase
        $p3 = "application_remote_collector" nocase
        $v0 = "7.5.0"
        $v1 = "8.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11652_blackberry_workspaces_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain blackberry workspaces server, affected by CVE-2020-11652"
        severity = "high"
        cve = "CVE-2020-11652"
        cvss = "6.5"
        vendor = "blackberry"
        product = "workspaces_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11652"
    strings:
        $p = "workspaces server" nocase
        $p2 = "workspaces-server" nocase
        $p3 = "workspaces_server" nocase
        $v0 = "7.1.3"
        $v1 = "8.0.0"
        $v2 = "8.2.6"
        $v3 = "9.1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11652_vmware_application_remote_collector : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware application remote collector, affected by CVE-2020-11652"
        severity = "high"
        cve = "CVE-2020-11652"
        cvss = "6.5"
        vendor = "vmware"
        product = "application_remote_collector"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11652"
    strings:
        $p = "application remote collector" nocase
        $p2 = "application-remote-collector" nocase
        $p3 = "application_remote_collector" nocase
        $v0 = "7.5.0"
        $v1 = "8.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_12641_roundcube_webmail : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain roundcube webmail, affected by CVE-2020-12641"
        severity = "high"
        cve = "CVE-2020-12641"
        cvss = "9.8"
        vendor = "roundcube"
        product = "webmail"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-12641"
    strings:
        $p = "webmail" nocase
        $v0 = "1.2.0"
        $v1 = "1.2.10"
        $v2 = "1.3.0"
        $v3 = "1.3.11"
        $v4 = "1.4.0"
        $v5 = "1.4.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_12641_opensuse_backports_sle : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain opensuse backports sle, affected by CVE-2020-12641"
        severity = "high"
        cve = "CVE-2020-12641"
        cvss = "9.8"
        vendor = "opensuse"
        product = "backports_sle"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-12641"
    strings:
        $p = "backports sle" nocase
        $p2 = "backports-sle" nocase
        $p3 = "backports_sle" nocase
        $v0 = "15.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3259_cisco_secure_firewall_threat_defense : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cisco secure firewall threat defense, affected by CVE-2020-3259"
        severity = "high"
        cve = "CVE-2020-3259"
        cvss = "7.5"
        vendor = "cisco"
        product = "secure_firewall_threat_defense"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3259"
    strings:
        $p = "secure firewall threat defense" nocase
        $p2 = "secure-firewall-threat-defense" nocase
        $p3 = "secure_firewall_threat_defense" nocase
        $v0 = "6.2.3"
        $v1 = "6.2.3.16"
        $v2 = "6.3.0"
        $v3 = "6.3.0.6"
        $v4 = "6.4.0"
        $v5 = "6.4.0.9"
        $v6 = "6.5.0"
        $v7 = "6.5.0.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_4427_ibm_data_risk_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm data risk manager, affected by CVE-2020-4427"
        severity = "high"
        cve = "CVE-2020-4427"
        cvss = "9.8"
        vendor = "ibm"
        product = "data_risk_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4427"
    strings:
        $p = "data risk manager" nocase
        $p2 = "data-risk-manager" nocase
        $p3 = "data_risk_manager" nocase
        $v0 = "2.0.1"
        $v1 = "2.0.6.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_4428_ibm_data_risk_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm data risk manager, affected by CVE-2020-4428"
        severity = "high"
        cve = "CVE-2020-4428"
        cvss = "9.1"
        vendor = "ibm"
        product = "data_risk_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4428"
    strings:
        $p = "data risk manager" nocase
        $p2 = "data-risk-manager" nocase
        $p3 = "data_risk_manager" nocase
        $v0 = "2.0.1"
        $v1 = "2.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_4430_ibm_data_risk_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ibm data risk manager, affected by CVE-2020-4430"
        severity = "high"
        cve = "CVE-2020-4430"
        cvss = "4.3"
        vendor = "ibm"
        product = "data_risk_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4430"
    strings:
        $p = "data risk manager" nocase
        $p2 = "data-risk-manager" nocase
        $p3 = "data_risk_manager" nocase
        $v0 = "2.0.1"
        $v1 = "2.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5741_plex_media_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain plex media server, affected by CVE-2020-5741"
        severity = "high"
        cve = "CVE-2020-5741"
        cvss = "7.2"
        vendor = "plex"
        product = "media_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5741"
    strings:
        $p = "media server" nocase
        $p2 = "media-server" nocase
        $p3 = "media_server" nocase
        $v0 = "1.19.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1956_apache_kylin : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache kylin, affected by CVE-2020-1956"
        severity = "high"
        cve = "CVE-2020-1956"
        cvss = "8.8"
        vendor = "apache"
        product = "kylin"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1956"
    strings:
        $p = "kylin" nocase
        $v0 = "2.3.0"
        $v1 = "2.3.2"
        $v2 = "2.4.0"
        $v3 = "2.4.1"
        $v4 = "2.5.0"
        $v5 = "2.5.2"
        $v6 = "2.6.0"
        $v7 = "2.6.5"
        $v8 = "3.0.0"
        $v9 = "3.0.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8816_pi_hole_pi_hole : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain pi-hole pi-hole, affected by CVE-2020-8816"
        severity = "high"
        cve = "CVE-2020-8816"
        cvss = "7.2"
        vendor = "pi-hole"
        product = "pi-hole"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8816"
    strings:
        $p = "pi-hole" nocase
        $v0 = "4.3.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5410_vmware_spring_cloud_config : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware spring cloud config, affected by CVE-2020-5410"
        severity = "high"
        cve = "CVE-2020-5410"
        cvss = "7.5"
        vendor = "vmware"
        product = "spring_cloud_config"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5410"
    strings:
        $p = "spring cloud config" nocase
        $p2 = "spring-cloud-config" nocase
        $p3 = "spring_cloud_config" nocase
        $v0 = "2.1.0"
        $v1 = "2.1.9"
        $v2 = "2.2.0"
        $v3 = "2.2.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_13965_roundcube_webmail : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain roundcube webmail, affected by CVE-2020-13965"
        severity = "high"
        cve = "CVE-2020-13965"
        cvss = "6.1"
        vendor = "roundcube"
        product = "webmail"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13965"
    strings:
        $p = "webmail" nocase
        $v0 = "1.3.12"
        $v1 = "1.4.0"
        $v2 = "1.4.5"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_access_policy_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip access policy manager, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_access_policy_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip access policy manager" nocase
        $p2 = "big-ip-access-policy-manager" nocase
        $p3 = "big-ip_access_policy_manager" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_advanced_firewall_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced firewall manager, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_advanced_firewall_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip advanced firewall manager" nocase
        $p2 = "big-ip-advanced-firewall-manager" nocase
        $p3 = "big-ip_advanced_firewall_manager" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_advanced_web_application : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced web application firewall, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_advanced_web_application_firewall"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip advanced web application firewall" nocase
        $p2 = "big-ip-advanced-web-application-firewall" nocase
        $p3 = "big-ip_advanced_web_application_firewall" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip analytics, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip analytics" nocase
        $p2 = "big-ip-analytics" nocase
        $p3 = "big-ip_analytics" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_application_acceleration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application acceleration manager, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_acceleration_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip application acceleration manager" nocase
        $p2 = "big-ip-application-acceleration-manager" nocase
        $p3 = "big-ip_application_acceleration_manager" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_application_security_mana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application security manager, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_security_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip application security manager" nocase
        $p2 = "big-ip-application-security-manager" nocase
        $p3 = "big-ip_application_security_manager" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_ddos_hybrid_defender : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip ddos hybrid defender, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_ddos_hybrid_defender"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip ddos hybrid defender" nocase
        $p2 = "big-ip-ddos-hybrid-defender" nocase
        $p3 = "big-ip_ddos_hybrid_defender" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_domain_name_system : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip domain name system, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_domain_name_system"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip domain name system" nocase
        $p2 = "big-ip-domain-name-system" nocase
        $p3 = "big-ip_domain_name_system" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_fraud_protection_service : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip fraud protection service, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_fraud_protection_service"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip fraud protection service" nocase
        $p2 = "big-ip-fraud-protection-service" nocase
        $p3 = "big-ip_fraud_protection_service" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_global_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip global traffic manager, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_global_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip global traffic manager" nocase
        $p2 = "big-ip-global-traffic-manager" nocase
        $p3 = "big-ip_global_traffic_manager" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_link_controller : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip link controller, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_link_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip link controller" nocase
        $p2 = "big-ip-link-controller" nocase
        $p3 = "big-ip_link_controller" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_local_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip local traffic manager, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_local_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip local traffic manager" nocase
        $p2 = "big-ip-local-traffic-manager" nocase
        $p3 = "big-ip_local_traffic_manager" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_big_ip_policy_enforcement_manage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip policy enforcement manager, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_policy_enforcement_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "big-ip policy enforcement manager" nocase
        $p2 = "big-ip-policy-enforcement-manager" nocase
        $p3 = "big-ip_policy_enforcement_manager" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_5902_f5_ssl_orchestrator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 ssl orchestrator, affected by CVE-2020-5902"
        severity = "high"
        cve = "CVE-2020-5902"
        cvss = "9.8"
        vendor = "f5"
        product = "ssl_orchestrator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    strings:
        $p = "ssl orchestrator" nocase
        $p2 = "ssl-orchestrator" nocase
        $p3 = "ssl_orchestrator" nocase
        $v0 = "11.6.1"
        $v1 = "11.6.5.2"
        $v2 = "12.1.0"
        $v3 = "12.1.5.2"
        $v4 = "13.1.0"
        $v5 = "13.1.3.4"
        $v6 = "14.1.0"
        $v7 = "14.1.2.6"
        $v8 = "15.0.0"
        $v9 = "15.0.1.4"
        $v10 = "15.1.0"
        $v11 = "15.1.0.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_15505_mobileiron_enterprise_connector : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mobileiron enterprise connector, affected by CVE-2020-15505"
        severity = "high"
        cve = "CVE-2020-15505"
        cvss = "9.8"
        vendor = "mobileiron"
        product = "enterprise_connector"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15505"
    strings:
        $p = "enterprise connector" nocase
        $p2 = "enterprise-connector" nocase
        $p3 = "enterprise_connector" nocase
        $v0 = "10.3.0.4"
        $v1 = "10.4.0.0"
        $v2 = "10.4.0.4"
        $v3 = "10.5.1.0"
        $v4 = "10.5.1.1"
        $v5 = "10.5.2.0"
        $v6 = "10.5.2.1"
        $v7 = "10.6.0.0"
        $v8 = "10.6.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_15505_mobileiron_monitor_and_reporting_database : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mobileiron monitor and reporting database, affected by CVE-2020-15505"
        severity = "high"
        cve = "CVE-2020-15505"
        cvss = "9.8"
        vendor = "mobileiron"
        product = "monitor_and_reporting_database"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15505"
    strings:
        $p = "monitor and reporting database" nocase
        $p2 = "monitor-and-reporting-database" nocase
        $p3 = "monitor_and_reporting_database" nocase
        $v0 = "2.0.0.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_15505_mobileiron_sentry : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mobileiron sentry, affected by CVE-2020-15505"
        severity = "high"
        cve = "CVE-2020-15505"
        cvss = "9.8"
        vendor = "mobileiron"
        product = "sentry"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15505"
    strings:
        $p = "sentry" nocase
        $v0 = "9.7.0"
        $v1 = "9.7.3"
        $v2 = "9.8.0"
        $v3 = "9.8.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8195_citrix_gateway_plug_in_for_linux : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain citrix gateway plug-in for linux, affected by CVE-2020-8195"
        severity = "high"
        cve = "CVE-2020-8195"
        cvss = "6.5"
        vendor = "citrix"
        product = "gateway_plug-in_for_linux"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8195"
    strings:
        $p = "gateway plug-in for linux" nocase
        $p2 = "gateway-plug-in-for-linux" nocase
        $p3 = "gateway_plug-in_for_linux" nocase
        $v0 = "1.0.0.137"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_6287_sap_netweaver_application_server_jav : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap netweaver application server java, affected by CVE-2020-6287"
        severity = "high"
        cve = "CVE-2020-6287"
        cvss = "10.0"
        vendor = "sap"
        product = "netweaver_application_server_java"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6287"
    strings:
        $p = "netweaver application server java" nocase
        $p2 = "netweaver-application-server-java" nocase
        $p3 = "netweaver_application_server_java" nocase
        $v0 = "7.30"
        $v1 = "7.31"
        $v2 = "7.40"
        $v3 = "7.50"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1147_microsoft_net_core : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft .net core, affected by CVE-2020-1147"
        severity = "high"
        cve = "CVE-2020-1147"
        cvss = "7.8"
        vendor = "microsoft"
        product = ".net_core"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1147"
    strings:
        $p = ".net core" nocase
        $p2 = ".net-core" nocase
        $p3 = ".net_core" nocase
        $v0 = "2.1"
        $v1 = "3.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1147_microsoft_net_framework : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft .net framework, affected by CVE-2020-1147"
        severity = "high"
        cve = "CVE-2020-1147"
        cvss = "7.8"
        vendor = "microsoft"
        product = ".net_framework"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1147"
    strings:
        $p = ".net framework" nocase
        $p2 = ".net-framework" nocase
        $p3 = ".net_framework" nocase
        $v0 = "2.0"
        $v1 = "3.0"
        $v2 = "3.5"
        $v3 = "3.5.1"
        $v4 = "4.5.2"
        $v5 = "4.6"
        $v6 = "4.6.1"
        $v7 = "4.6.2"
        $v8 = "4.7"
        $v9 = "4.7.1"
        $v10 = "4.7.2"
        $v11 = "4.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1147_microsoft_visual_studio_2017 : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft visual studio 2017, affected by CVE-2020-1147"
        severity = "high"
        cve = "CVE-2020-1147"
        cvss = "7.8"
        vendor = "microsoft"
        product = "visual_studio_2017"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1147"
    strings:
        $p = "visual studio 2017" nocase
        $p2 = "visual-studio-2017" nocase
        $p3 = "visual_studio_2017" nocase
        $v0 = "15.0"
        $v1 = "15.9"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1147_microsoft_visual_studio_2019 : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft visual studio 2019, affected by CVE-2020-1147"
        severity = "high"
        cve = "CVE-2020-1147"
        cvss = "7.8"
        vendor = "microsoft"
        product = "visual_studio_2019"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1147"
    strings:
        $p = "visual studio 2019" nocase
        $p2 = "visual-studio-2019" nocase
        $p3 = "visual_studio_2019" nocase
        $v0 = "16.0"
        $v1 = "16.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_14644_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2020-14644"
        severity = "high"
        cve = "CVE-2020-14644"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14644"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "12.2.1.3.0"
        $v1 = "12.2.1.4.0"
        $v2 = "14.1.1.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_11978_apache_airflow : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache airflow, affected by CVE-2020-11978"
        severity = "high"
        cve = "CVE-2020-11978"
        cvss = "8.8"
        vendor = "apache"
        product = "airflow"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11978"
    strings:
        $p = "airflow" nocase
        $v0 = "1.10.11"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3452_cisco_secure_firewall_threat_defense : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cisco secure firewall threat defense, affected by CVE-2020-3452"
        severity = "high"
        cve = "CVE-2020-3452"
        cvss = "7.5"
        vendor = "cisco"
        product = "secure_firewall_threat_defense"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3452"
    strings:
        $p = "secure firewall threat defense" nocase
        $p2 = "secure-firewall-threat-defense" nocase
        $p3 = "secure_firewall_threat_defense" nocase
        $v0 = "6.2.3"
        $v1 = "6.2.3.16"
        $v2 = "6.3.0"
        $v3 = "6.3.0.6"
        $v4 = "6.4.0"
        $v5 = "6.4.0.10"
        $v6 = "6.5.0"
        $v7 = "6.5.0.5"
        $v8 = "6.6.0"
        $v9 = "6.6.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8218_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2020-8218"
        severity = "high"
        cve = "CVE-2020-8218"
        cvss = "7.2"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8218"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "9.0"
        $v1 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8218_ivanti_policy_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti policy secure, affected by CVE-2020-8218"
        severity = "high"
        cve = "CVE-2020-8218"
        cvss = "7.2"
        vendor = "ivanti"
        product = "policy_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8218"
    strings:
        $p = "policy secure" nocase
        $p2 = "policy-secure" nocase
        $p3 = "policy_secure" nocase
        $v0 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8218_pulsesecure_pulse_policy_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain pulsesecure pulse policy secure, affected by CVE-2020-8218"
        severity = "high"
        cve = "CVE-2020-8218"
        cvss = "7.2"
        vendor = "pulsesecure"
        product = "pulse_policy_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8218"
    strings:
        $p = "pulse policy secure" nocase
        $p2 = "pulse-policy-secure" nocase
        $p3 = "pulse_policy_secure" nocase
        $v0 = "9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17496_vbulletin_vbulletin : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vbulletin vbulletin, affected by CVE-2020-17496"
        severity = "high"
        cve = "CVE-2020-17496"
        cvss = "9.8"
        vendor = "vbulletin"
        product = "vbulletin"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17496"
    strings:
        $p = "vbulletin" nocase
        $v0 = "5.5.4"
        $v1 = "5.6.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17463_thedaylightstudio_fuel_cms : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain thedaylightstudio fuel cms, affected by CVE-2020-17463"
        severity = "high"
        cve = "CVE-2020-17463"
        cvss = "9.8"
        vendor = "thedaylightstudio"
        product = "fuel_cms"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17463"
    strings:
        $p = "fuel cms" nocase
        $p2 = "fuel-cms" nocase
        $p3 = "fuel_cms" nocase
        $v0 = "1.4.7"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3433_cisco_anyconnect_secure_mobility_clien : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cisco anyconnect secure mobility client, affected by CVE-2020-3433"
        severity = "high"
        cve = "CVE-2020-3433"
        cvss = "7.8"
        vendor = "cisco"
        product = "anyconnect_secure_mobility_client"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3433"
    strings:
        $p = "anyconnect secure mobility client" nocase
        $p2 = "anyconnect-secure-mobility-client" nocase
        $p3 = "anyconnect_secure_mobility_client" nocase
        $v0 = "4.9.00086"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1472_synology_directory_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain synology directory server, affected by CVE-2020-1472"
        severity = "high"
        cve = "CVE-2020-1472"
        cvss = "5.5"
        vendor = "synology"
        product = "directory_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
    strings:
        $p = "directory server" nocase
        $p2 = "directory-server" nocase
        $p3 = "directory_server" nocase
        $v0 = "4.4.5-0101"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1472_samba_samba : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain samba samba, affected by CVE-2020-1472"
        severity = "high"
        cve = "CVE-2020-1472"
        cvss = "5.5"
        vendor = "samba"
        product = "samba"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
    strings:
        $p = "samba" nocase
        $v0 = "4.10.18"
        $v1 = "4.11.0"
        $v2 = "4.11.13"
        $v3 = "4.12.0"
        $v4 = "4.12.7"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_1472_oracle_zfs_storage_appliance_kit : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle zfs storage appliance kit, affected by CVE-2020-1472"
        severity = "high"
        cve = "CVE-2020-1472"
        cvss = "5.5"
        vendor = "oracle"
        product = "zfs_storage_appliance_kit"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
    strings:
        $p = "zfs storage appliance kit" nocase
        $p2 = "zfs-storage-appliance-kit" nocase
        $p3 = "zfs_storage_appliance_kit" nocase
        $v0 = "8.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_9715_adobe_acrobat_dc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat dc, affected by CVE-2020-9715"
        severity = "high"
        cve = "CVE-2020-9715"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_dc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9715"
    strings:
        $p = "acrobat dc" nocase
        $p2 = "acrobat-dc" nocase
        $p3 = "acrobat_dc" nocase
        $v0 = "15.006.30060"
        $v1 = "15.006.30523"
        $v2 = "15.008.20082"
        $v3 = "17.011.30059"
        $v4 = "17.011.30171"
        $v5 = "20.001.30002"
        $v6 = "20.009.20074"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_9715_adobe_acrobat_reader_dc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader dc, affected by CVE-2020-9715"
        severity = "high"
        cve = "CVE-2020-9715"
        cvss = "7.8"
        vendor = "adobe"
        product = "acrobat_reader_dc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9715"
    strings:
        $p = "acrobat reader dc" nocase
        $p2 = "acrobat-reader-dc" nocase
        $p3 = "acrobat_reader_dc" nocase
        $v0 = "15.006.30060"
        $v1 = "15.006.30523"
        $v2 = "15.008.20082"
        $v3 = "17.011.30059"
        $v4 = "17.011.30171"
        $v5 = "20.001.30002"
        $v6 = "20.009.20074"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_24557_trendmicro_worry_free_business_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain trendmicro worry-free business security, affected by CVE-2020-24557"
        severity = "high"
        cve = "CVE-2020-24557"
        cvss = "7.8"
        vendor = "trendmicro"
        product = "worry-free_business_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24557"
    strings:
        $p = "worry-free business security" nocase
        $p2 = "worry-free-business-security" nocase
        $p3 = "worry-free_business_security" nocase
        $v0 = "10.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_25213_filemanagerpro_file_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain filemanagerpro file manager, affected by CVE-2020-25213"
        severity = "high"
        cve = "CVE-2020-25213"
        cvss = "10.0"
        vendor = "filemanagerpro"
        product = "file_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-25213"
    strings:
        $p = "file manager" nocase
        $p2 = "file-manager" nocase
        $p3 = "file_manager" nocase
        $v0 = "6.9"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_25223_sophos_unified_threat_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sophos unified threat management, affected by CVE-2020-25223"
        severity = "high"
        cve = "CVE-2020-25223"
        cvss = "9.8"
        vendor = "sophos"
        product = "unified_threat_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-25223"
    strings:
        $p = "unified threat management" nocase
        $p2 = "unified-threat-management" nocase
        $p3 = "unified_threat_management" nocase
        $v0 = "9.511"
        $v1 = "9.600"
        $v2 = "9.607"
        $v3 = "9.700"
        $v4 = "9.705"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8243_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2020-8243"
        severity = "high"
        cve = "CVE-2020-8243"
        cvss = "7.2"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8243"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "9.0"
        $v1 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8243_ivanti_policy_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti policy secure, affected by CVE-2020-8243"
        severity = "high"
        cve = "CVE-2020-8243"
        cvss = "7.2"
        vendor = "ivanti"
        product = "policy_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8243"
    strings:
        $p = "policy secure" nocase
        $p2 = "policy-secure" nocase
        $p3 = "policy_secure" nocase
        $v0 = "9.0"
        $v1 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3992_vmware_cloud_foundation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware cloud foundation, affected by CVE-2020-3992"
        severity = "high"
        cve = "CVE-2020-3992"
        cvss = "9.8"
        vendor = "vmware"
        product = "cloud_foundation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3992"
    strings:
        $p = "cloud foundation" nocase
        $p2 = "cloud-foundation" nocase
        $p3 = "cloud_foundation" nocase
        $v0 = "3.0"
        $v1 = "3.10.1.2"
        $v2 = "4.0"
        $v3 = "4.1.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_14864_oracle_business_intelligence : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle business intelligence, affected by CVE-2020-14864"
        severity = "high"
        cve = "CVE-2020-14864"
        cvss = "7.5"
        vendor = "oracle"
        product = "business_intelligence"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14864"
    strings:
        $p = "business intelligence" nocase
        $p2 = "business-intelligence" nocase
        $p3 = "business_intelligence" nocase
        $v0 = "12.2.1.3.0"
        $v1 = "12.2.1.4.0"
        $v2 = "5.5.0.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_14882_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2020-14882"
        severity = "high"
        cve = "CVE-2020-14882"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14882"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.3.0"
        $v3 = "12.2.1.4.0"
        $v4 = "14.1.1.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_14883_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2020-14883"
        severity = "high"
        cve = "CVE-2020-14883"
        cvss = "7.2"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14883"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.3.0"
        $v3 = "12.2.1.4.0"
        $v4 = "14.1.1.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_3580_cisco_secure_firewall_threat_defense : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cisco secure firewall threat defense, affected by CVE-2020-3580"
        severity = "high"
        cve = "CVE-2020-3580"
        cvss = "6.1"
        vendor = "cisco"
        product = "secure_firewall_threat_defense"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3580"
    strings:
        $p = "secure firewall threat defense" nocase
        $p2 = "secure-firewall-threat-defense" nocase
        $p3 = "secure_firewall_threat_defense" nocase
        $v0 = "6.4.0.12"
        $v1 = "6.5.0"
        $v2 = "6.6.4"
        $v3 = "6.7.0"
        $v4 = "6.7.0.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_8260_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2020-8260"
        severity = "high"
        cve = "CVE-2020-8260"
        cvss = "7.2"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8260"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "9.0"
        $v1 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_14750_oracle_weblogic_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle weblogic server, affected by CVE-2020-14750"
        severity = "high"
        cve = "CVE-2020-14750"
        cvss = "9.8"
        vendor = "oracle"
        product = "weblogic_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14750"
    strings:
        $p = "weblogic server" nocase
        $p2 = "weblogic-server" nocase
        $p3 = "weblogic_server" nocase
        $v0 = "10.3.6.0.0"
        $v1 = "12.1.3.0.0"
        $v2 = "12.2.1.3.0"
        $v3 = "12.2.1.4.0"
        $v4 = "14.1.1.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_15999_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2020-15999"
        severity = "high"
        cve = "CVE-2020-15999"
        cvss = "9.6"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15999"
    strings:
        $p = "chrome" nocase
        $v0 = "86.0.4240.111"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_15999_freetype_freetype : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain freetype freetype, affected by CVE-2020-15999"
        severity = "high"
        cve = "CVE-2020-15999"
        cvss = "9.6"
        vendor = "freetype"
        product = "freetype"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15999"
    strings:
        $p = "freetype" nocase
        $v0 = "2.10.4"
        $v1 = "2.6.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_15999_opensuse_backports_sle : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain opensuse backports sle, affected by CVE-2020-15999"
        severity = "high"
        cve = "CVE-2020-15999"
        cvss = "9.6"
        vendor = "opensuse"
        product = "backports_sle"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15999"
    strings:
        $p = "backports sle" nocase
        $p2 = "backports-sle" nocase
        $p3 = "backports_sle" nocase
        $v0 = "15.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_16009_cefsharp_cefsharp : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain cefsharp cefsharp, affected by CVE-2020-16009"
        severity = "high"
        cve = "CVE-2020-16009"
        cvss = "8.8"
        vendor = "cefsharp"
        product = "cefsharp"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16009"
    strings:
        $p = "cefsharp" nocase
        $v0 = "86.0.241"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_16009_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2020-16009"
        severity = "high"
        cve = "CVE-2020-16009"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16009"
    strings:
        $p = "chrome" nocase
        $v0 = "86.0.4240.183"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_16009_microsoft_edge_chromium : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft edge chromium, affected by CVE-2020-16009"
        severity = "high"
        cve = "CVE-2020-16009"
        cvss = "8.8"
        vendor = "microsoft"
        product = "edge_chromium"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16009"
    strings:
        $p = "edge chromium" nocase
        $p2 = "edge-chromium" nocase
        $p3 = "edge_chromium" nocase
        $v0 = "86.0.4240.183"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_16009_opensuse_backports_sle : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain opensuse backports sle, affected by CVE-2020-16009"
        severity = "high"
        cve = "CVE-2020-16009"
        cvss = "8.8"
        vendor = "opensuse"
        product = "backports_sle"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16009"
    strings:
        $p = "backports sle" nocase
        $p2 = "backports-sle" nocase
        $p3 = "backports_sle" nocase
        $v0 = "15.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_16010_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2020-16010"
        severity = "high"
        cve = "CVE-2020-16010"
        cvss = "9.6"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16010"
    strings:
        $p = "chrome" nocase
        $v0 = "86.0.4240.185"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_13927_apache_airflow : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache airflow, affected by CVE-2020-13927"
        severity = "high"
        cve = "CVE-2020-13927"
        cvss = "9.8"
        vendor = "apache"
        product = "airflow"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13927"
    strings:
        $p = "airflow" nocase
        $v0 = "1.10.11"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_28949_php_archive_tar : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain php archive tar, affected by CVE-2020-28949"
        severity = "high"
        cve = "CVE-2020-28949"
        cvss = "7.8"
        vendor = "php"
        product = "archive_tar"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-28949"
    strings:
        $p = "archive tar" nocase
        $p2 = "archive-tar" nocase
        $p3 = "archive_tar" nocase
        $v0 = "1.4.12"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_28949_drupal_drupal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain drupal drupal, affected by CVE-2020-28949"
        severity = "high"
        cve = "CVE-2020-28949"
        cvss = "7.8"
        vendor = "drupal"
        product = "drupal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-28949"
    strings:
        $p = "drupal" nocase
        $v0 = "7.0"
        $v1 = "7.75"
        $v2 = "8.0.0"
        $v3 = "8.8.0"
        $v4 = "8.8.12"
        $v5 = "8.9.10"
        $v6 = "9.0.0"
        $v7 = "9.0.9"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_13671_drupal_drupal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain drupal drupal, affected by CVE-2020-13671"
        severity = "high"
        cve = "CVE-2020-13671"
        cvss = "8.8"
        vendor = "drupal"
        product = "drupal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13671"
    strings:
        $p = "drupal" nocase
        $v0 = "7.0"
        $v1 = "7.74"
        $v2 = "8.8.0"
        $v3 = "8.8.11"
        $v4 = "8.9.0"
        $v5 = "8.9.9"
        $v6 = "9.0.0"
        $v7 = "9.0.8"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_4006_vmware_identity_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware identity manager, affected by CVE-2020-4006"
        severity = "high"
        cve = "CVE-2020-4006"
        cvss = "9.1"
        vendor = "vmware"
        product = "identity_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4006"
    strings:
        $p = "identity manager" nocase
        $p2 = "identity-manager" nocase
        $p3 = "identity_manager" nocase
        $v0 = "3.3.1"
        $v1 = "3.3.2"
        $v2 = "3.3.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_4006_vmware_identity_manager_connector : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware identity manager connector, affected by CVE-2020-4006"
        severity = "high"
        cve = "CVE-2020-4006"
        cvss = "9.1"
        vendor = "vmware"
        product = "identity_manager_connector"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4006"
    strings:
        $p = "identity manager connector" nocase
        $p2 = "identity-manager-connector" nocase
        $p3 = "identity_manager_connector" nocase
        $v0 = "3.3.1"
        $v1 = "3.3.2"
        $v2 = "3.3.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_4006_vmware_one_access : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware one access, affected by CVE-2020-4006"
        severity = "high"
        cve = "CVE-2020-4006"
        cvss = "9.1"
        vendor = "vmware"
        product = "one_access"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4006"
    strings:
        $p = "one access" nocase
        $p2 = "one-access" nocase
        $p3 = "one_access" nocase
        $v0 = "20.01"
        $v1 = "20.10"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_4006_vmware_cloud_foundation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware cloud foundation, affected by CVE-2020-4006"
        severity = "high"
        cve = "CVE-2020-4006"
        cvss = "9.1"
        vendor = "vmware"
        product = "cloud_foundation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4006"
    strings:
        $p = "cloud foundation" nocase
        $p2 = "cloud-foundation" nocase
        $p3 = "cloud_foundation" nocase
        $v0 = "4.0"
        $v1 = "4.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_4006_vmware_vrealize_suite_lifecycle_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vrealize suite lifecycle manager, affected by CVE-2020-4006"
        severity = "high"
        cve = "CVE-2020-4006"
        cvss = "9.1"
        vendor = "vmware"
        product = "vrealize_suite_lifecycle_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4006"
    strings:
        $p = "vrealize suite lifecycle manager" nocase
        $p2 = "vrealize-suite-lifecycle-manager" nocase
        $p3 = "vrealize_suite_lifecycle_manager" nocase
        $v0 = "8.0"
        $v1 = "8.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_27932_apple_icloud : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apple icloud, affected by CVE-2020-27932"
        severity = "high"
        cve = "CVE-2020-27932"
        cvss = "7.8"
        vendor = "apple"
        product = "icloud"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-27932"
    strings:
        $p = "icloud" nocase
        $v0 = "11.5"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_27932_apple_itunes : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apple itunes, affected by CVE-2020-27932"
        severity = "high"
        cve = "CVE-2020-27932"
        cvss = "7.8"
        vendor = "apple"
        product = "itunes"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-27932"
    strings:
        $p = "itunes" nocase
        $v0 = "12.11"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17530_apache_struts : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache struts, affected by CVE-2020-17530"
        severity = "high"
        cve = "CVE-2020-17530"
        cvss = "9.8"
        vendor = "apache"
        product = "struts"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17530"
    strings:
        $p = "struts" nocase
        $v0 = "2.0.0"
        $v1 = "2.5.30"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17530_oracle_business_intelligence : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle business intelligence, affected by CVE-2020-17530"
        severity = "high"
        cve = "CVE-2020-17530"
        cvss = "9.8"
        vendor = "oracle"
        product = "business_intelligence"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17530"
    strings:
        $p = "business intelligence" nocase
        $p2 = "business-intelligence" nocase
        $p3 = "business_intelligence" nocase
        $v0 = "12.2.1.3.0"
        $v1 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17530_oracle_communications_diameter_intellig : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications diameter intelligence hub, affected by CVE-2020-17530"
        severity = "high"
        cve = "CVE-2020-17530"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_diameter_intelligence_hub"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17530"
    strings:
        $p = "communications diameter intelligence hub" nocase
        $p2 = "communications-diameter-intelligence-hub" nocase
        $p3 = "communications_diameter_intelligence_hub" nocase
        $v0 = "8.0.0"
        $v1 = "8.1.0"
        $v2 = "8.2.0"
        $v3 = "8.2.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17530_oracle_communications_policy_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications policy management, affected by CVE-2020-17530"
        severity = "high"
        cve = "CVE-2020-17530"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_policy_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17530"
    strings:
        $p = "communications policy management" nocase
        $p2 = "communications-policy-management" nocase
        $p3 = "communications_policy_management" nocase
        $v0 = "12.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17530_oracle_communications_pricing_design_ce : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications pricing design center, affected by CVE-2020-17530"
        severity = "high"
        cve = "CVE-2020-17530"
        cvss = "9.8"
        vendor = "oracle"
        product = "communications_pricing_design_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17530"
    strings:
        $p = "communications pricing design center" nocase
        $p2 = "communications-pricing-design-center" nocase
        $p3 = "communications_pricing_design_center" nocase
        $v0 = "12.0.0.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17530_oracle_financial_services_data_integrat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle financial services data integration hub, affected by CVE-2020-17530"
        severity = "high"
        cve = "CVE-2020-17530"
        cvss = "9.8"
        vendor = "oracle"
        product = "financial_services_data_integration_hub"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17530"
    strings:
        $p = "financial services data integration hub" nocase
        $p2 = "financial-services-data-integration-hub" nocase
        $p3 = "financial_services_data_integration_hub" nocase
        $v0 = "8.0.3"
        $v1 = "8.0.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17530_oracle_hospitality_opera_5 : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle hospitality opera 5, affected by CVE-2020-17530"
        severity = "high"
        cve = "CVE-2020-17530"
        cvss = "9.8"
        vendor = "oracle"
        product = "hospitality_opera_5"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17530"
    strings:
        $p = "hospitality opera 5" nocase
        $p2 = "hospitality-opera-5" nocase
        $p3 = "hospitality_opera_5" nocase
        $v0 = "5.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17530_oracle_mysql_enterprise_monitor : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle mysql enterprise monitor, affected by CVE-2020-17530"
        severity = "high"
        cve = "CVE-2020-17530"
        cvss = "9.8"
        vendor = "oracle"
        product = "mysql_enterprise_monitor"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17530"
    strings:
        $p = "mysql enterprise monitor" nocase
        $p2 = "mysql-enterprise-monitor" nocase
        $p3 = "mysql_enterprise_monitor" nocase
        $v0 = "8.0.23"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_35730_roundcube_webmail : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain roundcube webmail, affected by CVE-2020-35730"
        severity = "high"
        cve = "CVE-2020-35730"
        cvss = "6.1"
        vendor = "roundcube"
        product = "webmail"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35730"
    strings:
        $p = "webmail" nocase
        $v0 = "1.2.13"
        $v1 = "1.3.0"
        $v2 = "1.3.16"
        $v3 = "1.4"
        $v4 = "1.4.10"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_10148_solarwinds_orion_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain solarwinds orion platform, affected by CVE-2020-10148"
        severity = "high"
        cve = "CVE-2020-10148"
        cvss = "9.8"
        vendor = "solarwinds"
        product = "orion_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10148"
    strings:
        $p = "orion platform" nocase
        $p2 = "orion-platform" nocase
        $p3 = "orion_platform" nocase
        $v0 = "2019.4"
        $v1 = "2020.2"
        $v2 = "2020.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_17519_apache_flink : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache flink, affected by CVE-2020-17519"
        severity = "high"
        cve = "CVE-2020-17519"
        cvss = "7.5"
        vendor = "apache"
        product = "flink"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17519"
    strings:
        $p = "flink" nocase
        $v0 = "1.11.0"
        $v1 = "1.11.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_16013_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2020-16013"
        severity = "high"
        cve = "CVE-2020-16013"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16013"
    strings:
        $p = "chrome" nocase
        $v0 = "86.0.4240.198"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_16017_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2020-16017"
        severity = "high"
        cve = "CVE-2020-16017"
        cvss = "9.6"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16017"
    strings:
        $p = "chrome" nocase
        $v0 = "86.0.4240.198"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_3129_facade_ignition : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain facade ignition, affected by CVE-2021-3129"
        severity = "high"
        cve = "CVE-2021-3129"
        cvss = "9.8"
        vendor = "facade"
        product = "ignition"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3129"
    strings:
        $p = "ignition" nocase
        $v0 = "2.5.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_6572_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2020-6572"
        severity = "high"
        cve = "CVE-2020-6572"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6572"
    strings:
        $p = "chrome" nocase
        $v0 = "81.0.4044.92"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_36193_php_archive_tar : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain php archive tar, affected by CVE-2020-36193"
        severity = "high"
        cve = "CVE-2020-36193"
        cvss = "7.5"
        vendor = "php"
        product = "archive_tar"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-36193"
    strings:
        $p = "archive tar" nocase
        $p2 = "archive-tar" nocase
        $p3 = "archive_tar" nocase
        $v0 = "1.4.11"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_36193_drupal_drupal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain drupal drupal, affected by CVE-2020-36193"
        severity = "high"
        cve = "CVE-2020-36193"
        cvss = "7.5"
        vendor = "drupal"
        product = "drupal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-36193"
    strings:
        $p = "drupal" nocase
        $v0 = "7.0"
        $v1 = "7.78"
        $v2 = "8.9.0"
        $v3 = "8.9.13"
        $v4 = "9.0.0"
        $v5 = "9.0.11"
        $v6 = "9.1.0"
        $v7 = "9.1.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_3156_mcafee_web_gateway : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mcafee web gateway, affected by CVE-2021-3156"
        severity = "high"
        cve = "CVE-2021-3156"
        cvss = "7.8"
        vendor = "mcafee"
        product = "web_gateway"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"
    strings:
        $p = "web gateway" nocase
        $p2 = "web-gateway" nocase
        $p3 = "web_gateway" nocase
        $v0 = "10.0.4"
        $v1 = "8.2.17"
        $v2 = "9.2.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_3156_synology_diskstation_manager_unified_cont : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain synology diskstation manager unified controller, affected by CVE-2021-3156"
        severity = "high"
        cve = "CVE-2021-3156"
        cvss = "7.8"
        vendor = "synology"
        product = "diskstation_manager_unified_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"
    strings:
        $p = "diskstation manager unified controller" nocase
        $p2 = "diskstation-manager-unified-controller" nocase
        $p3 = "diskstation_manager_unified_controller" nocase
        $v0 = "3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_3156_beyondtrust_privilege_management_for_mac : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain beyondtrust privilege management for mac, affected by CVE-2021-3156"
        severity = "high"
        cve = "CVE-2021-3156"
        cvss = "7.8"
        vendor = "beyondtrust"
        product = "privilege_management_for_mac"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"
    strings:
        $p = "privilege management for mac" nocase
        $p2 = "privilege-management-for-mac" nocase
        $p3 = "privilege_management_for_mac" nocase
        $v0 = "21.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_3156_oracle_communications_performance_intel : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications performance intelligence center, affected by CVE-2021-3156"
        severity = "high"
        cve = "CVE-2021-3156"
        cvss = "7.8"
        vendor = "oracle"
        product = "communications_performance_intelligence_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"
    strings:
        $p = "communications performance intelligence center" nocase
        $p2 = "communications-performance-intelligence-center" nocase
        $p3 = "communications_performance_intelligence_center" nocase
        $v0 = "10.3.0.0.0"
        $v1 = "10.3.0.2.1"
        $v2 = "10.4.0.1.0"
        $v3 = "10.4.0.3.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_3156_oracle_tekelec_platform_distribution : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle tekelec platform distribution, affected by CVE-2021-3156"
        severity = "high"
        cve = "CVE-2021-3156"
        cvss = "7.8"
        vendor = "oracle"
        product = "tekelec_platform_distribution"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"
    strings:
        $p = "tekelec platform distribution" nocase
        $p2 = "tekelec-platform-distribution" nocase
        $p3 = "tekelec_platform_distribution" nocase
        $v0 = "7.4.0"
        $v1 = "7.7.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2020_2506_qnap_helpdesk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain qnap helpdesk, affected by CVE-2020-2506"
        severity = "high"
        cve = "CVE-2020-2506"
        cvss = "7.3"
        vendor = "qnap"
        product = "helpdesk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2506"
    strings:
        $p = "helpdesk" nocase
        $v0 = "3.0.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22502_microfocus_operation_bridge_reporter : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microfocus operation bridge reporter, affected by CVE-2021-22502"
        severity = "high"
        cve = "CVE-2021-22502"
        cvss = "9.8"
        vendor = "microfocus"
        product = "operation_bridge_reporter"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22502"
    strings:
        $p = "operation bridge reporter" nocase
        $p2 = "operation-bridge-reporter" nocase
        $p3 = "operation_bridge_reporter" nocase
        $v0 = "10.40"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21148_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-21148"
        severity = "high"
        cve = "CVE-2021-21148"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21148"
    strings:
        $p = "chrome" nocase
        $v0 = "88.0.4324.150"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_23874_mcafee_total_protection : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain mcafee total protection, affected by CVE-2021-23874"
        severity = "high"
        cve = "CVE-2021-23874"
        cvss = "8.2"
        vendor = "mcafee"
        product = "total_protection"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-23874"
    strings:
        $p = "total protection" nocase
        $p2 = "total-protection" nocase
        $p3 = "total_protection" nocase
        $v0 = "16.0.30"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21017_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2021-21017"
        severity = "high"
        cve = "CVE-2021-21017"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21017"
    strings:
        $p = "acrobat" nocase
        $v0 = "17.0"
        $v1 = "17.011.30188"
        $v2 = "20.0"
        $v3 = "20.001.30018"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21017_adobe_acrobat_dc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat dc, affected by CVE-2021-21017"
        severity = "high"
        cve = "CVE-2021-21017"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_dc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21017"
    strings:
        $p = "acrobat dc" nocase
        $p2 = "acrobat-dc" nocase
        $p3 = "acrobat_dc" nocase
        $v0 = "20.013.20074"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21017_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2021-21017"
        severity = "high"
        cve = "CVE-2021-21017"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21017"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "17.0"
        $v1 = "17.011.30188"
        $v2 = "20.0"
        $v3 = "20.001.300183"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21017_adobe_acrobat_reader_dc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader dc, affected by CVE-2021-21017"
        severity = "high"
        cve = "CVE-2021-21017"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader_dc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21017"
    strings:
        $p = "acrobat reader dc" nocase
        $p2 = "acrobat-reader-dc" nocase
        $p3 = "acrobat_reader_dc" nocase
        $v0 = "20.013.20074"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21311_adminer_adminer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adminer adminer, affected by CVE-2021-21311"
        severity = "high"
        cve = "CVE-2021-21311"
        cvss = "7.2"
        vendor = "adminer"
        product = "adminer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21311"
    strings:
        $p = "adminer" nocase
        $v0 = "4.0.0"
        $v1 = "4.7.9"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_25296_nagios_nagios_xi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain nagios nagios xi, affected by CVE-2021-25296"
        severity = "high"
        cve = "CVE-2021-25296"
        cvss = "8.8"
        vendor = "nagios"
        product = "nagios_xi"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25296"
    strings:
        $p = "nagios xi" nocase
        $p2 = "nagios-xi" nocase
        $p3 = "nagios_xi" nocase
        $v0 = "5.5.6"
        $v1 = "5.7.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_25297_nagios_nagios_xi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain nagios nagios xi, affected by CVE-2021-25297"
        severity = "high"
        cve = "CVE-2021-25297"
        cvss = "8.8"
        vendor = "nagios"
        product = "nagios_xi"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25297"
    strings:
        $p = "nagios xi" nocase
        $p2 = "nagios-xi" nocase
        $p3 = "nagios_xi" nocase
        $v0 = "5.5.6"
        $v1 = "5.7.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_25298_nagios_nagios_xi : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain nagios nagios xi, affected by CVE-2021-25298"
        severity = "high"
        cve = "CVE-2021-25298"
        cvss = "8.8"
        vendor = "nagios"
        product = "nagios_xi"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-25298"
    strings:
        $p = "nagios xi" nocase
        $p2 = "nagios-xi" nocase
        $p3 = "nagios_xi" nocase
        $v0 = "5.5.6"
        $v1 = "5.7.5"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21315_systeminformation_systeminformation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain systeminformation systeminformation, affected by CVE-2021-21315"
        severity = "high"
        cve = "CVE-2021-21315"
        cvss = "7.1"
        vendor = "systeminformation"
        product = "systeminformation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21315"
    strings:
        $p = "systeminformation" nocase
        $v0 = "5.3.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21315_apache_cordova : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache cordova, affected by CVE-2021-21315"
        severity = "high"
        cve = "CVE-2021-21315"
        cvss = "7.1"
        vendor = "apache"
        product = "cordova"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21315"
    strings:
        $p = "cordova" nocase
        $v0 = "10.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21972_vmware_cloud_foundation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware cloud foundation, affected by CVE-2021-21972"
        severity = "high"
        cve = "CVE-2021-21972"
        cvss = "9.8"
        vendor = "vmware"
        product = "cloud_foundation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21972"
    strings:
        $p = "cloud foundation" nocase
        $p2 = "cloud-foundation" nocase
        $p3 = "cloud_foundation" nocase
        $v0 = "3.0"
        $v1 = "3.10.1.2"
        $v2 = "4.0"
        $v3 = "4.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21972_vmware_vcenter_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vcenter server, affected by CVE-2021-21972"
        severity = "high"
        cve = "CVE-2021-21972"
        cvss = "9.8"
        vendor = "vmware"
        product = "vcenter_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21972"
    strings:
        $p = "vcenter server" nocase
        $p2 = "vcenter-server" nocase
        $p3 = "vcenter_server" nocase
        $v0 = "6.5"
        $v1 = "6.7"
        $v2 = "7.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21973_vmware_cloud_foundation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware cloud foundation, affected by CVE-2021-21973"
        severity = "high"
        cve = "CVE-2021-21973"
        cvss = "5.3"
        vendor = "vmware"
        product = "cloud_foundation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21973"
    strings:
        $p = "cloud foundation" nocase
        $p2 = "cloud-foundation" nocase
        $p3 = "cloud_foundation" nocase
        $v0 = "3.0"
        $v1 = "3.10.1.2"
        $v2 = "4.0"
        $v3 = "4.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21973_vmware_vcenter_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vcenter server, affected by CVE-2021-21973"
        severity = "high"
        cve = "CVE-2021-21973"
        cvss = "5.3"
        vendor = "vmware"
        product = "vcenter_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21973"
    strings:
        $p = "vcenter server" nocase
        $p2 = "vcenter-server" nocase
        $p3 = "vcenter_server" nocase
        $v0 = "6.5"
        $v1 = "6.7"
        $v2 = "7.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_27876_veritas_backup_exec : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain veritas backup exec, affected by CVE-2021-27876"
        severity = "high"
        cve = "CVE-2021-27876"
        cvss = "8.1"
        vendor = "veritas"
        product = "backup_exec"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27876"
    strings:
        $p = "backup exec" nocase
        $p2 = "backup-exec" nocase
        $p3 = "backup_exec" nocase
        $v0 = "21.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_27877_veritas_backup_exec : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain veritas backup exec, affected by CVE-2021-27877"
        severity = "high"
        cve = "CVE-2021-27877"
        cvss = "8.2"
        vendor = "veritas"
        product = "backup_exec"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27877"
    strings:
        $p = "backup exec" nocase
        $p2 = "backup-exec" nocase
        $p3 = "backup_exec" nocase
        $v0 = "21.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_27878_veritas_backup_exec : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain veritas backup exec, affected by CVE-2021-27878"
        severity = "high"
        cve = "CVE-2021-27878"
        cvss = "8.8"
        vendor = "veritas"
        product = "backup_exec"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27878"
    strings:
        $p = "backup exec" nocase
        $p2 = "backup-exec" nocase
        $p3 = "backup_exec" nocase
        $v0 = "21.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22681_rockwellautomation_factorytalk_services_platform : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain rockwellautomation factorytalk services platform, affected by CVE-2021-22681"
        severity = "high"
        cve = "CVE-2021-22681"
        cvss = "9.8"
        vendor = "rockwellautomation"
        product = "factorytalk_services_platform"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22681"
    strings:
        $p = "factorytalk services platform" nocase
        $p2 = "factorytalk-services-platform" nocase
        $p3 = "factorytalk_services_platform" nocase
        $v0 = "2.10"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22681_rockwellautomation_studio_5000_logix_designer : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain rockwellautomation studio 5000 logix designer, affected by CVE-2021-22681"
        severity = "high"
        cve = "CVE-2021-22681"
        cvss = "9.8"
        vendor = "rockwellautomation"
        product = "studio_5000_logix_designer"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22681"
    strings:
        $p = "studio 5000 logix designer" nocase
        $p2 = "studio-5000-logix-designer" nocase
        $p3 = "studio_5000_logix_designer" nocase
        $v0 = "21.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21166_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-21166"
        severity = "high"
        cve = "CVE-2021-21166"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21166"
    strings:
        $p = "chrome" nocase
        $v0 = "89.0.4389.72"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21193_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-21193"
        severity = "high"
        cve = "CVE-2021-21193"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21193"
    strings:
        $p = "chrome" nocase
        $v0 = "89.0.4389.90"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22506_microfocus_access_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microfocus access manager, affected by CVE-2021-22506"
        severity = "high"
        cve = "CVE-2021-22506"
        cvss = "7.5"
        vendor = "microfocus"
        product = "access_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22506"
    strings:
        $p = "access manager" nocase
        $p2 = "access-manager" nocase
        $p3 = "access_manager" nocase
        $v0 = "5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_access_policy_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip access policy manager, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_access_policy_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip access policy manager" nocase
        $p2 = "big-ip-access-policy-manager" nocase
        $p3 = "big-ip_access_policy_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_advanced_firewall_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced firewall manager, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_advanced_firewall_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip advanced firewall manager" nocase
        $p2 = "big-ip-advanced-firewall-manager" nocase
        $p3 = "big-ip_advanced_firewall_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_advanced_web_application : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced web application firewall, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_advanced_web_application_firewall"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip advanced web application firewall" nocase
        $p2 = "big-ip-advanced-web-application-firewall" nocase
        $p3 = "big-ip_advanced_web_application_firewall" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip analytics, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip analytics" nocase
        $p2 = "big-ip-analytics" nocase
        $p3 = "big-ip_analytics" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_application_acceleration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application acceleration manager, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_acceleration_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip application acceleration manager" nocase
        $p2 = "big-ip-application-acceleration-manager" nocase
        $p3 = "big-ip_application_acceleration_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_application_security_mana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application security manager, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_security_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip application security manager" nocase
        $p2 = "big-ip-application-security-manager" nocase
        $p3 = "big-ip_application_security_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_ddos_hybrid_defender : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip ddos hybrid defender, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_ddos_hybrid_defender"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip ddos hybrid defender" nocase
        $p2 = "big-ip-ddos-hybrid-defender" nocase
        $p3 = "big-ip_ddos_hybrid_defender" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_domain_name_system : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip domain name system, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_domain_name_system"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip domain name system" nocase
        $p2 = "big-ip-domain-name-system" nocase
        $p3 = "big-ip_domain_name_system" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_fraud_protection_service : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip fraud protection service, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_fraud_protection_service"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip fraud protection service" nocase
        $p2 = "big-ip-fraud-protection-service" nocase
        $p3 = "big-ip_fraud_protection_service" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_global_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip global traffic manager, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_global_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip global traffic manager" nocase
        $p2 = "big-ip-global-traffic-manager" nocase
        $p3 = "big-ip_global_traffic_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_link_controller : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip link controller, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_link_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip link controller" nocase
        $p2 = "big-ip-link-controller" nocase
        $p3 = "big-ip_link_controller" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_local_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip local traffic manager, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_local_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip local traffic manager" nocase
        $p2 = "big-ip-local-traffic-manager" nocase
        $p3 = "big-ip_local_traffic_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_ip_policy_enforcement_manage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip policy enforcement manager, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_policy_enforcement_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-ip policy enforcement manager" nocase
        $p2 = "big-ip-policy-enforcement-manager" nocase
        $p3 = "big-ip_policy_enforcement_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_big_iq_centralized_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-iq centralized management, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "big-iq_centralized_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "big-iq centralized management" nocase
        $p2 = "big-iq-centralized-management" nocase
        $p3 = "big-iq_centralized_management" nocase
        $v0 = "6.0.0"
        $v1 = "6.1.0"
        $v2 = "7.0.0"
        $v3 = "7.0.0.2"
        $v4 = "7.1.0"
        $v5 = "7.1.0.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22986_f5_ssl_orchestrator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 ssl orchestrator, affected by CVE-2021-22986"
        severity = "high"
        cve = "CVE-2021-22986"
        cvss = "9.8"
        vendor = "f5"
        product = "ssl_orchestrator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22986"
    strings:
        $p = "ssl orchestrator" nocase
        $p2 = "ssl-orchestrator" nocase
        $p3 = "ssl_orchestrator" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21975_vmware_cloud_foundation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware cloud foundation, affected by CVE-2021-21975"
        severity = "high"
        cve = "CVE-2021-21975"
        cvss = "7.5"
        vendor = "vmware"
        product = "cloud_foundation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21975"
    strings:
        $p = "cloud foundation" nocase
        $p2 = "cloud-foundation" nocase
        $p3 = "cloud_foundation" nocase
        $v0 = "3.0"
        $v1 = "3.0.1"
        $v2 = "3.0.1.1"
        $v3 = "3.10"
        $v4 = "3.5"
        $v5 = "3.5.1"
        $v6 = "3.7"
        $v7 = "3.7.1"
        $v8 = "3.7.2"
        $v9 = "3.8"
        $v10 = "3.8.1"
        $v11 = "3.9"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21975_vmware_vrealize_operations_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vrealize operations manager, affected by CVE-2021-21975"
        severity = "high"
        cve = "CVE-2021-21975"
        cvss = "7.5"
        vendor = "vmware"
        product = "vrealize_operations_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21975"
    strings:
        $p = "vrealize operations manager" nocase
        $p2 = "vrealize-operations-manager" nocase
        $p3 = "vrealize_operations_manager" nocase
        $v0 = "7.0.0"
        $v1 = "7.5.0"
        $v2 = "8.0.0"
        $v3 = "8.0.1"
        $v4 = "8.1.0"
        $v5 = "8.1.1"
        $v6 = "8.2.0"
        $v7 = "8.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21975_vmware_vrealize_suite_lifecycle_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vrealize suite lifecycle manager, affected by CVE-2021-21975"
        severity = "high"
        cve = "CVE-2021-21975"
        cvss = "7.5"
        vendor = "vmware"
        product = "vrealize_suite_lifecycle_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21975"
    strings:
        $p = "vrealize suite lifecycle manager" nocase
        $p2 = "vrealize-suite-lifecycle-manager" nocase
        $p3 = "vrealize_suite_lifecycle_manager" nocase
        $v0 = "8.0"
        $v1 = "8.0.1"
        $v2 = "8.1"
        $v3 = "8.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_access_policy_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip access policy manager, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_access_policy_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip access policy manager" nocase
        $p2 = "big-ip-access-policy-manager" nocase
        $p3 = "big-ip_access_policy_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_advanced_firewall_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced firewall manager, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_advanced_firewall_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip advanced firewall manager" nocase
        $p2 = "big-ip-advanced-firewall-manager" nocase
        $p3 = "big-ip_advanced_firewall_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_advanced_web_application : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip advanced web application firewall, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_advanced_web_application_firewall"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip advanced web application firewall" nocase
        $p2 = "big-ip-advanced-web-application-firewall" nocase
        $p3 = "big-ip_advanced_web_application_firewall" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_analytics : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip analytics, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_analytics"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip analytics" nocase
        $p2 = "big-ip-analytics" nocase
        $p3 = "big-ip_analytics" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_application_acceleration : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application acceleration manager, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_acceleration_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip application acceleration manager" nocase
        $p2 = "big-ip-application-acceleration-manager" nocase
        $p3 = "big-ip_application_acceleration_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_application_security_mana : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip application security manager, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_application_security_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip application security manager" nocase
        $p2 = "big-ip-application-security-manager" nocase
        $p3 = "big-ip_application_security_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_ddos_hybrid_defender : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip ddos hybrid defender, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_ddos_hybrid_defender"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip ddos hybrid defender" nocase
        $p2 = "big-ip-ddos-hybrid-defender" nocase
        $p3 = "big-ip_ddos_hybrid_defender" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_domain_name_system : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip domain name system, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_domain_name_system"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip domain name system" nocase
        $p2 = "big-ip-domain-name-system" nocase
        $p3 = "big-ip_domain_name_system" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_fraud_protection_service : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip fraud protection service, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_fraud_protection_service"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip fraud protection service" nocase
        $p2 = "big-ip-fraud-protection-service" nocase
        $p3 = "big-ip_fraud_protection_service" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_global_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip global traffic manager, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_global_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip global traffic manager" nocase
        $p2 = "big-ip-global-traffic-manager" nocase
        $p3 = "big-ip_global_traffic_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_link_controller : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip link controller, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_link_controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip link controller" nocase
        $p2 = "big-ip-link-controller" nocase
        $p3 = "big-ip_link_controller" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_local_traffic_manager : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip local traffic manager, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_local_traffic_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip local traffic manager" nocase
        $p2 = "big-ip-local-traffic-manager" nocase
        $p3 = "big-ip_local_traffic_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_big_ip_policy_enforcement_manage : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 big-ip policy enforcement manager, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "big-ip_policy_enforcement_manager"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "big-ip policy enforcement manager" nocase
        $p2 = "big-ip-policy-enforcement-manager" nocase
        $p3 = "big-ip_policy_enforcement_manager" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22991_f5_ssl_orchestrator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain f5 ssl orchestrator, affected by CVE-2021-22991"
        severity = "high"
        cve = "CVE-2021-22991"
        cvss = "9.8"
        vendor = "f5"
        product = "ssl_orchestrator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22991"
    strings:
        $p = "ssl orchestrator" nocase
        $p2 = "ssl-orchestrator" nocase
        $p3 = "ssl_orchestrator" nocase
        $v0 = "12.1.0"
        $v1 = "12.1.5.3"
        $v2 = "13.1.0"
        $v3 = "13.1.3.6"
        $v4 = "14.1.0"
        $v5 = "14.1.4"
        $v6 = "15.1.0"
        $v7 = "15.1.2.1"
        $v8 = "16.0.0"
        $v9 = "16.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_1789_webkitgtk_webkitgtk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain webkitgtk webkitgtk, affected by CVE-2021-1789"
        severity = "high"
        cve = "CVE-2021-1789"
        cvss = "8.8"
        vendor = "webkitgtk"
        product = "webkitgtk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-1789"
    strings:
        $p = "webkitgtk" nocase
        $v0 = "2.30.6"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_1870_webkitgtk_webkitgtk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain webkitgtk webkitgtk, affected by CVE-2021-1870"
        severity = "high"
        cve = "CVE-2021-1870"
        cvss = "9.8"
        vendor = "webkitgtk"
        product = "webkitgtk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-1870"
    strings:
        $p = "webkitgtk" nocase
        $v0 = "2.30.6"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20021_sonicwall_email_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall email security, affected by CVE-2021-20021"
        severity = "high"
        cve = "CVE-2021-20021"
        cvss = "9.8"
        vendor = "sonicwall"
        product = "email_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20021"
    strings:
        $p = "email security" nocase
        $p2 = "email-security" nocase
        $p3 = "email_security" nocase
        $v0 = "10.0.9.6103"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20021_sonicwall_email_security_virtual_appliance : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall email security virtual appliance, affected by CVE-2021-20021"
        severity = "high"
        cve = "CVE-2021-20021"
        cvss = "9.8"
        vendor = "sonicwall"
        product = "email_security_virtual_appliance"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20021"
    strings:
        $p = "email security virtual appliance" nocase
        $p2 = "email-security-virtual-appliance" nocase
        $p3 = "email_security_virtual_appliance" nocase
        $v0 = "10.0.9.6105"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20021_sonicwall_hosted_email_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall hosted email security, affected by CVE-2021-20021"
        severity = "high"
        cve = "CVE-2021-20021"
        cvss = "9.8"
        vendor = "sonicwall"
        product = "hosted_email_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20021"
    strings:
        $p = "hosted email security" nocase
        $p2 = "hosted-email-security" nocase
        $p3 = "hosted_email_security" nocase
        $v0 = "10.0.9.6103"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20022_sonicwall_email_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall email security, affected by CVE-2021-20022"
        severity = "high"
        cve = "CVE-2021-20022"
        cvss = "7.2"
        vendor = "sonicwall"
        product = "email_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20022"
    strings:
        $p = "email security" nocase
        $p2 = "email-security" nocase
        $p3 = "email_security" nocase
        $v0 = "10.0.9.6103"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20022_sonicwall_email_security_virtual_appliance : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall email security virtual appliance, affected by CVE-2021-20022"
        severity = "high"
        cve = "CVE-2021-20022"
        cvss = "7.2"
        vendor = "sonicwall"
        product = "email_security_virtual_appliance"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20022"
    strings:
        $p = "email security virtual appliance" nocase
        $p2 = "email-security-virtual-appliance" nocase
        $p3 = "email_security_virtual_appliance" nocase
        $v0 = "10.0.9.6105"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20022_sonicwall_hosted_email_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall hosted email security, affected by CVE-2021-20022"
        severity = "high"
        cve = "CVE-2021-20022"
        cvss = "7.2"
        vendor = "sonicwall"
        product = "hosted_email_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20022"
    strings:
        $p = "hosted email security" nocase
        $p2 = "hosted-email-security" nocase
        $p3 = "hosted_email_security" nocase
        $v0 = "10.0.9.6103"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20023_sonicwall_email_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall email security, affected by CVE-2021-20023"
        severity = "high"
        cve = "CVE-2021-20023"
        cvss = "4.9"
        vendor = "sonicwall"
        product = "email_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20023"
    strings:
        $p = "email security" nocase
        $p2 = "email-security" nocase
        $p3 = "email_security" nocase
        $v0 = "10.0.9.6173"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20023_sonicwall_email_security_virtual_appliance : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall email security virtual appliance, affected by CVE-2021-20023"
        severity = "high"
        cve = "CVE-2021-20023"
        cvss = "4.9"
        vendor = "sonicwall"
        product = "email_security_virtual_appliance"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20023"
    strings:
        $p = "email security virtual appliance" nocase
        $p2 = "email-security-virtual-appliance" nocase
        $p3 = "email_security_virtual_appliance" nocase
        $v0 = "10.0.9.6177"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_20023_sonicwall_hosted_email_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sonicwall hosted email security, affected by CVE-2021-20023"
        severity = "high"
        cve = "CVE-2021-20023"
        cvss = "4.9"
        vendor = "sonicwall"
        product = "hosted_email_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-20023"
    strings:
        $p = "hosted email security" nocase
        $p2 = "hosted-email-security" nocase
        $p3 = "hosted_email_security" nocase
        $v0 = "10.0.9.6173"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22893_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2021-22893"
        severity = "high"
        cve = "CVE-2021-22893"
        cvss = "10.0"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22893"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "9.0"
        $v1 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22204_exiftool_project_exiftool : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain exiftool project exiftool, affected by CVE-2021-22204"
        severity = "high"
        cve = "CVE-2021-22204"
        cvss = "6.8"
        vendor = "exiftool_project"
        product = "exiftool"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22204"
    strings:
        $p = "exiftool" nocase
        $v0 = "12.24"
        $v1 = "7.44"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22205_gitlab_gitlab : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gitlab gitlab, affected by CVE-2021-22205"
        severity = "high"
        cve = "CVE-2021-22205"
        cvss = "10.0"
        vendor = "gitlab"
        product = "gitlab"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22205"
    strings:
        $p = "gitlab" nocase
        $v0 = "11.9.0"
        $v1 = "13.10.0"
        $v2 = "13.10.3"
        $v3 = "13.8.8"
        $v4 = "13.9.0"
        $v5 = "13.9.6"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21206_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-21206"
        severity = "high"
        cve = "CVE-2021-21206"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21206"
    strings:
        $p = "chrome" nocase
        $v0 = "89.0.4389.128"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21220_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-21220"
        severity = "high"
        cve = "CVE-2021-21220"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21220"
    strings:
        $p = "chrome" nocase
        $v0 = "89.0.4389.128"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21224_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-21224"
        severity = "high"
        cve = "CVE-2021-21224"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21224"
    strings:
        $p = "chrome" nocase
        $v0 = "90.0.4430.85"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21551_dell_dbutil : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain dell dbutil, affected by CVE-2021-21551"
        severity = "high"
        cve = "CVE-2021-21551"
        cvss = "8.8"
        vendor = "dell"
        product = "dbutil"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21551"
    strings:
        $p = "dbutil" nocase
        $v0 = "2.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_28799_qnap_hybrid_backup_sync : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain qnap hybrid backup sync, affected by CVE-2021-28799"
        severity = "high"
        cve = "CVE-2021-28799"
        cvss = "10.0"
        vendor = "qnap"
        product = "hybrid_backup_sync"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28799"
    strings:
        $p = "hybrid backup sync" nocase
        $p2 = "hybrid-backup-sync" nocase
        $p3 = "hybrid_backup_sync" nocase
        $v0 = "16.0.0415"
        $v1 = "16.0.0419"
        $v2 = "3.0.210411"
        $v3 = "3.0.210412"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21985_vmware_vcenter_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware vcenter server, affected by CVE-2021-21985"
        severity = "high"
        cve = "CVE-2021-21985"
        cvss = "9.8"
        vendor = "vmware"
        product = "vcenter_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21985"
    strings:
        $p = "vcenter server" nocase
        $p2 = "vcenter-server" nocase
        $p3 = "vcenter_server" nocase
        $v0 = "6.5"
        $v1 = "6.7"
        $v2 = "7.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_21985_vmware_cloud_foundation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware cloud foundation, affected by CVE-2021-21985"
        severity = "high"
        cve = "CVE-2021-21985"
        cvss = "9.8"
        vendor = "vmware"
        product = "cloud_foundation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-21985"
    strings:
        $p = "cloud foundation" nocase
        $p2 = "cloud-foundation" nocase
        $p3 = "cloud_foundation" nocase
        $v0 = "3.0"
        $v1 = "3.10.2.1"
        $v2 = "4.0"
        $v3 = "4.2.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22894_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2021-22894"
        severity = "high"
        cve = "CVE-2021-22894"
        cvss = "8.8"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22894"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "9.0"
        $v1 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22899_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2021-22899"
        severity = "high"
        cve = "CVE-2021-22899"
        cvss = "8.8"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22899"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "9.0"
        $v1 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22900_ivanti_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain ivanti connect secure, affected by CVE-2021-22900"
        severity = "high"
        cve = "CVE-2021-22900"
        cvss = "7.2"
        vendor = "ivanti"
        product = "connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22900"
    strings:
        $p = "connect secure" nocase
        $p2 = "connect-secure" nocase
        $p3 = "connect_secure" nocase
        $v0 = "9.0"
        $v1 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22900_pulsesecure_pulse_connect_secure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain pulsesecure pulse connect secure, affected by CVE-2021-22900"
        severity = "high"
        cve = "CVE-2021-22900"
        cvss = "7.2"
        vendor = "pulsesecure"
        product = "pulse_connect_secure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22900"
    strings:
        $p = "pulse connect secure" nocase
        $p2 = "pulse-connect-secure" nocase
        $p3 = "pulse_connect_secure" nocase
        $v0 = "9.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_27852_checkbox_survey : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain checkbox survey, affected by CVE-2021-27852"
        severity = "high"
        cve = "CVE-2021-27852"
        cvss = "9.8"
        vendor = "checkbox"
        product = "survey"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-27852"
    strings:
        $p = "survey" nocase
        $v0 = "7.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30533_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-30533"
        severity = "high"
        cve = "CVE-2021-30533"
        cvss = "6.5"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30533"
    strings:
        $p = "chrome" nocase
        $v0 = "91.0.4472.77"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_26828_scadabr_scadabr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain scadabr scadabr, affected by CVE-2021-26828"
        severity = "high"
        cve = "CVE-2021-26828"
        cvss = "8.8"
        vendor = "scadabr"
        product = "scadabr"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26828"
    strings:
        $p = "scadabr" nocase
        $v0 = "0.9.1"
        $v1 = "1.12.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_26829_scadabr_scadabr : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain scadabr scadabr, affected by CVE-2021-26829"
        severity = "high"
        cve = "CVE-2021-26829"
        cvss = "5.4"
        vendor = "scadabr"
        product = "scadabr"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26829"
    strings:
        $p = "scadabr" nocase
        $v0 = "0.9.1"
        $v1 = "1.12.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22175_gitlab_gitlab : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain gitlab gitlab, affected by CVE-2021-22175"
        severity = "high"
        cve = "CVE-2021-22175"
        cvss = "6.8"
        vendor = "gitlab"
        product = "gitlab"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22175"
    strings:
        $p = "gitlab" nocase
        $v0 = "10.5.0"
        $v1 = "13.6.7"
        $v2 = "13.7.0"
        $v3 = "13.7.7"
        $v4 = "13.8.0"
        $v5 = "13.8.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30551_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-30551"
        severity = "high"
        cve = "CVE-2021-30551"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30551"
    strings:
        $p = "chrome" nocase
        $v0 = "91.0.4472.101"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30554_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-30554"
        severity = "high"
        cve = "CVE-2021-30554"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30554"
    strings:
        $p = "chrome" nocase
        $v0 = "91.0.4472.114"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30116_kaseya_vsa_agent : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain kaseya vsa agent, affected by CVE-2021-30116"
        severity = "high"
        cve = "CVE-2021-30116"
        cvss = "10.0"
        vendor = "kaseya"
        product = "vsa_agent"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30116"
    strings:
        $p = "vsa agent" nocase
        $p2 = "vsa-agent" nocase
        $p3 = "vsa_agent" nocase
        $v0 = "9.5.0.24"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30116_kaseya_vsa_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain kaseya vsa server, affected by CVE-2021-30116"
        severity = "high"
        cve = "CVE-2021-30116"
        cvss = "10.0"
        vendor = "kaseya"
        product = "vsa_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30116"
    strings:
        $p = "vsa server" nocase
        $p2 = "vsa-server" nocase
        $p3 = "vsa_server" nocase
        $v0 = "9.5.7a"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_35211_solarwinds_serv_u : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain solarwinds serv-u, affected by CVE-2021-35211"
        severity = "high"
        cve = "CVE-2021-35211"
        cvss = "9.0"
        vendor = "solarwinds"
        product = "serv-u"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35211"
    strings:
        $p = "serv-u" nocase
        $v0 = "15.2.3"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_35464_forgerock_access_management : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain forgerock access management, affected by CVE-2021-35464"
        severity = "high"
        cve = "CVE-2021-35464"
        cvss = "9.8"
        vendor = "forgerock"
        product = "access_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35464"
    strings:
        $p = "access management" nocase
        $p2 = "access-management" nocase
        $p3 = "access_management" nocase
        $v0 = "6.5.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_35464_forgerock_openam : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain forgerock openam, affected by CVE-2021-35464"
        severity = "high"
        cve = "CVE-2021-35464"
        cvss = "9.8"
        vendor = "forgerock"
        product = "openam"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35464"
    strings:
        $p = "openam" nocase
        $v0 = "14.6.3"
        $v1 = "9.0.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_36741_trendmicro_officescan_business_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain trendmicro officescan business security, affected by CVE-2021-36741"
        severity = "high"
        cve = "CVE-2021-36741"
        cvss = "8.8"
        vendor = "trendmicro"
        product = "officescan_business_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36741"
    strings:
        $p = "officescan business security" nocase
        $p2 = "officescan-business-security" nocase
        $p3 = "officescan_business_security" nocase
        $v0 = "10.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_36741_trendmicro_worry_free_business_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain trendmicro worry-free business security, affected by CVE-2021-36741"
        severity = "high"
        cve = "CVE-2021-36741"
        cvss = "8.8"
        vendor = "trendmicro"
        product = "worry-free_business_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36741"
    strings:
        $p = "worry-free business security" nocase
        $p2 = "worry-free-business-security" nocase
        $p3 = "worry-free_business_security" nocase
        $v0 = "10.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_36742_trendmicro_officescan_business_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain trendmicro officescan business security, affected by CVE-2021-36742"
        severity = "high"
        cve = "CVE-2021-36742"
        cvss = "7.8"
        vendor = "trendmicro"
        product = "officescan_business_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36742"
    strings:
        $p = "officescan business security" nocase
        $p2 = "officescan-business-security" nocase
        $p3 = "officescan_business_security" nocase
        $v0 = "10.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_36742_trendmicro_worry_free_business_security : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain trendmicro worry-free business security, affected by CVE-2021-36742"
        severity = "high"
        cve = "CVE-2021-36742"
        cvss = "7.8"
        vendor = "trendmicro"
        product = "worry-free_business_security"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36742"
    strings:
        $p = "worry-free business security" nocase
        $p2 = "worry-free-business-security" nocase
        $p3 = "worry-free_business_security" nocase
        $v0 = "10.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_26085_atlassian_confluence_data_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian confluence data center, affected by CVE-2021-26085"
        severity = "high"
        cve = "CVE-2021-26085"
        cvss = "5.3"
        vendor = "atlassian"
        product = "confluence_data_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26085"
    strings:
        $p = "confluence data center" nocase
        $p2 = "confluence-data-center" nocase
        $p3 = "confluence_data_center" nocase
        $v0 = "7.12.3"
        $v1 = "7.4.10"
        $v2 = "7.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_26085_atlassian_confluence_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian confluence server, affected by CVE-2021-26085"
        severity = "high"
        cve = "CVE-2021-26085"
        cvss = "5.3"
        vendor = "atlassian"
        product = "confluence_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26085"
    strings:
        $p = "confluence server" nocase
        $p2 = "confluence-server" nocase
        $p3 = "confluence_server" nocase
        $v0 = "7.12.3"
        $v1 = "7.4.10"
        $v2 = "7.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30563_google_chrome : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain google chrome, affected by CVE-2021-30563"
        severity = "high"
        cve = "CVE-2021-30563"
        cvss = "8.8"
        vendor = "google"
        product = "chrome"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30563"
    strings:
        $p = "chrome" nocase
        $v0 = "91.0.4472.164"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_36380_sunhillo_sureline : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sunhillo sureline, affected by CVE-2021-36380"
        severity = "high"
        cve = "CVE-2021-36380"
        cvss = "9.8"
        vendor = "sunhillo"
        product = "sureline"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-36380"
    strings:
        $p = "sureline" nocase
        $v0 = "8.7.0.1.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_26086_atlassian_jira_data_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian jira data center, affected by CVE-2021-26086"
        severity = "high"
        cve = "CVE-2021-26086"
        cvss = "5.3"
        vendor = "atlassian"
        product = "jira_data_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26086"
    strings:
        $p = "jira data center" nocase
        $p2 = "jira-data-center" nocase
        $p3 = "jira_data_center" nocase
        $v0 = "8.13.6"
        $v1 = "8.14.0"
        $v2 = "8.16.1"
        $v3 = "8.5.14"
        $v4 = "8.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_26086_atlassian_jira_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian jira server, affected by CVE-2021-26086"
        severity = "high"
        cve = "CVE-2021-26086"
        cvss = "5.3"
        vendor = "atlassian"
        product = "jira_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26086"
    strings:
        $p = "jira server" nocase
        $p2 = "jira-server" nocase
        $p3 = "jira_server" nocase
        $v0 = "8.13.6"
        $v1 = "8.14.0"
        $v2 = "8.16.1"
        $v3 = "8.5.14"
        $v4 = "8.6.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_35394_realtek_rtl819x_jungle_software_developm : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain realtek rtl819x jungle software development kit, affected by CVE-2021-35394"
        severity = "high"
        cve = "CVE-2021-35394"
        cvss = "9.8"
        vendor = "realtek"
        product = "rtl819x_jungle_software_development_kit"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35394"
    strings:
        $p = "rtl819x jungle software development kit" nocase
        $p2 = "rtl819x-jungle-software-development-kit" nocase
        $p3 = "rtl819x_jungle_software_development_kit" nocase
        $v0 = "2.0"
        $v1 = "3.4.14b"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_35395_realtek_rtl819x_jungle_software_developm : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain realtek rtl819x jungle software development kit, affected by CVE-2021-35395"
        severity = "high"
        cve = "CVE-2021-35395"
        cvss = "9.8"
        vendor = "realtek"
        product = "rtl819x_jungle_software_development_kit"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-35395"
    strings:
        $p = "rtl819x jungle software development kit" nocase
        $p2 = "rtl819x-jungle-software-development-kit" nocase
        $p3 = "rtl819x_jungle_software_development_kit" nocase
        $v0 = "2.0"
        $v1 = "3.4.14b"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_xstream_xstream : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain xstream xstream, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "xstream"
        product = "xstream"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "xstream" nocase
        $v0 = "1.4.18"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_business_activity_monitoring : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle business activity monitoring, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "business_activity_monitoring"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "business activity monitoring" nocase
        $p2 = "business-activity-monitoring" nocase
        $p3 = "business_activity_monitoring" nocase
        $v0 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_commerce_guided_search : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle commerce guided search, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "commerce_guided_search"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "commerce guided search" nocase
        $p2 = "commerce-guided-search" nocase
        $p3 = "commerce_guided_search" nocase
        $v0 = "11.3.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_communications_billing_and_reven : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications billing and revenue management elastic charging engine, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "communications_billing_and_revenue_management_elastic_charging_engine"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "communications billing and revenue management elastic charging engine" nocase
        $p2 = "communications-billing-and-revenue-management-elastic-charging-engine" nocase
        $p3 = "communications_billing_and_revenue_management_elastic_charging_engine" nocase
        $v0 = "11.3"
        $v1 = "12.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_communications_cloud_native_core : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications cloud native core automated test suite, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "communications_cloud_native_core_automated_test_suite"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "communications cloud native core automated test suite" nocase
        $p2 = "communications-cloud-native-core-automated-test-suite" nocase
        $p3 = "communications_cloud_native_core_automated_test_suite" nocase
        $v0 = "1.9.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_communications_unified_inventory : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle communications unified inventory management, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "communications_unified_inventory_management"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "communications unified inventory management" nocase
        $p2 = "communications-unified-inventory-management" nocase
        $p3 = "communications_unified_inventory_management" nocase
        $v0 = "7.3.4"
        $v1 = "7.3.5"
        $v2 = "7.4.0"
        $v3 = "7.4.1"
        $v4 = "7.4.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_retail_xstore_point_of_service : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle retail xstore point of service, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "retail_xstore_point_of_service"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "retail xstore point of service" nocase
        $p2 = "retail-xstore-point-of-service" nocase
        $p3 = "retail_xstore_point_of_service" nocase
        $v0 = "16.0.6"
        $v1 = "17.0.4"
        $v2 = "18.0.3"
        $v3 = "19.0.2"
        $v4 = "20.0.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_utilities_framework : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle utilities framework, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "utilities_framework"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "utilities framework" nocase
        $p2 = "utilities-framework" nocase
        $p3 = "utilities_framework" nocase
        $v0 = "4.2.0.2.0"
        $v1 = "4.2.0.3.0"
        $v2 = "4.3.0.1.0"
        $v3 = "4.3.0.6.0"
        $v4 = "4.4.0.0.0"
        $v5 = "4.4.0.2.0"
        $v6 = "4.4.0.3.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_utilities_testing_accelerator : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle utilities testing accelerator, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "utilities_testing_accelerator"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "utilities testing accelerator" nocase
        $p2 = "utilities-testing-accelerator" nocase
        $p3 = "utilities_testing_accelerator" nocase
        $v0 = "6.0.0.1.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_39144_oracle_webcenter_portal : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle webcenter portal, affected by CVE-2021-39144"
        severity = "high"
        cve = "CVE-2021-39144"
        cvss = "8.5"
        vendor = "oracle"
        product = "webcenter_portal"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-39144"
    strings:
        $p = "webcenter portal" nocase
        $p2 = "webcenter-portal" nocase
        $p3 = "webcenter_portal" nocase
        $v0 = "12.2.1.3.0"
        $v1 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30860_freedesktop_poppler : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain freedesktop poppler, affected by CVE-2021-30860"
        severity = "high"
        cve = "CVE-2021-30860"
        cvss = "7.8"
        vendor = "freedesktop"
        product = "poppler"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30860"
    strings:
        $p = "poppler" nocase
        $v0 = "22.09.0"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30952_apple_safari : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apple safari, affected by CVE-2021-30952"
        severity = "high"
        cve = "CVE-2021-30952"
        cvss = "7.8"
        vendor = "apple"
        product = "safari"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30952"
    strings:
        $p = "safari" nocase
        $v0 = "15.2"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30952_webkitgtk_webkitgtk : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain webkitgtk webkitgtk, affected by CVE-2021-30952"
        severity = "high"
        cve = "CVE-2021-30952"
        cvss = "7.8"
        vendor = "webkitgtk"
        product = "webkitgtk"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30952"
    strings:
        $p = "webkitgtk" nocase
        $v0 = "2.34.4"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30952_wpewebkit_wpe_webkit : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain wpewebkit wpe webkit, affected by CVE-2021-30952"
        severity = "high"
        cve = "CVE-2021-30952"
        cvss = "7.8"
        vendor = "wpewebkit"
        product = "wpe_webkit"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30952"
    strings:
        $p = "wpe webkit" nocase
        $p2 = "wpe-webkit" nocase
        $p3 = "wpe_webkit" nocase
        $v0 = "2.34.4"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_32648_octobercms_october : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain octobercms october, affected by CVE-2021-32648"
        severity = "high"
        cve = "CVE-2021-32648"
        cvss = "8.2"
        vendor = "octobercms"
        product = "october"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-32648"
    strings:
        $p = "october" nocase
        $v0 = "1.0.471"
        $v1 = "1.1.1"
        $v2 = "1.1.5"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_26084_atlassian_confluence_data_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian confluence data center, affected by CVE-2021-26084"
        severity = "high"
        cve = "CVE-2021-26084"
        cvss = "9.8"
        vendor = "atlassian"
        product = "confluence_data_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26084"
    strings:
        $p = "confluence data center" nocase
        $p2 = "confluence-data-center" nocase
        $p3 = "confluence_data_center" nocase
        $v0 = "6.13.23"
        $v1 = "6.14.0"
        $v2 = "7.11.6"
        $v3 = "7.12.0"
        $v4 = "7.12.5"
        $v5 = "7.4.11"
        $v6 = "7.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_26084_atlassian_confluence_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain atlassian confluence server, affected by CVE-2021-26084"
        severity = "high"
        cve = "CVE-2021-26084"
        cvss = "9.8"
        vendor = "atlassian"
        product = "confluence_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-26084"
    strings:
        $p = "confluence server" nocase
        $p2 = "confluence-server" nocase
        $p3 = "confluence_server" nocase
        $v0 = "6.13.23"
        $v1 = "6.14.0"
        $v2 = "7.11.6"
        $v3 = "7.12.0"
        $v4 = "7.12.5"
        $v5 = "7.4.11"
        $v6 = "7.5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_37415_zohocorp_manageengine_servicedesk_plus : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain zohocorp manageengine servicedesk plus, affected by CVE-2021-37415"
        severity = "high"
        cve = "CVE-2021-37415"
        cvss = "9.8"
        vendor = "zohocorp"
        product = "manageengine_servicedesk_plus"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-37415"
    strings:
        $p = "manageengine servicedesk plus" nocase
        $p2 = "manageengine-servicedesk-plus" nocase
        $p3 = "manageengine_servicedesk_plus" nocase
        $v0 = "11.0"
        $v1 = "11.1"
        $v2 = "11.2"
        $v3 = "11.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_28550_adobe_acrobat_dc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat dc, affected by CVE-2021-28550"
        severity = "high"
        cve = "CVE-2021-28550"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_dc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28550"
    strings:
        $p = "acrobat dc" nocase
        $p2 = "acrobat-dc" nocase
        $p3 = "acrobat_dc" nocase
        $v0 = "15.008.20082"
        $v1 = "21.001.20149"
        $v2 = "21.001.20150"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_28550_adobe_acrobat_reader_dc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader dc, affected by CVE-2021-28550"
        severity = "high"
        cve = "CVE-2021-28550"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader_dc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28550"
    strings:
        $p = "acrobat reader dc" nocase
        $p2 = "acrobat-reader-dc" nocase
        $p3 = "acrobat_reader_dc" nocase
        $v0 = "15.008.20082"
        $v1 = "21.001.20149"
        $v2 = "21.001.20150"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_28550_adobe_acrobat : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat, affected by CVE-2021-28550"
        severity = "high"
        cve = "CVE-2021-28550"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28550"
    strings:
        $p = "acrobat" nocase
        $v0 = "17.011.30059"
        $v1 = "17.011.30194"
        $v2 = "20.001.30005"
        $v3 = "20.001.30020"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_28550_adobe_acrobat_reader : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain adobe acrobat reader, affected by CVE-2021-28550"
        severity = "high"
        cve = "CVE-2021-28550"
        cvss = "8.8"
        vendor = "adobe"
        product = "acrobat_reader"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-28550"
    strings:
        $p = "acrobat reader" nocase
        $p2 = "acrobat-reader" nocase
        $p3 = "acrobat_reader" nocase
        $v0 = "17.011.30059"
        $v1 = "17.011.30194"
        $v2 = "20.001.30005"
        $v3 = "20.001.30020"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40539_zohocorp_manageengine_adselfservice_plus : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain zohocorp manageengine adselfservice plus, affected by CVE-2021-40539"
        severity = "high"
        cve = "CVE-2021-40539"
        cvss = "9.8"
        vendor = "zohocorp"
        product = "manageengine_adselfservice_plus"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40539"
    strings:
        $p = "manageengine adselfservice plus" nocase
        $p2 = "manageengine-adselfservice-plus" nocase
        $p3 = "manageengine_adselfservice_plus" nocase
        $v0 = "6.1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30661_apple_safari : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apple safari, affected by CVE-2021-30661"
        severity = "high"
        cve = "CVE-2021-30661"
        cvss = "8.8"
        vendor = "apple"
        product = "safari"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30661"
    strings:
        $p = "safari" nocase
        $v0 = "14.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_30663_apple_safari : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apple safari, affected by CVE-2021-30663"
        severity = "high"
        cve = "CVE-2021-30663"
        cvss = "8.8"
        vendor = "apple"
        product = "safari"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-30663"
    strings:
        $p = "safari" nocase
        $v0 = "14.1.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40870_aviatrix_controller : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain aviatrix controller, affected by CVE-2021-40870"
        severity = "high"
        cve = "CVE-2021-40870"
        cvss = "9.8"
        vendor = "aviatrix"
        product = "controller"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40870"
    strings:
        $p = "controller" nocase
        $v0 = "6.2"
        $v1 = "6.2.2043"
        $v2 = "6.3"
        $v3 = "6.3.2490"
        $v4 = "6.4"
        $v5 = "6.4.2838"
        $v6 = "6.5"
        $v7 = "6.5.1922"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_38163_sap_netweaver : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain sap netweaver, affected by CVE-2021-38163"
        severity = "high"
        cve = "CVE-2021-38163"
        cvss = "9.9"
        vendor = "sap"
        product = "netweaver"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38163"
    strings:
        $p = "netweaver" nocase
        $v0 = "7.30"
        $v1 = "7.31"
        $v2 = "7.40"
        $v3 = "7.50"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_38645_microsoft_open_management_infrastructure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft open management infrastructure, affected by CVE-2021-38645"
        severity = "high"
        cve = "CVE-2021-38645"
        cvss = "7.8"
        vendor = "microsoft"
        product = "open_management_infrastructure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38645"
    strings:
        $p = "open management infrastructure" nocase
        $p2 = "open-management-infrastructure" nocase
        $p3 = "open_management_infrastructure" nocase
        $v0 = "1.6.8-1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_38647_microsoft_open_management_infrastructure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft open management infrastructure, affected by CVE-2021-38647"
        severity = "high"
        cve = "CVE-2021-38647"
        cvss = "9.8"
        vendor = "microsoft"
        product = "open_management_infrastructure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38647"
    strings:
        $p = "open management infrastructure" nocase
        $p2 = "open-management-infrastructure" nocase
        $p3 = "open_management_infrastructure" nocase
        $v0 = "1.6.8-1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_38648_microsoft_open_management_infrastructure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft open management infrastructure, affected by CVE-2021-38648"
        severity = "high"
        cve = "CVE-2021-38648"
        cvss = "7.8"
        vendor = "microsoft"
        product = "open_management_infrastructure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38648"
    strings:
        $p = "open management infrastructure" nocase
        $p2 = "open-management-infrastructure" nocase
        $p3 = "open_management_infrastructure" nocase
        $v0 = "1.6.8-1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_38649_microsoft_open_management_infrastructure : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain microsoft open management infrastructure, affected by CVE-2021-38649"
        severity = "high"
        cve = "CVE-2021-38649"
        cvss = "7.0"
        vendor = "microsoft"
        product = "open_management_infrastructure"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38649"
    strings:
        $p = "open management infrastructure" nocase
        $p2 = "open-management-infrastructure" nocase
        $p3 = "open_management_infrastructure" nocase
        $v0 = "1.6.8-1"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_redhat_jboss_core_services : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat jboss core services, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "redhat"
        product = "jboss_core_services"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "jboss core services" nocase
        $p2 = "jboss-core-services" nocase
        $p3 = "jboss_core_services" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_redhat_software_collections : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain redhat software collections, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "redhat"
        product = "software_collections"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "software collections" nocase
        $p2 = "software-collections" nocase
        $p3 = "software_collections" nocase
        $v0 = "1.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_apache_http_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain apache http server, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "apache"
        product = "http_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "http server" nocase
        $p2 = "http-server" nocase
        $p3 = "http_server" nocase
        $v0 = "2.4.48"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_oracle_enterprise_manager_ops_center : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle enterprise manager ops center, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "oracle"
        product = "enterprise_manager_ops_center"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "enterprise manager ops center" nocase
        $p2 = "enterprise-manager-ops-center" nocase
        $p3 = "enterprise_manager_ops_center" nocase
        $v0 = "12.4.0.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_oracle_http_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle http server, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "oracle"
        product = "http_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "http server" nocase
        $p2 = "http-server" nocase
        $p3 = "http_server" nocase
        $v0 = "12.2.1.3.0"
        $v1 = "12.2.1.4.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_oracle_instantis_enterprisetrack : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle instantis enterprisetrack, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "oracle"
        product = "instantis_enterprisetrack"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "instantis enterprisetrack" nocase
        $p2 = "instantis-enterprisetrack" nocase
        $p3 = "instantis_enterprisetrack" nocase
        $v0 = "17.1"
        $v1 = "17.2"
        $v2 = "17.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_oracle_secure_global_desktop : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle secure global desktop, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "oracle"
        product = "secure_global_desktop"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "secure global desktop" nocase
        $p2 = "secure-global-desktop" nocase
        $p3 = "secure_global_desktop" nocase
        $v0 = "5.6"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_oracle_zfs_storage_appliance_kit : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain oracle zfs storage appliance kit, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "oracle"
        product = "zfs_storage_appliance_kit"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "zfs storage appliance kit" nocase
        $p2 = "zfs-storage-appliance-kit" nocase
        $p3 = "zfs_storage_appliance_kit" nocase
        $v0 = "8.8"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_siemens_sinec_nms : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain siemens sinec nms, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "siemens"
        product = "sinec_nms"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "sinec nms" nocase
        $p2 = "sinec-nms" nocase
        $p3 = "sinec_nms" nocase
        $v0 = "1.0.3"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_siemens_sinema_remote_connect_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain siemens sinema remote connect server, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "siemens"
        product = "sinema_remote_connect_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "sinema remote connect server" nocase
        $p2 = "sinema-remote-connect-server" nocase
        $p3 = "sinema_remote_connect_server" nocase
        $v0 = "3.1"
        $v1 = "3.2"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_siemens_sinema_server : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain siemens sinema server, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "siemens"
        product = "sinema_server"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "sinema server" nocase
        $p2 = "sinema-server" nocase
        $p3 = "sinema_server" nocase
        $v0 = "14.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_40438_tenable_tenable_sc : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain tenable tenable.sc, affected by CVE-2021-40438"
        severity = "high"
        cve = "CVE-2021-40438"
        cvss = "9.0"
        vendor = "tenable"
        product = "tenable.sc"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
    strings:
        $p = "tenable.sc" nocase
        $v0 = "5.19.1"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_38406_deltaww_dopsoft : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain deltaww dopsoft, affected by CVE-2021-38406"
        severity = "high"
        cve = "CVE-2021-38406"
        cvss = "7.8"
        vendor = "deltaww"
        product = "dopsoft"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-38406"
    strings:
        $p = "dopsoft" nocase
        $v0 = "2.00"
        $v1 = "2.00.07"
    condition:
        $p and any of ($v*) and filesize < 50MB
}

rule NVD_CVE_2021_22005_vmware_cloud_foundation : vulnerable_component kev
{
    meta:
        description = "Artifact appears to contain vmware cloud foundation, affected by CVE-2021-22005"
        severity = "high"
        cve = "CVE-2021-22005"
        cvss = "9.8"
        vendor = "vmware"
        product = "cloud_foundation"
        known_exploited = "yes"
        generator = "nvd-rulegen"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22005"
    strings:
        $p = "cloud foundation" nocase
        $p2 = "cloud-foundation" nocase
        $p3 = "cloud_foundation" nocase
        $v0 = "3.0"
        $v1 = "5.0"
    condition:
        any of ($p*) and any of ($v*) and filesize < 50MB
}
