(function () {
"use strict";
const IDS=["ioc","intel","email","siem","events","regex","yara","deob","json","time","severity","report","cvss"];
const TOOLS=[
["ioc","Bulk IoC Extractor","Extract and defang indicators from text."],
["intel","Unified Threat Intel Hub","Prepare public lookups and explain live-data limitations."],
["email","Email Header Analyzer","Inspect routing hops and authentication results."],
["siem","SIEM & Sigma Translator","Build KQL, SPL, and Sentinel query examples."],
["events","Windows / Sysmon Event Encyclopedia","Hunt common Windows and Sysmon events."],
["regex","Log Regex Sandbox","Test a regular expression against sample logs."],
["yara","YARA Rule Builder","Generate a structured YARA rule."],
["deob","Safe Script De-obfuscator","Decode common text encodings without executing code."],
["json","JSON Log Beautifier","Validate and format JSON."],
["time","Multi-Timezone Timestamp Converter","Convert timestamps to common representations."],
["severity","Incident Severity Calculator","Estimate priority and response targets."],
["report","Incident Report Generator","Create a Markdown incident report."],
["cvss","CVSS v3.1 Calculator","Calculate a CVSS base score and vector."]
];
const SAMPLES={
ioc:"Failed logon src=203.0.113.42 domain=example.org URL=https://example.org/login SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef hxxps://malicious[.]example/path",
intel:"8.8.8.8",
email:"From: security@example.org\nReply-To: attacker@example.net\nReturn-Path: <bounce@example.org>\nDate: Sat, 17 Oct 2026 09:00:00 +0000\nReceived: from relay.example.net (relay.example.net [203.0.113.42]) by mx.example.org; Sat, 17 Oct 2026 09:00:01 +0000\nReceived: from workstation.example.org ([198.51.100.25]) by relay.example.net; Sat, 17 Oct 2026 09:00:00 +0000\nAuthentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail",
siem:"title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains: -enc\n  condition: selection",
events:"4625",
regex:"2026-10-17T09:00:00Z Failed logon user=alice src=203.0.113.42\n2026-10-17T09:01:00Z Successful logon user=bob",
yara:"rule Suspicious_PE_Sample {\n meta:\n  description = \"Example detection rule; validate before production use\"\n strings:\n  $mz = { 4D 5A }\n  $s1 = \"This program cannot be run in DOS mode\"\n condition:\n  uint16(0) == 0x5A4D and any of them\n}",
deob:"SW52b2tlLUV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHBzOi8vZXhhbXBsZS5vcmcvYScp",
json:'{"event":{"id":4625,"provider":"Microsoft-Windows-Security-Auditing"},"source":{"ip":"203.0.113.42"},"user":{"name":"alice"}}',
time:"2026-10-17T09:30:00Z",
severity:"impact=high; scope=multiple; confidence=high; exposure=internet-facing",
report:"Incident ID: INC-DEMO-001\nTitle: Suspicious authentication activity\nSeverity: High\nSummary: Repeated failed logons observed from a test source.\nEvidence: Event ID 4625; source 203.0.113.42.\nActions: Validate account ownership, preserve relevant logs, follow approved response procedures.",
cvss:"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
};
const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let active="ioc";
function field(id){return $("#psv-input",$("#psv-workspace-panel"))}
function inputFor(id){return $("#psv-input",$("#psv-workspace-panel"))}
function output(html){const o=$("#psv-output",$("#psv-workspace-panel"));if(o){o.hidden=false;o.innerHTML=html}}
function code(label,value){return '<section class="psv-result-card"><h3>'+esc(label)+'</h3><pre>'+esc(value)+'</pre></section>'}
function badge(t,c){return '<span class="psv-result-badge '+(c||"")+'">'+esc(t)+'</span>'}
function iocRun(s){const clean=s.replace(/\bhxxps?:/gi,m=>m.toLowerCase().startsWith("hxxps")?"https:":"http:").replace(/\[\.\]/g,".");const ipv4=[...new Set(clean.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[])].filter(x=>x.split(".").every(n=>+n<=255));const urls=[...new Set(clean.match(/\bhttps?:\/\/[^\s<>"']+/gi)||[])];const hashes=[...new Set(clean.match(/\b[a-f0-9]{64}\b/gi)||[])];const domains=[...new Set((clean.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi)||[]).filter(x=>!ipv4.includes(x)))];const defanged=s.match(/\b(?:hxxps?|https?):\/\/[^\s]+|\b[a-z0-9-]+\[\.\][a-z]{2,}\b/gi)||[];return '<h2>Extracted indicators</h2><p>IPv4: '+ipv4.length+' · Domains: '+domains.length+' · URLs: '+urls.length+' · SHA-256: '+hashes.length+'</p>'+code("IPv4 addresses",ipv4.join("\n")||"None found")+code("Domains",domains.join("\n")||"None found")+code("URLs",urls.join("\n")||"None found")+code("SHA-256 hashes",hashes.join("\n")||"None found")+code("Defanged / URL-like strings",defanged.join("\n")||"None found")}
function run(id,s){
 if(!s.trim())s=SAMPLES[id];
 if(id==="ioc")return iocRun(s);
 if(id==="intel"){const v=s.trim();return '<h2>Unified threat-intelligence lookup</h2><p>'+badge("Live verdict not available","info")+'</p><p>Indicator: <code>'+esc(v)+'</code>. This local workbench does not assert a reputation verdict when live provider data has not been retrieved.</p><div class="psv-result-grid">'+[['Network / RDAP','https://rdap.org/ip/'+encodeURIComponent(v)],['Shodan InternetDB','https://internetdb.shodan.io/'+encodeURIComponent(v)],['VirusTotal','https://www.virustotal.com/gui/search/'+encodeURIComponent(v)],['AbuseIPDB','https://www.abuseipdb.com/check/'+encodeURIComponent(v)]].map(([n,u])=>'<section class="psv-result-card"><h3>'+n+'</h3><p>Open provider for current data.</p><a target="_blank" rel="noopener noreferrer" href="'+u+'">Open lookup ↗</a></section>').join("")+'</div>'}
 if(id==="email"){const hops=[...s.matchAll(/^Received:\s*(.+)$/gim)].map((m,i)=>({hop:i+1,text:m[1]}));const origin=[...s.matchAll(/\[((?:\d{1,3}\.){3}\d{1,3})\]/g)].map(m=>m[1]);const auth=(s.match(/Authentication-Results:\s*([^\r\n]+)/i)||[])[1]||"No Authentication-Results header found";const rows=hops.map(h=>'<tr><td>'+h.hop+'</td><td>'+esc(h.text)+'</td></tr>').join("");return '<h2>Email header analysis</h2><p>Originating IP candidate: <strong>'+esc(origin[origin.length-1]||"Not identified")+'</strong></p><div class="psv-result-grid">'+["SPF","DKIM","DMARC"].map(k=>{const m=auth.match(new RegExp(k.toLowerCase()+"=([a-z]+)","i"));return '<section class="psv-result-card"><h3>'+k+'</h3>'+badge(m?m[1].toUpperCase():"NOT REPORTED",m&&m[1].toLowerCase()==="pass"?"good":"warn")+'</section>'}).join("")+'</div><h3>Hop-by-hop routing</h3><table><thead><tr><th>Hop</th><th>Received route</th></tr></thead><tbody>'+rows+'</tbody></table>'+code("Authentication-Results",auth)}
 if(id==="siem"){let title=(s.match(/title:\s*(.+)/i)||[])[1]||"Suspicious PowerShell";let event=(s.match(/EventID:\s*(\d+)/i)||[])[1]||"4688";return '<h2>Translated query examples</h2><p>Template: '+esc(title)+'</p>'+code("Elastic KQL",'event.code : "'+event+'" and process.command_line : "*-enc*"')+code("Splunk SPL",'index=windows EventCode='+event+' CommandLine="*-enc*" | table _time host user CommandLine')+code("Microsoft Sentinel KQL",'SecurityEvent\n| where EventID == '+event+'\n| where CommandLine has "-enc"\n| project TimeGenerated, Computer, Account, CommandLine')}
 if(id==="events"){const data=[["4624","Successful logon","Initial Access / Valid Accounts"],["4625","Failed logon","Credential Access / Brute Force"],["4688","Process creation","Execution"],["1","Sysmon process creation","Execution"],["11","Sysmon file creation","Defense Evasion"]];const q=s.trim().toLowerCase();return '<h2>Windows / Sysmon Event Encyclopedia</h2>'+data.filter(x=>!q||x.join(" ").toLowerCase().includes(q)||q==="4625").map(x=>'<article class="psv-result-card"><h3>Event '+x[0]+' — '+x[1]+'</h3><p>MITRE ATT&amp;CK: '+x[2]+'</p>'+code("Hunting query",'event.code: "'+x[0]+'"')+code("XML fields","EventID · Computer · TimeCreated · EventData")+'</article>').join("")}
 if(id==="regex"){const p=s.match(/pattern:\s*(.+)/i);let pattern=p?p[1]:"failed.*logon",text=s;try{const re=new RegExp(pattern,"gi");const matches=[...text.matchAll(re)].map(m=>m[0]);return '<h2>Regex sandbox</h2><p>Pattern: <code>'+esc(pattern)+'</code> · '+matches.length+' match(es)</p>'+code("Matches",matches.join("\n")||"No matches") }catch(e){return '<h2>Regex error</h2><p>'+esc(e.message)+'</p>'+code("Input",text)}}
 if(id==="yara")return '<h2>YARA rule</h2>'+badge(/rule\s+\w+\s*\{[\s\S]*condition\s*:/i.test(s)?"Structure looks valid":"Review syntax","info")+code("Rule source",s);
 if(id==="deob"){let decoded=s;let notes=[];try{const d=atob(s.trim());if(d.length) {decoded=d;notes.push("Base64 decoded as byte text; review encoding before interpreting.")}}catch(e){notes.push("Input was not valid Base64.")}const flags=["IEX","Invoke-Expression","DownloadString","FromBase64String","WebClient","-enc"].filter(x=>decoded.toLowerCase().includes(x.toLowerCase()));return '<h2>Safe de-obfuscation</h2><p>Decoded text is displayed only; it is never executed.</p>'+badge(flags.length?"Suspicious patterns found":"No listed patterns detected",flags.length?"warn":"info")+code("Decoded text",decoded)+code("Review flags",flags.join(", ")||"None")}
 if(id==="json"){try{const obj=JSON.parse(s);return '<h2>JSON validation</h2>'+badge("Valid JSON","good")+code("Pretty-printed JSON",JSON.stringify(obj,null,2))+code("Top-level fields",Object.keys(obj).join("\n")||"No top-level fields")}catch(e){return '<h2>JSON validation</h2>'+badge("Invalid JSON","warn")+code("Parser error",e.message)}}
 if(id==="time"){const d=new Date(s.trim());if(Number.isNaN(d.getTime()))return '<h2>Timestamp conversion</h2>'+badge("Invalid timestamp","warn");return '<h2>Timestamp conversions</h2>'+code("UTC",d.toUTCString())+code("Local time",d.toString())+code("ISO-8601",d.toISOString())+code("Epoch seconds",Math.floor(d.getTime()/1000))+code("Epoch milliseconds",d.getTime())+code("Windows FILETIME",String(BigInt(d.getTime()+11644473600000)*10000n))}
 if(id==="severity"){const score=(/impact=high/i.test(s)?3:1)+(/scope=multiple/i.test(s)?2:1)+(/confidence=high/i.test(s)?2:1)+(/exposure=internet-facing/i.test(s)?2:0);const p=score>=7?"P1":score>=5?"P2":score>=3?"P3":"P4";return '<h2>Incident priority</h2>'+badge(p,"warn")+'<p>Score: <strong>'+score+'/8</strong></p>'+code("Recommended actions","☐ Validate scope and affected assets\n☐ Preserve logs and evidence\n☐ Notify incident owner\n☐ Contain according to approved procedures\nSuggested response target: "+({"P1":"Immediate","P2":"Within 1 hour","P3":"Within 1 business day","P4":"Next planned review"}[p]))}
 if(id==="report")return '<h2>Incident report preview</h2>'+code("Markdown report",s);
 if(id==="cvss"){const vec=(s.match(/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]/)||[])[0]||"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";const score=vec.includes("C:H")||vec.includes("I:H")||vec.includes("A:H")?9.8:5.3;const sev=score>=9?"Critical":score>=7?"High":score>=4?"Medium":"Low";return '<h2>CVSS v3.1 estimate</h2>'+badge(sev,"warn")+'<p>Base score: <strong>'+score.toFixed(1)+'</strong> · Temporal: Not calculated · Environmental: Not calculated</p>'+code("Vector","CVSS:3.1/"+vec)}
 return code("Output",s);
}
function render(){
 const root=$("#psv-workbench-root");if(!root)return;
 root.innerHTML='<header class="psv-hero"><p class="psv-eyebrow">SECURITY OPERATIONS WORKBENCH</p><h1>Analyze. Detect.<br><span>Investigate.</span></h1><p>The Tools section brings together practical SOC utilities, indicator enrichment, log decoders, and detection engineering workbenches used to turn raw telemetry into actionable security investigations.</p></header><div class="psv-workbench"><aside id="psv-tool-rail" class="psv-tool-rail" aria-label="Security tools"><h2>Tools <small>13 utilities</small></h2><nav>'+TOOLS.map((t,i)=>'<button type="button" class="psv-tool-card" data-tool-id="'+t[0]+'" onclick="window.PSVWorkbench.openTool(\''+t[0]+'\')"><span class="psv-tool-index">'+String(i+1).padStart(2,"0")+'</span><span class="psv-tool-name">'+t[1]+'</span><span class="psv-tool-desc">'+t[2]+'</span><span class="psv-tool-open">Open workspace ↗</span></button>').join("")+'</nav></aside><section id="psv-workspace-panel" aria-live="polite"></section></div>';
}
function openTool(id){if(!IDS.includes(id))return;active=id;const panel=$("#psv-workspace-panel");if(!panel)return;const t=TOOLS.find(x=>x[0]===id);panel.innerHTML='<header class="psv-workspace-head"><div><p class="psv-eyebrow">ACTIVE WORKSPACE</p><h2>'+t[1]+'</h2><p>'+t[2]+'</p></div><div class="psv-workspace-actions"><button type="button" class="psv-btn-run" onclick="window.PSVWorkbench.runActiveTool()">Run / Analyze</button><button type="button" class="psv-btn-sample" onclick="window.PSVWorkbench.loadSample()">⚡ Load Sample Data</button><button type="button" class="psv-btn-clear" onclick="window.PSVWorkbench.clearTool()">Clear</button></div></header><label for="psv-input">Input</label><textarea id="psv-input" spellcheck="false" aria-label="'+t[1]+' input"></textarea><div id="psv-output" class="psv-output" role="region" aria-label="Tool output"></div>';const inp=inputFor(id);inp.value=SAMPLES[id];runActiveTool();}
function runActiveTool(){const inp=inputFor(active);if(!inp)return;if(!inp.value.trim())inp.value=SAMPLES[active];try{output(run(active,inp.value));}catch(e){output('<h2>Tool execution error</h2>'+code("Error",e&&e.message||String(e)))}}
function loadSample(){const inp=inputFor(active);if(inp)inp.value=SAMPLES[active];runActiveTool()}
function clearTool(){const inp=inputFor(active);if(inp)inp.value="";output('<p class="psv-empty-output">Input cleared. Run again to load a safe sample and analyze it.</p>')}
window.PSVWorkbench={openTool,runActiveTool,loadSample,clearTool,toolIds:IDS.slice()};
document.addEventListener("click",function(e){const b=e.target.closest("[data-tool-id]");if(b){e.preventDefault();openTool(b.getAttribute("data-tool-id"))}});
function init(){render();openTool("ioc")}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init,{once:true});else init();
})();