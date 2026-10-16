(function () {
"use strict";
var $=function(s,r){return (r||document).querySelector(s)}, $$=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
var esc=function(s){return String(s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})};
var defs=[
["ioc","Bulk IoC Extractor","Extract IPs, domains, URLs and hashes from pasted text."],
["intel","Multi-Source Threat Intel Hub","Open provider lookups without embedding API keys."],
["email","Email Header Analyzer","Inspect routing headers and authentication signals."],
["siem","SIEM Query Builder & Sigma Translator","Generate starter queries and inspect basic Sigma YAML."],
["events","Windows Event ID Encyclopedia","Search common Windows Security and Sysmon IDs."],
["regex","Log Regex Sandbox","Test JavaScript regex patterns against sample logs."],
["yara","YARA Rule Builder","Generate a structured YARA rule scaffold."],
["deob","Safe Script De-obfuscator","Decode text encodings without executing scripts."],
["json","JSON Log Beautifier","Validate, format and compact JSON locally."],
["time","Multi-Timezone Timestamp Converter","Convert ISO timestamps and Unix epochs."],
["severity","Incident Severity Calculator","Calculate a transparent triage score."],
["report","Incident Report Generator","Draft a structured incident report locally."],
["cvss","CVSS v3.1 Calculator","Calculate CVSS v3.1 base score metrics."]
];
var events=[
["4624","Windows Security","Successful logon","Review Logon Type, source address, account and authentication package."],
["4625","Windows Security","Failed logon","Review Status/SubStatus, source, target account and failure bursts."],
["4688","Windows Security","Process creation","Review command line visibility, parent/child process and user."],
["4672","Windows Security","Special privileges assigned","Correlate with logon events and expected administrator activity."],
["4697","Windows Security","Service installed","Validate service name, binary path, signer and initiating process."],
["4720","Windows Security","User account created","Verify requester, timestamp and subsequent group membership."],
["4728","Windows Security","Member added to global security group","Check group sensitivity, actor and change approval."],
["1102","Windows Security","Audit log cleared","Confirm whether log clearing was authorized."],
["1","Sysmon","Process creation","Review Image, CommandLine, ParentImage, hashes and ProcessGuid."],
["3","Sysmon","Network connection","Network connection telemetry; depends on Sysmon configuration."],
["7","Sysmon","Image loaded","High-volume module load events; tune by process and signature."],
["8","Sysmon","CreateRemoteThread","Investigate source/target process and adjacent activity."],
["10","Sysmon","Process access","Review GrantedAccess, CallTrace and target process."],
["11","Sysmon","File create","Correlate path, process, hash and nearby events."],
["12","Sysmon","Registry object create/delete","Review registry path and process context."],
["13","Sysmon","Registry value set","Review target value and writing process."],
["22","Sysmon","DNS query","Correlate query name, process and network activity."]
];
var F=function(id,label,placeholder,type){return '<label class="psv-field">'+label+'<input id="'+id+'" type="'+(type||"text")+'" placeholder="'+(placeholder||"")+'"></label>'};
var A=function(id,label,placeholder,rows){return '<label class="psv-field">'+label+'<textarea id="'+id+'" rows="'+(rows||6)+'" placeholder="'+(placeholder||"")+'"></textarea></label>'};
var S=function(id,label,opts){return '<label class="psv-field">'+label+'<select id="'+id+'">'+opts.map(function(o){return '<option value="'+esc(o[0])+'">'+esc(o[1])+'</option>'}).join("")+'</select></label>'};
var B=function(label,action){return '<button class="psv-btn" type="button" data-action="'+(action||"run")+'">'+label+'</button>'};
var O=function(){return '<pre class="psv-output" id="out" aria-live="polite">Output will appear here.</pre>'};
var panel=function(id,title,desc,body){return '<section class="psv-tool-panel" id="panel-'+id+'" hidden><div class="psv-panel-head"><div><div class="psv-eyebrow">TOOL WORKSPACE</div><h2>'+title+'</h2><p>'+desc+'</p></div>'+B("← All tools","back")+'</div>'+body+'</section>'};
var bodies={
ioc:A("ioc-input","Input text","Paste logs, email or text to scan locally…",9)+'<div class="psv-actions">'+B("Extract indicators")+' '+B("Clear","clear")+'</div>'+O(),
intel:F("intel-indicator","IP address or domain","203.0.113.10 or example.com")+'<p class="psv-note">Nothing is submitted automatically. Selecting a provider sends the indicator to that external service. No API keys are requested or stored here.</p>'+B("Prepare lookup links")+'<div id="intel-links" class="psv-link-grid"></div>',
email:A("email-input","Raw email headers","Received: …\nAuthentication-Results: …",10)+B("Analyze headers")+O(),
siem:S("siem-platform","Target platform",[["splunk","Splunk SPL"],["elastic","Elastic / KQL"],["sentinel","Microsoft Sentinel / KQL"],["qradar","IBM QRadar AQL"]])+S("siem-kind","Detection pattern",[["failed","Repeated failed logons"],["powershell","PowerShell execution"],["network","Outbound network connection"],["sigma","Inspect basic Sigma YAML"]])+A("siem-fields","Optional Sigma YAML / parameters","title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 4688\n  condition: selection",6)+B("Build query")+O(),
events:F("event-search","Search ID, source or keyword","4625, Sysmon, process")+'<div id="event-results" class="psv-event-list"></div>',
regex:F("regex-pattern","Pattern","\b\d{3}\b")+F("regex-flags","Flags (gimsyu)","gm")+A("regex-text","Test text","Paste sample logs…",7)+B("Test pattern")+O(),
yara:F("yara-name","Rule name","Suspicious_Sample")+A("yara-strings","String indicators (one per line)","suspicious_marker\nanother marker",5)+S("yara-condition","Match condition",[["any","Any string"],["all","All strings"],["two","At least 2 strings"]])+B("Generate YARA rule")+O(),
deob:A("deob-input","Encoded or escaped text","Paste Base64, URL-encoded or escaped text…",7)+S("deob-mode","Decode operation",[["base64","Base64 → UTF-8"],["url","URL decode"],["unicode","Decode \\uXXXX escapes"],["hex","Hex bytes → UTF-8"],["entities","HTML entities"]])+B("Decode text")+O(),
json:A("json-input","JSON input",'{"event":{"id":4625}}',8)+'<div class="psv-actions">'+B("Beautify","run")+' '+B("Minify","minify")+'</div>'+O(),
time:F("time-input","Timestamp","2026-10-17T12:30:00Z")+F("time-zone","Target time zone","Asia/Riyadh")+B("Convert timestamp")+O(),
severity:S("sev-impact","Business impact",[["0","None / negligible"],["1","Limited"],["2","Material"],["3","Severe / critical"]])+S("sev-scope","Scope",[["0","Single endpoint / user"],["1","Multiple endpoints"],["2","Critical system / many users"],["3","Enterprise-wide"]])+S("sev-confidence","Evidence confidence",[["0","Unconfirmed"],["1","Plausible"],["2","Strong evidence"],["3","Confirmed"]])+S("sev-exposure","Threat / exposure",[["0","Contained / no known exposure"],["1","Potential exposure"],["2","Active suspicious activity"],["3","Active compromise / exfiltration"]])+B("Calculate triage severity")+O(),
report:F("rep-id","Incident ID","INC-2026-001")+F("rep-title","Title","Suspicious authentication activity")+F("rep-date","Detected at (ISO 8601)","2026-10-17T00:00:00+03:00")+S("rep-sev","Severity",[["Critical","Critical"],["High","High"],["Medium","Medium"],["Low","Low"],["Informational","Informational"]])+A("rep-summary","Executive summary","What happened, affected assets, current status…",4)+A("rep-evidence","Evidence and timeline","Timestamps, event IDs, hashes, source IPs…",4)+A("rep-actions","Containment and next steps","Actions completed and pending…",4)+B("Generate report")+O(),
cvss:S("cv-av","Attack Vector",[["N","Network (N)"],["A","Adjacent (A)"],["L","Local (L)"],["P","Physical (P)"]])+S("cv-ac","Attack Complexity",[["L","Low (L)"],["H","High (H)"]])+S("cv-pr","Privileges Required",[["N","None (N)"],["L","Low (L)"],["H","High (H)"]])+S("cv-ui","User Interaction",[["N","None (N)"],["R","Required (R)"]])+S("cv-s","Scope",[["U","Unchanged (U)"],["C","Changed (C)"]])+'<div class="psv-form-grid">'+["c","i","a"].map(function(k){return S("cv-"+k,k.toUpperCase()+" impact",[["N","None (N)"],["L","Low (L)"],["H","High (H)"]])}).join("")+'</div>'+B("Calculate CVSS v3.1")+O()
};
var app=$("#psv-tools-app");if(!app)return;
app.innerHTML='<div class="psv-console"><div class="psv-console-top"><span class="psv-live-dot"></span><span>LOCAL PROCESSING</span><span class="psv-console-spacer"></span><span id="psv-clock"></span><button id="psv-theme" class="psv-theme-btn" type="button">☼ Toggle theme</button></div><header class="psv-hero"><div class="psv-eyebrow">PRIVACY SKILL VAULT / SECURITY TOOLS</div><h1>Security operations.<br><span>At your fingertips.</span></h1><p>Browser-based utilities for SOC analysts, incident responders and detection engineers. Your text stays local unless you deliberately open an external lookup.</p><div class="psv-hero-stats"><span><b>13</b> utilities</span><span><b>0</b> required accounts</span><span><b>Local</b> by default</span></div></header><div class="psv-search-wrap"><input id="psv-search" type="search" placeholder="Search tools, workflows, indicators…" aria-label="Search tools"><span class="psv-shortcut">FILTER</span></div><nav id="psv-tool-grid" class="psv-tool-grid" aria-label="Available tools">'+defs.map(function(t,i){return '<button class="psv-tool-card" data-tool="'+t[0]+'"><span class="psv-tool-index">'+String(i+1).padStart(2,"0")+'</span><span class="psv-tool-title">'+t[1]+'</span><span class="psv-tool-desc">'+t[2]+'</span><span class="psv-tool-open">Open workspace ↗</span></button>'}).join("")+'</nav><div id="psv-workspace">'+defs.map(function(t){return panel(t[0],t[1],t[2],bodies[t[0]])}).join("")+'</div><footer class="psv-footnote"><span>PSV / CLIENT-SIDE WORKBENCH</span><span>Verify outputs before operational use.</span></footer><div id="psv-toast" class="psv-toast" role="status"></div></div>';
var get=function(id){return ($("#"+id)?.value||"").trim()}, out=function(s){var e=$("#out");if(e)e.textContent=s}, toast=function(s){var e=$("#psv-toast");e.textContent=s;e.classList.add("show");setTimeout(function(){e.classList.remove("show")},2200)};
var back=function(){$$(".psv-tool-panel").forEach(function(p){p.hidden=true});$("#psv-tool-grid").hidden=false;$(".psv-search-wrap").hidden=false};
var show=function(id){$("#psv-tool-grid").hidden=true;$(".psv-search-wrap").hidden=true;$$(".psv-tool-panel").forEach(function(p){p.hidden=p.id!=="panel-"+id});if(id==="events")renderEvents();window.scrollTo({top:0,behavior:"smooth"})};
function renderEvents(){var q=get("event-search").toLowerCase(),rows=events.filter(function(e){return e.join(" ").toLowerCase().includes(q)});$("#event-results").innerHTML=rows.map(function(e){return '<article class="psv-event-row"><div class="psv-event-id">'+esc(e[0])+'</div><div><b>'+esc(e[2])+'</b><small>'+esc(e[1])+'</small><p>'+esc(e[3])+'</p></div></article>'}).join("")||'<p class="psv-note">No entries found.</p>'}
function cvss(){
var AV={N:.85,A:.62,L:.55,P:.2},AC={L:.77,H:.44},UI={N:.85,R:.62},scope=get("cv-s"),PR=scope==="U"?{N:0,L:.62,H:.27}:{N:0,L:.68,H:.5},imp={N:0,L:.22,H:.56};
var C=imp[get("cv-c")],I=imp[get("cv-i")],A=imp[get("cv-a")],isc=1-(1-C)*(1-I)*(1-A);
var impact=scope==="U"?6.42*isc:7.52*(isc-.029)-3.25*Math.pow(isc-.02,15);
var vector="CVSS:3.1/AV:"+get("cv-av")+"/AC:"+get("cv-ac")+"/PR:"+get("cv-pr")+"/UI:"+get("cv-ui")+"/S:"+scope+"/C:"+get("cv-c")+"/I:"+get("cv-i")+"/A:"+get("cv-a");
if(impact<=0){out("CVSS v3.1 Base Score: 0.0 (None)\nVector: "+vector);return}
var exploit=8.22*AV[get("cv-av")]*AC[get("cv-ac")]*PR[get("cv-pr")]*UI[get("cv-ui")],score=scope==="U"?Math.min(impact+exploit,10):Math.min(1.08*(impact+exploit),10);
score=Math.ceil(score*10)/10;var rating=score===0?"None":score<4?"Low":score<7?"Medium":score<9?"High":"Critical";
out("CVSS v3.1 Base Score: "+score.toFixed(1)+" ("+rating+")\nVector: "+vector+"\n\nBase metrics only. Confirm using the official FIRST calculator before publishing.")
}
function run(id,action){
try{
if(action==="back"){back();return}if(action==="clear"){$$("textarea",$("#panel-"+id)).forEach(function(e){e.value=""});out("Cleared.");return}
if(id==="ioc"){
var text=get("ioc-input"),sets={IPv4:new Set(),Domains:new Set(),URLs:new Set(),MD5:new Set(),SHA1:new Set(),SHA256:new Set()};
var add=function(k,re){Array.from(text.matchAll(re)).forEach(function(m){sets[k].add(m[0].replace(/[),.;\]}]+$/,""))})};
add("URLs",/https?:\/\/[^\s"'<>]+/gi);add("IPv4",/(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])/g);
add("MD5",/(?<![a-f\d])[a-f\d]{32}(?![a-f\d])/gi);add("SHA1",/(?<![a-f\d])[a-f\d]{40}(?![a-f\d])/gi);add("SHA256",/(?<![a-f\d])[a-f\d]{64}(?![a-f\d])/gi);add("Domains",/(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])/gi);
out(Object.keys(sets).map(function(k){return k+" ("+sets[k].size+")\n"+(Array.from(sets[k]).join("\n")||"—")}).join("\n\n"));return
}
if(id==="intel"){
var val=get("intel-indicator");if(!val)throw Error("Enter an IP address or domain.");var clean=val.replace(/^https?:\/\//i,"").split("/")[0];if(!/^[a-z0-9.:-]+$/i.test(clean))throw Error("Enter a plain IP address or domain.");
var links=[["VirusTotal","https://www.virustotal.com/gui/search/"],["AbuseIPDB","https://www.abuseipdb.com/check/"],["Cisco Talos","https://talosintelligence.com/reputation_center/lookup?search="],["URLhaus","https://urlhaus.abuse.ch/browse.php?search="],["Google Safe Browsing","https://transparencyreport.google.com/safe-browsing/search?url="]];
$("#intel-links").innerHTML=links.map(function(x){return '<a class="psv-external-link" href="'+x[1]+encodeURIComponent(clean)+'" target="_blank" rel="noopener noreferrer">'+x[0]+' ↗</a>'}).join("");toast("Choose a provider to submit the indicator externally.");return
}
if(id==="email"){
var raw=get("email-input");if(!raw)throw Error("Paste email headers first.");var lines=raw.split(/\r?\n/),pick=function(label){return lines.filter(function(l){return new RegExp("^"+label+"\\s*:","i").test(l)}).map(function(l){return l.replace(/^[^:]+:\s*/,"")}).join("\n")||"Not present"};
out("HEADER SUMMARY\nReceived hops: "+lines.filter(function(l){return /^Received\s*:/i.test(l)}).length+"\nFrom: "+pick("From")+"\nReply-To: "+pick("Reply-To")+"\nReturn-Path: "+pick("Return-Path")+"\nMessage-ID: "+pick("Message-ID")+"\nDate: "+pick("Date")+"\nSubject: "+pick("Subject")+"\n\nAuthentication-Results: "+pick("Authentication-Results")+"\nSPF: "+((/spf=(pass|fail|softfail|neutral|none)/i.exec(raw)||[])[0]||"Not found")+"\nDKIM: "+((/dkim=(pass|fail|neutral|none)/i.exec(raw)||[])[0]||"Not found")+"\nDMARC: "+((/dmarc=(pass|fail|bestguesspass|none)/i.exec(raw)||[])[0]||"Not found")+"\n\nHeaders can be forged. Trust authentication results only when added by a trusted receiving system.");return
}
if(id==="siem"){
var p=get("siem-platform"),k=get("siem-kind"),q={
splunk:{failed:'index=* (EventCode=4625 OR EventID=4625) | stats count by user, src, host | where count >= 5',powershell:'index=* (EventCode=4104 OR EventID=4104 OR EventCode=4688) (powershell OR pwsh)',network:'index=* (EventID=3 OR EventCode=3) | stats count by Image, DestinationIp, DestinationPort'},
elastic:{failed:'event.code : "4625"',powershell:'event.code : ("4104" or "4688") and process.name : ("powershell.exe" or "pwsh.exe")',network:'event.code : "3" and destination.ip:*'},
sentinel:{failed:'SecurityEvent | where EventID == 4625 | summarize Attempts=count() by Account, IpAddress, Computer | where Attempts >= 5',powershell:'SecurityEvent | where EventID in (4104, 4688) and Process has_any ("powershell", "pwsh")',network:'Event | where EventID == 3 | summarize count() by Computer, Source, Destination'},
qradar:{failed:'SELECT username, sourceip, COUNT(*) AS attempts FROM events WHERE eventid = 4625 GROUP BY username, sourceip HAVING COUNT(*) >= 5 LAST 1 HOURS',powershell:'SELECT username, sourceip, QIDNAME(qid) FROM events WHERE eventid IN (4104, 4688) LAST 1 HOURS',network:'SELECT sourceip, destinationip, destinationport FROM events WHERE eventid = 3 LAST 1 HOURS'}};
if(k==="sigma"){var y=get("siem-fields"),title=(/title:\s*(.+)/i.exec(y)||[])[1]||"Imported Sigma detection",eid=(/EventID:\s*(\d+)/i.exec(y)||[])[1]||"not detected";out("Basic Sigma YAML inspection (not a complete compiler)\nTitle: "+title+"\nEventID: "+eid+"\n\n"+(p==="splunk"?'index=* '+(eid!=="not detected"?"EventCode="+eid:"")+' | table _time, host, user, EventCode, CommandLine':p==="qradar"?'SELECT * FROM events WHERE '+(eid!=="not detected"?"eventid = "+eid:"eventid IS NOT NULL")+' LAST 1 HOURS':(p==="elastic"?'event.code':'EventID')+' '+(eid!=="not detected"?'== "'+eid+'"':"*")+'\n| project TimeGenerated, Computer, Account, EventID')+"\n\nReview modifiers, logsource mappings and backend syntax manually.");}else out(q[p][k]+"\n\nStarter query only. Validate field mappings and syntax in your SIEM.");return
}
if(id==="events"){renderEvents();return}
if(id==="regex"){var flags=get("regex-flags")||"g";if(/[^dgimsuvy]/.test(flags)||new Set(flags).size!==flags.length)throw Error("Invalid or duplicate JavaScript regex flags.");var re=new RegExp(get("regex-pattern"),flags),matches=Array.from(get("regex-text").matchAll(re)).slice(0,500);out("Matches: "+matches.length+"\n\n"+(matches.map(function(m,i){return (i+1)+". "+JSON.stringify(m[0])+" at index "+m.index}).join("\n")||"No matches."));return}
if(id==="yara"){var name=get("yara-name")||"PSV_Rule";if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))throw Error("Use a rule name containing letters, digits and underscores.");var vals=get("yara-strings").split(/\r?\n/).map(function(s){return s.trim()}).filter(Boolean);if(!vals.length)throw Error("Add at least one string.");var ss=vals.map(function(v,i){return "    "+(/^\$[a-zA-Z_]\w*\s*=/.test(v)?v:"$s"+(i+1)+' = "'+v.replace(/\\/g,"\\\\").replace(/"/g,'\\"')+'"')});out("rule "+name+"\n{\n  meta:\n    author = \"Privacy Skill Vault\"\n    description = \"Generated scaffold; review before deployment\"\n  strings:\n"+ss.join("\n")+"\n  condition:\n    "+({"any":"any of them","all":"all of them","two":"2 of them"}[get("yara-condition")])+"\n}");return}
if(id==="deob"){var v=get("deob-input"),mode=get("deob-mode"),res="";if(mode==="base64"){var bin=atob(v.replace(/\s/g,""));res=new TextDecoder("utf-8",{fatal:true}).decode(Uint8Array.from(bin,function(c){return c.charCodeAt(0)}))}if(mode==="url")res=decodeURIComponent(v.replace(/\+/g," "));if(mode==="unicode")res=v.replace(/\\u([0-9a-f]{4})/gi,function(_,h){return String.fromCharCode(parseInt(h,16))}).replace(/\\x([0-9a-f]{2})/gi,function(_,h){return String.fromCharCode(parseInt(h,16))});if(mode==="hex"){var h=v.replace(/0x/gi,"").replace(/[\s,:-]/g,"");if(!/^(?:[0-9a-f]{2})+$/i.test(h))throw Error("Hex input must contain pairs of hex digits.");res=new TextDecoder("utf-8",{fatal:true}).decode(Uint8Array.from(h.match(/../g),function(x){return parseInt(x,16)}))}if(mode==="entities"){var d=document.createElement("textarea");d.innerHTML=v;res=d.value}out(res);return}
if(id==="json"){var obj=JSON.parse(get("json-input"));out(action==="minify"?JSON.stringify(obj):JSON.stringify(obj,null,2));return}
if(id==="time"){var raw=get("time-input"),zone=get("time-zone")||"UTC",date=/^\d{10,13}$/.test(raw)?new Date(Number(raw)*(raw.length===10?1000:1)):new Date(raw);if(isNaN(date.getTime()))throw Error("Invalid timestamp. Use ISO 8601 or Unix epoch seconds/milliseconds.");var fmt=function(z){return new Intl.DateTimeFormat("en-GB",{timeZone:z,dateStyle:"full",timeStyle:"long",hourCycle:"h23"}).format(date)};out("UTC: "+fmt("UTC")+"\n"+zone+": "+fmt(zone)+"\n\nUnix seconds: "+Math.floor(date.getTime()/1000)+"\nUnix milliseconds: "+date.getTime()+"\nISO 8601: "+date.toISOString());return}
if(id==="severity"){var score=["sev-impact","sev-scope","sev-confidence","sev-exposure"].reduce(function(a,x){return a+Number(get(x))},0),level=score>=10?"CRITICAL":score>=8?"HIGH":score>=5?"MEDIUM":"LOW";out("Triage score: "+score+"/12\nSuggested severity: "+level+"\n\nFactors are weighted equally in this illustrative heuristic. Apply your organization's escalation matrix.");return}
if(id==="report"){out("# Incident Report — "+(get("rep-id")||"Unassigned")+"\n\n**Title:** "+(get("rep-title")||"Untitled incident")+"\n**Detected at:** "+(get("rep-date")||"Not recorded")+"\n**Severity:** "+get("rep-sev")+"\n**Status:** Under investigation\n\n## Executive summary\n"+(get("rep-summary")||"Not provided.")+"\n\n## Evidence and timeline\n"+(get("rep-evidence")||"Not provided.")+"\n\n## Containment and next steps\n"+(get("rep-actions")||"Not provided.")+"\n\n## Handling notes\n- Preserve original evidence and record timestamps/time zones.\n- Separate confirmed facts from hypotheses; document sources and confidence.\n- Follow internal evidence-handling procedures.");return}
if(id==="cvss"){cvss();return}
}catch(e){out("Error: "+(e.message||e))}
}
app.addEventListener("click",function(e){var card=e.target.closest("[data-tool]");if(card){show(card.dataset.tool);return}var b=e.target.closest("[data-action]");if(!b)return;var p=b.closest(".psv-tool-panel");if(p)run(p.id.replace("panel-",""),b.dataset.action)});
$("#psv-search").addEventListener("input",function(e){$$(".psv-tool-card").forEach(function(c){var t=defs.find(function(x){return x[0]===c.dataset.tool});c.hidden=!(t[1]+" "+t[2]).toLowerCase().includes(e.target.value.toLowerCase())})});
$("#event-search").addEventListener("input",renderEvents);
$("#psv-theme").addEventListener("click",function(){var root=document.documentElement,light=root.dataset.mdColorScheme==="default";root.dataset.mdColorScheme=light?"slate":"default";root.style.colorScheme=light?"dark":"light";toast("Switched to "+(light?"dark":"light")+" mode")});
var tick=function(){$("#psv-clock").textContent=new Date().toLocaleTimeString([],{hour12:false})};tick();setInterval(tick,1000);
})();

/* PSV hardening pack: ephemeral credentials, public enrichment, richer references and CVSS v3.1. */
(function(){
"use strict";
let memoryApiKeys={}; // Deliberately ephemeral: never persisted in Web Storage.
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const safe=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const out=s=>{const e=$("#out");if(e)e.textContent=s};
const toast=s=>{const e=$("#psv-toast");if(e){e.textContent=s;e.classList.add("show");setTimeout(()=>e.classList.remove("show"),2200)}};
const addOption=(select,value,label)=>{if(select&&!Array.from(select.options).some(o=>o.value===value))select.add(new Option(label,value))};
const domains=["203.0.113.42","example.org"];
const eventData=[
["1102","Windows Security","Audit log cleared","1102","SubjectUserName,SubjectDomainName,SubjectLogonId","T1070.001",'winlog.event_id: 1102',"Tune approved maintenance; investigate unexpected clear events."],
["4624","Windows Security","Successful logon","4624","TargetUserName,TargetDomainName,LogonType,IpAddress,WorkstationName,AuthenticationPackageName,TargetLogonId","T1078",'event.code: "4624" and winlog.event_data.LogonType: ("3" or "10")',"Tune service accounts and known management subnets; retain unusual logon types."],
["4625","Windows Security","Failed logon","4625","TargetUserName,TargetDomainName,LogonType,IpAddress,Status,SubStatus,WorkstationName","T1110",'event.code: "4625" and winlog.event_data.SubStatus: "0xC000006A"',"Tune stale credentials and known scanners; correlate source and account burst patterns."],
["4648","Windows Security","Explicit credentials used","4648","SubjectUserName,TargetUserName,TargetServerName,ProcessName,IpAddress","T1078",'event.code: "4648"',"Tune approved run-as tools and admin workflows."],
["4656","Windows Security","Handle requested","4656","SubjectUserName,ObjectName,ObjectType,AccessMask,ProcessName","T1003",'event.code: "4656" and winlog.event_data.ObjectName:*' ,"Enable only relevant SACLs; tune backup and endpoint agents."],
["4663","Windows Security","Object access attempt","4663","SubjectUserName,ObjectName,AccessMask,ProcessName","T1005",'event.code: "4663" and winlog.event_data.AccessMask:*',"Tune known indexing, backup and security processes."],
["4672","Windows Security","Special privileges assigned","4672","SubjectUserName,SubjectLogonId,PrivilegeList","T1078",'event.code: "4672"',"Correlate with 4624; exclude expected system/service identities carefully."],
["4688","Windows Security","Process creation","4688","NewProcessName,CommandLine,CreatorProcessName,SubjectUserName,TokenElevationType","T1059",'event.code: "4688" and process.command_line:*',"Enable command-line auditing; tune known software deployment tooling."],
["4697","Windows Security","Service installed","4697","ServiceName,ServiceFileName,ServiceType,SubjectUserName","T1543.003",'event.code: "4697"',"Tune signed management agents and approved deployment windows."],
["4698","Windows Security","Scheduled task created","4698","TaskName,TaskContent,SubjectUserName","T1053.005",'event.code: "4698"',"Tune approved software updaters and scheduled enterprise jobs."],
["4719","Windows Security","Audit policy changed","4719","SubjectUserName,CategoryId,SubcategoryGuid,AuditPolicyChanges","T1562.002",'event.code: "4719"',"Correlate with authorized GPO/security baseline changes."],
["4720","Windows Security","User account created","4720","TargetUserName,TargetDomainName,SubjectUserName","T1136.001",'event.code: "4720"',"Tune approved onboarding and identity provisioning."],
["4722","Windows Security","User account enabled","4722","TargetUserName,SubjectUserName","T1098",'event.code: "4722"',"Correlate with ticketed access restoration."],
["4724","Windows Security","Password reset attempted","4724","TargetUserName,SubjectUserName","T1098",'event.code: "4724"',"Tune helpdesk workflows; alert on privileged targets and unusual actors."],
["4728","Windows Security","Member added to global security group","4728","TargetUserName,MemberName,SubjectUserName","T1098.007",'event.code: "4728"',"Allow-list approved group administration, not all group changes."],
["4732","Windows Security","Member added to local security group","4732","TargetUserName,MemberName,SubjectUserName","T1098.007",'event.code: "4732"',"Tune endpoint management and local admin tooling."],
["4738","Windows Security","User account changed","4738","TargetUserName,SubjectUserName,PasswordLastSet,UserAccountControl","T1098",'event.code: "4738"',"Compare against approved identity change workflows."],
["4740","Windows Security","Account locked out","4740","TargetUserName,CallerComputerName,SubjectUserName","T1110",'event.code: "4740"',"Tune user-reported lockouts; correlate preceding 4625 events."],
["4768","Windows Security","Kerberos TGT requested","4768","TargetUserName,IpAddress,Status,TicketEncryptionType,PreAuthType","T1558.004",'event.code: "4768" and winlog.event_data.Status != "0x0"',"Tune domain-controller noise and known legacy clients."],
["4769","Windows Security","Kerberos service ticket requested","4769","TargetUserName,ServiceName,IpAddress,TicketEncryptionType,Status","T1558.003",'event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17"',"Tune known service-account ticket patterns; investigate RC4 in context."],
["4771","Windows Security","Kerberos pre-authentication failed","4771","TargetUserName,IpAddress,FailureCode,PreAuthType","T1110",'event.code: "4771"',"Tune clock skew and expired credentials; correlate by source/account."],
["4776","Windows Security","NTLM credential validation","4776","TargetUserName,Workstation,Status","T1550.002",'event.code: "4776" and winlog.event_data.Status != "0x0"',"Tune legacy apps and expected NTLM-dependent systems."],
["5140","Windows Security","Network share accessed","5140","SubjectUserName,ShareName,ShareLocalPath,IpAddress","T1135",'event.code: "5140"',"Tune standard file-server access by group and share."],
["5145","Windows Security","Detailed share access check","5145","SubjectUserName,ShareName,RelativeTargetName,AccessMask,IpAddress","T1039",'event.code: "5145"',"Tune common file extensions and backup services; preserve unusual writes."],
["7045","System","Service installed","7045","ServiceName,ImagePath,ServiceType,StartType,AccountName","T1543.003",'winlog.channel: "System" and event.code: "7045"',"Tune approved software installation windows."],
["1","Sysmon","Process creation","1","UtcTime,ProcessGuid,ProcessId,Image,CommandLine,ParentImage,ParentCommandLine,Hashes,User","T1059",'winlog.channel: "Microsoft-Windows-Sysmon/Operational" and event.code: "1" and process.command_line:*',"Tune signed software deployment; retain suspicious parent-child combinations."],
["2","Sysmon","File creation time changed","2","UtcTime,ProcessGuid,Image,TargetFilename,CreationUtcTime","T1070.006",'event.code: "2"',"Tune installers and synchronization tools."],
["3","Sysmon","Network connection","3","UtcTime,ProcessGuid,Image,DestinationIp,DestinationPort,Protocol,Initiated","T1071",'event.code: "3" and destination.ip:*',"Tune approved browsers and agents; investigate rare process destinations."],
["6","Sysmon","Driver loaded","6","UtcTime,ImageLoaded,Hashes,Signature,SignatureStatus","T1068",'event.code: "6"',"Tune signed vendor drivers; alert on unsigned/unexpected paths."],
["7","Sysmon","Image loaded","7","UtcTime,Image,ImageLoaded,Hashes,Signature,SignatureStatus","T1129",'event.code: "7" and winlog.event_data.SignatureStatus: "Unavailable"',"High volume: enable selectively and tune trusted signed modules."],
["8","Sysmon","CreateRemoteThread","8","UtcTime,SourceImage,TargetImage,StartAddress,StartModule,StartFunction","T1055",'event.code: "8"',"Tune debuggers, EDR and accessibility software."],
["10","Sysmon","Process access","10","UtcTime,SourceImage,TargetImage,GrantedAccess,CallTrace","T1003",'event.code: "10" and winlog.event_data.TargetImage:*lsass.exe',"Tune EDR/AV and diagnostics; scrutinize unusual LSASS access rights."],
["11","Sysmon","File created","11","UtcTime,Image,TargetFilename","T1105",'event.code: "11" and file.path:*',"Tune browser caches and installer temp directories."],
["12","Sysmon","Registry object create/delete","12","EventType,Image,TargetObject","T1112",'event.code: "12"',"Tune software install registry activity."],
["13","Sysmon","Registry value set","13","EventType,Image,TargetObject,Details","T1112",'event.code: "13" and winlog.event_data.TargetObject:*CurrentVersion\\\\Run*',"Tune legitimate application persistence and OS updates."],
["15","Sysmon","File stream created","15","Image,TargetFilename,CreationUtcTime,Hashes","T1564.004",'event.code: "15"',"Tune browser downloads and common zone identifier creation."],
["17","Sysmon","Named pipe created","17","PipeName,Image,ProcessGuid","T1559",'event.code: "17"',"Tune known RPC/service pipes; investigate rare names and processes."],
["18","Sysmon","Named pipe connected","18","PipeName,Image,ProcessGuid","T1559",'event.code: "18"',"Tune known service communication and security tooling."],
["22","Sysmon","DNS query","22","QueryName,QueryStatus,QueryResults,Image,ProcessGuid","T1071.004",'event.code: "22" and dns.question.name:*',"Tune telemetry domains and known security vendors; retain rare domains."],
["23","Sysmon","File delete archived","23","Image,TargetFilename,Hashes","T1070.004",'event.code: "23"',"Tune cleanup utilities; review deleted executable/script artifacts."],
["25","Sysmon","Process tampering","25","Image,ProcessGuid,Type","T1055",'event.code: "25"',"Correlate with EDR alerts and expected protected-process behavior."]
];
const logonTypes={"2":"Interactive — local console","3":"Network — SMB/network authentication","4":"Batch — scheduled task","5":"Service — service account logon","7":"Unlock — workstation unlock","8":"NetworkCleartext — cleartext credentials to authentication package","9":"NewCredentials — RunAs /netonly","10":"RemoteInteractive — RDP/Terminal Services","11":"CachedInteractive — cached domain credentials"};
const substatus={"0xC0000064":"Username does not exist","0xC000006A":"Incorrect password","0xC000006D":"Generic logon failure","0xC000006E":"Account restriction","0xC0000070":"Workstation restriction","0xC0000071":"Password expired","0xC0000072":"Account disabled","0xC0000193":"Account expired","0xC0000224":"Password must change","0xC0000234":"Account locked out"};
function initEnhancements(){
 const app=$("#psv-tools-app");if(!app||app.dataset.psvEnhanced)return;app.dataset.psvEnhanced="1";
 /* Public enrichment never persists credentials or indicators. */
 const intel=$("#panel-intel");
 if(intel){const note=intel.querySelector(".psv-note");if(note)note.textContent="Public lookups send the entered indicator to the named public providers. Optional keys exist only in memory and disappear on reload/tab close; they are never written to browser storage.";
 const head=intel.querySelector(".psv-panel-head");if(head){const b=document.createElement("button");b.className="psv-btn";b.type="button";b.textContent="Optional in-memory API keys";b.onclick=()=>{const vals={};["VirusTotal","AbuseIPDB","AlienVault OTX","URLScan.io"].forEach(n=>{const k=prompt(n+" API key (leave blank to skip; memory only):");if(k)vals[n]=k});memoryApiKeys=vals;toast("Keys retained in memory only until reload/close.");};head.append(b)}}
 /* Add CVSS temporal/environmental controls. */
 const cv=$("#panel-cvss");if(cv&&!$("#cv-e")){const groups=[
 ["Temporal metrics",[["cv-e","E",["X","H","F","P","U"]],["cv-rl","RL",["X","U","W","T","O"]],["cv-rc","RC",["X","C","R","U"]]]],
 ["Environmental metrics",[["cv-cr","CR",["X","L","M","H"]],["cv-ir","IR",["X","L","M","H"]],["cv-ar","AR",["X","L","M","H"]],["cv-mav","MAV",["X","N","A","L","P"]],["cv-mac","MAC",["X","L","H"]],["cv-mpr","MPR",["X","N","L","H"]],["cv-mui","MUI",["X","N","R"]],["cv-ms","MS",["X","U","C"]],["cv-mc","MC",["X","N","L","H"]],["cv-mi","MI",["X","N","L","H"]],["cv-ma","MA",["X","N","L","H"]]]]
 ];groups.forEach(([title,items])=>{const h=document.createElement("h3");h.textContent=title;cv.insertBefore(h,cv.querySelector('[data-action="run"]'));const wrap=document.createElement("div");wrap.className="psv-form-grid";items.forEach(([id,label,opts])=>{const l=document.createElement("label");l.className="psv-field";l.textContent=label+" ";const s=document.createElement("select");s.id=id;opts.forEach(o=>s.add(new Option(o,o)));l.append(s);wrap.append(l)});cv.insertBefore(wrap,cv.querySelector('[data-action="run"]'))})}
 /* Searchable analyst encyclopedia with XML fields, KQL, ATT&CK and tuning. */
 const search=$("#event-search");if(search){search.placeholder="Search 35+ Windows / Sysmon events";const render=()=>{const q=search.value.toLowerCase();const host=$("#event-results");if(!host)return;const rows=eventData.filter(e=>e.join(" ").toLowerCase().includes(q));host.innerHTML=rows.map(e=>'<article class="psv-event-row"><div class="psv-event-id">'+safe(e[0])+'</div><div><b>'+safe(e[2])+' — '+safe(e[1])+'</b><small>Event '+safe(e[0])+' · ATT&CK '+safe(e[5])+'</small><p><b>XML fields:</b> '+safe(e[4])+'</p><p><b>Elastic KQL:</b> <code>'+safe(e[6])+'</code></p><p><b>False-positive tuning:</b> '+safe(e[7])+'</p>'+(e[0]==="4624"?'<p><b>Logon types:</b> '+Object.entries(logonTypes).map(([k,v])=>k+" "+v).join("; ")+'</p>':'')+(e[0]==="4625"?'<p><b>SubStatus:</b> '+Object.entries(substatus).map(([k,v])=>k+" "+v).join("; ")+'</p>':'')+'</div></article>').join("")||'<p class="psv-note">No events found.</p>'};search.addEventListener("input",render);search.value="";render()}
 /* One capture-phase listener adds keyless enrichment and verified CVSS math before legacy handlers. */
 app.addEventListener("click",async ev=>{const b=ev.target.closest("button[data-action='run']");if(!b)return;const p=b.closest(".psv-tool-panel");if(!p)return;const id=p.id.replace("panel-","");
 if(id==="intel"){ev.preventDefault();ev.stopImmediatePropagation();await intelLookup();return}
 if(id==="cvss"){ev.preventDefault();ev.stopImmediatePropagation();cvssFull();return}
 },true);
 /* Every workspace receives a sample button. It runs the tool after populating safe synthetic data. */
 const samples={
 ioc:{"ioc-input":"Failed logon source=203.0.113.42 domain=example.org URL=https://example.org/login hash=d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"},
 intel:{"intel-indicator":"8.8.8.8"},email:{"email-input":"From: security@example.org\nReply-To: attacker@example.net\nReceived: from mail.example.net (203.0.113.42)\nAuthentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail"},
 siem:{"siem-kind":"sigma","siem-fields":"title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains: -enc\n  filter:\n    Image|endswith: powershell.exe\n  condition: selection and not filter"},
 events:{"event-search":"4625"},regex:{"regex-pattern":"failed.*logon","regex-flags":"gi","regex-text":"Failed logon user=alice src=203.0.113.42\nSuccessful logon user=bob"},yara:{"yara-name":"Suspicious_PE_Sample","yara-strings":"MZ\nThis program cannot be run in DOS mode","yara-condition":"any"},deob:{"deob-input":"SGVsbG8gU29D","deob-mode":"base64"},json:{"json-input":'{"event":{"id":4625},"source":{"ip":"203.0.113.42"}}'},time:{"time-input":"2026-10-17T12:30:00Z","time-zone":"Asia/Riyadh"},severity:{"sev-impact":"2","sev-scope":"1","sev-confidence":"2","sev-exposure":"2"},report:{"rep-id":"INC-DEMO-001","rep-title":"Suspicious authentication activity","rep-date":"2026-10-17T12:30:00Z","rep-summary":"Repeated failed logons from a test source.","rep-evidence":"Event 4625; source 203.0.113.42; UTC preserved.","rep-actions":"Validate account owner, preserve logs, follow approved response."},cvss:{"cv-av":"N","cv-ac":"L","cv-pr":"N","cv-ui":"N","cv-s":"U","cv-c":"H","cv-i":"H","cv-a":"H"}};
 $$(".psv-tool-panel").forEach(p=>{if(p.querySelector("[data-psv-sample]"))return;const b=document.createElement("button");b.type="button";b.className="psv-btn";b.dataset.psvSample="1";b.textContent="⚡ Load Sample Data";const head=p.querySelector(".psv-panel-head");if(head)head.after(b);b.addEventListener("click",()=>{const id=p.id.replace("panel-","");Object.entries(samples[id]||{}).forEach(([k,v])=>{const e=$("#"+k);if(e)e.value=v});if(id==="events")search?.dispatchEvent(new Event("input"));else p.querySelector("button[data-action='run']")?.click();toast("Synthetic sample loaded; output refreshed.")})});
 async function fetchJson(url,headers={}){const r=await fetch(url,{headers,mode:"cors",credentials:"omit"});if(!r.ok)throw Error("HTTP "+r.status);return r.json()}
 async function intelLookup(){const input=($("#intel-indicator")?.value||"").trim().replace(/^https?:\/\//i,"").split("/")[0];if(!input) return out("Enter an IP address or domain.");const is4=/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input),is6=/^[0-9a-f:]+$/i.test(input)&&input.includes(":"),isIp=is4||is6,domain=/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(input);if(!isIp&&!domain)return out("Use a valid IPv4/IPv6 address or fully qualified domain.");
 const tasks=[];if(isIp){tasks.push(["Shodan InternetDB",()=>fetchJson("https://internetdb.shodan.io/"+encodeURIComponent(input))],["ICANN RDAP",()=>fetchJson("https://rdap.org/ip/"+encodeURIComponent(input))])}else{tasks.push(["ICANN RDAP",()=>fetchJson("https://rdap.org/domain/"+encodeURIComponent(input))]);for(const t of ["A","MX","TXT"]){tasks.push(["Cloudflare DNS "+t,()=>fetchJson("https://cloudflare-dns.com/dns-query?name="+encodeURIComponent(input)+"&type="+t,{Accept:"application/dns-json"})])}}
 const results=await Promise.all(tasks.map(async([name,fn])=>{try{return{name,data:await fn()}}catch(e){return{name,error:e.message+" (provider/CORS may block browser requests)"}}}));
 const card=(r)=>'<article class="psv-intel-card"><h4>'+safe(r.name)+'</h4><pre>'+safe(r.error||JSON.stringify(r.data,null,2).slice(0,10000))+'</pre></article>';
 const links=[["VirusTotal","https://www.virustotal.com/gui/search/"],["AbuseIPDB","https://www.abuseipdb.com/check/"],["URLScan","https://urlscan.io/search/#"],["Cisco Talos","https://talosintelligence.com/reputation_center/lookup?search="]].map(([n,u])=>'<a class="psv-external-link" target="_blank" rel="noopener noreferrer" href="'+u+encodeURIComponent(input)+'">'+n+' ↗</a>').join("");
 const host=$("#intel-links");if(host)host.innerHTML='<p><b>Unified public enrichment:</b> '+safe(input)+'</p><div class="psv-intel-grid">'+results.map(card).join("")+'</div><h4>External provider searches</h4><div class="psv-link-grid">'+links+'</div>';out("Completed "+results.length+" public lookup(s). Failed providers are shown with explicit errors; external quick links require deliberate selection.");}
 function cvssFull(){
 const v=id=>$("#"+id)?.value||"X", pick=(id,def)=>v(id)==="X"?def:v(id);
 const AV={N:.85,A:.62,L:.55,P:.2},AC={L:.77,H:.44},UI={N:.85,R:.62},imp={N:0,L:.22,H:.56},req={L:.5,M:1,H:1.5},E={X:1,H:1,F:.97,P:.94,U:.91},RL={X:1,U:1,W:.97,T:.96,O:.95},RC={X:1,C:1,R:.96,U:.92};
 const roundUp1=x=>Math.ceil(Math.round(x*100000)/10000)/10;
 const S=v("cv-s"),PR=S==="U"?{N:.85,L:.62,H:.27}:{N:.85,L:.68,H:.5};
 const m={AV:v("cv-av"),AC:v("cv-ac"),PR:v("cv-pr"),UI:v("cv-ui"),S,C:v("cv-c"),I:v("cv-i"),A:v("cv-a")};
 if(!AV[m.AV]||!AC[m.AC]||!PR[m.PR]||!UI[m.UI]||![m.C,m.I,m.A].every(x=>x in imp))return out("Select all base metrics.");
 const isc=1-(1-imp[m.C])*(1-imp[m.I])*(1-imp[m.A]);const impact=S==="U"?6.42*isc:7.52*(isc-.029)-3.25*Math.pow(isc-.02,15);const exploit=8.22*AV[m.AV]*AC[m.AC]*PR[m.PR]*UI[m.UI];const base=impact<=0?0:roundUp1(Math.min(S==="U"?impact+exploit:1.08*(impact+exploit),10));
 const temporal=roundUp1(base*E[v("cv-e")]*RL[v("cv-rl")]*RC[v("cv-rc")]);
 const mav=pick("cv-mav",m.AV),mac=pick("cv-mac",m.AC),mpr=pick("cv-mpr",m.PR),mui=pick("cv-mui",m.UI),ms=pick("cv-ms",S),mc=pick("cv-mc",m.C),mi=pick("cv-mi",m.I),ma=pick("cv-ma",m.A);
 const avv=AV[mav],acv=AC[mac],prMap=ms==="U"?{N:.85,L:.62,H:.27}:{N:.85,L:.68,H:.5},prv=prMap[mpr],uiv=UI[mui],cc=imp[mc],ii=imp[mi],aa=imp[ma];
 const cr=req[pick("cv-cr","M")],ir=req[pick("cv-ir","M")],ar=req[pick("cv-ar","M")];
 const missc=Math.min(1-((1-Math.min(1,cc*cr))*(1-Math.min(1,ii*ir))*(1-Math.min(1,aa*ar))),.915);
 const mimpact=ms==="U"?6.42*missc:7.52*(missc-.029)-3.25*Math.pow(missc*.9731-.02,13);
 const mexploit=8.22*avv*acv*prv*uiv;
 let environmental=0;if(mimpact>0){const mbase=Math.min(ms==="U"?mimpact+mexploit:1.08*(mimpact+mexploit),10);environmental=roundUp1(mbase*E[v("cv-e")]*RL[v("cv-rl")]*RC[v("cv-rc")]);}
 const baseVector="CVSS:3.1/AV:"+m.AV+"/AC:"+m.AC+"/PR:"+m.PR+"/UI:"+m.UI+"/S:"+m.S+"/C:"+m.C+"/I:"+m.I+"/A:"+m.A;
 const temporalVector="/E:"+v("cv-e")+"/RL:"+v("cv-rl")+"/RC:"+v("cv-rc");
 const envVector="/CR:"+pick("cv-cr","M")+"/IR:"+pick("cv-ir","M")+"/AR:"+pick("cv-ar","M")+"/MAV:"+mav+"/MAC:"+mac+"/MPR:"+mpr+"/MUI:"+mui+"/MS:"+ms+"/MC:"+mc+"/MI:"+mi+"/MA:"+ma;
 out("CVSS v3.1 Base Score: "+base.toFixed(1)+"\nTemporal Score: "+temporal.toFixed(1)+"\nEnvironmental Score (modified metrics): "+environmental.toFixed(1)+"\n\nVector: "+baseVector+temporalVector+envVector+"\n\nNote: environmental math follows FIRST CVSS v3.1 modified-impact/exploitability approach; validate vectors with the official FIRST calculator for release decisions.");
 }
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",initEnhancements,{once:true});else initEnhancements();
if(window.document$?.subscribe)window.document$.subscribe(()=>initEnhancements());
})();