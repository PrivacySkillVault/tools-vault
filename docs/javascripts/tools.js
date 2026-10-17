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
app.innerHTML='<div class="psv-console"><header class="psv-hero"><div class="psv-eyebrow">SECURITY OPERATIONS WORKBENCH</div><h1>Analyze. Detect.<br><span>Investigate.</span></h1><p>The Tools section brings together practical SOC utilities, indicator enrichment, log decoders, and detection engineering workbenches used to turn raw telemetry into actionable security investigations.</p></header><div class="psv-search-wrap"><input id="psv-search" type="search" placeholder="Search tools, workflows, indicators…" aria-label="Search tools"><span class="psv-shortcut">FILTER</span></div><nav id="psv-tool-grid" class="psv-tool-grid" aria-label="Available tools">'+defs.map(function(t,i){return '<button class="psv-tool-card" data-tool="'+t[0]+'"><span class="psv-tool-index">'+String(i+1).padStart(2,"0")+'</span><span class="psv-tool-title">'+t[1]+'</span><span class="psv-tool-desc">'+t[2]+'</span><span class="psv-tool-open">Open workspace ↗</span></button>'}).join("")+'</nav><div id="psv-workspace">'+defs.map(function(t){return panel(t[0],t[1],t[2],bodies[t[0]])}).join("")+'</div><div id="psv-toast" class="psv-toast" role="status"></div></div>';
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

(function(){
"use strict";
const $=s=>document.querySelector(s),write=s=>{const e=$("#out");if(e)e.textContent=s};
const presets=[
["LSASS dump via comsvcs.dll","title: LSASS dump via comsvcs.dll\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains|all: comsvcs.dll, MiniDump\n  condition: selection"],
["Kerberoasting RC4","title: Kerberoasting RC4\ndetection:\n  selection:\n    EventID: 4769\n    TicketEncryptionType: '0x17'\n  condition: selection"],
["Shadow copy deletion","title: Shadow copy deletion\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains|all: vssadmin.exe, delete, shadows\n  condition: selection"],
["PowerShell download cradle","title: PowerShell download cradle\ndetection:\n  selection:\n    Image|endswith: powershell.exe\n    CommandLine|contains: DownloadString, Invoke-WebRequest\n  condition: selection"],
["Impossible-travel login triage","title: Remote login triage\ndetection:\n  selection:\n    EventID: 4624\n    LogonType: 10\n  condition: selection"],
["Webshell spawned by w3wp.exe","title: IIS worker spawning shell\ndetection:\n  selection:\n    ParentImage|endswith: w3wp.exe\n    Image|endswith: cmd.exe, powershell.exe\n  condition: selection"]
];
const maps={Image:["process.executable","Image","FolderPath"],CommandLine:["process.command_line","CommandLine","ProcessCommandLine"],ParentImage:["process.parent.executable","ParentImage","InitiatingProcessFolderPath"],TargetFilename:["file.path","TargetFilename","FolderPath"],DestinationIp:["destination.ip","DestinationIp","RemoteIP"],DestinationPort:["destination.port","DestinationPort","RemotePort"],EventID:["event.code","EventCode","EventID"],LogonType:["winlog.event_data.LogonType","LogonType","LogonType"],TicketEncryptionType:["winlog.event_data.TicketEncryptionType","TicketEncryptionType","TicketEncryptionType"]};
function parse(src){let section="",block="",condition="selection",title="",blocks={};for(const line of src.split(/\r?\n/)){let m;if((m=line.match(/^\s*title\s*:\s*(.*)$/)))title=m[1].replace(/^['"]|['"]$/g,"");if(/^\s*detection\s*:\s*$/.test(line)){section="d";continue}if(section!=="d")continue;if((m=line.match(/^\s{2}([A-Za-z0-9_*]+)\s*:\s*$/))&&m[1]!=="condition"){block=m[1];blocks[block]=blocks[block]||[];continue}if((m=line.match(/^\s{2}condition\s*:\s*(.+)$/))){condition=m[1].trim();continue}if((m=line.match(/^\s{4}([A-Za-z0-9_]+)((?:\|[A-Za-z]+)*)\s*:\s*(.*?)\s*$/))&&block){let v=m[3].trim(),values=v.startsWith("[")&&v.endsWith("]")?v.slice(1,-1).split(",").map(x=>x.trim()):v.split(/,\s*/);values=values.map(x=>x.replace(/^['"]|['"]$/g,""));blocks[block].push({field:m[1],mods:m[2].split("|").filter(Boolean),values})}}if(!Object.keys(blocks).length)throw Error("No supported detection blocks found.");return{title,condition,blocks}}
function translate(src,target){const p=parse(src),built={};const q=x=>"'"+String(x).replace(/'/g,"\\'")+"'";function one(x,v){const f=(maps[x.field]||[x.field,x.field,x.field])[target],m=x.mods;if(m.includes("contains"))return target===0?f+":*"+v+"*":target===1?f+"=\"*"+v+"*\"":f+" contains "+q(v);if(m.includes("startswith"))return target===2?f+" startswith "+q(v):target===0?f+":"+v+"*":f+"=\""+v+"*\"";if(m.includes("endswith"))return target===2?f+" endswith "+q(v):target===0?f+":*"+v:f+"=\"*"+v+"\"";return target===0?f+": "+q(v):target===1?f+"="+q(v):f+" == "+q(v)}for(const [name,items] of Object.entries(p.blocks)){const parts=items.map(x=>{const vs=x.values.map(v=>one(x,v));return x.mods.includes("all")?"("+vs.join(" and ")+")":vs.length>1?"("+vs.join(" or ")+")":vs[0]}).filter(Boolean);if(parts.length)built[name]="("+parts.join(" and ")+")"}let expr=p.condition;const wildcard=expr.match(/(\d+)\s+of\s+selection\*/i);if(wildcard){const keys=Object.keys(built).filter(k=>k.startsWith("selection"));if(keys.length<Number(wildcard[1]))throw Error("Not enough selection blocks for numeric-of condition.");expr="("+keys.slice(0,Number(wildcard[1])).map(k=>built[k]).join(" or ")+")"}else if(/all\s+of\s+them/i.test(expr)){expr="("+Object.values(built).join(" and ")+")"}else{for(const k of Object.keys(built).sort((a,b)=>b.length-a.length)){expr=expr.split(k).join(built[k])}if(/\b(selection|filter)\b/.test(expr))throw Error("Could not resolve condition identifiers; review condition and block names.")}return(p.title?p.title+"\n":"")+expr}
function runSigma(){try{const src=$("#siem-fields")?.value||"";write(["ELASTIC KQL",translate(src,0),"SPLUNK SPL",translate(src,1),"MICROSOFT SENTINEL KQL",translate(src,2)].reduce((a,x,i)=>a+(i%2===0?"\n=== "+x+" ===\n":"\n"+x+"\n"),"")+"\nSupported subset only: selection/filter, AND/OR/NOT, numeric 'of selection*', contains/startswith/endswith/all. Review backend syntax and mappings.");}catch(e){write("Sigma translation error: "+e.message)}}
function lintYara(){const name=$("#yara-name")?.value.trim()||"",raw=$("#yara-strings")?.value||"",c=$("#yara-condition")?.value||"any",issues=[],declared=new Set(),rows=raw.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))issues.push("Invalid rule identifier.");let n=1,strings=[];for(const row of rows){let m=row.match(/^(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/),id=m?m[1]:"$s"+n++,pat=m?m[2]:'"'+row.replace(/\\/g,"\\\\").replace(/"/g,'\\"')+'" ascii wide nocase';if(declared.has(id))issues.push("Duplicate identifier "+id);declared.add(id);if((pat.match(/"/g)||[]).length%2)issues.push(id+": unbalanced quotes");if(pat.includes("{")&&(!pat.includes("}")||!/\{[\s\S]*\}/.test(pat)))issues.push(id+": unbalanced hex string");const hex=(pat.match(/\{([\s\S]*?)\}/)||[])[1];if(hex&&(/\[[^\]]*$/.test(hex)||(/\[[^\]]+\]/.test(hex)&&!/\[\s*\d+\s*-\s*\d+\s*\]/.test(hex))))issues.push(id+": malformed hex jump; use [4-8]");if(hex&&/[^0-9a-fA-F?\s\[\]-]/.test(hex))issues.push(id+": invalid hex token; use ?? for wildcard bytes");strings.push("    "+id+" = "+pat)}if(!rows.length)issues.push("Add at least one string.");const condition=({any:"any of them",all:"all of them",two:"2 of them",pe:"uint16(0) == 0x5A4D",size:"filesize < 5MB"}[c]||c);const refs=condition.match(/\$[A-Za-z_][A-Za-z0-9_]*/g)||[];refs.forEach(x=>{if(!declared.has(x))issues.push("Undefined string "+x)});declared.forEach(x=>{if(!refs.includes(x))issues.push("Defined string "+x+" is not referenced in condition")});const rule="rule "+name+" {\n strings:\n"+strings.join("\n")+"\n condition:\n  "+condition+"\n}";const box=$("#yara-live-lint");if(box){box.textContent=issues.length?"Lint findings:\n• "+issues.join("\n• "):"Structural lint passed for supported subset.";box.classList.toggle("is-error",!!issues.length);box.classList.toggle("is-ok",!issues.length)}return{issues,rule}}
function install(){const app=$("#psv-tools-app");if(!app||app.dataset.finalSigmaYara)return;app.dataset.finalSigmaYara="1";const siem=$("#panel-siem"),yara=$("#panel-yara");if(siem){const box=document.createElement("div");box.className="psv-template-list";presets.forEach(([name,rule])=>{const b=document.createElement("button");b.type="button";b.className="psv-btn";b.textContent=name;b.addEventListener("click",()=>{$("#siem-fields").value=rule;runSigma()});box.append(b)});siem.querySelector(".psv-panel-head")?.after(box)}if(yara){let status=$("#yara-live-lint");if(!status){status=document.createElement("pre");status.id="yara-live-lint";status.className="psv-lint-status";yara.querySelector(".psv-panel-head")?.after(status)}const box=document.createElement("div");box.className="psv-template-list";[["PE header","pe"],["File size limit","size"],["String modifiers","mods"]].forEach(([label,value])=>{const b=document.createElement("button");b.type="button";b.className="psv-btn";b.textContent=label;b.addEventListener("click",()=>{if(value==="mods"){const e=$("#yara-strings");if(e)e.value=(e.value+"\n$sample = \"sample\" nocase wide ascii fullword xor").trim()}else{$("#yara-condition").value=value}lintYara()});box.append(b)});yara.querySelector(".psv-panel-head")?.after(box);yara.addEventListener("input",e=>{if(e.target.matches("#yara-name,#yara-strings,#yara-condition"))lintYara()})}document.addEventListener("click",e=>{const b=e.target.closest("button[data-action='run']");if(!b)return;const p=b.closest(".psv-tool-panel");if(p?.id==="panel-siem"){e.preventDefault();e.stopImmediatePropagation();runSigma()}if(p?.id==="panel-yara"){e.preventDefault();e.stopImmediatePropagation();const r=lintYara();write((r.issues.length?"Lint findings:\n- "+r.issues.join("\n- ")+"\n\n":"Lint passed for supported subset.\n\n")+r.rule+"\n\nValidate with the official YARA parser before deployment.")}},true);lintYara()}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",install,{once:true});else install();if(window.document$?.subscribe)window.document$.subscribe(()=>{const a=$("#psv-tools-app");if(a)a.dataset.finalSigmaYara="";install()});
})();

/* Application workbench layout and in-page multi-source threat intelligence. */
(function(){
"use strict";
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>Array.from(r.querySelectorAll(s));
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const txt=v=>v===undefined||v===null||v===""?"Not reported":String(v);
const fetchJson=async(url,headers={})=>{const r=await fetch(url,{headers,mode:"cors",credentials:"omit"});if(!r.ok)throw Error("HTTP "+r.status);return r.json()};
function init(){
 const app=$("#psv-tools-app"),root=$(".psv-console",app),grid=$("#psv-tool-grid",app),search=$(".psv-search-wrap",app),workspace=$("#psv-workspace",app);
 if(!app||!root||!grid||!workspace||app.dataset.psvAppLayout==="1")return;
 app.dataset.psvAppLayout="1";
 $("#psv-theme",app)?.remove();$$("#psv-tools-app .psv-footnote").forEach(e=>e.remove());
 const layout=document.createElement("div");layout.className="psv-app-layout";
 const rail=document.createElement("aside");rail.className="psv-tool-rail";rail.setAttribute("aria-label","Tool selector");
 const main=document.createElement("main");main.className="psv-workspace-main";main.id="tool-workspace";main.tabIndex=-1;
 const empty=document.createElement("div");empty.className="psv-workspace-empty";empty.id="psv-workspace-empty";empty.innerHTML="<strong>Select a tool to begin.</strong><p>Choose a utility from the left. Its workspace opens here.</p>";
 search?.remove();grid.remove();workspace.remove();if(search)rail.append(search);rail.append(grid);main.append(empty,workspace);layout.append(rail,main);
 const hero=$(".psv-hero",root);if(hero)hero.after(layout);else root.append(layout);
 const footer=document.createElement("footer");footer.className="psv-app-footer";footer.innerHTML="<span>PRIVACY SKILL VAULT · CLIENT-SIDE WORKBENCH</span><span>Local-first where possible · Validate outputs before operational use.</span>";layout.after(footer);
 $$(".psv-tool-card",grid).forEach(b=>{b.type="button";b.dataset.toolId=b.dataset.tool||"";b.setAttribute("aria-controls","panel-"+b.dataset.toolId)});
 const open=id=>{const p=$("#panel-"+CSS.escape(id),workspace);if(!p)return;$$(".psv-tool-panel",workspace).forEach(x=>x.hidden=x!==p);empty.hidden=true;$$(".psv-tool-card",grid).forEach(b=>{const active=b.dataset.toolId===id;b.classList.toggle("is-active",active);b.setAttribute("aria-current",active?"page":"false")});main.scrollIntoView({behavior:matchMedia("(prefers-reduced-motion: reduce)").matches?"auto":"smooth",block:"start"})};
 document.addEventListener("click",e=>{
  const card=e.target.closest("#psv-tool-grid button[data-tool-id]");
  if(card){e.preventDefault();e.stopImmediatePropagation();open(card.dataset.toolId);return}
  const back=e.target.closest("#tool-workspace button[data-action='back']");
  if(back){e.preventDefault();e.stopImmediatePropagation();$$(".psv-tool-panel",workspace).forEach(x=>x.hidden=true);empty.hidden=false;$$(".psv-tool-card",grid).forEach(b=>{b.classList.remove("is-active");b.setAttribute("aria-current","false")});main.scrollIntoView({behavior:"smooth",block:"start"})}
 },true);
 $("#psv-search",app)?.addEventListener("input",e=>{const q=e.target.value.toLowerCase();$$(".psv-tool-card",grid).forEach(b=>b.hidden=!b.textContent.toLowerCase().includes(q))});
 const admonitions=$$(".md-typeset .admonition");admonitions.forEach(e=>{if(/Privacy-first by default|Operational use/i.test(e.textContent))e.remove()});
 installIntel($("#panel-intel",workspace));
 const first=$("#panel-ioc",workspace); if(first){first.hidden=false;empty.hidden=true;}
}
function installIntel(panel){
 const input=$("#intel-indicator",panel),links=$("#intel-links",panel);if(!input||!links||panel.dataset.psvUnifiedIntel==="1")return;panel.dataset.psvUnifiedIntel="1";
 const button=$$("button",panel).find(b=>/prepare lookup links/i.test(b.textContent));if(button){button.textContent="Analyze indicator";button.dataset.psvAnalyze="1"}
 const keys=document.createElement("div");keys.className="psv-intel-key-row";keys.innerHTML='<label class="psv-field">Optional VirusTotal API key (memory only)<input id="psv-vt-key" type="password" autocomplete="off" placeholder="Optional; not saved"></label><label class="psv-field">Optional AbuseIPDB API key (memory only)<input id="psv-abuse-key" type="password" autocomplete="off" placeholder="Optional; not saved"></label>';
 links.replaceChildren(keys);
 const report=document.createElement("div");report.id="psv-unified-intel-report";report.className="psv-intel-dashboard";report.setAttribute("aria-live","polite");links.after(report);
 const card=(title,body)=>'<section class="psv-intel-section"><h3>'+esc(title)+'</h3>'+body+'</section>';
 const kv=obj=>'<dl class="psv-intel-kv">'+Object.entries(obj).map(([k,v])=>'<div><dt>'+esc(k)+'</dt><dd>'+esc(txt(v))+'</dd></div>').join("")+'</dl>';
 const table=(heads,rows)=>'<div class="psv-intel-table-wrap"><table class="psv-intel-table"><thead><tr>'+heads.map(x=>'<th>'+esc(x)+'</th>').join("")+'</tr></thead><tbody>'+(rows.length?rows.map(row=>'<tr>'+row.map(x=>'<td>'+esc(txt(x))+'</td>').join("")+'</tr>').join(""):'<tr><td colspan="'+heads.length+'">No records returned.</td></tr>')+'</tbody></table></div>';
 const get=async(label,fn)=>{try{return{label,data:await fn()}}catch(e){return{label,error:e.message}}};
 const run=async()=>{
  const indicator=input.value.trim().replace(/^https?:\/\//i,"").split("/")[0].replace(/\.$/,"");
  const ip4=/^(?:\d{1,3}\.){3}\d{1,3}$/.test(indicator)&&indicator.split(".").every(n=>+n<=255),ip6=/^(?=.*:)[0-9a-f:]+$/i.test(indicator),isIp=ip4||ip6;
  const domain=/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(indicator),hash=/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(indicator);
  if(!isIp&&!domain&&!hash){report.innerHTML='<p class="psv-intel-note">Enter a valid IPv4/IPv6 address, fully qualified domain, or MD5/SHA-1/SHA-256 hash.</p>';return}
  report.innerHTML='<p class="psv-intel-note">Fetching public intelligence sources. Provider errors and missing data will be shown explicitly.</p>';
  const jobs=[];
  if(isIp){jobs.push(get("IP geolocation",()=>fetchJson("https://ipwho.is/"+encodeURIComponent(indicator))));jobs.push(get("RDAP",()=>fetchJson("https://rdap.org/ip/"+encodeURIComponent(indicator))));jobs.push(get("Shodan InternetDB",()=>fetchJson("https://internetdb.shodan.io/"+encodeURIComponent(indicator))))}
  if(domain){jobs.push(get("RDAP",()=>fetchJson("https://rdap.org/domain/"+encodeURIComponent(indicator))));jobs.push(get("Certificate transparency",()=>fetchJson("https://crt.sh/?q=%25."+encodeURIComponent(indicator)+"&output=json")));for(const [type,label] of [[1,"A"],[15,"MX"],[16,"TXT/SPF"],[2,"NS"]])jobs.push(get("DNS "+label,()=>fetchJson("https://cloudflare-dns.com/dns-query?name="+encodeURIComponent(indicator)+"&type="+type,{Accept:"application/dns-json"})))}
  const vtKey=$("#psv-vt-key")?.value.trim(),abuseKey=$("#psv-abuse-key")?.value.trim();
  if(vtKey)jobs.push(get("VirusTotal",()=>fetchJson("https://www.virustotal.com/api/v3/"+(hash?"files/":isIp?"ip_addresses/":"domains/")+encodeURIComponent(indicator),{"x-apikey":vtKey})));
  if(abuseKey&&ip4)jobs.push(get("AbuseIPDB",()=>fetchJson("https://api.abuseipdb.com/api/v2/check?ipAddress="+encodeURIComponent(indicator)+"&maxAgeInDays=90",{Key:abuseKey,Accept:"application/json"})));
  const results=await Promise.all(jobs),find=label=>results.find(r=>r.label===label&&r.data)?.data,geo=find("IP geolocation")||{},rdap=find("RDAP")||{},shodan=find("Shodan InternetDB")||{};
  const vtResult=results.find(r=>r.label==="VirusTotal"&&r.data)?.data,vtStats=vtResult?.data?.attributes?.last_analysis_stats||{},vtBad=Number(vtStats.malicious||0)+Number(vtStats.suspicious||0);
  const abuse=find("AbuseIPDB")?.data,abuseScore=Number(abuse?.abuseConfidenceScore||0),ports=Array.isArray(shodan.ports)?shodan.ports:[],cves=Array.isArray(shodan.vulns)?shodan.vulns:[];
  const score=Math.min(100,Math.round(Math.min(25,ports.length*4)+Math.min(40,cves.length*8)+Math.min(30,vtBad*5)+Math.min(30,abuseScore*.3)));
  const verdict=score>=65?"Malicious":score>=30?"Suspicious":"Clean / low signal",color=score>=65?"#ef4444":score>=30?"#f59e0b":"#22c55e";
  const external='<div class="psv-intel-corner-links"><a target="_blank" rel="noopener noreferrer" href="https://www.virustotal.com/gui/search/'+encodeURIComponent(indicator)+'">↗ VirusTotal</a><a target="_blank" rel="noopener noreferrer" href="https://www.abuseipdb.com/check/'+encodeURIComponent(indicator)+'">↗ AbuseIPDB</a><a target="_blank" rel="noopener noreferrer" href="https://www.shodan.io/search?query='+encodeURIComponent(indicator)+'">↗ Shodan</a></div>';
  const banner='<section class="psv-intel-banner"><div class="psv-risk-gauge" style="--risk:'+score+';--psv-risk-color:'+color+'"><strong>'+score+'</strong></div><div><div class="psv-eyebrow">UNIFIED VERDICT · '+(isIp?"IP ADDRESS":domain?"DOMAIN":"FILE HASH")+'</div><h3 style="margin:0 0 6px;color:var(--psv-text)">'+verdict+'</h3><p class="psv-intel-note">Heuristic score based only on returned port, CVE and reputation signals. Missing data is not evidence of safety.</p></div>'+external+'</section>';
  const entities=Array.isArray(rdap.entities)?rdap.entities:[],emails=entities.flatMap(e=>e.vcardArray?.[1]||[]).filter(v=>/email/i.test(v[0])).map(v=>v[3]).filter(Boolean);
  const network=isIp?{IP:indicator,ASN:geo.connection?.asn,ISP:geo.connection?.isp,Organization:geo.connection?.org,Country:geo.country,Region:geo.region,City:geo.city,CIDR:(rdap.cidr0_cidrs||[]).map(x=>x.v4prefix||x.v6prefix).filter(Boolean).join(", ")||(rdap.startAddress&&rdap.endAddress?rdap.startAddress+" – "+rdap.endAddress:undefined),"Abuse contact":emails.join(", ")||"Not exposed by public RDAP"}:domain?{Domain:indicator,Registrar:entities.map(e=>e.handle).filter(Boolean).join(", "),Status:Array.isArray(rdap.status)?rdap.status.join(", "):undefined,Nameservers:(rdap.nameservers||[]).map(n=>n.ldhName).filter(Boolean).join(", "),Handle:rdap.handle}:{Hash:indicator,Type:indicator.length===32?"MD5":indicator.length===40?"SHA-1":"SHA-256","VirusTotal malicious/suspicious":vtBad};
  const net=card("Network, Geo & ASN Ownership",kv(network));
  const hostnames=(shodan.hostnames||[]).join(", "),cpes=(shodan.cpes||[]).join(", ");
  const attack=card("Attack Surface, Open Ports & CVEs",'<p class="psv-intel-note">Shodan InternetDB supplies IP-focused results. Empty results do not mean the host is safe.</p>'+table(["Port","Protocol / signal","Hostnames","CVE IDs"],ports.map(p=>[p,"Reported open",hostnames,cves.join(", ")||"None reported"]))+'<p class="psv-intel-note">CPEs: '+esc(cpes||"Not reported")+'</p>');
  const dnsRows=results.filter(r=>r.label.startsWith("DNS ")).flatMap(r=>(r.data?.Answer||[]).map(a=>[r.label,a.name,a.TTL,a.data]));const certRows=results.find(r=>r.label==="Certificate transparency"&&Array.isArray(r.data))?.data.slice(0,8).map(x=>["Certificate transparency",x.common_name||x.name_value,x.not_after||"Expiry not reported",(x.issuer_name||"Issuer not reported")+" · "+(x.not_before||"Start date not reported")])||[];dnsRows.push(...certRows);
  const rep=[["VirusTotal",vtResult?"Response received":vtKey?"No data / provider error":"No key supplied",JSON.stringify(vtStats)],["AbuseIPDB",abuse?"Confidence "+abuseScore+"%":abuseKey?"No data / not an IPv4 query":"No key supplied",abuse?.totalReports??"—"],["Shodan",results.some(r=>r.label==="Shodan InternetDB"&&r.data)?"Response received":"Unavailable / not applicable",cves.join(", ")||"No CVEs reported"]];
  const dns=card("DNS, SSL & Reputation Matrix",table(["Source / record","Name / signal","TTL / score","Value / details"],dnsRows.concat(rep))+'<p class="psv-intel-note">Certificate transparency entries are historical/public CT observations, not a live TLS handshake or certificate-validity check.</p>');
  const errors=results.filter(r=>r.error).map(r=>[r.label,r.error,"—","CORS, rate limit, invalid/unavailable indicator, or provider error"]);
  report.innerHTML=banner+net+attack+dns+(errors.length?card("Provider status & limitations",table(["Provider","Error","Details","Possible cause"],errors)):"")+'<p class="psv-intel-note">Public-source enrichment is best-effort. A clean/low-signal result is not a guarantee of benign activity. API keys are held only in the page memory and sent directly to the provider.</p>';
 };
 button?.addEventListener("click",e=>{e.preventDefault();e.stopImmediatePropagation();run().catch(err=>report.textContent="Analysis failed: "+err.message)},true);
 input.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();run().catch(err=>report.textContent=err.message)}});
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init,{once:true});else init();
if(window.document$?.subscribe)window.document$.subscribe(()=>init());
})();

/* PSV UI and reliable sample/render lifecycle fixes. */
(function(){
"use strict";
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>Array.from(r.querySelectorAll(s));
const samples={
ioc:{"ioc-input":"Failed logon source=203.0.113.42 domain=example.org URL=https://example.org/login SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef defanged=hxxps://malicious[.]example/path MD5=d41d8cd98f00b204e9800998ecf8427e"},
intel:{"intel-indicator":"8.8.8.8"},
email:{"email-input":"From: security@example.org\nReply-To: attacker@example.net\nReturn-Path: <bounce@example.org>\nDate: Sat, 17 Oct 2026 12:00:00 +0300\nSubject: Suspicious sign-in alert\nReceived: from relay.example.net (relay.example.net [203.0.113.42]) by mx.example.org; Sat, 17 Oct 2026 09:00:01 +0000\nReceived: from workstation.example.org ([198.51.100.25]) by relay.example.net; Sat, 17 Oct 2026 09:00:00 +0000\nAuthentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail"},
siem:{"siem-kind":"sigma","siem-fields":"title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains: -enc\n  condition: selection"},
events:{"event-search":"4625"},regex:{"regex-pattern":"failed.*logon","regex-flags":"gi","regex-text":"Failed logon user=alice src=203.0.113.42\nSuccessful logon user=bob"},
yara:{"yara-name":"Suspicious_PE_Sample","yara-strings":"MZ\nThis program cannot be run in DOS mode","yara-condition":"any"},
deob:{"deob-input":"SW52b2tlLUV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHBzOi8vZXhhbXBsZS5vcmcvYScp","deob-mode":"base64"},
json:{"json-input":'{"event":{"id":4625,"provider":"Microsoft-Windows-Security-Auditing"},"source":{"ip":"203.0.113.42"},"user":{"name":"alice"}}'},
time:{"time-input":"2026-10-17T09:30:00Z","time-zone":"Asia/Riyadh"},
severity:{"sev-impact":"2","sev-scope":"1","sev-confidence":"2","sev-exposure":"2"},
report:{"rep-id":"INC-DEMO-001","rep-title":"Suspicious authentication activity","rep-date":"2026-10-17T12:30:00+03:00","rep-sev":"High","rep-summary":"Repeated failed logons were observed from a test source. Impact is under investigation.","rep-evidence":"Event ID 4625; source 203.0.113.42; timestamp normalized to UTC.","rep-actions":"Validate account ownership, preserve relevant logs, block only under approved response procedures."},
cvss:{"cv-av":"N","cv-ac":"L","cv-pr":"N","cv-ui":"N","cv-s":"U","cv-c":"H","cv-i":"H","cv-a":"H"}
};
function renderSample(panel){
 const id=panel.id.replace("panel-","");
 Object.entries(samples[id]||{}).forEach(([key,value])=>{const el=$("#"+key,panel);if(el){el.value=value;el.dispatchEvent(new Event("input",{bubbles:true}));}});
 if(id==="events"){const s=$("#event-search",panel);if(s)s.dispatchEvent(new Event("input",{bubbles:true}));return;}
 if(id==="intel"){const b=Array.from(panel.querySelectorAll("button")).find(x=>/analyze indicator|prepare lookup links/i.test(x.textContent));if(b)b.click();return;}
 const run=$('button[data-action="run"]',panel);if(run)run.click();
}
document.addEventListener("click",e=>{const sample=e.target.closest("button[data-psv-sample]");if(sample){const panel=sample.closest(".psv-tool-panel");if(panel){e.preventDefault();e.stopImmediatePropagation();renderSample(panel);}}},true);
document.addEventListener("input",e=>{
 const panel=e.target.closest(".psv-tool-panel");if(!panel||!e.target.matches("input,textarea,select")||e.target.matches("#event-search"))return;
 const id=panel.id.replace("panel-","");if(id==="intel")return;
 const run=$('button[data-action="run"]',panel);
 if(run&&["ioc","email","siem","regex","yara","deob","json","time","severity","report","cvss"].includes(id))run.click();
},true);
function init(){
 const app=$("#psv-tools-app");if(!app||app.dataset.psvFinalFix==="1")return;app.dataset.psvFinalFix="1";
 $$(".psv-console-top,.psv-hero-stats,.psv-footnote,.psv-app-footer",app).forEach(el=>el.remove());
 const eyebrow=$(".psv-hero .psv-eyebrow",app);if(eyebrow)eyebrow.textContent="SECURITY OPERATIONS WORKBENCH";
 const h=$(".psv-hero h1",app);if(h)h.innerHTML='Analyze. Detect.<br><span>Investigate.</span>';
 const p=$(".psv-hero p",app);if(p)p.textContent="The Tools section brings together practical SOC utilities, indicator enrichment, log decoders, and detection engineering workbenches used to turn raw telemetry into actionable security investigations.";
 const first=$("#panel-ioc",app);if(first){first.hidden=false;const input=$("#ioc-input",first);if(input)input.value=samples.ioc["ioc-input"];const run=$('button[data-action="run"]',first);if(run)run.click();}
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init,{once:true});else init();
if(window.document$?.subscribe)window.document$.subscribe(init);
})();