const ACTION = "orf:action";
const $emit = (name, detail) => window.dispatchEvent(new CustomEvent(name, { detail }));
const toast = (message, type = "info") => $emit("orf:toast", { message: String(message), type });
const progress = (phase, message, completed = 0, total = 0) => $emit("orf:progress", { phase, message, completed, total, percent: total ? Math.max(0, Math.min(100, Math.round(completed * 100 / total))) : 0 });
const pause = () => new Promise(resolve => setTimeout(resolve, 0));
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });
const LIMITS = { fileBytes: 35 * 1024 * 1024, scanBytes: 3 * 1024 * 1024, totalBytes: 120 * 1024 * 1024, entries: 20000, packBytes: 5 * 1024 * 1024, customRules: 10000 };
const state = {
  status: "empty", projectName: "Untitled project", files: new Map(), findings: [], selectedFindingId: null,
  repairPreview: null, repairHistory: [], undoStack: [], filters: { query: "", severity: "all", category: "all", language: "all" },
  scan: { scannedFiles: 0, totalFiles: 0, patternsChecked: 0, progress: 0 }, working: false, cancel: false,
  worker: null, workerUrl: null, customRules: [], customPackPersistence: "checking", lastError: null
};
const LANG_EXT = {
  js:"javascript",mjs:"javascript",cjs:"javascript",jsx:"jsx",ts:"typescript",tsx:"tsx",html:"html",htm:"html",css:"css",scss:"css",less:"css",
  json:"json",jsonc:"json",yaml:"yaml",yml:"yaml",py:"python",pyi:"python",java:"java",kt:"kotlin",go:"go",rs:"rust",php:"php",rb:"ruby",
  sh:"shell",bash:"shell",zsh:"shell",env:"env",xml:"xml",svg:"html",md:"markdown",mdx:"markdown",sql:"sql",vue:"vue",svelte:"svelte",astro:"astro",
  tf:"terraform",hcl:"terraform",toml:"toml",ini:"ini",properties:"properties",dockerfile:"dockerfile"
};
const TEXT_EXT = new Set(Object.keys(LANG_EXT).concat(["txt","conf","config","gitignore","editorconfig","makefile","lock","graphql","gql","gradle"]));
function extension(path) { const name = String(path).split("/").pop().toLowerCase(); if (name === "dockerfile") return "dockerfile"; if (name === "makefile") return "makefile"; const i = name.lastIndexOf("."); return i < 0 ? name : name.slice(i + 1); }
function languageFromPath(path) { return LANG_EXT[extension(path)] || "text"; }
function normalizePath(path) {
  const raw = String(path || "").replace(/\\/g, "/");
  if (!raw || raw.startsWith("/") || /^[a-z]:/i.test(raw)) throw new Error("Absolute or empty file paths are not accepted.");
  const parts = [];
  for (const part of raw.split("/")) { if (!part || part === ".") continue; if (part === "..") { if (!parts.length) throw new Error("Path traversal was rejected."); parts.pop(); } else parts.push(part); }
  if (!parts.length) throw new Error("The import contains an empty file path.");
  return parts.join("/");
}
const RULES = [
{id:"JS-EVAL-01",title:"Dynamic code execution with eval",severity:"high",category:"code-execution",language:["javascript","typescript","jsx","tsx"],needle:"eval",pattern:"\\beval\\s*\\(",description:"eval executes a string as program code. Avoid it for untrusted values; use a parser or explicit dispatch instead.",confidence:"high"},
{id:"JS-FUNC-01",title:"Dynamic Function constructor",severity:"high",category:"code-execution",language:["javascript","typescript","jsx","tsx"],needle:"new function",pattern:"\\bnew\\s+Function\\s*\\(",description:"The Function constructor compiles strings into executable code and can create injection risk.",confidence:"high"},
{id:"JS-INNERHTML-01",title:"Potentially unsafe innerHTML assignment",severity:"high",category:"xss",language:["javascript","typescript","jsx","tsx"],needle:"innerhtml",pattern:"\\.innerHTML\\s*=",description:"Assigning untrusted data to innerHTML can create cross-site scripting. Prefer textContent or a maintained sanitizer.",confidence:"medium"},
{id:"JS-DOCWRITE-01",title:"document.write usage",severity:"medium",category:"dom-safety",language:["javascript","typescript","jsx","tsx"],needle:"document.write",pattern:"\\bdocument\\.write\\s*\\(",description:"document.write can inject markup into the active document and has fragile lifecycle behavior.",confidence:"medium"},
{id:"JS-DANGEROUS-HTML-01",title:"React dangerous HTML rendering",severity:"high",category:"xss",language:["javascript","typescript","jsx","tsx"],needle:"dangerouslysetinnerhtml",pattern:"dangerouslySetInnerHTML\\s*=",description:"dangerouslySetInnerHTML bypasses React's normal text escaping. Ensure values are rigorously sanitized.",confidence:"medium"},
{id:"JS-WEAK-RANDOM-01",title:"Math.random used for a security-sensitive value",severity:"medium",category:"cryptography",language:["javascript","typescript","jsx","tsx"],needle:"math.random",pattern:"Math\\.random\\s*\\(",description:"Math.random is not cryptographically secure. Use crypto.getRandomValues for secrets, tokens, or security-sensitive identifiers.",confidence:"medium"},
{id:"JS-LOCALSTORAGE-01",title:"Possible secret stored in browser storage",severity:"medium",category:"credential-storage",language:["javascript","typescript","jsx","tsx"],needle:"localstorage",pattern:"localStorage\\.(?:setItem|getItem)\\s*\\(",description:"Browser storage is readable by scripts running on the same origin. Avoid storing long-lived secrets or sensitive credentials.",confidence:"low"},
{id:"JS-POSTMESSAGE-01",title:"Wildcard postMessage target",severity:"medium",category:"messaging",language:["javascript","typescript","jsx","tsx"],needle:"postmessage",pattern:"\\.postMessage\\s*\\([^;]{0,180},\\s*['\"]\\*['\"]",description:"A wildcard targetOrigin sends a message without restricting the receiving origin. Use the exact expected origin.",confidence:"medium"},
{id:"HTTP-URL-01",title:"Unencrypted HTTP URL",severity:"low",category:"transport-security",language:["javascript","typescript","jsx","tsx","html","text","json","yaml","css"],needle:"http://",pattern:"http://[^\\s\"'<>]+",description:"An HTTP URL may expose traffic to interception. Confirm the destination supports HTTPS; local development URLs may be harmless.",confidence:"low"},
{id:"SECRET-STRIPE-01",title:"Possible live API credential in source",severity:"critical",category:"secrets",language:["javascript","typescript","jsx","tsx","python","shell","yaml","json","text","env"],needle:"sk_live_",pattern:"\\bsk_live_[A-Za-z0-9]{12,}\\b",description:"This resembles a live secret key. Remove it from source history and rotate it with the issuing provider.",confidence:"high"},
{id:"SECRET-AWS-01",title:"Possible AWS access key",severity:"critical",category:"secrets",language:["javascript","typescript","jsx","tsx","python","shell","yaml","json","text","env"],needle:"akia",pattern:"\\bAKIA[0-9A-Z]{16}\\b",description:"This resembles an AWS access key ID. Check nearby context, revoke exposed credentials, and rotate affected keys.",confidence:"medium"},
{id:"SECRET-PRIVATE-KEY-01",title:"Private key material in file",severity:"critical",category:"secrets",language:["javascript","typescript","jsx","tsx","python","shell","yaml","json","text","env"],needle:"-----begin",pattern:"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",description:"Private key material appears in a project file. Remove it from the repository and revoke or rotate the key as appropriate.",confidence:"high"},
{id:"SECRET-PASSWORD-01",title:"Hard-coded password-like assignment",severity:"high",category:"secrets",language:["javascript","typescript","jsx","tsx","python","shell","yaml","json","text","env"],needle:"password",pattern:"\\b(?:password|passwd|pwd)\\s*[:=]\\s*['\"][^'\"]{6,}['\"]",description:"A password-like literal is assigned directly in source. This can flag examples and test fixtures; review the context.",confidence:"medium"},
{id:"NODE-EXEC-01",title:"Potential shell command execution",severity:"high",category:"command-injection",language:["javascript","typescript","jsx","tsx"],needle:"exec",pattern:"\\bexec\\s*\\(",description:"Shell execution is dangerous when arguments can contain user-controlled text. Prefer argument-array APIs and validate inputs.",confidence:"low"},
{id:"NODE-CHILD-PROCESS-01",title:"Child process invocation",severity:"medium",category:"command-injection",language:["javascript","typescript","jsx","tsx"],needle:"child_process",pattern:"child_process",description:"Review subprocess invocation for shell interpolation, untrusted arguments, and unnecessary privileges.",confidence:"low"},
{id:"PY-EVAL-01",title:"Python eval usage",severity:"high",category:"code-execution",language:["python"],needle:"eval",pattern:"\\beval\\s*\\(",description:"Python eval evaluates text as Python code. Avoid untrusted input; consider a constrained parser.",confidence:"high"},
{id:"PY-EXEC-01",title:"Python exec usage",severity:"high",category:"code-execution",language:["python"],needle:"exec(",pattern:"\\bexec\\s*\\(",description:"Python exec executes dynamically constructed code. Check whether it can be replaced with explicit logic.",confidence:"medium"},
{id:"PY-PICKLE-01",title:"Deserialization with pickle",severity:"high",category:"deserialization",language:["python"],needle:"pickle.loads",pattern:"\\bpickle\\.(?:load|loads)\\s*\\(",description:"Unpickling untrusted data can execute code. Never deserialize attacker-controlled pickle data.",confidence:"high"},
{id:"PY-SHELL-TRUE-01",title:"Subprocess shell=True",severity:"high",category:"command-injection",language:["python"],needle:"shell",pattern:"\\bshell\\s*=\\s*True",description:"Shell interpretation can allow command injection when arguments are influenced by external input.",confidence:"medium"},
{id:"PY-YAML-LOAD-01",title:"Potentially unsafe YAML loading",severity:"medium",category:"deserialization",language:["python"],needle:"yaml.load",pattern:"\\byaml\\.load\\s*\\(",description:"Some YAML loaders can construct arbitrary objects. For untrusted input, use a safe loader.",confidence:"medium"},
{id:"SQL-CONCAT-01",title:"Potential SQL string construction",severity:"high",category:"sql-injection",language:["javascript","typescript","python","php","java","go","ruby"],needle:"select|update|delete|insert",pattern:"(?:SELECT|UPDATE|DELETE|INSERT)[^;]{0,160}(?:\\+\\s*[A-Za-z_$]|\\$\\{[^}]+\\}|%s)",description:"Query strings appear to incorporate variables or formatting. Prefer parameterized queries and validate query structure.",confidence:"low"},
{id:"HTML-LINK-NOOPENER",title:"External link missing rel=noopener",severity:"low",category:"html-safety",language:["html"],needle:"target",pattern:"<a\\b[^>]*\\btarget\\s*=\\s*['\"]_blank['\"][^>]*>",description:"A link opening a new browsing context should use rel=noopener. The supported repair adds noopener noreferrer.",confidence:"high",repair:"noopener"},
{id:"HTML-IMAGE-ALT-01",title:"Image may be missing alternative text",severity:"low",category:"accessibility",language:["html"],needle:"<img",pattern:"<img\\b(?![^>]*\\balt\\s*=)[^>]*>",description:"Images should have meaningful alt text or an empty alt for decorative images. The correct text depends on context.",confidence:"medium"},
{id:"HTML-EXT-SCRIPT-01",title:"External script without integrity metadata",severity:"low",category:"supply-chain",language:["html"],needle:"<script",pattern:"<script\\b(?=[^>]*\\bsrc\\s*=\\s*['\"]https?://)[^>]*>",description:"Consider Subresource Integrity for third-party scripts when a stable integrity hash is provided by the supplier.",confidence:"low"},
{id:"HTML-IFRAME-TITLE-01",title:"Iframe may be missing a title",severity:"low",category:"accessibility",language:["html"],needle:"<iframe",pattern:"<iframe\\b(?![^>]*\\btitle\\s*=)[^>]*>",description:"Give each iframe a title describing its content to assistive technology.",confidence:"medium"},
{id:"HTML-INLINE-EVENT-01",title:"Inline event handler",severity:"medium",category:"content-security-policy",language:["html"],needle:"on",pattern:"\\bon(?:click|load|error|mouseover)\\s*=\\s*['\"]",description:"Inline event handlers complicate a strict Content Security Policy and are best moved into script code.",confidence:"low"},
{id:"CSS-EXPRESSION-01",title:"Legacy CSS expression()",severity:"medium",category:"legacy-code",language:["css"],needle:"expression(",pattern:"\\bexpression\\s*\\(",description:"The legacy CSS expression construct is obsolete and may indicate outdated compatibility code.",confidence:"high"},
{id:"CORS-WILDCARD-01",title:"Wildcard CORS origin",severity:"medium",category:"cors",language:["javascript","typescript","python","yaml","json","text"],needle:"access-control-allow-origin",pattern:"Access-Control-Allow-Origin\\s*[:=]\\s*['\"]?\\*",description:"A wildcard CORS origin may be intentional for public resources. Do not combine credentialed requests with a wildcard origin.",confidence:"medium"},
{id:"TLS-VERIFY-OFF-01",title:"TLS certificate verification disabled",severity:"high",category:"transport-security",language:["javascript","typescript","python","go","text"],needle:"rejectunauthorized",pattern:"rejectUnauthorized\\s*:\\s*false",description:"Disabling certificate verification weakens TLS. Restrict exceptions to controlled test environments.",confidence:"high"},
{id:"GO-TLS-INSECURE-01",title:"Go TLS verification disabled",severity:"high",category:"transport-security",language:["go"],needle:"insecureskipverify",pattern:"InsecureSkipVerify\\s*:\\s*true",description:"TLS verification is disabled in this configuration. Use a correctly configured certificate chain.",confidence:"high"},
{id:"JWT-HARDCODED-01",title:"JWT secret-like hard-coded value",severity:"high",category:"secrets",language:["javascript","typescript","python","java","text"],needle:"jwt",pattern:"(?:jwt|token|signing)[A-Za-z_$]{0,24}(?:secret|key)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",description:"A hard-coded signing secret may be exposed. Use protected runtime configuration and rotate any real leaked secret.",confidence:"low"},
{id:"NEXT-PUBLIC-SECRET-01",title:"Secret-like variable exposed to public frontend env",severity:"high",category:"secrets",language:["javascript","typescript","text","env"],needle:"next_public_",pattern:"NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY)",description:"NEXT_PUBLIC_ variables are normally exposed in browser bundles. Do not put private credentials in them.",confidence:"medium"},
{id:"PROTO-ASSIGN-01",title:"Possible prototype mutation",severity:"medium",category:"object-safety",language:["javascript","typescript"],needle:"__proto__",pattern:"__proto__\\s*=",description:"Mutating __proto__ can create confusing object behavior and may contribute to prototype-pollution issues.",confidence:"low"},
{id:"DOCKER-LATEST-01",title:"Container image uses latest tag",severity:"low",category:"supply-chain",language:["dockerfile","text"],needle:":latest",pattern:"\\bFROM\\s+[^\\s:]+(?::latest)?(?:\\s+AS\\s+\\w+)?",description:"Pinning a version or digest improves build repeatability and makes dependency changes auditable.",confidence:"medium"},
{id:"GHA-UNPINNED-01",title:"GitHub Action references moving branch",severity:"medium",category:"supply-chain",language:["yaml","text"],needle:"uses:",pattern:"\\buses:\\s*[^\\s@]+@(?:main|master)\\b",description:"Pin GitHub Actions to a full commit SHA where possible to reduce supply-chain drift.",confidence:"medium"},
{id:"PERMISSION-777-01",title:"World-writable permission mode",severity:"high",category:"filesystem",language:["shell","text","yaml"],needle:"chmod 777",pattern:"chmod\\s+(?:-R\\s+)?777\\b",description:"World-writable permissions allow all local users to modify the target. Apply least privilege instead.",confidence:"high"},
{id:"HTTP-WS-01",title:"Unencrypted WebSocket URL",severity:"medium",category:"transport-security",language:["javascript","typescript","html","text"],needle:"ws://",pattern:"ws://[^\\s\"'<>]+",description:"Production WebSocket connections should generally use wss:// to protect traffic in transit.",confidence:"medium"},
{id:"JS-TIMEOUT-STRING-01",title:"String passed to setTimeout",severity:"medium",category:"code-execution",language:["javascript","typescript"],needle:"settimeout",pattern:"setTimeout\\s*\\(\\s*['\"]",description:"String arguments to setTimeout are treated as code in some environments. Pass a function instead.",confidence:"medium"},
{id:"HTML-FORM-NO-HTTPS-01",title:"Form submits to an HTTP endpoint",severity:"high",category:"transport-security",language:["html"],needle:"action=",pattern:"<form\\b[^>]*\\baction\\s*=\\s*['\"]http://",description:"Form data submitted over HTTP can be intercepted. Use HTTPS for production submissions.",confidence:"medium"},
{id:"PY-TEMPFILE-01",title:"Potentially predictable temporary file",severity:"low",category:"filesystem",language:["python"],needle:"tmpnam",pattern:"\\btempfile\\.mktemp\\s*\\(",description:"mktemp returns a path without safely creating the file, allowing a race. Prefer safer temporary-file APIs.",confidence:"high"},
{id:"RUBY-EVAL-01",title:"Ruby eval usage",severity:"high",category:"code-execution",language:["ruby"],needle:"eval(",pattern:"\\beval\\s*\\(",description:"Dynamic evaluation executes constructed code. Avoid untrusted input and prefer explicit parsing.",confidence:"medium"}
];
function allowedLanguage(rule, language) { return (rule.language || ["text"]).includes(language) || (rule.language || []).includes("text"); }
function safeRulePack(rawRules) {
  if (!Array.isArray(rawRules)) throw new Error("A pattern pack must contain a rules array.");
  if (rawRules.length > LIMITS.customRules) throw new Error("Pattern pack exceeds the 10,000-rule limit.");
  const seen = new Set(state.customRules.map(r => r.id));
  let totalNeedleChars = state.customRules.reduce((sum, rule) => sum + String(rule.needle || "").length, 0);
  const out = [];
  const validSeverity = new Set(["critical","high","medium","low","info"]);
  for (const raw of rawRules) {
    if (!raw || typeof raw !== "object") continue;
    const id = String(raw.id || "").trim(), match = String(raw.match || "");
    if (!/^[A-Za-z0-9._:-]{3,100}$/.test(id) || seen.has(id) || !match || match.length > 1000) continue;
    if (totalNeedleChars + match.length > 100000) throw new Error("Pattern pack exceeds the 100,000-character aggregate literal-trigger limit.");
    totalNeedleChars += match.length;
    const severity = String(raw.severity || "medium").toLowerCase();
    if (!validSeverity.has(severity)) continue;
    let languages = Array.isArray(raw.languages) ? raw.languages : Array.isArray(raw.language) ? raw.language : ["text"];
    languages = languages.map(String).filter(v => /^[a-z0-9_-]{1,30}$/i.test(v)).slice(0, 30);
    out.push({ id, title: String(raw.title || id).slice(0,180), severity, category: String(raw.category || "custom").slice(0,80), language: languages.length ? languages : ["text"], needle: match.toLowerCase(), match, description: String(raw.description || raw.desc || "Custom literal match; inspect context before acting.").slice(0,1000), confidence: "medium", repair: null });
    seen.add(id);
  }
  return out;
}
function lineColumn(text, offset) {
  let line = 1, last = -1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) { line++; last = i; }
  return { line, column: offset - last };
}
function excerpt(text, start, end) {
  const a = text.lastIndexOf("\n", Math.max(0,start-1))+1; let b=text.indexOf("\n",end); if(b<0)b=text.length;
  let result=text.slice(a,b).trim(); if(result.length>260)result=result.slice(0,130)+" … "+result.slice(-100); return result;
}
function makeFinding(rule, path, language, text, match, start, end) {
  const lc=lineColumn(text,start); let snippet=excerpt(text,start,end);
  if(rule.category==="secrets") snippet=snippet.replace(/[A-Za-z0-9_\-/.+=]{12,}/g,"[redacted candidate]");
  return { id:rule.id+":"+path+":"+start, ruleId:rule.id, title:rule.title, severity:rule.severity, category:rule.category, path, line:lc.line, column:lc.column, description:rule.description||"Review this deterministic heuristic in context.", confidence:rule.confidence||"medium", status:"open", fixAvailable:rule.repair==="noopener", repairSafety:rule.repair==="noopener"?"safe":"review", language, start, end, matchedText:rule.category==="secrets"?"[redacted candidate]":String(match).slice(0,1000), snippet };
}
let mainNeedleIndex = null;
let mainNeedleIndexCount = -1;
function buildNeedleIndex(rules) {
  const nodes = [{ next: Object.create(null), fail: 0, out: [] }];
  for (const rule of rules) {
    const needles = String(rule.needle || "").toLowerCase().split("|").filter(Boolean);
    for (const needle of needles) {
      let node = 0;
      for (const ch of needle) {
        let next = nodes[node].next[ch];
        if (next === undefined) { next = nodes.length; nodes[node].next[ch] = next; nodes.push({ next: Object.create(null), fail: 0, out: [] }); }
        node = next;
      }
      if (!nodes[node].out.includes(rule)) nodes[node].out.push(rule);
    }
  }
  const queue = [];
  for (const ch of Object.keys(nodes[0].next)) { const child = nodes[0].next[ch]; nodes[child].fail = 0; queue.push(child); }
  for (let cursor = 0; cursor < queue.length; cursor++) {
    const parent = queue[cursor];
    for (const ch of Object.keys(nodes[parent].next)) {
      const child = nodes[parent].next[ch];
      let fallback = nodes[parent].fail;
      while (fallback && nodes[fallback].next[ch] === undefined) fallback = nodes[fallback].fail;
      const target = nodes[fallback].next[ch];
      if (target !== undefined && target !== child) nodes[child].fail = target;
      nodes[child].out.push(...nodes[nodes[child].fail].out);
      queue.push(child);
    }
  }
  return nodes;
}
function selectIndexedRules(text, nodes) {
  const found = new Set();
  if (!nodes) return [];
  let node = 0;
  const low = String(text).toLowerCase();
  for (const ch of low) {
    while (node && nodes[node].next[ch] === undefined) node = nodes[node].fail;
    const next = nodes[node].next[ch];
    if (next !== undefined) node = next;
    for (const rule of nodes[node].out) found.add(rule);
  }
  return [...found];
}
function indexedRules(text, customRules) {
  const all = RULES.concat(customRules || []);
  if (!mainNeedleIndex || mainNeedleIndexCount !== all.length) {
    const totalNeedleChars = all.reduce((sum, rule) => sum + String(rule.needle || "").split("|").reduce((n, part) => n + part.length, 0), 0);
    if (totalNeedleChars > 100000) throw new Error("Pattern index exceeds the 100,000-character literal-trigger budget.");
    mainNeedleIndex = buildNeedleIndex(all);
    mainNeedleIndexCount = all.length;
  }
  return selectIndexedRules(text, mainNeedleIndex);
}

function scanSync(file, customRules) {
  const text=file.currentText||"", low=text.toLowerCase(), language=file.language, findings=[]; let checked=0;
  if(language==="json"){try{JSON.parse(text)}catch(error){const m=String(error.message||"Invalid JSON"),pos=Number((m.match(/position\s+(\d+)/i)||[])[1]||0);findings.push(makeFinding({id:"JSON-INVALID-01",title:"Invalid JSON syntax",severity:"high",category:"syntax",description:"JSON parser: "+m.slice(0,180),confidence:"high"} ,file.path,language,text,text.slice(pos,pos+1),Math.min(pos,text.length),Math.min(pos+1,text.length)))}}
  for(const rule of indexedRules(text, customRules||[])){
    if(!allowedLanguage(rule,language))continue;
    if(rule.always)continue; checked++;
    try{
      if(rule.match){let at=0,n=0;const needle=String(rule.match).toLowerCase();while((at=low.indexOf(needle,at))!==-1&&n<8){findings.push(makeFinding(rule,file.path,language,text,text.slice(at,at+needle.length),at,at+needle.length));n++;at+=Math.max(1,needle.length)}continue}
      const re=new RegExp(rule.pattern,rule.flags||"gi");let n=0;
      for(let m;(m=re.exec(text))&&n<8;){if(!(rule.id==="HTML-LINK-NOOPENER"&&/\brel\s*=\s*(['"])[^'"]*\bnoopener\b/i.test(m[0]))){findings.push(makeFinding(rule,file.path,language,text,m[0],m.index,m.index+m[0].length));n++}if(!m[0].length)re.lastIndex++}
    }catch{}
  }
  return { findings, checked };
}
function crossFileFindings(files) {
  const out=[], paths=new Set(files.map(f=>f.path.toLowerCase()));
  for(const file of files){if(file.language!=="html"||file.currentText===null)continue;const text=file.currentText,re=/\b(?:src|href)\s*=\s*(['"])([^'"]+)\1/gi;
    for(let m;(m=re.exec(text))&&out.length<300;){const ref=m[2].trim();if(!ref||/^(?:https?:|\/\/|data:|blob:|mailto:|tel:|javascript:|#)/i.test(ref))continue;let value;try{value=decodeURIComponent(ref.split(/[?#]/)[0])}catch{value=ref.split(/[?#]/)[0]}
      const parts=file.path.split("/");parts.pop();if(value.startsWith("/"))parts.length=0;for(const seg of value.replace(/^\//,"").split("/")){if(!seg||seg===".")continue;if(seg==="..")parts.pop();else parts.push(seg)}
      const target=parts.join("/").toLowerCase();if(target&&!paths.has(target)){const lc=lineColumn(text,m.index);out.push({id:"PROJECT-REF-0001:"+file.path+":"+m.index,ruleId:"PROJECT-REF-0001",title:"Local asset reference not found",severity:"medium",category:"project-integrity",path:file.path,line:lc.line,column:lc.column,description:'The local reference "'+ref+'" did not match any imported project file. Check spelling, case, and the relative path.',confidence:"medium",status:"open",fixAvailable:false,repairSafety:"review",language:file.language,start:m.index,end:m.index+m[0].length,matchedText:m[0],snippet:excerpt(text,m.index,m.index+m[0].length)})}
    }
  }
  return out;
}
function scannerWorkerCore() {
  let cachedIndex = null, cachedVersion = -1, cachedRules = [];
  function buildIndex(rules) {
    const nodes = [{ next: Object.create(null), fail: 0, out: [] }];
    for (const rule of rules) for (const needle of String(rule.needle || "").toLowerCase().split("|").filter(Boolean)) {
      let node = 0;
      for (const ch of needle) {
        let next = nodes[node].next[ch];
        if (next === undefined) { next = nodes.length; nodes[node].next[ch] = next; nodes.push({ next: Object.create(null), fail: 0, out: [] }); }
        node = next;
      }
      if (!nodes[node].out.includes(rule)) nodes[node].out.push(rule);
    }
    const queue = [];
    for (const ch of Object.keys(nodes[0].next)) { const child=nodes[0].next[ch]; nodes[child].fail=0; queue.push(child); }
    for (let cursor=0; cursor<queue.length; cursor++) { const parent=queue[cursor]; for (const ch of Object.keys(nodes[parent].next)) { const child=nodes[parent].next[ch]; let fallback=nodes[parent].fail; while(fallback&&nodes[fallback].next[ch]===undefined)fallback=nodes[fallback].fail; const target=nodes[fallback].next[ch]; if(target!==undefined&&target!==child)nodes[child].fail=target; nodes[child].out.push(...nodes[nodes[child].fail].out); queue.push(child); } }
    return nodes;
  }
  function select(text) {
    const found=new Set();if(!cachedIndex)return [];let node=0;
    for(const ch of String(text).toLowerCase()){while(node&&cachedIndex[node].next[ch]===undefined)node=cachedIndex[node].fail;const next=cachedIndex[node].next[ch];if(next!==undefined)node=next;for(const rule of cachedIndex[node].out)found.add(rule);}
    return [...found];
  }
  self.onmessage = function(event) {
    const data=event.data||{}; if(data.type!=="scan")return;
    try {
      const text=String(data.text||""),low=text.toLowerCase(),language=data.language,out=[];let checked=0;
      if(data.version!==cachedVersion&&Array.isArray(data.rules)&&Array.isArray(data.customRules)){cachedRules=data.rules.concat(data.customRules);const chars=cachedRules.reduce((sum,r)=>sum+String(r.needle||"").split("|").reduce((n,p)=>n+p.length,0),0);if(chars>100000)throw new Error("Pattern index exceeds the aggregate literal-trigger limit.");cachedIndex=buildIndex(cachedRules);cachedVersion=data.version;}
      const candidates=select(text);
      const starts=[0];for(let i=0;i<text.length;i++)if(text.charCodeAt(i)===10)starts.push(i+1);
      const loc=at=>{let lo=0,hi=starts.length-1;while(lo<=hi){const mid=(lo+hi)>>1;if(starts[mid]<=at)lo=mid+1;else hi=mid-1}const line=Math.max(0,hi);return {line:line+1,column:at-starts[line]+1}};
      const snip=(start,end)=>{const a=text.lastIndexOf("\n",Math.max(0,start-1))+1;let b=text.indexOf("\n",end);if(b<0)b=text.length;let s=text.slice(a,b).trim();if(s.length>260)s=s.slice(0,130)+" … "+s.slice(-100);return s};
      const add=(r,match,start,end)=>{const lc=loc(start);let snippet=snip(start,end);if(r.category==="secrets")snippet=snippet.replace(/[A-Za-z0-9_\-/.+=]{12,}/g,"[redacted candidate]");out.push({id:r.id+":"+data.path+":"+start,ruleId:r.id,title:r.title,severity:r.severity,category:r.category,path:data.path,line:lc.line,column:lc.column,description:r.description||"Review this deterministic heuristic in context.",confidence:r.confidence||"medium",status:"open",fixAvailable:r.repair==="noopener",repairSafety:r.repair==="noopener"?"safe":"review",language,start,end,matchedText:r.category==="secrets"?"[redacted candidate]":String(match).slice(0,1000),snippet})};
      if(language==="json"){try{JSON.parse(text)}catch(err){const msg=String(err.message||"Invalid JSON"),pos=Number((msg.match(/position\s+(\d+)/i)||[])[1]||0);add({id:"JSON-INVALID-01",title:"Invalid JSON syntax",severity:"high",category:"syntax",description:"JSON parser: "+msg.slice(0,180),confidence:"high"},text.slice(pos,pos+1),Math.min(pos,text.length),Math.min(pos+1,text.length))}}
      for(const r of candidates){if(!((r.language||[]).includes(language)||(r.language||[]).includes("text")))continue;checked++;try{if(r.match){const needle=String(r.match).toLowerCase();let at=0,n=0;while((at=low.indexOf(needle,at))!==-1&&n<8){add(r,text.slice(at,at+needle.length),at,at+needle.length);n++;at+=Math.max(1,needle.length)}continue}const re=new RegExp(r.pattern,r.flags||"gi");let n=0;for(let m;(m=re.exec(text))&&n<8;){if(!(r.id==="HTML-LINK-NOOPENER"&&/\brel\s*=\s*(['"])[^'"]*\bnoopener\b/i.test(m[0]))){add(r,m[0],m.index,m.index+m[0].length);n++}if(!m[0].length)re.lastIndex++}}catch{}}
      self.postMessage({type:"done",id:data.id,findings:out,checked});
    } catch(error) { self.postMessage({type:"error",id:data.id,error:String(error&&error.message||error)}); }
  };
}
function ensureWorker() {
  if(state.worker)return state.worker;
  try{state.workerUrl=URL.createObjectURL(new Blob(["("+scannerWorkerCore.toString()+")()"],{type:"text/javascript"}));state.worker=new Worker(state.workerUrl);return state.worker}catch{return null}
}
let workerJob=0, workerRulesVersion=-1;
function scanInWorker(file) {
  const worker=ensureWorker();if(!worker)return Promise.resolve(scanSync(file,state.customRules));
  const id="orf-"+(++workerJob);
  return new Promise(resolve=>{
    const finish=(result)=>{clearTimeout(timer);worker.removeEventListener("message",listener);resolve(result)};
    const timer=setTimeout(()=>{workerRulesVersion=-1;finish(scanSync(file,state.customRules))},12000);
    const listener=event=>{if(event.data?.id!==id)return;if(event.data.type==="done")finish({findings:event.data.findings,checked:event.data.checked});else{workerRulesVersion=-1;finish(scanSync(file,state.customRules))}};
    worker.addEventListener("message",listener);
    const version=RULES.length+state.customRules.length;
    const message={type:"scan",id,path:file.path,text:file.currentText,language:file.language,version};
    if(workerRulesVersion!==version){message.rules=RULES;message.customRules=state.customRules;workerRulesVersion=version;}
    worker.postMessage(message);
  });
}
function severityCounts() {
  const result={critical:0,high:0,medium:0,low:0,info:0};
  for(const finding of state.findings)if(Object.prototype.hasOwnProperty.call(result,finding.severity))result[finding.severity]++;
  const active=state.repairHistory.filter(item=>!item.undone);
  return {...result,findings:state.findings.length,repaired:active.length,verified:active.filter(item=>item.verified).length,skipped:state.repairHistory.filter(item=>item.skipped&&!item.undone).length};
}
function snapshot() {
  const files=[...state.files.values()],summary=severityCounts();
  return {status:state.status,project:{name:state.projectName,files:files.map(f=>({path:f.path,size:f.size,language:f.language,status:f.status})),fileCount:files.length,totalBytes:files.reduce((sum,f)=>sum+(f.size||0),0)},
    scan:{...state.scan},summary,findings:state.findings.map(item=>({...item})),selectedFindingId:state.selectedFindingId,repairPreview:state.repairPreview?({...state.repairPreview}):null,
    filters:{...state.filters},capabilities:{canScan:files.some(f=>f.isText&&f.currentText!==null)&&!state.working,canCancel:state.working,canApplySafe:!state.working&&state.findings.some(f=>f.fixAvailable&&f.repairSafety==="safe"),canUndo:state.undoStack.length>0&&!state.working,canExportZip:files.length>0&&!state.working,canExportReport:files.length>0||state.findings.length>0},
    engine:{name:"ORF Deterministic Engine",version:"1.0.0",ruleCount:RULES.length+state.customRules.length,builtInRuleCount:RULES.length,customRuleCount:state.customRules.length,customPackPersistence:state.customPackPersistence,contractVersion:1},error:state.lastError};
}
function publish(){ $emit("orf:state",snapshot()); $emit("orf:engine-ready",{contractVersion:1,ruleCount:RULES.length+state.customRules.length,builtInRuleCount:RULES.length,customRuleCount:state.customRules.length}); }
function safeProjectName(name){return String(name||"repaired-project").replace(/[^a-z0-9._-]+/gi,"-").replace(/^-+|-+$/g,"")||"repaired-project";}
function inferredProjectName(records){if(!records.length)return "Untitled project";const first=records[0].path.split("/");if(first.length>1&&records.every(f=>f.path.startsWith(first[0]+"/")))return first[0];return "Imported project";}
function classify(path,bytes){const ext=extension(path),lang=languageFromPath(path),sample=bytes.subarray(0,Math.min(8192,bytes.length));const binary=sample.includes(0)||(!TEXT_EXT.has(ext)&&sample.some(b=>b<8||(b>13&&b<32)));const isText=!binary&&TEXT_EXT.has(ext)&&bytes.length<=LIMITS.scanBytes;return {language:lang,isText};}
async function recordsFromFiles(files) {
  const records=[];let total=0;
  for(const input of Array.from(files||[])){const path=normalizePath(input.webkitRelativePath||input.name);if(input.size>LIMITS.fileBytes)throw new Error("A file exceeds the 35 MB limit: "+path);total+=input.size;if(total>LIMITS.totalBytes)throw new Error("This import exceeds 120 MB. Import a smaller project.");const bytes=new Uint8Array(await input.arrayBuffer()),kind=classify(path,bytes),text=kind.isText?decoder.decode(bytes):null;records.push({path,name:path.split("/").pop(),size:bytes.length,language:kind.language,isText:kind.isText,originalBytes:bytes,currentText:text,status:kind.isText?"ready":bytes.length>LIMITS.scanBytes?"too-large-to-scan":"binary"});}
  return records;
}
async function importProject(mode,records) {
  if(state.working)throw new Error("Cancel the current scan before importing files.");
  if(!records.length){toast("No files were selected.");return;}
  if(mode!=="append"){state.files.clear();state.repairHistory=[];state.undoStack=[];}
  let collisions=0;
  for(const record of records){if(state.files.has(record.path))collisions++;state.files.set(record.path,record);}
  state.projectName=inferredProjectName([...state.files.values()]);state.findings=[];state.selectedFindingId=null;state.repairPreview=null;state.status="ready";state.lastError=null;state.scan={scannedFiles:0,totalFiles:0,patternsChecked:0,progress:0};publish();
  toast(records.length+" file(s) imported"+(mode==="append"?" and merged":"")+(collisions?", "+collisions+" existing path(s) replaced":""),"success");
}
function createPreview(finding) {
  if(!finding)throw new Error("Select a finding first.");
  if(finding.ruleId!=="HTML-LINK-NOOPENER"||!finding.fixAvailable)throw new Error("No tested automatic repair is registered for this finding.");
  const file=state.files.get(finding.path);if(!file||file.currentText===null)throw new Error("The source file is not editable text.");
  const before=file.currentText.slice(finding.start,finding.end);
  if(!/^<a\b/i.test(before)||/\brel\s*=\s*(['"])[^'"]*\bnoopener\b/i.test(before))throw new Error("The source no longer matches the repair recipe; rescan first.");
  let after;
  const rel=/\brel\s*=\s*(['"])(.*?)\1/i;
  if(rel.test(before))after=before.replace(rel,(all,q,value)=>{const parts=value.split(/\s+/).filter(Boolean);for(const item of ["noopener","noreferrer"])if(!parts.some(p=>p.toLowerCase()===item))parts.push(item);return "rel="+q+parts.join(" ")+q;});
  else {const end=before.lastIndexOf(">");if(end<0)throw new Error("The link tag is incomplete.");after=before.slice(0,end).replace(/\/\s*$/,"")+' rel="noopener noreferrer"'+before.slice(end);}
  state.selectedFindingId=finding.id;state.repairPreview={findingId:finding.id,path:finding.path,before,after,explanation:finding.description,safety:"safe",canApply:true,start:finding.start,end:finding.end,ruleId:finding.ruleId};publish();
}
async function runScan() {
  if(state.working){toast("A scan is already running.","warning");return;}
  const eligible=[...state.files.values()].filter(file=>file.isText&&file.currentText!==null);
  if(!eligible.length)throw new Error("Import at least one supported text/source file before scanning.");
  state.working=true;state.cancel=false;state.status="scanning";state.lastError=null;state.findings=[];state.selectedFindingId=null;state.repairPreview=null;state.scan={scannedFiles:0,totalFiles:eligible.length,patternsChecked:0,progress:0};publish();
  try{
    for(const file of eligible){if(state.cancel)break;progress("scan","Scanning "+file.path,state.scan.scannedFiles,eligible.length);const result=await scanInWorker(file);state.findings.push(...result.findings);state.scan.patternsChecked+=result.checked||0;state.scan.scannedFiles++;file.status=file.status==="modified"?"modified":"scanned";state.scan.progress=Math.round(state.scan.scannedFiles*100/eligible.length);publish();await pause();}
    if(!state.cancel){state.findings.push(...crossFileFindings([...state.files.values()]));const unique=new Map();for(const f of state.findings)unique.set(f.ruleId+"|"+f.path+"|"+f.start+"|"+f.end,f);state.findings=[...unique.values()].sort((a,b)=>({critical:0,high:1,medium:2,low:3,info:4}[a.severity]??9)-({critical:0,high:1,medium:2,low:3,info:4}[b.severity]??9)||a.path.localeCompare(b.path)||a.line-b.line);
      for(const entry of state.repairHistory.filter(item=>!item.undone))entry.verified=!state.findings.some(f=>f.path===entry.path&&f.ruleId===entry.ruleId);
      state.status="complete";state.scan.progress=100;if(!state.selectedFindingId&&state.findings.length)state.selectedFindingId=state.findings[0].id;progress("scan","Scan complete",eligible.length,eligible.length);toast("Scan complete · "+eligible.length+" files · "+state.findings.length+" finding(s)","success");
    }else{state.findings.sort((a,b)=>a.path.localeCompare(b.path)||a.line-b.line);state.status="cancelled";toast("Scan cancelled after the current file.","warning");}
  }catch(error){state.status="error";state.lastError=String(error&&error.message||error);toast("Scan failed: "+state.lastError,"error");}
  finally{state.working=false;publish();}
}
function applyPatch(finding) {
  if(state.working)throw new Error("Wait for the current scan to finish.");
  const file=state.files.get(finding.path);if(!file||file.currentText===null)throw new Error("Source text is unavailable.");
  const preview=state.repairPreview;if(!preview||preview.findingId!==finding.id)throw new Error("Preview the repair before applying it.");
  if(file.currentText.slice(preview.start,preview.end)!==preview.before)throw new Error("The source changed since preview. Rescan first.");
  const old=file.currentText;file.currentText=old.slice(0,preview.start)+preview.after+old.slice(preview.end);file.size=encoder.encode(file.currentText).length;file.status="modified";
  state.undoStack.push({before:new Map([[file.path,old]]),path:file.path,ruleId:finding.ruleId});state.repairHistory.push({path:file.path,ruleId:finding.ruleId,undone:false,verified:false,skipped:false});state.repairPreview=null;toast("Repair applied. Running a verification scan…","success");return runScan();
}
async function applySafeRepairs() {
  if(state.working)throw new Error("Wait for the current scan to finish.");
  const candidates=state.findings.filter(f=>f.fixAvailable&&f.repairSafety==="safe"&&f.ruleId==="HTML-LINK-NOOPENER");
  if(!candidates.length){toast("No eligible safe repairs are available.");return;}
  if(!window.confirm("Apply "+candidates.length+" eligible safe repair(s)? The project will be rescanned."))return;
  const groups=new Map(),records=[];
  for(const f of candidates){const file=state.files.get(f.path);if(!file||file.currentText===null)continue;try{if(!groups.has(file.path))groups.set(file.path,{file,before:file.currentText,patches:[]});const p={start:f.start,end:f.end,before:file.currentText.slice(f.start,f.end),finding:f};if(!/^<a\b/i.test(p.before)||/\brel\s*=\s*(['"])[^'"]*\bnoopener\b/i.test(p.before))continue;let after;const rel=/\brel\s*=\s*(['"])(.*?)\1/i;if(rel.test(p.before))after=p.before.replace(rel,(all,q,value)=>{const bits=value.split(/\s+/).filter(Boolean);["noopener","noreferrer"].forEach(x=>{if(!bits.some(b=>b.toLowerCase()===x))bits.push(x)});return "rel="+q+bits.join(" ")+q});else { const end=p.before.lastIndexOf(">"); after=p.before.slice(0,end).replace(/\/\s*$/,"")+' rel="noopener noreferrer"'+p.before.slice(end); }p.after=after;groups.get(file.path).patches.push(p);records.push({path:f.path,ruleId:f.ruleId,undone:false,verified:false,skipped:false});}catch{}}
  const history={before:new Map(),path:"bulk",ruleId:"HTML-LINK-NOOPENER",records:[]};let changed=0;
  for(const group of groups.values()){const {file,before,patches}=group;if(!patches.length)continue;patches.sort((a,b)=>b.start-a.start);let next=before;for(const p of patches){if(next.slice(p.start,p.end)!==p.before)continue;next=next.slice(0,p.start)+p.after+next.slice(p.end);history.records.push({path:file.path,ruleId:p.finding.ruleId,undone:false,verified:false,skipped:false});changed++}if(next!==before){history.before.set(file.path,before);file.currentText=next;file.size=encoder.encode(next).length;file.status="modified";}}
  if(!history.before.size){toast("No eligible repair matched the current source. Scan again.","warning");return;}
  state.undoStack.push({before:history.before,path:"bulk",ruleId:"HTML-LINK-NOOPENER",records:history.records});state.repairHistory.push(...history.records);state.repairPreview=null;await runScan();
}
async function undoRepair() {
  if(state.working)throw new Error("Wait for the scan to finish.");const item=state.undoStack.pop();if(!item)throw new Error("There is no repair to undo.");
  for(const [path,old] of item.before){const file=state.files.get(path);if(file){file.currentText=old;file.size=encoder.encode(old).length;file.status="ready";}}
  const records=item.records||state.repairHistory.filter(r=>r.path===item.path&&r.ruleId===item.ruleId&&!r.undone).slice(-1);records.forEach(r=>r.undone=true);
  state.repairPreview=null;toast("Previous repair operation undone. Rechecking the project.","success");await runScan();
}
function crc32(bytes){let c=0xffffffff;for(const b of bytes){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0)}return(c^0xffffffff)>>>0;}
async function zipWrite(entries){
  const locals=[],centrals=[];let offset=0;
  for(const entry of entries){const name=encoder.encode(entry.path),data=entry.bytes,crc=crc32(data),local=new Uint8Array(30+name.length+data.length),lv=new DataView(local.buffer);lv.setUint32(0,0x04034b50,true);lv.setUint16(4,20,true);lv.setUint16(6,0,true);lv.setUint16(8,0,true);lv.setUint32(14,crc,true);lv.setUint32(18,data.length,true);lv.setUint32(22,data.length,true);lv.setUint16(26,name.length,true);local.set(name,30);local.set(data,30+name.length);locals.push(local);
    const cd=new Uint8Array(46+name.length),cv=new DataView(cd.buffer);cv.setUint32(0,0x02014b50,true);cv.setUint16(4,20,true);cv.setUint16(6,20,true);cv.setUint16(8,0,true);cv.setUint16(10,0,true);cv.setUint32(16,crc,true);cv.setUint32(20,data.length,true);cv.setUint32(24,data.length,true);cv.setUint16(28,name.length,true);cv.setUint32(42,offset,true);cd.set(name,46);centrals.push(cd);offset+=local.length;
  }
  const centralSize=centrals.reduce((sum,x)=>sum+x.length,0),end=new Uint8Array(22),dv=new DataView(end.buffer);dv.setUint32(0,0x06054b50,true);dv.setUint16(8,entries.length,true);dv.setUint16(10,entries.length,true);dv.setUint32(12,centralSize,true);dv.setUint32(16,offset,true);
  const blob=new Blob([...locals,...centrals,end],{type:"application/zip"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=safeProjectName(state.projectName)+"-repaired.zip";document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),15000);return {bytes:blob.size,count:entries.length};
}
async function zipRead(file){
  if(file.size>LIMITS.totalBytes)throw new Error("ZIP exceeds the 120 MB import limit.");
  const bytes=new Uint8Array(await file.arrayBuffer()),dv=new DataView(bytes.buffer);let eocd=-1;
  for(let i=bytes.length-22;i>=Math.max(0,bytes.length-65557);i--)if(dv.getUint32(i,true)===0x06054b50){eocd=i;break;}
  if(eocd<0)throw new Error("No ZIP directory was found.");const count=dv.getUint16(eocd+10,true);let at=dv.getUint32(eocd+16,true);if(count>LIMITS.entries)throw new Error("ZIP has more than 20,000 entries.");
  const records=[];let totalUncompressed=0;
  for(let n=0;n<count;n++){if(dv.getUint32(at,true)!==0x02014b50)throw new Error("Malformed ZIP directory.");const flags=dv.getUint16(at+8,true),method=dv.getUint16(at+10,true),compressedSize=dv.getUint32(at+20,true),size=dv.getUint32(at+24,true),nameLen=dv.getUint16(at+28,true),extraLen=dv.getUint16(at+30,true),commentLen=dv.getUint16(at+32,true),localOffset=dv.getUint32(at+42,true),path=decoder.decode(bytes.slice(at+46,at+46+nameLen));at+=46+nameLen+extraLen+commentLen;if(path.endsWith("/"))continue;const safePath=normalizePath(path);if(flags&1)throw new Error("Encrypted ZIP entries are unsupported: "+safePath);if(size>LIMITS.fileBytes)throw new Error("ZIP entry exceeds 35 MB: "+safePath);totalUncompressed+=size;if(totalUncompressed>LIMITS.totalBytes)throw new Error("The uncompressed ZIP contents exceed the 120 MB safety limit.");if(dv.getUint32(localOffset,true)!==0x04034b50)throw new Error("Malformed ZIP file entry.");const start=localOffset+30+dv.getUint16(localOffset+26,true)+dv.getUint16(localOffset+28,true),stored=bytes.slice(start,start+compressedSize);let data;
    if(method===0)data=stored;else if(method===8){if(typeof DecompressionStream==="undefined")throw new Error("This browser cannot unpack compressed ZIP files; use a current Chrome or Edge.");const stream=new Blob([stored]).stream().pipeThrough(new DecompressionStream("deflate-raw"));data=new Uint8Array(await new Response(stream).arrayBuffer())}else throw new Error("Unsupported ZIP compression method "+method+" in "+safePath);
    if(data.length!==size)throw new Error("ZIP entry size mismatch: "+safePath);const ext=extension(safePath),sample=data.subarray(0,Math.min(8192,data.length)),binary=sample.includes(0)||(!TEXT_EXT.has(ext)&&sample.some(b=>b<8||(b>13&&b<32))),isText=TEXT_EXT.has(ext)&&!binary&&data.length<=LIMITS.scanBytes,txt=isText?decoder.decode(data):null;
    records.push({path:safePath,name:safePath.split("/").pop(),size:data.length,language:languageFromPath(safePath),isText,originalBytes:data,currentText:txt,status:isText?"ready":data.length>LIMITS.scanBytes?"too-large-to-scan":"binary"});
  }
  return records;
}
function report(format){
  const s=severityCounts(),name=safeProjectName(state.projectName);let data,filename,mime;
  if(format==="sarif"){const ids=[...new Set(state.findings.map(f=>f.ruleId))];data={$schema:"https://json.schemastore.org/sarif-2.1.0.json",version:"2.1.0",runs:[{tool:{driver:{name:"ORF Repository Fixer",version:"1.0.0",rules:ids.map(id=>{const f=state.findings.find(x=>x.ruleId===id);return{id,shortDescription:{text:f?.title||id},fullDescription:{text:f?.description||""}}})}},results:state.findings.map(f=>({ruleId:f.ruleId,level:({critical:"error",high:"error",medium:"warning",low:"note",info:"note"})[f.severity]||"warning",message:{text:f.description||f.title},locations:[{physicalLocation:{artifactLocation:{uri:f.path},region:{startLine:f.line||1,startColumn:f.column||1}}}],properties:{severity:f.severity,category:f.category,confidence:f.confidence}}))}]};filename=name+"-findings.sarif";mime="application/sarif+json";}
  else{data={schemaVersion:1,generatedAt:new Date().toISOString(),engine:{name:"ORF Deterministic Engine",version:"1.0.0",ruleCount:RULES.length+state.customRules.length,builtInRuleCount:RULES.length,customRuleCount:state.customRules.length},project:{name:state.projectName,fileCount:state.files.size,totalBytes:[...state.files.values()].reduce((sum,f)=>sum+f.size,0)},summary:s,findings:state.findings.map(f=>({...f,matchedText:f.category==="secrets"?"[redacted]":f.matchedText})),repairs:state.repairHistory.filter(x=>!x.undone),notes:["Static heuristics may produce false positives and false negatives.","A clean scan is not a guarantee that the project is secure or correct."]};filename=name+"-findings.json";mime="application/json";}
  const blob=new Blob([JSON.stringify(data,null,2)],{type:mime}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),12000);toast(format.toUpperCase()+" report exported.","success");
}
async function importPatternPack(file){
  if(!file)throw new Error("Choose a pattern pack.");if(file.size>LIMITS.packBytes)throw new Error("Pattern pack exceeds the 5 MB limit.");
  const payload=JSON.parse(await file.text()),fresh=safeRulePack(payload.rules);
  if(!fresh.length)throw new Error("No valid unique literal rules were found. Pack rules must provide id and match strings.");
  state.customRules.push(...fresh);workerRulesVersion=-1;mainNeedleIndex=null;mainNeedleIndexCount=-1;await persistRules();publish();toast("Imported "+fresh.length+" validated literal rule(s).","success");
}
function exportPatternPack(){if(!state.customRules.length)throw new Error("No custom patterns to export yet.");const payload={schemaVersion:1,name:"ORF custom literal pattern pack",createdAt:new Date().toISOString(),rules:state.customRules.map(r=>({id:r.id,title:r.title,severity:r.severity,category:r.category,languages:r.language,match:r.match,description:r.description}))};const blob=new Blob([JSON.stringify(payload,null,2)],{type:"application/json"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download="orf-custom-patterns.json";document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),12000);toast("Exported "+state.customRules.length+" custom rules.","success");}
async function persistRules(){
  try{if(!window.indexedDB)throw new Error("no IndexedDB");const db=await new Promise((resolve,reject)=>{const req=indexedDB.open("orf-browser-patterns",1);req.onupgradeneeded=()=>{if(!req.result.objectStoreNames.contains("state"))req.result.createObjectStore("state")};req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error)});await new Promise((resolve,reject)=>{const tx=db.transaction("state","readwrite");tx.objectStore("state").put(state.customRules.map(r=>({id:r.id,title:r.title,severity:r.severity,category:r.category,language:r.language,match:r.match,description:r.description})),"customRules");tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error)});db.close();state.customPackPersistence="IndexedDB";}catch{state.customPackPersistence="session only";}
}
async function restoreRules(){
  try{const db=await new Promise((resolve,reject)=>{const req=indexedDB.open("orf-browser-patterns",1);req.onupgradeneeded=()=>{if(!req.result.objectStoreNames.contains("state"))req.result.createObjectStore("state")};req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error)});const stored=await new Promise((resolve,reject)=>{const req=db.transaction("state","readonly").objectStore("state").get("customRules");req.onsuccess=()=>resolve(req.result||[]);req.onerror=()=>reject(req.error)});db.close();if(Array.isArray(stored))state.customRules=safeRulePack(stored);workerRulesVersion=-1;mainNeedleIndex=null;mainNeedleIndexCount=-1;state.customPackPersistence="IndexedDB";}catch{state.customPackPersistence="unavailable";}publish();
}
async function handleAction({detail}) {
  const d=detail||{};
  try {
    switch(d.type){
      case "PROJECT_IMPORT_FILES":
      case "PROJECT_IMPORT_FOLDER": {progress("import","Reading selected files…",0,d.files?.length||0);await importProject(d.mode==="append"?"append":"replace",await recordsFromFiles(d.files));break;}
      case "PROJECT_IMPORT_ZIP": {progress("import","Opening ZIP archive…",0,1);await importProject(d.mode==="append"?"append":"replace",await zipRead(d.file));break;}
      case "SCAN_START": await runScan();break;
      case "SCAN_CANCEL": if(!state.working)toast("No scan is running.");else{state.cancel=true;progress("scan","Cancellation requested…",state.scan.scannedFiles,state.scan.totalFiles); }break;
      case "FILTERS_CHANGE": state.filters={query:String(d.query||""),severity:String(d.severity||"all"),category:String(d.category||"all"),language:String(d.language||"all")};publish();break;
      case "FINDING_SELECT": if(!state.findings.some(f=>f.id===d.findingId))throw new Error("Finding no longer exists. Run the scan again.");state.selectedFindingId=d.findingId;state.repairPreview=null;publish();break;
      case "REPAIR_PREVIEW": createPreview(state.findings.find(f=>f.id===d.findingId));break;
      case "REPAIR_APPLY": {const f=state.findings.find(x=>x.id===d.findingId);if(!f)throw new Error("Finding no longer exists.");await applyPatch(f);break;}
      case "REPAIR_REJECT": state.repairPreview=null;publish();toast("Repair proposal rejected. No source files changed.");break;
      case "REPAIR_APPLY_SAFE": await applySafeRepairs();break;
      case "REPAIR_UNDO": await undoRepair();break;
      case "EXPORT_ZIP": {const entries=[];for(const f of state.files.values())entries.push({path:f.path,bytes:f.isText&&f.currentText!==null?encoder.encode(f.currentText):f.originalBytes});const result=await zipWrite(entries);toast("Created ZIP · "+result.count+" files · "+result.bytes+" bytes.","success");break;}
      case "EXPORT_REPORT": report(d.format==="sarif"?"sarif":"json");break;
      case "PATTERN_PACK_IMPORT": await importPatternPack(d.file);break;
      case "PATTERN_PACK_EXPORT": exportPatternPack();break;
      default: toast("Unsupported action: "+String(d.type||"(missing type)"),"warning");
    }
  }catch(error){state.lastError=String(error&&error.message||error);toast(state.lastError,"error");if(!state.working)state.status=state.files.size?"ready":"error";publish();}
}
window.addEventListener(ACTION,handleAction);
window.addEventListener("orf:ui-ready",()=>{publish();toast("Engine ready · "+(RULES.length+state.customRules.length)+" deterministic rules loaded.","info");});
window.addEventListener("pagehide",()=>{if(state.worker)state.worker.terminate();if(state.workerUrl)URL.revokeObjectURL(state.workerUrl);});
publish();
void restoreRules();