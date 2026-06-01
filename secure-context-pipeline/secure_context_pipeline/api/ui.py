"""Self-contained demo UI for the Secure Context Pipeline.

A single-page app served same-origin at ``GET /ui``. Walks the full CRUD
lifecycle (open session → upload → list → run → destroy session) and renders a
**live activity timeline** powered by the SSE stream at ``/events``. Every step,
including errors and the leak-gate firing, lands on the timeline in real time
with end-user-friendly copy ("Encrypting your document", "Leak check passed",
"Vault destroyed — token map gone forever").

The trust-boundary view (Original → Sent → LLM raw → Restored) remains as four
panels populated from the ``/run`` response.

The page key is entered at runtime in the browser and forwarded as either the
``X-API-Key`` header (regular requests) or ``?api_key=…`` (SSE/history, since
``EventSource`` cannot set headers).
"""

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Secure Context Pipeline — Live Activity</title>
<style>
  :root {
    --bg:#0b0f17; --panel:#141a24; --panel-2:#1a2230; --border:#2a3344;
    --text:#e6edf3; --muted:#8b949e;
    --accent:#2f81f7; --boundary:#1f6feb; --token:#d29922;
    --ok:#3fb950; --warn:#d29922; --err:#f85149; --working:#58a6ff;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
    font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:14px 22px; border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:16px; flex-wrap:wrap;
    background:linear-gradient(180deg,#0d1320,var(--bg)); }
  header h1 { font-size:17px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:12px; }
  .stats-mini { margin-left:auto; display:flex; gap:18px; font-size:12px; color:var(--muted); }
  .stats-mini b { color:var(--text); font-size:14px; }
  main { display:grid; grid-template-columns: 1.15fr 0.85fr; gap:0;
    min-height:calc(100vh - 56px); }
  @media (max-width:980px){ main { grid-template-columns:1fr; } }
  .left { padding:18px 22px; border-right:1px solid var(--border); overflow:auto; }
  .right { padding:18px 22px; overflow:auto; background:var(--panel); }

  /* controls */
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; }
  label.field { display:flex; flex-direction:column; gap:4px;
    font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }
  input, textarea, select, button {
    background:var(--panel); color:var(--text); border:1px solid var(--border);
    border-radius:6px; padding:8px 10px; font:inherit; }
  input:focus, textarea:focus, select:focus { outline:none; border-color:var(--accent); }
  textarea { width:100%; min-height:120px; resize:vertical;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:13px; }
  button { cursor:pointer; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff;
    font-weight:600; padding:9px 16px; }
  button.danger { background:transparent; border-color:#5a2a2a; color:#ff7b72; }
  button.ghost { background:transparent; }
  button:disabled { opacity:.4; cursor:not-allowed; }
  .actions { display:flex; gap:8px; flex-wrap:wrap; margin:14px 0 4px; }
  .samples { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0 0; align-items:center; }
  .samples .note, .muted { color:var(--muted); font-size:12px; }
  .err { color:var(--err); margin:10px 0; white-space:pre-wrap; font-size:13px; min-height:1em; }
  .session-info { display:flex; gap:14px; margin:10px 0; flex-wrap:wrap;
    color:var(--muted); font-size:12px; font-family:ui-monospace,Consolas,monospace; }
  .session-info b { color:var(--text); }
  .session-info .dot { display:inline-block; width:8px; height:8px; border-radius:50%;
    background:var(--err); margin-right:6px; vertical-align:middle; }
  .session-info.connected .dot { background:var(--ok); }

  /* 4-panel grid */
  .grid { display:grid; grid-template-columns:repeat(2,1fr); gap:12px; margin-top:18px; }
  @media (max-width:680px){ .grid { grid-template-columns:1fr; } }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  .card h2 { font-size:11px; text-transform:uppercase; letter-spacing:.05em;
    margin:0; padding:9px 12px; border-bottom:1px solid var(--border);
    color:var(--muted); display:flex; align-items:center; gap:8px; }
  .card .body { padding:12px; white-space:pre-wrap; word-break:break-word;
    font-family:ui-monospace,Consolas,monospace; font-size:12.5px; min-height:60px; }
  .card.boundary { border-color:var(--boundary); }
  .card.boundary h2 { color:var(--boundary); }
  .badge { font-size:10px; padding:2px 7px; border-radius:10px;
    border:1px solid var(--border); color:var(--muted); text-transform:none; letter-spacing:0; }
  .badge.leaves { background:rgba(31,111,235,.15); color:#79c0ff; border-color:#1f6feb; }
  .tok { color:var(--token); background:rgba(210,153,34,.13); border-radius:3px; padding:0 2px; }
  .runstats { display:flex; gap:18px; flex-wrap:wrap; margin-top:12px; color:var(--muted); font-size:12px; }
  .runstats b { color:var(--text); font-size:14px; }

  /* docs list */
  #docs-list { list-style:none; padding:0; margin:8px 0 0; max-height:140px; overflow:auto; }
  #docs-list li { padding:6px 9px; border:1px solid var(--border); border-radius:5px;
    margin-bottom:5px; font-family:ui-monospace,Consolas,monospace; font-size:12px; color:var(--muted); }

  /* activity timeline */
  .right h2 { font-size:13px; margin:0 0 4px; display:flex; align-items:center; gap:8px; }
  .stream-status { font-size:11px; color:var(--muted); }
  .stream-status.live { color:var(--ok); }
  #timeline { list-style:none; padding:0; margin:14px 0 0; position:relative; }
  #timeline::before { content:""; position:absolute; left:13px; top:6px; bottom:6px;
    width:2px; background:linear-gradient(180deg,var(--border),transparent); }
  .tl-item { position:relative; padding:8px 10px 8px 38px; margin-bottom:6px;
    border-radius:6px; background:var(--panel-2); border:1px solid var(--border);
    display:grid; grid-template-columns: 1fr auto; gap:8px; align-items:center;
    animation: slideIn .25s ease-out; }
  @keyframes slideIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }
  .tl-item .tl-icon { position:absolute; left:6px; top:50%; transform:translateY(-50%);
    width:22px; height:22px; border-radius:50%; background:var(--panel);
    display:flex; align-items:center; justify-content:center; font-size:13px;
    border:2px solid var(--border); }
  .tl-text { font-size:13px; }
  .tl-sub { display:block; color:var(--muted); font-size:11px; margin-top:2px; }
  .tl-time { color:var(--muted); font-size:11px; font-family:Consolas,monospace; }
  .lvl-ok       { border-color:rgba(63,185,80,.35); }
  .lvl-ok .tl-icon       { border-color:var(--ok); }
  .lvl-info     { }
  .lvl-working  { border-color:rgba(88,166,255,.35); }
  .lvl-working .tl-icon  { border-color:var(--working); animation: pulse 1.4s infinite; }
  @keyframes pulse { 50% { box-shadow:0 0 0 3px rgba(88,166,255,.2); } }
  .lvl-warn     { border-color:rgba(210,153,34,.4); }
  .lvl-warn .tl-icon     { border-color:var(--warn); }
  .lvl-err      { border-color:rgba(248,81,73,.5); background:rgba(248,81,73,.06); }
  .lvl-err .tl-icon      { border-color:var(--err); }
  .tl-empty { color:var(--muted); font-size:12px; padding:18px 0; text-align:center;
    border:1px dashed var(--border); border-radius:6px; }

  details.tech { margin-top:18px; }
  details.tech summary { cursor:pointer; color:var(--muted); font-size:12px; }
</style>
</head>
<body>
<header>
  <h1>🔒 Secure Context Pipeline</h1>
  <span class="sub">live activity • detect → obfuscate → leak-gate → LLM → restore</span>
  <div class="stats-mini">
    <span>sessions <b id="stat-sessions">0</b></span>
    <span>leaks caught <b id="stat-leaks">0</b></span>
    <span>clean round trips <b id="stat-rt">0</b></span>
    <span id="backend">backend …</span>
  </div>
</header>
<main>

  <section class="left">
    <div class="row">
      <label class="field">API key
        <input id="apikey" type="password" placeholder="X-API-Key" size="28" />
      </label>
      <label class="field">User
        <input id="userid" type="text" value="demo-user" size="14" />
      </label>
      <label class="field">Strategy
        <select id="strategy">
          <option value="">default</option>
          <option value="tokenization">tokenization</option>
          <option value="pseudonymization">pseudonymization</option>
        </select>
      </label>
    </div>

    <div class="session-info" id="session-info">
      <span><span class="dot"></span><span id="stream-status">offline</span></span>
      <span>session: <b id="session-id">(none)</b></span>
      <span>last doc: <b id="doc-id">(none)</b></span>
    </div>

    <div class="actions">
      <button id="btn-open"    class="primary">Open secure session</button>
      <button id="btn-upload"  class="ghost"   disabled>Upload document</button>
      <button id="btn-list"    class="ghost"   disabled>List my documents</button>
      <button id="btn-run"     class="primary" disabled>Run pipeline</button>
      <button id="btn-trigger-leak" class="ghost" disabled title="Sends a bare card number bypassing detection, just to see the leak gate fire">Try to leak data</button>
      <button id="btn-destroy" class="danger"  disabled>Destroy session</button>
    </div>

    <div class="err" id="err"></div>

    <label class="field" style="margin-top:8px;display:block;">Sensitive document</label>
    <textarea id="doc"></textarea>
    <div class="samples">
      <span class="note">Samples:</span>
      <button class="ghost" data-s="medical">Medical</button>
      <button class="ghost" data-s="legal">Legal</button>
      <button class="ghost" data-s="financial">Financial</button>
      <button class="ghost" data-s="clean">Clean (no PII)</button>
    </div>

    <label class="field" style="margin-top:12px;display:block;">Question for the AI</label>
    <input id="query" type="text" style="width:100%;" value="Summarize this record." />

    <ul id="docs-list"></ul>

    <div class="grid">
      <div class="card">
        <h2>① Original <span class="badge">stays inside YourAI</span></h2>
        <div class="body" id="p-original"></div>
      </div>
      <div class="card boundary">
        <h2>② Sent to AI <span class="badge leaves">crosses boundary →</span></h2>
        <div class="body" id="p-sent"></div>
      </div>
      <div class="card">
        <h2>③ AI raw reply <span class="badge">tokens, pre-restore</span></h2>
        <div class="body" id="p-raw"></div>
      </div>
      <div class="card">
        <h2>④ Restored <span class="badge">shown to you</span></h2>
        <div class="body" id="p-restored"></div>
      </div>
    </div>
    <div class="runstats" id="runstats"></div>
  </section>

  <aside class="right">
    <h2>📡 Live activity
      <span class="stream-status" id="stream-status-2">offline</span>
    </h2>
    <p class="muted" style="margin:4px 0 0;">Every Create/Read/Update/Delete and every error appears here in real time. The stream replays prior events on reconnect.</p>
    <ul id="timeline"></ul>
    <p class="tl-empty" id="tl-empty">Open a secure session to start the live feed.</p>
  </aside>

</main>

<script>
const SAMPLES = {
  medical: "Patient John Smith (DOB 04/12/1981), MRN 884211, was diagnosed with Type 2 Diabetes Mellitus and prescribed Metformin 500mg twice daily. Contact: john.smith@example.com, (415) 555-0182. Insurance ID BCBS-99812341. Latest HbA1c 7.8%.",
  legal: "Client Maria Gonzalez retained the firm regarding the merger. Litigation strategy: file for summary judgment before the 03/01 deadline. SSN 412-55-9981. Reach her at maria.g@example.com.",
  financial: "Account holder Robert Tan, account 4012 8888 8888 1881, routing via tax ID 47-1234567. Disclosed annual income and a wire of $84,000 to settle the dispute.",
  clean: "The quarterly report shows revenue grew 12% driven by strong demand in the cloud segment. No customer data is included in this summary."
};
const $ = id => document.getElementById(id);
const esc = s => (s||"").replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const highlightTokens = s => (s||"").replace(/\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\]/g,
  m => '<span class="tok">'+m+'</span>');

const STATE = { sessionId: null, es: null };
const STATS = { sessions: 0, leaksCaught: 0, cleanRoundTrips: 0 };

const apiKey = () => $("apikey").value.trim();
const userId = () => $("userid").value.trim();
const baseHeaders = () => {
  const h = { "Content-Type": "application/json" };
  if (apiKey()) h["X-API-Key"] = apiKey();
  return h;
};
const setErr = msg => { $("err").textContent = msg || ""; };
function refreshStats() {
  $("stat-sessions").textContent = STATS.sessions;
  $("stat-leaks").textContent = STATS.leaksCaught;
  $("stat-rt").textContent = STATS.cleanRoundTrips;
}
function setControlState(open) {
  ["btn-upload","btn-list","btn-run","btn-trigger-leak","btn-destroy"].forEach(id => $(id).disabled = !open);
  $("btn-open").disabled = open;
}
function setStreamStatus(text, live) {
  $("stream-status").textContent = text;
  $("stream-status-2").textContent = text;
  $("stream-status-2").classList.toggle("live", !!live);
  $("session-info").classList.toggle("connected", !!live);
}

// === friendly copy ===
const FRIENDLY = {
  "session.creating":   { icon:"🔐", level:"info",    label: e => "Creating a secure session" },
  "session.created":    { icon:"✅", level:"ok",      label: e => "Secure session ready",
                          sub: e => e.session_id ? e.session_id.slice(0,20)+"…" : "" },
  "session.destroying": { icon:"🔥", level:"warn",    label: e => "Burning the vault — token map about to be unrecoverable" },
  "session.destroyed":  { icon:"💥", level:"ok",      label: e => "Vault destroyed — your data can never be re-linked" },
  "document.uploading": { icon:"📤", level:"working", label: e => "Encrypting your document",
                          sub: e => `${e.data.bytes||0} bytes · ${e.data.mime||""}` },
  "document.uploaded":  { icon:"📄", level:"ok",      label: e => "Document encrypted at rest (AES-256-GCM)",
                          sub: e => e.data.document_id ? `id: ${e.data.document_id.slice(0,8)}…` : "" },
  "document.listing":   { icon:"🔍", level:"working", label: e => "Looking up your documents" },
  "document.listed":    { icon:"📚", level:"ok",      label: e => `Found ${e.data.count} document(s)` },
  "document.deleting":  { icon:"🗑️", level:"warn",    label: e => "Deleting document" },
  "document.deleted":   { icon:"🧹", level:"ok",      label: e => "Document deleted from encrypted store" },
  "pipeline.started":   { icon:"🚀", level:"info",    label: e => "Starting secure processing",
                          sub: e => `${e.data.chars||0} characters` },
  "pipeline.detecting": { icon:"🔬", level:"working", label: e => "Scanning for sensitive data",
                          sub: e => `${e.data.chars} chars · ${e.data.chunks} chunk(s)` },
  "pipeline.detected":  { icon:"🎯", level:"ok",      label: e => `Found ${e.data.entities_count} sensitive item(s)`,
                          sub: e => Object.entries(e.data.by_type||{}).map(([k,v])=>`${k.replace(/^(PII|PHI|FIN|LEG)_/,"")}:${v}`).join(" · ") },
  "pipeline.obfuscated":{ icon:"🛡️", level:"ok",      label: e => `Replaced ${e.data.tokens_count} item(s) with secure tokens`,
                          sub: e => `strategy: ${e.data.strategy}` },
  "pipeline.gate_checking":{ icon:"🚦", level:"working", label: e => "Checking outbound payload for leaks",
                             sub: e => `${e.data.payload_chars||0} chars to scan` },
  "pipeline.gate_passed":  { icon:"🟢", level:"ok",   label: e => "Leak check passed — nothing sensitive leaving" },
  "pipeline.gate_aborted": { icon:"🚨", level:"err",  label: e => `LEAK CAUGHT — call aborted before reaching AI`,
                             sub: e => `${e.data.entity_type} detected at ${e.data.stage}` },
  "pipeline.llm_calling":  { icon:"🤖", level:"working", label: e => "Asking the AI (sees tokens only, no PII)",
                             sub: e => `provider: ${e.data.provider}` },
  "pipeline.llm_responded":{ icon:"💬", level:"ok",   label: e => `AI responded`,
                             sub: e => `${Math.round(e.data.duration_ms)} ms · ${e.data.chars} chars` },
  "pipeline.restoring":    { icon:"🔓", level:"working", label: e => "Restoring real values from the vault" },
  "pipeline.restored":     { icon:"📜", level:"ok",   label: e => `Restored ${e.data.tokens_restored} token(s) to original values` },
  "pipeline.completed":    { icon:"✨", level:"ok",   label: e => "Secure round trip complete — 0 PII left your data",
                             sub: e => `${Math.round(e.data.duration_ms)} ms total` },
  "pipeline.failed":       { icon:"❌", level:"err",  label: e => `Pipeline failed: ${e.data.message}` },
  "error":                 { icon:"⚠️", level:"err",  label: e => `${e.data.op}: ${e.data.message}`,
                             sub: e => e.data.kind },
};

function addTimelineEvent(env) {
  const f = FRIENDLY[env.type] || { icon:"•", level:"info", label: () => env.type };
  if (env.type === "session.created") STATS.sessions++;
  if (env.type === "pipeline.gate_aborted") STATS.leaksCaught++;
  if (env.type === "pipeline.completed") STATS.cleanRoundTrips++;
  refreshStats();
  $("tl-empty").style.display = "none";
  const li = document.createElement("li");
  li.className = "tl-item lvl-" + f.level;
  const time = new Date(env.ts * 1000).toLocaleTimeString([], {hour12:false});
  const sub = f.sub ? f.sub(env) : "";
  li.innerHTML =
    `<span class="tl-icon">${f.icon}</span>` +
    `<span><span class="tl-text">${esc(f.label(env))}</span>${sub ? `<span class="tl-sub">${esc(sub)}</span>` : ""}</span>` +
    `<span class="tl-time">${time}</span>`;
  $("timeline").prepend(li);
  while ($("timeline").children.length > 200) $("timeline").lastChild.remove();
}
function clearTimeline() { $("timeline").innerHTML = ""; $("tl-empty").style.display = "block"; }

// === SSE ===
function startEventStream(sid) {
  if (STATE.es) { STATE.es.close(); STATE.es = null; }
  const q = new URLSearchParams({ session_id: sid });
  if (apiKey()) q.set("api_key", apiKey());
  const es = new EventSource("/events?" + q.toString());
  STATE.es = es;
  es.onopen = () => setStreamStatus("● live", true);
  es.onerror = () => setStreamStatus("● reconnecting…", false);
  es.onmessage = msg => { try { addTimelineEvent(JSON.parse(msg.data)); } catch {} };
}

async function health(){
  try {
    const r = await fetch("/health");
    const j = await r.json();
    $("backend").innerHTML = `backend <b>${j.llm_backend}</b>`;
  } catch { $("backend").innerHTML = "backend <b style='color:var(--err)'>unreachable</b>"; }
}

// === actions ===
$("btn-open").onclick = async () => {
  setErr("");
  try {
    const r = await fetch("/sessions", { method:"POST", headers: baseHeaders(),
      body: JSON.stringify({ user_id: userId() }) });
    if (!r.ok) throw new Error(`POST /sessions → ${r.status} ${await r.text()}`);
    const j = await r.json();
    STATE.sessionId = j.session_id;
    sessionStorage.setItem("scp.session", j.session_id);
    $("session-id").textContent = j.session_id;
    $("doc-id").textContent = "(none)";
    clearTimeline();
    startEventStream(j.session_id);
    setControlState(true);
  } catch (e) { setErr(e.message); }
};

$("btn-upload").onclick = async () => {
  setErr("");
  try {
    const blob = new Blob([$("doc").value], { type:"text/plain" });
    const fd = new FormData();
    fd.append("user_id", userId());
    fd.append("session_id", STATE.sessionId);
    fd.append("file", blob, "sample.txt");
    const headers = apiKey() ? { "X-API-Key": apiKey() } : {};
    const r = await fetch("/documents", { method:"POST", headers, body: fd });
    if (!r.ok) throw new Error(`POST /documents → ${r.status} ${await r.text()}`);
    const j = await r.json();
    $("doc-id").textContent = j.document_id.slice(0,8) + "…";
  } catch (e) { setErr(e.message); }
};

$("btn-list").onclick = async () => {
  setErr("");
  try {
    const q = new URLSearchParams({ user_id: userId(), session_id: STATE.sessionId });
    const r = await fetch("/documents?" + q.toString(), { headers: baseHeaders() });
    if (!r.ok) throw new Error(`GET /documents → ${r.status} ${await r.text()}`);
    const j = await r.json();
    $("docs-list").innerHTML = j.documents.length
      ? j.documents.map(d => `<li>${d.document_id.slice(0,8)}… · ${d.bytes} bytes · ${esc(d.mime_type)}</li>`).join("")
      : "<li class='muted'>No documents yet — upload one above.</li>";
  } catch (e) { setErr(e.message); }
};

$("btn-run").onclick = async () => {
  setErr("");
  ["p-sent","p-raw","p-restored"].forEach(id => $(id).textContent = "");
  $("p-original").innerHTML = esc($("doc").value);
  $("runstats").innerHTML = "";
  try {
    const body = JSON.stringify({
      user_id: userId(), session_id: STATE.sessionId,
      text: $("doc").value, user_query: $("query").value,
      strategy: $("strategy").value || null,
    });
    const r = await fetch("/run", { method:"POST", headers: baseHeaders(), body });
    const t = await r.text();
    if (!r.ok) throw new Error(`POST /run → ${r.status} ${t}`);
    const j = JSON.parse(t);
    $("p-sent").innerHTML = highlightTokens(esc(j.obfuscated_preview));
    $("p-raw").innerHTML = highlightTokens(esc(j.llm_raw_response));
    $("p-restored").innerHTML = esc(j.restored_response);
    $("runstats").innerHTML =
      `<span>detected <b>${j.entities_detected}</b></span>` +
      `<span>obfuscated <b>${j.entities_obfuscated}</b></span>` +
      `<span>restored <b>${j.tokens_restored}</b></span>` +
      `<span><b>${j.pipeline_duration_ms.toFixed(1)}</b> ms</span>`;
  } catch (e) { setErr(e.message); }
};

// The user_query is concatenated into the outbound payload without being
// obfuscated — it represents a question the user typed about their data.
// Sticking raw PII into the question is exactly the accidental-leak scenario
// the residual leak gate exists to catch. Sending one here lets the user
// *watch* the gate fire and stop the call before any data reaches the AI.
$("btn-trigger-leak").onclick = async () => {
  setErr("");
  const body = JSON.stringify({
    user_id: userId(), session_id: STATE.sessionId,
    text: "Routine quarterly summary.",
    user_query: "Please email the report to the holder at SSN 412-55-9981.",
  });
  try {
    const r = await fetch("/run", { method:"POST", headers: baseHeaders(), body });
    if (r.status === 422) return;  // expected — gate aborted, see the timeline
    const t = await r.text();
    if (!r.ok) throw new Error(`POST /run → ${r.status} ${t}`);
    // If it didn't 422, the user's environment caught it elsewhere — surface that:
    setErr("Leak gate did not fire (expected 422). Detector may have caught it pre-gate.");
  } catch (e) { setErr(e.message); }
};

$("btn-destroy").onclick = async () => {
  setErr("");
  try {
    const q = new URLSearchParams({ user_id: userId() });
    const r = await fetch(`/sessions/${encodeURIComponent(STATE.sessionId)}?` + q.toString(),
      { method:"DELETE", headers: baseHeaders() });
    if (!r.ok) throw new Error(`DELETE /sessions → ${r.status} ${await r.text()}`);
    // Let the destroyed event arrive over SSE, then tear down the client side.
    setTimeout(() => {
      if (STATE.es) { STATE.es.close(); STATE.es = null; }
      STATE.sessionId = null;
      sessionStorage.removeItem("scp.session");
      $("session-id").textContent = "(none)";
      $("doc-id").textContent = "(none)";
      setStreamStatus("offline", false);
      setControlState(false);
    }, 700);
  } catch (e) { setErr(e.message); }
};

document.querySelectorAll(".samples button").forEach(b =>
  b.addEventListener("click", () => { $("doc").value = SAMPLES[b.dataset.s]; }));

// === restore on reload ===
(function restore() {
  const sid = sessionStorage.getItem("scp.session");
  if (sid) {
    STATE.sessionId = sid;
    $("session-id").textContent = sid;
    startEventStream(sid);
    setControlState(true);
  }
  $("doc").value = SAMPLES.medical;
  health();
})();
</script>
</body>
</html>
"""
