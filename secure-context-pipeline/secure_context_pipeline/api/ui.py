"""Self-contained demo UI for the Secure Context Pipeline.

A single-page app served same-origin at ``GET /ui`` (so there is no CORS to
configure). It walks the full round trip and renders the trust boundary:

    Original  ->  Sent to LLM (obfuscated)  ->  LLM raw reply  ->  Restored

The page calls ``POST /sessions`` then ``POST /run`` with whatever ``X-API-Key``
the user enters. Nothing sensitive is embedded here — the key is supplied at
runtime in the browser and only sent back to this same service.
"""

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Secure Context Pipeline — Demo</title>
<style>
  :root {
    --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#e6edf3;
    --muted:#8b949e; --accent:#2f81f7; --danger:#f85149; --ok:#3fb950;
    --token:#d29922; --boundary:#1f6feb;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
    font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:18px 24px; border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
  header h1 { font-size:17px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:12px; }
  #backend { margin-left:auto; font-size:12px; color:var(--muted); }
  #backend b { color:var(--ok); }
  main { padding:20px 24px; max-width:1200px; margin:0 auto; }
  .controls { display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end;
    margin-bottom:16px; }
  .controls label { display:flex; flex-direction:column; gap:4px;
    font-size:12px; color:var(--muted); }
  input, textarea, select, button {
    background:var(--panel); color:var(--text); border:1px solid var(--border);
    border-radius:6px; padding:8px 10px; font:inherit; }
  input:focus, textarea:focus, select:focus { outline:none; border-color:var(--accent); }
  textarea { width:100%; min-height:120px; resize:vertical; font-family:ui-monospace,
    SFMono-Regular,Menlo,Consolas,monospace; font-size:13px; }
  button.primary { background:var(--accent); border-color:var(--accent);
    color:#fff; font-weight:600; cursor:pointer; padding:10px 18px; }
  button.primary:disabled { opacity:.5; cursor:default; }
  button.ghost { cursor:pointer; }
  .samples { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0 0; }
  .samples button { font-size:12px; cursor:pointer; }
  .grid { display:grid; grid-template-columns:repeat(2,1fr); gap:14px; margin-top:18px; }
  @media (max-width:860px){ .grid { grid-template-columns:1fr; } }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:8px;
    overflow:hidden; }
  .card h2 { font-size:12px; text-transform:uppercase; letter-spacing:.05em;
    margin:0; padding:10px 14px; border-bottom:1px solid var(--border);
    color:var(--muted); display:flex; align-items:center; gap:8px; }
  .card .body { padding:14px; white-space:pre-wrap; word-break:break-word;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:13px;
    min-height:80px; }
  .card.boundary { border-color:var(--boundary); }
  .card.boundary h2 { color:var(--boundary); }
  .badge { font-size:10px; padding:2px 7px; border-radius:10px; border:1px solid var(--border);
    color:var(--muted); text-transform:none; letter-spacing:0; }
  .badge.leaves { background:rgba(31,111,235,.15); color:#79c0ff; border-color:#1f6feb; }
  .tok { color:var(--token); background:rgba(210,153,34,.12); border-radius:3px;
    padding:0 2px; }
  .stats { display:flex; gap:18px; flex-wrap:wrap; margin-top:16px;
    color:var(--muted); font-size:13px; }
  .stats b { color:var(--text); font-size:15px; }
  .err { color:var(--danger); margin-top:14px; white-space:pre-wrap; }
  .note { color:var(--muted); font-size:12px; margin-top:6px; }
  .spin { display:inline-block; width:13px; height:13px; border:2px solid var(--muted);
    border-top-color:transparent; border-radius:50%; animation:s .7s linear infinite; }
  @keyframes s { to { transform:rotate(360deg); } }
</style>
</head>
<body>
<header>
  <h1>🔒 Secure Context Pipeline</h1>
  <span class="sub">detect → obfuscate → leak-gate → LLM → de-obfuscate → restore</span>
  <span id="backend">backend: <b>…</b></span>
</header>
<main>
  <div class="controls">
    <label>API key (X-API-Key)
      <input id="apikey" type="password" placeholder="paste service_api_key" size="34" />
    </label>
    <label>User id
      <input id="userid" type="text" value="demo-user" size="14" />
    </label>
    <label>Strategy
      <select id="strategy">
        <option value="">default</option>
        <option value="tokenization">tokenization</option>
        <option value="pseudonymization">pseudonymization</option>
      </select>
    </label>
  </div>

  <label style="font-size:12px;color:var(--muted);">Sensitive document</label>
  <textarea id="doc"></textarea>
  <div class="samples">
    <span class="note">Samples:</span>
    <button class="ghost" data-s="medical">Medical</button>
    <button class="ghost" data-s="legal">Legal</button>
    <button class="ghost" data-s="financial">Financial</button>
    <button class="ghost" data-s="clean">Clean (no PII)</button>
  </div>

  <label style="font-size:12px;color:var(--muted);display:block;margin-top:14px;">Question for the LLM</label>
  <input id="query" type="text" style="width:100%;" value="Summarize this record." />

  <div style="margin-top:16px;">
    <button id="run" class="primary">Run pipeline</button>
    <span id="status" class="note"></span>
  </div>

  <div id="err" class="err"></div>

  <div class="grid">
    <div class="card">
      <h2>① Original <span class="badge">stays inside YourAI</span></h2>
      <div class="body" id="p-original"></div>
    </div>
    <div class="card boundary">
      <h2>② Sent to LLM <span class="badge leaves">crosses trust boundary →</span></h2>
      <div class="body" id="p-sent"></div>
    </div>
    <div class="card">
      <h2>③ LLM raw reply <span class="badge">tokens, pre-restore</span></h2>
      <div class="body" id="p-raw"></div>
    </div>
    <div class="card">
      <h2>④ Restored <span class="badge">shown to user</span></h2>
      <div class="body" id="p-restored"></div>
    </div>
  </div>

  <div class="stats" id="stats"></div>
  <p class="note">The “Sent to LLM” panel is exactly what leaves the trust boundary —
    it contains tokens/pseudonyms only, never recoverable PII. A pre-call leak gate
    aborts (HTTP 422) if any raw identifier is detected in the payload.</p>
</main>

<script>
const SAMPLES = {
  medical: "Patient John Smith (DOB 04/12/1981), MRN 884211, was diagnosed with Type 2 Diabetes Mellitus and prescribed Metformin 500mg twice daily. Contact: john.smith@example.com, (415) 555-0182. Insurance ID BCBS-99812341. Latest HbA1c 7.8%.",
  legal: "Client Maria Gonzalez retained the firm regarding the merger. Litigation strategy: file for summary judgment before the 03/01 deadline. SSN 412-55-9981. Reach her at maria.g@example.com.",
  financial: "Account holder Robert Tan, account 4012 8888 8888 1881, routing via tax ID 47-1234567. Disclosed annual income and a wire of $84,000 to settle the dispute.",
  clean: "The quarterly report shows revenue grew 12% driven by strong demand in the cloud segment. No customer data is included in this summary."
};
const $ = id => document.getElementById(id);
const BASE = ""; // same origin

function highlightTokens(s){
  // [PII_NAME_a3f2c1d4] style tokens
  return (s||"").replace(/\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\]/g,
    m => '<span class="tok">'+m+'</span>');
}
function esc(s){ return (s||"").replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

async function health(){
  try {
    const r = await fetch(BASE+"/health");
    const j = await r.json();
    $("backend").innerHTML = "backend: <b>"+j.llm_backend+"</b> ("+j.model+")";
  } catch(e){ $("backend").innerHTML = "backend: <b style='color:var(--danger)'>unreachable</b>"; }
}

document.querySelectorAll(".samples button").forEach(b =>
  b.onclick = () => { $("doc").value = SAMPLES[b.dataset.s]; });

$("run").onclick = async () => {
  const key = $("apikey").value.trim();
  const headers = { "Content-Type":"application/json" };
  if (key) headers["X-API-Key"] = key;
  $("err").textContent = "";
  $("run").disabled = true;
  $("status").innerHTML = '<span class="spin"></span> running…';
  $("p-original").innerHTML = esc($("doc").value);
  ["p-sent","p-raw","p-restored"].forEach(id => $(id).textContent = "");
  $("stats").innerHTML = "";
  try {
    let r = await fetch(BASE+"/sessions", { method:"POST", headers,
      body: JSON.stringify({ user_id: $("userid").value }) });
    if (!r.ok) throw new Error("POST /sessions → "+r.status+" "+(await r.text()));
    const { session_id } = await r.json();

    r = await fetch(BASE+"/run", { method:"POST", headers, body: JSON.stringify({
      user_id: $("userid").value, session_id,
      text: $("doc").value, user_query: $("query").value,
      strategy: $("strategy").value || null }) });
    const body = await r.text();
    if (!r.ok) throw new Error("POST /run → "+r.status+" "+body);
    const j = JSON.parse(body);

    $("p-sent").innerHTML = highlightTokens(esc(j.obfuscated_preview));
    $("p-raw").innerHTML = highlightTokens(esc(j.llm_raw_response));
    $("p-restored").innerHTML = esc(j.restored_response);
    $("stats").innerHTML =
      "<span>detected <b>"+j.entities_detected+"</b></span>" +
      "<span>obfuscated <b>"+j.entities_obfuscated+"</b></span>" +
      "<span>restored <b>"+j.tokens_restored+"</b></span>" +
      "<span><b>"+j.pipeline_duration_ms.toFixed(1)+"</b> ms</span>";
  } catch(e){
    $("err").textContent = e.message;
  } finally {
    $("run").disabled = false;
    $("status").textContent = "";
  }
};

$("doc").value = SAMPLES.medical;
health();
</script>
</body>
</html>
"""
