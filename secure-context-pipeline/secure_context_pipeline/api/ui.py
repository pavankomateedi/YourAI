"""Self-contained demo UI — premium "Swiss-bank-grade custody" framing.

Single HTML/CSS/JS document served at ``GET /ui``. Walks the full lifecycle in
plain English (open vault → deposit a document → send to AI → close vault),
shows the trust boundary as four restful panels, and narrates every step in a
right-hand **custody ledger** powered by SSE. Hides developer fields behind a
collapsible settings panel and avoids jargon in the main flow.
"""

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>YourAI Vault — Secure File Transfer for AI</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600&family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#070905; --panel:#10140c; --panel-2:#171c12; --border:#2a311e;
    --border-soft:#1f2418;
    --text:#eef0e5; --muted:#9aa087; --muted-2:#6c7458;
    --olive:#9bb04a; --olive-deep:#6e8035; --olive-soft:rgba(155,176,74,.12);
    --cream:#d4c79a; --cream-soft:rgba(212,199,154,.10);
    --ok:#7fbf3f; --warn:#d2a922; --err:#e26b65; --working:#9bb04a;
    --radius:10px;
    --shadow: 0 1px 0 rgba(255,255,255,.03) inset, 0 18px 60px rgba(0,0,0,.55);
  }
  * { box-sizing:border-box; }
  body { margin:0; background:
    radial-gradient(1200px 600px at 80% -20%, rgba(155,176,74,.07), transparent 60%),
    radial-gradient(900px 600px at -10% 30%, rgba(212,199,154,.04), transparent 60%),
    var(--bg);
    color:var(--text);
    font:15px/1.62 "Manrope",ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    -webkit-font-smoothing:antialiased; }
  h1, h2.serif { font-family:"Fraunces",Georgia,serif; font-weight:500;
    letter-spacing:-.01em; font-optical-sizing:auto; }

  /* HEADER */
  header { padding:18px 32px; border-bottom:1px solid var(--border-soft);
    display:flex; align-items:center; gap:18px; flex-wrap:wrap;
    background:linear-gradient(180deg,rgba(16,20,12,.92),rgba(7,9,5,0)); }
  .brand { display:flex; align-items:center; gap:10px; }
  .brand .crest { font-size:22px; }
  .brand h1 { font-size:22px; margin:0; }
  .brand .tagline { color:var(--muted); font-size:12.5px; margin-left:14px; letter-spacing:.02em; }
  .hdr-stats { margin-left:auto; display:flex; gap:24px; font-size:12px; color:var(--muted); align-items:center; }
  .hdr-stats b { color:var(--text); font-size:15px; margin-left:6px; }
  .hdr-stats .sep { width:1px; height:18px; background:var(--border); }
  #cog { background:none; border:1px solid var(--border); color:var(--muted-2); border-radius:8px;
    width:34px; height:34px; cursor:pointer; position:relative; }
  #cog:hover { color:var(--text); border-color:var(--border); }
  #cog.needs-key::after { content:""; position:absolute; top:-3px; right:-3px;
    width:9px; height:9px; border-radius:50%; background:var(--err);
    box-shadow:0 0 0 2px var(--bg); animation:pulse 1.6s infinite; }

  /* SETTINGS DRAWER */
  #settings { display:none; padding:18px 32px; border-bottom:1px solid var(--border-soft);
    background:var(--panel); }
  #settings.open { display:block; }
  #settings .row { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; max-width:980px; }
  @media (max-width:780px){ #settings .row { grid-template-columns:1fr; } }

  /* LAYOUT */
  main { display:grid; grid-template-columns: minmax(0,1.85fr) minmax(0,.65fr); gap:0;
    min-height:calc(100vh - 70px); }
  @media (max-width:1080px){ main { grid-template-columns:1fr; } }
  .left { padding:34px 40px; border-right:1px solid var(--border-soft); overflow:auto; }
  .right { padding:30px 28px; overflow:auto;
    background:linear-gradient(180deg,var(--panel),rgba(7,9,5,.55)); }

  /* CARDS / TYPOGRAPHY */
  .lead { color:var(--muted); font-size:14px; max-width:64ch; margin:0 0 18px; }
  .section { margin:28px 0; }
  .section > h2 { font-size:20px; margin:0 0 4px; }
  .section > h2 small { color:var(--muted); font-size:12px; font-family:Manrope,sans-serif;
    font-weight:500; margin-left:10px; letter-spacing:.04em; text-transform:uppercase; }
  .section > .hint { color:var(--muted); font-size:13px; margin:0 0 14px; }

  /* CONTROLS */
  label.field { display:flex; flex-direction:column; gap:5px;
    font-size:11.5px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }
  input, textarea, select, button {
    background:var(--panel); color:var(--text); border:1px solid var(--border);
    border-radius:8px; padding:11px 13px; font:inherit; }
  input:focus, textarea:focus, select:focus { outline:none; border-color:var(--olive); }
  textarea { width:100%; min-height:160px; resize:vertical; font-size:13.5px;
    line-height:1.55; font-family:"Manrope",sans-serif; }
  button { cursor:pointer; transition:transform .04s ease, border-color .15s, color .15s, background .15s; }
  button:active { transform:translateY(1px); }
  button:disabled { opacity:.4; cursor:not-allowed; }
  button.primary { background:var(--olive); border-color:var(--olive); color:#1a1303;
    font-weight:600; padding:13px 22px; font-size:14.5px; }
  button.primary:hover:not(:disabled) { background:#b6cd5e; }
  button.ghost { background:transparent; color:var(--text); }
  button.ghost:hover:not(:disabled) { border-color:var(--olive); color:var(--olive); }
  button.danger { background:transparent; border-color:#5a2a2a; color:#ff7b72; }
  button.danger:hover:not(:disabled) { background:rgba(255,123,114,.08); }
  button.linkish { background:none; border:none; color:var(--cream); padding:4px 0; }

  /* VAULT STATUS HERO */
  .hero { background:var(--panel); border:1px solid var(--border); border-radius:14px;
    padding:24px 26px; box-shadow:var(--shadow); display:flex; align-items:center; gap:22px; flex-wrap:wrap; }
  .hero .lock { font-size:34px; }
  .hero .copy { flex:1; min-width:240px; }
  .hero h2 { margin:0; font-size:19px; font-family:Fraunces,Georgia,serif; }
  .hero p { margin:4px 0 0; color:var(--muted); font-size:13.5px; }
  .hero.open  { border-color:rgba(63,185,80,.4); }
  .hero.open  .lock { color:var(--ok); }

  /* SAMPLE CARDS */
  .samples { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }
  @media (max-width:680px){ .samples { grid-template-columns:1fr; } }
  .sample { background:var(--panel-2); border:1px solid var(--border); border-radius:10px;
    padding:16px; display:flex; flex-direction:column; gap:8px; }
  .sample h3 { margin:0; font-size:15px; }
  .sample p { margin:0; color:var(--muted); font-size:12.5px; }
  .sample .actions { display:flex; gap:8px; margin-top:6px; }
  .sample button { padding:7px 10px; font-size:12.5px; }

  /* FILE PICKER */
  .filepick { background:var(--panel-2); border:1.5px dashed var(--border);
    border-radius:10px; padding:18px 18px; display:flex; align-items:center;
    gap:14px; flex-wrap:wrap; }
  .filepick input[type=file] { color:var(--muted); }
  .filepick .or { color:var(--muted-2); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }

  /* PANELS */
  .panels { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
  @media (max-width:720px){ .panels { grid-template-columns:1fr; } }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  .card h3 { font-size:11px; text-transform:uppercase; letter-spacing:.08em;
    margin:0; padding:11px 14px; border-bottom:1px solid var(--border-soft);
    color:var(--muted); display:flex; align-items:center; gap:8px; font-weight:600; }
  .card .desc { color:var(--muted-2); font-size:11px; padding:7px 14px 0; }
  .card .body { padding:14px; white-space:pre-wrap; word-break:break-word;
    font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12.5px; min-height:70px;
    color:#dde3ee; }
  .card.boundary { border-color:rgba(90,147,255,.35); }
  .card.boundary h3 { color:var(--cream); }
  .badge { font-size:9.5px; padding:2px 7px; border-radius:10px;
    border:1px solid var(--border); color:var(--muted-2); text-transform:uppercase; letter-spacing:.06em; }
  .badge.leaves { background:var(--cream-soft); color:var(--cream); border-color:rgba(212,199,154,.45); }
  .tok { color:var(--olive); background:var(--olive-soft); border-radius:3px; padding:0 2px; }
  .runstats { display:flex; gap:20px; flex-wrap:wrap; margin-top:14px; color:var(--muted); font-size:12.5px; }
  .runstats b { color:var(--text); font-size:14px; }

  /* DOCS LIST */
  #docs-list { list-style:none; padding:0; margin:10px 0 0; max-height:160px; overflow:auto; }
  #docs-list li { padding:8px 10px; border:1px solid var(--border-soft); border-radius:6px;
    margin-bottom:5px; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; color:var(--muted); }

  /* FOOTER ACTIONS */
  .footer-actions { margin-top:30px; padding-top:20px; border-top:1px dashed var(--border-soft);
    display:flex; gap:10px; flex-wrap:wrap; }

  /* RIGHT: CUSTODY LEDGER */
  .right h2 { font-size:20px; margin:0; }
  .ledger-intro { background:var(--panel); border:1px solid var(--border); border-radius:10px;
    padding:14px 16px; margin:12px 0 20px; color:var(--muted); font-size:13px; line-height:1.55; }
  .ledger-intro b { color:var(--text); font-weight:600; }
  .stream-status { font-size:12px; color:var(--muted); margin-left:10px; }
  .stream-status.live { color:var(--ok); }
  .stream-status::before { content:"●  "; color:currentColor; }

  #timeline { list-style:none; padding:0; margin:0; position:relative; }
  #timeline::before { content:""; position:absolute; left:13px; top:6px; bottom:6px;
    width:1px; background:linear-gradient(180deg,var(--border),transparent); }
  .tl-item { position:relative; padding:12px 14px 12px 42px; margin-bottom:10px;
    border-radius:10px; background:var(--panel-2); border:1px solid var(--border-soft);
    display:grid; grid-template-columns: 1fr auto; gap:10px; align-items:center;
    animation: slideIn .25s ease-out; }
  @keyframes slideIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }
  .tl-item .tl-icon { position:absolute; left:5px; top:50%; transform:translateY(-50%);
    width:26px; height:26px; border-radius:50%; background:var(--panel);
    display:flex; align-items:center; justify-content:center; font-size:14px;
    border:1.5px solid var(--border); }
  .tl-text { font-size:14px; color:var(--text); }
  .tl-sub { display:block; color:var(--muted); font-size:12px; margin-top:3px; font-style:normal; }
  .tl-time { color:var(--muted-2); font-size:11px; font-family:Consolas,monospace; }
  .lvl-ok       { border-color:rgba(63,185,80,.32); }
  .lvl-ok .tl-icon       { border-color:var(--ok); }
  .lvl-info     { }
  .lvl-working  { border-color:rgba(90,147,255,.35); }
  .lvl-working .tl-icon  { border-color:var(--working); animation: pulse 1.6s infinite; }
  @keyframes pulse { 50% { box-shadow:0 0 0 3px rgba(155,176,74,.22); } }
  .lvl-warn     { border-color:rgba(210,153,34,.4); }
  .lvl-warn .tl-icon     { border-color:var(--warn); }
  .lvl-err      { border-color:rgba(241,93,87,.5); background:rgba(241,93,87,.06); }
  .lvl-err .tl-icon      { border-color:var(--err); }
  .lvl-vault    { border-color:rgba(196,166,97,.4); }
  .lvl-vault .tl-icon { border-color:var(--olive); }
  .tl-empty { color:var(--muted-2); font-size:13px; padding:20px 0; text-align:center;
    border:1px dashed var(--border-soft); border-radius:8px; }

  .legend { display:flex; gap:14px; flex-wrap:wrap; margin-top:20px; color:var(--muted); font-size:12px; }
  .legend .item { display:inline-flex; align-items:center; gap:6px; }
  .legend .dot { width:10px; height:10px; border-radius:50%; border:1.5px solid currentColor; }

  .err { color:var(--err); margin:12px 0; white-space:pre-wrap; font-size:13.5px; min-height:1em; }

  details.tech summary { cursor:pointer; color:var(--muted); font-size:12px; }
</style>
</head>
<body>

<header>
  <div class="brand">
    <span class="crest">🔒</span>
    <h1>YourAI Vault</h1>
    <span class="tagline">Swiss-bank-grade custody · for documents you share with AI</span>
  </div>
  <div class="hdr-stats">
    <span>Sessions opened <b id="stat-sessions">0</b></span>
    <span class="sep"></span>
    <span>Leaks caught <b id="stat-leaks">0</b></span>
    <span class="sep"></span>
    <span>Clean transfers <b id="stat-rt">0</b></span>
    <span class="sep"></span>
    <span id="backend">backend …</span>
    <button id="cog" title="Settings">⚙</button>
  </div>
</header>

<!-- SETTINGS DRAWER -->
<div id="settings">
  <div class="row">
    <label class="field">Vault access key
      <input id="apikey" type="password" placeholder="enter your access key" />
    </label>
    <label class="field">Customer reference
      <input id="userid" type="text" value="demo-customer" />
    </label>
    <label class="field">Protection mode
      <select id="strategy">
        <option value="">Default · tokenize identifiers</option>
        <option value="tokenization">Tokenize everything</option>
        <option value="pseudonymization">Pseudonymize names & addresses</option>
      </select>
    </label>
  </div>
  <p style="color:var(--muted-2); font-size:12px; margin:12px 0 0;">Your vault access key is the credential that unlocks this service. It's stored only in this browser session and sent over the wire as a header. Customer reference is used to derive your per-customer encryption key.</p>
</div>

<main>

  <section class="left">

    <p class="lead">A private vault for the documents you want to ask AI about — medical records, legal files, financial disclosures. Your data is sealed before it ever leaves us. The AI sees only protected references; the originals stay in custody and are restored just for you.</p>

    <!-- HERO / VAULT STATUS -->
    <div id="hero" class="hero">
      <div class="lock" id="hero-lock">🔒</div>
      <div class="copy">
        <h2 id="hero-title">Vault is closed</h2>
        <p id="hero-sub">Open a private vault to begin a secure transfer. Each session is isolated and encrypted with its own key — destroyed on close.</p>
      </div>
      <button id="btn-open" class="primary">Open vault</button>
      <button id="btn-destroy" class="danger" disabled>Close vault</button>
    </div>

    <div class="err" id="err"></div>

    <!-- STEP 1: CHOOSE DOCUMENT -->
    <section class="section">
      <h2 class="serif">① Choose a document <small>that you'd like to share with the AI</small></h2>
      <p class="hint">Try one of our synthetic samples or upload your own file. Everything happens in your private vault.</p>

      <div class="samples">
        <div class="sample">
          <h3>📋 Medical record</h3>
          <p>A patient visit summary with diagnosis, medications, MRN, insurance, and contact details.</p>
          <div class="actions">
            <button class="ghost" data-sample="medical" data-mode="compose">Use this</button>
            <button class="linkish" data-sample="medical" data-mode="download">Download .txt</button>
          </div>
        </div>
        <div class="sample">
          <h3>⚖️ Legal case file</h3>
          <p>Attorney work product with client identity, strategy, and settlement posture.</p>
          <div class="actions">
            <button class="ghost" data-sample="legal" data-mode="compose">Use this</button>
            <button class="linkish" data-sample="legal" data-mode="download">Download .txt</button>
          </div>
        </div>
        <div class="sample">
          <h3>💼 Financial disclosure</h3>
          <p>Wealth-advisor disclosure with account, tax ID, income, and transaction notes.</p>
          <div class="actions">
            <button class="ghost" data-sample="financial" data-mode="compose">Use this</button>
            <button class="linkish" data-sample="financial" data-mode="download">Download .txt</button>
          </div>
        </div>
      </div>

      <div class="filepick" style="margin-top:14px;">
        <span class="or">Or upload</span>
        <input id="file" type="file" accept=".txt,.pdf,.docx,text/plain,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" disabled />
        <button id="btn-deposit" class="ghost" disabled>Deposit in vault</button>
        <span class="hint" id="deposit-status"></span>
      </div>

      <details style="margin-top:18px;">
        <summary class="ghost" style="cursor:pointer; color:var(--muted); font-size:12px;">Or compose / edit text directly</summary>
        <label class="field" style="margin-top:10px;">Document text</label>
        <textarea id="doc" placeholder="Paste or type a document here…"></textarea>
      </details>
    </section>

    <!-- STEP 2: ASK -->
    <section class="section">
      <h2 class="serif">② What would you like the AI to do? <small>your question is sent with the protected document</small></h2>
      <input id="query" type="text" style="width:100%;" value="Summarize this document for me." />
    </section>

    <!-- STEP 3: SEND -->
    <section class="section">
      <h2 class="serif">③ Send to AI safely</h2>
      <p class="hint">We'll seal the sensitive parts, run a leak check, ask the AI, and restore the answer for you.</p>
      <button id="btn-run" class="primary" disabled>🤖 Send to AI safely</button>
      <button id="btn-list" class="ghost" disabled style="margin-left:8px;">List my deposits</button>
      <ul id="docs-list"></ul>
    </section>

    <!-- RESULT PANELS -->
    <section class="section" id="result-section" style="display:none;">
      <h2 class="serif">④ What happened on the wire <small>same data, four moments in time</small></h2>
      <p class="hint">From left-to-right, top-to-bottom: your original, the protected version that left for the AI, the AI's reply (still in protected form), and the version restored for you.</p>
      <div class="panels">
        <div class="card">
          <h3>① Your document <span class="badge">stays in vault</span></h3>
          <div class="desc">The original you provided. Never leaves the vault.</div>
          <div class="body" id="p-original"></div>
        </div>
        <div class="card boundary">
          <h3>② What the AI sees <span class="badge leaves">crosses to AI →</span></h3>
          <div class="desc">Sensitive parts replaced with secure references. Zero recoverable PII.</div>
          <div class="body" id="p-sent"></div>
        </div>
        <div class="card">
          <h3>③ AI's reply <span class="badge">before restore</span></h3>
          <div class="desc">The AI answered using the references; we'll restore them next.</div>
          <div class="body" id="p-raw"></div>
        </div>
        <div class="card">
          <h3>④ Restored for you <span class="badge">shown to you</span></h3>
          <div class="desc">References swapped back to their real values, just for you.</div>
          <div class="body" id="p-restored"></div>
        </div>
      </div>
      <div class="runstats" id="runstats"></div>
    </section>

    <!-- FOOTER ACTIONS -->
    <div class="footer-actions">
      <button id="btn-trigger-leak" class="ghost" disabled title="Sends raw PII in your question (not the document) — the leak gate should catch it before any data leaves.">Test the safety mechanism</button>
    </div>
  </section>


  <aside class="right">
    <h2 class="serif">📒 Custody ledger <span class="stream-status" id="stream-status-2">closed</span></h2>

    <div class="ledger-intro">
      <b>What you're seeing.</b> Every step of your transfer is recorded here in real time — opening the vault, sealing the document, the safety check, asking the AI, and unsealing the reply for you. This ledger is your <i>proof</i> that no original data ever crossed to the AI.
    </div>

    <ul id="timeline"></ul>
    <p class="tl-empty" id="tl-empty">Open the vault to start the ledger.</p>

    <div class="legend">
      <span class="item"><span class="dot" style="color:var(--ok)"></span> Done</span>
      <span class="item"><span class="dot" style="color:var(--working)"></span> In progress</span>
      <span class="item"><span class="dot" style="color:var(--olive)"></span> Vault event</span>
      <span class="item"><span class="dot" style="color:var(--err)"></span> Stopped / error</span>
    </div>
  </aside>

</main>

<script>
const $ = id => document.getElementById(id);
const esc = s => (s||"").replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const highlightTokens = s => (s||"").replace(/\[[A-Z]+_[A-Z]+_[0-9a-f]{8}\]/g,
  m => '<span class="tok">'+m+'</span>');

const STATE = { sessionId: null, es: null, lastDocId: null, lastFile: null };
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
function setVaultState(open) {
  $("hero").classList.toggle("open", open);
  $("hero-lock").textContent = open ? "🔓" : "🔒";
  $("hero-title").textContent = open ? "Vault is open" : "Vault is closed";
  $("hero-sub").textContent = open
    ? "Your secure session is active. Add a document and send it to the AI when ready."
    : "Open a private vault to begin a secure transfer. Each session is isolated and encrypted with its own key — destroyed on close.";
  $("btn-open").disabled = open;
  $("btn-destroy").disabled = !open;
  ["file","btn-deposit","btn-run","btn-list","btn-trigger-leak"].forEach(id => $(id).disabled = !open);
}
function setStreamStatus(text, live) {
  $("stream-status-2").textContent = text;
  $("stream-status-2").classList.toggle("live", !!live);
}

// === FRIENDLY copy + plain-English explanations ===
const FRIENDLY = {
  "session.creating":   { icon:"🔑", level:"vault",   label: e => "Cutting a fresh vault key",
                          sub: e => "A unique encryption key is generated just for this session." },
  "session.created":    { icon:"🏛️", level:"vault",   label: e => "Private vault opened",
                          sub: e => "Only you (and this browser tab) can use this vault." },
  "session.destroying": { icon:"🔥", level:"warn",    label: e => "Sealing and burning the vault",
                          sub: e => "The token-to-original map is about to be destroyed." },
  "session.destroyed":  { icon:"💥", level:"vault",   label: e => "Vault destroyed — keys are gone forever",
                          sub: e => "Nothing in this session can ever be re-linked to originals." },
  "document.uploading": { icon:"📤", level:"working", label: e => "Encrypting your document for deposit",
                          sub: e => `AES-256-GCM · ${e.data.bytes||0} bytes` },
  "document.uploaded":  { icon:"📥", level:"vault",   label: e => "Document deposited in the vault",
                          sub: e => `Stored under reference ${e.data.document_id?.slice(0,8)}…` },
  "document.listing":   { icon:"🔍", level:"working", label: e => "Looking up your deposits" },
  "document.listed":    { icon:"📚", level:"ok",      label: e => `Found ${e.data.count} document(s) in your vault` },
  "document.deleting":  { icon:"🗑️", level:"warn",    label: e => "Removing a deposit" },
  "document.deleted":   { icon:"🧹", level:"ok",      label: e => "Document removed from the vault" },
  "pipeline.started":   { icon:"🚀", level:"info",    label: e => "Starting a secure transfer to the AI",
                          sub: e => `${e.data.chars||0} characters of source material` },
  "pipeline.detecting": { icon:"🔬", level:"working", label: e => "Scanning the document for sensitive parts",
                          sub: e => `${e.data.chars} chars · ${e.data.chunks} block(s)` },
  "pipeline.detected":  { icon:"🎯", level:"ok",      label: e => `Spotted ${e.data.entities_count} sensitive item(s)`,
                          sub: e => Object.entries(e.data.by_type||{}).map(([k,v]) => `${k.replace(/^(PII|PHI|FIN|LEG)_/,"")}: ${v}`).join("  ·  ") },
  "pipeline.obfuscated":{ icon:"🛡️", level:"ok",      label: e => `Sealed ${e.data.tokens_count} item(s) with secure references`,
                          sub: e => `Originals stay in the vault; the AI will see references only.` },
  "pipeline.gate_checking":{ icon:"🚦", level:"working", label: e => "Final safety check before sending",
                             sub: e => `Scanning ${e.data.payload_chars||0} chars for any raw identifiers.` },
  "pipeline.gate_passed":  { icon:"🟢", level:"ok",   label: e => "Safety check passed",
                             sub: e => "No recoverable PII detected — clear to send." },
  "pipeline.gate_aborted": { icon:"🚨", level:"err",  label: e => "Leak caught — transfer aborted",
                             sub: e => `Detected raw ${e.data.entity_type} before it reached the AI. Nothing left the vault.` },
  "pipeline.llm_calling":  { icon:"🤖", level:"working", label: e => "Asking the AI safely",
                             sub: e => `The AI receives only references — no original PII. (${e.data.provider})` },
  "pipeline.llm_responded":{ icon:"💬", level:"ok",   label: e => "AI responded",
                             sub: e => `${Math.round(e.data.duration_ms)} ms · ${e.data.chars} chars (still references)` },
  "pipeline.restoring":    { icon:"🔓", level:"working", label: e => "Restoring originals from the vault",
                             sub: e => "Reading the encrypted map and swapping references back, just for you." },
  "pipeline.restored":     { icon:"📜", level:"ok",   label: e => `Restored ${e.data.tokens_restored} reference(s) to originals` },
  "pipeline.completed":    { icon:"✨", level:"ok",   label: e => "Secure transfer complete",
                             sub: e => `${Math.round(e.data.duration_ms)} ms total · zero originals left the vault.` },
  "pipeline.failed":       { icon:"❌", level:"err",  label: e => `Transfer failed`,
                             sub: e => e.data.message },
  "error":                 { icon:"⚠️", level:"err",  label: e => `Could not ${e.data.op}`,
                             sub: e => `${e.data.kind}: ${e.data.message}` },
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
  const t = new Date(env.ts * 1000);
  const time = t.toLocaleTimeString([], { hour12:false });
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
  es.onopen = () => setStreamStatus("live", true);
  es.onerror = () => setStreamStatus("reconnecting…", false);
  es.onmessage = msg => { try { addTimelineEvent(JSON.parse(msg.data)); } catch {} };
}

async function health(){
  try {
    const r = await fetch("/health");
    const j = await r.json();
    $("backend").innerHTML = `backend <b>${j.llm_backend}</b>`;
  } catch { $("backend").innerHTML = "backend <b style='color:var(--err)'>unreachable</b>"; }
}

// === SAMPLES (load into composer or download) ===
async function loadSampleAsText(id) {
  const r = await fetch("/samples/" + encodeURIComponent(id));
  if (!r.ok) throw new Error(`/samples/${id} → ${r.status}`);
  return await r.text();
}
async function loadSampleAsFile(id) {
  const r = await fetch("/samples/" + encodeURIComponent(id));
  if (!r.ok) throw new Error(`/samples/${id} → ${r.status}`);
  const txt = await r.text();
  const cd = r.headers.get("content-disposition") || "";
  const m = cd.match(/filename="([^"]+)"/);
  const name = m ? m[1] : `${id}.txt`;
  return new File([txt], name, { type: "text/plain" });
}
document.querySelectorAll('[data-sample]').forEach(btn => {
  btn.addEventListener("click", async (e) => {
    e.preventDefault();
    const id = btn.dataset.sample;
    const mode = btn.dataset.mode;
    setErr("");
    try {
      if (mode === "compose") {
        const text = await loadSampleAsText(id);
        $("doc").value = text;
        const det = $("doc").closest("details");
        if (det) det.open = true;
        $("deposit-status").textContent = `Sample "${id}" loaded into the composer.`;
      } else if (mode === "download") {
        const text = await loadSampleAsText(id);
        const a = document.createElement("a");
        a.href = "data:text/plain;charset=utf-8," + encodeURIComponent(text);
        a.download = `${id}.txt`;
        document.body.appendChild(a); a.click(); a.remove();
      }
    } catch (e) { setErr(e.message); }
  });
});

// keep selected file
$("file").addEventListener("change", e => {
  STATE.lastFile = e.target.files && e.target.files[0] || null;
  $("deposit-status").textContent = STATE.lastFile
    ? `Selected: ${STATE.lastFile.name} (${STATE.lastFile.size} bytes)` : "";
});

// === actions ===
$("btn-open").onclick = async () => {
  setErr("");
  if (!apiKey()) {
    $("settings").classList.add("open");
    $("apikey").focus();
    setErr("Enter your Vault access key above, then click Open vault. (See the ⚙ panel.)");
    return;
  }
  try {
    const r = await fetch("/sessions", { method:"POST", headers: baseHeaders(),
      body: JSON.stringify({ user_id: userId() }) });
    if (r.status === 401) {
      $("settings").classList.add("open");
      $("apikey").focus();
      throw new Error("That Vault access key was rejected. Check the ⚙ Settings panel and try again.");
    }
    if (!r.ok) throw new Error(`Could not open vault — ${r.status} ${await r.text()}`);
    const j = await r.json();
    STATE.sessionId = j.session_id;
    sessionStorage.setItem("scp.session", j.session_id);
    STATE.lastDocId = null;
    clearTimeline();
    startEventStream(j.session_id);
    setVaultState(true);
  } catch (e) { setErr(e.message); }
};

// Persist the vault key for this browser session so it's not re-typed on every action.
function refreshKeyHint() {
  $("cog").classList.toggle("needs-key", !apiKey());
}
$("apikey").addEventListener("input", () => {
  sessionStorage.setItem("scp.apikey", apiKey());
  refreshKeyHint();
});

$("btn-deposit").onclick = async () => {
  setErr("");
  let file = STATE.lastFile;
  if (!file) {
    // Auto-fallback: build a file from the composer textarea.
    const text = $("doc").value.trim();
    if (!text) {
      setErr("Pick a file (or use a sample / type some text) first.");
      return;
    }
    file = new File([text], "composed.txt", { type:"text/plain" });
  }
  const fd = new FormData();
  fd.append("user_id", userId());
  fd.append("session_id", STATE.sessionId);
  fd.append("file", file, file.name);
  const headers = apiKey() ? { "X-API-Key": apiKey() } : {};
  try {
    const r = await fetch("/documents", { method:"POST", headers, body: fd });
    if (!r.ok) throw new Error(`Deposit failed — ${r.status} ${await r.text()}`);
    const j = await r.json();
    STATE.lastDocId = j.document_id;
    $("deposit-status").textContent = `Deposited ${file.name} (${j.bytes} bytes) — ref ${j.document_id.slice(0,8)}…`;
  } catch (e) { setErr(e.message); }
};

$("btn-list").onclick = async () => {
  setErr("");
  try {
    const q = new URLSearchParams({ user_id: userId(), session_id: STATE.sessionId });
    const r = await fetch("/documents?" + q.toString(), { headers: baseHeaders() });
    if (!r.ok) throw new Error(`List failed — ${r.status} ${await r.text()}`);
    const j = await r.json();
    $("docs-list").innerHTML = j.documents.length
      ? j.documents.map(d => `<li>${d.document_id.slice(0,8)}… · ${d.bytes} bytes · ${esc(d.mime_type)}</li>`).join("")
      : "<li>No deposits yet — upload one above.</li>";
  } catch (e) { setErr(e.message); }
};

$("btn-run").onclick = async () => {
  setErr("");
  $("result-section").style.display = "block";
  ["p-sent","p-raw","p-restored"].forEach(id => $(id).textContent = "");
  $("p-original").innerHTML = esc($("doc").value || (STATE.lastDocId ? "(deposited file — content stays in the vault)" : ""));
  $("runstats").innerHTML = "";
  const composer = $("doc").value.trim();
  const body = {
    user_id: userId(),
    session_id: STATE.sessionId,
    text: composer || null,
    document_id: composer ? null : STATE.lastDocId,
    user_query: $("query").value,
    strategy: $("strategy").value || null,
  };
  if (!body.text && !body.document_id) {
    setErr("Add a document (use a sample, upload a file, or paste text) before sending.");
    return;
  }
  try {
    const r = await fetch("/run", { method:"POST", headers: baseHeaders(), body: JSON.stringify(body) });
    const t = await r.text();
    if (!r.ok) throw new Error(`Transfer failed — ${r.status} ${t}`);
    const j = JSON.parse(t);
    $("p-sent").innerHTML = highlightTokens(esc(j.obfuscated_preview));
    $("p-raw").innerHTML = highlightTokens(esc(j.llm_raw_response));
    $("p-restored").innerHTML = esc(j.restored_response);
    $("runstats").innerHTML =
      `<span>spotted <b>${j.entities_detected}</b></span>` +
      `<span>sealed <b>${j.entities_obfuscated}</b></span>` +
      `<span>restored <b>${j.tokens_restored}</b></span>` +
      `<span><b>${j.pipeline_duration_ms.toFixed(1)}</b> ms total</span>`;
  } catch (e) { setErr(e.message); }
};

$("btn-trigger-leak").onclick = async () => {
  setErr("");
  const body = JSON.stringify({
    user_id: userId(), session_id: STATE.sessionId,
    text: "Routine quarterly summary.",
    user_query: "Please email the report to the holder at SSN 412-55-9981.",
  });
  try {
    const r = await fetch("/run", { method:"POST", headers: baseHeaders(), body });
    if (r.status === 422) return; // expected — gate caught it, see ledger
    const t = await r.text();
    if (!r.ok) throw new Error(`Test request failed — ${r.status} ${t}`);
    setErr("Safety mechanism did not fire (expected 422). The detector may have caught the test value upstream.");
  } catch (e) { setErr(e.message); }
};

$("btn-destroy").onclick = async () => {
  setErr("");
  try {
    const q = new URLSearchParams({ user_id: userId() });
    const r = await fetch(`/sessions/${encodeURIComponent(STATE.sessionId)}?` + q.toString(),
      { method:"DELETE", headers: baseHeaders() });
    if (!r.ok) throw new Error(`Close failed — ${r.status} ${await r.text()}`);
    setTimeout(() => {
      if (STATE.es) { STATE.es.close(); STATE.es = null; }
      STATE.sessionId = null;
      STATE.lastDocId = null;
      sessionStorage.removeItem("scp.session");
      setStreamStatus("closed", false);
      setVaultState(false);
      $("deposit-status").textContent = "";
    }, 700);
  } catch (e) { setErr(e.message); }
};

$("cog").onclick = () => $("settings").classList.toggle("open");

// === restore on reload ===
(function restore() {
  const savedKey = sessionStorage.getItem("scp.apikey");
  if (savedKey) $("apikey").value = savedKey;
  refreshKeyHint();
  // First-run nudge: if no key entered, open the settings drawer so the field
  // is right there. The user doesn't have to hunt for the cog.
  if (!apiKey()) $("settings").classList.add("open");

  const sid = sessionStorage.getItem("scp.session");
  if (sid) {
    STATE.sessionId = sid;
    startEventStream(sid);
    setVaultState(true);
  } else {
    setVaultState(false);
  }
  health();
})();
</script>
</body>
</html>
"""
