/* AI Assistant: ask anything about the compliance system and its live data.
   The browser gathers a compact, privacy-safe snapshot from the other sections
   (counts, ids, rules, findings, signals, incidents: no names, emails, phones or
   log messages) and sends it with the question to consent_service, which holds the
   Groq / xAI key and streams the answer back. Conversations are kept in this
   browser only. Uses session / refreshSession / show from app.js. */
const AI = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const LS = "aiChats";

  const SOURCES = {
    logs: { label: "Logs", desc: "7-day log activity, errors, HTTP status, services", get: () => Dashboard.context(), need: "telemetry:ReadLogs" },
    consent: { label: "Consent", desc: "Policy, rules, issues, customer consent status", get: () => Consent.context(), need: "consent:ReadFindings" },
    retention: { label: "Retention", desc: "Schedule, deadlines, erasure requests, inactivity", get: () => Retention.context(), need: "retention:ReadSchedule" },
    breach: { label: "Breach", desc: "Detectors, signals, incidents and their clocks", get: () => Breach.context(), need: "breach:ReadSignals" },
    evidence: { label: "Evidence", desc: "Record integrity, the chain, seals, evidence packs, log retention", get: () => Evidence.context(), need: ["readiness:Read", "readiness:VerifyIntegrity", "readiness:ExportEvidence"] },
  };
  const canSrc = (s) => [].concat(s.need).some((a) => can(a));
  // The AI only sees data from sections the user may read.
  const permitted = () => Object.keys(SOURCES).filter((k) => canSrc(SOURCES[k]));
  const PROMPTS = {
    Explain: [
      ["What needs my attention most today, and why?", "all"],
      ["Explain the consent issues in plain language", "consent"],
      ["What does Rule 7 require when we have a breach?", "breach"],
      ["How is each retention deadline calculated here?", "retention"],
      ["Are our records intact, and can I prove it to an auditor?", "evidence"],
    ],
    Investigate: [
      ["Which services produce the most errors, and when did they spike?", "logs"],
      ["Are any of the open breach signals a real personal data breach?", "breach"],
      ["Which customers have the most consent findings, and what rules do they break?", "consent"],
      ["Why are 26 log lines flagged for personal data?", "logs"],
    ],
    Fix: [
      ["Give me a step-by-step plan to clear every consent issue", "consent"],
      ["What should I do about the session tokens due soon?", "retention"],
      ["Draft the first checks for the API gateway 503 outage", "breach"],
      ["Which incident deadlines are at risk and what do I do now?", "breach"],
    ],
    Prevent: [
      ["How do we stop personal data from reaching the logs?", "logs"],
      ["What controls would prevent processing before consent?", "consent"],
      ["Which detectors should we tune or add?", "breach"],
      ["How do we protect our evidence records from someone with server access?", "evidence"],
      ["Build a monthly DPDP compliance checklist for our team", "all"],
    ],
  };
  const CAT_ICON = { Explain: "💡", Investigate: "🔎", Fix: "🛠️", Prevent: "🛡️" };

  const A = { started: false, status: null, chats: [], cur: null, scopes: new Set(Object.keys(SOURCES)), attach: null, busy: false, ctrl: null, cat: "Explain", sizes: {} };

  /* ---------- storage (per browser) ---------- */
  function load() { try { A.chats = JSON.parse(localStorage.getItem(LS)) || []; } catch { A.chats = []; } }
  function persist() { try { localStorage.setItem(LS, JSON.stringify(A.chats.slice(0, 25))); } catch {} }
  const chat = () => A.chats.find((c) => c.id === A.cur);

  /* ---------- markdown (small, safe: escape first) ---------- */
  function md(src) {
    const blocks = [], codes = [];
    let s = esc(src).replace(/\\([*_`#|])/g, (_, c) => `&#${c.charCodeAt(0)};`).replace(/```[\w-]*\n?([\s\S]*?)(```|$)/g, (_, c) => { codes.push(c); return `\u0000${codes.length - 1}\u0000`; });
    const inline = (t) => t.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<i>$2</i>");
    const lines = s.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (/^\u0000\d+\u0000$/.test(l.trim())) { blocks.push(`<pre class="ai-code"><code>${codes[+l.trim().slice(1, -1)]}</code></pre>`); continue; }
      let m;
      if ((m = l.match(/^(#{1,4})\s+(.*)/))) { blocks.push(`<h${Math.min(4, m[1].length + 2)}>${inline(m[2])}</h${Math.min(4, m[1].length + 2)}>`); continue; }
      if (/^\s*\|.*\|\s*$/.test(l) && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1] || "")) {
        const row = (r) => r.trim().replace(/^\||\|$/g, "").split("|").map((c) => inline(c.trim()));
        const head = row(l); i++;
        const body = [];
        while (i + 1 < lines.length && /^\s*\|.*\|\s*$/.test(lines[i + 1])) body.push(row(lines[++i]));
        blocks.push(`<div class="ai-tablewrap"><table><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${body.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`);
        continue;
      }
      if (/^\s*([-*•]|\d+[.)])\s+/.test(l)) {
        const ordered = /^\s*\d+[.)]/.test(l), items = [];
        while (i < lines.length && /^\s*([-*•]|\d+[.)])\s+/.test(lines[i])) { items.push(inline(lines[i].replace(/^\s*([-*•]|\d+[.)])\s+/, ""))); i++; }
        i--;
        blocks.push(`<${ordered ? "ol" : "ul"}>${items.map((x) => `<li>${x}</li>`).join("")}</${ordered ? "ol" : "ul"}>`);
        continue;
      }
      if (/^\s*(---|\*\*\*)\s*$/.test(l)) { blocks.push("<hr>"); continue; }
      if (!l.trim()) { blocks.push(""); continue; }
      const last = blocks[blocks.length - 1];
      if (last && last.startsWith("<p>")) blocks[blocks.length - 1] = last.replace(/<\/p>$/, `<br>${inline(l)}</p>`);
      else blocks.push(`<p>${inline(l)}</p>`);
    }
    return blocks.filter(Boolean).join("");
  }
  // The model ends with "FOLLOW_UPS: a | b | c"; split it off (also while streaming).
  function split(text) {
    const i = text.search(/\n?\s*\**FOLLOW[_ ]UPS\**:/i);
    if (i < 0) return { body: text, follow: [] };
    const tail = text.slice(i).replace(/^\s*\**FOLLOW[_ ]UPS\**:\s*/i, "");
    return { body: text.slice(0, i).trimEnd(), follow: tail.split("|").map((x) => x.replace(/[*_]/g, "").trim()).filter((x) => x.length > 3).slice(0, 3) };
  }

  /* ---------- render ---------- */
  function render() {
    renderSide();
    const c = chat(), thread = $("aiThread");
    if (!c || !c.messages.length) { thread.innerHTML = welcomeHtml(); $("aiTitle").textContent = "New conversation"; }
    else {
      $("aiTitle").textContent = c.title;
      thread.innerHTML = c.messages.map(msgHtml).join("");
    }
    renderComposer();
  }
  function welcomeHtml() {
    const st = A.status;
    return `<div class="ai-welcome">
      <div class="ai-orb" aria-hidden="true">✦</div>
      <h2>Ask anything about your compliance</h2>
      <p>Answers use the live data in this dashboard: logs, consent, retention and breaches. Ask the assistant to explain, investigate, fix or prevent.</p>
      ${st && !st.configured ? `<div class="cp-warn"><b>The AI isn't configured.</b><span>Add GROK_API_KEY to .env and restart the consent service.</span></div>` : ""}
      <div class="ai-cats" role="tablist">${Object.keys(PROMPTS).map((k) => `<button role="tab" class="${A.cat === k ? "on" : ""}" aria-selected="${A.cat === k}" data-cat="${k}"><span aria-hidden="true">${CAT_ICON[k]}</span>${k}</button>`).join("")}</div>
      <div class="ai-prompts">${PROMPTS[A.cat].map(([q, src]) => `<button class="ai-prompt" data-q="${esc(q)}"><b>${esc(q)}</b><span>${src === "all" ? "Uses every section" : `Uses ${esc(SOURCES[src].label)}`}</span></button>`).join("")}</div>
    </div>`;
  }
  function msgHtml(m, i) {
    if (m.role === "user") return `<div class="ai-msg user"><div class="ai-bubble">${m.attach ? `<span class="ai-chip att" title="${esc(m.attach)}">📎 ${esc(m.attach)}</span>` : ""}${esc(m.content).replace(/\n/g, "<br>")}</div></div>`;
    const { body, follow } = split(m.content || "");
    const last = i === chat().messages.length - 1;
    return `<div class="ai-msg bot${m.error ? " err" : ""}">
      <div class="ai-avatar" aria-hidden="true">✦</div>
      <div class="ai-answer">
        <div class="ai-md">${m.error ? `<p>${esc(m.error)}</p>` : body ? md(body) : `<p class="ai-typing"><i></i><i></i><i></i> Reading your data…</p>`}${m.streaming && body ? `<span class="ai-caret"></span>` : ""}</div>
        ${!m.streaming ? `<div class="ai-meta">${m.model ? `<span>${esc(m.model)}</span>` : ""}${m.scopes ? `<span>Data: ${esc(m.scopes)}</span>` : ""}
          ${m.error ? `<button class="link" data-act="retry">Try again</button>` : `<button class="link" data-copy="${i}">Copy</button>${last ? `<button class="link" data-act="retry">Regenerate</button>` : ""}`}</div>
          ${last && follow.length ? `<div class="ai-follow">${follow.map((q) => `<button data-q="${esc(q)}">${esc(q)}</button>`).join("")}</div>` : ""}` : ""}
      </div></div>`;
  }
  function renderSide() {
    for (const k of [...A.scopes]) if (!canSrc(SOURCES[k])) A.scopes.delete(k);
    $("aiScopes").innerHTML = Object.entries(SOURCES).map(([k, s]) => { const ok = canSrc(s); return `<label class="ai-scope${ok ? "" : " off"}"><input type="checkbox" data-scope="${k}" ${A.scopes.has(k) ? "checked" : ""} ${ok ? "" : "disabled"}><span><b>${esc(s.label)}</b><small>${ok ? esc(s.desc) : `No access (needs ${esc(s.need)})`}</small></span>${A.sizes[k] && ok ? `<em>${esc(A.sizes[k])}</em>` : ""}</label>`; }).join("");
    $("aiHistory").innerHTML = A.chats.length ? A.chats.map((c) => `<div class="ai-hrow${c.id === A.cur ? " on" : ""}"><button class="ai-hitem" data-chat="${c.id}"><b>${esc(c.title)}</b><span>${esc(new Date(c.at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", hour: "numeric", minute: "2-digit", hour12: true }))}</span></button><button class="icon-btn" data-del="${c.id}" aria-label="Delete conversation">×</button></div>`).join("")
      : `<p class="muted ai-none">Your conversations appear here. They stay in this browser.</p>`;
    const st = A.status;
    $("aiModel").innerHTML = !st ? "Connecting…" : st.error ? `<span class="cp-red">${esc(st.error)}</span>` : st.configured ? `<i class="ai-dot"></i>${esc(st.provider)} · ${esc(st.model)}` : `<span class="cp-red">Not configured</span>`;
  }
  function renderComposer() {
    $("aiAttach").innerHTML = A.attach ? `<span class="ai-chip att">📎 ${esc(A.attach.name)} <button data-act="detach" aria-label="Remove attachment">×</button></span>` : "";
    $("aiSend").hidden = A.busy; $("aiStop").hidden = !A.busy;
    $("aiInput").disabled = false;
    const n = A.scopes.size;
    $("aiUses").textContent = (n ? `Uses ${[...A.scopes].map((k) => SOURCES[k].label).join(" · ")} · aggregates only, no personal data leaves the dashboard` : "No dashboard data selected: answers will be general")
      + (ME?.ai_left != null ? ` · ${ME.ai_left} AI question${ME.ai_left === 1 ? "" : "s"} left this cycle` : "");
  }
  const scrollEnd = () => { const t = $("aiThread"); t.scrollTop = t.scrollHeight; };

  /* ---------- ask ---------- */
  // Send only the sections a question is about (the AI's free tier has a small per-minute budget).
  const TOPICS = {
    logs: /\blogs?\b|error|service|http|\b[45]\d\d\b|outage|traffic|spike|masked|telemetry|gateway|latency/i,
    consent: /consent|notice|purpose|opt[- ]?in|marketing|terms|\bR\d\b|re-?consent/i,
    retention: /retention|retain|delet|erasure|erase|inactiv|deadline|token|legal hold|keep|schedule|worklist/i,
    breach: /breach|incident|signal|detector|cert-?in|board|rule 7|72|notif|attack|sign-?in|exfiltrat|leak/i,
  };
  function scopesFor(q) {
    const hit = Object.keys(TOPICS).filter((k) => A.scopes.has(k) && TOPICS[k].test(q));
    return hit.length && !/attention|overall|summary|everything|today|checklist|status|priorit/i.test(q) ? hit : [...A.scopes];
  }
  async function gather(scopes) {
    const ctx = {}, sizes = {};
    await Promise.all(scopes.map(async (k) => {
      try { ctx[k] = await SOURCES[k].get(); } catch (e) { ctx[k] = { error: e.message }; }
      if (!ctx[k]) ctx[k] = { error: "not available (is the consent service running?)" };
      const kb = JSON.stringify(ctx[k]).length / 1024;
      sizes[k] = kb < 1 ? "<1 KB" : `${Math.round(kb)} KB`;
    }));
    A.sizes = sizes;
    return ctx;
  }
  async function ask(q, opts = {}) {
    q = (q || "").trim();
    if (!q || A.busy) return;
    if (!chat()) { const c = { id: `c${Date.now()}`, title: q.slice(0, 70), at: Date.now(), messages: [] }; A.chats.unshift(c); A.cur = c.id; }
    const c = chat();
    const attach = opts.attach !== undefined ? opts.attach : A.attach;
    if (!opts.retry) c.messages.push({ role: "user", content: q, attach: attach?.name || null, attachText: attach?.text || null });
    const bot = { role: "assistant", content: "", streaming: true };
    c.messages.push(bot);
    c.at = Date.now();
    A.attach = null; A.busy = true; $("aiInput").value = ""; autosize();
    render(); scrollEnd();
    A.ctrl = new AbortController();
    try {
      const userQ = c.messages[c.messages.length - 2];
      const scopes = scopesFor(`${userQ.content} ${userQ.attach || ""}`);
      const context = await gather(scopes);
      bot.scopes = scopes.map((k) => SOURCES[k].label).join(", ") || "none";
      renderSide();
      const history = c.messages.slice(0, -2).filter((m) => !m.error).map((m) => ({ role: m.role, content: m.role === "assistant" ? split(m.content).body : m.content }));
      const userMsg = c.messages[c.messages.length - 2];
      const body = JSON.stringify({ question: userMsg.content, history, context, attachment: userMsg.attachText ? { name: userMsg.attach, text: userMsg.attachText } : null });
      const go = () => fetch(`${BASE}/api/ai/chat`, { method: "POST", signal: A.ctrl.signal, headers: { Authorization: `Bearer ${session?.access_token || ""}`, "Content-Type": "application/json" }, body });
      let r = await go();
      if (r.status === 401 && session?.refresh_token) { await refreshSession(); r = await go(); }
      if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `HTTP ${r.status}`); }
      bot.model = r.headers.get("X-AI-Model") || "";
      const reader = r.body.getReader(), dec = new TextDecoder();
      let paint = 0;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        bot.content += dec.decode(value, { stream: true });
        if (Date.now() - paint > 60) { paint = Date.now(); updateLast(); }
      }
      if (!bot.content.trim()) throw new Error("The AI returned an empty answer. Try rephrasing.");
      if (ME?.ai_left != null) ME.ai_left = Math.max(0, ME.ai_left - 1);
    } catch (e) {
      if (e.name === "AbortError") { if (!bot.content) bot.error = "Stopped."; }
      else bot.error = e.message === "Failed to fetch" ? "The consent service isn't running. Start it with: python3 consent_service/server.py" : e.message;
    } finally {
      bot.streaming = false; A.busy = false; A.ctrl = null;
      persist(); render(); scrollEnd();
    }
  }
  function updateLast() {
    const t = $("aiThread"), c = chat(), nodes = t.querySelectorAll(".ai-msg");
    const atEnd = t.scrollHeight - t.scrollTop - t.clientHeight < 80;
    if (nodes.length) nodes[nodes.length - 1].outerHTML = msgHtml(c.messages[c.messages.length - 1], c.messages.length - 1);
    if (atEnd) scrollEnd();
  }

  /* ---------- files (drag and drop) ---------- */
  async function attachFile(f) {
    if (!f) return;
    if (f.size > 2e6) return toast("That file is over 2 MB. Attach a smaller extract.");
    if (!/^text\/|json|csv|xml|javascript|yaml/.test(f.type) && !/\.(log|txt|csv|json|md|sql|ya?ml|xml|py|js|java|properties)$/i.test(f.name)) return toast("Attach a text file: log, CSV, JSON, SQL, Markdown or source code.");
    const text = await f.text();
    A.attach = { name: f.name, text: text.length > 30000 ? text.slice(0, 30000) + "\n…(truncated)" : text };
    renderComposer(); $("aiInput").focus();
    toast(`${f.name} attached${text.length > 30000 ? " (first 30,000 characters)" : ""}. Personal data in it is sent to the AI provider, so remove it first if needed.`, true);
  }
  let toastT;
  function toast(m, ok = false) { const t = $("aiToast"); t.textContent = m; t.className = "ttoast" + (ok ? " ok" : ""); t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 5000); }
  function autosize() { const el = $("aiInput"); el.style.height = "auto"; el.style.height = `${Math.min(180, el.scrollHeight)}px`; }

  function bind() {
    const view = $("view-ai");
    view.addEventListener("click", (e) => {
      const t = (s) => e.target.closest(s);
      let b;
      if ((b = t("[data-q]"))) return ask(b.dataset.q);
      if ((b = t("[data-cat]"))) { A.cat = b.dataset.cat; return render(); }
      if ((b = t("[data-chat]"))) { if (A.busy) return; A.cur = b.dataset.chat; render(); return scrollEnd(); }
      if ((b = t("[data-del]"))) { if (A.busy) return; A.chats = A.chats.filter((c) => c.id !== b.dataset.del); if (A.cur === b.dataset.del) A.cur = null; persist(); return render(); }
      if ((b = t("[data-copy]"))) { const m = chat().messages[+b.dataset.copy]; return navigator.clipboard?.writeText(split(m.content).body).then(() => toast("Answer copied.", true)); }
      b = t("[data-act]"); if (!b) return;
      switch (b.dataset.act) {
        case "new": if (A.busy) return; A.cur = null; A.attach = null; render(); return $("aiInput").focus();
        case "detach": A.attach = null; return renderComposer();
        case "attach": return $("aiFile").click();
        case "retry": { const c = chat(); if (!c || A.busy) return; c.messages.pop(); const u = c.messages[c.messages.length - 1]; return ask(u.content, { retry: true, attach: null }); }
        case "clear-all": if (A.busy || !window.confirm("Delete all conversations in this browser?")) return; A.chats = []; A.cur = null; persist(); return render();
      }
    });
    view.addEventListener("change", (e) => {
      if (e.target.matches("[data-scope]")) { e.target.checked && canSrc(SOURCES[e.target.dataset.scope]) ? A.scopes.add(e.target.dataset.scope) : A.scopes.delete(e.target.dataset.scope); renderComposer(); }
      if (e.target.id === "aiFile") { attachFile(e.target.files[0]); e.target.value = ""; }
    });
    $("aiForm").addEventListener("submit", (e) => { e.preventDefault(); ask($("aiInput").value); });
    $("aiInput").addEventListener("input", autosize);
    $("aiInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); ask($("aiInput").value); } });
    $("aiStop").onclick = () => A.ctrl?.abort();
    const panel = $("aiMain");
    let depth = 0;
    panel.addEventListener("dragenter", (e) => { if ([...(e.dataTransfer?.types || [])].includes("Files")) { depth++; panel.classList.add("drop"); } });
    panel.addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; panel.classList.remove("drop"); } });
    panel.addEventListener("dragover", (e) => e.preventDefault());
    panel.addEventListener("drop", (e) => { e.preventDefault(); depth = 0; panel.classList.remove("drop"); attachFile(e.dataTransfer.files[0]); });
  }
  async function loadStatus() {
    try {
      const r = await fetch(`${BASE}/api/ai/status`, { headers: { Authorization: `Bearer ${session?.access_token || ""}` } });
      if (r.status === 401 && session?.refresh_token) { await refreshSession(); return loadStatus(); }
      A.status = await r.json();
    } catch { A.status = { error: "Consent service offline" }; }
    renderSide(); if (!chat()?.messages.length) render();
  }

  // "✦ Ask AI" buttons anywhere in the app: data-ask-ai="consent:R1" | "breach:signal:<id>" | "breach:incident:<id>".
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-ask-ai]");
    if (!b) return;
    e.preventDefault(); e.stopPropagation();
    const [mod, ...rest] = b.dataset.askAi.split(":");
    const item = mod === "consent" ? Consent.aiItem(rest.join(":")) : mod === "breach" ? Breach.aiItem(rest.join(":")) : mod === "readiness" ? Readiness.aiItem(rest.join(":")) : mod === "datamap" ? DataMap.aiItem() : mod === "evidence" ? Evidence.aiItem(rest.join(":")) : mod === "anomaly" ? Anomaly.aiItem(rest.join(":")) : null;
    if (!item) return;
    show("ai");
    A.cur = null; A.attach = { name: item.name, text: item.text };
    const sc = mod === "consent" ? "consent" : mod === "evidence" ? "evidence" : "breach";
    if (canSrc(SOURCES[sc])) A.scopes.add(sc);
    render();
    $("aiInput").value = item.question; autosize(); $("aiInput").focus();
  }, true);

  return {
    show() {
      if (!A.started) { A.started = true; load(); bind(); loadStatus(); }
      render(); scrollEnd();
      setTimeout(() => $("aiInput").focus(), 50);
    },
  };
})();
