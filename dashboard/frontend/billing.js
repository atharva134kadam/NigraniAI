/* Billing (Usage & plan → Billing tab): change plan (pro-rated upgrade invoice, downgrade at the next
   cycle), invoices with GST (CGST+SGST within the seller's state, IGST otherwise), online payment with
   Razorpay Checkout, printable tax invoices and the billing profile. The server fixes every amount,
   creates the Razorpay order, and verifies each payment with Razorpay before marking it paid.
   Payments go to the provider's Razorpay account. Server: /api/billing*. Uses session / refreshSession / can / show / ME. */
const Billing = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const inr = (n) => `₹${Number(n || 0).toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  const inr0 = (n) => `₹${Number(n || 0).toLocaleString("en-IN", { maximumFractionDigits: 0 })}`;
  const F = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", year: "numeric" });
  const d = (v) => (v ? F.format(new Date(v)) : "–");
  const dEnd = (v) => (v ? F.format(new Date(new Date(v).getTime() - 1000)) : "–");   // period ends are exclusive (next cycle's midnight)
  const S = { b: null, box: null, err: "", busy: false, bound: new WeakSet(), loadedAt: 0 };

  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r;
    try { r = await go(); } catch { throw new Error("The consent service isn't running."); }
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }
  function toast(m, ok = false) { const t = document.getElementById("usToast"); if (!t) return; t.textContent = m; t.className = "ttoast" + (ok ? " ok" : ""); t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 5000); }
  async function load() {
    try { S.b = await api("/api/billing"); S.err = ""; S.loadedAt = Date.now(); } catch (e) { S.err = e.message; }
    render();
  }
  const pill = (i) => i.status === "paid" ? `<span class="rt-pill ok">Paid</span>` : i.status === "refunded" ? `<span class="rt-pill off">Refunded</span>` : i.status === "void" ? `<span class="rt-pill off">Void</span>` : i.overdue ? `<span class="rt-pill bad">Overdue</span>` : `<span class="rt-pill warn">Due ${esc(d(i.due_at))}</span>`;

  function render() {
    const box = S.box; if (!box || !document.body.contains(box)) return;
    if (S.err && !S.b) { box.innerHTML = `<div class="panel cp-empty"><h3>Billing isn't available</h3><p>${esc(S.err)}</p></div>`; return; }
    if (!S.b) { box.innerHTML = `<div class="panel cp-empty"><p>Loading billing…</p></div>`; return; }
    const b = S.b, prof = b.profile || {}, unpaid = b.invoices.filter((i) => i.status === "issued");
    box.innerHTML = `
      ${b.restricted ? `<div class="cp-warn us-alert" role="alert"><b>Your dashboard is on Free-plan limits because an invoice is more than ${b.grace_days} days overdue.</b><span>Pay it below and your plan is restored at once. Breach monitoring keeps running.</span></div>` : ""}
      ${!b.online_payment ? `<div class="cp-warn us-alert" role="status"><b>Online payment isn't set up yet.</b><span>Invoices can still be paid by bank transfer; your provider records the payment.</span></div>` : b.test_mode ? `<p class="bl-test">Razorpay <b>test mode</b>: no real money moves. Pay with a test card or the UPI ID <code>success@razorpay</code>.</p>` : ""}
      <section class="panel us-sec">
        <div class="cp-list-head flat"><h3>Your plan</h3><span class="muted">${esc(b.plan.name)}${b.plan.base_fee ? ` · ${inr0(b.plan.base_fee)} / month + GST` : ""}${b.pending_plan ? ` · changes to ${esc(b.upgrades[b.pending_plan]?.name || b.pending_plan)} next cycle` : ""}</span></div>
        <div class="bl-plans">${Object.entries(b.upgrades).map(([k, u]) => `<div class="bl-plan${u.kind === "current" ? " on" : ""}">
          <b>${esc(u.name)}</b><span class="bl-fee">${inr0(u.base_fee)}<small> / month</small></span>
          ${u.kind === "current" ? `<span class="rt-pill ok">Current plan</span>`
            : u.kind === "upgrade" ? `<small class="muted">Upgrade now: ${inr(u.total)} incl. GST for the rest of this cycle (${Math.round(u.fraction * 100)}%), then ${inr0(u.base_fee)} / month.</small>${b.can_change_plan ? `<button class="btn primary sm" data-bill="upgrade" data-t="${esc(k)}">Upgrade · pay ${inr(u.total)}</button>` : ""}`
            : `<small class="muted">Moves to ${esc(u.name)} when this cycle ends (${esc(d(u.starts))}).</small>${b.can_change_plan ? `<button class="btn ghost sm" data-bill="upgrade" data-t="${esc(k)}">Switch next cycle</button>` : ""}`}
        </div>`).join("")}</div>
        ${!b.can_change_plan ? `<p class="muted bl-note">Ask someone with usage:ManagePlan to change the plan.</p>` : ""}
      </section>
      <section class="panel cp-cpanel">
        <div class="cp-ctools"><h3 class="pl-h">Invoices</h3><span class="muted pl-sub">${unpaid.length ? `${unpaid.length} unpaid · ${inr(unpaid.reduce((n, i) => n + i.total, 0))}` : "Nothing to pay"}</span></div>
        ${b.invoices.length ? `<div class="cp-tablewrap"><table class="cp-ctable bl-table"><thead><tr><th>Invoice</th><th>For</th><th>Issued</th><th class="num">Amount</th><th>Status</th><th></th></tr></thead>
          <tbody>${b.invoices.map((i) => `<tr><td><b>${esc(i.number)}</b><div class="muted pl-id">${esc({ cycle: "Monthly", upgrade: "Plan change", interim: "Usage to date" }[i.kind] || i.kind)}</div></td>
            <td>${esc(d(i.period_start))} – ${esc(dEnd(i.period_end))}</td><td>${esc(d(i.issued_at))}</td><td class="num"><b>${inr(i.total)}</b><div class="muted pl-id">incl. ${inr(i.tax.total)} GST</div></td>
            <td>${pill(i)}${i.payments?.length ? `<div class="muted pl-id">${esc(i.payments[0].method || "")} · ${esc(i.payments[0].id)}</div>` : ""}</td>
            <td class="pl-act"><div class="pl-btns"><button class="btn ghost sm" data-bill="view" data-id="${esc(i.id)}">View / PDF</button>${i.status === "issued" && b.can_pay && b.online_payment ? `<button class="btn primary sm" data-bill="pay" data-id="${esc(i.id)}">Pay ${inr(i.total)}</button>` : ""}</div></td></tr>`).join("")}</tbody></table></div>`
          : `<p class="cp-none br-padx">No invoices yet. They're issued when a billing cycle closes.</p>`}
      </section>
      <form class="panel us-sec" data-bill-form>
        <div class="cp-list-head flat"><h3>Billing details</h3><span class="muted">Printed on your invoices. GST: ${b.gst ? `CGST + SGST if you're in ${esc(b.seller.state || "the seller's state")}, IGST otherwise` : "not charged"}</span></div>
        <div class="su-grid">
          <label class="field"><span>Legal name</span><input name="legal_name" maxlength="120" value="${esc(prof.legal_name || "")}" ${b.can_profile ? "" : "disabled"}></label>
          <label class="field"><span>State (place of supply)</span><select name="state" ${b.can_profile ? "" : "disabled"}><option value="">Choose…</option>${b.states.map((x) => `<option ${prof.state === x ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></label>
          <label class="field"><span>GSTIN (optional)</span><input name="gstin" maxlength="15" value="${esc(prof.gstin || "")}" placeholder="e.g. 29AAACR5055K1Z5" ${b.can_profile ? "" : "disabled"}></label>
          <label class="field"><span>Invoice email</span><input name="email" type="email" value="${esc(prof.email || "")}" ${b.can_profile ? "" : "disabled"}></label>
          <label class="field wide"><span>Billing address</span><input name="address" maxlength="300" value="${esc(prof.address || "")}" ${b.can_profile ? "" : "disabled"}></label>
        </div>
        ${b.can_profile ? `<div class="su-act"><button class="btn primary" type="submit">Save billing details</button></div>` : ""}
      </form>
      <p class="rt-note">Payments are processed by Razorpay; card and bank details never reach this dashboard. Amounts in ₹. Unpaid invoices: reminders from the due date, Free-plan limits ${b.grace_days} days after it until paid.</p>`;
  }

  /* ---------- Razorpay Checkout ---------- */
  function loadCheckout() {
    if (window.Razorpay) return Promise.resolve();
    return new Promise((ok, fail) => { const sc = document.createElement("script"); sc.src = "https://checkout.razorpay.com/v1/checkout.js"; sc.onload = ok; sc.onerror = () => fail(new Error("Couldn't load Razorpay Checkout. Check your connection.")); document.head.appendChild(sc); });
  }
  async function pay(id) {
    if (S.busy) return;
    S.busy = true;
    try {
      const [o] = await Promise.all([api(`/api/billing/invoices/${id}/pay`, { method: "POST", body: "{}" }), loadCheckout()]);
      const rzp = new window.Razorpay({
        key: o.key, order_id: o.order_id, amount: o.amount, currency: o.currency, name: o.name, description: o.description, prefill: o.prefill, notes: o.notes,
        theme: { color: "#1d4ed8" },
        handler: async (resp) => {
          try { const inv = await api("/api/billing/verify", { method: "POST", body: JSON.stringify(resp) }); toast(`Payment received for ${inv.number}. Thank you!`, true); }
          catch (e) { toast(`Payment couldn't be confirmed: ${e.message}`); }
          await load(); if (typeof Account !== "undefined") Account.refreshMe();
        },
        modal: { ondismiss: () => { S.busy = false; } },
      });
      rzp.on("payment.failed", (r) => toast(`Payment failed: ${r.error?.description || "try another method"}`));
      rzp.open();
    } catch (e) { toast(e.message); }
    S.busy = false;
  }

  /* ---------- printable tax invoice ---------- */
  function words(n) {
    const a = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"];
    const t = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"];
    const two = (x) => (x < 20 ? a[x] : `${t[Math.floor(x / 10)]}${x % 10 ? " " + a[x % 10] : ""}`);
    const three = (x) => `${x >= 100 ? a[Math.floor(x / 100)] + " Hundred" + (x % 100 ? " " : "") : ""}${x % 100 ? two(x % 100) : ""}`;
    let r = Math.floor(n), p = Math.round((n - r) * 100), out = [];
    const cr = Math.floor(r / 1e7); r %= 1e7; const lk = Math.floor(r / 1e5); r %= 1e5; const th = Math.floor(r / 1e3); r %= 1e3;
    if (cr) out.push(`${three(cr)} Crore`); if (lk) out.push(`${two(lk)} Lakh`); if (th) out.push(`${two(th)} Thousand`); if (r) out.push(three(r));
    return `Rupees ${out.join(" ") || "Zero"}${p ? ` and ${two(p)} Paise` : ""} only`;
  }
  function invoiceDoc(i) {
    const s = i.seller, by = i.buyer, t = i.tax;
    const row = (l, v, cls = "") => `<tr class="${cls}"><td colspan="4">${l}</td><td class="r">${v}</td></tr>`;
    return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(i.number)}</title><style>
      body{font:13px/1.5 Inter,system-ui,sans-serif;color:#111;margin:32px;max-width:820px}h1{font-size:20px;margin:0}table{width:100%;border-collapse:collapse;margin-top:16px}
      th,td{padding:8px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}th{background:#f5f6f8;font-size:12px}.r{text-align:right}.grid{display:flex;justify-content:space-between;gap:24px;margin-top:18px}
      .muted{color:#555}.tot td{font-weight:700;border-top:2px solid #111}.stamp{display:inline-block;margin-top:6px;padding:2px 10px;border:2px solid;border-radius:6px;font-weight:700;letter-spacing:.06em}
      .paid{color:#15803d}.due{color:#b45309}@media print{button{display:none}body{margin:0}}</style></head><body>
      <div class="grid"><div><h1>Tax Invoice</h1><div class="muted">Original for recipient</div>
        <span class="stamp ${i.status === "paid" ? "paid" : "due"}">${esc(i.status === "paid" ? "PAID" : i.status === "issued" ? "PAYMENT DUE" : i.status.toUpperCase())}</span></div>
        <div class="r"><b>${esc(i.number)}</b><br>Date: ${esc(d(i.issued_at))}<br>Due: ${esc(d(i.due_at))}</div></div>
      <div class="grid"><div><b>From</b><br>${esc(s.legal_name)}<br>${esc(s.address)}<br>${esc(s.state)}<br>${s.gstin ? `GSTIN: ${esc(s.gstin)}` : ""}</div>
        <div><b>Bill to</b><br>${esc(by.name)}<br>${esc(by.address)}<br>${esc(by.state)}<br>${by.gstin ? `GSTIN: ${esc(by.gstin)}` : "Unregistered"}<br>${esc(by.email)}</div></div>
      <p class="muted">Place of supply: ${esc(i.place_of_supply)} · SAC ${esc(s.sac)} · Period ${esc(d(i.period_start))} – ${esc(dEnd(i.period_end))}</p>
      <table><thead><tr><th>Description</th><th class="r">Qty</th><th>Unit</th><th class="r">Rate</th><th class="r">Amount</th></tr></thead><tbody>
        ${i.lines.map((l) => `<tr><td>${esc(l.desc)}</td><td class="r">${l.qty}</td><td>${esc(l.unit)}</td><td class="r">${inr(l.rate)}</td><td class="r">${inr(l.amount)}</td></tr>`).join("")}
        ${row("Taxable value", inr(i.subtotal))}
        ${t.type === "CGST+SGST" ? row(`CGST ${t.rate / 2}%`, inr(t.cgst)) + row(`SGST ${t.rate / 2}%`, inr(t.sgst)) : t.type === "IGST" ? row(`IGST ${t.rate}%`, inr(t.igst)) : ""}
        ${row("Total", inr(i.total), "tot")}</tbody></table>
      <p><b>Amount in words:</b> ${esc(words(i.total))}</p>
      ${i.payments?.length ? `<p class="muted">Paid ${esc(d(i.paid_at))} · ${esc(i.payments.map((p) => `${p.method || ""} ${p.id}`).join(", "))}</p>` : ""}
      <p class="muted">This is a computer-generated invoice. Questions: ${esc(s.email || "")}</p>
      <button onclick="print()">Print / save as PDF</button></body></html>`;
  }
  function view(id) {
    const i = S.b.invoices.find((x) => x.id === id); if (!i) return;
    const w = window.open("", "_blank", "width=900,height=1000");
    if (!w) return toast("Allow pop-ups to view the invoice.");
    w.document.write(invoiceDoc(i)); w.document.close();
  }

  function bind(box) {
    if (S.bound.has(box)) return;
    S.bound.add(box);
    box.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-bill]"); if (!b) return;
      if (b.dataset.bill === "view") return view(b.dataset.id);
      if (b.dataset.bill === "pay") return pay(b.dataset.id);
      if (b.dataset.bill === "upgrade") {
        const u = S.b.upgrades[b.dataset.t];
        const msg = u.kind === "upgrade" ? `Move to ${u.name} now? An invoice of ${inr(u.total)} (incl. GST) is issued for the rest of this cycle; the plan starts as soon as it's paid.` : `Move to ${u.name} when this cycle ends? Nothing changes until then.`;
        if (!window.confirm(msg)) return;
        try {
          const r = await api("/api/billing/upgrade", { method: "POST", body: JSON.stringify({ template: b.dataset.t }) });
          await load();
          if (r.kind === "invoice") { toast(`Invoice ${r.invoice.number} issued.`, true); if (S.b.online_payment && S.b.can_pay) pay(r.invoice.id); }
          else toast(r.kind === "downgrade" ? "Scheduled for the next cycle." : "Plan changed.", true);
        } catch (err) { toast(err.message); }
      }
    });
    box.addEventListener("submit", async (e) => {
      if (!e.target.matches("[data-bill-form]")) return;
      e.preventDefault();
      try { S.b.profile = await api("/api/billing/profile", { method: "PUT", body: JSON.stringify(Object.fromEntries(new FormData(e.target).entries())) }); toast("Billing details saved. New invoices use them.", true); load(); }
      catch (err) { toast(err.message); }
    });
  }
  return {
    mount(box) { S.box = box; bind(box); render(); if (!S.b || Date.now() - S.loadedAt > 15000) load(); },
    invoiceDoc, words,
  };
})();
