/* NigraniAI website: navigation, scroll reveals, tool filters, the live hero illustration, the DPDP
   countdown, the cookie banner and the demo booking form (saved to Supabase table demo_bookings).
   Plain JavaScript, no build step. */
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- navigation ---------- */
  const nav = $('#nav'), burger = $('#burger'), sheet = $('#sheet');
  const solid = () => nav && nav.classList.toggle('solid', scrollY > 8);
  solid(); addEventListener('scroll', solid, { passive: true });
  const setSheet = (open) => {
    if (!sheet) return;
    sheet.hidden = !open; burger.setAttribute('aria-expanded', String(open));
    burger.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    burger.querySelector('use').setAttribute('href', open ? '#i-x' : '#i-menu');
    document.body.style.overflow = open ? 'hidden' : '';
    nav.classList.toggle('solid', open || scrollY > 8);
  };
  burger && burger.addEventListener('click', () => setSheet(sheet.hidden));
  sheet && sheet.addEventListener('click', (e) => { if (e.target.closest('a')) setSheet(false); });
  addEventListener('keydown', (e) => { if (e.key === 'Escape' && sheet && !sheet.hidden) setSheet(false); });

  // highlight the section in view
  const links = $$('.nav-links a[href^="#"]');
  if (links.length && 'IntersectionObserver' in window) {
    const io = new IntersectionObserver((es) => es.forEach((en) => {
      if (en.isIntersecting) links.forEach((a) => a.classList.toggle('on', a.getAttribute('href') === `#${en.target.id}`));
    }), { rootMargin: '-45% 0px -50% 0px' });
    links.forEach((a) => { const s = $(a.getAttribute('href')); if (s) io.observe(s); });
  }
  if (location.pathname.endsWith('company.html')) $$('.nav-links a').forEach((a) => a.classList.toggle('on', a.getAttribute('href') === 'company.html'));

  /* ---------- reveal on scroll ---------- */
  const rv = $$('.rv');
  if (reduced || !('IntersectionObserver' in window)) rv.forEach((el) => el.classList.add('in'));
  else {
    const io = new IntersectionObserver((es) => es.forEach((en) => { if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); } }), { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    rv.forEach((el) => io.observe(el));
  }

  /* ---------- platform filter ---------- */
  $$('.tab').forEach((t) => t.addEventListener('click', () => {
    $$('.tab').forEach((x) => { x.classList.toggle('on', x === t); x.setAttribute('aria-selected', String(x === t)); });
    $$('#tools .tool').forEach((card) => { card.hidden = t.dataset.cat !== 'all' && card.dataset.cat !== t.dataset.cat; });
  }));

  /* ---------- hero: an illustration of the dashboard working live ---------- */
  const ring = $('#ringVal'), ringNum = $('#ringNum');
  if (ring) {
    const target = 86, C = 314.2;
    const go = () => {
      ring.style.strokeDashoffset = String(C * (1 - target / 100));
      if (reduced) { ringNum.textContent = target; return; }
      const t0 = performance.now();
      const step = (t) => { const k = Math.min(1, (t - t0) / 1600); ringNum.textContent = Math.round(target * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); };
      requestAnimationFrame(step);
    };
    setTimeout(go, 350);
  }
  const EVENTS = [
    ['t-bad', 'i-pulse', 'Anomaly explained', 'auth-service · rejected sign-ins 23× the night-time normal'],
    ['t-ok', 'i-consent', 'Consent verified', 'new sign-up accepted the current notice'],
    ['t-warn', 'i-scan', 'Personal data in a log line', 'unmasked phone number caught in order-service'],
    ['t-info', 'i-clock', 'Retention deadline', 'session records due for erasure this week'],
    ['t-ok', 'i-chain', 'Evidence sealed', "today's records fingerprinted into the chain"],
    ['t-warn', 'i-map', 'Purpose gap', 'analytics-service reading payment data without a purpose'],
    ['t-bad', 'i-alert', 'Incident opened', 'Rule 7 clocks started · Board report due in 72 h'],
    ['t-info', 'i-ai', 'AI assistant', 'drafted the steps to close the consent gap'],
  ];
  const feed = $('#feed'), chain = $('#chain');
  if (feed) {
    let i = 0;
    const hex = () => Math.random().toString(16).slice(2, 6);
    const push = () => {
      const [cls, ic, title, sub] = EVENTS[i++ % EVENTS.length];
      const el = document.createElement('div');
      el.className = `feed-item ${cls}`;
      el.innerHTML = `<span class="fi"><svg class="i"><use href="#${ic}"/></svg></span><div><b>${title}</b><span>${sub}</span></div><em>now</em>`;
      $$('em', feed).forEach((e, n) => { e.textContent = `${(n + 1) * 3}s`; });
      feed.prepend(el);
      while (feed.children.length > 4) feed.lastElementChild.remove();
      if (chain) {
        if (chain.querySelector('.blk')) chain.appendChild(Object.assign(document.createElement('i'), { className: 'lnk' }));
        chain.appendChild(Object.assign(document.createElement('span'), { className: 'blk', textContent: `${hex()}…${hex()}` }));
        while (chain.querySelectorAll('.blk').length > 6) { chain.querySelector('.blk').remove(); chain.querySelector('.lnk')?.remove(); }
      }
    };
    for (let n = 0; n < 3; n++) push();
    if (!reduced) setInterval(() => { if (!document.hidden) push(); }, 2800);
  }

  /* ---------- DPDP countdown: full obligations from 13 May 2027 (IST) ---------- */
  const cd = $('#countdown');
  if (cd) {
    const end = new Date('2027-05-13T00:00:00+05:30').getTime();
    const put = (u, v) => { const el = cd.querySelector(`[data-u="${u}"]`); if (el) el.textContent = String(v).padStart(u === 'd' ? 1 : 2, '0'); };
    const tick = () => {
      let s = Math.max(0, Math.floor((end - Date.now()) / 1000));
      put('d', Math.floor(s / 86400)); s %= 86400; put('h', Math.floor(s / 3600)); s %= 3600; put('m', Math.floor(s / 60)); put('s', s % 60);
    };
    tick(); setInterval(tick, 1000);
  }

  /* ---------- cookie banner (only essential storage unless accepted) ---------- */
  const cookie = $('#cookie');
  const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage blocked: banner shows again next time */ } } };
  if (cookie && !store.get('nigrani_cookie_choice')) setTimeout(() => { cookie.hidden = false; }, 1200);
  cookie && cookie.addEventListener('click', (e) => {
    const b = e.target.closest('[data-cookie]'); if (!b) return;
    store.set('nigrani_cookie_choice', JSON.stringify({ choice: b.dataset.cookie, at: new Date().toISOString() }));
    cookie.hidden = true;
  });

  $$('.yr').forEach((el) => { el.textContent = new Date().getFullYear(); });

  /* ---------- demo booking → Supabase (demo_bookings, anonymous insert only) ---------- */
  const form = $('#bookForm');
  if (!form) return;
  const cfg = window.NIGRANI_CONFIG || {};
  const date = form.elements.preferred_date;
  const iso = (d) => new Date(d.getTime() + 330 * 6e4).toISOString().slice(0, 10);
  date.min = iso(new Date(Date.now() + 864e5));
  date.max = iso(new Date(Date.now() + 120 * 864e5));
  const RULES = {
    full_name: (v) => (v.trim().length >= 2 ? '' : 'Please enter your name.'),
    business_email: (v) => (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim()) ? '' : 'Please enter a valid email.'),
    phone_number: (v) => (v.replace(/\D/g, '').length >= 10 ? '' : 'Please enter a phone number with at least 10 digits.'),
    designation: (v) => (v.trim() ? '' : 'Please enter your designation.'),
    organization_name: (v) => (v.trim() ? '' : 'Please enter your organisation.'),
    industry: (v) => (v ? '' : 'Please choose an industry.'),
    organization_size: (v) => (v ? '' : 'Please choose a size.'),
    preferred_date: (v) => (v && v >= date.min ? '' : 'Please choose a date from tomorrow.'),
    preferred_time: (v) => (v ? '' : 'Please choose a time.'),
  };
  const check = (name) => {
    const el = form.elements[name], msg = RULES[name](el.value), box = el.closest('.f');
    box.classList.toggle('bad', !!msg); box.querySelector('.err').textContent = msg;
    return !msg;
  };
  Object.keys(RULES).forEach((n) => form.elements[n].addEventListener('blur', () => check(n)));
  const say = (text, ok) => { const m = $('#bookMsg'); m.textContent = text; m.className = `form-msg ${ok ? 'ok' : 'bad'}`; m.hidden = !text; };

  form.addEventListener('submit', async (e) => {
    e.preventDefault(); say('');
    const okAll = Object.keys(RULES).map(check).every(Boolean);
    if (!okAll) { form.querySelector('.f.bad input, .f.bad select')?.focus(); return; }
    if (form.elements.website.value) return;   // filled by a bot
    if (!cfg.SUPABASE_URL || !cfg.SUPABASE_ANON_KEY) { say('Booking is not configured yet. Please email us instead.', false); return; }
    const btn = $('#bookBtn'); btn.classList.add('loading'); btn.disabled = true; btn.firstChild.textContent = 'Booking… ';
    const ref = `NIG-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
    const v = (n) => form.elements[n].value.trim();
    const body = {
      booking_reference: ref, full_name: v('full_name'), business_email: v('business_email').toLowerCase(), phone_number: v('phone_number'),
      organization_name: v('organization_name'), designation: v('designation'), industry: v('industry'), organization_size: v('organization_size'),
      preferred_date: v('preferred_date'), preferred_time: v('preferred_time'),
      areas_of_interest: $$('#picks input:checked').map((c) => c.value), additional_requirements: v('additional_requirements') || null, status: 'PENDING',
    };
    try {
      const r = await fetch(`${cfg.SUPABASE_URL.replace(/\/$/, '')}/rest/v1/demo_bookings`, {
        method: 'POST',
        headers: { apikey: cfg.SUPABASE_ANON_KEY, Authorization: `Bearer ${cfg.SUPABASE_ANON_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      $('#bookFields').hidden = true; $('#bookRef').textContent = ref; $('#bookDone').hidden = false;
      form.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'center' });
    } catch (err) {
      console.warn('Booking failed:', err.message);
      say("We couldn't save your booking just now. Please try again in a minute.", false);
    } finally { btn.classList.remove('loading'); btn.disabled = false; btn.firstChild.textContent = 'Book my demo '; }
  });
})();
