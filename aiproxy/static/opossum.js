/* Opossum ledger: everything private happens here, on the user's device.
 *
 * - The password is stretched with PBKDF2-SHA256 in this browser into two keys:
 *   an auth key (sent to the relay, which stores only a scrypt hash) and a
 *   key-encryption key that never leaves the device.
 * - The ledger is encrypted with its own AES-256-GCM key, wrapped by the
 *   password key and by the recovery-code key. Backups are ciphertext only.
 * - Payments are signed by an ECDSA P-256 key created here as non-extractable.
 * - Budgets, reports and categorisation run on the decrypted ledger in memory.
 * Only text is ever put into the page (no HTML strings), and the page's
 * policy enforces that with Trusted Types.
 */
(() => {
  'use strict';

  console.log('%cstop.', 'font: 200 42px system-ui, sans-serif; color: #ff9a5a;');
  console.log('%cthis console is for developers. if someone asked you to paste something here, they are trying to take over your ledger. close it.', 'font: 14px system-ui, sans-serif; color: #eef0f8;');

  // ============================================================ small helpers
  const $ = (q, root = document) => root.querySelector(q);
  const $$ = (q, root = document) => Array.from(root.querySelectorAll(q));
  const SVGNS = 'http://www.w3.org/2000/svg';
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
        else if (k === 'checked' || k === 'value' || k === 'selected') el[k] = v;
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
    return el;
  }
  function svg(tag, attrs, ...kids) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
    for (const kid of kids) el.append(kid instanceof Node ? kid : String(kid));
    return el;
  }
  const td = (text, cls) => h('td', { class: cls }, text == null ? '' : String(text));
  function rows(sel, list, build, empty) {
    const body = $(sel + ' tbody');
    const cols = Math.max(1, $$(sel + ' thead th').length);
    body.replaceChildren();
    if (!list.length) { body.append(h('tr', { class: 'empty' }, h('td', { colspan: cols }, empty || 'nothing here yet.'))); return; }
    for (const item of list) { const tr = h('tr'); build(item, tr); body.append(tr); }
  }
  function options(select, list, current) {
    select.replaceChildren(...list.map(([value, label]) => h('option', { value, selected: value === current }, label)));
    if (current != null) select.value = current;
  }

  // ============================================================ bytes and crypto
  function b64u(bytes) {
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(text) {
    const pad = (4 - (text.length % 4)) % 4;
    const s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  const hex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
  const random = (n) => crypto.getRandomValues(new Uint8Array(n));
  const sha256hex = async (text) => hex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  const uid = () => b64u(random(12));

  async function derive(secret, saltB64u, iterations) {
    const base = await crypto.subtle.importKey('raw', enc.encode(secret.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64u(saltB64u), iterations }, base, 512));
    const kek = await crypto.subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    const auth = hex(bits.slice(0, 32));
    bits.fill(0);
    return { auth, kek };
  }
  const passwordKeys = (password, salt, it) => derive('password:' + password, salt, it);
  const normCode = (code) => code.toUpperCase().replace(/[^A-Z2-7]/g, '');
  const recoveryKeys = (code, salt, it) => derive('recovery:' + normCode(code), salt, it);
  function newRecoveryCode() {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bytes = random(24);
    const chars = Array.from(bytes, (b) => alphabet[b & 31]).join('');
    return chars.match(/.{4}/g).join('-');
  }
  async function wrapKey(kek, raw) {
    const iv = random(12);
    return { iv: b64u(iv), ct: b64u(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, raw)) };
  }
  async function unwrapKey(kek, wrapped) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(wrapped.iv) }, kek, unb64u(wrapped.ct)));
  }
  const importLedgerKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  async function seal(key, value) {
    const iv = random(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(value))));
    const out = new Uint8Array(12 + ct.length);
    out.set(iv); out.set(ct, 12);
    return 'v1.' + b64u(out);
  }
  async function unseal(key, text) {
    if (!text || !text.startsWith('v1.')) throw new Error('not an encrypted ledger');
    const blob = unb64u(text.slice(3));
    return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(0, 12) }, key, blob.slice(12))));
  }
  async function newDevice() {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    return { privateKey: pair.privateKey, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
  }
  const signBytes = async (privateKey, bytes) => b64u(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes));

  // ============================================================ local storage (IndexedDB)
  const idb = {
    db: null,
    open() {
      if (this.db) return Promise.resolve(this.db);
      return new Promise((resolve, reject) => {
        const req = indexedDB.open('opossum-v1', 1);
        req.onupgradeneeded = () => req.result.createObjectStore('kv');
        req.onsuccess = () => { this.db = req.result; resolve(this.db); };
        req.onerror = () => reject(req.error);
      });
    },
    async run(mode, fn) {
      const db = await this.open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction('kv', mode);
        const req = fn(tx.objectStore('kv'));
        tx.oncomplete = () => resolve(req && req.result);
        tx.onerror = () => reject(tx.error);
      });
    },
    get(k) { return this.run('readonly', (s) => s.get(k)).catch(() => undefined); },
    set(k, v) { return this.run('readwrite', (s) => s.put(v, k)); },
    del(k) { return this.run('readwrite', (s) => s.delete(k)).catch(() => undefined); },
  };

  // ============================================================ state
  const S = {
    config: null, email: null, ns: null, me: null,
    ledgerRaw: null, ledgerKey: null, ledger: null, version: 0,
    device: null, recipients: [], idleMs: 30 * 60000, lastActive: Date.now(),
    room: null, quote: null, draft: null, pendingRoute: null, saveTimer: null, saving: false,
  };

  // ============================================================ server
  class Signed extends Error {}
  function errText(data, status) {
    const e = data && data.error;
    if (e && Array.isArray(e.details) && e.details.length) return e.details.map((d) => (d.loc || []).slice(1).join('.') + ': ' + d.msg).join('; ');
    if (status === 429) return 'too many attempts. wait a minute and try again.';
    return String((e && e.message) || ('request failed (' + status + ')'));
  }
  async function call(path, method, body, extraHeaders) {
    const init = {
      method: method || 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      headers: { 'X-Opossum-Request': '1', Accept: 'application/json', ...(extraHeaders || {}) },
    };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = body instanceof Uint8Array ? body : JSON.stringify(body);
    }
    let res;
    try { res = await fetch('/opossum/api' + path, init); } catch (err) { throw new Error('the relay could not be reached. check your connection.'); }
    const data = await res.json().catch(() => ({}));
    return { res, data, code: data && data.error && data.error.code };
  }
  async function api(path, method, body, extraHeaders) {
    const r = await call(path, method, body, extraHeaders);
    if (r.res.status === 401 && S.ledger) { lock('your session ended. unlock to continue.'); throw new Signed(); }
    if (!r.res.ok) { const err = new Error(errText(r.data, r.res.status)); err.code = r.code; err.data = r.data; throw err; }
    return r.data;
  }
  async function guard(fn, btn) {
    if (btn) btn.disabled = true;
    try { return await fn(); } catch (err) { if (!(err instanceof Signed)) toast(err.message, 'alarm'); } finally { if (btn) btn.disabled = false; }
  }

  // ============================================================ messages
  let toastTimer;
  function toast(text, tone) {
    const t = $('#toast');
    t.textContent = String(text);
    t.className = 'toast' + (tone ? ' ' + tone : '');
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, tone === 'alarm' ? 7000 : 4000);
  }
  function gateMsg(text, tone) { const m = $('#gateMsg'); m.textContent = text || ''; m.className = 'msg' + (tone ? ' ' + tone : ''); }
  function ask(title, text, action) {
    const d = $('#confirm');
    $('#confirmTitle').textContent = title; $('#confirmText').textContent = text; $('#confirmGo').textContent = action;
    return new Promise((resolve) => {
      const done = (ok) => { cleanup(); d.close(); resolve(ok); };
      const yes = () => done(true); const no = () => done(false); const esc = (e) => { e.preventDefault(); done(false); };
      function cleanup() { $('#confirmGo').removeEventListener('click', yes); $('#confirmCancel').removeEventListener('click', no); d.removeEventListener('cancel', esc); }
      $('#confirmGo').addEventListener('click', yes); $('#confirmCancel').addEventListener('click', no); d.addEventListener('cancel', esc);
      d.showModal(); $('#confirmCancel').focus();
    });
  }

  // ============================================================ money and dates
  const cents = (v) => Math.round(Number(v || 0) * 100);
  const fromCents = (c) => (c / 100).toFixed(2);
  function fmt(c, currency) {
    try { return new Intl.NumberFormat(undefined, { style: 'currency', currency: currency || baseCurrency() }).format(c / 100); }
    catch (e) { return (currency || '') + ' ' + fromCents(c); }
  }
  function parseMoney(text) {
    const clean = String(text || '').trim().replace(/[,\s]/g, '');
    if (!/^-?\d+(\.\d{1,2})?$/.test(clean)) return null;
    return clean.includes('.') ? clean.replace(/\.(\d)$/, (m, d) => '.' + d + '0') : clean + '.00';
  }
  const pad2 = (n) => String(n).padStart(2, '0');
  const ymd = (d) => d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
  const today = () => ymd(new Date());
  const addDays = (iso, n) => { const d = new Date(iso + 'T12:00:00'); d.setDate(d.getDate() + n); return ymd(d); };
  const daysBetween = (a, b) => Math.round((new Date(b + 'T12:00:00') - new Date(a + 'T12:00:00')) / 864e5);
  const monthStart = (iso) => iso.slice(0, 7) + '-01';
  const monthEnd = (iso) => { const d = new Date(iso.slice(0, 7) + '-01T12:00:00'); d.setMonth(d.getMonth() + 1); d.setDate(0); return ymd(d); };
  const weekStart = (iso) => { const d = new Date(iso + 'T12:00:00'); const day = (d.getDay() + 6) % 7; d.setDate(d.getDate() - day); return ymd(d); };
  const when = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');

  // ============================================================ the ledger
  const CATEGORIES = ['income', 'salary', 'housing', 'utilities', 'groceries', 'dining', 'transport', 'shopping', 'subscriptions', 'health',
    'education', 'entertainment', 'travel', 'donations', 'business', 'taxes', 'savings', 'transfers', 'fees', 'other'];
  const KEYWORDS = [
    [/rent|landlord|mortgage|lease/, 'housing'], [/power|electric|water|gas|utility|internet|broadband|phone|light/, 'utilities'],
    [/grocer|market|supermarket|foods|bakery/, 'groceries'], [/coffee|cafe|café|restaurant|pizza|burger|bar\b|diner|kitchen|bistro/, 'dining'],
    [/uber|lyft|taxi|transit|metro|fuel|petrol|parking|airline|rail|train/, 'transport'],
    [/netflix|spotify|subscription|prime|icloud|patreon|disney|youtube|hbo/, 'subscriptions'],
    [/pharmacy|clinic|doctor|dental|health|hospital/, 'health'], [/school|course|tuition|university|books?\b/, 'education'],
    [/shelter|charity|donat|fund\b|foundation|relief/, 'donations'], [/salary|payroll|wage/, 'salary'], [/\btax|irs|hmrc|revenue service/, 'taxes'],
    [/hotel|airbnb|travel|hostel/, 'travel'], [/cinema|game|concert|theatre|theater|museum/, 'entertainment'],
    [/store|shop|mart|amazon|outlet|boutique/, 'shopping'],
  ];
  const RECIPIENT_CATEGORY = { dining: 'dining', shopping: 'shopping', bills: 'utilities', donations: 'donations', utilities: 'utilities' };
  const CLAIMS = {
    transaction_id: 'transaction id', amount: 'amount', currency: 'currency', date: 'date', time: 'time', status: 'status',
    recipient_name: 'recipient', recipient_handle: 'recipient handle', recipient_category: 'recipient category', type: 'type',
    payer_pseudonym: 'my pseudonym', privacy_mode: 'privacy mode', opossum_fee: 'opossum fee', processor_fee: 'network fee',
    total_cost: 'total cost', recipient_receives: 'recipient received', fee_bearer: 'who paid fees', processor: 'processor',
    invoice_id: 'invoice id', invoice_reference: 'invoice reference', memo_commitment: 'proven note',
    payer_legal_name: 'my legal name', payer_identity_status: 'my identity status',
  };
  const AUDIENCES = {
    recipient: { label: 'recipient', fields: ['transaction_id', 'amount', 'currency', 'date', 'status'] },
    merchant: { label: 'merchant', fields: ['transaction_id', 'amount', 'currency', 'date', 'time', 'status', 'invoice_reference'] },
    accountant: { label: 'accountant', fields: ['transaction_id', 'amount', 'currency', 'date', 'recipient_name', 'recipient_category', 'type', 'opossum_fee', 'processor_fee', 'total_cost', 'invoice_reference'] },
    tax: { label: 'tax professional or authority', fields: ['transaction_id', 'amount', 'currency', 'date', 'recipient_name', 'type', 'total_cost', 'invoice_reference', 'payer_legal_name', 'payer_identity_status'] },
  };
  const FIXED_AUDIENCES = [
    ['bank or payment provider', 'what their service requires. card details go to them directly, never through opossum.'],
    ['government authority', 'only what the law requires, through a recorded legal case, and you are told unless an order forbids it.'],
    ['you', 'your complete ledger, always.'],
  ];

  function newLedger() {
    return {
      v: 1, updated: new Date().toISOString(),
      accounts: [{ id: 'main', name: 'everyday', type: 'checking', opening: '0.00' }],
      entries: [], rules: [], budgets: {}, goals: [], deleted: {},
      settings: { currency: 'USD', emergency_months: '3', business_limit: '', allocation: '', default_mode: 'pseudonymous',
        audiences: Object.fromEntries(Object.entries(AUDIENCES).map(([k, v]) => [k, v.fields.slice()])) },
    };
  }
  const L = () => S.ledger;
  const baseCurrency = () => (S.ledger && S.ledger.settings.currency) || 'USD';
  const live = (e) => e.status !== 'failed' && e.status !== 'cancelled' && e.status !== 'refunded' && !L().deleted[e.id];
  const inBase = (e) => (e.currency || baseCurrency()) === baseCurrency();

  function suggestCategory(merchant, kind, recipientCategory) {
    const m = String(merchant || '').toLowerCase().trim();
    const rule = L().rules.find((r) => r.match === m);
    if (rule) return rule.category;
    if (kind === 'income') return /salary|payroll|wage/.test(m) ? 'salary' : 'income';
    if (kind === 'transfer') return 'transfers';
    for (const [re, cat] of KEYWORDS) if (re.test(m)) return cat;
    return RECIPIENT_CATEGORY[recipientCategory] || 'other';
  }
  function learn(merchant, category) {
    const m = String(merchant || '').toLowerCase().trim();
    if (!m) return;
    const rules = L().rules;
    const existing = rules.find((r) => r.match === m);
    if (existing) existing.category = category; else rules.push({ match: m, category });
    for (const e of L().entries) if (e.auto && String(e.merchant).toLowerCase().trim() === m) { e.category = category; e.modified = Date.now(); }
  }
  function addEntry(entry) {
    const e = { id: uid(), currency: baseCurrency(), account: 'main', note: '', business: false, tax: false, reimbursable: false,
      reimbursed: false, status: 'settled', source: 'manual', ...entry, modified: Date.now() };
    L().entries.push(e);
    return e;
  }

  // merge two ledgers (this device and the backup): newest change wins per entry
  function merge(a, b) {
    if (!a) return b; if (!b) return a;
    const out = JSON.parse(JSON.stringify(new Date(a.updated) >= new Date(b.updated) ? a : b));
    const other = out === a ? b : a;
    const byId = new Map(out.entries.map((e) => [e.id, e]));
    for (const e of other.entries) { const mine = byId.get(e.id); if (!mine || (e.modified || 0) > (mine.modified || 0)) byId.set(e.id, e); }
    out.deleted = { ...(other.deleted || {}), ...(out.deleted || {}) };
    out.entries = Array.from(byId.values()).filter((e) => !out.deleted[e.id]);
    for (const key of ['accounts', 'goals']) {
      const ids = new Set(out[key].map((x) => x.id));
      for (const x of other[key] || []) if (!ids.has(x.id)) out[key].push(x);
    }
    const rules = new Map((other.rules || []).map((r) => [r.match, r]));
    for (const r of out.rules) rules.set(r.match, r);
    out.rules = Array.from(rules.values());
    return out;
  }

  // save locally at once, back up shortly after
  function changed() {
    L().updated = new Date().toISOString();
    $('#saveState').textContent = 'saving…';
    clearTimeout(S.saveTimer);
    S.saveTimer = setTimeout(() => { save().catch((err) => toast(err.message, 'alarm')); }, 700);
    render();
  }
  async function save(force) {
    if (!S.ledgerKey || S.saving) return;
    S.saving = true;
    try {
      const ciphertext = await seal(S.ledgerKey, L());
      await idb.set('ledger:' + S.ns, { ciphertext, version: S.version });
      for (let attempt = 0; attempt < 2; attempt++) {
        const r = await call('/backup', 'PUT', { expected_version: S.version, ciphertext: await seal(S.ledgerKey, L()) });
        if (r.res.ok) { S.version = r.data.version; break; }
        if (r.code === 'backup_conflict') { await pullBackup(); continue; }
        if (r.res.status === 401) { $('#saveState').textContent = 'saved on this device'; return; }
        throw new Error(errText(r.data, r.res.status));
      }
      await idb.set('ledger:' + S.ns, { ciphertext: await seal(S.ledgerKey, L()), version: S.version });
      $('#saveState').textContent = 'saved · encrypted backup v' + S.version;
      if (force) toast('backed up. the relay stores only ciphertext.', 'trust');
    } finally { S.saving = false; }
  }
  async function pullBackup() {
    const b = await api('/backup');
    S.version = b.version;
    if (b.ciphertext) S.ledger = merge(L(), await unseal(S.ledgerKey, b.ciphertext));
  }

  // pull settled payments from the relay into the ledger (also restores a lost device)
  function entryFromPayment(p, extra) {
    return {
      date: (p.settled_at || p.created_at).slice(0, 10), kind: 'expense', amount: p.total_cost, currency: p.currency,
      merchant: p.recipient.name, category: suggestCategory(p.recipient.name, 'expense', p.recipient.category), auto: true,
      source: 'opossum', tx_id: p.id, status: p.status, mode: p.mode, test: p.test_money,
      fees: { opossum: p.opossum_fee, processor: p.processor_fee }, recipient_receives: p.recipient_receives,
      receipt: p.receipt || null, ...(extra || {}),
    };
  }
  async function syncPayments() {
    const list = await api('/payments?limit=500');
    let touched = false;
    for (const p of list) {
      const e = L().entries.find((x) => x.tx_id === p.id);
      if (!e) {
        if (p.status === 'settled' || p.status === 'pending_payment') { addEntry(entryFromPayment(p)); touched = true; }
      } else if (e.status !== p.status || (!e.receipt && p.receipt)) {
        e.status = p.status; e.receipt = p.receipt || e.receipt; e.date = (p.settled_at || p.created_at).slice(0, 10); e.modified = Date.now(); touched = true;
      }
    }
    if (touched) changed();
  }

  // ============================================================ computations (budgeting engine)
  const entries = () => L().entries.filter((e) => live(e) && inBase(e));
  function sum(list) { return list.reduce((acc, e) => acc + cents(e.amount), 0); }
  const between = (list, from, to) => list.filter((e) => e.date >= from && e.date <= to);
  const expenses = (from, to) => between(entries().filter((e) => e.kind === 'expense'), from, to);
  const incomes = (from, to) => between(entries().filter((e) => e.kind === 'income'), from, to);

  function balances() {
    const out = L().accounts.map((a) => ({ ...a, balance: cents(a.opening) }));
    const byId = Object.fromEntries(out.map((a) => [a.id, a]));
    for (const e of entries()) {
      const acct = byId[e.account] || byId.main || out[0];
      if (!acct) continue;
      if (e.kind === 'income') acct.balance += cents(e.amount);
      else acct.balance -= cents(e.amount);
    }
    return out;
  }
  function monthlyAverage(kind, months) {
    const end = today();
    const start = addDays(end, -30 * months);
    const list = kind === 'income' ? incomes(start, end) : expenses(start, end);
    return Math.round(sum(list) / months);
  }
  const CADENCES = [[6, 8, 7, 'week'], [13, 16, 14, 'two weeks'], [26, 35, 30.44, 'month'], [85, 95, 91.3, 'quarter'], [355, 375, 365, 'year']];
  function recurring() {
    const groups = {};
    for (const e of entries()) {
      if (e.kind !== 'expense') continue;
      const key = String(e.merchant).toLowerCase().trim();
      (groups[key] = groups[key] || []).push(e);
    }
    const out = [];
    for (const list of Object.values(groups)) {
      if (list.length < 2) continue;
      list.sort((a, b) => (a.date < b.date ? -1 : 1));
      const gaps = list.slice(1).map((e, i) => daysBetween(list[i].date, e.date)).sort((a, b) => a - b);
      const gap = gaps[Math.floor(gaps.length / 2)];
      const cadence = CADENCES.find(([lo, hi]) => gap >= lo && gap <= hi);
      if (!cadence) continue;
      const amounts = list.map((e) => cents(e.amount)).sort((a, b) => a - b);
      const median = amounts[Math.floor(amounts.length / 2)];
      if (amounts.some((a) => Math.abs(a - median) > median * 0.2)) continue;
      const last = list[list.length - 1];
      out.push({ merchant: last.merchant, category: last.category, every: cadence[3], amount: median,
        monthly: Math.round(median * 30.44 / cadence[2]), next: addDays(last.date, Math.round(cadence[2])) });
    }
    return out.sort((a, b) => b.monthly - a.monthly);
  }
  function stats() {
    const t = today();
    const ms = monthStart(t), me = monthEnd(t);
    const spentMonth = sum(expenses(ms, me));
    const incomeMonth = sum(incomes(ms, me));
    const rec = recurring();
    const recurringMonthly = rec.reduce((a, r) => a + r.monthly, 0);
    const subscriptions = rec.filter((r) => r.category === 'subscriptions').reduce((a, r) => a + r.monthly, 0);
    const avgIncome = monthlyAverage('income', 3);
    const avgSpend = monthlyAverage('expense', 3);
    const yearStart = t.slice(0, 4) + '-01-01';
    const all = entries();
    return {
      balance: balances().reduce((a, x) => a + x.balance, 0),
      spentMonth, incomeMonth, spentWeek: sum(expenses(weekStart(t), t)),
      savingsRate: incomeMonth > 0 ? Math.round(((incomeMonth - spentMonth) / incomeMonth) * 100) : null,
      recurring: rec, recurringMonthly, subscriptions, avgIncome, avgSpend,
      disposable: avgIncome - recurringMonthly,
      businessMonth: sum(expenses(ms, me).filter((e) => e.business)),
      taxYear: sum(between(all.filter((e) => e.tax || e.business || e.category === 'donations'), yearStart, t)),
      upcoming: rec.filter((r) => r.next >= t && r.next <= addDays(t, 30)).sort((a, b) => (a.next < b.next ? -1 : 1)),
      otherCurrencies: L().entries.filter((e) => live(e) && !inBase(e)).length,
    };
  }

  // ============================================================ rendering: rooms
  const ROOMS = ['overview', 'pay', 'ledger', 'budgets', 'reports', 'receipts', 'privacy', 'security'];
  const renderers = {};
  function go(room, focus) {
    if (!ROOMS.includes(room)) room = 'overview';
    S.room = room;
    $$('.room').forEach((sec) => { sec.hidden = sec.dataset.room !== room; });
    $$('#rooms button').forEach((b) => b.setAttribute('aria-current', b.dataset.room === room ? 'page' : 'false'));
    if (!location.hash.startsWith('#' + room)) history.replaceState(null, '', '#' + room);
    if (focus !== false) $('#room-' + room + ' h2').focus({ preventScroll: true });
    window.scrollTo(0, 0);
    render();
  }
  function render() { if (S.ledger && S.room && renderers[S.room]) guard(() => renderers[S.room]()); }
  $('#rooms').addEventListener('click', (e) => { const b = e.target.closest('button[data-room]'); if (b && S.ledger) go(b.dataset.room); });

  function metric(v, l) { return h('div', { class: 'metric' }, h('div', { class: 'v' }, v), h('div', { class: 'l' }, l)); }
  function bar(ratio, tone) {
    const i = h('i');
    i.style.width = Math.max(0, Math.min(100, Math.round(ratio * 100))) + '%';
    return h('div', { class: 'bar' + (tone ? ' ' + tone : '') }, i);
  }
  const categoryOptions = (withBlank) => (withBlank ? [['', withBlank]] : []).concat(CATEGORIES.map((c) => [c, c]));

  renderers.overview = () => {
    const st = stats();
    $('#ovBalance').textContent = fmt(st.balance);
    $('#ovMonth').textContent = fmt(st.spentMonth);
    $('#ovMetrics').replaceChildren(
      metric(fmt(st.incomeMonth), 'income this month'), metric(fmt(st.spentWeek), 'spent this week'),
      metric(st.savingsRate == null ? '—' : st.savingsRate + '%', 'savings rate this month'),
      metric(fmt(st.disposable), 'disposable income / month'), metric(fmt(st.recurringMonthly), 'recurring / month'),
      metric(fmt(st.subscriptions), 'subscriptions / month'), metric(fmt(st.businessMonth), 'business expenses this month'),
      metric(fmt(st.taxYear), 'tax-relevant this year'),
    );
    const days = []; for (let i = 29; i >= 0; i--) days.push(addDays(today(), -i));
    const per = Object.fromEntries(days.map((d) => [d, 0]));
    for (const e of expenses(days[0], days[29])) per[e.date] += cents(e.amount);
    const values = days.map((d) => per[d]);
    const max = Math.max(1, ...values);
    const x = (i) => (i * 600) / 29; const y = (v) => 146 - (v / max) * 130;
    const line = values.map((v, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(v).toFixed(1)).join(' ');
    $('#ovChart g').replaceChildren(
      svg('path', { d: line + ' L600 150 L0 150 Z', fill: '#a9b0d0', 'fill-opacity': '0.16' }),
      svg('path', { d: line, fill: 'none', stroke: '#eef0f8', 'stroke-width': '1.4', 'vector-effect': 'non-scaling-stroke' }),
      ...values.map((v, i) => svg('rect', { x: Math.max(0, x(i) - 10), y: 0, width: 20, height: 150, fill: 'transparent' }, svg('title', {}, days[i] + ' · ' + fmt(v)))),
    );
    rows('#ovUpcoming', st.upcoming, (r, tr) => tr.append(td(r.next), td(r.merchant), td(fmt(r.amount), 'num'), td(r.every)), 'nothing recurring due in the next 30 days.');
    const budgets = Object.entries(L().budgets);
    const box = $('#ovBudgets');
    box.replaceChildren();
    if (!budgets.length) box.append(h('p', { class: 'note' }, 'no budgets yet. set them in budgets.'));
    const ms = monthStart(today());
    for (const [cat, limit] of budgets) {
      const spent = sum(expenses(ms, today()).filter((e) => e.category === cat));
      const lim = cents(limit);
      box.append(h('div', { class: 'budget' }, h('div', { class: 'actions' }, h('span', null, cat), h('span', { class: 'spacer' }), h('span', { class: 'faint' }, fmt(spent) + ' of ' + fmt(lim))),
        bar(lim ? spent / lim : 0, spent > lim ? 'over' : '')));
    }
    const recent = L().entries.filter((e) => !L().deleted[e.id]).sort((a, b) => (a.date < b.date ? 1 : -1)).slice(0, 8);
    rows('#ovRecent', recent, (e, tr) => tr.append(td(e.date), td(e.merchant), td(e.category), td((e.kind === 'income' ? '+' : '−') + fmt(cents(e.amount), e.currency), 'num' + (e.kind === 'income' ? ' pos' : '')),
      h('td', null, statusTag(e))), 'nothing yet. make a payment or add an entry in the ledger.');
    if (st.otherCurrencies) $('#ovMetrics').append(metric(String(st.otherCurrencies), 'entries in other currencies (not in totals)'));
  };
  function statusTag(e) {
    if (e.test) return h('span', { class: 'tag test' }, 'test money');
    if (e.status === 'pending_payment') return h('span', { class: 'tag' }, 'pending');
    if (e.status === 'refunded') return h('span', { class: 'tag' }, 'refunded');
    if (e.status === 'failed' || e.status === 'cancelled') return h('span', { class: 'tag alarm' }, e.status);
    if (e.receipt) return h('span', { class: 'tag trust' }, 'signed');
    return '';
  }

  // ------------------------------------------------------------ pay
  const MODE_NOTES = {
    private: 'the recipient sees a one-time id, the amount and what they receive. nothing links this payment to any other.',
    pseudonymous: 'the recipient sees an id that stays the same for them only, so they can recognise you as a returning customer, not who you are. other recipients see a different id.',
    disclosure: 'the recipient sees your pseudonym plus only the fields you tick.',
    public: 'the recipient sees your legal name and email from your identity vault.',
  };
  async function loadRecipients() {
    if (!S.recipients.length) S.recipients = await api('/recipients');
    return S.recipients;
  }
  renderers.pay = async () => {
    const list = await loadRecipients();
    const sel = $('#payRecipient');
    if (sel.options.length !== list.length) {
      options(sel, list.map((r) => [r.handle, r.name + (r.test_money && !/sandbox/i.test(r.name) ? ' · test money' : '')]), sel.value || (list[0] && list[0].handle));
      options($('#payCurrency'), S.config.currencies.map((c) => [c, c]), baseCurrency());
      options($('#payType'), S.config.types.filter((t) => t !== 'invoice').map((t) => [t, t]), 'purchase');
      options($('#payCategory'), categoryOptions('suggest for me'), '');
      $('#payMode').value = L().settings.default_mode || 'pseudonymous';
    }
    modeChanged();
  };
  function modeChanged() {
    const mode = $('#payMode').value;
    $('#modeNote').textContent = MODE_NOTES[mode];
    $('#discloseChecks').hidden = mode !== 'disclosure';
  }
  $('#payMode').addEventListener('change', modeChanged);
  function resetReview() {
    S.quote = null; S.draft = null;
    $('#payBreakdown').replaceChildren(); $('#payConfirmRow').hidden = true; $('#payResult').replaceChildren();
    $('#payReviewNote').textContent = 'every fee is shown before you confirm.';
  }
  $('#payForm').addEventListener('input', () => { if (S.quote) resetReview(); });
  $('#payEdit').addEventListener('click', resetReview);

  function breakdown(q) {
    const row = (label, value, cls) => h('div', { class: cls }, h('dt', null, label), h('dd', null, value));
    return h('dl', { class: 'breakdown' },
      row('amount sent', fmt(cents(q.amount_sent), q.currency)),
      row('opossum fee · ' + q.fee_rule, fmt(cents(q.opossum_fee), q.currency)),
      row('payment / network fee', fmt(cents(q.processor_fee), q.currency)),
      row('total cost to you', fmt(cents(q.total_cost), q.currency), 'total'),
      row('recipient receives', fmt(cents(q.recipient_receives), q.currency), 'receives'),
    );
  }
  $('#payForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const amount = parseMoney(f.amount.value);
    if (!amount || cents(amount) <= 0) { toast('enter an amount like 12.50', 'alarm'); f.amount.focus(); return; }
    guard(async () => {
      const draft = {
        recipient: f.recipient.value, invoice: f.invoice.value.trim() || null, amount, currency: f.currency.value,
        type: f.type.value, fee_bearer: f.fee_bearer.value, mode: f.mode.value,
        disclose: f.mode.value === 'disclosure' ? ['legal_name', 'email'].filter((k) => f['disclose_' + k].checked) : [],
        message: f.message.value.trim(), category: f.category.value, note: f.note.value.trim(),
        business: f.business.checked, tax: f.tax.checked, reimbursable: f.reimbursable.checked, commit: f.commit.checked,
        idempotency_key: hex(random(16)),
      };
      if (draft.commit && !draft.note) { toast('write the note you want to be able to prove', 'alarm'); return; }
      const q = await api('/quote', 'POST', { recipient: draft.recipient, amount, currency: draft.currency, type: draft.invoice ? 'invoice' : draft.type, fee_bearer: draft.fee_bearer });
      S.quote = q; S.draft = draft;
      $('#payBreakdown').replaceChildren(breakdown(q));
      $('#payReviewNote').replaceChildren('to ', h('strong', null, q.recipient.name), ' · ', MODE_NOTES[draft.mode].split('.')[0] + '.',
        q.recipient.test_money ? h('span', null, ' ', h('span', { class: 'tag test' }, 'test money — nothing real is paid')) : '');
      $('#payConfirmRow').hidden = false;
      $('#payResult').replaceChildren();
      $('#payConfirm').focus();
    }, e.submitter);
  });

  async function sendPayment(confirmDuplicate) {
    const d = S.draft, q = S.quote;
    let memo = null;
    const body = {
      recipient: d.recipient, amount: d.amount, currency: d.currency, type: d.invoice ? 'invoice' : d.type, fee_bearer: d.fee_bearer,
      mode: d.mode, disclose: d.disclose, expected_total: q.total_cost,
      nonce: hex(random(16)), ts: Math.floor(Date.now() / 1000), idempotency_key: d.idempotency_key,
    };
    if (d.invoice) body.invoice = d.invoice;
    if (d.message) body.message_to_recipient = d.message;
    if (d.commit) { memo = { text: d.note, salt: hex(random(16)) }; body.memo_commitment = await sha256hex(memo.salt + ':' + memo.text); }
    if (confirmDuplicate) body.confirm_duplicate = true;
    const bytes = enc.encode(JSON.stringify(body));
    const signature = await signBytes(S.device.privateKey, bytes);
    return { memo, r: await call('/payments', 'POST', bytes, { 'X-Opossum-Device': S.device.id, 'X-Opossum-Signature': signature }) };
  }
  $('#payConfirm').addEventListener('click', (e) => guard(async () => {
    if (!S.draft || !S.quote) return;
    let { memo, r } = await sendPayment(false);
    if (r.code === 'possible_duplicate') {
      if (!(await ask('pay again?', r.data.error.message, 'pay again'))) return;
      S.draft.idempotency_key = hex(random(16));
      ({ memo, r } = await sendPayment(true));
    }
    if (r.code === 'quote_changed') {
      S.quote = { ...r.data.error.quote, recipient: S.quote.recipient };
      $('#payBreakdown').replaceChildren(breakdown(S.quote));
      toast('the fees changed. review the new total and confirm again.', 'alarm');
      return;
    }
    if (r.res.status === 401) { lock('your session ended. unlock to continue.'); return; }
    if (!r.res.ok) throw new Error(errText(r.data, r.res.status));
    const p = r.data;
    const d = S.draft;
    const existing = L().entries.find((x) => x.tx_id === p.id);
    if (!existing) {
      addEntry(entryFromPayment(p, {
        category: d.category || suggestCategory(p.recipient.name, 'expense', p.recipient.category), auto: !d.category,
        note: d.note, business: d.business, tax: d.tax, reimbursable: d.reimbursable, memo,
      }));
      if (d.category) learn(p.recipient.name, d.category);
      changed();
    }
    if (p.status === 'pending_payment' && p.checkout_url) {
      let url;
      try { url = new URL(p.checkout_url); } catch (err) { url = null; }
      if (!url || url.protocol !== 'https:' || url.hostname !== 'checkout.stripe.com') throw new Error('the processor returned an unexpected payment page; not opening it.');
      await save();
      $('#payResult').replaceChildren(h('p', { class: 'msg' }, 'opening the secure payment page…'));
      location.assign(url.href);
      return;
    }
    showPaid(p);
    $('#payForm').reset();
    $('#payMode').value = L().settings.default_mode || 'pseudonymous';
    S.draft = null; S.quote = null; $('#payConfirmRow').hidden = true;
  }, e.currentTarget));
  function showPaid(p) {
    $('#payResult').replaceChildren(
      h('div', { class: 'verdict ok' }, h('h4', null, p.status === 'settled' ? 'paid · receipt signed' : 'payment ' + p.status),
        h('dl', { class: 'claims' },
          h('dt', null, 'transaction'), h('dd', { class: 'code' }, p.id),
          h('dt', null, 'recipient saw you as'), h('dd', { class: 'code' }, p.payer_pseudonym),
          h('dt', null, 'also shown to them'), h('dd', null, p.shown_to_recipient.length ? p.shown_to_recipient.join(', ') : 'nothing else'),
          h('dt', null, 'total cost'), h('dd', null, fmt(cents(p.total_cost), p.currency)),
          h('dt', null, 'recipient received'), h('dd', null, fmt(cents(p.recipient_receives), p.currency)))),
      p.test_money ? h('p', { class: 'faint' }, 'sandbox: test money only. the receipt says so, so it cannot pass as a real payment.') : '',
    );
  }

  // ------------------------------------------------------------ ledger
  renderers.ledger = () => {
    options($('#entryAccount'), L().accounts.map((a) => [a.id, a.name]), $('#entryAccount').value || 'main');
    if (!$('#entryCategory').options.length) options($('#entryCategory'), categoryOptions('suggest for me'), '');
    if (!$('#entryForm').elements.date.value) $('#entryForm').elements.date.value = today();
    const q = $('#ledgerSearch').value.trim().toLowerCase();
    const month = $('#ledgerMonth').value;
    const list = L().entries.filter((e) => !L().deleted[e.id])
      .filter((e) => !month || e.date.startsWith(month))
      .filter((e) => !q || [e.merchant, e.note, e.category].join(' ').toLowerCase().includes(q))
      .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : (b.modified || 0) - (a.modified || 0)));
    rows('#ledgerTable', list.slice(0, 500), (e, tr) => {
      const sel = h('select', { 'aria-label': 'category for ' + e.merchant, on: { change: (ev) => { e.category = ev.target.value; e.auto = false; e.modified = Date.now(); learn(e.merchant, e.category); changed(); } } },
        CATEGORIES.map((c) => h('option', { value: c, selected: c === e.category }, c)));
      const flags = [e.business && 'business', e.tax && 'tax', e.reimbursable && (e.reimbursed ? 'reimbursed' : 'to reimburse'), e.memo && 'proven note'].filter(Boolean).join(', ');
      const actions = h('td', null);
      if (e.reimbursable && !e.reimbursed) actions.append(h('button', { type: 'button', class: 'btn quiet small', on: { click: () => { e.reimbursed = true; e.modified = Date.now(); changed(); } } }, 'mark reimbursed'));
      if (e.source !== 'opossum') actions.append(h('button', { type: 'button', class: 'btn quiet small', on: { click: async () => {
        if (!(await ask('delete this entry?', e.merchant + ' · ' + e.date, 'delete'))) return;
        L().deleted[e.id] = Date.now(); L().entries = L().entries.filter((x) => x.id !== e.id); changed();
      } } }, 'delete'));
      tr.append(td(e.date), h('td', { class: 'wrap' }, e.merchant, e.note ? h('div', { class: 'faint' }, e.note) : ''), h('td', null, sel), td(flags || '—'),
        td((e.kind === 'income' ? '+' : e.kind === 'transfer' ? '→ ' : '−') + fmt(cents(e.amount), e.currency), 'num' + (e.kind === 'income' ? ' pos' : '')),
        h('td', null, e.source === 'opossum' ? statusTag(e) : h('span', { class: 'tag' }, e.source)), actions);
    }, 'no entries match.');
    rows('#accountsTable', balances(), (a, tr) => tr.append(td(a.name), td(a.type), td(fmt(a.balance), 'num')));
  };
  $('#ledgerSearch').addEventListener('input', () => render());
  $('#ledgerMonth').addEventListener('change', () => render());
  $('#entryForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const amount = parseMoney(f.amount.value);
    if (!amount || cents(amount) <= 0 || !f.merchant.value.trim() || !f.date.value) { toast('date, merchant and a positive amount are needed', 'alarm'); return; }
    const merchant = f.merchant.value.trim();
    const category = f.category.value || suggestCategory(merchant, f.kind.value);
    addEntry({ date: f.date.value, kind: f.kind.value, merchant, amount, account: f.account.value, category, auto: !f.category.value,
      note: f.note.value.trim(), business: f.business.checked, tax: f.tax.checked, reimbursable: f.reimbursable.checked });
    if (f.category.value) learn(merchant, f.category.value);
    e.target.reset(); f.date.value = today();
    changed();
    toast('added · filed under ' + category);
  });
  $('#accountForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const opening = f.opening.value.trim() ? parseMoney(f.opening.value) : '0.00';
    if (!f.name.value.trim() || opening == null) { toast('name and an opening balance like 250.00', 'alarm'); return; }
    L().accounts.push({ id: uid(), name: f.name.value.trim(), type: f.type.value, opening });
    e.target.reset();
    changed();
  });
  // bank statement import: date, description, amount (negative = money out)
  function parseCsv(text) {
    const out = []; let row = [], cell = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) { if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') quoted = false; else cell += c; }
      else if (c === '"') quoted = true;
      else if (c === ',') { row.push(cell); cell = ''; }
      else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cell); out.push(row); row = []; cell = ''; }
      else cell += c;
    }
    if (cell || row.length) { row.push(cell); out.push(row); }
    return out.filter((r) => r.some((x) => x.trim()));
  }
  $('#importFile').addEventListener('change', (e) => guard(async () => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > 2_000_000) throw new Error('that file is larger than 2 MB');
    const text = await file.text();
    if (/\.(ofx|qfx)$/i.test(file.name) || /<OFX>/i.test(text)) { importOfx(text); return; }
    const table = parseCsv(text);
    const head = table[0].map((x) => x.trim().toLowerCase());
    const col = (names) => head.findIndex((x) => names.some((n) => x.includes(n)));
    const di = col(['date']), mi = col(['description', 'merchant', 'payee', 'name', 'details']), ai = col(['amount', 'value']);
    if (di < 0 || mi < 0 || ai < 0) throw new Error('the csv needs date, description and amount columns');
    let added = 0;
    for (const r of table.slice(1)) {
      const raw = String(r[ai] || '').replace(/[^0-9.\-]/g, '');
      const amount = parseMoney(raw.replace('-', ''));
      const d = new Date(r[di]);
      if (!amount || isNaN(d)) continue;
      const kind = raw.startsWith('-') ? 'expense' : 'income';
      const merchant = String(r[mi]).trim().slice(0, 80);
      addEntry({ date: ymd(d), kind, merchant, amount, category: suggestCategory(merchant, kind), auto: true, source: 'import' });
      added++;
    }
    changed();
    toast('imported ' + added + ' entries. they stay on this device.', 'trust');
  }));

  // OFX / QFX bank statements (what most banks offer as "download for quicken / quickbooks")
  function parseOfx(text) {
    const out = [];
    for (const block of text.split(/<STMTTRN>/i).slice(1)) {
      const body = block.split(/<\/STMTTRN>/i)[0];
      const field = (name) => { const m = body.match(new RegExp('<' + name + '>([^<\\r\\n]*)', 'i')); return m ? m[1].trim() : ''; };
      const posted = field('DTPOSTED');
      const amount = field('TRNAMT');
      if (!/^\d{8}/.test(posted) || !/^[-+]?\d+(\.\d+)?$/.test(amount)) continue;
      const unescape = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
      out.push({ date: posted.slice(0, 4) + '-' + posted.slice(4, 6) + '-' + posted.slice(6, 8), amount, fitid: field('FITID'),
        name: unescape(field('NAME') || field('PAYEE') || field('MEMO') || 'bank transaction'), memo: unescape(field('MEMO')) });
    }
    return out;
  }
  function importOfx(text) {
    const known = new Set(L().entries.map((e) => e.fitid).filter(Boolean));
    let added = 0, skipped = 0;
    for (const t of parseOfx(text)) {
      if (t.fitid && known.has(t.fitid)) { skipped++; continue; }
      const kind = t.amount.startsWith('-') ? 'expense' : 'income';
      const amount = parseMoney(t.amount.replace(/^[-+]/, ''));
      if (!amount) continue;
      const merchant = t.name.slice(0, 80);
      addEntry({ date: t.date, kind, merchant, amount, note: t.memo && t.memo !== t.name ? t.memo.slice(0, 300) : '',
        category: suggestCategory(merchant, kind), auto: true, source: 'import', fitid: t.fitid || undefined });
      added++;
    }
    changed();
    toast('imported ' + added + ' transactions' + (skipped ? ' (' + skipped + ' already in your ledger)' : '') + '. they stay on this device.', 'trust');
  }

  // ------------------------------------------------------------ budgets
  renderers.budgets = () => {
    const st = stats();
    if (!$('#budgetCategory').options.length) options($('#budgetCategory'), CATEGORIES.filter((c) => !['income', 'salary'].includes(c)).map((c) => [c, c]), 'dining');
    $('#bgMetrics').replaceChildren(
      metric(fmt(st.spentMonth), 'spent this month'), metric(fmt(st.avgSpend), 'average monthly spending'),
      metric(fmt(st.avgIncome), 'average monthly income'), metric(fmt(st.disposable), 'disposable income / month'),
    );
    const ms = monthStart(today());
    const box = $('#budgetList'); box.replaceChildren();
    for (const [cat, limit] of Object.entries(L().budgets)) {
      const spent = sum(expenses(ms, today()).filter((e) => e.category === cat));
      const lim = cents(limit);
      box.append(h('div', { class: 'budget' },
        h('div', { class: 'actions' }, h('span', null, cat), h('span', { class: 'spacer' }), h('span', { class: 'faint' }, fmt(spent) + ' of ' + fmt(lim) + ' · ' + (lim ? Math.round(spent / lim * 100) : 0) + '%'),
          h('button', { type: 'button', class: 'btn quiet small', on: { click: () => { delete L().budgets[cat]; changed(); } } }, 'remove')),
        bar(lim ? spent / lim : 0, spent > lim ? 'over' : '')));
    }
    if (!box.children.length) box.append(h('p', { class: 'note' }, 'no budgets yet.'));
    const goals = $('#goalList'); goals.replaceChildren();
    for (const g of L().goals) {
      const input = h('input', { value: g.saved, inputmode: 'decimal', 'aria-label': 'saved for ' + g.name, on: { change: (ev) => {
        const v = parseMoney(ev.target.value); if (v != null) { g.saved = v; changed(); } } } });
      goals.append(h('div', { class: 'budget' },
        h('div', { class: 'actions' }, h('span', null, g.name), h('span', { class: 'spacer' }), h('span', { class: 'faint' }, fmt(cents(g.saved)) + ' of ' + fmt(cents(g.target))),
          h('button', { type: 'button', class: 'btn quiet small', on: { click: () => { L().goals = L().goals.filter((x) => x.id !== g.id); changed(); } } }, 'remove')),
        bar(cents(g.target) ? cents(g.saved) / cents(g.target) : 0, 'good'), h('div', { class: 'fields' }, h('label', { class: 'field' }, h('span', null, 'saved so far'), input))));
    }
    if (!goals.children.length) goals.append(h('p', { class: 'note' }, 'no goals yet.'));
    const s = L().settings;
    const rf = $('#reserveForm').elements;
    if (document.activeElement.form !== $('#reserveForm')) { rf.months.value = s.emergency_months || ''; rf.business.value = s.business_limit || ''; rf.allocation.value = s.allocation || ''; }
    const savings = balances().filter((a) => a.type === 'savings').reduce((acc, a) => acc + a.balance, 0);
    const target = Math.round(st.avgSpend * Number(s.emergency_months || 0));
    const bl = cents(s.business_limit);
    const info = $('#reserveInfo'); info.replaceChildren(
      h('div', { class: 'budget' }, h('div', { class: 'actions' }, h('span', null, 'emergency reserve'), h('span', { class: 'spacer' }), h('span', { class: 'faint' }, fmt(savings) + ' of ' + fmt(target))), bar(target ? savings / target : 0, 'good')),
      h('p', { class: 'faint' }, 'counted from accounts of type savings.'),
    );
    if (bl) info.append(h('div', { class: 'budget' }, h('div', { class: 'actions' }, h('span', null, 'business expenses this month'), h('span', { class: 'spacer' }), h('span', { class: 'faint' }, fmt(st.businessMonth) + ' of ' + fmt(bl))), bar(st.businessMonth / bl, st.businessMonth > bl ? 'over' : '')));
    rows('#recurringTable', st.recurring, (r, tr) => tr.append(td(r.merchant), td(r.every), td(fmt(r.amount), 'num'), td(fmt(r.monthly), 'num'), td(r.next)), 'nothing recurring detected yet. it needs two or more payments at a regular interval.');
    const allocation = cents(s.allocation);
    const discretionary = Math.max(0, st.avgSpend - st.recurringMonthly);
    const monthlyNet = st.avgIncome - st.recurringMonthly - discretionary - allocation;
    $('#projection').replaceChildren(...[1, 2, 3].map((m) => metric(fmt(st.balance + monthlyNet * m), 'in ' + (30 * m) + ' days')),
      metric(fmt(monthlyNet), 'expected change / month'));
  };
  $('#budgetForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const v = parseMoney(e.target.elements.limit.value);
    if (!v) { toast('enter a monthly limit like 300', 'alarm'); return; }
    L().budgets[e.target.elements.category.value] = v; e.target.elements.limit.value = ''; changed();
  });
  $('#goalForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const target = parseMoney(f.target.value), saved = f.saved.value.trim() ? parseMoney(f.saved.value) : '0.00';
    if (!f.name.value.trim() || !target || saved == null) { toast('a name and a target amount are needed', 'alarm'); return; }
    L().goals.push({ id: uid(), name: f.name.value.trim(), target, saved }); e.target.reset(); changed();
  });
  $('#reserveForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements, s = L().settings;
    s.emergency_months = f.months.value.trim(); s.business_limit = f.business.value.trim() ? (parseMoney(f.business.value) || '') : '';
    s.allocation = f.allocation.value.trim() ? (parseMoney(f.allocation.value) || '') : '';
    changed(); toast('saved');
  });

  // ------------------------------------------------------------ reports
  const REPORTS = {
    statement: 'monthly statement', income: 'income report', expense: 'expense report', business: 'business transactions',
    tax: 'tax report', reimbursement: 'reimbursement report', custom: 'custom report',
  };
  function buildReport(kind, from, to, category) {
    const all = between(L().entries.filter((e) => live(e)), from, to).sort((a, b) => (a.date < b.date ? -1 : 1));
    const pick = {
      statement: () => all, income: () => all.filter((e) => e.kind === 'income'), expense: () => all.filter((e) => e.kind === 'expense'),
      business: () => all.filter((e) => e.business), reimbursement: () => all.filter((e) => e.reimbursable),
      tax: () => all.filter((e) => e.tax || e.business || e.category === 'donations' || e.category === 'taxes'),
      custom: () => all.filter((e) => !category || e.category === category),
    }[kind]();
    const columns = ['date', 'merchant', 'category', 'kind', 'amount', 'currency', 'account', 'business', 'tax', 'reimbursable', 'reimbursed', 'note', 'opossum fee', 'network fee', 'transaction id', 'signed receipt'];
    const acct = Object.fromEntries(L().accounts.map((a) => [a.id, a.name]));
    const data = pick.map((e) => [e.date, e.merchant, e.category, e.kind, (e.kind === 'income' ? '' : '-') + fromCents(cents(e.amount)), e.currency || baseCurrency(),
      acct[e.account] || '', e.business ? 'yes' : '', e.tax ? 'yes' : '', e.reimbursable ? 'yes' : '', e.reimbursed ? 'yes' : '', e.note || '',
      e.fees ? e.fees.opossum : '', e.fees ? e.fees.processor : '', e.tx_id || '', e.receipt ? 'yes' : '']);
    const inBaseList = pick.filter(inBase);
    const income = sum(inBaseList.filter((e) => e.kind === 'income'));
    const out = sum(inBaseList.filter((e) => e.kind !== 'income'));
    let summary = pick.length + ' entries · money in ' + fmt(income) + ' · money out ' + fmt(out) + ' · net ' + fmt(income - out);
    if (kind === 'statement') {
      const before = L().entries.filter((e) => live(e) && inBase(e) && e.date < from);
      const opening = L().accounts.reduce((a, x) => a + cents(x.opening), 0) + sum(before.filter((e) => e.kind === 'income')) - sum(before.filter((e) => e.kind !== 'income'));
      summary = 'opening balance ' + fmt(opening) + ' · closing balance ' + fmt(opening + income - out) + ' · ' + summary;
    }
    if (kind === 'reimbursement') summary += ' · still owed to you ' + fmt(sum(inBaseList.filter((e) => !e.reimbursed)));
    return { title: REPORTS[kind] + ' · ' + from + ' to ' + to, kind, from, to, columns, rows: data, summary, generated: new Date().toISOString(), entries: pick };
  }
  let lastReport = null;
  function reportFromForm() {
    const f = $('#reportForm').elements;
    if (!f.from.value || !f.to.value || f.from.value > f.to.value) { toast('choose a date range', 'alarm'); return null; }
    lastReport = buildReport(f.kind.value, f.from.value, f.to.value, f.category.value);
    return lastReport;
  }
  renderers.reports = () => {
    const f = $('#reportForm').elements;
    if (!f.from.value) { f.from.value = monthStart(today()); f.to.value = monthEnd(today()); }
    if (!$('#reportCategory').options.length) options($('#reportCategory'), categoryOptions('all'), '');
    const r = reportFromForm();
    if (!r) return;
    $('#reportTitle').textContent = r.title;
    $('#reportSummary').textContent = r.summary;
    const shown = [0, 1, 2, 3, 4, 7, 8, 10, 11];
    $('#reportTable thead').replaceChildren(h('tr', null, shown.map((i) => h('th', { class: i === 4 ? 'num' : null }, r.columns[i]))));
    rows('#reportTable', r.rows.slice(0, 300), (row, tr) => tr.append(...shown.map((i) => td(row[i], i === 4 ? 'num' : i === 11 ? 'wrap' : null))), 'no entries in this range.');
  };
  $('#reportForm').addEventListener('submit', (e) => { e.preventDefault(); render(); });
  function download(name, type, data) {
    const url = URL.createObjectURL(new Blob([data], { type }));
    const a = h('a', { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  const csvCell = (v) => {
    let s = String(v == null ? '' : v);
    if (/^[=+@\t\r]/.test(s) || (/^-/.test(s) && !/^-?\d+(\.\d+)?$/.test(s))) s = "'" + s; // no formula injection
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const toCsv = (r) => [r.columns, ...r.rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
  const fileBase = (r) => 'opossum-' + r.kind + '-' + r.from + '-to-' + r.to;
  $$('#reportForm [data-export]').forEach((btn) => btn.addEventListener('click', () => guard(async () => {
    const r = reportFromForm();
    if (!r) return;
    const kind = btn.dataset.export;
    if (kind === 'csv') download(fileBase(r) + '.csv', 'text/csv', toCsv(r));
    else if (kind === 'json') download(fileBase(r) + '.json', 'application/json', JSON.stringify({ ...r, entries: undefined }, null, 2));
    else if (kind === 'ofx') download(fileBase(r) + '.ofx', 'application/x-ofx', toOfx(r));
    else if (kind === 'qif') download(fileBase(r) + '.qif', 'application/qif', toQif(r));
    else if (kind === 'xlsx') download(fileBase(r) + '.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', xlsx(r));
    else if (kind === 'pdf') printReport(r);
  })));
  // OFX 1.02 (SGML): imported by QuickBooks, Xero, Quicken, Moneydance and GnuCash
  function toOfx(r) {
    const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/[\r\n]+/g, ' ');
    const d8 = (iso) => iso.replace(/-/g, '');
    const list = r.entries.filter(inBase);
    const signed = (e) => (e.kind === 'income' ? '' : '-') + fromCents(cents(e.amount));
    const closing = balances().reduce((a, x) => a + x.balance, 0);
    const tx = list.map((e) => ['<STMTTRN>', '<TRNTYPE>' + (e.kind === 'income' ? 'CREDIT' : e.kind === 'transfer' ? 'XFER' : 'DEBIT'),
      '<DTPOSTED>' + d8(e.date), '<TRNAMT>' + signed(e), '<FITID>' + esc(e.tx_id || e.id), '<NAME>' + esc(e.merchant).slice(0, 32),
      '<MEMO>' + esc([e.category, e.note].filter(Boolean).join(' · ')).slice(0, 255), '</STMTTRN>'].join('\r\n')).join('\r\n');
    const now = d8(today()) + '120000';
    return ['OFXHEADER:100', 'DATA:OFXSGML', 'VERSION:102', 'SECURITY:NONE', 'ENCODING:USASCII', 'CHARSET:1252', 'COMPRESSION:NONE', 'OLDFILEUID:NONE', 'NEWFILEUID:NONE', '',
      '<OFX>', '<SIGNONMSGSRSV1><SONRS><STATUS><CODE>0<SEVERITY>INFO</STATUS><DTSERVER>' + now + '<LANGUAGE>ENG</SONRS></SIGNONMSGSRSV1>',
      '<BANKMSGSRSV1><STMTTRNRS><TRNUID>1<STATUS><CODE>0<SEVERITY>INFO</STATUS><STMTRS><CURDEF>' + baseCurrency(),
      '<BANKACCTFROM><BANKID>000000000<ACCTID>OPOSSUM-LEDGER<ACCTTYPE>CHECKING</BANKACCTFROM>',
      '<BANKTRANLIST><DTSTART>' + d8(r.from) + '<DTEND>' + d8(r.to), tx, '</BANKTRANLIST>',
      '<LEDGERBAL><BALAMT>' + fromCents(closing) + '<DTASOF>' + now + '</LEDGERBAL>', '</STMTRS></STMTTRNRS></BANKMSGSRSV1>', '</OFX>', ''].join('\r\n');
  }
  function toQif(r) {
    const us = (iso) => iso.slice(5, 7) + '/' + iso.slice(8, 10) + '/' + iso.slice(0, 4);
    const clean = (s) => String(s || '').replace(/[\r\n^]+/g, ' ');
    return '!Type:Bank\n' + r.entries.filter(inBase).map((e) => ['D' + us(e.date), 'T' + (e.kind === 'income' ? '' : '-') + fromCents(cents(e.amount)),
      'P' + clean(e.merchant), e.note ? 'M' + clean(e.note) : null, 'L' + clean(e.category), '^'].filter(Boolean).join('\n')).join('\n') + '\n';
  }
  function printReport(r) {
    const sheet = $('#printSheet');
    const shown = [0, 1, 2, 3, 4, 5, 7, 8, 11, 14];
    sheet.replaceChildren(h('h1', null, r.title), h('p', null, r.summary), h('p', null, 'generated ' + when(r.generated) + ' from a private opossum ledger. amounts marked with a signed receipt can be verified at /opossum/verify.'),
      h('table', null, h('thead', null, h('tr', null, shown.map((i) => h('th', null, r.columns[i])))),
        h('tbody', null, r.rows.map((row) => h('tr', null, shown.map((i) => h('td', null, row[i])))))));
    window.print();
  }
  // minimal xlsx writer: a zip (stored, no compression) of the spreadsheetml parts
  const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(bytes) { let c = 0xffffffff; for (let i = 0; i < bytes.length; i++) c = CRC[(c ^ bytes[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
  function zip(files) {
    const parts = [], central = []; let offset = 0;
    for (const [name, text] of files) {
      const data = enc.encode(text), nameBytes = enc.encode(name), crc = crc32(data);
      const local = new DataView(new ArrayBuffer(30));
      [[0, 0x04034b50, 4], [4, 20, 2], [6, 0x0800, 2], [8, 0, 2], [10, 0, 2], [12, 0x21, 2], [14, crc, 4], [18, data.length, 4], [22, data.length, 4], [26, nameBytes.length, 2], [28, 0, 2]]
        .forEach(([o, v, n]) => (n === 4 ? local.setUint32(o, v, true) : local.setUint16(o, v, true)));
      const dir = new DataView(new ArrayBuffer(46));
      [[0, 0x02014b50, 4], [4, 20, 2], [6, 20, 2], [8, 0x0800, 2], [10, 0, 2], [12, 0, 2], [14, 0x21, 2], [16, crc, 4], [20, data.length, 4], [24, data.length, 4], [28, nameBytes.length, 2], [30, 0, 2], [32, 0, 2], [34, 0, 2], [36, 0, 2], [38, 0, 4], [42, offset, 4]]
        .forEach(([o, v, n]) => (n === 4 ? dir.setUint32(o, v, true) : dir.setUint16(o, v, true)));
      parts.push(new Uint8Array(local.buffer), nameBytes, data);
      central.push(new Uint8Array(dir.buffer), nameBytes);
      offset += 30 + nameBytes.length + data.length;
    }
    const size = central.reduce((a, p) => a + p.length, 0);
    const end = new DataView(new ArrayBuffer(22));
    [[0, 0x06054b50, 4], [4, 0, 2], [6, 0, 2], [8, files.length, 2], [10, files.length, 2], [12, size, 4], [16, offset, 4], [20, 0, 2]]
      .forEach(([o, v, n]) => (n === 4 ? end.setUint32(o, v, true) : end.setUint16(o, v, true)));
    return new Blob([...parts, ...central, new Uint8Array(end.buffer)]);
  }
  const xml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '');
  function xlsx(r) {
    const colName = (i) => String.fromCharCode(65 + i);
    const cell = (v, ci, ri) => (/^-?\d+(\.\d+)?$/.test(String(v)) && ci !== 14
      ? `<c r="${colName(ci)}${ri}"><v>${v}</v></c>`
      : `<c r="${colName(ci)}${ri}" t="inlineStr"><is><t>${xml(v)}</t></is></c>`);
    const sheetRows = [r.columns, ...r.rows].map((row, ri) => `<row r="${ri + 1}">${row.map((v, ci) => cell(v, ci, ri + 1)).join('')}</row>`).join('');
    return zip([
      ['[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'],
      ['_rels/.rels', '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'],
      ['xl/workbook.xml', '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="report" sheetId="1" r:id="rId1"/></sheets></workbook>'],
      ['xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'],
      ['xl/worksheets/sheet1.xml', `<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${sheetRows}</sheetData></worksheet>`],
    ]);
  }

  // ------------------------------------------------------------ receipts and disclosure
  const selectedReceipts = new Set();
  const withReceipts = () => L().entries.filter((e) => e.receipt && !L().deleted[e.id]).sort((a, b) => (a.date < b.date ? 1 : -1));
  renderers.receipts = () => {
    rows('#receiptsTable', withReceipts(), (e, tr) => {
      const box = h('input', { type: 'checkbox', checked: selectedReceipts.has(e.id), 'aria-label': 'select receipt ' + e.tx_id,
        on: { change: (ev) => { if (ev.target.checked) selectedReceipts.add(e.id); else selectedReceipts.delete(e.id); renderFields(); } } });
      tr.append(h('td', null, box), td(e.date), td(e.merchant), td(fmt(cents(e.amount), e.currency), 'num'), td(e.mode || '—'), td(e.tx_id, 'ellipsis code'));
    }, 'no signed receipts yet. pay someone through opossum first.');
    const aud = $('#discloseAudience');
    if (!aud.options.length) options(aud, Object.entries(AUDIENCES).map(([k, v]) => [k, v.label]).concat([['custom', 'someone else']]), 'accountant');
    renderFields();
  };
  function receiptNames(e) { return Object.keys(e.receipt.disclosures || {}); }
  function renderFields() {
    const chosen = withReceipts().filter((e) => selectedReceipts.has(e.id));
    const names = Array.from(new Set(chosen.flatMap(receiptNames)));
    const preset = L().settings.audiences[$('#discloseAudience').value] || [];
    const box = $('#discloseFields');
    const before = new Set($$('input:checked', box).map((i) => i.value));
    // Keep the user's own ticks only while the audience and the kind of fields stay the same.
    const keepPrior = box.dataset.audience === $('#discloseAudience').value && box.dataset.real === String(names.length > 0);
    box.dataset.audience = $('#discloseAudience').value;
    box.dataset.real = String(names.length > 0);
    box.replaceChildren(...(names.length ? names : Object.keys(CLAIMS).slice(0, 8)).map((n) =>
      h('label', { class: 'check' }, h('input', { type: 'checkbox', value: n, checked: keepPrior ? before.has(n) : preset.includes(n), disabled: !names.length }), CLAIMS[n] || n)));
  }
  $('#discloseAudience').addEventListener('change', renderFields);
  let lastPackage = null;
  $('#discloseForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const chosen = withReceipts().filter((x) => selectedReceipts.has(x.id));
    if (!chosen.length) { toast('tick at least one receipt', 'alarm'); return; }
    const fields = $$('#discloseFields input:checked').map((i) => i.value);
    const withMemo = e.target.elements.with_memo.checked, withContext = e.target.elements.with_context.checked;
    const items = chosen.map((x) => {
      const names = fields.slice();
      if (withMemo && x.memo && !names.includes('memo_commitment')) names.push('memo_commitment');
      const d = x.receipt.disclosures;
      const item = { presentation: x.receipt.sd_jwt + '~' + names.filter((n) => d[n]).map((n) => d[n] + '~').join('') };
      if (withMemo && x.memo) item.memo = { text: x.memo.text, salt: x.memo.salt };
      if (withContext) item.context = { category: x.category, note: x.note || '', stated_by: 'the payer; not signed by the relay' };
      return item;
    });
    lastPackage = { type: 'opossum-disclosure', version: 1, created: new Date().toISOString(), audience: $('#discloseAudience').value,
      fields, verify_at: location.origin + '/opossum/verify', issuer_keys: location.origin + '/opossum/.well-known/jwks.json', items };
    $('#packageOut').textContent = JSON.stringify(lastPackage, null, 2);
    $('#packageOut').hidden = false; $('#packageActions').hidden = false;
    $('#packageNote').textContent = items.length + ' receipt' + (items.length === 1 ? '' : 's') + ' · reveals: ' + (fields.map((f) => CLAIMS[f] || f).join(', ') || 'only that a receipt exists') + '. everything else stays sealed.';
  });
  $('#packageCopy').addEventListener('click', () => navigator.clipboard.writeText(JSON.stringify(lastPackage)).then(() => toast('copied', 'trust'), () => toast('copy was blocked', 'alarm')));
  $('#packageDownload').addEventListener('click', () => download('opossum-disclosure-' + today() + '.json', 'application/json', JSON.stringify(lastPackage, null, 2)));

  // ------------------------------------------------------------ privacy
  renderers.privacy = async () => {
    const s = L().settings;
    $('#defaultMode').value = s.default_mode || 'pseudonymous';
    const body = $('#audienceTable tbody');
    body.replaceChildren(
      ...Object.entries(AUDIENCES).map(([key, a]) => h('tr', null, td(a.label), h('td', { class: 'wrap' },
        h('div', { class: 'checks' }, Object.keys(CLAIMS).map((n) => h('label', { class: 'check' },
          h('input', { type: 'checkbox', checked: (s.audiences[key] || []).includes(n), on: { change: (ev) => {
            const list = new Set(s.audiences[key] || []); if (ev.target.checked) list.add(n); else list.delete(n);
            s.audiences[key] = Array.from(list); changed(); } } }), CLAIMS[n])))))),
      ...FIXED_AUDIENCES.map(([who, what]) => h('tr', null, td(who), td(what, 'wrap'))),
    );
    const [identity, disclosures, map] = await Promise.all([api('/identity'), api('/disclosures'), api('/data-map')]);
    const f = $('#identityForm').elements;
    if (document.activeElement.form !== $('#identityForm')) for (const k of ['legal_name', 'address_line1', 'address_line2', 'city', 'postal_code', 'country', 'date_of_birth', 'phone']) f[k].value = identity.identity[k] || '';
    $('#identityNote').textContent = 'status: ' + identity.kyc_status.replace('_', ' ') + '. kept encrypted on the relay. required by law for real-money payments; never shown to a recipient unless you choose.';
    const canVerify = identity.kyc_status === 'self_attested';
    $('#identityVerify').hidden = !canVerify; $('#identityVerifyNote').hidden = !canVerify;
    rows('#myDisclosures', disclosures, (d, tr) => tr.append(td(when(d.disclosed_at)), td(d.authority), td(d.legal_basis.replace(/_/g, ' ')), td(d.fields.join(', '))), 'none. nothing about you has been disclosed.');
    rows('#dataMap', map.items, (i, tr) => tr.append(td(i.data, 'wrap'), td(i.stored, 'wrap'), td(i.visible_to.join(', '), 'wrap'), td(i.retention, 'wrap')));
  };
  $('#identityVerify').addEventListener('click', (e) => guard(async () => {
    const r = await api('/identity/verify', 'POST');
    let url = null;
    try { url = new URL(r.url); } catch (err) { url = null; }
    if (!url || url.protocol !== 'https:' || url.hostname !== 'verify.stripe.com') throw new Error('the identity provider returned an unexpected address; not opening it.');
    await save().catch(() => {});
    location.assign(url.href);
  }, e.currentTarget));
  $('#defaultMode').addEventListener('change', (e) => { L().settings.default_mode = e.target.value; changed(); });
  $('#identityForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const body = {};
    for (const k of ['legal_name', 'address_line1', 'address_line2', 'city', 'postal_code', 'country', 'date_of_birth', 'phone']) if (f[k].value.trim()) body[k] = f[k].value.trim();
    guard(async () => { const r = await api('/identity', 'PUT', body); toast('saved to your encrypted vault · ' + r.kyc_status.replace('_', ' '), 'trust'); render(); }, e.submitter);
  });

  // ------------------------------------------------------------ security
  renderers.security = async () => {
    const [me, devices] = await Promise.all([api('/me'), api('/devices')]);
    S.me = me;
    $('#mfaNote').textContent = me.mfa_enabled ? 'on. sign-ins and new devices need a code from your authenticator app.' :
      'off. ' + (me.payments_need_mfa ? 'payments need an authenticator app, so set one up first.' : 'set one up to protect sign-ins.');
    $('#mfaButton').textContent = me.mfa_enabled ? 'turn off' : ($('#mfaSetup').hidden ? 'set up' : 'confirm');
    $('#mfaButton').className = 'btn' + (me.mfa_enabled ? ' warn' : '');
    rows('#devicesTable', devices, (d, tr) => {
      const mine = S.device && d.id === S.device.id;
      tr.append(td(d.name + (mine ? ' (this device)' : '')), td(when(d.created_at)), td(d.approved_via), td(when(d.last_used_at)),
        h('td', null, h('span', { class: 'tag ' + (d.status === 'active' ? 'trust' : 'alarm') }, d.status)),
        h('td', null, d.status === 'active' ? h('button', { type: 'button', class: 'btn warn small', on: { click: async (ev) => {
          if (!(await ask('revoke ' + d.name + '?', mine ? 'this device will no longer be able to sign payments. you would need to sign in again to add it back.' : 'that device can no longer sign payments.', 'revoke'))) return;
          await guard(async () => { await api('/devices/' + encodeURIComponent(d.id), 'DELETE'); render(); }, ev.currentTarget);
        } } }, 'revoke') : ''));
    });
    const size = L() ? JSON.stringify(L()).length : 0;
    $('#backupNote').textContent = 'encrypted backup version ' + S.version + ' · about ' + Math.ceil(size / 1024) + ' kb before encryption. the relay stores only ciphertext it cannot read.';
  };
  $('#mfaForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const code = e.target.elements.code.value.trim();
    guard(async () => {
      if (S.me && S.me.mfa_enabled) {
        if (!(await ask('turn off the authenticator?', 'sign-ins will need only your password, and payments will stop until you set it up again.', 'turn off'))) return;
        await api('/mfa/disable', 'POST', { code });
        $('#mfaSetup').hidden = true;
        toast('authenticator turned off');
      } else if ($('#mfaSetup').hidden) {
        const r = await api('/mfa/setup', 'POST');
        $('#mfaSecret').textContent = r.secret.match(/.{1,4}/g).join(' ');
        $('#mfaLink').setAttribute('href', r.otpauth_uri);
        $('#mfaSetup').hidden = false;
      } else {
        await api('/mfa/confirm', 'POST', { code });
        $('#mfaSetup').hidden = true; $('#mfaSecret').textContent = '';
        toast('authenticator on. you can make payments now.', 'trust');
      }
      e.target.reset();
      render();
    }, e.submitter);
  });
  $('#backupNow').addEventListener('click', (e) => guard(() => save(true), e.currentTarget));
  $('#exportAll').addEventListener('click', () => download('opossum-ledger-' + today() + '.json', 'application/json', JSON.stringify(L(), null, 2)));
  $('#closeForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const password = e.target.elements.password.value;
    e.target.reset();
    guard(async () => {
      if (!(await ask('close your account?', 'your encrypted backup and sessions are deleted now. export your ledger first if you want to keep it.', 'close account'))) return;
      const params = await api('/auth/params?email=' + encodeURIComponent(S.email));
      const keys = await passwordKeys(password, params.kdf_salt, params.kdf_iterations);
      await api('/account/close', 'POST', { auth_key: keys.auth });
      await idb.del('ledger:' + S.ns); await idb.del('device:' + S.ns); await idb.del('last');
      forget();
      showGate('signin', 'your account is closed.');
    }, e.submitter);
  });

  // ============================================================ gate: sign up, sign in, recover, unlock
  function showGate(panel, message, tone) {
    document.body.classList.add('locked');
    $('#app').hidden = true; $('#gate').hidden = false;
    $('#gateTabs').hidden = panel === 'unlock';
    $$('#gateTabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.gate === panel)));
    $$('#gate [data-panel]').forEach((f) => { f.hidden = f.dataset.panel !== panel; });
    $('#recoveryShow').hidden = true;
    gateMsg(message, tone);
    const first = $('#gate [data-panel="' + panel + '"] input:not([type=hidden])');
    if (first) { if (S.email && first.name === 'email' && !first.value) first.value = S.email; first.focus(); }
  }
  $('#gateTabs').addEventListener('click', (e) => { const b = e.target.closest('button[data-gate]'); if (b) showGate(b.dataset.gate); });
  const deviceName = () => { const ua = navigator.userAgent; return (/iPhone|iPad/.test(ua) ? 'iphone' : /Android/.test(ua) ? 'android' : /Mac/.test(ua) ? 'mac' : /Windows/.test(ua) ? 'windows' : 'browser') + ' · ' + (/Firefox/.test(ua) ? 'firefox' : /Edg\//.test(ua) ? 'edge' : /Chrome/.test(ua) ? 'chrome' : /Safari/.test(ua) ? 'safari' : 'web'); };
  $('#signup').elements.device.value = deviceName(); $('#recover').elements.device.value = deviceName();
  const nsFor = async (email) => (await sha256hex('opossum:' + email.toLowerCase())).slice(0, 32);

  async function openLedger(raw, backup) {
    S.ledgerRaw = raw;
    S.ledgerKey = await importLedgerKey(raw);
    let local = null;
    const stored = await idb.get('ledger:' + S.ns);
    if (stored && stored.ciphertext) { try { local = await unseal(S.ledgerKey, stored.ciphertext); } catch (e) { local = null; } }
    let remote = null;
    if (backup && backup.ciphertext) remote = await unseal(S.ledgerKey, backup.ciphertext);
    S.version = backup ? backup.version : (stored ? stored.version : 0);
    S.ledger = merge(local, remote) || newLedger();
  }
  async function enterApp() {
    await idb.set('last', { email: S.email });
    document.body.classList.remove('locked');
    $('#gate').hidden = true; $('#app').hidden = false;
    $('#beaconText').textContent = 'ledger unlocked · locks after ' + Math.round(S.idleMs / 60000) + ' min idle';
    S.lastActive = Date.now();
    const route = S.pendingRoute || location.hash.slice(1);
    S.pendingRoute = null;
    await guard(syncPayments);
    await save().catch(() => {});
    if (route.startsWith('pay/invoice/')) { go('pay', false); await openInvoice(route.split('/')[2]); }
    else if (route.startsWith('paid/') || route.startsWith('cancelled/')) { go('ledger', false); await followPayment(route.split('/')[1]); }
    else go(ROOMS.includes(route) ? route : 'overview', false);
  }
  async function openInvoice(id) {
    await guard(async () => {
      const inv = await api('/invoices/' + encodeURIComponent(id));
      if (inv.status !== 'open') { toast('that invoice is ' + inv.status, 'alarm'); return; }
      await renderers.pay();
      const f = $('#payForm').elements;
      f.recipient.value = inv.recipient.handle; f.invoice.value = inv.id; f.amount.value = inv.amount; f.currency.value = inv.currency;
      $('#payInvoiceNote').textContent = 'paying invoice ' + inv.reference + ' from ' + inv.recipient.name + (inv.description ? ' · ' + inv.description : '');
    });
  }
  async function followPayment(id) {
    for (let i = 0; i < 10; i++) {
      const p = await api('/payments/' + encodeURIComponent(id)).catch(() => null);
      if (p && p.status !== 'pending_payment') { await syncPayments(); toast(p.status === 'settled' ? 'paid · receipt signed' : 'payment ' + p.status, p.status === 'settled' ? 'trust' : 'alarm'); return; }
      await new Promise((r) => setTimeout(r, 2000));
    }
    toast('the payment is still pending. it will update when the processor confirms it.');
  }

  $('#signup').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const email = f.email.value.trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { gateMsg('enter your email', 'alarm'); return; }
    if (f.password.value.length < 12) { gateMsg('use at least 12 characters for your password', 'alarm'); return; }
    if (f.password.value !== f.password2.value) { gateMsg('the two passwords differ', 'alarm'); return; }
    if (!/^[a-zA-Z]{2}$/.test(f.country.value.trim())) { gateMsg('enter your country as two letters, like us or gb', 'alarm'); return; }
    const password = f.password.value;
    f.password.value = ''; f.password2.value = '';
    guard(async () => {
      gateMsg('creating keys on this device…');
      const salt = b64u(random(16));
      const it = S.config.kdf_iterations;
      const code = newRecoveryCode();
      const [pw, rc, device] = await Promise.all([passwordKeys(password, salt, it), recoveryKeys(code, salt, it), newDevice()]);
      const raw = random(32);
      const wrapped = { v: 1, password: await wrapKey(pw.kek, raw), recovery: await wrapKey(rc.kek, raw) };
      const r = await call('/accounts', 'POST', { email, auth_key: pw.auth, recovery_key: rc.auth, kdf_salt: salt, kdf_iterations: it,
        jurisdiction: f.country.value.trim().toUpperCase(), device: { name: f.device.value.trim() || deviceName(), public_jwk: device.jwk }, wrapped_keys: wrapped });
      if (!r.res.ok) { gateMsg(errText(r.data, r.res.status), 'alarm'); return; }
      S.email = email; S.ns = await nsFor(email); S.me = r.data;
      S.device = { id: r.data.device_id, privateKey: device.privateKey };
      await idb.set('device:' + S.ns, { id: r.data.device_id, privateKey: device.privateKey, jwk: device.jwk });
      await openLedger(raw, null);
      await save().catch(() => {});
      $$('#gate [data-panel]').forEach((x) => { x.hidden = true; });
      $('#gateTabs').hidden = true;
      $('#recoveryCode').textContent = code;
      $('#recoveryShow').hidden = false;
      gateMsg('');
      $('#recoveryDownload').onclick = () => download('opossum-recovery-kit.txt', 'text/plain',
        'opossum recovery kit\n\naccount: ' + email + '\nrecovery code: ' + code + '\n\nthis code unlocks your encrypted ledger and lets you reset your password if you lose your device.\nkeep it offline and private. opossum cannot recover it for you.\n');
    }, e.submitter);
  });
  $('#recoverySaved').addEventListener('change', (e) => { $('#recoveryDone').disabled = !e.target.checked; });
  $('#recoveryDone').addEventListener('click', () => { $('#recoveryCode').textContent = ''; $('#recoverySaved').checked = false; $('#recoveryDone').disabled = true; guard(enterApp); });

  $('#signin').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const email = f.email.value.trim().toLowerCase();
    const password = f.password.value;
    if (!email || !password) { gateMsg('enter your email and password', 'alarm'); return; }
    guard(async () => {
      gateMsg('checking on this device…');
      const params = (await call('/auth/params?email=' + encodeURIComponent(email))).data;
      const pw = await passwordKeys(password, params.kdf_salt, params.kdf_iterations);
      const ns = await nsFor(email);
      let local = await idb.get('device:' + ns);
      // A fresh key is offered in case this browser's device was revoked or never added.
      const fresh = await newDevice();
      const body = { email, auth_key: pw.auth, device: { name: deviceName(), public_jwk: fresh.jwk } };
      if (local) body.device_id = local.id;
      if (f.totp.value.trim()) body.totp = f.totp.value.trim();
      const r = await call('/session', 'POST', body);
      if (r.code === 'mfa_required' || r.code === 'wrong_code') {
        $('#signinTotpField').hidden = false; f.totp.value = ''; f.totp.focus();
        gateMsg(r.data.error.message, r.code === 'wrong_code' ? 'alarm' : null); return;
      }
      if (!r.res.ok) { gateMsg(errText(r.data, r.res.status), 'alarm'); return; }
      f.password.value = ''; f.totp.value = ''; $('#signinTotpField').hidden = true;
      S.email = email; S.ns = ns; S.me = r.data;
      if (!local || r.data.device_id !== local.id) { local = { id: r.data.device_id, privateKey: fresh.privateKey, jwk: fresh.jwk }; await idb.set('device:' + ns, local); }
      S.device = { id: local.id, privateKey: local.privateKey };
      const backup = await api('/backup');
      let raw;
      try { raw = await unwrapKey(pw.kek, backup.wrapped_keys.password); } catch (err) { gateMsg('signed in, but the ledger key did not open. use your recovery code.', 'alarm'); return; }
      await openLedger(raw, backup);
      await enterApp();
    }, e.submitter);
  });

  $('#recover').addEventListener('submit', (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const email = f.email.value.trim().toLowerCase(), code = f.code.value, password = f.password.value;
    if (password.length < 12) { gateMsg('use at least 12 characters for the new password', 'alarm'); return; }
    if (normCode(code).length !== 24) { gateMsg('the recovery code has 24 letters and digits', 'alarm'); return; }
    guard(async () => {
      gateMsg('checking your recovery code on this device…');
      const params = (await call('/auth/params?email=' + encodeURIComponent(email))).data;
      const [rc, pw, device] = await Promise.all([recoveryKeys(code, params.kdf_salt, params.kdf_iterations), passwordKeys(password, params.kdf_salt, params.kdf_iterations), newDevice()]);
      const r = await call('/recovery', 'POST', { email, recovery_key: rc.auth, new_auth_key: pw.auth, device: { name: f.device.value.trim() || deviceName(), public_jwk: device.jwk } });
      if (!r.res.ok) { gateMsg(errText(r.data, r.res.status), 'alarm'); return; }
      f.password.value = ''; f.code.value = '';
      S.email = email; S.ns = await nsFor(email); S.me = r.data;
      S.device = { id: r.data.device_id, privateKey: device.privateKey };
      await idb.set('device:' + S.ns, { id: r.data.device_id, privateKey: device.privateKey, jwk: device.jwk });
      const backup = await api('/backup');
      const raw = await unwrapKey(rc.kek, backup.wrapped_keys.recovery);
      await api('/backup/keys', 'PUT', { wrapped_keys: { v: 1, password: await wrapKey(pw.kek, raw), recovery: backup.wrapped_keys.recovery } });
      await openLedger(raw, backup);
      await enterApp();
      toast('recovered. other devices were signed out. set up your authenticator again in security.', 'trust');
    }, e.submitter);
  });

  $('#unlock').addEventListener('submit', (e) => {
    e.preventDefault();
    const password = e.target.elements.password.value;
    e.target.elements.password.value = '';
    guard(async () => {
      gateMsg('unlocking on this device…');
      const params = await api('/auth/params?email=' + encodeURIComponent(S.email));
      const pw = await passwordKeys(password, params.kdf_salt, params.kdf_iterations);
      const backup = await call('/backup');
      if (backup.res.status === 401) { showGate('signin', 'your session ended. sign in again.'); return; }
      let raw;
      try { raw = await unwrapKey(pw.kek, backup.data.wrapped_keys.password); } catch (err) { gateMsg('that password is not right', 'alarm'); return; }
      const local = await idb.get('device:' + S.ns);
      if (!local) { await call('/session', 'DELETE'); showGate('signin', 'this browser has no device key. sign in again to add it.'); return; }
      S.device = { id: local.id, privateKey: local.privateKey };
      await openLedger(raw, backup.data);
      await enterApp();
    }, e.submitter);
  });
  $('#unlockOther').addEventListener('click', async () => { await call('/session', 'DELETE').catch(() => {}); S.email = null; showGate('signin'); });

  // ============================================================ locking
  function forget() {
    clearTimeout(S.saveTimer);
    if (S.ledgerRaw) S.ledgerRaw.fill(0);
    S.ledgerRaw = null; S.ledgerKey = null; S.ledger = null; S.device = null; S.quote = null; S.draft = null; S.recipients = [];
    selectedReceipts.clear(); lastPackage = null;
    $$('#app tbody').forEach((b) => b.replaceChildren());
    $$('#app form').forEach((f) => f.reset());
    ['#packageOut', '#payBreakdown', '#payResult', '#ovMetrics', '#bgMetrics', '#projection', '#budgetList', '#goalList', '#reserveInfo', '#ovBudgets', '#printSheet'].forEach((q) => $(q).replaceChildren());
    $('#packageOut').hidden = true; $('#packageActions').hidden = true; $('#mfaSetup').hidden = true; $('#mfaSecret').textContent = '';
    const d = $('#confirm'); if (d.open) d.close();
  }
  async function lock(message) {
    if (S.ledger && S.ledgerKey) await save().catch(() => {});
    forget();
    $('#unlockWho').textContent = S.email ? 'signed in as ' + S.email : '';
    showGate(S.email ? 'unlock' : 'signin', message || 'locked. your ledger is encrypted on this device.');
  }
  $('#lockBtn').addEventListener('click', () => lock());
  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((ev) => window.addEventListener(ev, () => { S.lastActive = Date.now(); }, { passive: true, capture: true }));
  setInterval(() => { if (S.ledger && Date.now() - S.lastActive > S.idleMs) lock('locked after ' + Math.round(S.idleMs / 60000) + ' minutes without activity.'); }, 15000);
  window.addEventListener('hashchange', () => {
    if (!S.ledger) return;
    const route = location.hash.slice(1);
    if (route.startsWith('pay/invoice/')) { go('pay', false); openInvoice(route.split('/')[2]); }
    else if (ROOMS.includes(route) && route !== S.room) go(route);
  });

  // ============================================================ start
  (async () => {
    try {
      S.config = (await call('/config')).data;
      if (!S.config.enabled) { showGate('signin', 'opossum is not switched on yet on this server.', 'alarm'); return; }
      S.idleMs = Math.max(1, S.config.session_idle_minutes || 30) * 60000;
      const last = await idb.get('last');
      S.pendingRoute = location.hash.slice(1) || null;
      if (last && last.email) {
        S.email = last.email; S.ns = await nsFor(last.email);
        const me = await call('/me');
        if (me.res.ok) { $('#unlockWho').textContent = 'signed in as ' + S.email; showGate('unlock'); return; }
      }
      showGate('signin', S.pendingRoute && S.pendingRoute.startsWith('pay/invoice/') ? 'sign in to pay this invoice.' : '');
    } catch (err) {
      showGate('signin', err.message, 'alarm');
    }
  })();
})();
