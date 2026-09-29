/* Verifies Opossum disclosure packages in the reader's own browser. */
(() => {
  'use strict';
  const $ = (q) => document.querySelector(q);
  const enc = new TextEncoder();
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) if (v != null && v !== false) { if (k === 'class') el.className = v; else el.setAttribute(k, String(v)); }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
    return el;
  }
  function b64u(bytes) {
    let s = ''; const b = new Uint8Array(bytes);
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(text) {
    const s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  }
  const utf8 = (bytes) => new TextDecoder().decode(bytes);
  const sha256 = async (text) => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  const LABELS = {
    transaction_id: 'transaction id', amount: 'amount', currency: 'currency', date: 'date', time: 'time', status: 'status',
    recipient_name: 'recipient', recipient_handle: 'recipient handle', recipient_category: 'recipient category', type: 'type',
    payer_pseudonym: 'payer pseudonym', privacy_mode: 'privacy mode', opossum_fee: 'opossum fee', processor_fee: 'network fee',
    total_cost: 'total cost', recipient_receives: 'recipient received', fee_bearer: 'fees paid by', processor: 'processor',
    invoice_id: 'invoice id', invoice_reference: 'invoice reference', memo_commitment: 'note commitment',
    payer_legal_name: 'payer legal name', payer_identity_status: 'payer identity status',
  };

  let jwksCache = null;
  async function jwks() {
    if (!jwksCache) {
      const r = await fetch('/opossum/.well-known/jwks.json', { cache: 'no-store', credentials: 'omit' });
      if (!r.ok) throw new Error('could not load the relay\'s public key');
      jwksCache = await r.json();
    }
    return jwksCache;
  }

  // local verification with WebCrypto Ed25519; falls back to the relay's /verify
  async function verifyLocally(presentation) {
    const parts = presentation.trim().split('~');
    const [hb, pb, sb] = parts[0].split('.');
    const header = JSON.parse(utf8(unb64u(hb)));
    const payload = JSON.parse(utf8(unb64u(pb)));
    if (header.alg !== 'EdDSA' || header.typ !== 'opossum-receipt+sd-jwt') return { valid: false, reason: 'not an opossum receipt' };
    const jwk = (await jwks()).keys.find((k) => k.kid === header.kid);
    if (!jwk) return { valid: false, reason: 'signed with a key this relay does not publish' };
    const key = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify']);
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, unb64u(sb), enc.encode(hb + '.' + pb));
    if (!ok) return { valid: false, reason: 'signature does not match: altered, or not issued by this relay' };
    const digests = new Set(payload._sd || []);
    const disclosed = {};
    for (const d of parts.slice(1).filter(Boolean)) {
      if (!digests.has(b64u(await sha256(d)))) return { valid: false, reason: 'a shown field was not part of the signed receipt' };
      const [salt, name, value] = JSON.parse(utf8(unb64u(d)));
      if (typeof salt !== 'string' || typeof name !== 'string' || name in disclosed) return { valid: false, reason: 'a shown field is malformed or repeated' };
      disclosed[name] = value;
    }
    const issuer = Object.fromEntries(Object.entries(payload).filter(([k]) => !k.startsWith('_')));
    return { valid: true, issuer_claims: issuer, disclosed, hidden: Math.max(0, digests.size - 3 - Object.keys(disclosed).length), where: 'checked in your browser' };
  }
  async function verifyOne(item) {
    let result;
    try { result = await verifyLocally(item.presentation); } catch (err) {
      const r = await fetch('/opossum/api/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'omit',
        body: JSON.stringify({ presentation: item.presentation }) });
      result = { ...(await r.json()), where: 'checked by the relay (this browser lacks ed25519)' };
    }
    if (result.valid && item.memo) {
      const c = result.disclosed.memo_commitment;
      result.memo = { text: item.memo.text, valid: !!c && hex(await sha256(item.memo.salt + ':' + item.memo.text)) === c };
    }
    return result;
  }

  function show(results, pkg) {
    const out = $('#verifyOut');
    out.replaceChildren();
    if (pkg && pkg.audience) out.append(h('p', { class: 'faint' }, 'package for: ' + pkg.audience + ' · created ' + (pkg.created || 'unknown')));
    results.forEach(({ item, r }, i) => {
      const panel = h('div', { class: 'verdict ' + (r.valid ? 'ok' : 'bad') });
      if (!r.valid) { panel.append(h('h4', null, 'receipt ' + (i + 1) + ': not valid'), h('p', null, r.reason || 'unknown problem')); out.append(panel); return; }
      const test = r.issuer_claims && r.issuer_claims.test;
      panel.append(h('h4', null, 'receipt ' + (i + 1) + ': signed by the opossum relay', test ? h('span', null, ' ', h('span', { class: 'tag test' }, 'test money')) : ''));
      const dl = h('dl', { class: 'claims' });
      for (const [k, v] of Object.entries(r.disclosed)) dl.append(h('dt', null, LABELS[k] || k), h('dd', null, typeof v === 'object' ? JSON.stringify(v) : String(v)));
      if (r.issuer_claims && r.issuer_claims.iat) dl.append(h('dt', null, 'signed at'), h('dd', null, new Date(r.issuer_claims.iat * 1000).toISOString()));
      panel.append(dl, h('p', { class: 'faint' }, r.hidden + ' other field' + (r.hidden === 1 ? '' : 's') + ' stay sealed · ' + r.where));
      if (r.memo) panel.append(h('p', { class: r.memo.valid ? 'msg trust' : 'msg alarm' }, (r.memo.valid ? 'proven note: ' : 'note does not match its commitment: ') + '“' + r.memo.text + '”'));
      if (item.context) panel.append(h('p', { class: 'faint' }, 'stated by the payer (not signed): ' + [item.context.category, item.context.note].filter(Boolean).join(' · ')));
      out.append(panel);
    });
  }

  async function run(text) {
    const msg = $('#verifyMsg');
    msg.textContent = ''; msg.className = 'msg';
    let pkg = null, items;
    const trimmed = text.trim();
    if (!trimmed) { msg.textContent = 'paste a package first'; msg.className = 'msg alarm'; return; }
    if (trimmed.startsWith('{')) {
      try { pkg = JSON.parse(trimmed); } catch (e) { msg.textContent = 'that is not valid json'; msg.className = 'msg alarm'; return; }
      if (pkg.type !== 'opossum-disclosure' || !Array.isArray(pkg.items)) { msg.textContent = 'not an opossum disclosure package'; msg.className = 'msg alarm'; return; }
      items = pkg.items.slice(0, 200);
    } else {
      items = [{ presentation: trimmed }];
    }
    msg.textContent = 'checking ' + items.length + ' receipt' + (items.length === 1 ? '' : 's') + '…';
    const results = [];
    for (const item of items) results.push({ item, r: await verifyOne(item).catch((e) => ({ valid: false, reason: e.message })) });
    const good = results.filter((x) => x.r.valid).length;
    msg.textContent = good + ' of ' + results.length + ' verified';
    msg.className = 'msg ' + (good === results.length ? 'trust' : 'alarm');
    show(results, pkg);
  }
  $('#verifyForm').addEventListener('submit', (e) => { e.preventDefault(); run(e.target.elements.input.value); });
  $('#verifyFile').addEventListener('change', async (e) => {
    const file = e.target.files[0]; e.target.value = '';
    if (!file || file.size > 5_000_000) return;
    const text = await file.text();
    $('#verifyForm').elements.input.value = text;
    run(text);
  });
})();
