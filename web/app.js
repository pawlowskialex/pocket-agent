import { importPrivateKey, sign, b64decode, b64encode } from './sshkey.js';

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
/// SHA256:longbase64… is unreadable in a list; keep both ends so it is still recognisable.
const shortFp = fp => fp.length > 28 ? fp.slice(0, 14) + '…' + fp.slice(-6) : fp;

// ---- device identity & key store (IndexedDB holds CryptoKey objects) ----
const deviceId = localStorage.deviceId || (localStorage.deviceId = [...crypto.getRandomValues(new Uint8Array(12))].map(b => b.toString(16).padStart(2, '0')).join(''));
const deviceName = localStorage.deviceName || (localStorage.deviceName = (navigator.userAgent.match(/iPhone|iPad|Android|Macintosh/) || ['phone'])[0]);
let db;
function openDb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('sshkeys', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('keys', { keyPath: 'fingerprint' });
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
const tx = (mode, fn) => new Promise((res, rej) => { const t = db.transaction('keys', mode); const q = fn(t.objectStore('keys')); t.oncomplete = () => res(q.result); t.onerror = () => rej(t.error); });
const allKeys = () => tx('readonly', s => s.getAll());
const putKey = k => tx('readwrite', s => s.put(k));
const delKey = fp => tx('readwrite', s => s.delete(fp));

let keys = [], state = null, pending = [], polling = false, swReg = null;
let online = null, addOpen = false;

// ---- server sync ----
async function api(path, opts = {}) {
  const r = await fetch(path, { cache: 'no-store', ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) } });
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return r.status === 204 ? null : r.json();
}
async function syncDevice() {
  const push = swReg ? await swReg.pushManager.getSubscription() : null;
  await api(`/api/devices/${deviceId}`, { method: 'PUT', body: JSON.stringify({
    name: deviceName,
    keys: keys.map(k => ({ fingerprint: k.fingerprint, name: k.name, type: k.type, blob: b64encode(k.blob) })),
    push: push ? push.toJSON() : null,
  }) });
}
async function loadState() {
  try { state = await api('/api/state'); online = true; }
  catch (e) { state = { error: e.message }; online = false; }
  render();
}

// ---- signing requests ----
async function poll() {
  if (polling) return;
  polling = true;
  while (!document.hidden) {
    try {
      const r = await api(`/api/requests?device=${deviceId}&wait=25`);
      pending = r.requests;
      setOnline(true);
      for (const req of pending) {
        const k = keys.find(k => k.fingerprint === req.key_fingerprint);
        if (k && k.auto) await approve(req.id);
      }
      render();
    } catch (e) { setOnline(false); await new Promise(r => setTimeout(r, 3000)); }
  }
  polling = false;
}
function setOnline(v) { if (v !== online) { online = v; render(); } }

async function approve(id) {
  const req = pending.find(r => r.id === id);
  if (!req) return;
  const k = keys.find(k => k.fingerprint === req.key_fingerprint);
  if (!k) return say(id, 'That key is not on this phone.', 'err');
  say(id, 'Signing…');
  try {
    const sig = await sign(k, req.algorithm, b64decode(req.data));
    await api(`/api/requests/${id}/signature`, { method: 'POST', body: JSON.stringify({ signature: b64encode(sig), algorithm: req.algorithm }) });
  } catch (e) { return say(id, e.message, 'err'); }
  drop(id);
}
async function deny(id) {
  try { await api(`/api/requests/${id}/deny`, { method: 'POST' }); } catch {}
  drop(id);
}
function drop(id) { pending = pending.filter(r => r.id !== id); render(); }
/// Per-request feedback, written in place so a re-render of the list does not fight with it.
function say(id, text, cls = '') { const el = document.querySelector(`[data-msg="${id}"]`); if (el) { el.className = 'msg ' + cls; el.textContent = text; } }

// ---- keys ----
async function addKey(ev) {
  ev.preventDefault();
  const msg = $('#addmsg'); msg.className = 'msg'; msg.textContent = 'Importing…';
  try {
    const rec = await importPrivateKey($('#keytext').value, $('#keyname').value.trim());
    await putKey(rec);
    keys = await allKeys();
    $('#keytext').value = ''; $('#keyname').value = '';
    await syncDevice();
    msg.className = 'msg ok'; msg.textContent = `${rec.name} is on this phone now.`;
    addOpen = false;
    render();
    setTimeout(() => { msg.textContent = ''; }, 6000);
    poll(); loadState();
  } catch (e) { msg.className = 'msg err'; msg.textContent = e.message; }
}
async function removeKey(fp) {
  const k = keys.find(k => k.fingerprint === fp);
  if (!confirm(`Remove ${k ? k.name : 'this key'} from this phone?\n\nThe private key is deleted and cannot be recovered from here.`)) return;
  await delKey(fp); keys = await allKeys(); await syncDevice(); render(); loadState();
}
async function toggleAuto(fp) {
  const k = keys.find(k => k.fingerprint === fp); k.auto = !k.auto; await putKey(k); render();
}

// ---- push ----
const canPush = 'PushManager' in window && 'serviceWorker' in navigator;
function pushState() {
  const me = state && !state.error ? (state.devices || []).find(d => d.id === deviceId) : null;
  if (me && me.push) return 'on';
  if (!canPush) return 'install';                                   // iOS Safari before Add to Home Screen
  if (window.Notification && Notification.permission === 'denied') return 'blocked';
  return 'off';
}
async function enablePush() {
  const msg = $('#pushmsg'); msg.className = 'msg'; msg.textContent = 'Asking…';
  try {
    if (await Notification.requestPermission() !== 'granted') throw new Error('Notifications were not allowed.');
    await swReg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64decode(state.vapid_public) });
    await syncDevice(); await loadState();
  } catch (e) { msg.className = 'msg err'; msg.textContent = e.message; }
}
async function testPush() {
  const msg = $('#pushmsg'); msg.className = 'msg'; msg.textContent = 'Sending…';
  try { await api(`/api/devices/${deviceId}/push-test`, { method: 'POST' }); msg.className = 'msg ok'; msg.textContent = 'Sent.'; }
  catch (e) { msg.className = 'msg err'; msg.textContent = e.message; }
}

// ---- render ----
// Sections are shown or hidden by what the app is actually for right now: approving a waiting
// request, getting the first key on board, or sitting quietly. Each list is rebuilt only when its
// contents changed, so open disclosures and inline messages survive a poll.
const memo = {};
function fill(sel, sig, html) {
  if (memo[sel] === sig) return;
  memo[sel] = sig;
  $(sel).innerHTML = html();
}

function render() {
  const mode = pending.length ? 'approve' : keys.length ? 'home' : 'setup';
  $('#approve').hidden = mode !== 'approve';
  $('#setup').hidden = mode !== 'setup';
  $('#home').hidden = mode !== 'home';
  $('#macsec').hidden = mode !== 'home';
  $('#addsec').hidden = !(mode === 'setup' || (mode === 'home' && addOpen));
  $('#addcancel').hidden = mode !== 'home';
  $('#addopen').hidden = addOpen;
  $('#offline').hidden = online !== false;
  document.body.classList.toggle('offline', online === false);

  $('#dot').className = 'dot ' + (online === false ? 'off' : online ? 'on' : '');
  $('#host').textContent = state && state.host ? state.host.split('.')[0] : online === false ? 'offline' : 'connecting…';

  if (mode === 'approve') renderApprove();
  if (mode === 'home') { renderKeys(); renderNudge(); renderServer(); }

  clearInterval(ageTimer); ageTimer = null;
  if (mode === 'approve') { tickAges(); ageTimer = setInterval(tickAges, 1000); }
}

/// How long the request has been waiting — a request that appeared while you were away should not
/// look like the one you just triggered yourself.
function ago(iso) {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso)) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
}
function tickAges() { for (const el of document.querySelectorAll('.ago')) el.textContent = ago(el.dataset.since); }
let ageTimer = null;

function renderApprove() {
  fill('#approve', pending.map(r => r.id).join(), () => pending.map(r => {
    const known = keys.some(k => k.fingerprint === r.key_fingerprint);
    const proc = (r.process || []).slice(0, 6);
    const head = proc.find(p => p.name === 'ssh' || p.name === 'git' || p.name === 'ssh-keygen') || proc[0];
    return `
      <div class="card approve">
        <div class="eyebrow"><span>Signature requested</span><span class="ago" data-since="${esc(r.created)}"></span></div>
        <div class="row"><div class="name">${esc(r.key_name)}</div><span class="tag">${esc(r.algorithm)}</span></div>
        ${r.ssh_user ? `<div class="meta">Logging in as <b>${esc(r.ssh_user)}</b></div>` : ''}
        ${head ? `<div class="cmd">${esc(head.args || head.name)}</div>` : ''}
        <details class="proc-det"><summary>Which key, and what asked</summary>
          <div class="proc">${proc.map(p => `<div><b>${esc(p.name)}</b> ${esc(p.args)}</div>`).join('')}</div>
          <div class="meta mono">${esc(r.key_fingerprint)}</div>
        </details>
        ${known ? '' : '<div class="msg err">This key is not on this phone — you can only deny.</div>'}
        <div class="btns">
          <button class="bad" data-deny="${r.id}">Deny</button>
          <button class="ok" data-approve="${r.id}" ${known ? '' : 'disabled style="opacity:.4"'}>Sign</button>
        </div>
        <div class="msg" data-msg="${r.id}"></div>
      </div>`;
  }).join(''));
}

function renderKeys() {
  fill('#keys', JSON.stringify(keys.map(k => [k.fingerprint, k.name, !!k.auto])), () => keys.map(k => `
    <details class="card key">
      <summary>
        <div class="row">
          <div><div class="name">${esc(k.name)}</div><div class="meta mono">${esc(shortFp(k.fingerprint))}</div></div>
          ${k.auto ? '<span class="tag on">auto-sign</span>' : `<span class="tag">${esc(k.type.replace(/^ssh-|^ecdsa-sha2-/, ''))}</span>`}
        </div>
      </summary>
      <div class="kbody">
        <div class="meta mono">${esc(k.type)}<br>${esc(k.fingerprint)}</div>
        <label class="switch"><input type="checkbox" data-auto="${esc(k.fingerprint)}" ${k.auto ? 'checked' : ''}>
          <span>Sign automatically while this app is open</span></label>
        <button class="ghost danger small" data-remove="${esc(k.fingerprint)}">Remove from this phone</button>
      </div>
    </details>`).join(''));
}

// Shown only while there is something to do about notifications; once they are on it moves into
// the Mac disclosure and stops taking up the screen.
function renderNudge() {
  const p = pushState();
  fill('#nudge', p, () => {
    if (p === 'on') return '';
    if (p === 'install') return `<div class="card"><div class="name">Add to the Home Screen</div>
      <div class="meta">Tap Share, then “Add to Home Screen”, and open the app from there. Requests can then reach you as a notification instead of only when this page is open.</div></div>`;
    if (p === 'blocked') return `<div class="card"><div class="name">Notifications are blocked</div>
      <div class="meta">Allow them for this app in Settings to be alerted when a signature is needed.</div></div>`;
    return `<div class="card"><div class="row">
        <div><div class="name">Turn on notifications</div><div class="meta">Otherwise you only see requests while this app is open.</div></div>
        <button class="small" id="pushon">Enable</button>
      </div><div id="pushmsg" class="msg"></div></div>`;
  });
  $('#pushon')?.addEventListener('click', enablePush, { once: true });
}

function renderServer() {
  const p = pushState();
  const sig = JSON.stringify([state, p]);
  fill('#server', sig, () => {
    if (!state) return '';
    if (state.error) return `<div class="card"><div class="name">Cannot reach the Mac</div><div class="meta">${esc(state.error)}</div></div>`;
    const label = { on: 'On', off: 'Off', install: 'Add to Home Screen first', blocked: 'Blocked in Settings' }[p];
    return `
      <div class="card">
        <div class="pair"><span>Mac</span><span>${esc(state.host)}</span></div>
        <div class="pair"><span>Other agent</span><span>${state.upstream_ok ? 'connected' : 'none'}</span></div>
        <div class="pair"><span>This phone</span><span>${esc(deviceName)} · ${esc(deviceId.slice(0, 8))}</span></div>
        <div class="pair"><span>Notifications</span><span>${esc(label)}${p === 'on' ? ' <button class="ghost small" id="pushtest">Test</button>' : ''}</span></div>
        <div id="pushmsg" class="msg"></div>
      </div>
      ${(state.upstream || []).length ? `<h2>Other keys on the Mac</h2>` + state.upstream.map(u => `
        <div class="card"><div class="row">
          <div><div class="name">${esc(u.name)}</div><div class="meta mono">${esc(shortFp(u.fingerprint))}</div></div>
          <span class="tag ${u.registered ? 'on' : ''}">${u.registered ? 'phone + Mac' : 'Mac only'}</span>
        </div></div>`).join('') : ''}`;
  });
  $('#pushtest')?.addEventListener('click', testPush, { once: true });
}

// ---- events ----
document.addEventListener('click', e => {
  const t = e.target.closest('[data-approve],[data-deny],[data-remove]');
  if (!t) return;
  if (t.dataset.approve) approve(t.dataset.approve);
  if (t.dataset.deny) deny(t.dataset.deny);
  if (t.dataset.remove) removeKey(t.dataset.remove);
});
document.addEventListener('change', e => { if (e.target.dataset.auto) toggleAuto(e.target.dataset.auto); });
$('#addform').addEventListener('submit', addKey);
$('#addopen').addEventListener('click', () => { addOpen = true; render(); $('#keytext').focus(); });
$('#addcancel').addEventListener('click', () => { addOpen = false; $('#addmsg').textContent = ''; render(); });
$('#statuschip').addEventListener('click', () => {
  const d = $('#macdet');
  if ($('#macsec').hidden) return;
  d.open = !d.open;
  if (d.open) d.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
});
document.addEventListener('visibilitychange', () => { if (!document.hidden) { poll(); loadState(); } });

(async () => {
  db = await openDb();
  keys = await allKeys();
  if ('serviceWorker' in navigator) {
    try { swReg = await navigator.serviceWorker.register('/sw.js'); navigator.serviceWorker.addEventListener('message', () => poll()); } catch (e) { console.warn('sw', e); }
  }
  render();
  try { await syncDevice(); } catch (e) { console.warn('sync', e); }
  await loadState();
  poll();
})();
