import { importPrivateKey, sign, b64decode, b64encode } from './sshkey.js';

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

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
async function loadState() { try { state = await api('/api/state'); } catch (e) { state = { error: e.message }; } render(); }

// ---- signing requests ----
async function poll() {
  if (polling) return;
  polling = true;
  while (!document.hidden) {
    try {
      const r = await api(`/api/requests?device=${deviceId}&wait=25`);
      pending = r.requests;
      for (const req of pending) {
        const k = keys.find(k => k.fingerprint === req.key_fingerprint);
        if (k && k.auto) await approve(req.id);
      }
      render();
    } catch (e) { $('#dot').classList.remove('on'); await new Promise(r => setTimeout(r, 3000)); continue; }
    $('#dot').classList.add('on');
  }
  polling = false;
}
async function approve(id) {
  const req = pending.find(r => r.id === id);
  const k = keys.find(k => k.fingerprint === req.key_fingerprint);
  if (!k) return alert('key not on this device');
  try {
    const sig = await sign(k, req.algorithm, b64decode(req.data));
    await api(`/api/requests/${id}/signature`, { method: 'POST', body: JSON.stringify({ signature: b64encode(sig), algorithm: req.algorithm }) });
  } catch (e) { alert('signing failed: ' + e.message); }
  pending = pending.filter(r => r.id !== id);
  render();
}
async function deny(id) {
  try { await api(`/api/requests/${id}/deny`, { method: 'POST' }); } catch {}
  pending = pending.filter(r => r.id !== id);
  render();
}

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
    msg.className = 'msg ok'; msg.textContent = `Added ${rec.name}. The private key is stored on this device only.`;
    poll(); loadState();
  } catch (e) { msg.className = 'msg err'; msg.textContent = e.message; }
}
async function removeKey(fp) {
  if (!confirm('Remove this key from the phone?')) return;
  await delKey(fp); keys = await allKeys(); await syncDevice(); render(); loadState();
}
async function toggleAuto(fp) {
  const k = keys.find(k => k.fingerprint === fp); k.auto = !k.auto; await putKey(k); render();
}

// ---- push ----
const standalone = window.matchMedia('(display-mode: standalone)').matches || navigator.standalone;
async function enablePush() {
  const msg = $('#pushmsg'); msg.className = 'msg';
  try {
    if (!('PushManager' in window)) throw new Error(standalone ? 'push not supported here' : 'add this page to the Home Screen first (Share → Add to Home Screen), then enable notifications from the installed app');
    if (await Notification.requestPermission() !== 'granted') throw new Error('notifications not allowed');
    const raw = b64decode(state.vapid_public);
    await swReg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: raw });
    await syncDevice(); await loadState();
    msg.className = 'msg ok'; msg.textContent = 'Notifications on. You will be alerted when a signature is needed.';
  } catch (e) { msg.className = 'msg err'; msg.textContent = e.message; }
}
async function testPush() {
  const msg = $('#pushmsg');
  try { await api(`/api/devices/${deviceId}/push-test`, { method: 'POST' }); msg.className = 'msg ok'; msg.textContent = 'Test notification sent.'; }
  catch (e) { msg.className = 'msg err'; msg.textContent = e.message; }
}

// ---- render ----
function render() {
  const P = $('#pending');
  P.innerHTML = pending.length ? pending.map(r => `
    <div class="card pending">
      <div class="row"><div class="name">${esc(r.key_name)}</div><span class="tag">${esc(r.algorithm)}</span></div>
      <div class="meta">${r.ssh_user ? 'login as <b>' + esc(r.ssh_user) + '</b> · ' : ''}${esc(r.key_fingerprint)}</div>
      <div class="proc">${(r.process || []).slice(0, 5).map(p => `<div><b>${esc(p.name)}</b> ${esc(p.args)}</div>`).join('')}</div>
      <div class="btns"><button class="ok" data-approve="${r.id}">Sign</button><button class="bad" data-deny="${r.id}">Deny</button></div>
    </div>`).join('') : '';
  const K = $('#keys');
  K.innerHTML = keys.length ? keys.map(k => `
    <div class="card"><div class="row"><div><div class="name">${esc(k.name)}</div><div class="meta">${esc(k.type)} · ${esc(k.fingerprint)}</div></div>
      <button class="ghost danger" data-remove="${esc(k.fingerprint)}">Remove</button></div>
      <label class="switch"><input type="checkbox" data-auto="${esc(k.fingerprint)}" ${k.auto ? 'checked' : ''}> Sign automatically while this app is open</label>
    </div>`).join('') : `<div class="card"><div class="empty">No keys on this device yet</div></div>`;
  const S = $('#server');
  if (!state) S.textContent = '';
  else if (state.error) S.innerHTML = `<div class="card"><div class="empty">Cannot reach the Mac: ${esc(state.error)}</div></div>`;
  else {
    const me = (state.devices || []).find(d => d.id === deviceId);
    $('#host').textContent = state.host.split('.')[0];
    S.innerHTML = `
      <div class="card"><div class="row"><div><div class="name">Notifications</div><div class="meta">${me && me.push ? 'enabled on this device' : standalone ? 'not enabled' : 'install to Home Screen to enable'}</div></div>
        ${me && me.push ? '<button class="ghost" id="pushtest">Test</button>' : '<button class="ghost" id="pushon">Enable</button>'}</div><div id="pushmsg" class="msg"></div></div>
      ${(state.upstream || []).length ? `<h2>Other keys on the Mac</h2>` + state.upstream.map(u => `<div class="card row"><div><div class="name">${esc(u.name)}</div><div class="meta">${esc(u.type)} · ${esc(u.fingerprint)}</div></div><span class="tag ${u.registered ? 'on' : ''}">${u.registered ? 'on phone' : 'Mac only'}</span></div>`).join('') : ''}`;
    $('#pushon')?.addEventListener('click', enablePush);
    $('#pushtest')?.addEventListener('click', testPush);
  }
}
document.addEventListener('click', e => {
  const t = e.target;
  if (t.dataset.approve) approve(t.dataset.approve);
  if (t.dataset.deny) deny(t.dataset.deny);
  if (t.dataset.remove) removeKey(t.dataset.remove);
});
document.addEventListener('change', e => { if (e.target.dataset.auto) toggleAuto(e.target.dataset.auto); });
$('#addform').addEventListener('submit', addKey);
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
