// A headless "phone": imports keys with web/sshkey.js, registers them with the daemon,
// long-polls for signing requests and signs them. Used by test/e2e.sh.
// usage: node test/phone.mjs <base-url> <device-id> <auto:0|1> key1[:name] key2 ...
import { importPrivateKey, sign, b64decode, b64encode } from '../web/sshkey.js';
import { readFileSync } from 'node:fs';

const [base, deviceId, auto, ...files] = process.argv.slice(2);
const keys = [];
for (const spec of files) {
  const [file, name] = spec.split(':');
  keys.push(await importPrivateKey(readFileSync(file, 'utf8'), name || ''));
}
const api = async (path, opts = {}) => {
  const r = await fetch(base + path, { ...opts, headers: { 'Content-Type': 'application/json' } });
  if (!r.ok) throw new Error(`${path}: ${r.status} ${(await r.text()).trim()}`);
  return r.status === 204 ? null : r.json();
};
await api(`/api/devices/${deviceId}`, { method: 'PUT', body: JSON.stringify({ name: 'node-phone', keys: keys.map(k => ({ fingerprint: k.fingerprint, name: k.name, type: k.type, blob: b64encode(k.blob) })), push: null }) });
console.log('registered', keys.map(k => `${k.name} ${k.fingerprint}`).join(', '));
if (auto === 'register-only') process.exit(0);
for (;;) {
  const { requests } = await api(`/api/requests?device=${deviceId}&wait=25`);
  for (const req of requests) {
    const k = keys.find(k => k.fingerprint === req.key_fingerprint);
    if (!k) { console.log('unknown key, denying', req.id); await api(`/api/requests/${req.id}/deny`, { method: 'POST' }); continue; }
    if (auto === '0' || (process.env.DENY_USER && req.ssh_user === process.env.DENY_USER)) {
      console.log('denying', req.id, req.key_name, req.ssh_user);
      await api(`/api/requests/${req.id}/deny`, { method: 'POST' });
      continue;
    }
    const sig = await sign(k, req.algorithm, b64decode(req.data));
    await api(`/api/requests/${req.id}/signature`, { method: 'POST', body: JSON.stringify({ signature: b64encode(sig), algorithm: req.algorithm }) });
    console.log('signed', req.id, req.key_name, req.algorithm, 'user=' + req.ssh_user, 'proc=' + (req.process || []).map(p => p.name).join('<'));
  }
}
