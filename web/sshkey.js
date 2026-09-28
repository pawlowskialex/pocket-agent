// Parse OpenSSH / PEM private keys, hold them as non-extractable WebCrypto keys, and sign
// SSH agent challenges. Works in browsers and Node (ESM, no DOM).

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

export function b64decode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function b64encode(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64url(u8) { return b64encode(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function concat(...arrs) {
  const n = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(n);
  let p = 0;
  for (const a of arrs) { out.set(a, p); p += a.length; }
  return out;
}

// ---- SSH wire format ----
function u32(n) { return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }
function sshString(b) { if (typeof b === 'string') b = te.encode(b); return concat(u32(b.length), b); }
function sshMpint(b) {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  if (b[0] & 0x80) b = concat(new Uint8Array([0]), b);
  return sshString(b);
}
function reader(buf) {
  let pos = 0;
  return {
    u32() { const v = ((buf[pos] << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3]) >>> 0; pos += 4; return v; },
    string() { const n = this.u32(); if (pos + n > buf.length) throw new Error('truncated key'); const s = buf.subarray(pos, pos + n); pos += n; return s; },
    text() { return new TextDecoder().decode(this.string()); },
    bytes(n) { const s = buf.subarray(pos, pos + n); pos += n; return s; },
  };
}

// ---- DER ----
function derLen(n) {
  if (n < 128) return new Uint8Array([n]);
  const b = [];
  while (n > 0) { b.unshift(n & 255); n >>= 8; }
  return new Uint8Array([0x80 | b.length, ...b]);
}
function der(tag, ...parts) { const c = concat(...parts); return concat(new Uint8Array([tag]), derLen(c.length), c); }
function derInt(b) {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  if (b[0] & 0x80) b = concat(new Uint8Array([0]), b);
  return der(0x02, b);
}
const derSeq = (...p) => der(0x30, ...p);
const derOctet = (b) => der(0x04, b);
const derOid = (b) => der(0x06, b);
const derBits = (b) => der(0x03, new Uint8Array([0]), b);
const derNull = () => new Uint8Array([0x05, 0x00]);
const derCtx = (n, ...p) => der(0xa0 | n, ...p);

const OID = {
  ed25519: new Uint8Array([0x2b, 0x65, 0x70]),
  ec: new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
  rsa: new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
  'P-256': new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
  'P-384': new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x22]),
  'P-521': new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x23]),
};
const CURVES = { nistp256: 'P-256', nistp384: 'P-384', nistp521: 'P-521' };
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function readTLV(buf, pos) {
  const tag = buf[pos++];
  let len = buf[pos++];
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | buf[pos++]; }
  return { tag, start: pos, end: pos + len };
}

// Curve from an EC AlgorithmIdentifier/SEC1 parameter TLV: a named-curve OID, or explicit
// parameters (LibreSSL-built ssh-keygen writes those), identified by the field prime's size.
function curveFromParams(buf, t) {
  if (t.tag === 0x06) {
    const c = buf.subarray(t.start, t.end);
    return ['P-256', 'P-384', 'P-521'].find(n => eq(c, OID[n]));
  }
  if (t.tag === 0x30) {
    const ver = readTLV(buf, t.start);
    const field = readTLV(buf, ver.end);
    const ftype = readTLV(buf, field.start);
    const prime = readTLV(buf, ftype.end);
    const bits = (prime.end - prime.start - (buf[prime.start] === 0 ? 1 : 0)) * 8;
    return { 256: 'P-256', 384: 'P-384', 528: 'P-521', 521: 'P-521' }[bits];
  }
  return undefined;
}

// Detect the key type of a PKCS#8 blob: SEQ { INT, SEQ { OID alg, [params] }, OCTET STRING }
function pkcs8Parts(der) {
  const outer = readTLV(der, 0);
  const ver = readTLV(der, outer.start);
  const algSeq = readTLV(der, ver.end);
  const oid = readTLV(der, algSeq.start);
  const o = der.subarray(oid.start, oid.end);
  const octets = readTLV(der, algSeq.end);
  const inner = der.subarray(octets.start, octets.end);
  if (eq(o, OID.ed25519)) return { type: 'ed25519' };
  if (eq(o, OID.rsa)) return { type: 'rsa' };
  if (eq(o, OID.ec)) {
    const curve = oid.end < algSeq.end ? curveFromParams(der, readTLV(der, oid.end)) : undefined;
    return { type: 'ecdsa', curve, inner };
  }
  throw new Error('unsupported key algorithm');
}

// SEC1 ECPrivateKey: SEQ { INT 1, OCTET d, [0] params, [1] BITS pub }
function parseSec1(body, curveHint) {
  const seq = readTLV(body, 0);
  const v = readTLV(body, seq.start);
  const d = readTLV(body, v.end);
  let pos = d.end, curve = curveHint, pub;
  while (pos < seq.end) {
    const t = readTLV(body, pos);
    if (t.tag === 0xa0) curve = curveFromParams(body, readTLV(body, t.start)) || curve;
    else if (t.tag === 0xa1) { const bits = readTLV(body, t.start); pub = body.subarray(bits.start + 1, bits.end); }
    pos = t.end;
  }
  if (!curve) throw new Error('unsupported EC curve');
  return { ...ecPkcs8(curve, body.subarray(d.start, d.end), pub), comment: '' };
}

// ---- BigInt helpers for RSA CRT parameters ----
function bytesToBig(b) { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; }
function bigToBytes(n) { let h = n.toString(16); if (h.length % 2) h = '0' + h; return Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16))); }

function pkcs8Wrap(algOid, params, privateOctets) {
  return derSeq(derInt(new Uint8Array([0])), derSeq(derOid(algOid), params), derOctet(privateOctets));
}
function ecPkcs8(curve, d, pub) {
  const sec1 = derSeq(derInt(new Uint8Array([1])), derOctet(d), ...(pub ? [derCtx(1, derBits(pub))] : []));
  return { type: 'ecdsa', curve, pkcs8: pkcs8Wrap(OID.ec, derOid(OID[curve]), sec1) };
}
function rsaPkcs8FromParts(n, e, d, p, q, iqmp) {
  const [N, E, D, P, Q] = [n, e, d, p, q].map(bytesToBig);
  const dp = D % (P - 1n), dq = D % (Q - 1n);
  const pkcs1 = derSeq(derInt(new Uint8Array([0])), derInt(n), derInt(e), derInt(d), derInt(p), derInt(q), derInt(bigToBytes(dp)), derInt(bigToBytes(dq)), derInt(iqmp));
  return { type: 'rsa', pkcs8: pkcs8Wrap(OID.rsa, derNull(), pkcs1) };
}

function parseOpenSSH(bytes) {
  const magic = 'openssh-key-v1\0';
  if (new TextDecoder().decode(bytes.subarray(0, magic.length)) !== magic) throw new Error('not an OpenSSH private key');
  const r = reader(bytes.subarray(magic.length));
  const cipher = r.text(); r.text(); r.string();
  if (cipher !== 'none') throw new Error('this key is passphrase-protected; export it without a passphrase first');
  const nkeys = r.u32();
  if (nkeys !== 1) throw new Error('unexpected key count');
  r.string(); // public key
  const priv = reader(r.string());
  priv.u32(); priv.u32();
  const keytype = priv.text();
  let out;
  if (keytype === 'ssh-ed25519') {
    priv.string();
    const sk = priv.string();
    out = { type: 'ed25519', pkcs8: pkcs8Wrap(OID.ed25519, new Uint8Array(0), derOctet(sk.subarray(0, 32))) };
  } else if (keytype === 'ssh-rsa') {
    const n = priv.string(), e = priv.string(), d = priv.string(), iqmp = priv.string(), p = priv.string(), q = priv.string();
    out = rsaPkcs8FromParts(n, e, d, p, q, iqmp);
  } else if (keytype.startsWith('ecdsa-sha2-')) {
    const curve = CURVES[priv.text()];
    if (!curve) throw new Error('unsupported curve');
    const pub = priv.string(), d = priv.string();
    out = ecPkcs8(curve, d, pub);
  } else {
    throw new Error(`unsupported key type ${keytype}`);
  }
  out.comment = priv.text();
  return out;
}

// Accepts PEM text, including text flattened onto one line by a password field.
export function parsePrivateKey(text) {
  const m = text.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/);
  if (!m) throw new Error('paste a private key in OpenSSH or PEM format');
  const label = m[1];
  const body = b64decode(m[2]);
  if (label === 'OPENSSH PRIVATE KEY') return parseOpenSSH(body);
  if (label === 'PRIVATE KEY') {
    const parts = pkcs8Parts(body);
    if (parts.type === 'ecdsa') return parseSec1(parts.inner, parts.curve); // re-wrapped with a named curve
    return { type: parts.type, pkcs8: body, comment: '' };
  }
  if (label === 'ENCRYPTED PRIVATE KEY') throw new Error('this key is passphrase-protected; export it unencrypted');
  if (label === 'RSA PRIVATE KEY') return { type: 'rsa', pkcs8: pkcs8Wrap(OID.rsa, derNull(), body), comment: '' };
  if (label === 'EC PRIVATE KEY') return parseSec1(body);
  throw new Error(`unsupported key format: ${label}`);
}

function algoParams(parsed, hash) {
  if (parsed.type === 'ed25519') return { name: 'Ed25519' };
  if (parsed.type === 'ecdsa') return { name: 'ECDSA', namedCurve: parsed.curve };
  return { name: 'RSASSA-PKCS1-v1_5', hash };
}

function publicBlobFromJwk(jwk) {
  if (jwk.kty === 'OKP') return concat(sshString('ssh-ed25519'), sshString(b64decode(jwk.x)));
  if (jwk.kty === 'EC') {
    const name = 'nistp' + jwk.crv.slice(2);
    const point = concat(new Uint8Array([4]), b64decode(jwk.x), b64decode(jwk.y));
    return concat(sshString('ecdsa-sha2-' + name), sshString(name), sshString(point));
  }
  return concat(sshString('ssh-rsa'), sshMpint(b64decode(jwk.e)), sshMpint(b64decode(jwk.n)));
}

export async function fingerprint(blob) {
  const h = new Uint8Array(await subtle.digest('SHA-256', blob));
  return 'SHA256:' + b64encode(h).replace(/=+$/, '');
}

// Import a private key. The returned record holds only non-extractable CryptoKeys.
export async function importPrivateKey(text, name) {
  const parsed = parsePrivateKey(text);
  const hashes = parsed.type === 'rsa' ? ['SHA-256', 'SHA-512'] : [undefined];
  const tmp = await subtle.importKey('pkcs8', parsed.pkcs8, algoParams(parsed, hashes[0]), true, ['sign']);
  const jwk = await subtle.exportKey('jwk', tmp);
  const blob = publicBlobFromJwk(jwk);
  const keys = {};
  for (const h of hashes) {
    const j = { ...jwk };
    delete j.alg; delete j.key_ops; delete j.ext;
    keys[h || 'sign'] = await subtle.importKey('jwk', j, algoParams(parsed, h), false, ['sign']);
  }
  parsed.pkcs8.fill(0);
  const sshType = blob.length >= 4 ? new TextDecoder().decode(blob.subarray(4, 4 + ((blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3]))) : '';
  return {
    fingerprint: await fingerprint(blob),
    name: name || parsed.comment || sshType,
    type: sshType,
    blob,
    keys,
    auto: false,
    added: new Date().toISOString(),
  };
}

// Sign an agent challenge. Returns the raw signature the daemon wraps into SSH format.
export async function sign(rec, algorithm, data) {
  if (algorithm === 'ssh-ed25519') return new Uint8Array(await subtle.sign({ name: 'Ed25519' }, rec.keys.sign, data));
  if (algorithm.startsWith('ecdsa-sha2-nistp')) {
    const hash = { nistp256: 'SHA-256', nistp384: 'SHA-384', nistp521: 'SHA-512' }[algorithm.slice(11)];
    return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash }, rec.keys.sign, data));
  }
  if (algorithm === 'rsa-sha2-256') return new Uint8Array(await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, rec.keys['SHA-256'], data));
  if (algorithm === 'rsa-sha2-512') return new Uint8Array(await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, rec.keys['SHA-512'], data));
  throw new Error(`unsupported algorithm ${algorithm}`);
}

export { b64url };
