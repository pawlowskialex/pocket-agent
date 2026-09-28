// Unit test for web/sshkey.js under Node: parse keys made by ssh-keygen, compare the derived
// public key with the .pub file, and round-trip a signature. Run: node test/sshkey.test.mjs
import { importPrivateKey, sign, parsePrivateKey, b64encode, b64decode } from '../web/sshkey.js';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto, generateKeyPairSync, createPrivateKey, createPublicKey, verify } from 'node:crypto';

const dir = mkdtempSync(join(tmpdir(), 'sshkey-'));
let fail = 0;
const check = (ok, msg) => { console.log((ok ? 'ok   ' : 'FAIL ') + msg); if (!ok) fail = 1; };

const cases = [
  ['ed25519', ['-t', 'ed25519'], 'ssh-ed25519'],
  ['ecdsa256', ['-t', 'ecdsa', '-b', '256'], 'ecdsa-sha2-nistp256'],
  ['ecdsa384', ['-t', 'ecdsa', '-b', '384'], 'ecdsa-sha2-nistp384'],
  ['rsa', ['-t', 'rsa', '-b', '2048'], 'rsa-sha2-512'],
];
for (const [name, args, algo] of cases) {
  const f = join(dir, name);
  execFileSync('ssh-keygen', ['-q', ...args, '-N', '', '-C', `comment-${name}`, '-f', f]);
  const pub = readFileSync(f + '.pub', 'utf8').trim().split(' ');
  const text = readFileSync(f, 'utf8');
  const rec = await importPrivateKey(text, '');
  check(b64encode(rec.blob) === pub[1], `${name}: public key blob matches ssh-keygen`);
  check(rec.name === `comment-${name}`, `${name}: name from comment (${rec.name})`);
  const fp = execFileSync('ssh-keygen', ['-lf', f + '.pub']).toString().split(' ')[1];
  check(rec.fingerprint === fp, `${name}: fingerprint matches (${rec.fingerprint})`);

  // Flattened onto one line (as a password field would do)
  const flat = await importPrivateKey(text.replace(/\n/g, ' '), 'flat');
  check(flat.fingerprint === fp, `${name}: parses when flattened to one line`);

  // PKCS#8 form: ssh-keygen converts RSA/ECDSA; for Ed25519 use openssl and derive the .pub with ssh-keygen -y
  if (name === 'ed25519') {
    // ssh-keygen cannot write/read Ed25519 PKCS#8 here; compare with Node's own public key instead.
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const p8 = await importPrivateKey(privateKey.export({ type: 'pkcs8', format: 'pem' }), 'p8');
    const x = b64decode(publicKey.export({ format: 'jwk' }).x);
    const want = new Uint8Array([0, 0, 0, 11, ...new TextEncoder().encode('ssh-ed25519'), 0, 0, 0, 32, ...x]);
    check(b64encode(p8.blob) === b64encode(want), `${name}: PKCS#8 form imports`);
  } else {
    // Traditional PEM via ssh-keygen (EC/RSA PRIVATE KEY), then PKCS#8 via Node.
    writeFileSync(f + '.pem', text, { mode: 0o600 });
    execFileSync('ssh-keygen', ['-p', '-N', '', '-m', 'PEM', '-f', f + '.pem'], { stdio: 'ignore' });
    const pem = readFileSync(f + '.pem', 'utf8');
    const trad = await importPrivateKey(pem, 'pem');
    check(trad.fingerprint === fp, `${name}: traditional PEM form imports`);
    const p8 = await importPrivateKey(createPrivateKey(pem).export({ type: 'pkcs8', format: 'pem' }), 'p8');
    check(p8.fingerprint === fp, `${name}: PKCS#8 form imports`);
  }

  // Sign and verify with WebCrypto public key derived from the blob
  const data = new TextEncoder().encode('challenge ' + name);
  const sig = await sign(rec, algo, data);
  let verified = false;
  if (algo === 'ssh-ed25519') {
    const x = rec.blob.subarray(4 + 11 + 4);
    const pk = await webcrypto.subtle.importKey('raw', x, { name: 'Ed25519' }, false, ['verify']);
    verified = await webcrypto.subtle.verify({ name: 'Ed25519' }, pk, sig, data);
  } else {
    // Verify with Node's crypto against the public half of the same key (from the PEM made above).
    const pub = createPublicKey(createPrivateKey(readFileSync(f + '.pem', 'utf8')));
    if (algo.startsWith('ecdsa')) verified = verify(algo.endsWith('256') ? 'sha256' : 'sha384', data, { key: pub, dsaEncoding: 'ieee-p1363' }, sig);
    else verified = verify('sha512', data, pub, sig);
  }
  check(verified, `${name}: signature verifies (${algo})`);
}
try { parsePrivateKey('garbage'); check(false, 'garbage rejected'); } catch (e) { check(true, 'garbage rejected: ' + e.message); }
const enc = join(dir, 'enc'); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', 'secret', '-f', enc]);
try { parsePrivateKey(readFileSync(enc, 'utf8')); check(false, 'encrypted rejected'); } catch (e) { check(true, 'encrypted rejected: ' + e.message); }
console.log(fail ? 'SOME FAILED' : 'ALL PASSED');
process.exit(fail);
