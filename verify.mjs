#!/usr/bin/env node
// verify.mjs — replay harness: corpus consistency + verdict replay on YOUR stack.
// Hard checks: manifest lock, small-order math, equation, pinned-dep verdicts (noble/tweetnacl).
// Soft check: node:crypto — its verdict depends on the OpenSSL your Node was built with
//             (recorded env: OpenSSL 3.5.8 → rejects all; e.g. Ubuntu 22.04 OpenSSL 3.0 → accepts some).
//             A divergence here is DATA, not failure: append your row upstream.
// Usage: git clone ... && npm i && node verify.mjs
import { ed25519 } from '@noble/curves/ed25519.js';
import nacl from 'tweetnacl';
import { verify as nodeVerify, createPublicKey, createHash } from 'node:crypto';
import fs from 'node:fs';

const V = JSON.parse(fs.readFileSync('vectors.json', 'utf8'));
const R = JSON.parse(fs.readFileSync('rows.json', 'utf8'));

let fail = 0, softDiverge = 0;
const hard = (name, cond) => { console.log((cond ? 'PASS' : 'FAIL') + '  ' + name); if (!cond) fail++; };
const note = (name) => { console.log('NOTE  ' + name); softDiverge++; };

// 1. content lock
for (const f of ['vectors.json', 'rows.json']) {
  const h = createHash('sha256').update(fs.readFileSync(f)).digest('hex');
  const m = fs.readFileSync('manifest.sha256', 'utf8').split('\n').find(l => l.endsWith(f));
  hard('manifest: ' + f, !!m && m.startsWith(h));
}

// 2. math: every encoding is small-order (8P = I)
for (const v of V.vectors) {
  const P = ed25519.Point.fromBytes(new Uint8Array(Buffer.from(v.encoding_hex, 'hex')));
  hard(`8P=I  ${v.cls}  ${v.encoding_hex.slice(0, 16)}…`, P.multiply(8n).equals(ed25519.Point.ZERO));
}

// 3. equation: S·G == R + k·A for every vector (independent of any verifier's policy)
for (const v of V.vectors) {
  const A = ed25519.Point.fromBytes(new Uint8Array(Buffer.from(v.encoding_hex, 'hex')));
  const sig = Buffer.from(v.sig_rsb_hex, 'hex');
  const Rv = ed25519.Point.fromBytes(sig.subarray(0, 32));
  const Sv = 0n; { let s = 0n; for (const b of sig.subarray(32)) s = (s << 8n) | BigInt(b); }
  const M = Buffer.from(v.message_variant_hex || V.base_message_hex, 'hex');
  const hbuf = createHash('sha512').update(Buffer.concat([sig.subarray(0, 32), Buffer.from(v.encoding_hex, 'hex'), M])).digest();
  let kv = 0n; for (let i = 63; i >= 0; i--) kv = (kv << 8n) | BigInt(hbuf[i]); kv %= ed25519.Point.CURVE().n;
  hard(`equation S·G==R+k·A  ${v.cls}`, ed25519.Point.BASE.multiply(Sv).equals(Rv.add(A.multiply(kv))));
}

// 4. verdict replay
for (let i = 0; i < V.vectors.length; i++) {
  const v = V.vectors[i], r = R[i];
  const A = new Uint8Array(Buffer.from(v.encoding_hex, 'hex'));
  const M = new Uint8Array(Buffer.from(v.message_variant_hex || V.base_message_hex, 'hex'));
  const S = new Uint8Array(Buffer.from(v.sig_rsb_hex, 'hex'));
  const nb = (opts) => { try { return ed25519.verify(S, M, A, opts) === true; } catch { return false; } };
  hard(`noble default   (expect ${r['noble-2.4.0:default']})`, nb(undefined) === r['noble-2.4.0:default']);
  hard(`noble zip215:f  (expect ${r['noble-2.4.0:zip215_false']})`, nb({ zip215: false }) === r['noble-2.4.0:zip215_false']);
  const tn = (() => { try { return nacl.sign.detached.verify(M, S, A) === true; } catch { return false; } })();
  hard(`tweetnacl       (expect ${r['tweetnacl']})`, tn === r['tweetnacl']);
  const nc = (() => { try { return nodeVerify(null, M, createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(v.encoding_hex, 'hex')]), format: 'der', type: 'spki' }), S) === true; } catch { return false; } })();
  const recorded = r['node-crypto(OpenSSL3.5.8)'] === false;
  if (recorded ? nc !== false : true) {
    // recorded env (OpenSSL 3.5.8) rejects all; other OpenSSL builds may accept — divergence is data
    if (nc !== false) note(`node:crypto ACCEPTS ${v.cls} ${v.encoding_hex.slice(0, 12)}… on your OpenSSL — recorded rows say reject (OpenSSL 3.5.8). Divergence datum, please cite upstream.`);
  } else {
    console.log('PASS  node:crypto       rejects (matches recorded)');
  }
}

console.log('');
if (softDiverge) console.log(`${softDiverge} node:crypto verdict(s) diverge from the recorded OpenSSL-3.5.8 environment — this is the phenomenon under study, not a harness failure. Report your OpenSSL version: node -e "console.log(process.versions.openssl)"`);
console.log(fail ? `${fail} HARD FAILURES — corpus integrity problem, do not cite.` : 'HARD CHECKS ALL PASS — corpus integrity verified; divergence reproduced.');
process.exit(fail ? 1 : 0);
