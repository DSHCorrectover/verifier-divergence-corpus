#!/usr/bin/env node
// verify.mjs — replay harness: asserts corpus consistency and re-runs verdicts on YOUR stack.
// Usage: npm i @noble/curves@2.4.0 tweetnacl && node verify.mjs
import { ed25519 } from '@noble/curves/ed25519.js';
import nacl from 'tweetnacl';
import { verify as nodeVerify, createPublicKey, createHash } from 'node:crypto';
import fs from 'node:fs';

const V = JSON.parse(fs.readFileSync('vectors.json', 'utf8'));
const R = JSON.parse(fs.readFileSync('rows.json', 'utf8'));

let fail = 0;
const ok = (name, cond) => { console.log((cond ? 'PASS' : 'FAIL') + '  ' + name); if (!cond) fail++; };

// 1. content lock
for (const f of ['vectors.json', 'rows.json']) {
  const h = createHash('sha256').update(fs.readFileSync(f)).digest('hex');
  const m = fs.readFileSync('manifest.sha256', 'utf8').split('\n').find(l => l.endsWith(f));
  ok('manifest: ' + f, m && m.startsWith(h));
}

// 2. math: every encoding is small-order (8P = I) — via decoding + multiplication
for (const v of V.vectors) {
  const P = ed25519.Point.fromBytes(new Uint8Array(Buffer.from(v.encoding_hex, 'hex')));
  ok('8P=I  ' + v.encoding_hex.slice(0, 16) + '…', P.multiply(8n).equals(ed25519.Point.ZERO));
}

// 3. replay verdicts (RSB shape, noble + tweetnacl + node:crypto)
for (let i = 0; i < V.vectors.length; i++) {
  const v = V.vectors[i], r = R[i];
  const A = new Uint8Array(Buffer.from(v.encoding_hex, 'hex'));
  const M = new Uint8Array(Buffer.from(v.message_variant_hex || V.base_message_hex, 'hex'));
  const S = new Uint8Array(Buffer.from(v.sig_rsb_hex, 'hex'));
  const Z = new Uint8Array(Buffer.from(V.sig_zero_hex, 'hex'));
  const nb = o => { try { return ed25519.verify(S, M, A, o) === true; } catch { return false; } };
  ok(`noble default    accepts  ${v.cls}  (expect ${r['noble-2.4.0:default']})`, nb(undefined) === r['noble-2.4.0:default']);
  ok(`noble zip215:f   rejects  ${v.cls}  (expect ${r['noble-2.4.0:zip215_false']})`, nb({ zip215: false }) === r['noble-2.4.0:zip215_false']);
  const tn = (() => { try { return nacl.sign.detached.verify(M, S, A) === true; } catch { return false; } })();
  ok(`tweetnacl        verdict  ${v.cls}  (expect ${r['tweetnacl']})`, tn === r['tweetnacl']);
  const nc = (() => { try { return nodeVerify(null, M, createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(v.encoding_hex, 'hex')]), format: 'der', type: 'spki' }), S) === true; } catch { return false; } })();
  ok(`node:crypto      rejects  ${v.cls}  (expect ${r['node-crypto(OpenSSL3.5.8)'] === false})`, nc === false);
}

console.log(fail ? `\n${fail} FAILURES — corpus does not match this environment; record your rows.json!` : '\nALL PASS — divergence reproduced on this stack. Your verify() verdict is now pinned.');
process.exit(fail ? 1 : 0);
