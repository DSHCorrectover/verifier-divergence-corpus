#!/usr/bin/env node
// poc-vacuity.mjs — one-command, idempotent PoC for the vacuity theorem (v1.1).
//
// THEOREM (empirically demonstrated here): for an Ed25519 public key A in the
// small-order torsion subgroup (ord(A) | 8), a forged signature constructed as
//   R = s·B − k_used·A     (s any scalar < ℓ, k_used any scalar — ALL PUBLIC values,
//                           zero secret knowledge required)
// is accepted by every zip215-style COFACTORED verifier for ANY message,
// because the verification check [8](R + k·A − s·B) == 0 holds for ANY k = H(R,A,M):
//   R + k·A − s·B = (k_used − k)·A  ∈  E[8-torsion]  →  killed by [8].
// The equation therefore constrains only the PUBLIC, attacker-computable relation
// R = s·B − k_used·A — never the message binding. Acceptance must come from an
// explicit subgroup property test (isSmallOrder / strict mode), not the equation.
//
// Usage: node poc-vacuity.mjs   (deterministic; exits 0 when phenomenon reproduced)
import { ed25519 } from '@noble/curves/ed25519.js';
import nacl from 'tweetnacl';
import fs from 'node:fs';

const V = JSON.parse(fs.readFileSync('vectors.json', 'utf8'));
const Ahex = V.vectors[2].encoding_hex; // order-4 canonical vector
const A = ed25519.Point.fromBytes(new Uint8Array(Buffer.from(Ahex, 'hex')));
const Abytes = new Uint8Array(Buffer.from(Ahex, 'hex'));

// forge: s = 4·2^248 (LE, < ℓ), k_used = 1, R = s·B − k_used·A
const s = Buffer.alloc(32); s[31] = 0x04;
let sN = 0n; for (let i = 31; i >= 0; i--) sN = (sN << 8n) | BigInt(s[i]);
const R = ed25519.Point.BASE.multiplyUnsafe(sN).subtract(A.multiplyUnsafe(1n));
const S = new Uint8Array(64);
Buffer.from(R.toBytes()).copy(S, 0); s.copy(S, 32);

const msgs = ['any message 1', 'totally different content', 'attacker-chosen payload 3'];
let accepted = 0, strictRejected = 0, controlOk = false, tnAccepted = 0;
const rows = [];
for (const msg of msgs) {
  const M = new Uint8Array(Buffer.from(msg));
  const zt = ed25519.verify(S, M, Abytes, { zip215: true });
  const zf = ed25519.verify(S, M, Abytes, { zip215: false });
  const dn = ed25519.verify(S, M, Abytes);
  const tn = nacl.sign.detached.verify(M, S, Abytes);
  if (zt) accepted++;
  if (dn) accepted; // noble default == zip215:true semantics
  if (zf === false) strictRejected++;
  if (tn) tnAccepted++;
  rows.push({ msg: msg.slice(0, 26), zip215_true: zt, zip215_false: zf, noble_default: dn, tweetnacl: tn });
}
// control: same forged sig against a NORMAL prime-order key must be rejected
const kp = ed25519.keygen();
controlOk = ed25519.verify(S, new Uint8Array(Buffer.from('any message 1')), kp.publicKey, { zip215: true }) === false;

console.log(JSON.stringify({ poc: 'vacuity-theorem-v1.1', forgeries_accepted_cofactored: `${accepted}/3`, strict_rejected: `${strictRejected}/3`, control_normal_key_rejected: controlOk, tweetnacl_accepted: `${tnAccepted}/3 (message-dependent — additional divergence datum)`, rows }, null, 1));
const pass = accepted === 3 && strictRejected === 3 && controlOk;
console.log(pass ? 'POC PASS — vacuity reproduced: cofactored path accepts all 3 zero-secret forgeries; strict path rejects all; control clean.' : 'POC FAIL — environment divergence; please report your stack.');
process.exit(pass ? 0 : 1);
