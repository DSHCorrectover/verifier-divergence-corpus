# verifier-divergence-corpus

**Ed25519 small-order zero-key forgery — cross-verifier verdict divergence dataset (v1, 2026-11-20)**

## One-page thesis

The same zero-secret forgery — a public key taken from the 8-point small-order torsion subgroup of Ed25519, paired with a signature an attacker computes without knowing any scalar — produces **different verdicts on every mainstream verifier**:

| Verifier (same machine, same vectors) | accepts enumerated R=S·G forgery | accepts all-zero signature |
|---|---|---|
| @noble/curves 2.4.0 `verify()` **default** | **8/8** | **8/8** |
| @noble/curves 2.4.0 `{zip215:false}` | 0/8 | 0/8 |
| tweetnacl (latest) | 2/8 | 1/8 |
| OpenSSL CLI 3.5.7 (`pkeyutl -rawin`) | 2/8 | 0/8 |
| pyca/cryptography 44.0.3 | 2/8 | 0/8 |
| node:crypto (OpenSSL 3.5.8 lib) | 0/8 | 0/8 |

Per-encoding rows: `rows.json` (machine-generated, SHA-256-locked in `manifest.sha256`). Every vector's verification equation `S·G == R + k·A` (k = H(R‖A‖M) mod ℓ) is independently verified true before testing — acceptance vs rejection is a **policy choice per implementation**, not a math disagreement.

**A trust decision that flips on library choice is not a verification result — it is an implementation artifact.** Any protocol that treats `verify() == true` as a trust anchor (receipts, DSSE, attestation, payment signing) inherits whichever verdict its dependency vendor chose. The fix is not "use a different library"; it is an evidence layer that pins the decision: pinned vectors, pinned semantics, independent replay. That is what this corpus is for.

## Attack construction (zero secret, attacker-side only)

```
S ← canonical scalar (attacker-chosen, fixed)
R ← S·G                      ← public point arithmetic, no secret
A ← small-order encoding     ← 8-torsion subgroup; ord(A) ∈ {1,2,4}
sig ← R ‖ S
enumerate message variant #n until k = H(R‖A‖Mₙ) mod l ≡ 0 (mod ord(A))   — ≤ 2³ hashes
then S·G == R + k·A holds exactly (cofactorless); cofactored: 8·(k·A) = 0 always
```

Every vector in `vectors.json` ships with its message variant and the equation check (`math_eq_verified: true` for all 8 encodings). The all-zero signature (`R=I, S=0`) additionally demonstrates degenerate-case acceptance.

## Files

| file | purpose | license |
|---|---|---|
| `vectors.json` | 8 small-order encodings (orders 1/2/4/4/8/8/8/8, each proven `8P=I`), message variants, forged signatures | CC0 |
| `rows.json` | machine-run verdict matrix, 6 verifier configurations × 8 encodings × 2 signature shapes | CC0 |
| `corpus-build.mjs` | deterministic generator: re-enumerates torsion encodings from curve math, rebuilds vectors, re-runs the matrix | MIT |
| `verify.mjs` | replay harness: asserts vectors.json/rows.json consistency and re-executes the verdicts on your stack | MIT |
| `manifest.sha256` | content lock | — |

## Reproduce (30-second PoC)

```bash
git clone https://github.com/DSHCorrectover/verifier-divergence-corpus.git
cd verifier-divergence-corpus
npm i @noble/curves@2.4.0 tweetnacl
node verify.mjs
```

Expected output: `ALL PASS — divergence reproduced on this stack.` (verified on a fresh public clone 2026-11-20; CI runs the same harness on Node 20/22/24 on every push.)

The harness checks, in order: ① SHA-256 manifest lock on vectors/rows ② every encoding is mathematically small-order (8P = I) ③ every forgery satisfies the verification equation S·G == R + k·A ④ re-runs noble (3 option sets), tweetnacl and node:crypto verdicts against the recorded rows on **your** stack — any mismatch tells you *your* verifier's policy differs.

Verdicts for `node:crypto`, OpenSSL CLI and pyca replay with system OpenSSL / Python (`openssl pkeyutl`, `cryptography`).

## Provenance

- First documented publicly in paulmillr/noble-curves#261 (2026-11-19) and corrected/clarified in issuecomment-7027062323 (2026-11-20).
- Related background: RFC 8032 §8.8; ZIP-215 semantics (Ellumus/Zcash); Solana `is_small_order` pre-checks in @solana/kit.
- Maintained by Correctover (AI Reliability) — the deterministic audit-trail engine for agent ecosystems. Contact: wangguigui@correctover.com

## Scope & honesty notes

- Environment: Linux 5.10 x86_64, Node 24.21.0, OpenSSL 3.5.7/3.5.8, pyca 44.0.3, tweetnacl latest (2026-11). Verdicts are environment-tagged, not universal claims.
- Go `crypto/ed25519` was characterized in earlier runs (accepts identity-key forgeries; enumerable) but is **not** in this v1 matrix — no Go toolchain in the build environment. v2 will add it, plus Rust ed25519-dalek.
- `zip215:false` on noble-curves rejects all small-order vectors — the strict path works and is documented upstream; the divergence is about **defaults and cross-library inconsistency**, not a bypass claim.
