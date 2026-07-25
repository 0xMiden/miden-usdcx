# Precompile-Execution Grounding Canary — Report (P5-01)

**Final status: `GROUNDED`. Verdict: D5d can proceed on this proven primitive with NO custom host
wiring.** The Keccak256 and secp256k1-ECDSA-over-keccak precompiles are proven to **EXECUTE** (not
merely assemble / `procref`) end-to-end under MockChain on the pinned **Miden v0.15.3 / assembler
0.23.3 / miden-crypto 0.25.1** stack, via the safe `CodeBuilder` + `miden-testing` path (no raw
`Assembler`). All seven `<questions_to_resolve>` are answered below with running-code evidence plus a
`file:line` source ground.

This canary is **scratch**: it hashes a known input and verifies one valid + several
structurally-valid-but-invalid signature triples. It decides **nothing** about the faucet's real
attestation/allowlist logic, and touches no faucet (`asm/standards/xreserve/`), 04, or D5a/D5b/D5c
source. Its purpose is to retire the one toolchain item `BUILDER-GATES.md` G-MASM still lists PENDING
— *precompile **execution** with `Host` handlers* — so **D5d (keccak the DepositIntent payload +
ECDSA-verify against an allowlisted attester key, R-MINT-13/14)** builds on a proven primitive instead
of guesswork. The MASM grounding spike (`docs/governing/GROUNDING-REPORT.md` §2 Q2) had proven the
precompiles only *present & assembly-linkable*; this canary goes past that to **execution**.

| | |
|---|---|
| Pin (API ground truth) | `protocol v0.15.3` (`681fc9058`) → `miden-core-lib`/`miden-assembly` `0.23.3`; `miden-crypto 0.25.1` |
| Safe path | `CodeBuilder::new()` → `compile_component_code` / `compile_tx_script`; stock `MockChain` host |
| Gate | MockChain (NOT local-node) |
| Branch / commits | `canary/storage-map-grounding` / `6e46d0f` (canary, signed) + `744cdfa` (malformed-error pin, signed) |
| Result | `test result: ok. 7 passed; 0 failed` |
| Anti-circularity | ECDSA keypair+signature from independent `k256` (re-verified by `k256`); keccak digest from independent `sha3` |

Source-path conventions below: **MASM/handler cites** are `miden-core-lib 0.23.3` under
`~/.cargo/registry/src/<hash>/miden-core-lib-0.23.3/` (`<hash> = index.crates.io-1949cf8c6b5b557f`);
**host cites** are `protocol-pin-v0.15.3/`; **crypto cites** are `miden-crypto-0.25.1` under the same
registry. The running-code evidence is the seven-test suite in §3.

---

## 1. Files created (isolated scratch tree)

All under `xusdc-miden/canary/precompile-execution-grounding/` — an isolated Cargo workspace (own
`[workspace]` table) so the parent `xusdc-miden/Cargo.toml` is untouched:

```
canary/precompile-execution-grounding/
  Cargo.toml             # isolated workspace; path-deps -> ../../../protocol-pin-v0.15.3;
                         #   vector-gen dev-deps ONLY: k256, sha3, rand, miden-crypto (format/Poseidon2)
  Cargo.lock             # seeded from the pin -> miden-core-lib 0.23.3 / miden-crypto 0.25.1
  asm/canary_precompile.masm  # 3 pub-proc drivers over @locals scratch; advice-delivered inputs; G-MASM house style
  src/lib.rs             # include_str! the .masm + path const
  tests/precompile_canary.rs  # MockChain gate: 7 tests; independent vector gen + assertions
  PRECOMPILE-EXECUTION-GROUNDING-REPORT.md   # this file
  target/                # build artifacts (gitignored)
```

The driver bodies mirror the upstream precedent
`miden-core-lib-0.23.3/asm/crypto/dsa/ecdsa_k256_keccak.masm` (the `verify` advice→locals
materialization) and `.../hashes/keccak256.masm` (the `hash` wrapper), so the findings transfer to
D5d's real attestation proc.

---

## 2. Questions resolved (each: answer + source `file:line` + running-code evidence)

### Q1 — Keccak execution + contract
- **Contract (`asm/crypto/hashes/keccak256.masm:22-39`):** `keccak256::hash_bytes` — `Input:
  [ptr, len_bytes]`, `Output: [DIGEST_U32[8]]`. `ptr` is a word-aligned memory address holding the
  input packed **4 bytes per u32, little-endian** (`v_i = u32::from_le_bytes([b_4i..b_4i+3])`,
  encoding conventions `:4-12`; unused trailing bytes zero). The 256-bit digest returns as **8 u32
  limbs `d_0..d_7` on the stack, least-significant limb `d_0` on top** (handler doc
  `src/handlers/keccak256.rs:60-65`).
- **Deferred precompile:** `hash_bytes` `emit`s `KECCAK_HASH_BYTES_EVENT` (`keccak256.masm:103`); the
  host `KeccakPrecompile` computes a **real `miden_core::crypto::hash::Keccak256`** and supplies the
  digest via the advice stack (`src/handlers/keccak256.rs:88+`; the proc reads it back with `adv_pipe`
  at `keccak256.masm:115`). This is the proc D5d uses (variable-length payload).
- **Evidence:** test `keccak_hash_bytes_known_answer` drives `keccak_hash_bytes_canary` (advice-fed
  32-byte input) and asserts each of the 8 returned limbs equals an **INDEPENDENT** `sha3::Keccak256`
  digest (`push.{e_i} assert_eq` per limb). Output: `Q1 keccak256::hash_bytes EXECUTED under MockChain;
  digest == sha3 known-answer.`

### Q2 — ECDSA-verify execution + contract
- **Consts (`asm/crypto/dsa/ecdsa_k256_keccak.masm:20-22`):** `PK_LEN_FELTS=9, DIGEST_LEN_FELTS=8,
  SIG_LEN_FELTS=17`.
- **`verify_prehash` (`ecdsa_k256_keccak.masm:102-130`):** `Input: [pk_ptr, digest_ptr, sig_ptr]`,
  `Output: [result]`. All three in **word-aligned memory**, packed 4 bytes/u32 LE: pk = **33-byte
  compressed SEC1** (9 felts), digest = 32 bytes (8 felts), sig = **65-byte `r‖s‖v`** (17 felts;
  `src/handlers/ecdsa.rs:29-31, 60-65` — `r(32)+s(32)+v(1)`). This is D5d's primitive
  (recompute-keccak-digest → verify_prehash).
- **`verify` (`ecdsa_k256_keccak.masm:27-100`, `@locals(48)`):** operand `[PK_COMM, MSG]` + advice
  `[PK[9]‖SIG[17]]`; `PK_COMM = Poseidon2::hash_elements(pk_felts)` (asserted `:65-66`), `MSG` is a
  single word keccak'd internally to 32 bytes (via `word::store_word_u32s_le`, `asm/word.masm:27`);
  `Output: []`.
- **Evidence:** `ecdsa_verify_prehash_accept` (memory path) and `ecdsa_verify_accept_via_advice`
  (advice path) both EXECUTE and accept a valid independent `k256` triple. Output: `Q2/Q3 … valid
  triple -> result == 1 (accept).` and `Q2/Q5 ecdsa verify (advice path) EXECUTED; valid triple
  accepted (no trap).`

### Q3 — Accept vs reject semantics (load-bearing for R-MINT-14)
- **Valid → `verify_prehash` returns `1`** (`src/handlers/ecdsa.rs:118-119` pushes
  `Felt::from_bool(result)` via advice; `result = pk.verify_prehash(digest, sig)` at `:193-195`);
  `verify` returns `[]` (no trap).
- **Structurally-valid-but-invalid (wrong key / wrong digest) → `verify_prehash` returns `0` (NO
  trap)**; the `verify` wrapper **TRAPS** via `assert.err="ECDSA signature verification failed"`
  (`ecdsa_k256_keccak.masm:99`).
- **Malformed bytes are a DIFFERENT mode:** the handler `read_from_bytes`-deserializes pk+sig
  **before** verifying (`src/handlers/ecdsa.rs:94-108`), so corrupt bytes raise an
  `EcdsaError::DeserializeError` (a host **event error** that aborts the tx) — **not** a boolean `0`.
- **D5d wiring:** the forged-signature reject can be **fail-closed via the `verify` trap**, or an
  explicit branch on `verify_prehash`'s `0/1`. Either is grounded.
- **Evidence (four tests):** `…reject_wrong_key` → `result == 0`; `…reject_wrong_digest` → `result ==
  0`; `…trap_on_validly_serialized_invalid` → tx fails with the exact string `ECDSA signature
  verification failed`; `…malformed_bytes` → tx fails with `failed to deserialize signature` /
  `Invalid recovery ID` (asserted, not just `is_err()`). Each reject/trap vector is independently
  confirmed invalid by `k256`'s own verifier before MASM.

### Q4 — HOST-HANDLER (the crux): default MockChain host auto-registers the handlers; NO manual wiring
- **Source chain (read-only):**
  1. `miden-core-lib-0.23.3/src/lib.rs:133-147` — `CoreLibrary::handlers()` returns
     `(KECCAK_HASH_BYTES_EVENT → KeccakPrecompile)` and `(ECDSA_VERIFY_EVENT → EcdsaPrecompile)`
     (event names `src/handlers/keccak256.rs:44-46`, `src/handlers/ecdsa.rs:57-58`).
  2. `protocol-pin-v0.15.3/crates/miden-tx/src/host/mod.rs:116-126` — `TransactionBaseHost::new()`
     loops `CoreLibrary::default().handlers()` and registers every handler into `core_lib_handlers`
     (dispatched by `handle_core_lib_events`, `:267-277`).
  3. `protocol-pin-v0.15.3/crates/miden-testing/src/mock_host.rs:43-69` — *"CoreLibrary events are
     always handled."*
- **Evidence:** all seven tests run through the stock
  `mock_chain.build_tx_context(...).extend_advice_inputs(...).tx_script(...).build().execute()` —
  **no custom host, no manual handler registration** — and the precompiles execute. (An assemble-only
  / `procref` test could not produce the keccak digest or the 0/1 verify result; both required the
  registered handlers to run.)

### Q5 — Advice/host inputs
- **Host handlers supply the OUTPUTS via advice automatically** — keccak digest
  (`keccak256.masm:115` `adv_pipe`) and ecdsa result (`ecdsa.rs:118-119` → `ecdsa_k256_keccak.masm:162`
  `adv_push`). The harness does **not** seed those.
- **The harness supplies the INPUTS:** `verify_prehash` reads pk/digest/sig from **memory**
  (caller-placed); the `verify` wrapper reads pk+sig from the **advice stack**. The canary models
  D5d's advice delivery by reading all driver inputs from the advice stack into `@locals` (mirroring
  `verify`'s materialization, `ecdsa_k256_keccak.masm:57-90`) and seeding them via
  `TransactionContextBuilder::extend_advice_inputs` (`miden-testing/src/tx_context/builder.rs:149`).
- **Advice ordering (calibrated to source):** `AdviceInputs.stack` is read **FIFO in seed order** —
  `extend_stack` collects, reverses, and `push_front`s, and `pop_stack` does `pop_front`
  (`miden-processor-0.23.3/src/host/advice/mod.rs:338-348, 193-194`). The canary seeds `[PK(9),
  DIGEST(8), SIG(17)]` and the driver reads them in that order; the passing accept test confirms it.
- **`advice-provider-hygiene` implication for D5d:** the attester pubkey + signature are
  attacker-influenced advice. D5d MUST validate them (length/format) and never default — and MUST bind
  the pubkey to the **allowlist commitment** (`Poseidon2(pubkey)`), exactly as the `verify` wrapper
  already binds pk to `PK_COMM` (`ecdsa_k256_keccak.masm:64-66`). A forged pubkey that does not hash to
  the committed value is rejected before verification.

### Q6 — Cost/feasibility signal
- **Deferred execution = cheap in-VM:** the heavy Keccak/ECDSA computation runs **host-side** in the
  precompile handler; the in-VM cost is only the calldata materialization + the commitment `Poseidon2`
  hashes (`ecdsa_k256_keccak.masm:165-195`). The full circuit is re-checked at proving time by the
  `PrecompileVerifier`, not during tx execution.
- **Wall-clock:** all seven MockChain transactions (4 keccak/ecdsa execs + advice paths + trap +
  malformed) complete in **~0.33s total** — a single keccak or ECDSA-verify is sub-millisecond order
  under MockChain. No feasibility red flag for D5d.
- **One constraint to carry forward:** the keccak handler enforces a `max_hash_len_bytes` input cap
  (`src/handlers/keccak256.rs`); D5d's DepositIntent payload must stay under it.

### Q7 — Local-node residual (no overclaim)
- **What this proves:** MockChain shares the `miden-tx` transaction host (Q4 chain), so the precompiles
  **execute** through the same host path the devnet node uses at **execution** time.
- **What it does NOT prove:** (a) the deferred precompile **verification** end-to-end at **proving**
  time (the `PrecompileVerifier` recompute + commitment check — `src/handlers/ecdsa.rs:125-136`,
  `src/handlers/keccak256.rs`); and (b) **devnet `miden-node v0.15.0`** precompile execution + proving.
  Both are a separate, later gate (`BUILDER-GATES.md` §3.9 local-node-validation). No MockChain →
  devnet claim is made.

---

## 3. Exact commands + outputs

Run from `xusdc-miden/`. `cargo` runs sandboxed for source reads; the signed `git commit` ran with the
sandbox disabled because it must read the SSH signing key under `~/.ssh` (blocked by the default
sandbox).

**MockChain gate (EXECUTES the precompiles — assemble-only / `procref` would be invalid):**
```
$ cargo test --locked --manifest-path canary/precompile-execution-grounding/Cargo.toml \
      --test precompile_canary -- --nocapture
[canary] Q1 keccak256::hash_bytes EXECUTED under MockChain; digest == sha3 known-answer.
[canary] Q2/Q3 ecdsa verify_prehash EXECUTED; valid triple -> result == 1 (accept).
[canary] Q3 ecdsa verify_prehash EXECUTED; wrong-key triple -> result == 0 (reject).
[canary] Q3 ecdsa verify_prehash EXECUTED; wrong-digest triple -> result == 0 (reject).
[canary] Q2/Q5 ecdsa verify (advice path) EXECUTED; valid triple accepted (no trap).
[canary] Q3 ecdsa verify (advice path) EXECUTED; forged triple TRAPPED (fail-closed).
[canary] malformed-sig case EXECUTED; surfaced a deserialization error (NOT a boolean reject):
         failed to deserialize signature -> invalid value: Invalid recovery ID
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.33s
```

**Proof of EXECUTION (not assembly):** the first runs failed at runtime with VM `call`-contract errors
— `when returning from a call, stack depth must be 16, but was 24` (keccak) and `… but was 17`
(verify_prehash) — resolved by the trailing `repeat.8 movup.8 drop` / `swap drop` depth normalization.
Assemble-only / `procref` resolution could never surface these.

**Reproducible lock (G0 build hygiene) + pins:**
```
$ cargo build --locked --manifest-path canary/precompile-execution-grounding/Cargo.toml
    Finished `dev` profile [unoptimized + debuginfo] target(s)        # clean, no lock drift
$ cargo tree | grep -E "miden-core-lib v|miden-crypto v|k256 v|sha3 v"
    miden-core-lib v0.23.3   miden-crypto v0.25.1   k256 v0.13.4   sha3 v0.10.9
```

**Isolation (no faucet/04/D5 touched by the canary commits):**
```
$ git show --stat 6e46d0f 744cdfa --name-only | grep -E "asm/standards/xreserve|crates/xusdc-encoding|docs/"
  (none)
$ git status --porcelain        # the pre-existing docs/governing + docs/spec edits remain, UNCOMMITTED
   M docs/governing/...; M docs/spec/...
```

---

## 4. Verification gates

- **G0 (objective gate / execution):** `cargo test --locked … --test precompile_canary` →
  `test result: ok. 7 passed; 0 failed`; per-step output shows keccak hashing + ECDSA accept + ECDSA
  reject (0 and trap) executing under MockChain. `cargo build --locked` clean; lock resolves the
  `0.23.3` family + `miden-crypto 0.25.1`.
- **G-MASM (conventions are source-backed):** the component module follows house style — namespace-
  first `#` header, `# SECTION` + `# ===` banners, `#!` doc blocks (Description / Inputs / Outputs /
  Where / Panics if / Invocation including advice inputs), named const (`KECCAK_INPUT_LEN_BYTES`),
  lowercase `# =>` trackers, `@locals` scratch (`masm-locals-over-globals`), explicit `call`-return
  depth-16 discipline (`masm-padding`). Driver bodies mirror `ecdsa_k256_keccak.masm` /
  `keccak256.masm`. The G-MASM PENDING row (precompile **execution**) is **RESOLVED** by this canary.
- **Anti-circularity:** keccak digest from independent `sha3`; ECDSA keypair+signature from independent
  `k256` and re-verified by `k256` (`k256_independently_verifies`) before MASM; `miden-crypto` used
  only for the `Poseidon2` PK_COMM parity helper and as a serialization format reference — never to sign.
- **Skills exercised:** `masm-formatting`/`-file-structure`/`-doc-comments`/`-inline-comments`/
  `-constants`/`-named-literals`/`-explicit-stack-inputs`/`-locals-over-globals`/`-padding`/
  `cheap-masm-equivalents`; `advice-provider-hygiene` (Q5); `felt-construction` (the 4-byte-LE packer
  uses `Felt::from(u32)`, never `Felt::new`); `masm-rust-constant-parity` (`KECCAK_INPUT_LEN_BYTES` +
  the dual-side vectors — the passing test is the parity check); `assert-specific-error-in-tests` (the
  trap and malformed tests assert the exact error strings). `u32-assert-*`/`checked-arithmetic` are N/A
  (no untrusted arithmetic in the drivers; the precompiles handle their own limb math).

---

## 5. Notes / findings (scope boundaries, not defects)

1. **Adjacent primitives NOT grounded here (intentionally out of scope):** the real attestation proc,
   the attester allowlist, the `Poseidon2(pubkey)` commitment, DepositIntent parsing, and wiring keccak
   to the real payload layout are D5d's to build (the allowlist is the already-grounded storage-map +
   Poseidon2 primitives composed).
2. **`verify` vs `verify_prehash`:** D5d's "recompute-keccak-digest-then-verify" maps cleanest onto
   `keccak256::hash_bytes(payload)` → `verify_prehash(digest)` (explicit `0/1`); the `verify` wrapper
   (message-in, trap-on-fail) is the fail-closed alternative. Both are grounded.
3. **Malformed ≠ reject:** arbitrary byte tampering aborts the tx with a deserialization error, not a
   boolean `0`. D5d must source reject semantics from a **well-formed** invalid triple (wrong key/sig),
   and must treat a deserialization abort as its own (also-rejecting) path.
4. **tx-script error strings:** the ephemeral tx scripts use inline `.err="…"`; the component module
   carries no asserts (the precompiles assert internally), so it needs no `ERR_*` consts.

---

## 6. D5d readiness — verdict

**D5d (keccak the DepositIntent payload + ECDSA-verify against an allowlisted attester key) can proceed
on this proven primitive with NO custom host wiring — nothing is BLOCKED.** Grounded end-to-end under
MockChain on the pinned v0.15.3 / 0.23.3 / miden-crypto 0.25.1 stack:
- keccak the payload via `keccak256::hash_bytes` — Q1 (executes; matches an independent digest);
- ECDSA-verify the digest via `ecdsa_k256_keccak::verify_prehash` (explicit `0/1`) or `verify`
  (fail-closed trap) — Q2/Q3;
- with the attester pubkey + signature delivered via the **advice provider**, validated against the
  allowlist commitment (`Poseidon2(pubkey)`) — Q5;
- through the **stock MockChain host** that auto-registers `CoreLibrary::handlers()` — Q4 (no manual
  wiring).

**Still unproven (a later, separate gate):** devnet `miden-node v0.15.0` precompile execution and the
deferred precompile **verification** at proving time — the local-node-validation gate (Q7). This canary
deliberately does not claim them.

---

## 7. STOP conditions honored

No real attestation / allowlist / `Poseidon2(pubkey)` / D5d logic; no keccak wired to the real
DepositIntent payload; no real attester keys; no touch of the faucet's `asm/standards/xreserve/`, 04,
D5a/D5b/D5c, or their vectors; no Cargo/pin changes beyond the isolated canary seed + the two
vector-gen dev-deps (`k256`, `sha3`) plus `rand`/`miden-crypto`; no Circle `DEV-*`/`Q-*` resolved; no
weakened/skipped tests; the EXECUTING test was committed (`6e46d0f`) before this report; the
malformed-error pin (`744cdfa`) is a new commit (no amend); **no push / publish / PR.**
