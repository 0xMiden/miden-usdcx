> **MIRROR — READ-ONLY (mirrored 2026-06-11).** Canonical source: `/Users/philipp/Documents/Work/Miden-Coding/agentic-template/ai-tasks/circle-integration/06-phase4-component-specs/04-shared-encoding/TEST-AND-VERIFICATION-HARNESS.md`. Do NOT edit this copy; if it diverges from the canonical source, the canonical source wins. Re-sync via `tools/sync-mirrors.sh`.

# TEST-AND-VERIFICATION-HARNESS — Shared Encoding Helper Library (`P4-ENCODE`)

**Authority.** This harness conforms to `../00-foundation/PHASE4-VERIFICATION-HARNESS.md` (the program-wide test-first contract `## 1`, builder loop `## 2`, mock policy `## 3`, the per-component test set `## 4.4`, the MockChain/local-node obligations `## 5`, the commands `## 6`, the acceptance gate `## 7`, and the static sweeps `## 8`). It is designed as part of THIS deep analysis — testing/verification is NOT deferred to the builder.

**Test-first (mandatory, T1–T5).** The builder MUST create/scaffold every test below BEFORE the main implementation. For each pure-encoding helper, the red step is the **vector assertion failing against the unimplemented helper** (`../00-foundation/PHASE4-VERIFICATION-HARNESS.md:24`). No final PASS without these tests existing and passing. Miden behavior is never faked at acceptance (T5).

**Mock policy (canonical, verbatim).** Circle API may be mocked. The per-helper boundary is in `COMPONENT-SPEC.md:## 11`; the disclosure block is `## 5` below.

---

## 1. Test file / module map

All Rust test modules live beside the implementation in `miden-standards/src/xreserve/encoding/` (unit + vector tests via `#[cfg(test)]` modules) and `miden-standards/tests/` (integration-style vector tests). The MASM-side exercise of the dual helpers runs inside the faucet harness (TASK-P4-ONCHAIN-XUSDC-FAUCET) — `project-template/integration/tests/` (MockChain) + `project-template/integration/src/bin/` (local node).

| Module / file | Covers | Harness type |
|---|---|---|
| `encoding/bytes32.rs::tests` | TV-B32-1..4 | Rust unit + vectors |
| `encoding/amount.rs::tests` | TV-AMT-1..7 | Rust unit + vectors |
| `encoding/account_id.rs::tests` | TV-AID-1..4 | Rust unit + vectors |
| `encoding/deposit_intent.rs::tests` | TV-DI-1..9 | Rust unit + vectors |
| `encoding/burn_note.rs::tests` | TV-BN-1..4 | Rust unit + vectors |
| `encoding/attestation.rs::tests` | TV-ATT-1..3 | Rust unit + vectors |
| `circle_json/*::tests` | TV-JSON-1..4 | Rust serde + mock fixtures |
| `circle_binary/*::tests` | TV-BIN-1..2 (OPTIONAL/NON-GATING) | Rust + mock fixtures |
| `tests/dual_agreement.rs` | TV-DUAL-1..5 | Rust ref vs MASM, shared vectors |
| `project-template/integration/tests/xreserve_encoding_onchain.rs` | the MASM side of TV-DUAL-1..5 | MockChain (faucet harness) |
| `project-template/integration/src/bin/validate_local.rs` (faucet) | local-node leg of the on-chain-consumed helpers | local node (GATE) |

**Shared test-vector file (both tasks consume it):** `miden-standards/tests/vectors/xreserve-encoding-vectors.json`. Each vector carries: the input bytes (hex), the `scale_exp` where relevant, the expected output (felt array / Word / AssetAmount / error tag), and a `cite` field naming the `path:LINE` the vector traces to. The faucet's MockChain test loads the same JSON so the Rust reference and the MASM implementation are asserted against identical inputs/outputs (TV-DUAL-*).

---

## 2. Deterministic unit tests + source-backed vectors (PRIMARY harness — `## 9.A`)

For each helper family: at least one **source-backed positive vector** plus **negative vectors**. Each vector names its citation.

### 2.1 `bytes32 → StorageMapKey` (INV-BYTES32-HASH-TO-WORD)

- **TV-B32-1 (positive).** A known `bytes32` → its Poseidon2 `Hasher::hash_elements` `Word` over the 8× u32-LE packing. Assert: `bytes32_to_storage_map_key(b)` equals the expected `Word`. Trace: E-4 `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:79`, E-6 `:81`, E-12 `:87`.
- **TV-B32-2 (fallibility bypass, negative→positive).** A `bytes32` whose native `TryFrom<[u8;32]> for Word` would FAIL (an 8-byte LE limb ≥ `p`): assert `bytes32_to_word_lossless(b)` returns `Err(LimbOutOfField)`, AND `bytes32_to_storage_map_key(b)` SUCCEEDS (Option B is infallible). This proves the fallible native path is bypassed. Trace: E-3 `:78`, C-5 `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:58-61`.
- **TV-B32-3 (determinism / idempotency).** Same input → same key twice: `bytes32_to_storage_map_key(b) == bytes32_to_storage_map_key(b)`. (This is the replay/idempotency analogue for the keying helper.) Trace: `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:67` (MC-CR-4).
- **TV-B32-4 (2-Words width).** Assert `bytes32_to_packed_felts(b)` yields 8 felts (= 2 Words), proving the packing does not fit one `StorageMapKey` and the hash-to-Word step is required. Trace: E-12 `:87`, E-13 `:88`, C-5 `:60`.

### 2.2 `uint256 → AssetAmount` (INV-UINT256-TO-ASSETAMOUNT)

- **TV-AMT-1 (positive, in-bound, 6-dp scale).** A 6-decimal amount within bound scales correctly: `uint256_to_asset_amount(limbs, scale_exp)` == expected `AssetAmount`. Trace: E-16 `:91`, CIR-FEE-3 `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:116`.
- **TV-AMT-2 (boundary accept).** Exactly `AssetAmount::MAX = 2^63 − 2^31` (post-scale) is accepted at the cap. Trace: E-7 `:82`.
- **TV-AMT-3 (boundary reject).** `MAX + 1` (post-scale) is rejected with `AmountOverCap`. Trace: E-7 `:82`.
- **TV-AMT-4 (high-limb reject).** A value with the high 4 limbs nonzero (> `2^128`) is rejected with `AmountTooLarge` / `ERR_X_TOO_LARGE`. Trace: E-16 `:91`.
- **TV-AMT-5 (reduced-compare).** `reduced_ge(amount, maxFee, scale_exp)` is `false` when `amount < maxFee` after reduction; the caller's `amount ≥ maxFee` assert fails. Trace: CIR-MINT-PRE-8 `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:47`, D5b `03-architecture/ARCHITECTURE-FLOWS.md:50`.
- **TV-AMT-6 (dust, RCC).** A value with a non-zero division remainder: `uint256_to_asset_amount_with_dust` returns `(y, z)` with `0 ≤ z < 10^scale_exp`; the test asserts `z` is surfaced and labels the dust *policy* **REQUIRES CIRCLE CONFIRMATION** (DEV-5). Trace: E-16 `:91`, DEV-5 `02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:44-49`.
- **TV-AMT-7 (scale-overflow reject).** A `scale_exp` so large that `10^scale_exp` overflows is rejected with `ScaleExpTooLarge` (the helper guards `10u64.checked_pow(scale_exp)`). Trace: C-6 `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:63-66`; `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:133`.

### 2.3 `AccountId ↔ bytes32` (INV-ACCOUNTID-ENCODING)

- **TV-AID-1 (round-trip).** For valid AccountIds: `bytes32_to_account_id(account_id_to_bytes32(id)) == id`, lossless. Trace: E-9 `:84`, E-10 `:85`, DL-9 `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:21`.
- **TV-AID-2 (out-of-range + non-canonical reject).** A `bytes32` with bytes set outside the 15-byte serialization region is rejected with `AccountIdOutOfRange`; a separate vector whose bytes lie *inside* the 15-byte region but do NOT decode to a canonical AccountId is rejected with `NonCanonicalAccountId`. Trace: E-9 `:84`, E-10 `:85`.
- **TV-AID-3 (AddressType + no fallback).** Assert `ADDRESS_TYPE_ACCOUNT_ID == 232`, and assert there is no keccak fallback path (the helper has no >32-byte branch — CIR-HOOK-3 not needed). Trace: E-11 `:86`, `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:125`, `03-architecture/ARCHITECTURE-TRACEABILITY-MATRIX.md:67`. The byte-layout draft is submitted to Circle via the S1-NDA L22 workflow (`06-resources/CIRCLE_PARTNER_INTEGRATION_GUIDELINES.md:22`); the layout is **REQUIRES CIRCLE CONFIRMATION** (DEV-10) and **REQUIRES IMPLEMENTATION VALIDATION** (IMPL-ACCOUNTID-LAYOUT).
- **TV-AID-4 (on-chain two-felt form).** Assert `account_id_to_felts(id)` yields the expected `[prefix, suffix]` two-felt pair (the on-chain natural form, no byte repacking) and that those two felts match the prefix/suffix recovered from `account_id_to_bytes32(id)`. This is the only on-chain-shape check for the AccountId family (it has no MASM-dual proc — the two felts are consumed directly). Trace: E-9 `:84`, E-10 `:85`, `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:152`.

### 2.4 `DepositIntent` parse (INV-DEPOSITINTENT-PARSE)

- **TV-DI-1 (positive).** A full 240-byte header + `hookData` parses to the exact fields with the DC-1 offsets. Assert each field equals its expected value. Trace: `02-specifications/CIRCLE-DATA-SCHEMAS.md:21-35`.
- **TV-DI-2..6 (per-field negative, one case PER field).** Each rejected at the cited step:
  - TV-DI-2: wrong `magic` → `BadMagic` (CIR-MINT-PRE-2 `:41`).
  - TV-DI-3: `version != 1` → `BadVersion` (CIR-MINT-PRE-3 `:42`).
  - TV-DI-4: `amount == 0` → `ZeroField{Amount}` (CIR-MINT-PRE-4 `:43`).
  - TV-DI-5: `localToken == 0` or `localDepositor == 0` → `ZeroField{..}` (CIR-MINT-PRE-5 `:44`).
  - TV-DI-6: `len != 240 + hookDataLen` → `LengthMismatch` (CIR-MINT-PRE-11 `:50`); a header `< 240` → `TruncatedHeader` (`02-specifications/CIRCLE-DATA-SCHEMAS.md:35`).
- **TV-DI-7 (felt-count guard, anti-ASG-16).** Assert `deposit_intent_to_packed_felts` produces a **60-felt** header (NOT 30), and the whole preimage (header + hookData felts) stays within the 1024-felt `NoteStorage` bound; a `hookDataLen` that would overflow returns `HookDataTooLarge`. Trace: C-10 `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:85`, N-4 `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:100`.
- **TV-DI-8 (note-input immutability).** Assert the parsed header is read-only over the input slice (no mutation of `NoteStorage.items` during parse). Trace: INV-NOTE-MODEL-CURRENT, C-12 `:93-96`.
- **TV-DI-9 (offsets).** A table-driven test asserting every `deposit_intent_field_offset(field)` equals the DC-1 offset (`magic`@0, `version`@4, `amount`@8, `remoteDomain`@40, `remoteToken`@44, `remoteRecipient`@76, `localToken`@108, `localDepositor`@140, `maxFee`@172, `nonce`@204, `hookDataLen`@236, `hookData`@240). Trace: `02-specifications/CIRCLE-DATA-SCHEMAS.md:21-32`.

The domain/identifier equality compares (`remoteDomain == self.domain`, `remoteToken == self.identifier`) are NOT tested here — they are faucet-owned storage compares (D5a `03-architecture/ARCHITECTURE-FLOWS.md:49`; CIR-MINT-PRE-6/7 `:45-46`) exercised in the faucet's per-field DepositIntent rejection tests (`../00-foundation/PHASE4-VERIFICATION-HARNESS.md:87`).

### 2.5 Burn-note storage-schema (INV-PUBLIC-BURN-OBSERVABILITY)

- **TV-BN-1 (round-trip).** `decode_burn_note_items(encode_burn_note_items(x)) == x` for `(amount, destDomain, destRecipient, salt)`. Trace: `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:44`.
- **TV-BN-2 (destination-in-items guard, anti-ASG-13).** A guard test asserting the destination fields are encoded into the `NoteStorage.items` felt layout and that `metadata.sender` is reserved for the depositor only — the encoder has no metadata-destination path. Trace: `03-architecture/ARCHITECTURE-CLAIM-ADJUDICATION.md:75-90`, ARCHITECTURE-COMPONENT-MAP.md:44.
- **TV-BN-3 (note-model placement).** Assert the payload targets `NoteStorage.items` (≤1024 felts), not `NoteInputs`/`aux` (anti-ASG-17). Trace: C-12 `:93-96`, N-4 `:100`.
- **TV-BN-4 (malformed).** Wrong-length items → `BurnItemsMalformed`.

### 2.6 Attestation wire-form (INV-DEPOSIT-ATTESTATION-RAW-KECCAK)

- **TV-ATT-1 (felt shapes).** `keccak_digest_felts(d)` = 8 felts; `compressed_pubkey_felts(pk)` = 9 felts; `signature_felts(sig)` = 17 felts (the `v` byte carried, unused). Trace: `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:40-42`,`:53-54`.
- **TV-ATT-2 (commitment).** `pubkey_commitment(pk)` = `Poseidon2(33-byte pubkey)` → one `Word`, matching the attester-allowlist keying primitive. Trace: MIDEN-CRYPTO `:46`, ARCHITECTURE-COMPONENT-MAP.md:25.
- **TV-ATT-3 (raw-keccak, not EIP-712).** Assert the helper packs the digest of `keccak256(full DepositIntent payload)` and carries NO EIP-712 domain / personal-sign prefix; there is no `depositAttestation` struct (the input is the raw 65-byte signature). Trace: `02-specifications/CIRCLE-DATA-SCHEMAS.md:43-45`,`:53`; `02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:27-28`.

### 2.7 Circle JSON types (mock fixtures)

- **TV-JSON-1 (round-trip).** Serialize/deserialize `PrepareBurnIntentInput` against a fixture matching `02-specifications/CIRCLE-API-SURFACE.md:129-143` exactly (required fields, the `valueExcludingFees` XOR `valueIncludingFees` constraint, the `remoteDomain != finalDestinationDomain` constraint, the 32-byte hex patterns).
- **TV-JSON-2 (response).** Deserialize the attestation-fetch response `{payload, messageHash, attestation}` (`:44`) and the `WithdrawBatch` constraints `burnIntents` minItems 1 / maxItems 10, `burnSignatures` minItems 2 (`:179-185`).
- **TV-JSON-3 (malformed/error).** Fixtures for HTTP 400/404/409/500 and a wrong-field/bad-length body → `JsonSchema(..)`; a malformed body is rejected, not forwarded.
- **TV-JSON-4 (no-conflate).** Assert the JSON `StructuredHookData.forwardingContractAddress` (20-byte) is modelled distinctly from the binary `forwardingContract` (32-byte) — the two representations are not conflated. Trace: `02-specifications/CIRCLE-DATA-SCHEMAS.md:144-166`,`:157`,`:162`.

### 2.8 (Optional) Circle binary decoders — NON-GATING

- **TV-BIN-1 (decode + reconcile + negative).** Decode a `TransferSpec` (340B, magic `0xca85def7`), `BurnIntent` (72B, magic `0x070afbc2`), `WithdrawHookData` (112B, magic `0x6b20f62a`) vector; assert the magic and the `BurnIntent(72)+TransferSpec(340)+WithdrawHookData(112)=524B + forwardingCalldata` reconciliation. Negative vectors: a corrupted magic → `BinaryMagic`; a wrong total length that breaks the 524B reconciliation → `BinaryLength`. Trace: `02-specifications/CIRCLE-DATA-SCHEMAS.md:57-140`; `02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:76`.
- **TV-BIN-2 (label).** Assert this path is labelled OPTIONAL / NON-GATING — the partner signs `messageHashToSign` as opaque; binary reconstruction is off the critical path (`02-specifications/CIRCLE-DATA-SCHEMAS.md:164`; the ASG-5 boundary). The byte-level JSON→binary transform is **REQUIRES CIRCLE CONFIRMATION** (`:166`).

---

## 3. Dual-implementation agreement tests (`## 9.B`)

For every **dual** helper (consumed on-chain AND with a Rust reference), a test asserts the Rust reference and the MASM implementation produce identical output on the SAME shared vectors (`tests/vectors/xreserve-encoding-vectors.json`).

- **TV-DUAL-1** — `bytes32_to_storage_map_key` (Rust) vs `xreserve::encoding::bytes32_to_key` (MASM): identical `Word` on every vector.
- **TV-DUAL-2** — `uint256_to_asset_amount` (Rust) vs `xreserve::encoding::uint256_to_asset_amount` (MASM): identical `AssetAmount` / identical trap on every vector.
- **TV-DUAL-3** — `parse_deposit_intent_header` + `deposit_intent_to_packed_felts` (Rust) vs `xreserve::encoding::parse_deposit_intent` (MASM): identical accept/reject and identical 60-felt preimage on every vector.
- **TV-DUAL-4** — `encode_burn_note_items` (Rust) vs the burn-note MASM script's `NoteStorage.items` write (faucet-owned): identical felt layout on every vector.
- **TV-DUAL-5** — `keccak_digest_felts` / `compressed_pubkey_felts` / `signature_felts` / `pubkey_commitment` (Rust) vs `xreserve::encoding::attestation.masm` staging: identical felts/commitment on every vector.

**The MASM side MUST be exercised through the faucet's MockChain / local-node harness** owned by TASK-P4-ONCHAIN-XUSDC-FAUCET — NOT asserted in prose, and NOT replaced by a Rust-only fake for final acceptance (`../00-foundation/PHASE4-VERIFICATION-HARNESS.md:28`,`:200-210`). The Rust reference is a NON-GATING speed aid; the gating check is the MockChain + local-node exercise inside the faucet flow.

---

## 4. Exact commands (`## 9.C`)

The builder runs these after each meaningful change and captures their output (paths rooted at the monorepo per the project CLAUDE.md):

- **Unit + vector tests (gating for this component):**
  `cargo test -p <encoding-crate>`
- **Build any MASM-bearing helper consumed on-chain (via the faucet contract):**
  `cargo miden build --manifest-path project-template/contracts/<faucet>/Cargo.toml --release`
- **MockChain exercise of the on-chain-consumed helpers (via the faucet harness):**
  `cd project-template && cargo test -p integration --release`
- **Local-node validation where an encoding helper participates in an on-chain mint/burn flow the faucet validates:**
  Start node: `cd project-template && miden-node bundled start --data-directory local-node-data --rpc.url http://0.0.0.0:57291`
  Validate (GATE): `cd project-template && cargo run --bin validate_local --release`

**Gating statement.** The encoding **unit/vector tests gate this component**; the **MASM-side correctness of any on-chain-consumed helper is gated by the faucet's MockChain + local-node harness**. A Rust-only check is **NON-GATING** for the on-chain path (`../00-foundation/PHASE4-VERIFICATION-HARNESS.md:186`,`:256-259`).

---

## 5. Mock disclosure block (mandatory)

> **Circle API may be mocked.**

- **What uses a mock fixture:** the Circle JSON types (`circle_json`, TV-JSON-1..4) and the optional Circle binary decoders (`circle_binary`, TV-BIN-1..2). Both validate against mock fixtures that match the Phase-1 OpenAPI/schema package exactly and include malformed/error cases.
- **Why it is safe:** the encoding library never makes a live Circle call — it only encodes/decodes the bytes the services move; the live call is unavailable while `Q-API-AUTH`, `Q-INFO-PARAM`, and `Q-DOM-1` are OPEN (`02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:99`,`:101`,`:96`).
- **What real verification compensates:** every Miden-specific encoding assumption (Poseidon2 hash-to-Word, the u32-LE packing, the uint256 reduction, the AccountId serialization, the burn-note `NoteStorage.items` layout) is exercised on-chain through the faucet's **MockChain** (contract level) and **local-node** (note/RPC/lifecycle GATE) harness via the dual-agreement tests (TV-DUAL-1..5). No Miden fake substitutes for that in final acceptance; any Rust-only reference is labelled **NON-GATING**.

---

## 6. Acceptance gate (component-scope — mirrors `../00-foundation/PHASE4-VERIFICATION-HARNESS.md:256-259`)

A component is "done" — ready for audit handoff — ONLY when ALL hold:

- The `bytes32→StorageMapKey`, `uint256→AssetAmount`, `AccountId↔bytes32` round-trip, `DepositIntent` layout, burn-note storage-schema, and deposit-attestation wire-form vector tests pass; vectors trace to the cited Phase-1/2 source lines (`## 2`).
- The on-chain helpers (parser, reducer, hash-to-Word, attestation packing, burn-note write) are exercised inside the faucet MockChain/local-node harness (TV-DUAL-1..5), not asserted only in prose.
- `cargo test -p <encoding-crate>` is green; the on-chain-consumed helpers pass `cd project-template && cargo test -p integration --release` and local-node validation within the faucet flow.
- Cap/scale (DEV-5), hookData carrier (DEV-6), AccountId layout (DEV-10) are labelled **REQUIRES CIRCLE CONFIRMATION** + **REQUIRES IMPLEMENTATION VALIDATION** as applicable; every Circle item stays OPEN (the 8d false-approval sweep is clean).
- Every static sweep in `../00-foundation/PHASE4-VERIFICATION-HARNESS.md:269-305` is clean: no banned prose (8a); the literal word in 8b appears only in the one sanctioned phrase; the open-status tokens are present (8c); no false approval (8d); the mock-policy phrase is present (8e); citation discipline holds (8f).

**Audit-handoff bundle.** The builder hands the auditor: the exact commands run, their captured outputs, the test-id → invariant/CIR-*/MC-* map (`CLAIM-EVIDENCE-MATRIX.md`), this mock-disclosure block, and the list of RCC items still OPEN (`OPEN-DECISIONS-CONSUMED.md`).

---

## 7. Test-id → invariant / requirement coverage map

| Test ids | Invariant | Key requirement / evidence |
|---|---|---|
| TV-B32-1..4, TV-DUAL-1 | INV-BYTES32-HASH-TO-WORD | MC-CR-4 `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:67`; GMS-5 `03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:45`; E-3/E-4/E-6 |
| TV-AMT-1..7, TV-DUAL-2 | INV-UINT256-TO-ASSETAMOUNT | CIR-MINT-PRE-8/9 `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:47-48`, CIR-FEE-3 `:116`; MC-CR-5 `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:68`; MC-MINT-3 / GMS-4 `:44`; DC-5; E-7/E-15/E-16 |
| TV-AID-1..4 | INV-ACCOUNTID-ENCODING | CIR-DEPLOY-8 `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:22`, CIR-HOOK-3 `:125`; MC-CR-6 `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:69`; E-9/E-10/E-11 |
| TV-DI-1..9, TV-DUAL-3 | INV-DEPOSITINTENT-PARSE, INV-NOTE-MODEL-CURRENT | CIR-MINT-PRE-2..7/-11 `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:41-50`; MC-MINT-2 `:24`; C-10 `:85` |
| TV-BN-1..4, TV-DUAL-4 | INV-PUBLIC-BURN-OBSERVABILITY, INV-NOTE-MODEL-CURRENT | DC-7 `../00-foundation/PHASE4-DATA-CONTRACTS.md:148-165`; ARCHITECTURE-COMPONENT-MAP.md:44; C-3 `:48-51`; ASG-13 |
| TV-ATT-1..3, TV-DUAL-5 | INV-DEPOSIT-ATTESTATION-RAW-KECCAK | DC-2 `../00-foundation/PHASE4-DATA-CONTRACTS.md:62-77`; CIRCLE-DATA-SCHEMAS.md:43-45,:53; MIDEN-CRYPTO `:40-42`,`:53-54` |
| TV-JSON-1..4 | (off-chain encoding fidelity) | CIRCLE-API-SURFACE.md:129-143,:179-185; CIRCLE-DATA-SCHEMAS.md:144-166 |
| TV-BIN-1..2 (NON-GATING) | DC-13 optional | CIRCLE-DATA-SCHEMAS.md:57-140,:164,:166; CIRCLE-CLAIM-ADJUDICATION.md:76 |
