> **MIRROR — READ-ONLY (mirrored 2026-07-01).** Canonical source: `/Users/philipp/Documents/Work/Miden-Coding/agentic-template/ai-tasks/circle-integration/06-phase4-component-specs/04-shared-encoding/COMPONENT-SPEC.md`. Do NOT edit this copy; if it diverges from the canonical source, the canonical source wins. Re-sync via `tools/sync-mirrors.sh`.

# COMPONENT-SPEC — Shared Encoding Helper Library (`P4-ENCODE`)

**Program.** Integrate Circle **xReserve / xUSDC** (NOT standard USDC) onto Miden. The Miden-side MVP is standards/application code — a `miden-base/crates/miden-standards` (or app-crate) PR — NOT a VM/node/kernel/consensus change. Baselines pinned — **target: Miden v0.15 + devnet** (`07-implementation-readiness/V15-DEVNET-BASELINE.md`): protocol (= miden-base) released tag `v0.15.3` (`681fc9058`), miden-vm = **separate `0.23.x` cadence, NOT a v0.15 tag** (the v0.15 protocol resolves its VM/assembler crates at `0.23.3` from `miden-vm@v0.23.3`; the 2025 `v0.15.0` vm tag is unrelated — `V15-DEVNET-BASELINE.md` §1), miden-node released tag `v0.15.0` (`29a876c3`) — **the released TAG is the pin** (`next` equaled the tag at the 2026-06-10 verification but advances and is NOT the pin); deps protocol `0.15.3`, miden-client `origin/next` `ed94b05d6` (next-commit — still no v0.15 tag; re-pin at builder launch); guardian `c8d54b96` (third-party OpenZeppelin component, **not Miden-versioned**; off the xUSDC critical path — `V15-DEVNET-BASELINE.md` §1). v0.15.3 locks internal deps `miden-assembly`/`miden-core-lib` = `0.23.3` and `miden-crypto`/`miden-field` = `0.25.1` (v0.15.1 historically locked `0.23.1`) — v0.15 DEPENDENCIES, kept (not stale targets). Supersedes the old `miden-base 0b662adfb` (= `v0.15.0-21`, on the v0.15 line) / `miden-vm 328071990` / `miden-client 228c78445` / retrieval-ref `2c423249d` baseline. (`03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:100`; `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:21-28`).

**Spec key.** `P4-ENCODE`. **Component(s):** the DepositIntent parser (`CMP-A12`), the `uint256→AssetAmount` reducer (`CMP-A13`), and the `bytes32→StorageMapKey` hash-to-Word helper (`CMP-A14`) — plus the AccountId↔bytes32, burn-note storage-schema, attestation wire-form, Circle JSON, and optional Circle-binary helpers that share the same encoding surface. CMP ids are assigned in `../00-foundation/PHASE4-COMPONENT-INTERFACE-MATRIX.md:36-38`; the descriptive component rows are `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:30` (parser), `:31` (reducer), `:32` (hash-to-Word).

**Status of THIS spec.** TEMP PASS by program reality — the spec is decision-complete, but every Circle-owned `DEV-*`/`Q-*` it touches remains OPEN: NO EVIDENCE OF CIRCLE APPROVAL; most REQUIRES CIRCLE CONFIRMATION (`02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:6`,`:118`). No row in this package marks any Circle item approved.

**Consuming tasks.** This library is reused by `../agent-tasks/TASK-P4-ONCHAIN-XUSDC-FAUCET.md` (on-chain parser/reducer/hash-to-key, MASM side) and the three off-chain services (`TASK-P4-DEPOSIT-ATTESTATION-RELAYER.md`, `TASK-P4-WITHDRAWAL-LISTENER-ATTESTER.md`, `TASK-P4-MONITORING-ADMIN-OPS.md`). The single canonical encoding surface exists so no encoding is duplicated or divergent across components (`../00-foundation/PHASE4-DATA-CONTRACTS.md:7`).

**Source-of-truth policy.** Every load-bearing byte-level fact below carries an exact `relative/path.md:LINE` citation into a canonical Phase 1/2/3 file (or the Tier-2 NDA by local path+line). Historical/superseded files (`REPORT.md`, `GAP-MATRIX.md`, `EVIDENCE.md`, old audits) are claims to verify, never primary sources (the `../00-foundation/PHASE4-ANTI-SIMPLIFICATION-GATES.md` ASG-11 guardrail; `PHASE4-SOURCE-MAP.md:68-85`). Line numbers were opened and read before citing.

**Mock policy (canonical, verbatim).** Circle API may be mocked. The full per-helper mock boundary is in `## 11`; the test-side disclosure is in `TEST-AND-VERIFICATION-HARNESS.md`.

---

## 1. Scope, role, and what this library is NOT

### 1.1 What this library owns

This is the cross-cutting Rust + MASM utility layer that owns **every byte-level encode / decode / parse / scale / hash-to-key operation crossing the Circle (EVM, big-endian) ↔ Miden (Felt/Word, Poseidon2) boundary**. Concretely, seven helper families:

1. **`bytes32` parsing + hash-to-Word** — Option B Poseidon2 `Hasher::hash_elements` over the 8× u32-LE packing → one canonical `Word`/`StorageMapKey`; the fallibility of the native `TryFrom<[u8;32]> for Word`; the field-overflow guard. Consumed by the nonce registry (`CMP-A8`) and the attester allowlist keying (`CMP-A7`).
2. **AccountId ↔ bytes32** — protocol/natural form is 15-byte (`to_bytes()` = 8 BE prefix + 7 BE suffix) / two-felt `[prefix, suffix]` (`AddressType::AccountId = 232` is a bech32 discriminant, NOT in the wire form); the **bytes32 wire packaging** is the **R-B / Agglayer-mirroring** right-aligned draft (DEV-10, REQUIRES CIRCLE CONFIRMATION); no keccak fallback needed.
3. **uint256 → AssetAmount** — byte-swap, high-4-limbs-zero ceiling, low-4-as-u128, decimal scale-down, then reject/trap if the post-scale quotient exceeds `AssetAmount::MAX = 2^63 − 2^31` (no saturation or clamping); modelled on `EthAmount::scale_to_token_amount` / the AggLayer `verify_u256_to_native_amount_conversion` precedent.
4. **`DepositIntent` fixed-layout parsing helpers** — the 240-byte big-endian header offsets + variable `hookData`; the u32-LE-packed 60-felt on-chain preimage form; per-field extraction.
5. **Burn-note storage-schema helpers** — encode/decode of the `XReserveBurnNote` public `NoteStorage.items` payload `(amount, destDomain, destRecipient, salt)`.
6. **Circle JSON schema types** — typed Rust models of the Circle request/response JSON bodies the off-chain services serialize/deserialize.
7. **(Optional) Circle-returned binary decode/validation helpers** — `TransferSpec` / `BurnIntent` / `WithdrawHookData` binary-layout decoders used for OPTIONAL off-chain validation only.

A shared **attestation wire-form** sub-helper (the byte→felt packing of the keccak digest, the 33-byte pubkey, and the 65-byte signature, plus the `Poseidon2(pubkey)` commitment) is owned here too, because its encoding is shared by `CMP-A9` (mint) and the relayer even though the `verify_prehash` call itself is owned by the faucet task.

### 1.2 What this library is NOT

- It is **not** the faucet, the mint proc, the relayer, the listener, or the monitor. It exposes pure functions over bytes/felts; it does not perform a live Circle call, a node RPC, a `verify_prehash`, or a `token_supply` write.
- It does **not** resolve any Circle-owned `DEV-*`/`Q-*`. Where a value is Circle-owned and unresolved, this spec writes the literal token **REQUIRES CIRCLE CONFIRMATION** (**RCC**) plus a default assumption (`## 10`).
- It does **not** own the domain/identifier *equality* checks (`remoteDomain == self.domain`, `remoteToken == self.identifier`). Those are storage compares the faucet performs against `XReserveDomainConfig` at flow step D5a (`03-architecture/ARCHITECTURE-FLOWS.md:49`; `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:45-46`, CIR-MINT-PRE-6/7). This library only parses the fields and exposes them; the structural checks it owns are magic/version/length/non-zero.

### 1.3 Builder posture (test-first, decision-complete)

A future BUILDER agent executes this spec with the loop in `## 12`. The spec is authored so the builder has very little room to wander, simplify, or invent. If source evidence (`path:LINE`) disproves a claim here, the builder STOPS and reports the contradiction (`## 13`) rather than guessing or silently editing the spec.

---

## 2. Non-negotiable invariants (named, stated, cited, test-enforced)

Each invariant below is named exactly, stated, cited to canonical source, and bound to at least one specified test (test ids resolve in `TEST-AND-VERIFICATION-HARNESS.md`). These are the registry §2 invariants this component consumes (`../00-foundation/PHASE4-GLOBAL-INVARIANTS.md`).

### INV-BYTES32-HASH-TO-WORD
An external `bytes32` is **not** a raw `Word`. For external `bytes32` map keys use **Option B** Poseidon2 `Hasher::hash_elements` over the 8× u32-LE packing → one canonical `Word`/`StorageMapKey`. The native `TryFrom<[u8;32]> for Word` is **fallible** (decomposes into 4× u64-LE limbs, rejects any limb ≥ `p`, `WordError::InvalidFieldElement`); the 8× u32-LE packing spans **2 Words**, too wide for one key.
**Cite:** `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:58-61` (C-5), `:19` (DL-7); `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:78` (E-3, TryFrom fallible), `:79` (E-4, key hashed via `Hasher::hash_elements` before SMT insertion), `:80` (E-5, value slot is a `Word`), `:81` (E-6, protocol `Hasher` alias is Poseidon2), `:87` (E-12, 8 u32 limbs), `:88` (E-13, 4 bytes/u32-felt packing); `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:67` (MC-CR-4). **Gating:** DEV-9. **Tests:** TV-B32-1..4. **Guardrail:** ASG-6.

### INV-UINT256-TO-ASSETAMOUNT
Parse/scale-down `uint256` into `AssetAmount` (a `u64` newtype, `MAX = 2^63 − 2^31 = 9,223,372,034,707,292,160`), rejecting/trapping if the post-scale quotient exceeds `MAX` (no saturation or clamping); never treat a Felt as a u64/uint256 (values in `(MAX, p)` are valid Felts but invalid amounts; values ≥ `p` corrupt vault math). The same reduced-compare applies to `amount ≥ maxFee` and `feeAmount ≤ maxFee`.
**Cite:** `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:63-66` (C-6), `:20` (DL-8); `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:82` (E-7, the `MAX` constant), `:90` (E-15, `EthAmount::scale_to_token_amount` reuse precedent), `:91` (E-16, the byte-swap / high-4-limbs-zero / low-4-as-u128 / cap mechanic); `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:68` (MC-CR-5, `uint256→AssetAmount` bounded reduction); `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:114-117` (§4.1 bound), `:119-126` (§4.2 mechanic); `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:116` (CIR-FEE-3). **Capability:** MC-CR-5 (alongside MC-MINT-3 / GMS-4 / G4). **Gating:** DEV-5. **Tests:** TV-AMT-1..7. **Guardrail:** ASG-7.

### INV-ACCOUNTID-ENCODING
AccountId's protocol/natural form is **15-byte** (`to_bytes()` = 8 BE prefix + 7 BE suffix) / **two-felt** `[prefix, suffix]`; only the two-felt natural form fits one `Word`. The **bytes32 wire packaging is a separate integration proposal** — current draft **R-B / Agglayer-mirroring** right-aligned (`bytes[0..16]=0`, `bytes[16..24]=prefix u64 BE`, `bytes[24..32]=suffix u64 BE`; it occupies **8 felts / 2 Words**, NOT a raw `Word`; supersedes the prior left-aligned 15-byte/trailing-zero draft). Lossless, no keccak fallback (≤32B); gated by the S1-NDA **L22** approval workflow — **REQUIRES CIRCLE CONFIRMATION** (DEV-10).
**Cite:** `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:21` (DL-9); `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:84` (E-9, `SERIALIZED_SIZE = 15`, 2 felts), `:85` (E-10, 8 BE prefix + 7 BE suffix), `:86` (E-11, `AddressType::AccountId = 232`); `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:69` (MC-CR-6); `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:148-157` (§5); `06-resources/CIRCLE_PARTNER_INTEGRATION_GUIDELINES.md:22` (NDA L22, cite by path+line only). **Gating:** DEV-10. **Tests:** TV-AID-1..3.

### INV-DEPOSITINTENT-PARSE
`DepositIntent` is a fixed-offset **240-byte big-endian header** (u32-LE packed = **60 felts** on-chain) + variable `hookData`, parsed with magic / version / zero / length checks (the library's structural surface) and domain/identifier compares (the faucet's storage surface); note-input immutability holds.
**Cite:** `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:24` (MC-MINT-2); `02-specifications/CIRCLE-DATA-SCHEMAS.md:21-32` (field offsets), `:34-35` (total + decoder validation); `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:40-50` (CIR-MINT-PRE-1..11); `03-architecture/ARCHITECTURE-FLOWS.md:49` (D5a order); `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:85` (C-10, the 60-felt fact). **Gating:** DEV-6 (hookData cap). **Tests:** TV-DI-1..9. **Guardrails:** ASG-16, ASG-12.

### INV-NOTE-MODEL-CURRENT
Target the current note model: `NoteStorage` (≤1024 felts) not `NoteInputs`; no `aux`; `NoteType {Private,Public}` only (no `Encrypted`); 6-word nullifier; `NoteAttachments` (≤4 / ≤512 words).
**Cite:** `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:93-96` (C-12); `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:97` (N-1), `:100` (N-4), `:103` (N-7), `:105` (N-9), `:107` (N-11). **Gating:** —. **Tests:** TV-DI-7 (1024-felt bound), TV-BN-3 (NoteStorage placement). **Guardrail:** ASG-17.

Two adjacent registry invariants this spec also names, because the burn-note and attestation helpers encode their payloads here even though verification is owned elsewhere:

### INV-DEPOSIT-ATTESTATION-RAW-KECCAK
The deposit attestation is a raw secp256k1 ECDSA over `keccak256(full DepositIntent payload)`, **65B `r‖s‖v` = 17 felts** — NOT EIP-712, NOT a personal-sign prefix; there is no `depositAttestation` struct (it is the raw signature bytes). The 33-byte compressed pubkey = **9 felts**; the 32-byte digest = **8 felts**; the `v` byte is carried but unused.
**Cite:** `02-specifications/CIRCLE-DATA-SCHEMAS.md:43-45` (what is signed / raw keccak / 65B `r‖s‖v`), `:53` (no struct); `02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:27-28` (CONFIRMED raw ECDSA, not EIP-712), `:117` (no false EIP-712 for deposits); `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:40-44` (felt shapes), `:53-54` (`v` carried unused). **Data contract:** DC-2 (`## 3`). **Gating:** DEV-1 (owned by the faucet task; the encoding shapes are owned here). **Tests:** TV-ATT-1..3. **Guardrail:** ASG-12.

### INV-PUBLIC-BURN-OBSERVABILITY (burn-note storage-schema helper)
The burn note MUST be `NoteType::Public` with payload in `NoteStorage.items`; the destination fields `(amount, destDomain, destRecipient, salt)` go in `NoteStorage.items`, **NOT** note metadata; `metadata.sender` = depositor only.
**Cite:** `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:48-51` (C-3); `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:44` (burn-note storage form); `03-architecture/ARCHITECTURE-CLAIM-ADJUDICATION.md:75-90` (the destination-in-metadata prototype ban). **Data contract:** DC-7 (`## 3`). **Gating:** DEV-2 (owned by the faucet/listener tasks; the payload encoding is owned here). **Tests:** TV-BN-1..4. **Guardrail:** ASG-13.

---

## 3. Component-specific data contracts (named exactly)

Authored against `../00-foundation/PHASE4-DATA-CONTRACTS.md`. For each: the exact layout, producer/consumer/validation-owner, and gating open decision.

### DC-1 — `DepositIntent`
**Layout — fixed 240-byte big-endian header + variable `hookData`; total = `240 + hookDataLen`** (`02-specifications/CIRCLE-DATA-SCHEMAS.md:13-35`):

| # | Field | Offset | Width | Wire type | Cite | Notes |
|---|---|---|---|---|---|---|
| 0 | `magic` | 0 | 4 | `bytes4` | `:21` | `0x5a2e0acd` = `bytes4(keccak256("circle.xReserve.DepositIntent"))` |
| 1 | `version` | 4 | 4 | `uint32` | `:22` | MUST == `1` |
| 2 | `amount` | 8 | 32 | `uint256` | `:23` | 6-decimal USDC units |
| 3 | `remoteDomain` | 40 | 4 | `uint32` | `:24` | source notes "Domain where wrapped tokens are issued"; on Miden compared `== self.domain` (D5a) |
| 4 | `remoteToken` | 44 | 32 | `bytes32` | `:25` | source notes "Token identifier on the remote domain"; on Miden compared `== self.identifier` (D5a) |
| 5 | `remoteRecipient` | 76 | 32 | `bytes32` | `:26` | Miden recipient (AccountId-encoded, DC-6) |
| 6 | `localToken` | 108 | 32 | `bytes32` | `:27` | NDA types `address`; S4-REF types `bytes32` |
| 7 | `localDepositor` | 140 | 32 | `bytes32` | `:28` | same `address`-vs-`bytes32` note |
| 8 | `maxFee` | 172 | 32 | `uint256` | `:29` | in `localToken` units |
| 9 | `nonce` | 204 | 32 | `bytes32` | `:30` | replay nonce |
| 10 | `hookDataLen` | 236 | 4 | `uint32` | `:31` | length of `hookData` |
| 11 | `hookData` | 240 | `hookDataLen` | `bytes` | `:32` | optional |

**On-chain representation:** the 240-byte header is **60 u32-LE-packed felts** (4 bytes/felt) — `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:85` (C-10). Do **not** compute `240/8 = 30` (ASG-16; the verbatim banned phrasing is in `../00-foundation/PHASE4-ANTI-SIMPLIFICATION-GATES.md`). The full preimage must stay within the 1024-felt `NoteStorage` bound (`01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:100`, N-4).
**Structural validation owned here (library):** `magic == 0x5a2e0acd`; header ≥ 240; total length `== 240 + hookDataLen`; `version == 1`; `localToken ≠ 0`; `localDepositor ≠ 0`; `amount ≠ 0` (`02-specifications/CIRCLE-DATA-SCHEMAS.md:35`; `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:41-50`, CIR-MINT-PRE-2..5/-11). **Equality checks owned by the faucet:** `remoteDomain == self.domain`, `remoteToken == self.identifier` (`03-architecture/ARCHITECTURE-FLOWS.md:49`; CIR-MINT-PRE-6/7).
**PRODUCER:** Circle (signs the payload); the relayer (CMP-C1) transports it. **CONSUMER:** `xreserve_mint` (CMP-A9). **VALIDATION OWNER:** on-chain parser (this library's MASM proc). **Gating:** DEV-6 / Q-INFRA-5 (hookData cap — `02-specifications/CIRCLE-DATA-SCHEMAS.md:229` records a genuine `NO EVIDENCE FOUND`).

### DC-2 — `depositAttestation` (mint-side signature)
**Canonical name:** `depositAttestation` — the **raw 65-byte signature bytes**, NOT a struct (do not conflate with the Gateway `Attestation` of DC-10). **Source:** `02-specifications/CIRCLE-DATA-SCHEMAS.md:39-53`; `../00-foundation/PHASE4-DATA-CONTRACTS.md:62-77`.
**Wire form:** signed over `keccak256(full encoded DepositIntent payload)` — raw `keccak256`, **NOT EIP-712**, **NOT** the `\x19Ethereum Signed Message` personal-sign prefix (`02-specifications/CIRCLE-DATA-SCHEMAS.md:43-44`; `02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:27-28`,`:117`). secp256k1 ECDSA, **65 bytes `r‖s‖v` = 17 felts** (u32-LE-packed), the `v` byte carried but unused (`02-specifications/CIRCLE-DATA-SCHEMAS.md:45`; `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:42`,`:53-54`). There is **no `depositAttestation` struct** — the attestation is the signature; the message is the `DepositIntent` payload (`02-specifications/CIRCLE-DATA-SCHEMAS.md:53`).
**What this library owns:** the byte→felt packing of the 65-byte signature (→ 17 felts), the 33-byte compressed pubkey (→ 9 felts), and the 32-byte keccak digest (→ 8 felts) — `attestation.rs` (`## 6.7`). The `keccak256::hash_bytes` digest production and the `ecdsa_k256_keccak::verify_prehash` verification are owned by the faucet at flow step D5d (`03-architecture/ARCHITECTURE-FLOWS.md:52`; CMP-A9).
**Where stored/passed:** `XReserveMintNote.NoteAttachments`/advice (65B sig = 17 felts) — `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:43`.
**PRODUCER:** Circle deposit attester. **CONSUMER:** `xreserve_mint` (CMP-A9). **VALIDATION OWNER:** on-chain (no `ecrecover`; verified against a supplied candidate pubkey, DC-3, under `INV-NO-ECRECOVER`).
**Consumed invariants:** `INV-DEPOSIT-ATTESTATION-RAW-KECCAK`. **Tests:** TV-ATT-1..3, TV-DUAL-5. **Guardrail:** ASG-12. **Gating:** DEV-1 / Q-CRY-1 (pubkey-commitment allowlist — owned by the faucet task); Q-DA-QUORUM (single-sig reference vs production quorum — `02-specifications/CIRCLE-DATA-SCHEMAS.md:51`).

### DC-5 — Amount/fee uint256-reduction
**Layout (per `uint256` region)** (`01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:91`, E-16; `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:63-66`, C-6; `03-architecture/ARCHITECTURE-FLOWS.md:50`, D5b):
1. byte-swap the 8 LE u32 limbs to big-endian numeric order;
2. assert the **high 4 limbs are zero** (value ≤ `2^128`, else `ERR_X_TOO_LARGE` "larger than 2**128");
3. take the low 4 limbs as a u128 `x`;
4. `y = floor(x / 10^scale_exp)` with remainder `0 ≤ z = x − y·10^scale_exp < 10^scale_exp`;
5. reject/trap if the post-scale quotient `y` exceeds `AssetAmount::MAX = 2^63 − 2^31` (no saturation or clamping).

The same reduced-compare governs `amount ≥ maxFee` and `feeAmount ≤ maxFee` (CIR-MINT-PRE-8/9, `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:47-48`); scale to **6 decimals** (CIR-FEE-3, `:116`). **PRODUCER:** Circle (`amount`/`maxFee`), relayer/operator (`feeAmount`). **CONSUMER:** `xreserve_mint` (CMP-A9). **Capability:** MC-CR-5 (`01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:68`, `uint256` amounts bounded reduction) — alongside MC-MINT-3 / GMS-4 / G4. **Gating:** DEV-5 / Q-CRY-6 (cap value, scale factor, dust tolerance — the narrower-width category is spec-permitted: `02-specifications/CIRCLE-DATA-SCHEMAS.md:221`).

### DC-6 — AccountId ↔ `bytes32`
**Protocol fact (unchanged):** the canonical Miden `AccountId::SERIALIZED_SIZE = 15 bytes` = 8 BE prefix + 7 BE suffix = two felts `[prefix, suffix]`, fits a single `Word`; `AddressType::AccountId = 232` (bech32m discriminant — NOT part of the bytes32 wire form). **bytes32 packaging (DEV-10 draft):** **R-B / Agglayer-mirroring** bytes32 packaging (DEV-10 draft, human-selected 2026-06-15): `bytes[0..16]=0x00` (leading zero pad), `bytes[16..24]=AccountId prefix u64 BE`, `bytes[24..32]=AccountId suffix u64 BE` — mirrors the protocol Agglayer `EthEmbeddedAccountId` form `0x00000000 || prefix(8) || suffix(8)` (`protocol/crates/miden-agglayer/src/eth_types/eth_embedded_account_id.rs:117-122`) widened to a 32-byte slot; inverse validates `Felt<p` + `AccountId::try_from_elements` (ibid:86-96); lossless, no keccak fallback (≤32B). Supersedes the prior data-left-aligned 15-byte/trailing-zero draft (2026-06-15). **REQUIRES CIRCLE CONFIRMATION** (DEV-10); NO EVIDENCE OF CIRCLE APPROVAL. Lossless — **no keccak fallback** is needed (CIR-HOOK-3 not required because the identifier ≤ 32 bytes — `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:125`; `03-architecture/ARCHITECTURE-TRACEABILITY-MATRIX.md:67`; the >32-byte keccak path itself is `02-specifications/CIRCLE-DATA-SCHEMAS.md:234`). **PRODUCER/CONSUMER:** relayer/listener encode/decode (off-chain); on-chain compares `remoteRecipient`/`remoteToken == self.identifier`. **Gating:** DEV-10 / Q-CRY-3/4 (byte layout submitted via S1-NDA L22; CIR-DEPLOY-8, `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:22`).

### DC-7 — `XReserveBurnNote` public payload (burn-note storage-schema helper)
**Canonical name:** `XReserveBurnNote` payload `(amount, destDomain, destRecipient, salt)`. **Source:** `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:44`; `../00-foundation/PHASE4-DATA-CONTRACTS.md:148-165`.
**Layout (owned here — deterministic item encode/decode):** `NoteStorage.items` = `(amount, destDomain, destRecipient, salt)` — destination fields belong in `NoteStorage.items`, **NOT** in metadata (ASG-13); `metadata.sender` = depositor only (`03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:48-51`, C-3). The felt layout of these four items is tabled in `## 7`; the encode/decode helpers are `encode_burn_note_items` / `decode_burn_note_items` (`## 6.6`).
**Ownership boundary (load-bearing for Phase 4.2 reconciliation):** this library owns the **deterministic item-layout encode/decode** only. The **note lifecycle, public observability (`NoteType::Public`, the fixed full-32-bit tag, the two-block create/consume discipline), the holder-balance-at-create check, and the validation/discovery flow** are owned by the faucet (`../agent-tasks/TASK-P4-ONCHAIN-XUSDC-FAUCET.md`) and the burn listener (`../agent-tasks/TASK-P4-WITHDRAWAL-LISTENER-ATTESTER.md`) — `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:44`; `01-0xMiden-capabilities/MIDEN-RPC-BURN-EVIDENCE.md:25-26`.
**PRODUCER:** user burn tx (B1, faucet-owned). **CONSUMER:** burn listener (CMP-C2), Circle. **VALIDATION OWNER:** the burn flow / listener (note lifecycle); this library (item encode/decode round-trip).
**Consumed invariants:** `INV-PUBLIC-BURN-OBSERVABILITY` (the `NoteStorage.items` payload-placement portion owned here), `INV-NOTE-MODEL-CURRENT`. The lifecycle invariants `INV-TWO-BLOCK-BURN` and `INV-BURN-HOLDER-BALANCE-AT-CREATE` (foundation DC-7) are faucet/listener-owned, not owned by this library. **Tests:** TV-BN-1..4, TV-DUAL-4. **Guardrail:** ASG-13. **Gating:** DEV-2 / Q-BUR-1/2 (public note as burn event — owned by the faucet/listener tasks).

### DC-13 (optional) — Circle-returned binary decode/validation helpers
`WithdrawHookData` magic `0x6b20f62a`, 112-byte header (`02-specifications/CIRCLE-DATA-SCHEMAS.md:127`,`:133`); binary `forwardingContract` = 32B left-padded vs JSON `forwardingContractAddress` = 20B (`:157`,`:162`); reconciliation `BurnIntent(72) + TransferSpec(340) + WithdrawHookData(112) = 524B + forwardingCalldata` (`02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:76`). TransferSpec magic `0xca85def7`, 340-byte header (`02-specifications/CIRCLE-DATA-SCHEMAS.md:57`,`:63`); BurnIntent magic `0x070afbc2`, 72-byte header (`:88`,`:92`). **This path is OPTIONAL off-chain validation only:** the partner signs `messageHashToSign` as opaque; binary reconstruction is NOT on the critical path (`02-specifications/CIRCLE-DATA-SCHEMAS.md:164`; the ASG-5 boundary). **Gating:** RCC for the byte-level JSON→binary transform (`02-specifications/CIRCLE-DATA-SCHEMAS.md:166`).

### DC-4 — Nonce keying (consumed by the bytes32→key helper)
`DepositIntent.nonce` (`bytes32` @204) → Option B Poseidon2 hash-to-Word → `StorageMapKey`; the reference store is `mapping(bytes32 => bool) usedNonces`, false→true on first write (`02-specifications/CIRCLE-DATA-SCHEMAS.md:204-205`; `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:19`,`:58-61`). The on-chain assert-zero-then-set is owned by `CMP-A8`; the **keying primitive** is owned here. **Gating:** DEV-9 / Q-CRY-5.

### DC-3 — Candidate-pubkey + commitment (consumed by the bytes32→key helper)
commitment = `Poseidon2(33-byte compressed pubkey)` → one `Word`, the `xReserveAttesters` allowlist key (`01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:46`; `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:25`, allowlist value slot is a `Word`). The `verify`/`verify_prehash` call is owned by the faucet (`CMP-A7`/`CMP-A9`); the **commitment-keying primitive** is owned here. **Gating:** DEV-1 (owned by the faucet task).

---

## 4. File / crate layout

The library is a module inside `miden-base/crates/miden-standards` (new xUSDC code lives there — `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:100`,`:101`; the component rows are `IMPLEMENTABLE_IN_STANDARDS` — `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:24`,`:67`,`:69`). The builder MAY instead place it in a dedicated app-crate `xreserve-encoding` re-exported by `miden-standards`; the module tree below is identical either way.

```
miden-standards/
├── src/xreserve/encoding/
│   ├── mod.rs            # re-exports; the EncodingError type; the crate-level docs
│   ├── error.rs          # EncodingError enum + the MASM error-code constants
│   ├── bytes32.rs        # DUAL: bytes32 -> StorageMapKey (Option B), packing primitives
│   ├── account_id.rs     # RUST-PRIMARY: AccountId <-> bytes32 (two-felt form on-chain)
│   ├── amount.rs         # DUAL: uint256 -> AssetAmount, reduced-compare
│   ├── deposit_intent.rs # DUAL: DepositIntent fixed-offset parse + 60-felt preimage
│   ├── burn_note.rs      # DUAL: XReserveBurnNote NoteStorage.items encode/decode
│   └── attestation.rs    # DUAL: keccak-digest / pubkey / sig felt packing + commitment
├── src/xreserve/circle_json/        # RUST-ONLY (off-chain)
│   ├── mod.rs
│   ├── prepare_withdrawal.rs         # PrepareBurnIntentInput + response models
│   ├── attestation_api.rs            # GET /v1/attestations responses
│   ├── withdraw.rs                   # WithdrawBatch request/response
│   ├── balances.rs                   # /v1/balances, /v1/info
│   └── error_body.rs                 # HTTP 400/404/409/500 error bodies
├── src/xreserve/circle_binary/      # RUST-ONLY, OPTIONAL (off-chain validation only)
│   ├── mod.rs
│   ├── transfer_spec.rs              # 340B decoder, magic 0xca85def7
│   ├── burn_intent.rs                # 72B decoder, magic 0x070afbc2
│   └── withdraw_hook_data.rs         # 112B decoder, magic 0x6b20f62a, 524B reconciliation
├── masm/xreserve/encoding/          # MASM side of the DUAL helpers (compiled by the faucet)
│   ├── deposit_intent.masm           # parse_deposit_intent
│   ├── amount.masm                   # uint256_to_asset_amount
│   ├── bytes32_key.masm              # bytes32_to_key (Poseidon2 hash-to-Word)
│   └── attestation.masm              # digest/pubkey/sig staging + pubkey_commitment
└── tests/vectors/
    └── xreserve-encoding-vectors.json  # SHARED test vectors (Rust + MASM agree byte-for-byte)
```

**Dual / Rust-only / MASM classification:**

| Helper family | Rust-only | MASM | Dual (Rust ref + MASM agree on shared vectors) |
|---|---|---|---|
| `bytes32 → StorageMapKey` | | | **dual** — `bytes32.rs` + `bytes32_key.masm` |
| `uint256 → AssetAmount` | | | **dual** — `amount.rs` + `amount.masm` |
| `DepositIntent` parse + 60-felt preimage | | | **dual** — `deposit_intent.rs` + `deposit_intent.masm` |
| burn-note storage-schema | | | **dual** — `burn_note.rs` + the burn-note MASM script (owned by the faucet task) |
| attestation wire-form packing + commitment | | | **dual** — `attestation.rs` + `attestation.masm` |
| AccountId ↔ bytes32 | **Rust-primary** (off-chain encode/decode) | (on-chain consumes the two felts directly, no repacking — `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:152`) | — |
| Circle JSON types | **Rust-only** | | — |
| Circle binary decoders (DC-13) | **Rust-only, OPTIONAL** | | — |

For each **dual** helper, the MASM side MUST be exercised through the faucet's MockChain / local-node harness (TASK-P4-ONCHAIN-XUSDC-FAUCET); the Rust reference is a speed aid, explicitly labelled NON-GATING for the on-chain path (`## 9.C`, `## 11`).

---

## 5. Module boundaries

- **Exports.** `encoding/mod.rs` re-exports every public function in `## 6` plus `EncodingError`. `circle_json` and `circle_binary` are separate sub-modules, not re-exported into the core `encoding` namespace.
- **Forbidden dependencies (one-directional rule).** The encoding helpers MUST NOT import faucet/service business logic: no `xreserve_mint`, no HTTP client, no `miden-client` RPC, no `submit_new_transaction`. The dependency edge is one-way — faucet/relayer/listener/monitor import `encoding`, never the reverse. This keeps the library a pure leaf so the same bytes produce the same felts in every consumer (`../00-foundation/PHASE4-DATA-CONTRACTS.md:7`).
- **Allowed dependencies.** Core `encoding` depends only on `miden-protocol` types (`Word`, `Felt`, `StorageMapKey`, `AccountId`, `AssetAmount`), the `miden-core` packing utility `bytes_to_packed_u32_elements` (`01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:88`, E-13), and the protocol `Hasher` (Poseidon2, `:81`, E-6). The shared core is `no_std`-compatible so the Rust references for dual helpers can be cross-checked against the MASM side. `circle_json` may pull `serde`; `circle_binary` may pull `primitive_types::U256` only if the optional path is built. The `uint256→AssetAmount` reuse of AggLayer `EthAmount` (which pulls `primitive_types::U256` + the agglayer feature gate) is the implementation decision IMPL-UINT256-REUSE (`## 10`).
- **No business logic in encoding.** A helper returns a value or an `EncodingError`; it never performs a `token_supply` write, an `assert`-trap on chain semantics, a nonce-set, or a signature verification. Those belong to `CMP-A8`/`CMP-A9` and the off-chain services.

---

## 6. Exact function / procedure names and signatures

Rust signatures below are normative (names, parameter types, return types). MASM procedure names follow `xreserve::encoding::<name>` and document their stack in/out per the `masm-doc-comments` convention (Description / Inputs / Outputs / Where / Panics if / Invocation).

### 6.1 `error.rs`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingError {
    LimbOutOfField,        // a u64 limb >= p in the lossless bytes32->Word path (E-3)
    AmountTooLarge,        // high 4 limbs nonzero => value > 2^128 (ERR_X_TOO_LARGE, E-16)
    AmountOverCap,         // post-scale quotient y > AssetAmount::MAX (E-7)
    ScaleExpTooLarge,      // 10^scale_exp overflowed
    BadMagic,              // DepositIntent magic != 0x5a2e0acd
    BadVersion,            // version != 1
    ZeroField { field: DepositIntentField }, // amount/localToken/localDepositor == 0
    TruncatedHeader,       // input shorter than 240 bytes
    LengthMismatch,        // total length != 240 + hookDataLen
    HookDataTooLarge,      // 60-felt header + hookData felts exceed the 1024-felt bound (DEV-6)
    AccountIdOutOfRange,   // R-B: a non-zero byte in the leading 16-byte pad region bytes[0..16]
    NonCanonicalAccountId, // bytes32 does not decode to a canonical AccountId
    BurnItemsMalformed,    // burn-note NoteStorage.items wrong length/shape
    JsonSchema(String),    // Circle JSON does not match the Phase-1 schema
    BinaryMagic,           // optional decoder: wrong magic
    BinaryLength,          // optional decoder: 524B reconciliation failed
}

// MASM error-code constants (mirrored in masm/.../*.masm), modelled on AggLayer (E-14, E-16):
pub const ERR_X_TOO_LARGE: u32       = /* "larger than 2**128", E-16 */;
pub const ERR_FELT_OUT_OF_FIELD: u32 = /* build_felt overflow guard, E-14 */;
pub const ERR_DI_BAD_MAGIC: u32      = /* DepositIntent magic */;
pub const ERR_DI_BAD_VERSION: u32    = /* DepositIntent version */;
pub const ERR_DI_ZERO_FIELD: u32     = /* amount/localToken/localDepositor zero */;
pub const ERR_DI_LENGTH: u32         = /* length != 240 + hookDataLen */;
```

**Builder note (error codes).** The `ERR_*` constants above are declared with their intent. The builder MUST assign concrete `u32` error-code values per the `agent-tools` `masm-constants` convention and mirror them byte-for-byte between `error.rs` and the `.masm` files, so the Rust reference and the MASM implementation trap with the same code on the same vector (TV-DUAL-*).

### 6.2 `bytes32.rs` (dual — INV-BYTES32-HASH-TO-WORD)

```rust
/// Option B (canonical for arbitrary external bytes32): infallible Poseidon2 hash-to-Word.
/// felts = bytes_to_packed_u32_elements(b) (8 felts); key = Hasher::hash_elements(&felts).
/// Cite: MIDEN-CRYPTO-AND-ENCODING.md:91-108 (§3.3 Option B); EVIDENCE-LEDGER E-4/E-6/E-12/E-13.
pub fn bytes32_to_storage_map_key(b: &[u8; 32]) -> StorageMapKey;

/// The 8x u32-LE packing primitive (infallible, each u32 < 2^32 < p). Cite: E-12 (:87), E-13 (:88).
pub fn bytes32_to_packed_felts(b: &[u8; 32]) -> [Felt; 8];

/// Option A (lossless, FALLIBLE — NOT used for external map keys): native TryFrom.
/// Returns Err(LimbOutOfField) if any 8-byte LE limb >= p. Provided for round-trip tests only.
/// Cite: E-3 (:78), C-5 (ARCHITECTURE-DECISIONS-AND-CAVEATS.md:58-61).
pub fn bytes32_to_word_lossless(b: &[u8; 32]) -> Result<Word, EncodingError>;
```
MASM: `xreserve::encoding::bytes32_to_key`
- **Inputs:** `[B1, B0]` — the bytes32 staged word-aligned as 8 u32-LE limbs across two words.
- **Outputs:** `[KEY]` — the Poseidon2 `Word` key (the value goes into `StorageMapKey`).
- **Where:** `B0,B1` = the 8 u32 limbs; `KEY = hash_elements(B0 ‖ B1)`.
- **Panics if:** never (deterministic; the packing is overflow-free, E-13).
- **Invocation:** `exec`.

### 6.3 `account_id.rs` (Rust-primary — INV-ACCOUNTID-ENCODING)

```rust
pub const ADDRESS_TYPE_ACCOUNT_ID: u8 = 232; // E-11 (MIDEN-EVIDENCE-LEDGER.md:86)

/// AccountId -> bytes32 packaging. DEFAULT DRAFT LAYOUT = R-B / Agglayer-mirroring
/// (IMPL-ACCOUNTID-LAYOUT, RCC DEV-10; human-selected 2026-06-15):
///   bytes[0..16]  = 0x00 (leading zero padding)
///   bytes[16..24] = AccountId prefix, u64 big-endian   (prefix().as_u64().to_be_bytes())
///   bytes[24..32] = AccountId suffix, u64 big-endian   (suffix().as_canonical_u64().to_be_bytes())
/// Mirrors the protocol Agglayer EthEmbeddedAccountId 20-byte form `0x00000000 || prefix(8) || suffix(8)`
/// (protocol crates/miden-agglayer/src/eth_types/eth_embedded_account_id.rs:117-122) widened to a 32-byte slot;
/// the inverse validates Felt<p + AccountId::try_from_elements (ibid:86-96). Lossless; <=32 bytes so no keccak fallback.
/// SUPERSEDED (2026-06-15): the prior draft was data-LEFT-aligned (bytes[0..15] = the 15-byte AccountId::to_bytes(),
/// bytes[15..32] = zero). Replaced by R-B above; the 04 code+vector revision is a SEPARATE, builder-gated task.
/// The exact byte layout is a DRAFT submitted to Circle via the S1-NDA L22 workflow -- REQUIRES CIRCLE CONFIRMATION (DEV-10); no Circle approval.
/// Cite: E-9 (:84), E-10 (:85), MIDEN-CRYPTO-AND-ENCODING.md:148-157; Agglayer precedent eth_embedded_account_id.rs:117-122.
pub fn account_id_to_bytes32(id: AccountId) -> [u8; 32];

/// Inverse (R-B): rejects any non-zero byte in the leading 16-byte pad region bytes[0..16]
/// (AccountIdOutOfRange) and a prefix/suffix that is not a canonical AccountId (NonCanonicalAccountId).
/// Round-trip lossless for valid ids.
pub fn bytes32_to_account_id(b: &[u8; 32]) -> Result<AccountId, EncodingError>;

/// The on-chain natural form: the two felts [prefix, suffix] directly (no byte repacking).
/// Cite: MIDEN-CRYPTO-AND-ENCODING.md:152.
pub fn account_id_to_felts(id: AccountId) -> [Felt; 2];
```

### 6.4 `amount.rs` (dual — INV-UINT256-TO-ASSETAMOUNT)

```rust
/// uint256 (8 LE u32 limbs) -> AssetAmount via the E-16 mechanic. scale_exp = EVM-decimals - Miden-decimals (0..=18).
/// Steps: byte-swap -> assert high 4 limbs zero (else AmountTooLarge) -> low 4 as u128 x
///        -> y = floor(x / 10^scale_exp) -> AssetAmount::new(y) (rejects y > MAX => AmountOverCap).
/// Cite: E-16 (:91), C-6 (ARCHITECTURE-DECISIONS-AND-CAVEATS.md:63-66), D5b (ARCHITECTURE-FLOWS.md:50).
pub fn uint256_to_asset_amount(le_limbs: [u32; 8], scale_exp: u32) -> Result<AssetAmount, EncodingError>;

/// The reduced-compare: reduce both operands, then compare as u64. Used for amount >= maxFee
/// and feeAmount <= maxFee (CIR-MINT-PRE-8/9, CIRCLE-REQUIREMENTS-MATRIX.md:47-48).
pub fn reduced_ge(a: [u32; 8], b: [u32; 8], scale_exp: u32) -> Result<bool, EncodingError>;

/// The non-zero division remainder (dust). Exposed so the caller can apply the DEV-5 dust policy.
/// Returns (y = AssetAmount, z = remainder u128). Cite: E-16 (:91, 0 <= z < 10^scale).
pub fn uint256_to_asset_amount_with_dust(le_limbs: [u32; 8], scale_exp: u32)
    -> Result<(AssetAmount, u128), EncodingError>;
```
MASM: `xreserve::encoding::uint256_to_asset_amount` (model `verify_u256_to_native_amount_conversion`, E-16)
- **Inputs:** `[U1, U0, scale_exp]` — the uint256 as 8 u32-LE limbs across two words, plus the scale exponent.
- **Outputs:** `[y]` — the reduced `AssetAmount` (u64 felt); the proc traps rather than saturating if `y` exceeds `AssetAmount::MAX`.
- **Where:** byte-swap; assert high 4 limbs zero; `x` = low-4 u128; `y = floor(x/10^scale_exp)`; assert `y ≤ AssetAmount::MAX`.
- **Panics if:** high 4 limbs ≠ 0 (`ERR_X_TOO_LARGE`); `y > AssetAmount::MAX`.
- **Invocation:** `exec`.

### 6.5 `deposit_intent.rs` (dual — INV-DEPOSITINTENT-PARSE)

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositIntentField { Magic, Version, Amount, RemoteDomain, RemoteToken,
    RemoteRecipient, LocalToken, LocalDepositor, MaxFee, Nonce, HookDataLen, HookData }

pub const DEPOSIT_INTENT_HEADER_LEN: usize = 240;
pub const DEPOSIT_INTENT_MAGIC: u32 = 0x5a2e0acd;        // :21
pub const DEPOSIT_INTENT_VERSION: u32 = 1;               // :22
pub const DEPOSIT_INTENT_HEADER_FELTS: usize = 60;       // C-10 (:85), NOT 30 (ASG-16)

/// Fixed-offset accessor (offsets per DC-1 table).
pub fn deposit_intent_field_offset(field: DepositIntentField) -> usize;

#[derive(Debug, Clone)]
pub struct DepositIntentHeader {
    pub magic: u32, pub version: u32, pub amount: [u8; 32], pub remote_domain: u32,
    pub remote_token: [u8; 32], pub remote_recipient: [u8; 32], pub local_token: [u8; 32],
    pub local_depositor: [u8; 32], pub max_fee: [u8; 32], pub nonce: [u8; 32], pub hook_data_len: u32,
}

/// Structural parse + the library-owned checks (magic, version, length, non-zero). Does NOT do the
/// domain/identifier equality compares (faucet-owned, D5a). Cite: CIRCLE-DATA-SCHEMAS.md:34-35;
/// CIRCLE-REQUIREMENTS-MATRIX.md:41-50; ARCHITECTURE-FLOWS.md:49.
pub fn parse_deposit_intent_header(bytes: &[u8]) -> Result<DepositIntentHeader, EncodingError>;

/// The u32-LE-packed on-chain preimage: 60 felts for the header + ceil(hookDataLen/4) felts of hookData.
/// Errors HookDataTooLarge if total felts exceed the 1024-felt NoteStorage bound (DEV-6). Cite: C-10 (:85), N-4 (:100).
pub fn deposit_intent_to_packed_felts(bytes: &[u8]) -> Result<Vec<Felt>, EncodingError>;
```
MASM: `xreserve::encoding::parse_deposit_intent`
- **Inputs:** a pointer to the u32-LE-packed DepositIntent preimage in `NoteStorage.items` and its felt length.
- **Outputs:** the parsed field words pushed for the caller's compares; trap on a failed structural check.
- **Where:** offsets per DC-1; the 60-felt header bound; `hookData` felts within the 1024-felt cap.
- **Panics if:** `magic != 0x5a2e0acd`; `version != 1`; `amount == 0`; `localToken == 0`; `localDepositor == 0`; `len != 240 + hookDataLen` (the library-owned checks; the faucet adds the domain/identifier compares).
- **Invocation:** `exec`.

### 6.6 `burn_note.rs` (dual — INV-PUBLIC-BURN-OBSERVABILITY, DC-7)

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XReserveBurnItems {
    pub amount: AssetAmount, pub dest_domain: u32, pub dest_recipient: [u8; 32], pub salt: [u8; 32],
}

/// Encode (amount, destDomain, destRecipient, salt) into the NoteStorage.items felt layout.
/// Destination fields go in NoteStorage.items, NOT metadata (ASG-13). Cite: ARCHITECTURE-COMPONENT-MAP.md:44.
pub fn encode_burn_note_items(items: &XReserveBurnItems) -> Vec<Felt>;

/// Inverse; errors BurnItemsMalformed on wrong length/shape.
pub fn decode_burn_note_items(items: &[Felt]) -> Result<XReserveBurnItems, EncodingError>;
```

### 6.7 `attestation.rs` (dual — INV-DEPOSIT-ATTESTATION-RAW-KECCAK, DC-2)

```rust
/// 8-felt u32-LE packing of the 32-byte keccak256(DepositIntent payload) digest. Cite: MIDEN-CRYPTO-AND-ENCODING.md:40-42.
pub fn keccak_digest_felts(digest: &[u8; 32]) -> [Felt; 8];

/// 9-felt packing of the 33-byte compressed SEC1 secp256k1 pubkey. Cite: :41, :53.
pub fn compressed_pubkey_felts(pk: &[u8; 33]) -> [Felt; 9];

/// 17-felt packing of the 65-byte r‖s‖v signature (the v byte is carried, unused). Cite: :42, :53-54.
pub fn signature_felts(sig: &[u8; 65]) -> [Felt; 17];

/// Poseidon2(33-byte compressed pubkey) -> the xReserveAttesters allowlist commitment Word.
/// Cite: MIDEN-CRYPTO-AND-ENCODING.md:46; ARCHITECTURE-COMPONENT-MAP.md:25.
pub fn pubkey_commitment(pk: &[u8; 33]) -> Word;
```
The `keccak256::hash_bytes` digest production and the `ecdsa_k256_keccak::verify_prehash` call are owned by the faucet (`CMP-A9`, flow D5d, `03-architecture/ARCHITECTURE-FLOWS.md:52`); this library owns only the byte→felt packing and the commitment keying.

### 6.8 `circle_json/` (Rust-only) and `circle_binary/` (Rust-only, optional)

`circle_json` exposes serde-derived models mirroring the Phase-1 schemas exactly: `PrepareBurnIntentInput` and its response (`02-specifications/CIRCLE-API-SURFACE.md:129-143`), the attestation-fetch response (`:44`), `WithdrawBatch` (`:179-185`), `/v1/balances` and `/v1/info` (`:34-39`), and the error bodies. `circle_binary` exposes `decode_transfer_spec`, `decode_burn_intent`, `decode_withdraw_hook_data`, each asserting its magic and the 524B reconciliation (`02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:76`); this path is OPTIONAL validation only (DC-13).

---

## 7. Data shapes (byte widths, endianness, felt counts)

| Object | Bytes | Endianness | Felts | Cite |
|---|---|---|---|---|
| `bytes32` (external) | 32 | big-endian on wire | 8 u32-LE-packed felts = **2 Words** | E-12 `:87`, E-13 `:88`, C-5 `:58-61` |
| `bytes32 → StorageMapKey` | 32 in | — | 1 `Word` out (Poseidon2) | E-4 `:79`, E-6 `:81` |
| `uint256` amount/fee | 32 | big-endian on wire, byte-swapped to 8 LE limbs | low 4 limbs → u128 → `AssetAmount` (u64) | E-16 `:91`, C-6 `:63-66` |
| `AssetAmount` | — | — | `u64`, `MAX = 2^63 − 2^31` | E-7 `:82` |
| `AccountId` | 15 (8 BE prefix + 7 BE suffix) | big-endian | **2 felts** `[prefix, suffix]` | E-9 `:84`, E-10 `:85` |
| `AddressType::AccountId` | 1 | — | `232 = 0b1110_1000` | E-11 `:86` |
| DepositIntent header | 240 | big-endian | **60 u32-packed felts** (4 bytes/felt) | C-10 `:85` |
| keccak256 digest | 32 | u32-LE-packed | **8 felts** | MIDEN-CRYPTO `:40-42` |
| compressed pubkey | 33 | u32-LE-packed | **9 felts** | MIDEN-CRYPTO `:41`,`:53` |
| `r‖s‖v` signature | 65 | u32-LE-packed | **17 felts** (`v` carried unused) | MIDEN-CRYPTO `:42`,`:53-54` |
| `NoteStorage.items` | — | — | ≤ **1024 felts** | N-4 `:100` |
| `NoteAttachments` | — | — | ≤4 attachments / ≤512 words | N-9 `:105` |
| burn-note `NoteStorage.items` payload | — | — | `amount` (1 `AssetAmount` felt) + `destDomain` (1 u32 felt) + `destRecipient` (`bytes32` = 8 u32-packed felts) + `salt` (`bytes32` = 8 u32-packed felts) | ARCHITECTURE-COMPONENT-MAP.md:44 |

**Convention.** Circle/EVM wire is big-endian, fixed-offset headers + length-prefixed tails (`02-specifications/CIRCLE-DATA-SCHEMAS.md:17`,`:34`). The on-chain preimage form is u32-LE-packed, 4 bytes/felt — the keccak/ECDSA/AggLayer precompile convention (`01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:40-42`; E-12 `:87`, E-13 `:88`). `bytes32` is NOT a raw `Word` (8× u32 spans 2 Words) and is NOT mapped onto a single Felt (`../00-foundation/PHASE4-DATA-CONTRACTS.md:21-22`).

**Out of this byte/felt table by design.** Circle **JSON** request/response shapes are not byte/felt objects — their field schemas live in `## 6.8` + the `02-specifications/CIRCLE-API-SURFACE.md:129-143`,`:179-185` citations. The optional Circle **binary** byte shapes (TransferSpec 340B / BurnIntent 72B / WithdrawHookData 112B / the 524B reconciliation) are catalogued in DC-13 (`## 3`), not duplicated here.

---

## 8. Validation order (per parser, numbered, mirroring source order)

### 8.1 DepositIntent parse (D5a order — `03-architecture/ARCHITECTURE-FLOWS.md:49`; `02-specifications/CIRCLE-DATA-SCHEMAS.md:35`)

The library performs steps 1–4, 7, 8 (structural); the faucet performs steps 5, 6 (storage compares against `XReserveDomainConfig`). The numbering follows the cited D5a sequence so the on-chain proc asserts in the same order:

1. `magic == 0x5a2e0acd` — else `BadMagic` (CIR-MINT-PRE-2, `:41`).
2. `version == 1` — else `BadVersion` (CIR-MINT-PRE-3, `:42`).
3. `amount != 0` — else `ZeroField{Amount}` (CIR-MINT-PRE-4, `:43`).
4. `localToken != 0` and `localDepositor != 0` — else `ZeroField{..}` (CIR-MINT-PRE-5, `:44`).
5. `remoteDomain == self.domain` — *faucet-owned* (CIR-MINT-PRE-6, `:45`).
6. `remoteToken == self.identifier` — *faucet-owned* (CIR-MINT-PRE-7, `:46`).
7. `len == 240 + hookDataLen` — else `LengthMismatch` (CIR-MINT-PRE-11, `:50`).
8. header ≥ 240 — else `TruncatedHeader` (`02-specifications/CIRCLE-DATA-SCHEMAS.md:35`).

`amount ≥ maxFee` and `feeAmount ≤ maxFee` are reduced-compares applied AFTER the reduce step (D5b), via `reduced_ge` (CIR-MINT-PRE-8/9, `:47-48`).

### 8.2 uint256 → AssetAmount (D5b order — `03-architecture/ARCHITECTURE-FLOWS.md:50`; E-16 `:91`)

1. byte-swap the 8 LE u32 limbs to big-endian numeric order;
2. assert high 4 limbs == 0 (≤ `2^128`) — else `AmountTooLarge` / `ERR_X_TOO_LARGE`;
3. low 4 limbs → u128 `x`;
4. `y = floor(x / 10^scale_exp)`, remainder `0 ≤ z < 10^scale_exp`;
5. `AssetAmount::new(y)` — rejects/traps if `y` exceeds `MAX` (`AmountOverCap`); no saturation or clamping.

### 8.3 bytes32 → StorageMapKey (deterministic)

1. `felts = bytes_to_packed_u32_elements(b)` (8 felts, infallible);
2. `w = Hasher::hash_elements(&felts)` (Poseidon2, one canonical `Word`);
3. `StorageMapKey::new(w)`. No trap path; idempotent (same input → same key).

---

## 9. Edge cases and failure modes (each mapped to a named error)

| Edge case | Helper | Named error / trap | Cite |
|---|---|---|---|
| 8-byte LE limb ≥ `p` in the lossless native path | `bytes32_to_word_lossless` | `LimbOutOfField` (Option B bypasses this; the test proves Option B succeeds where Option A fails) | E-3 `:78` |
| high 4 limbs nonzero (value > `2^128`) | `uint256_to_asset_amount` | `AmountTooLarge` / `ERR_X_TOO_LARGE` | E-16 `:91` |
| post-scale quotient `y > AssetAmount::MAX` | `uint256_to_asset_amount` | `AmountOverCap` | E-7 `:82` |
| non-zero division remainder (dust) | `uint256_to_asset_amount_with_dust` | none — `z` returned; dust policy is DEV-5 RCC | E-16 `:91` |
| `10^scale_exp` overflow | `uint256_to_asset_amount` | `ScaleExpTooLarge` | C-6 `:63-66` |
| header < 240 bytes | `parse_deposit_intent_header` | `TruncatedHeader` | `:35` |
| `len != 240 + hookDataLen` | `parse_deposit_intent_header` | `LengthMismatch` | `:35`, CIR-MINT-PRE-11 `:50` |
| `magic`/`version` mismatch | `parse_deposit_intent_header` | `BadMagic` / `BadVersion` | `:35`, CIR-MINT-PRE-2/3 `:41-42` |
| `amount`/`localToken`/`localDepositor` == 0 | `parse_deposit_intent_header` | `ZeroField{..}` | `:35`, CIR-MINT-PRE-4/5 `:43-44` |
| `hookDataLen` overflowing the 1024-felt bound | `deposit_intent_to_packed_felts` | `HookDataTooLarge` (DEV-6 RCC; default cap within 1024 felts) | C-10 `:85`, N-4 `:100` |
| bytes32 with a non-zero byte in the R-B leading pad region `bytes[0..16]` | `bytes32_to_account_id` | `AccountIdOutOfRange` | E-9 `:84`, E-10 `:85` |
| bytes32 whose `bytes[16..24]`/`bytes[24..32]` prefix/suffix do not form a canonical AccountId (`AccountId::try_from_elements`) | `bytes32_to_account_id` | `NonCanonicalAccountId` | E-9 `:84` |
| burn-note items wrong length/shape | `decode_burn_note_items` | `BurnItemsMalformed` | ARCHITECTURE-COMPONENT-MAP.md:44 |
| Circle JSON off-schema / malformed / error body | `circle_json` | `JsonSchema(..)` | CIRCLE-API-SURFACE.md:129-143 |
| optional decoder wrong magic / 524B mismatch | `circle_binary` | `BinaryMagic` / `BinaryLength` | CIRCLE-CLAIM-ADJUDICATION.md:76 |

**Forbidden mechanic (ASG-7 + the superseded C-6 trap).** The historical "assert high **6** limbs zero, combine the low **2** into a u64" reduction is forbidden; the correct mechanic asserts high **4** limbs zero and takes the low **4** as a u128 (`03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:64`, the C-6 trap is named there; E-16 `:91`).

---

## 10. Open decisions consumed (RCC tokens; default assumptions; do NOT resolve)

Where a value is Circle-owned and unresolved, this spec writes **REQUIRES CIRCLE CONFIRMATION** and a default assumption; it does NOT resolve it. The full ledger is `OPEN-DECISIONS-CONSUMED.md`. Summary:

- **DEV-5 / Q-CRY-6** — uint256 cap + scale + dust. Default: cap `2^63 − 2^31`, scale to 6 dp. **REQUIRES CIRCLE CONFIRMATION**; **NO EVIDENCE OF CIRCLE APPROVAL** (`02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:44-49`).
- **DEV-6 / Q-INFRA-5** — hookData cap. Default: cap within the 1024-felt `NoteStorage` bound, attachment fallback. **REQUIRES CIRCLE CONFIRMATION** (Circle states no max length, `02-specifications/CIRCLE-DATA-SCHEMAS.md:229`; `02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:51-56`).
- **DEV-9 / Q-CRY-5** — nonce keyed by Poseidon2 commitment. Default: hash-to-Word keying. **REQUIRES CIRCLE CONFIRMATION**; **NO EVIDENCE OF CIRCLE APPROVAL** (`02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:73-78`).
- **DEV-10 / Q-CRY-3/4** — AccountId↔bytes32 byte layout (via S1-NDA L22). Default: **R-B / Agglayer-mirroring** right-aligned packaging (`bytes[0..16]=0`, `[16..24]=prefix u64 BE`, `[24..32]=suffix u64 BE`; see §DC-6; supersedes the prior left-aligned 15-byte/trailing-zero draft, 2026-06-15); draft + submit. **REQUIRES CIRCLE CONFIRMATION**; **NO EVIDENCE OF CIRCLE APPROVAL** (`02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:80-85`; `06-resources/CIRCLE_PARTNER_INTEGRATION_GUIDELINES.md:22`).
- **IMPL-UINT256-REUSE (DEV-5)** — reuse AggLayer `EthAmount::scale_to_token_amount` vs reimplement. **REQUIRES IMPLEMENTATION VALIDATION** (cap/scale still gated by the DEV-5 RCC) (`03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:126`; `../00-foundation/PHASE4-OPEN-DECISIONS.md:84`).
- **IMPL-HOOKDATA-CARRIER (DEV-6)** — hookData cap value + carrier (inline / attachment / commitment). **REQUIRES IMPLEMENTATION VALIDATION** (value gated by the DEV-6 RCC) (`03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:125`; `../00-foundation/PHASE4-OPEN-DECISIONS.md:83`).
- **IMPL-ACCOUNTID-LAYOUT (DEV-10)** — AccountId→bytes32 byte-layout draft for Circle approval; **current draft = R-B / Agglayer-mirroring right-aligned** (2026-06-15, supersedes left-aligned). **REQUIRES IMPLEMENTATION VALIDATION** (approval gated by the DEV-10 RCC) (`03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:127`; `../00-foundation/PHASE4-OPEN-DECISIONS.md:85`).

**Resolved-no-fallback (SOURCE-BACKED FACT, not an open decision):** CIR-HOOK-3 (>32-byte id keccak fallback) is **not needed** because an AccountId is 15 bytes (`02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:125`; `03-architecture/ARCHITECTURE-TRACEABILITY-MATRIX.md:67`; E-9 `:84`). Optional Circle-returned binary reconstruction (DC-13) carries an RCC for the byte-level JSON→binary transform (`02-specifications/CIRCLE-DATA-SCHEMAS.md:166`).

---

## 11. Mock policy for THIS component

> **Circle API may be mocked; Miden behavior must not be faked for final acceptance.**

Component-specific application:

- **Primary harness.** Deterministic **unit tests + source-backed test vectors** are the primary harness for the encoding library. Encoding helpers are pure functions over bytes/felts; their positive/negative/round-trip behavior is fully determined by the cited Phase 1/2 byte layouts.
- **Circle JSON / binary fixtures.** The Circle JSON types and the optional binary decoders are validated against **mock fixtures** that MUST match the Phase-1 OpenAPI/schema package exactly (`02-specifications/CIRCLE-API-SURFACE.md` + `02-specifications/CIRCLE-DATA-SCHEMAS.md`) and MUST include malformed/error cases (HTTP 400/404/409/500). **Circle API may be mocked.** This is safe because the encoding library never makes a live Circle call — it only encodes/decodes the bytes the services move; the live call is unavailable while `Q-API-AUTH`, `Q-INFO-PARAM`, `Q-DOM-1` are OPEN (`02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:99`,`:101`,`:96`).
- **Miden-specific encoding assumptions must NOT be faked.** Any Miden-specific encoding assumption — the Poseidon2 hash-to-Word equivalence, the u32-LE packing, the uint256 reduction, the AccountId serialization — MUST trace to a Phase-2 source citation, AND, **where the helper is consumed on-chain**, be exercised through the faucet's **MockChain** (contract level) and **local-node** (note/RPC/lifecycle) harness. No Miden fake substitutes for that in final acceptance. A Rust-only reference of a dual helper is a speed aid, explicitly labelled **NON-GATING**, paired with the real MockChain/local-node check the faucet task runs.
- **Per-helper boundary:**

| Helper | May use a mock fixture? | Why safe | What real verification compensates |
|---|---|---|---|
| `bytes32 → StorageMapKey` | no | deterministic over bytes | Rust vectors + the on-chain `bytes32_to_key` exercised in the faucet MockChain/local-node nonce + attester paths |
| `uint256 → AssetAmount` | no | deterministic over bytes | Rust vectors + the on-chain reducer exercised in the faucet D5b MockChain/local-node mint path |
| `DepositIntent` parse | no | deterministic over bytes | Rust vectors + the on-chain parser exercised in the faucet D5a MockChain/local-node path |
| burn-note storage-schema | no | deterministic over felts | Rust round-trip vectors + the on-chain burn-note write exercised in the faucet burn MockChain/local-node path |
| attestation wire-form packing | no | deterministic over bytes | Rust vectors + the felts consumed by the faucet `verify_prehash` D5d path |
| AccountId ↔ bytes32 | no | deterministic over bytes | Rust round-trip vectors |
| Circle JSON types | **yes — mock fixtures** | the library never calls Circle; live call gated on OPEN `Q-API-AUTH`/`Q-INFO-PARAM`/`Q-DOM-1` | serde round-trip against fixtures matching the Phase-1 schema, including malformed/error bodies |
| Circle binary decoders (DC-13) | **yes — mock fixtures**, OPTIONAL/NON-GATING | the partner signs `messageHashToSign` as opaque; binary reconstruction is off the critical path (`02-specifications/CIRCLE-DATA-SCHEMAS.md:164`) | magic + 524B reconciliation against a fixture (`02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:76`); labelled NON-GATING |

---

## 12. Future builder-agent loop (hand this to the implementation agent)

1. **Read** this COMPONENT-SPEC.md + the source-backed invariants (`## 2`) and their citations.
2. **Create/confirm the tests and harness FIRST** (test-first; `TEST-AND-VERIFICATION-HARNESS.md`). Confirm each vector test **fails** against the unimplemented helper (red), proving it exercises real behavior.
3. **Implement the smallest complete slice**, one helper family at a time, starting with the byte-level primitives `bytes32` and `uint256` that everything else composes.
4. **Run the relevant tests/commands after each meaningful change** (the `## 9.C` commands in `TEST-AND-VERIFICATION-HARNESS.md`).
5. **Compare** the implementation against this spec + the source-backed invariants.
6. **Fix gaps — OR, if source evidence (`path:LINE`) disproves this spec, STOP and report the contradiction** (do not guess, do not silently edit the spec).
7. **Repeat** until all acceptance gates (`## 13`) pass.
8. **Hand off for audit** with the exact commands + captured outputs (the audit-handoff bundle in `../00-foundation/PHASE4-VERIFICATION-HARNESS.md:265`).

**Test-first contract (mechanically followable).** The builder MUST build the testing + verification harness BEFORE the main implementation. No "implement first, add tests later"; no generic "add tests"; no hand-wavy Miden fake in final acceptance. The on-chain-consumed helpers' final acceptance is gated through the faucet's MockChain + local-node harness; the shared test-vector file both tasks consume is `tests/vectors/xreserve-encoding-vectors.json` (`## 4`).

---

## 13. Acceptance criteria (for the future implementation agent)

Acceptable only when ALL hold:

1. Every helper family in `## 1.1` is implemented with the exact names / signatures / data-shapes fixed in `## 6`–`## 7`.
2. The full `## 9.A` unit + source-backed vector suite in `TEST-AND-VERIFICATION-HARNESS.md` exists and passes (positive, boundary, per-field negative, round-trip, determinism).
3. For every **dual** helper, the `## 9.B` Rust-vs-MASM agreement test passes on the shared vectors, and the MASM side is exercised through the faucet's MockChain + local-node harness (NON-GATING Rust-only checks clearly labelled).
4. `cargo test -p <encoding-crate>` is green; the on-chain-consumed helpers pass `cd project-template && cargo test -p integration --release` and local-node validation within the faucet flow.
5. Every load-bearing claim traces to a `path:LINE` citation; no invented encoding beyond Phase 1/2/3.
6. Every Circle-owned `DEV-*`/`Q-*` touched remains OPEN, tagged with its verbatim status token; none is marked approved.
7. No banned shortcut from `## 14` is present (the static sweeps in `../00-foundation/PHASE4-VERIFICATION-HARNESS.md:269-305` are clean).

**Stop conditions (escalate, never guess):** a cited line does not say what this spec or the registry claims (a `path:LINE` mismatch — report both expected and actual); a required source file is missing/unreadable; two canonical sources conflict on a byte layout/bound/mechanic irreconcilably (a **BLOCKED** condition); the task would require resolving a Circle-owned `DEV-*`/`Q-*` (record OPEN, proceed with the documented default).

---

## 14. Anti-simplification guardrails this component enforces

Per the banned-language rule, only `../00-foundation/PHASE4-ANTI-SIMPLIFICATION-GATES.md` may quote the forbidden phrasings; below each gate is framed as a guardrail with a pointer there.

- **ASG-6** — packing `bytes32` directly as a `Word` is forbidden (`TryFrom` is fallible; 8× u32 = 2 Words); use Option B Poseidon2 hash-to-Word. Cite `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:58-61`; `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:78`. Enforced by TV-B32-1..4.
- **ASG-7** — treating a Felt as a u64 / mapping a uint256 onto one Felt is forbidden; decimal scale-down + reject/trap if the post-scale quotient exceeds `AssetAmount::MAX = 2^63−2^31` (no saturation or clamping). Cite `:63-66`; `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:82`. Enforced by TV-AMT-1..6.
- **ASG-16** — computing the DepositIntent header felt count as `240/8` is forbidden; the preimage is u32-LE-packed (4 bytes/felt) → **60 felts**. Cite `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:85` (C-10). Enforced by TV-DI-7.
- **ASG-17** — using `NoteInputs` / an `aux` field / an `Encrypted` note / a 4-word nullifier is forbidden; target the current note model. Cite `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:93-96` (C-12). Enforced by TV-DI-7, TV-BN-3.
- **ASG-13** — putting burn destination fields in note metadata is forbidden; `(amount, destDomain, destRecipient, salt)` lives in `NoteStorage.items`. Cite `03-architecture/ARCHITECTURE-CLAIM-ADJUDICATION.md:75-90`; `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:44`. Enforced by TV-BN-2/4.
- **ASG-12** — verifying only a subset of fields, or signing a synthetic Poseidon2 word instead of `keccak256(full DepositIntent payload)`, is forbidden; assert every parsed field and verify over the full-payload keccak. Cite `03-architecture/ARCHITECTURE-CLAIM-ADJUDICATION.md:75-90`. Enforced by TV-DI-1..6, TV-ATT-1..3.
- **ASG-11** — using historical files (`REPORT.md`, `GAP-MATRIX.md`, `EVIDENCE.md`, old audits) as primary sources is forbidden; cite only canonical Phase 1/2/3 files. Cite `PHASE4-SOURCE-MAP.md:68-85`.

---

## 15. Companion files

- `TEST-AND-VERIFICATION-HARNESS.md` — the test-first harness: exact test files/modules, positive/negative/malformed/determinism/integration cases, expected assertions, expected failure modes, exact commands.
- `CLAIM-EVIDENCE-MATRIX.md` — every load-bearing claim → class → exact `path:LINE` citation → how verified.
- `OPEN-DECISIONS-CONSUMED.md` — every `DEV-*`/`Q-*`/`IMPL-*` this component touches, default assumption, what changes if Circle answers differently, verbatim OPEN status token.
- `README.md` — the index, spec key, consuming tasks, final-status line.

**Final status of this spec: TEMP PASS** — decision-complete and fully cited, with every Circle-owned decision (DEV-5/6/9/10 and the IMPL-* rows) explicitly held OPEN (REQUIRES CIRCLE CONFIRMATION / REQUIRES IMPLEMENTATION VALIDATION; NO EVIDENCE OF CIRCLE APPROVAL).
