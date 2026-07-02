> **MIRROR — READ-ONLY (mirrored 2026-07-01).** Canonical source: `/Users/philipp/Documents/Work/Miden-Coding/agentic-template/ai-tasks/circle-integration/06-phase4-component-specs/04-shared-encoding/CLAIM-EVIDENCE-MATRIX.md`. Do NOT edit this copy; if it diverges from the canonical source, the canonical source wins. Re-sync via `tools/sync-mirrors.sh`.

# CLAIM-EVIDENCE-MATRIX — Shared Encoding Helper Library (`P4-ENCODE`)

Every load-bearing claim in `COMPONENT-SPEC.md` / `TEST-AND-VERIFICATION-HARNESS.md`, with its claim class, exact canonical `path:LINE` citation, the test/command that verifies it, and (where Circle-owned) the verbatim status token.

**Claim classes (`../00-foundation/PHASE4-SOURCE-MAP.md:18`):**
1. **SOURCE-BACKED FACT** — a byte layout / bound / mechanic proven in a Phase 1/2/3 row (`C-*`/`E-*`/`N-*`/`MC-*`/`CIR-*`).
2. **ARCHITECTURE DECISION (RACD)** — a recommended decision; Circle-owned RACDs carry an RCC.
3. **IMPLEMENTATION ASSUMPTION (RIV / RMD)** — `REQUIRES IMPLEMENTATION VALIDATION`.
4. **CIRCLE-OWNED OPEN QUESTION (RCC / DEV-* / Q-*)** and Miden optional/conditional upstream (U1/U2) — kept OPEN.

All citations were opened and read before citing. Where the registry attached a multi-line claim to a single line, the citation below is corrected to the exact line that carries the fact (the corrections are flagged in the **Notes** column).

---

## A. `bytes32` → hash-to-Word (INV-BYTES32-HASH-TO-WORD)

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| Native `TryFrom<[u8;32]> for Word` is fallible (4× u64-LE limbs, rejects any limb ≥ `p`) | SOURCE-BACKED FACT (E-3) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:78` | TV-B32-2 | — |
| StorageMap key is hashed via `Hasher::hash_elements` before SMT insertion | SOURCE-BACKED FACT (E-4) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:79` | TV-B32-1, TV-DUAL-1 | corrected: hash_elements lives at E-4 (`:79`), not E-5 |
| StorageMap value slot is a `Word`, not a `Felt` (no `StorageMap<Word,Felt>`) | SOURCE-BACKED FACT (E-5) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:80` | TV-B32-1 | — |
| Protocol `Hasher` alias is Poseidon2 | SOURCE-BACKED FACT (E-6) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:81` | TV-B32-1 | corrected: Poseidon2 lives at E-6 (`:81`) |
| 32-byte region = 8 u32 limbs (LE within limb); 4 bytes/u32-felt packing | SOURCE-BACKED FACT (E-12/E-13) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:87`,`:88` | TV-B32-4 | — |
| Use Option B Poseidon2 hash-to-Word over the 8× u32 packing → one canonical `Word`/`StorageMapKey` | ARCHITECTURE DECISION (RACD, C-5/DL-7) | `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:58-61`,`:19` | TV-B32-1..4, TV-DUAL-1 | RCC via DEV-9 |
| Option B helper signature (`bytes_to_packed_u32_elements` + `hash_elements`) | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:91-108` (§3.3) | TV-B32-1 | — |
| `bytes32` map keying capability is `IMPLEMENTABLE_IN_STANDARDS` (MC-CR-4) | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:67` | TV-B32-3 | — |
| Gap `GMS-5(G5)` = bytes32→StorageMapKey helper | SOURCE-BACKED FACT | `03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:45` | TV-B32-1 | — |
| Nonce keyed by a Poseidon2 commitment (assert-zero-then-set is faucet-owned) | CIRCLE-OWNED OPEN (DEV-9/Q-CRY-5) | `02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:73-78` | TV-B32-3 (keying), faucet TV | `REQUIRES CIRCLE CONFIRMATION` · `NO EVIDENCE OF CIRCLE APPROVAL` | — |
| Reference nonce store = `mapping(bytes32 => bool) usedNonces`, false→true first write | SOURCE-BACKED FACT (DC-4) | `02-specifications/CIRCLE-DATA-SCHEMAS.md:204-205` | TV-B32-3 | — |
| Attester commitment = `Poseidon2(33-byte pubkey)` → one `Word` (allowlist key, value slot `Word`) | SOURCE-BACKED FACT (DC-3) | `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:46`; `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:25` | TV-ATT-2 | — |

## B. uint256 → AssetAmount (INV-UINT256-TO-ASSETAMOUNT)

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| `AssetAmount(u64)`; `MAX = 2^63 − 2^31 = 9,223,372,034,707,292,160`; `new()` rejects strictly `> MAX` | SOURCE-BACKED FACT (E-7) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:82` | TV-AMT-2, TV-AMT-3 | — |
| Reduction mechanic: byte-swap 8 limbs → assert high 4 limbs zero (`ERR_X_TOO_LARGE`, 2^128 ceiling) → low 4 as u128 → `y=floor(x/10^scale)` → reject/trap if the post-scale quotient exceeds `AssetAmount::MAX` (no saturation or clamping) | SOURCE-BACKED FACT (E-16) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:91` | TV-AMT-1, TV-AMT-4, TV-DUAL-2 | corrected: the mechanic is E-16 (`:91`), NOT E-15 |
| `EthAmount::scale_to_token_amount` (U256 / 10^scale, bounds-check ≤ MAX_AMOUNT) — the reuse precedent | SOURCE-BACKED FACT (E-15) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:90` | IMPL-UINT256-REUSE | E-15 is the precedent, not the mechanic |
| Mechanic + bound also stated in MIDEN-CRYPTO §4.1/§4.2 | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:114-117`,`:119-126` | TV-AMT-1..4 | mechanic body at `:119-126`, bound at `:114-117` |
| Decimal scale-down + reject/trap if the post-scale quotient exceeds `AssetAmount::MAX = 2^63 − 2^31` (no saturation or clamping); the high-6-zero/low-2-into-u64 mechanic is superseded | ARCHITECTURE DECISION (RACD, C-6/DL-8) | `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:63-66`,`:20` | TV-AMT-1..4 | RCC via DEV-5 |
| Same reduced-compare for `amount ≥ maxFee`, `feeAmount ≤ maxFee` | SOURCE-BACKED FACT (CIR-MINT-PRE-8/9) | `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:47`,`:48` | TV-AMT-5 | — |
| D5b reduce step ordering | SOURCE-BACKED FACT | `03-architecture/ARCHITECTURE-FLOWS.md:50` | TV-AMT-1..5 | — |
| Scale to 6 decimals; narrower width permitted with overflow/underflow safeguards | SOURCE-BACKED FACT (CIR-FEE-3) | `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:116`; `02-specifications/CIRCLE-DATA-SCHEMAS.md:221` | TV-AMT-1 | — |
| Never map a uint256 onto one Felt / treat a Felt as a u64 (ASG-7) | ARCHITECTURE DECISION (RACD) | `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:66` | TV-AMT-4 | — |
| Cap value + scale factor + dust tolerance unresolved | CIRCLE-OWNED OPEN (DEV-5/Q-CRY-6) | `02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:44-49` | TV-AMT-6 | `REQUIRES CIRCLE CONFIRMATION` · `NO EVIDENCE OF CIRCLE APPROVAL` | — |
| Reuse AggLayer `EthAmount` vs reimplement | IMPLEMENTATION ASSUMPTION (RIV) | `03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:126`; `../00-foundation/PHASE4-OPEN-DECISIONS.md:84` | TV-DUAL-2 | `REQUIRES IMPLEMENTATION VALIDATION` (IMPL-UINT256-REUSE) | id is foundation-assigned |
| `MC-MINT-3 / GMS-4(G4)` = uint256→AssetAmount reducer | SOURCE-BACKED FACT | `03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:44`; `01-0xMiden-capabilities/MIDEN-GAPS-AND-REQUIRED-WORK.md:24` | TV-AMT-2 | G4 row at `:24` |
| `MC-CR-5` = `uint256` amounts bounded reduction (`uint256→AssetAmount` helper) | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:68` | TV-AMT-1..7, TV-DUAL-2 | added alongside MC-MINT-3 / GMS-4 / G4 (does not replace them); cites E-7/E-8/E-15/E-16, RCC DEV-5 |

## C. AccountId ↔ bytes32 (INV-ACCOUNTID-ENCODING)

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| Protocol/natural form: `AccountId::SERIALIZED_SIZE = 15` bytes = 2 felts (prefix,suffix); the two-felt form fits a `Word` (this is NOT the bytes32 wire packaging) | SOURCE-BACKED FACT (E-9) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:84` | TV-AID-1 | — |
| 15-byte serialization = 8 BE prefix + 7 BE suffix | SOURCE-BACKED FACT (E-10) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:85` | TV-AID-1, TV-AID-2 | — |
| `AddressType::AccountId = 232 = 0b1110_1000` (bech32 string discriminant — NOT part of the bytes32 wire form) | SOURCE-BACKED FACT (E-11) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:86` | TV-AID-3 | — |
| On-chain natural form = the two felts `[prefix, suffix]` directly (no repacking) | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:148-157` (§5), `:152` | TV-AID-4 | — |
| **bytes32 packaging (DEV-10 draft) = R-B / Agglayer-mirroring right-aligned** (`bytes[0..16]=0`, `bytes[16..24]=prefix u64 BE`, `bytes[24..32]=suffix u64 BE`); **supersedes the prior left-aligned 15-byte/trailing-zero bytes32 draft** (2026-06-15); lossless, no keccak fallback (≤32B) | ARCHITECTURE DECISION (RACD, DL-9/MC-CR-6) | `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:21`; `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:69`; Agglayer precedent `protocol/crates/miden-agglayer/src/eth_types/eth_embedded_account_id.rs:117-122` | TV-AID-1..3 | RCC via DEV-10 |
| CIR-HOOK-3 (>32-byte keccak fallback) NOT needed (AccountId 15 bytes) | SOURCE-BACKED FACT | `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:125`; `03-architecture/ARCHITECTURE-TRACEABILITY-MATRIX.md:67` | TV-AID-3 | resolved-no-fallback |
| The >32-byte keccak portability path itself | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:234` | TV-AID-3 (asserts absence) | — |
| Encoding change gated by the S1-NDA L22 approval workflow (CIR-DEPLOY-8) | CIRCLE-OWNED OPEN (DEV-10/Q-CRY-3/4) | `02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:80-85`; `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:22`; `06-resources/CIRCLE_PARTNER_INTEGRATION_GUIDELINES.md:22` | TV-AID-3 | `REQUIRES CIRCLE CONFIRMATION` · `NO EVIDENCE OF CIRCLE APPROVAL` | NDA L22 verbatim confirmed at `:22` |
| AccountId→bytes32 byte-layout draft for Circle approval (current draft = **R-B / Agglayer-mirroring right-aligned**, supersedes left-aligned 2026-06-15) | IMPLEMENTATION ASSUMPTION (RIV) | `03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:127`; `../00-foundation/PHASE4-OPEN-DECISIONS.md:85` | TV-AID-3 | `REQUIRES IMPLEMENTATION VALIDATION` (IMPL-ACCOUNTID-LAYOUT) | id foundation-assigned |

## D. DepositIntent parse (INV-DEPOSITINTENT-PARSE)

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| Fixed 240-byte BE header + variable `hookData`; total `240 + hookDataLen` | SOURCE-BACKED FACT (DC-1) | `02-specifications/CIRCLE-DATA-SCHEMAS.md:13-35` | TV-DI-1, TV-DI-9 | — |
| Field offsets (magic@0 … hookData@240) | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:21-32` | TV-DI-9 | — |
| `magic = 0x5a2e0acd` | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:21` | TV-DI-2 | — |
| `version == 1` | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:22` | TV-DI-3 | — |
| Decoder validation list (magic/version/length/localToken≠0/localDepositor≠0/amount≠0) | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:34-35`; `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:41-50` | TV-DI-2..6 | domain/identifier equality NOT in `:35` (faucet-owned) |
| Per-field preconditions CIR-MINT-PRE-1..11 | SOURCE-BACKED FACT | `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:40-50` | TV-DI-2..6 | PRE-1=`:40` … PRE-11=`:50` |
| D5a parse order (incl. faucet-owned `remoteDomain==self.domain`, `remoteToken==self.identifier`) | SOURCE-BACKED FACT | `03-architecture/ARCHITECTURE-FLOWS.md:49` | faucet TV (domain/identifier); TV-DI-1..6 (library checks) | — |
| 240-byte header = **60 u32-packed felts** (NOT 240/8=30) | SOURCE-BACKED FACT (C-10) | `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:85` | TV-DI-7 | corrected: 60-felt fact is `:85`, NOT E-13 |
| Preimage within the 1024-felt `NoteStorage` bound | SOURCE-BACKED FACT (N-4) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:100` | TV-DI-7 | — |
| `MC-MINT-2 / GMS-2(G2)` = DepositIntent parser capability | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CAPABILITY-MATRIX.md:24`; `03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:42` | TV-DI-1 | — |
| CIR-MINT-PRE traceability (PRE-2..7 → D5a; PRE-8/9 → D5b) | SOURCE-BACKED FACT | `03-architecture/ARCHITECTURE-TRACEABILITY-MATRIX.md:36`,`:37` | TV-DI-2..6, TV-AMT-5 | — |
| hookData cap unresolved (Circle states no max length) | CIRCLE-OWNED OPEN (DEV-6/Q-INFRA-5) | `02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:51-56`; `02-specifications/CIRCLE-DATA-SCHEMAS.md:229` | TV-DI-7 | `REQUIRES CIRCLE CONFIRMATION` · `NO EVIDENCE OF CIRCLE APPROVAL` | — |
| hookData cap value + carrier (inline/attachment/commitment) | IMPLEMENTATION ASSUMPTION (RIV) | `03-architecture/ARCHITECTURE-GAPS-AND-DECISIONS.md:125`; `../00-foundation/PHASE4-OPEN-DECISIONS.md:83` | TV-DI-7 | `REQUIRES IMPLEMENTATION VALIDATION` (IMPL-HOOKDATA-CARRIER) | id foundation-assigned |

## E. Note model (INV-NOTE-MODEL-CURRENT)

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| `NoteType {Private,Public}` only (no `Encrypted`) | SOURCE-BACKED FACT (N-1) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:97` | TV-DI-8, TV-BN-3 | — |
| `NoteStorage{items:Vec<Felt>}` replaces `NoteInputs`; `MAX_NOTE_STORAGE_ITEMS = 1024` | SOURCE-BACKED FACT (N-4) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:100` | TV-DI-7, TV-BN-3 | — |
| Nullifier hashes 6 words (binds storage + attachments) | SOURCE-BACKED FACT (N-7) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:103` | TV-BN-3 | — |
| `NoteAttachments` ≤4 / ≤512 words | SOURCE-BACKED FACT (N-9) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:105` | TV-ATT-1 (sig/pubkey carrier) | — |
| Current note model summary (no `NoteInputs`/`aux`/`Encrypted`/4-word nullifier) | SOURCE-BACKED FACT (C-12) | `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:93-96` | TV-DI-8, TV-BN-3 | — |

## F. Burn-note storage-schema (INV-PUBLIC-BURN-OBSERVABILITY, DC-7)

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| `DC-7` = `XReserveBurnNote` public payload contract; this library owns the deterministic item encode/decode, faucet/listener own lifecycle/observability/validation flow | SOURCE-BACKED FACT | `../00-foundation/PHASE4-DATA-CONTRACTS.md:148-165`; `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:44` | TV-BN-1, TV-DUAL-4 | DC-7; ownership boundary explicit |
| `NoteStorage.items = (amount, destDomain, destRecipient, salt)`; `metadata.sender` = depositor | SOURCE-BACKED FACT | `03-architecture/ARCHITECTURE-COMPONENT-MAP.md:44` | TV-BN-1, TV-BN-2 | DC-7 layout |
| Public burn note; payload in `NoteStorage.items` (not metadata); fixed-tag model | ARCHITECTURE DECISION (RACD, C-3) | `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:48-51` | TV-BN-2, TV-BN-3 | RCC via DEV-2 (faucet/listener-owned) |
| Destination-in-metadata is a prototype shortcut to avoid (ASG-13) | ARCHITECTURE DECISION (guardrail) | `03-architecture/ARCHITECTURE-CLAIM-ADJUDICATION.md:75-90` | TV-BN-2 | prototype bans are in the **architecture** adjudication file |
| Standard `BurnNote` hardcoded `NoteType::Public`, targets `faucet::receive_and_burn` | SOURCE-BACKED FACT (N-11) | `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:107` | TV-BN-1 | — |

## G. Attestation wire-form (INV-DEPOSIT-ATTESTATION-RAW-KECCAK, DC-2)

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| `DC-2` = `depositAttestation` mint-side signature contract; raw 65-byte `r‖s‖v` over `keccak256(full DepositIntent payload)`, not EIP-712/personal-sign, no struct; this library owns the byte→felt packing | SOURCE-BACKED FACT | `../00-foundation/PHASE4-DATA-CONTRACTS.md:62-77`; `02-specifications/CIRCLE-DATA-SCHEMAS.md:39-53` | TV-ATT-1..3, TV-DUAL-5 | DC-2; verify call faucet-owned |
| Signed = `keccak256(full DepositIntent payload)`; raw keccak, NOT EIP-712, NOT personal-sign prefix | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:43-45` | TV-ATT-3 | DC-2 wire form |
| No `depositAttestation` struct — it is the 65-byte signature; message = the payload | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:53` | TV-ATT-3 | — |
| CONFIRMED raw ECDSA, not EIP-712 (adjudication) | SOURCE-BACKED FACT | `02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:27-28`,`:117` | TV-ATT-3 | — |
| Felt shapes: 33-byte pubkey = 9 felts; 32-byte digest = 8 felts; 65-byte sig = 17 felts; `v` carried unused | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:40-42`,`:53-54` | TV-ATT-1 | — |
| `keccak256::hash_bytes` for payload >32 bytes; `verify_prehash(pk,digest,sig)` (faucet-owned) | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CRYPTO-AND-ENCODING.md:40-44`; `03-architecture/ARCHITECTURE-FLOWS.md:52` | faucet TV (D5d) | verify call owned by faucet |
| Deposit single-sig vs quorum unresolved | CIRCLE-OWNED OPEN (Q-DA-QUORUM) | `02-specifications/CIRCLE-DATA-SCHEMAS.md:51` | faucet TV | `REQUIRES CIRCLE CONFIRMATION` | quorum owned by faucet task |

## H. Circle JSON / binary helpers (off-chain)

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| `PrepareBurnIntentInput` request shape (required fields, XOR value, 32-byte hex, domain-differ) | SOURCE-BACKED FACT | `02-specifications/CIRCLE-API-SURFACE.md:129-143` | TV-JSON-1 | — |
| Attestation-fetch response `{payload, messageHash, attestation}` | SOURCE-BACKED FACT | `02-specifications/CIRCLE-API-SURFACE.md:44` | TV-JSON-2 | keccak relation stated at `:43` |
| `WithdrawBatch`: `burnIntents` minItems 1/maxItems 10, `burnSignatures` minItems 2 | SOURCE-BACKED FACT | `02-specifications/CIRCLE-API-SURFACE.md:179-185` | TV-JSON-2 | — |
| JSON `forwardingContractAddress` (20B) vs binary `forwardingContract` (32B, left-padded) — do not conflate | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:144-166`,`:157`,`:162` | TV-JSON-4, TV-BIN-1 | — |
| TransferSpec 340B `0xca85def7`; BurnIntent 72B `0x070afbc2`; WithdrawHookData 112B `0x6b20f62a` | SOURCE-BACKED FACT | `02-specifications/CIRCLE-DATA-SCHEMAS.md:57`,`:63`,`:88`,`:92`,`:127`,`:133` | TV-BIN-1 | — |
| Reconciliation 72+340+112 = 524B + forwardingCalldata | SOURCE-BACKED FACT | `02-specifications/CIRCLE-CLAIM-ADJUDICATION.md:76` | TV-BIN-1 | — |
| Binary reconstruction is OPTIONAL validation only; partner signs `messageHashToSign` as opaque | ARCHITECTURE DECISION (RACD, ASG-5 boundary) | `02-specifications/CIRCLE-DATA-SCHEMAS.md:164`; `02-specifications/CIRCLE-SPECIFICATION.md:105` | TV-BIN-2 | NON-GATING |
| Byte-level JSON→binary transform unresolved | CIRCLE-OWNED OPEN (RCC) | `02-specifications/CIRCLE-DATA-SCHEMAS.md:166` | TV-BIN-2 | `REQUIRES CIRCLE CONFIRMATION` | — |
| OpenAPI documents NO auth scheme; production key out-of-band | CIRCLE-OWNED OPEN (Q-API-AUTH) | `02-specifications/CIRCLE-API-SURFACE.md:19` | TV-JSON-3 | `REQUIRES CIRCLE CONFIRMATION` | mock-fixture safe |

## I. Program-level facts

| Claim | Class | Exact citation (`path:LINE`) | How verified | Status token | Notes |
|---|---|---|---|---|---|
| Pinned baselines — **target Miden v0.15 + devnet** (`07-implementation-readiness/V15-DEVNET-BASELINE.md`): protocol (= miden-base) tag `v0.15.3` (`681fc9058`), miden-vm = **separate `0.23.x` cadence, NOT a v0.15 tag** (VM/assembler crates resolved at `0.23.3` from `miden-vm@v0.23.3`; `V15-DEVNET-BASELINE.md` §1), miden-node released tag `v0.15.0` (`29a876c3`) — **the released TAG is the pin** (`next` equaled the tag at the 2026-06-10 verification but advances and is NOT the pin); deps protocol `0.15.3`, miden-client `origin/next ed94b05d6` (next-commit — still no v0.15 tag; re-pin at builder launch), guardian `c8d54b96` (third-party OpenZeppelin component, **not Miden-versioned**; off the xUSDC critical path — `V15-DEVNET-BASELINE.md` §1); v0.15.3 locks `miden-assembly`/`miden-core-lib` `0.23.3` (v0.15 deps, kept; v0.15.1 historically locked `0.23.1`). Supersedes old `miden-base 0b662adfb` (= `v0.15.0-21`) / retrieval-ref `2c423249d`. | SOURCE-BACKED FACT | `07-implementation-readiness/V15-DEVNET-BASELINE.md`; `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:100`; `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:21-28` | local-node validation pins | — |
| New xUSDC code lives in `miden-base/crates/miden-standards/` | SOURCE-BACKED FACT | `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:100` | `cargo test -p <encoding-crate>` | — |
| Phase 2 verdict TEMP PASS | SOURCE-BACKED FACT | `01-0xMiden-capabilities/MIDEN-CAPABILITIES.md:12` | — | — | — |
| MC-CR-1..7 crypto/encoding traceability | SOURCE-BACKED FACT | `03-architecture/ARCHITECTURE-TRACEABILITY-MATRIX.md:108` | all TV | — |
| No Circle approval observed; every deviation OPEN; nothing closed | CIRCLE-OWNED OPEN (governing) | `02-specifications/CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:6`,`:118` | static sweep 8d | `NO EVIDENCE OF CIRCLE APPROVAL` | — |

---

## J. Citation-correction log (registry/task line vs verified home)

These are the cases where the registry/task attached a fact to a line that carries a *related* statement, and the verification fan-out located the exact home. None is a factual contradiction (no §17 STOP); all facts are confirmed in canonical source.

| Fact | Registry/task said | Verified home | Used in this spec |
|---|---|---|---|
| uint256 byte-swap / high-4-zero / low-4-u128 **mechanic** | E-15/E-16 lumped | E-16 `01-0xMiden-capabilities/MIDEN-EVIDENCE-LEDGER.md:91` | cite E-16 for the mechanic; E-15 (`:90`) for the reuse precedent |
| Poseidon2 hasher / `hash_elements` | "E-3, E-5, E-6" lumped | Poseidon2 = E-6 `:81`; `hash_elements`-before-SMT = E-4 `:79` | cite E-4/E-6 distinctly |
| "60 felts" for the 240-byte header | E-12/E-13 | C-10 `03-architecture/ARCHITECTURE-DECISIONS-AND-CAVEATS.md:85` | cite `:85` for 60; E-12/E-13 for the 4-bytes/felt primitive |
| Prototype-shortcut bans (subset-field, dest-in-metadata, mint-without-supply) | task §3.2 cited CIRCLE-CLAIM-ADJUDICATION.md:75-90 | `03-architecture/ARCHITECTURE-CLAIM-ADJUDICATION.md:75-90` | cite the **architecture** adjudication; the Circle file `:76` carries the 524B reconciliation |
| NDA governance hook cross-reference | task §3.2 cited CIRCLE-SOURCE-LEDGER.md:6,26 | NDA `06-resources/CIRCLE_PARTNER_INTEGRATION_GUIDELINES.md:22`; CIR-DEPLOY-8 `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:22` | cite the NDA `:22` + CIR-DEPLOY-8 directly |
| CMP-A12/A13/A14 ids | ARCHITECTURE-COMPONENT-MAP.md:19-35 | ids assigned in `../00-foundation/PHASE4-COMPONENT-INTERFACE-MATRIX.md:36-38`; descriptive rows at `:30`/`:31`/`:32` | cite both layers distinctly |
| IMPL-* ids | ARCHITECTURE-GAPS-AND-DECISIONS.md:125-127 | ids assigned in `../00-foundation/PHASE4-OPEN-DECISIONS.md:83-85`; decision content at `:125`/`:126`/`:127` | cite both layers distinctly |
| CIR-HOOK-3 row | "find row" | `02-specifications/CIRCLE-REQUIREMENTS-MATRIX.md:125`; `03-architecture/ARCHITECTURE-TRACEABILITY-MATRIX.md:67` | cite `:125`/`:67` |
| CIR-BURN-PRE-4 traceability | task §3.4 cited `:45` | actual row at `03-architecture/ARCHITECTURE-TRACEABILITY-MATRIX.md:49` | not load-bearing for P4-ENCODE; cite `:49` if referenced (holder-balance is faucet-owned) |
