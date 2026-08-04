> **Reference document** — adapted from the internal xUSDC spec program; the shipped code and tests in this repo are the source of truth.

# CANONICAL-OWNERSHIP-MAP (GOVERNING — MASM-first)

**Purpose.** One — and only one — owner per shared concept, wire-format, and routine, so builders **conform to the owner instead of re-deriving it**. Re-deriving an owned thing is the defect generalized from an earlier reconciliation: the relayer keeps an off-chain DepositIntent layout that is byte-identical to the canonical 04 owner but not pinned to it, leaving a drift seam.

**MASM-first scope note (read before using this map).** Ownership here is at the **concept/component level**, not the file level. The custom contracts (faucet first) are **hand-written MASM**, so the *encoding contract* (byte offsets, felt packing, cap/scale, hash-to-Word rule) is realized in **two implementations that must agree**:
- **on-chain MASM** inside the faucet / shared MASM module (parse, verify, reduce), and
- **off-chain Rust** inside the relayer/listener/monitor harnesses (encode, decode, pre-validate).

The duplication rule is therefore **per language, plus cross-language conformance**: at most one MASM implementation and at most one Rust implementation of each owned routine, and both must pass the **same shared deterministic test vectors** (single canonical vector home — see Anti-duplication). A second copy *within* a language is a defect; an undocumented divergence *across* languages is the cross-language drift seam.

## Resolved MASM layout
The current faucet account is self-contained under the `xreserve` product-root namespace. The shared-encoding library declares the canonical `xreserve::encoding::<name>` procedures, and the faucet consumes them by that path.

```
asm/standards/
  xreserve/                       # xUSDC product-root namespace
    attestation_verify.masm       # FAUCET(01): on-chain attestation verify
    attester_admin.masm           # FAUCET(01): attester allowlist administration
    deposit_intent_parser.masm    # FAUCET(01): DepositIntent parser and mint validation
    identifier_init.masm          # FAUCET(01): init-once identifier fixpoint
    mint_policy.masm              # FAUCET(01): active attestation mint policy
    mod.masm                      # FAUCET(01): self-contained component root
    encoding/                     # SHARED-ENCODING(04)-OWNED sub-module → xreserve::encoding::*
      mod.masm                    #   04: flat public procs live here
      layout.masm                 #   04: DepositIntent felt offsets + packed magic constant (DC-1) — constants submodule (path xreserve::encoding::layout::* intentional for constants)
  notes/
    xreserve_identifier_init_note.masm
    xreserve_set_attester_note.masm
    xreserve_set_max_supply_note.masm
    xreserve_set_min_burn_size_note.masm
```
Owner→path rule: directory path = MASM module path and the Rust component `NAME` must equal it. **Logical owner ≠ physical parent:** 04 owns `xreserve::encoding::*` even though it sits under the `xreserve` product root; the faucet(01) owns the parser/attestation *assertion* logic but consumes 04's `encoding/layout.masm` constants.

**Layout decision:** assemble a single **self-contained** component `.masm`; builders implement the self-contained layout.

**Slot-binding convention.** The self-contained single-install xUSDC faucet may hard-code its own storage slot via `push.<SLOT_CONST>[0..2]`, source-backed by the stock faucet's `TOKEN_CONFIG_SLOT[0..2]` pattern. The #2927 `decouple-component-from-storage` parameterized-slot rule applies only to procs intended for multi-install reuse.

## Canonical owners (concept/component level)

| Owned thing (DC-id) | Canonical owner (concept) | On-chain MASM home (per §Resolved layout) | Off-chain Rust home | Conformance source of truth |
|---|---|---|---|---|
| `bytes32 → Word` hash-to-Word, Poseidon2 over 8×u32-LE (DC-3 commitment / DC-4 nonce key) | **shared-encoding (04)** (hash) + **faucet (01)** (nonce-registry & allowlist stores) | `asm/standards/xreserve/encoding/mod.masm` → **`xreserve::encoding::bytes32_to_key`** | harness encode helper | `INV-BYTES32-HASH-TO-WORD`; DC-4; DC-3 |
| `uint256 → AssetAmount` conversion (Rust floor-divides; MASM verifies the supplied witness) (DC-5) | **shared-encoding (04)** | `asm/standards/xreserve/encoding/mod.masm` → `xreserve::encoding::verify_uint256_to_asset_amount` | Rust `uint256_to_asset_amount` witness generator | `DC-5`; `INV-UINT256-TO-ASSETAMOUNT` |
| `AccountId ↔ bytes32` (protocol form 15-byte/two-felt; right-aligned bytes32 packaging; lossless, no keccak fallback) (DC-6) | **shared-encoding (04)** | Rust-primary: no MASM proc in the 04 slice | `crates/xusdc-encoding/src/xreserve/encoding/account_id.rs` | `DC-6`; `INV-ACCOUNTID-ENCODING` |
| `DepositIntent` 240-byte header = 60 u32-LE felts + hookData (DC-1) | **shared-encoding (04)** owns the layout constants; **faucet (01)** owns the on-chain parser and mint assertions | layout: `asm/standards/xreserve/encoding/layout.masm`; parser: `xreserve::deposit_intent_parser::parse` | Rust mirror keeps `parse_deposit_intent_header` | `DC-1`; `INV-DEPOSITINTENT-PARSE`; `TV-DUAL-3` |
| `depositAttestation` wire (raw secp256k1 over `keccak256(payload)`; NOT EIP-712) (DC-2) | **shared-encoding (04)** owns the staging/felt-packing; **faucet (01)** owns the on-chain verify | verify: `asm/standards/xreserve/attestation_verify.masm` | relayer transport + Rust packing helpers | `DC-2`; `INV-DEPOSIT-ATTESTATION-RAW-KECCAK`; `TV-DUAL-5` |
| pubkey commitment + allowlist key (`Poseidon2` over staged pubkey felts → `Word`) (DC-3) | **shared-encoding (04)** (commitment hash) + **faucet (01)** (the on-chain `StorageMap` store) | commitment via `xreserve::encoding::bytes32_to_key` in `encoding/mod.masm`; store `asm/standards/xreserve/attester_admin.masm` | Rust packing and commitment helpers | `DC-3`; `TV-DUAL-5` |
| `XReserveBurnNote` item codec `(amount,destDomain,destRecipient,salt)` (DC-7) | **shared-encoding (04)** owns the codec; **faucet (01)** owns note production/consumption policy | no MASM codec; the faucet uses the stock burn consume script | `crates/xusdc-encoding/src/xreserve/encoding/burn_note.rs`; listener decode | `DC-7`; `INV-PUBLIC-BURN-OBSERVABILITY` |
| Circle JSON schema types (DC-9/10/11/12) | **shared-encoding (04)** (type defs) | n/a (off-chain only) | relayer, listener, monitor | `DC-9..DC-12` |
| optional Circle binary decode (DC-13) | **shared-encoding (04)** (optional, NON-GATING) | n/a | listener (optional) | `DC-13` |
| burn-evidence package assembly (`burnTxId`+`note_id`+`nullifier`+`block_num`; proof-strength labels) (DC-8) | **listener (03)** | n/a | listener | `DC-8`; `INV-BURN-EVIDENCE-TRUST` |
| attestation mint policy, mint assertions, attester admin, identifier init, note factories, faucet account composition | **faucet (01)** — hand-written MASM plus Rust builder/harness code | `asm/standards/xreserve/*.masm` + notes `asm/standards/notes/xreserve_*_note.masm` | `crates/xusdc-encoding` account/note builder APIs | the faucet spec; `INV-MINT-*`/`INV-*BURN*` |
| supply/monitoring, admin SOPs, upgrade-governance | **monitoring (05)** | n/a (off-chain/ops) | monitor | off-chain/ops component (not in this repo) |

## Anti-duplication rule (preserved, MASM-aware — mechanical, not prose)
- Each owned routine: **≤ 1 MASM implementation** and **≤ 1 Rust implementation**, both conforming to the column-5 source of truth. A second within-language copy fails the duplication scan even if byte-identical.
- **Shared test vectors have ONE canonical home (owner = shared-encoding 04).** The golden vectors (input → expected bytes/felts, incl. cap-boundary/limb-overflow edges) live in a single artifact under 04; BOTH the MASM-side test and the Rust-side test load them **by reference**, not as hand-copied tables. A duplicate vector table outside that home fails the G1 duplication scan, same as a duplicate routine. The dual-implementation harness already pins this (the `TV-DUAL-*` cross-implementation vectors).
- **The off-chain Rust mirror must pin to the 04 owner, not re-derive it.** Per an earlier reconciliation's remediation, the relayer's DepositIntent decoder **re-exports the 04 serde / `parse_deposit_intent_header` model** OR carries an explicit lockstep-pin reference to 04 (owner `04:341-345,:388`) — a byte-identical independent copy fails G1 even if it passes its own local vectors.
- **Cross-language constants follow `masm-rust-constant-parity` — single source of truth.** Prefer defining DC-1 layout offsets, packed magic `0x5a2e0acd`, and DC-5 cap/scale in MASM and generating Rust counterparts through `build.rs`; where hand-duplicated, both sides must change together and pass canonical vectors.
- A new shared concept/boundary must be **added to this map first** (human re-approves) — no silent new shared shapes.

## Naming decisions

The decisions below are binding:

| # | Owner-04 side (normative per `04:210` "MASM procedure names follow `xreserve::encoding::<name>`") | Consumer/faucet-01 side | Bound test rows |
|---|---|---|---|
| NS-1 (bytes32, DC-3/DC-4) | `xreserve::encoding::bytes32_to_key` | Rust keeps `bytes32_to_storage_map_key`; do not add a MASM alias. | TV-DUAL-1 |
| NS-2 (DepositIntent parse, DC-1) | `xreserve::deposit_intent_parser::parse` | 01 owns the only MASM parser; 04 owns the layout and shared primitives. | TV-DUAL-3 |

## MASM Module Realization

**Source-proven constraint:** the pinned Miden assembler treats `mod.masm` as the directory-module root; any other file `<name>.masm` is its own submodule. Therefore a per-file home like `encoding/bytes32.masm` can only export `xreserve::encoding::bytes32::bytes32_to_key` — NOT the frozen flat path — and a re-export wrapper is banned (NS-1; G1 "wrappers that merely re-expose an owned routine also fail").

**Binding realization rules (empirically validated by `probe_p1_exports`, 37/37 green):**
1. Any public proc whose CANONICAL path is flat `xreserve::encoding::<proc>` has its body in **`asm/standards/xreserve/encoding/mod.masm`**.
2. Support submodules (e.g. `layout.masm`) are allowed when their exported path INTENTIONALLY includes the submodule segment (constants/helpers consumed from the root).
3. Do NOT create per-proc `bytes32.masm` / `uint256.masm` / `account_id.masm` / `burn_items.masm` for flat public proc paths unless the human explicitly changes the canonical name to a nested one.
4. Conceptual/routine ownership in the table above is unchanged — this section governs only physical module realization.

## Non-negotiables
- Every supply increase passes the active attestation mint policy; stock `mint_and_send` supplies the transport/effects path.
- No `ecrecover`: verify against a supplied candidate pubkey + commitment allowlist.
- Public burn note (`NoteType::Public`) + fixed full-32-bit tag; two-block create→consume.
- `burnTxId` linkage is **node-trusted** unless the optional full-block path runs (`DEV-7`, highest-risk, Circle-gated).
- xUSDC is **not** the chain fee token (MVP).
- Every Circle-owned `DEV-*`/`Q-*` stays **OPEN** — this map approves nothing Circle-owned.
