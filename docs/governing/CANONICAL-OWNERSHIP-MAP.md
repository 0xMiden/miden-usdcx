> **Reference document** — adapted from the internal xUSDC spec program; the shipped code and tests in this repo are the source of truth.

# CANONICAL-OWNERSHIP-MAP (GOVERNING — MASM-first)

**Purpose.** One — and only one — owner per shared concept, wire-format, and routine, so builders **conform to the owner instead of re-deriving it**. Re-deriving an owned thing is the defect generalized from an earlier reconciliation: the relayer keeps an off-chain DepositIntent layout that is byte-identical to the canonical 04 owner but not pinned to it, leaving a drift seam.

**MASM-first scope note (read before using this map).** Ownership here is at the **concept/component level**, not the file level. The custom contracts (faucet first) are **hand-written MASM**, so the *encoding contract* (byte offsets, felt packing, cap/scale, hash-to-Word rule) is realized in **two implementations that must agree**:
- **on-chain MASM** inside the faucet / shared MASM module (parse, verify, reduce), and
- **off-chain Rust** inside the relayer/listener/monitor harnesses (encode, decode, pre-validate).

The duplication rule is therefore **per language, plus cross-language conformance**: at most one MASM implementation and at most one Rust implementation of each owned routine, and both must pass the **same shared deterministic test vectors** (single canonical vector home — see Anti-duplication). A second copy *within* a language is a defect; an undocumented divergence *across* languages is the cross-language drift seam.

## Resolved MASM layout
The current faucet account is self-contained under the `xreserve` product-root namespace. It is organized by WIRE FORM rather than by owner: one module per format, each holding that format's constants and the procedures that realize it.

The tree lives beside the Rust that ships it, and every subtree is a declared Miden project assembled at build time.

```
crates/xusdc-encoding/asm/
  xreserve/                       # xUSDC product-root namespace; package `xreserve`, namespace `xreserve`
    miden-project.toml            # the library project: what `mod.masm` is the root of, and what it links against
    attestation_verify.masm       # FAUCET(01): on-chain attestation verify
    attester_admin.masm           # FAUCET(01): attester allowlist administration
    deposit_intent.masm           # Circle's DepositIntent wire form (DC-1, 04-owned layout) + `rebuild`, the faucet's on-chain realization of it (DC-14, 01-owned)
    mint_intent.masm              # What the mint note carries (DC-14): the carried felt offsets, the value widths, and the admissibility checks that hold over the carried fields alone (`validate`, `hash_nonce`, the replay guard + its registry slot)
    mint_policy.masm              # FAUCET(01): active attestation mint policy
    packed_mem.masm               # The layout-agnostic primitives `rebuild` writes the packed wire region with (guarded limb copies, big-endian u64/account-id stores)
    mod.masm                      # FAUCET(01): self-contained component root
  components/
    faucet_extension/faucet_extension.masm  # FAUCET(01): what the faucet adds to the stock fungible faucet — the two `@account_procedure` procs, and nothing else
  notes/                          # one project per note script, each carrying its own MAST
    set_attester/set_attester.masm
```
Owner→path rule: directory path = MASM module path and the Rust component `NAME` must equal it.

**Assembly is build-time and declared.** Each subtree above carries a `miden-project.toml` (the workspace roots under `components/` and `notes/` carry one too). `crates/xusdc-encoding/build.rs` assembles them into `.masp` packages the Rust side embeds, so a MASM error fails `cargo build` and nothing reads the tree at runtime. The note projects link the library **statically**, which is what lets a note script execute without the xreserve package being loaded into the executor; the single `linkage` line in `asm/notes/miden-project.toml` is where that flips to dynamic once the package can be distributed.

**Logical owner ≠ physical parent, and it is no longer a directory boundary either:** the `encoding/` submodule is gone. 04 still owns the wire *layouts* — the DC-1 offsets and the DC-14 carried shape — and the shared codecs; 01 owns the procedures that realize them. They now share two files, one per wire form, because a constant and the single procedure that writes at it are read together and drifted apart when they were not.

**Layout decision:** assemble a single **self-contained** component `.masm`; builders implement the self-contained layout.

**Slot-binding convention.** The self-contained single-install xUSDC faucet may hard-code its own storage slot via `push.<SLOT_CONST>[0..2]`, source-backed by the stock faucet's `TOKEN_CONFIG_SLOT[0..2]` pattern. The #2927 `decouple-component-from-storage` parameterized-slot rule applies only to procs intended for multi-install reuse.

## Canonical owners (concept/component level)

| Owned thing (DC-id) | Canonical owner (concept) | On-chain MASM home (per §Resolved layout) | Off-chain Rust home | Conformance source of truth |
|---|---|---|---|---|
| `bytes32 → Word` hash-to-Word, Poseidon2 over 8×u32-LE (DC-3 commitment / DC-4 nonce key) | **shared-encoding (04)** (hash) + **faucet (01)** (nonce-registry & allowlist stores) | `crates/xusdc-encoding/asm/xreserve/mint_intent.masm` → **`xreserve::mint_intent::hash_nonce`** | harness encode helper | `INV-BYTES32-HASH-TO-WORD`; DC-4; DC-3 |
| `uint256 → AssetAmount` conversion (DC-5) | **the protocol standards** (`EthAmount::scale_to_asset_amount`), consumed by **shared-encoding (04)** | **Rust-only.** The MASM witness verifier is removed — see the rider below | `crates/xusdc-encoding/src/xreserve/encoding/amount.rs` → `uint256_to_asset_amount`, which adapts the standards routine to this crate's error type and holds the golden vectors | `DC-5`; `INV-UINT256-TO-ASSETAMOUNT` |
| ↳ **MASM side removed (human-directed).** Under DC-14 the faucet writes the amount into the preimage from the note's own asset value, so no untrusted witness reaches the chain and nothing called `verify_uint256_to_asset_amount`. It was previously retained against a non-zero `DEPOSIT_SCALE_EXP` (DEV-5, OPEN); it is now deleted, along with `TV-DUAL-2` and the local `ERR_FELT_OUT_OF_FIELD`. **Reopening DEV-5 means restoring it from history**, together with a transport that carries the uint256 again — the reduction is not expressible on-chain without both. The Rust side keeps all its callers, and the division itself is now the standards' `EthAmount::scale_to_asset_amount` rather than a second copy of it here. | — | — | — | `DC-5`; `DEV-5` |
| `AccountId ↔ bytes32` (protocol form 15-byte/two-felt; right-aligned bytes32 packaging; lossless, no keccak fallback) (DC-6) | **shared-encoding (04)** (the decode) + the protocol (the stock `EthEmbeddedAccountId` encode, called directly) | Rust-primary: no MASM proc in the 04 slice | `crates/xusdc-encoding/src/xreserve/encoding/account_id.rs` | `DC-6`; `INV-ACCOUNTID-ENCODING` |
| `DepositIntent` 240-byte header = 60 u32-LE felts + hookData (DC-1) | **shared-encoding (04)** owns the layout constants; **faucet (01)** owns the on-chain realization | layout and realization both in `crates/xusdc-encoding/asm/xreserve/deposit_intent.masm`: `xreserve::deposit_intent::rebuild` (write side, DC-14) — the read-side parser is retired, see NS-2/NS-3 | Rust mirror keeps `DepositIntent`'s `Serializable` / `Deserializable` pair, plus the `TryFrom<&[u8]>` typed decode the relayer's pre-validate takes | `DC-1`; `INV-DEPOSITINTENT-PARSE`; `TV-DUAL-3` |
| **DepositIntent reconstruction from the carried mint intent; the mint-intent wire shape (DC-14)** | **faucet (01)** owns the writer and the carried shape (both are mint-transport concerns and the writer reads faucet state); **shared-encoding (04)** owns the felt offsets it writes at | `crates/xusdc-encoding/asm/xreserve/deposit_intent.masm` → `xreserve::deposit_intent::rebuild`; the carried offsets in `mint_intent.masm` | `crates/xusdc-encoding/src/xreserve/encoding/mint_intent.rs` → `MintIntent::{from_deposit_intent, to_deposit_intent, to_elements, from_elements}` (the bytes come from `DepositIntent`'s `Serializable`, which owns them; the narrowing to domain types happens once, in the decode) | `DC-14`; `TV-DUAL-6` (the round-trip and MASM/Rust preimage-parity rows) |
| `depositAttestation` wire (raw secp256k1 over `keccak256(payload)`; NOT EIP-712) (DC-2) | **shared-encoding (04)** owns the merged-transport staging/felt-packing; **faucet (01)** owns the on-chain verify | verify: `crates/xusdc-encoding/asm/xreserve/attestation_verify.masm` | relayer transport + Rust packing helpers | `DC-2`; `INV-DEPOSIT-ATTESTATION-RAW-KECCAK`; `TV-DUAL-5` |
| pubkey commitment + allowlist key (`Poseidon2` over staged pubkey felts → `Word`) (DC-3) | **shared-encoding (04)** (commitment hash) + **faucet (01)** (the on-chain `StorageMap` store) | commitment `xreserve::attestation_verify::pubkey_commitment`; store `crates/xusdc-encoding/asm/xreserve/attester_admin.masm` | the protocol's own `ecdsa_k256_keccak::PublicKey` (`to_elements` / `to_commitment`) — pinned by reference, not mirrored | `DC-3`; `TV-DUAL-5` |
| `XReserveBurnNote` item codec `(amount,destDomain,destRecipient,salt)` (DC-7) | **shared-encoding (04)** owns the codec; **faucet (01)** owns note production/consumption policy | no MASM codec; carried in a scheme-tagged note attachment (felt count, field offsets, scheme, word count and slot order: `DC-7` in `docs/spec/GLOSSARY.md`); the faucet uses the stock burn consume script | `crates/xusdc-encoding/src/xreserve/encoding/burn_note.rs`; listener decode | `DC-7`; `INV-PUBLIC-BURN-OBSERVABILITY` |
| Circle JSON schema types (DC-9/10/11/12) | **shared-encoding (04)** (type defs) | n/a (off-chain only) | relayer, listener, monitor | `DC-9..DC-12` |
| optional Circle binary decode (DC-13) | **shared-encoding (04)** (optional, NON-GATING) | n/a | listener (optional) | `DC-13` |
| burn-evidence package assembly (`burnTxId`+`note_id`+`nullifier`+`block_num`; proof-strength labels) (DC-8) | **listener (03)** | n/a | listener | `DC-8`; `INV-BURN-EVIDENCE-TRUST` |
| attestation mint policy, mint assertions, attester admin, note factories, faucet account composition | **faucet (01)** — hand-written MASM plus Rust builder/harness code | `crates/xusdc-encoding/asm/xreserve/*.masm` + notes `crates/xusdc-encoding/asm/notes/*/` | `crates/xusdc-encoding` account/note builder APIs | the faucet spec; `INV-MINT-*`/`INV-*BURN*` |
| supply/monitoring, admin SOPs, upgrade-governance | **monitoring (05)** | n/a (off-chain/ops) | monitor | off-chain/ops component (not in this repo) |

## Anti-duplication rule (preserved, MASM-aware — mechanical, not prose)
- Each owned routine: **≤ 1 MASM implementation** and **≤ 1 Rust implementation**, both conforming to the column-5 source of truth. A second within-language copy fails the duplication scan even if byte-identical.
- **Shared test vectors have ONE canonical home (owner = shared-encoding 04).** The golden vectors (input → expected bytes/felts, incl. cap-boundary/limb-overflow edges) live in a single artifact under 04; BOTH the MASM-side test and the Rust-side test load them **by reference**, not as hand-copied tables. A duplicate vector table outside that home fails the G1 duplication scan, same as a duplicate routine. The dual-implementation harness already pins this (the `TV-DUAL-*` cross-implementation vectors).
- **The off-chain Rust mirror must pin to the 04 owner, not re-derive it.** Per an earlier reconciliation's remediation, the relayer's DepositIntent decoder **returns the 04 `DepositIntent` type itself, decoded by 04's own `Deserializable`** OR carries an explicit lockstep-pin reference to 04 (owner `04:341-345,:388`) — a byte-identical independent copy fails G1 even if it passes its own local vectors.
- **Cross-language constants follow `masm-rust-constant-parity` — single source of truth.** Prefer defining DC-1 layout offsets, packed magic `0x5a2e0acd`, and DC-5 cap/scale in MASM and generating Rust counterparts through `build.rs`; where hand-duplicated, both sides must change together and pass canonical vectors.
- A new shared concept/boundary must be **added to this map first** (human re-approves) — no silent new shared shapes.
- **DC-14 vector exception, recorded here so it is not read as a G1/G4 violation.** The reconstructed preimage embeds the faucet's own account id, and an account id is a hash over the account's code — which, in a shell test, includes the test driver. The expected felts are therefore not knowable when the artifact is generated. The canonical artifact carries the DC-14 rows (`carried_felts`, `rebuilt_preimage_felts`) for **one fixed synthetic faucet id and domain**, and both sides load and execute those by reference as usual. The live-account tests, which cannot use them, check the MASM writer against the **Rust mirror as an oracle** instead. That is a deliberate mixed posture for exactly one owned thing, not a second vector home.

## Naming decisions

The decisions below are binding:

| # | Owner-04 side (normative per `04:210` "MASM procedure names follow `xreserve::encoding::<name>`") | Consumer/faucet-01 side | Bound test rows |
|---|---|---|---|
| NS-1 (bytes32, DC-3/DC-4) — **amended three times** | `xreserve::mint_intent::hash_nonce` | The path moved with the `encoding` module and again with the nonce it hashes, and the name became a verb for what it does; the routine, its body and its owner did not change. Rust keeps `bytes32_to_storage_map_key`; do not add a MASM alias. | TV-DUAL-1 |
| NS-2 (DepositIntent parse, DC-1) | ~~`xreserve::deposit_intent_parser::parse`~~ — **retired, superseded by NS-3** | 01 owns the only MASM realization; 04 owns the layout and shared primitives. The Rust `DepositIntent` decode is **unaffected**. | TV-DUAL-3 |
| NS-3 (DepositIntent write, DC-1/DC-14) | `xreserve::deposit_intent::rebuild` | 01 owns the only MASM realization of the DepositIntent wire form; 04 owns the felt offsets it writes at. Rust: `MintIntent::to_deposit_intent` (the bytes are then `DepositIntent`'s own `Serializable`). Do not add a MASM alias, and do not reintroduce a second parser. | TV-DUAL-6 |

**NS-2 retirement — the adjudication.** NS-2 froze the *name* of the on-chain DepositIntent parser
on the premise that the faucet reads the wire form. Under DC-14 the faucet **writes** it instead, so
there is no parser left to name: every field `parse` compared is now either written by the faucet or
proven by the signature over what the faucet wrote. Retiring NS-2 is therefore not a naming split
between two live implementations — the condition G5 makes a STOP — but the removal of one side of
the contract. NS-3 replaces it with the same single-owner discipline on the write side. What NS-2
actually protected, *one MASM realization of the DepositIntent wire form owned by 01*, is preserved
verbatim.

The parser file is gone with the parser. Its two surviving preconditions — the fee ceiling and the
replay guard — are statements about the CARRIED fields rather than the message, so they live in
`mint_intent.masm` as the single `validate` entry the mint policy runs before `rebuild`. The policy
therefore admits an intent and then rebuilds a message from it, rather than running a pile of stages
in the right order.

## MASM Module Realization

**Source-proven constraint:** the pinned Miden assembler treats `mod.masm` as the directory-module root; any other file `<name>.masm` is its own submodule, and its exported paths carry that segment. That is what the flat `xreserve::encoding::<proc>` naming used to fight; the tree is now one module per wire form directly under `xreserve/`, so every exported path already reads the way it is named and no re-export wrapper is needed (they remain banned — G1, "wrappers that merely re-expose an owned routine also fail").

**Binding realization rules (empirically validated by `probe_p1_exports`, 37/37 green):**
1. One module per WIRE FORM, directly under `crates/xusdc-encoding/asm/xreserve/`. A procedure lives with the format it reads or writes, and so do that format's constants.
2. Do NOT reintroduce a nesting directory to group by owner. Ownership is a column in the table above, not a path segment; the previous `encoding/` split put a constant and its single writer in different files and they drifted.
3. Do NOT create per-proc modules (`bytes32.masm`, `uint256.masm`, …) unless the human explicitly changes the canonical name to a nested one.
4. Conceptual/routine ownership in the table above is unchanged — this section governs only physical module realization.

## Non-negotiables
- Every supply increase passes the active attestation mint policy; stock `mint_and_send` supplies the transport/effects path.
- No `ecrecover`: verify against a supplied candidate pubkey + commitment allowlist.
- Public burn note (`NoteType::Public`) + fixed full-32-bit tag; two-block create→consume.
- `burnTxId` linkage is **node-trusted** unless the optional full-block path runs (`DEV-7`, highest-risk, Circle-gated).
- xUSDC is **not** the chain fee token (MVP).
- Every Circle-owned `DEV-*`/`Q-*` stays **OPEN** — this map approves nothing Circle-owned.
