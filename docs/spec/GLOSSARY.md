# Identifier glossary

This file defines every short identifier that appears in this repository's code comments,
documentation, and test names. The identifiers are stable anchors: a numbered
requirement (`R-MINT-15`), a named invariant (`INV-MINT-SECURITY`), a mint pipeline stage
(`D5c`), or an open question that is still owned by Circle (`DEV-10`). Comments keep them
only where the anchor is genuinely useful — for example, a reject condition that a test
asserts on by name. **The prose around an anchor always stands on its own; the anchor is a
label, not a pointer you must follow to understand the code.** This file is the single place
those labels are defined.

The identifiers originate in an off-chain planning/spec program that is *not* part of this
repository. That program is the historical source of the design; it is not needed to read,
build, audit, or run the code here.

Terminology note: **xUSDC** is Circle's xReserve stablecoin on Miden (native USDC stays
locked 1:1 in Circle's xReserve contract on the source chain; this repo is the Miden side).
A **DepositIntent** is the Circle-attested message authorizing a mint; an
**`XReserveBurnNote`** is the public note a holder creates to withdraw. **DOM_PAUSER** /
**DOM_MANAGER** are the two on-chain admin roles.

---

## Mint reject conditions — `R-MINT-<n>`

Numbered conditions the mint path enforces; a violation traps the transaction with no state
change. Several are asserted on by name in the tests. `R-MINT-1..8` are the structural /
addressing checks of stage `D5a`; `R-MINT-9..11` the amount/fee checks of `D5b`; `R-MINT-12`
the replay check of `D5c`; `R-MINT-13..14` the attestation checks of `D5d`; `R-MINT-15` the
supply-cap check of `D5e`; `R-MINT-16` the deny of the stock mint path.

| Id | Condition enforced |
|---|---|
| R-MINT-1 | DepositIntent `magic` matches the expected constant. |
| R-MINT-2 | DepositIntent `version` matches the supported version (1). |
| R-MINT-3 | `amount` field is non-zero. |
| R-MINT-4 | `localToken` field is non-zero. |
| R-MINT-5 | `localDepositor` field is non-zero. |
| R-MINT-6 | DepositIntent `remoteDomain` equals the faucet's configured domain. |
| R-MINT-7 | DepositIntent `remoteToken` (hashed to a key) equals the faucet's configured identifier key. |
| R-MINT-8 | Total preimage length equals `240 + hookDataLen` (header + hookData). |
| R-MINT-9 | Reduced `amount`/`maxFee`/`feeAmount` fit ≤ 2^128 (high four limbs zero) — else "too large". |
| R-MINT-10 | Reduced `amount ≥ maxFee`. |
| R-MINT-11 | Reduced `feeAmount ≤ maxFee` (in the MVP this is subsumed by the fee-must-be-zero gate). |
| R-MINT-12 | The DepositIntent `nonce` has not been used before (replay guard). |
| R-MINT-13 | The attester's pubkey commitment is enabled in the `xReserveAttesters` allowlist. |
| R-MINT-14 | The ECDSA signature verifies over `keccak256(payload)` for that pubkey. |
| R-MINT-15 | `token_supply + amount ≤ max_supply` and `max_supply ≤ AssetAmount::MAX` (supply cap). |
| R-MINT-16 | The stock `mint_and_send` path is denied — only the custom `xreserve_mint` may raise supply. |

## Burn reject conditions — `R-BURN-<n>`

| Id | Condition enforced |
|---|---|
| R-BURN-1 | Burn `amount > 0`. |
| R-BURN-2 | Burn `amount ≥ minBurnSize` (the configured floor). |
| R-BURN-3 | A paused faucet halts the burn (enforced by the stock burn-policy wrapper before the custom policy runs). |
| R-BURN-4 | A same-block create+consume erases the burn note (no inclusion proof / store record), so it is unverifiable — the design requires a two-block burn. |
| R-BURN-5 | A burn note cannot be created for more than the holder's balance (checked at note *creation*, when the asset leaves the vault). |
| R-BURN-6 | The `XReserveBurnNote` is always Public (never Private), so its payload is observable. |

## Admin reject conditions — `R-ADMIN-<n>`

| Id | Condition enforced |
|---|---|
| R-ADMIN-1 | `set_attester` is owner-gated (a non-owner sender is rejected). |
| R-ADMIN-2 | `set_min_burn_size` is owner-gated. |
| R-ADMIN-3 | `pause` / `unpause` require the `DOM_PAUSER` role. |
| R-ADMIN-4 | Domain config is init-once: a second `domain_init` traps. |

## Mint pipeline stages — `D5a`–`D5e`

The `xreserve_mint::mint` procedure runs a verify-once-then-write-once pipeline. `D5a`–`D5d`
verify; `D5e` writes. Any verify/extraction trap aborts the whole transaction, so a failed
mint performs no writes (in particular it never consumes the nonce).

| Stage | What it does |
|---|---|
| D5a | Structural parse + domain/identifier compares (`assert_deposit_intent`). |
| D5b | `amount` / `maxFee` / `feeAmount` reduction and bounds (`assert_mint_amounts`). |
| D5c | Nonce replay guard, assert-zero only (`assert_nonce_unused`). |
| D5d | Attestation verify: keccak the payload, allowlist gate, ECDSA verify (`verify_attestation`). |
| D5e | Atomic mint effects: supply-cap guard, nonce SET, P2ID recipient note, `token_supply += amount` (`apply_mint_effects`). |

## Component slices — `CMP-<x>`

Labels for the faucet's functional pieces (originally built as incremental slices). They name
*what* the piece is; the code that implements each lives where the comment sits.

| Id | Component |
|---|---|
| CMP-A5 | On-token transfer policy — deliberately **not** wired (xUSDC ships as a basic, transfer-policy-free asset; see IMPL-DEV-20 in this file and DEV items below). |
| CMP-A6 | `XReserveDomainConfig` — the faucet's domain-config fields (`domain`, `source_domain`, `xreserve_contract`, `identifier`). |
| CMP-A9 | The mint supply-increasing surface (`apply_mint_effects`) — the only place `token_supply` rises. |
| CMP-A10 | The burn security policy (`burn_policy::check_policy`), run on every `receive_and_burn`. |
| CMP-A15 | `XReserveStablecoinBuilder` — the Rust builder that composes the full faucet account and rejects an invalid wiring (e.g. no deny guard, non-Public faucet) at build time. |
| CMP-B1 | The `XReserveMintNote` script + account-side transport shim (`receive_and_mint`). |
| CMP-B2 | `XReserveBurnNote` construction (the public withdrawal note). |
| CMP-B3 | `receive_and_burn` consumption of the burn note. |
| CMP-F2 | The owner-gated `set_min_burn_size` setter. |
| CMP-F3 | The custom `DOM_PAUSER`-gated pause/unpause. |
| CMP-F5 | Role management (role-based access control): `grant_role`/`revoke_role` membership rotation (CIR-ADMIN-3) plus the BUILD-SEEDED `DOM_PAUSER.admin_role = DOM_MANAGER` delegation. The runtime `set_role_admin` note was REMOVED from the note-script allowlist (S21 disposition flip, human-ratified 2026-07-14) — the delegation graph deploys frozen at the seed; see IMPL-DEV-24. |

## Invariants — `INV-<name>`

Security/correctness properties the faucet must uphold. The faucet-binding ones:

| Invariant | Property |
|---|---|
| INV-MINT-SECURITY | `xreserve_mint` is the **only** supply-increasing surface, gated by an allowlisted-attester signature; the stock `mint_and_send` path is a deny guard. |
| INV-SUPPLY-CONSERVATION | `token_supply += amount` exactly once per mint and `-= amount` once per burn. |
| INV-NONCE-REPLAY | `usedNonces` is keyed by a Poseidon2 hash-to-Word of the nonce; assert-zero-then-set; replays are rejected. |
| INV-PUBLIC-BURN-OBSERVABILITY | The burn note is Public, with its payload in `NoteStorage.items` and a fixed 32-bit tag. |
| INV-TWO-BLOCK-BURN | A burn note is created in block N and consumed in block ≥ N+1; a same-block create+consume is erased. |
| INV-NO-ECRECOVER | No key recovery on-chain; ECDSA is verified against a supplied candidate pubkey + commitment allowlist. |
| INV-DEPOSITINTENT-PARSE | Fixed-offset 240-byte header = 60 u32-LE-packed felts plus hookData; all field asserts; note input is read-only. |
| INV-UINT256-TO-ASSETAMOUNT | uint256 reduction: assert the high half is zero, floor-divide by 10^scale, cap at `AssetAmount::MAX`; trap, never saturate. |
| INV-BYTES32-HASH-TO-WORD | bytes32 → Word via Poseidon2 `hash_elements` over the 8 u32-LE limbs (the raw fallible `TryFrom` is not used on this path). |
| INV-DEPOSIT-ATTESTATION-RAW-KECCAK | Raw secp256k1 ECDSA over `keccak256(full payload)`, 65-byte `r‖s‖v`, `v` unused; not EIP-712. |
| INV-ACCOUNTID-ENCODING | AccountId ↔ bytes32 is lossless with a fail-closed decode; reject any non-zero byte in the leading pad. |
| INV-PAUSE | Pause halts both the mint and the burn-consume paths (each dispatch asserts not-paused). |
| INV-VAULT-MODEL | Balances use Miden's vault model; per-holder balances are private, only `token_supply` and per-burn notes are public. |

(Off-chain units own further `INV-*` — e.g. `INV-BURN-EVIDENCE-TRUST`, `INV-OFFCHAIN-BURN-SIGNING` — which do not appear in this repo's on-chain code.)

## Anti-simplification gates — `ASG-<n>`

"Do not simplify away X" guardrails; each names a shortcut the implementation must **not**
take. The ones referenced in this repo:

| Gate | Guardrail |
|---|---|
| ASG-1 | Do not allow minting via the stock `mint_and_send` (a deny guard must be wired). |
| ASG-12 | Do not verify only a field subset — keccak the full payload and assert every field. |
| ASG-13 | Do not put the burn destination in note metadata — the payload goes in `NoteStorage.items`; `metadata.sender` carries only the depositor. |
| ASG-14 | Prove the sole-supply-surface property at the procedure-root level, not by asserting `faucet::mint` alone. |
| ASG-16 | Do not compute the header felt count as 240/8 = 30 — it is 60 u32-LE-packed felts. |
| ASG-17 | Do not use `NoteInputs`/`aux`/an Encrypted note/a 4-word nullifier — target the current note model (`NoteStorage` ≤ 1024 felts, {Private,Public}, 6-word nullifier). |

## Shared-encoding data contracts — `DC-<n>`

Codec decisions owned by the `xusdc-encoding` crate (`xreserve::encoding`).

| Id | Decision |
|---|---|
| DC-1 | DepositIntent wire format: fixed 240-byte big-endian header + variable `hookData`; on-chain = 60 u32-LE-packed felts (4 bytes per felt). |
| DC-2 | `depositAttestation` = the raw 65-byte `r‖s‖v` secp256k1 signature over `keccak256(payload)` (not EIP-712). |
| DC-3 | Attester commitment = `Poseidon2(33-byte compressed pubkey)` → one Word (the `xReserveAttesters` key). |
| DC-4 | Nonce keying: `nonce` (bytes32) → Poseidon2 hash-to-Word → storage-map key. |
| DC-5 | `amount`/`fee` uint256 → AssetAmount: byte-swap, assert high-4-limbs zero, `floor(x / 10^scale_exp)`, reject if over `AssetAmount::MAX` (no saturation). |
| DC-6 | AccountId ↔ bytes32 packaging (the "R-B" right-aligned layout; see DEV-10). |
| DC-7 | `XReserveBurnNote` payload codec `(amount, destDomain, destRecipient, salt)` in `NoteStorage.items`. Shipped as Rust only (`xreserve/encoding/burn_note.rs`); there is no `burn_items.masm`. |
| DC-8 | Burn-evidence package assembly (`burnTxId` + `note_id` + `nullifier` + `block_num` + proof-strength labels). Owned by the off-chain **listener**, not this crate. |
| DC-9 / DC-10 / DC-11 / DC-12 | Circle JSON request/response schema types (off-chain Rust type definitions). Not on-chain. |
| DC-13 | Optional decoders for Circle-returned binary blobs (`TransferSpec`/`BurnIntent`/`WithdrawHookData`); off-chain validation only, non-gating. |

## Naming decisions — `NS-<n>`

| Id | Decision |
|---|---|
| NS-1 | The canonical bytes32→key MASM procedure is `xreserve::encoding::bytes32_to_key`; the Rust routine is `bytes32_to_storage_map_key`. |
| NS-2 | The canonical DepositIntent parser (`xreserve::encoding::parse_deposit_intent`) is owned by the encoding crate; the faucet's `deposit_intent_parser` adds only mint-specific assertions. |

## Module-layout & implementation decisions

| Id | Decision |
|---|---|
| D-1A | The module-realization rule: the flat-named `xreserve::encoding::<name>` procedures live in the directory-module root `encoding/mod.masm` (a per-proc `.masm` file would force a nested module path). |
| D-5 | The `AccountId ↔ bytes32` codec (`DC-6`) is Rust-primary — there is no MASM procedure for it in the encoding module (`account_id.rs`). |
| IMPL-ACCOUNTID-LAYOUT | The shipped AccountId-in-bytes32 packaging (the right-aligned "R-B" layout: 16 zero bytes ‖ prefix u64 BE ‖ suffix u64 BE); see `DEV-10` / `DC-6`. Provisional, pending Circle confirmation. |

## Builder gates — `G0`–`G8`, `G-MASM`, `G-RUST`

The build/audit gates defined in `docs/governing/BUILDER-GATES.md`:

| Gate | Requirement |
|---|---|
| G0 | Objective gates run BEFORE any human review. |
| G1 | Single ownership / no duplication (one MASM + one Rust impl per routine, cross-language conformance). |
| G2 | The ownership map is the source of truth for component boundaries. |
| G3 | Module/file size and structure conform to the MASM conventions. |
| G4 | Test discipline — happy path first, then negatives. |
| G5 | Reality grounds the spec (claims backed by running code / grounding evidence). |
| G6 | Circle-owned open decisions stay OPEN (nothing marked approved). |
| G7 | Concurrency correctness. |
| G8 | The human merge gate — non-delegable. |
| G-MASM | MASM conventions are source-backed, never invented (the checklist for MASM units). |
| G-RUST | Off-chain Rust harness/tooling hygiene (typed errors, no panic on external input, etc.). |

## Circle-owned open items — `DEV-<n>` and `Q-<...>`

These are deviations from, or questions about, Circle's specification that **remain OPEN**
pending Circle confirmation. The code implements a documented position; the label marks it as
provisional. Do not treat any of these as resolved. `Q-<AREA>-<n>` are the underlying
questions (e.g. `Q-CRY-*` cryptography, `Q-BUR-*` burn, `Q-DOM-*` domain, `Q-MIN-*` mint fee,
`Q-ADMIN-*` admin, `Q-INFRA-*` infrastructure).

| Id | Open item (provisional position taken) |
|---|---|
| DEV-1 (Q-CRY-1) | Verify deposit attestations against a relayer-supplied pubkey + Poseidon2-commitment allowlist instead of EVM `ecrecover`. |
| DEV-2 (Q-BUR-1/2) | Use a public `XReserveBurnNote` as the burn-event substitute (Miden has no event log). |
| DEV-5 (Q-CRY-6) | Cap `amount` at `AssetAmount::MAX = 2^63 − 2^31` at 6-dp scale instead of full uint256; the exact cap/scale/dust tolerance await Circle. |
| DEV-6 (Q-INFRA-5) | Bound `hookData` length (default within the 1024-felt `NoteStorage` limit); the exact cap awaits Circle. |
| DEV-7 (Q-BUR-1/4) | The burn-evidence package (how a completed burn is proven to Circle: tx id, note id, nullifier, block number). Open. |
| DEV-8 (Q-MIN-*) | Permissionless relay + single custom `xreserve_mint`; MVP `feeAmount == 0`; the relayer-fee split awaits Circle. |
| DEV-9 (Q-CRY-5) | Key `usedNonces` by a Poseidon2 commitment of the nonce; the enabled marker stays a plain flag. |
| DEV-10 (Q-CRY-3/4) | Encode a Miden AccountId as bytes32 via the right-aligned "R-B" layout (16 zero bytes ‖ prefix u64 BE ‖ suffix u64 BE); lossless, no keccak fallback. Applies to `remoteRecipient` and `remoteToken`/identifier. |

Beyond these, `Q-<...>` labels in comments/fixtures mark a value or choice as awaiting Circle:
- `Q-DOM-1` — which remote-domain id does Circle assign Miden? (so any test `domain` value is a placeholder, never the real value).
- `Q-PRV-5` — confirm xUSDC ships as a basic, transfer-free asset with no on-token control (a pre-deployment, immutable choice; see `F4` / `IMPL-DEV-20`).
- `Q-ADMIN-1` — is the canonical `xReserveAttesters` key type `address` or `bytes32`?
- `Q-CRY-4` — does the AccountId↔bytes32 encoding (`DEV-10`) apply to `remoteToken` / the faucet's bytes32 identifier as well as to `remoteRecipient`?
- `Q-DA-QUORUM` — is deposit attestation single-signer or a quorum (how many signatures must verify)?
- `Q-FEE-MVP` — confirm the MVP's fail-loud `feeAmount==0` reject (the CIR-FEE-2 relayer-credit split is deferred to mainnet/production-final; see `F2`). Distinct from the narrower `Q-MIN-2`, which covers only the zero-fee note structure. Question to Circle pending (orchestrator-owned).

## Circle requirement ids — `CIR-<AREA>-<n>`

`CIR-*` are numbered requirements from Circle's own requirements matrix (external material not in
this repo). They survive only in a few test-assertion strings and register rows; the ones
referenced here:

| Id | Requirement |
|---|---|
| CIR-ADMIN-3 | Role rotation: the Domain Manager rotates the Domain Pauser; the owner is the rotation backstop (`onlyDomainManager`/`onlyOwner`). Satisfied by `grant_role`/`revoke_role` + the build-seeded delegation — NOT by any runtime `set_role_admin` (see IMPL-DEV-24). |
| CIR-ADMIN-4 | Pausing must halt **both** deposits (mint) and withdrawals (burn-consume) — the pause halt-gates. |
| CIR-FEE-2 | Circle credits the relayer `feeAmount` on mint (recipient `amount−feeAmount`, relayer `+feeAmount`) — DEFERRED to mainnet/production-final; the MVP fail-loud `feeAmount==0` reject stands in (see `F2` / `Q-FEE-MVP`). |
| CIR-FEE-3 | xUSDC uses 6 decimals; the amount reducer scales to 6 dp. |

`CIR-MINT-PRE-<n>` are Circle's numbered mint-precondition requirements, cited in the generated
deposit-intent test vectors. Each maps to a mint-path check:

| Id | Precondition |
|---|---|
| CIR-MINT-PRE-2 | DepositIntent `magic` must match (the bad-magic reject; `R-MINT-1`). |
| CIR-MINT-PRE-3 | `version` must match (the bad-version reject; `R-MINT-2`). |
| CIR-MINT-PRE-4 | `amount` must be non-zero (`R-MINT-3`). |
| CIR-MINT-PRE-5 | `localToken` / `localDepositor` must be non-zero (`R-MINT-4`/`R-MINT-5`). |
| CIR-MINT-PRE-8 | reduced `amount ≥ maxFee` (`R-MINT-10`). |
| CIR-MINT-PRE-9 | `feeAmount` within bound (`R-MINT-11`; MVP requires `feeAmount == 0`). |
| CIR-MINT-PRE-11 | the total length relation `len == 240 + hookDataLen` (`R-MINT-8`). |

## Implementation deviations — `IMPL-DEV-<n>`

Ways the *shipped code* differs from the frozen internal spec (as opposed to `DEV-*`, which
are open items with Circle). The ones referenced in this repo:

| Id | Shipped behaviour |
|---|---|
| IMPL-DEV-1 | The sole pause surface is the custom `DOM_PAUSER` path; the stock owner-pause path is not installed. |
| IMPL-DEV-2 | On-chain role symbols `DOM_PAUSER`/`DOM_MANAGER` are ≤12-char aliases of Circle's `DOMAIN_PAUSER`/`DOMAIN_MANAGER` (Miden's `RoleSymbol` limit). |
| IMPL-DEV-3 | Per-setter admin roles were replaced with owner-gating (which also matches Circle). |
| IMPL-DEV-4 | The burn-pause assertion emits the stock `ERR_PAUSABLE_IS_PAUSED`, not a custom string. |
| IMPL-DEV-6 | Attestation uses a Poseidon2 commitment + keccak256 precompile + `verify_prehash` instead of EVM `ecrecover`; the signature `v` byte is unused. |
| IMPL-DEV-7 | The burn note uses a fixed placeholder tag until Circle assigns one. |
| IMPL-DEV-8 | The burn payload carries `{amount, dest_domain, dest_recipient, salt}` with the depositor in `metadata.sender`. |
| IMPL-DEV-12 | Cosmetic fix: an `AccountId`-out-of-range error message once said "15-byte region" while the shipped layout is 16-byte-padded; the message now describes the shipped right-aligned bytes32 layout. |
| IMPL-DEV-16 | `domain_init` uses `ownable2step::assert_sender_is_owner` directly while setters use `authority::assert_authorized`; both resolve to owner-only. |
| IMPL-DEV-20 | xUSDC ships as a basic (callback-disabled) fungible asset with no on-token transfer policy — matches Circle's no-on-token-control model. |
| IMPL-DEV-21 | v16 stock `OwnerControlled` bundles an owner-gated account-self-freeze; present-but-unreachable on the keyless allowlist faucet; F4/CIR-consistent; NOT holder control. (The v0.16 `Authority` component contributes `freeze`/`unfreeze` account procedures — upstream #3102 — which are callable roots but operationally inert here: the immutable 12-root note-script allowlist has no freeze note and the tx-script allowlist is empty, so `is_frozen` is never set and `ERR_AUTHORITY_FROZEN` never fires — the same disposition as `renounce_role`. Pinned by `tests/account_callable_surface.rs`; human-ratified 2026-07-13; map row S12.) |
| IMPL-DEV-22 | Three further v0.16 stock callable roots the full-account pin exposed, human-ratified 2026-07-13 (map row S24; NOT under S12): `authority::get_authority` — a read-only view accessor (no state, no capability, not supply-raising); and the #3047 `policy_manager::invoke_send_policy`/`invoke_receive_policy` transfer-policy dispatch wrappers — INERT no-ops here. With no active send/receive policy the stock `invoke_transfer_policy` takes its empty-root branch, returns `ASSET_VALUE` unchanged, and SKIPS the pause check (no zero-root trap). F4 installs no transfer policy → `AssetCallbackFlag::Disabled` → the kernel never invokes them on a transfer; unreachable via the 12-root note allowlist (tx-allowlist empty). F1 (`{mint}`-only) and F4 (unpoliced transfers) both intact; the skipped pause is consistent with F4. `get_authority` read-only is now EXECUTED proof, not documentation: `tests/account_callable_surface.rs::get_authority_is_read_only_on_the_account` drives it and asserts zero storage/vault mutation. Frozen in `tests/account_callable_surface.rs`. |
| IMPL-DEV-24 | **The runtime `set_role_admin` note is REMOVED from the note-script allowlist** (13 → 12 roots; S21 disposition flip, human-ratified 2026-07-14 — two independent adversarial Circle-conformance audits, NO REFUTATION). The stock `rbac::set_role_admin` account procedure STAYS on the composed account's frozen 62-root surface but is present-but-UNREACHABLE — the same disposition as `renounce_role` (never allowlisted) and `freeze`/`unfreeze` (S12). Rationale: the `DOM_PAUSER.admin_role = DOM_MANAGER` delegation is BUILD-SEEDED (`seeded_dom_roles_rbac`, byte-identical to an owner-sent `set_role_admin(DOM_PAUSER, DOM_MANAGER)`), so removal changes NO deployed capability Circle requires; CIR-ADMIN-3 rotation is `grant_role`/`revoke_role` (mirroring `updateDomainManager`/`updateDomainPauser` address-slot updates); Circle's EVM reference (`DomainManageable.sol`) has NO function to change who administers a role — freezing the graph is MORE Circle-faithful. Removal makes owner self-lockout (re-pointing `DOM_MANAGER.admin_role` off `ADMIN`) and the v16 #3215 Manager re-delegation of DOM_PAUSER structurally unreachable (recoverability from either re-pointed state was UNVERIFIED). The owner's rotation backstop is the seeded fixed graph + grant/revoke — NOT any runtime re-delegation guarantee (prior "backstop unbreakable" wording was incorrect and is retracted). Enforced by `tests/account_callable_surface.rs` (MAST sweep + former-root non-membership: re-adding the note turns them RED) and `tests/f5_admin_notes.rs` (the preserved former note is consumed and REJECTED). Circle routing: FYI-only — freezing tightens the pending Q-ADMIN-RBAC-EQUIV equivalence question. Ratification artifact: `DECISION-SETROLEADMIN-NOTE-REMOVAL.md` (implementation-readiness tree); map row S21. |

## Revision findings — `F<n>` / `G<n>` / `L<n>`

Findings from an internal revision pass. Most are historical, but a few are referenced by
name because the code or validation records anchor on them:

| Id | Meaning |
|---|---|
| F1 | The mint-effects helpers (`apply_mint_effects`, `extract_recipient_account_id`) must stay **private** so they cannot become a second, ungated supply surface; only `xreserve_mint::mint` (and its note entry) is a callable mint-family root. |
| F2 | Defensive fee guard: `apply_mint_effects` asserts `feeAmount == 0` (the MVP has no relayer-fee leg). RATIFIED DEFERRAL (2026-07-14): the fail-loud `feeAmount==0` reject IS the MVP contract; the relayer-credit fee split (CIR-FEE-2 / CIR-MINT-STATE-3 — recipient `amount−feeAmount`, relayer `+feeAmount`) is a documented, Circle-gated deferral, priority P2, gated on **mainnet/production-final** (NOT on the testnet MVP go-live). The "reject nonzero fee in MVP" decision needs its OWN explicit Circle confirmation — tracked as the pending **Q-FEE-MVP** (canonical Q-MIN-2 is narrower: it covers only the zero-fee note *structure*, and must not be cited as approving the reject). |
| F4 | xUSDC ships with **no** on-token transfer policy (a basic, callback-disabled asset), so minted assets are exempt from any future on-token control — a registered deviation matching Circle's no-on-token-control model (see `CMP-A5` / `IMPL-DEV-20`). |
| F5 | The transaction-level auth boundary for the permissionless-mint model (a non-allowlisted note and tx-script must both be rejected). |
| F6 | The owner-gated setters are intentionally **not** pause-gated (matching Circle's `onlyOwner`). |
| F7 | The production burn note is same-block-erasable, which could starve Circle's burn discovery — kept OPEN as a Circle/DEV-7 decision, evidenced by a real-node run. |
| L1 | `extract_recipient_account_id` must stay a private helper — it must **not** be a callable account root (a read-only sibling of `F1`, asserted by the root-surface tripwire test). |

## Local-node validation rows — `LNV` rows `A`–`L`

The `xusdc-validation` crate runs a real-local-node acceptance matrix. Each row is a scenario:

| Row | Scenario |
|---|---|
| A | Deploy the production faucet to a fresh node; the node recognizes the account. |
| B | `domain_init` init-once (first succeeds, second rejected). |
| C | Admin suite: attester set/rotation, `set_min_burn_size`, `set_max_supply`, pause/unpause, role rotation, non-authorized negatives. |
| D | Mint happy path (both hookData variants); recipient consumes the emitted P2ID note. |
| E | Mint negatives: replayed nonce, forged sig, non-allowlisted attester, non-zero fee, tampered payload — each rejected with no state change. |
| F | Auth boundary: a non-allowlisted note and tx-script are both rejected. |
| G | Burn two-block (Circle read path): committed, tag-discoverable, retrievable after consume, supply decrements. |
| H | Burn same-block (F7 evidence): client-side consume executes but user-RPC submission is rejected — evidence for the DEV-7 decision, no acceptability verdict. |
| I | Burn negatives: below-min, wrong-asset, while-paused — each rejected. |
| J | Conservation ledger: `token_supply == Σ minted − Σ burned`. |
| K | Network-transaction-builder liveness: does the node auto-execute routed+allowlisted consumptions (observed: yes). |
| L | Clean logs: no unexplained ERROR/panic lines across the service logs. |

The matrix was built in slices `LNV-1`–`LNV-5` (each recorded in a `VALIDATION-RECORD*.md`):

| Slice | Rows covered |
|---|---|
| LNV-1 | The harness foundation + rows `A`/`B` (deploy the faucet; `domain_init` init-once). |
| LNV-2 | The admin suite (row `C`) + the auth boundary (row `F`). |
| LNV-3 | The mint lifecycle (rows `D`/`E`). |
| LNV-4 | The burn lifecycle (rows `G`/`H`/`I`/`J`). |
| LNV-5 | The consolidated full-matrix gate run (all rows `A`–`L` on one fresh node). |

**RIV** = real-integration validation — an evidence run against a real local node (as opposed to
a mock chain). Row `H` is the `F7` same-block-burn-erasure RIV: it produces an evidence packet for
the OPEN `DEV-7` decision and makes no acceptability verdict of its own.

## Test vectors — `TV-*`

`TV-*` are golden-vector ids in the encoding crate's tests. Grouped by area:

**bytes32 → key (`TV-B32-*`)**

| Id | Checks |
|---|---|
| TV-B32-1 | A known bytes32 hashes to the expected Poseidon2 key Word (over the 8 u32-LE limbs). |
| TV-B32-2 | An input whose native `TryFrom` fails (a limb ≥ field modulus) still hashes to a key (the Option-B path). |
| TV-B32-3 | Determinism/idempotency: the same input yields the same key twice. |
| TV-B32-4 | Width proof: the raw packing yields 8 felts (2 Words), so it can't be one key without hashing. |
| TV-B32-INV-1, TV-B32-INV-2 | Inverse-path checks for the lossless `packed_felts_to_bytes32` decode. |

**amount reduction (`TV-AMT-*`)**

| Id | Checks |
|---|---|
| TV-AMT-1 | An in-bound 6-dp amount reduces to the expected `AssetAmount`. |
| TV-AMT-2 | Boundary accept: exactly `AssetAmount::MAX` (post-scale) is accepted. |
| TV-AMT-3 | Boundary reject: `MAX + 1` (post-scale) is rejected (over cap). |
| TV-AMT-4 | High-limb reject: a value > 2^128 (high 4 limbs non-zero) is rejected ("too large"). |
| TV-AMT-5 | Reduced compare: `amount ≥ maxFee` is false when `amount < maxFee` after reduction. |
| TV-AMT-6 | Dust: a non-zero remainder is surfaced (off-chain only); dust policy stays OPEN (`DEV-5`). |
| TV-AMT-7 | Scale-overflow reject: `10^scale_exp` overflow is rejected. |

**AccountId ↔ bytes32 (`TV-AID-*`)**

| Id | Checks |
|---|---|
| TV-AID-1 | Round-trip: `bytes32_to_account_id(account_id_to_bytes32(id)) == id`. |
| TV-AID-2 | Reject a non-zero byte in the leading pad; reject a non-canonical prefix/suffix. |
| TV-AID-3 | The address-type discriminant is fixed and there is no keccak-fallback branch. |
| TV-AID-4 | The on-chain two-felt form `[prefix, suffix]` matches the bytes32 layout. |

**DepositIntent parse (`TV-DI-*`)**

| Id | Checks |
|---|---|
| TV-DI-1 | A full 240-byte header + hookData parses to the exact fields. |
| TV-DI-2 | Wrong `magic` is rejected. |
| TV-DI-3 | `version != 1` is rejected. |
| TV-DI-4 | `amount == 0` is rejected. |
| TV-DI-5 | `localToken == 0` or `localDepositor == 0` is rejected. |
| TV-DI-6 | Length-relation / truncated-header violations are rejected. |
| TV-DI-7 | The header is 60 felts (not 30); over the 1024-felt bound is rejected. |
| TV-DI-8 | Parse is read-only over the input slice. |
| TV-DI-9 | Every field offset equals its `DC-1` table value. |

**burn-note items (`TV-BN-*`)**

| Id | Checks |
|---|---|
| TV-BN-1 | Encode→decode round-trips the `(amount, destDomain, destRecipient, salt)` payload. |
| TV-BN-2 | The destination goes in `NoteStorage.items`; `metadata.sender` is the depositor only (`anti-ASG-13`). |
| TV-BN-3 | The payload targets `NoteStorage.items` (≤ 1024 felts), not `NoteInputs`/`aux` (`anti-ASG-17`). |
| TV-BN-4 | A wrong-length items list is rejected. |

**attestation (`TV-ATT-*`)**

| Id | Checks |
|---|---|
| TV-ATT-1 | Felt shapes: digest = 8 felts, pubkey = 9 felts, signature = 17 felts. |
| TV-ATT-2 | The pubkey commitment is `Poseidon2(33-byte pubkey)`, matching the allowlist keying. |
| TV-ATT-3 | Raw keccak (not EIP-712): the signature covers `keccak256(full payload)` with no domain prefix. |

**dual-implementation vectors (`TV-DUAL-*`)** — `-1`/`-2`/`-3`/`-5` assert Rust↔MASM agreement (run
in `tests/masm_dual.rs`); `-4` is Rust-only because `DC-7` has no MASM side.

| Id | Checks |
|---|---|
| TV-DUAL-1 | `bytes32_to_key`: Rust and MASM produce the identical key Word on every vector. |
| TV-DUAL-2 | `uint256_to_asset_amount`: Rust and MASM produce the identical amount / trap. |
| TV-DUAL-3 | DepositIntent parse: Rust and MASM agree on accept/reject and the 60-felt preimage. |
| TV-DUAL-4 | Burn-note items: the Rust-emitted burn note's `NoteStorage.items` match the Rust codec and the golden felts (an emit-vs-codec check within Rust — `DC-7` is Rust-only, there is no MASM burn-item codec). |
| TV-DUAL-5 | Attestation packing/commitment: Rust and MASM produce the identical felts / commitment. |

`TV-CIRCLE-DIFF` = a differential check of the DepositIntent parse against a locally-reconstructed
Circle ground-truth fixture. The faucet test harness also groups scenarios under module ids
`§4.A`–`§4.T` (mint = `§4.A`–`§4.J`, burn = `§4.M`–`§4.R`, admin/build/gate = `§4.K`–`§4.T`).

## Build phases & test anchors

| Id | Meaning |
|---|---|
| P5-01 | The build phase/slice for the on-chain xUSDC faucet (this repo's `asm/` and the faucet-side code of the encoding crate). |
| P5-04 | The build phase/slice for the shared encoding library (`xreserve::encoding`). |
| TAG-1 | The test that the mint note carries the faucet's account-target routing tag, and the burn note its fixed 32-bit tag (see `IMPL-DEV-7`). |

## Spec section references — `§<n>`

Some comments cite a section number of the internal component spec. The referenced content is
now documented in this repo (the faucet spec at `docs/spec/FAUCET-COMPONENT-SPEC.md` and the
encoding spec at `docs/spec/ENCODING-COMPONENT-SPEC.md`). The mapping of the frequently-cited
sections:

| Section | Topic (faucet spec unless noted) |
|---|---|
| §2 | (faucet spec) file/folder layout; (shared-encoding spec) the non-negotiable invariants. |
| §3 | (faucet spec) the invariants (`INV-*` list); (shared-encoding spec) the data contracts. |
| §5.1 | The mint write phase / `apply_mint_effects` effects. |
| §5.2 | The sole-supply-surface property (`INV-MINT-SECURITY`). |
| §5.5 | `XReserveAttesterAdmin` — home of the `xReserveAttesters` allowlist and `minBurnSize` slots. |
| §5.6 | The `usedNonces` nonce registry. |
| §5.9 | The four-field domain config (`domain_init`). |
| §5.12 | The admin setters and pause. |
| §5.13 | The builder's slot-presence guard. |
| §6.6 | (shared-encoding spec) the `burn_note` item codec (`DC-7`). |
| §6.7 | (shared-encoding spec) the `attestation` surface signatures. |
| §7 | (faucet spec) the consumed encoding boundary; (shared-encoding spec) data shapes (byte widths / felt counts). |
| §8.1 | (shared-encoding spec) DepositIntent validation order. |
| §8.2 | (shared-encoding spec) uint256 → AssetAmount reduction order. |
| §11.2 | The full-matrix real-node acceptance gate (the LNV matrix above). |

`§<n>.<n>` references written as "§N of the record" / "`VALIDATION-RECORD.md` §N" point to a
section of the named in-repo document (e.g. `§2.4`, `§3` of a validation record) and resolve
within this repository.
