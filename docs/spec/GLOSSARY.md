# Identifier glossary

This file defines every short identifier that appears in this repository's code comments,
documentation, and test names. The identifiers are stable anchors: a numbered
requirement (`R-MINT-15`), a named invariant (`INV-MINT-SECURITY`), or an open question that is
still owned by Circle (`DEV-10`). Comments keep them
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
change. Several are asserted on by name in the tests. `R-MINT-1..8` cover structural and
addressing checks; `R-MINT-9..11` amount and fee checks; `R-MINT-12` replay protection;
`R-MINT-13..14` attestation checks; `R-MINT-15` the supply-cap check; and `R-MINT-16` the
stock-mint-path denial. The third column records *how* each condition is enforced after `DC-14`:
several are no longer compares the faucet performs but states the faucet's own writing makes
unreachable.

| Id | Condition enforced | How it is enforced (see *Enforcement by construction* below) |
|---|---|---|
| R-MINT-1 | DepositIntent `magic` matches the expected constant. | by construction — the faucet writes it |
| R-MINT-2 | DepositIntent `version` matches the supported version (1). | by construction — the faucet writes it |
| R-MINT-3 | `amount` field is non-zero. | direct reject, `ERR_XRESERVE_MINT_ZERO_AMOUNT` |
| R-MINT-4 | `localToken` field is non-zero. | subsumed by R-MINT-14 |
| R-MINT-5 | `localDepositor` field is non-zero. | subsumed by R-MINT-14 |
| R-MINT-6 | DepositIntent `remoteDomain` equals the faucet's configured domain. | by construction — written from the domain config slot |
| R-MINT-7 | DepositIntent `remoteToken` equals the faucet's own account id. | by construction — written from `native_account::get_id` |
| R-MINT-8 | Total preimage length equals `240 + hookDataLen` (header + hookData). | direct reject, unchanged (the exact transport word-count binding) |
| R-MINT-9 | `amount` / `maxFee` are representable as an `AssetAmount`. | `maxFee`: off-chain typed reject at compress time, since it cannot be carried otherwise. `amount`: a direct on-chain reject against the protocol's `FUNGIBLE_ASSET_MAX_AMOUNT`, because it comes from the note rather than the payload |
| R-MINT-10 | `amount ≥ maxFee`. | direct reject, unchanged (now a felt compare) |
| R-MINT-11 | `feeAmount ≤ maxFee` (MVP: the fee must be zero). | inexpressible — `feeAmount` no longer travels on the wire at all |
| R-MINT-12 | The DepositIntent `nonce` has not been used before (replay guard). | direct reject, unchanged |
| R-MINT-13 | The carried attester index is a `u32` and the key stored at it is not all-zero. | direct reject; the shape changed with `DC-15` — the note carries an index, not a key, so "enabled" now means a key is present at that index |
| R-MINT-14 | The ECDSA signature verifies over `keccak256(payload)` for the key stored at that index. | direct reject, unchanged |
| R-MINT-15 | `token_supply + amount ≤ max_supply` and `max_supply ≤ AssetAmount::MAX` (supply cap). | direct reject, unchanged (stock-owned) |
| R-MINT-16 | The stock `mint_and_send` path is denied — only the custom `xreserve_mint` may raise supply. | superseded by the Wave-1 recomposition (the stock path IS the gated path) |

### Enforcement by construction, and what it costs

Under `DC-14` the faucet no longer reads Circle's DepositIntent off the wire — it **rebuilds** the
signed message from the note's mint intent plus its own state. A field the faucet writes cannot be
wrong: a divergent value produces a different keccak digest, so the attestation refuses it. Six
conditions above therefore stop being compares.

The cost is that they stop being *distinguishable*. A wrong domain, a wrong target faucet, a
mismatched amount and a misplaced field in the writer now all surface as the same
`ERR_XRESERVE_SIG_INVALID`. Every "by construction" and "subsumed" row above is consequently held
by a **pair** of tests, and neither half alone discharges it:

| Half | What it proves | Where |
|---|---|---|
| the e2e row | the mint fails closed — signature reject, nonce unburned, supply unraised | `mint_policy_e2e.rs`, `mint_policy_binding_e2e.rs` |
| the placement row | the writer puts *that* field at *that* offset, so the reject is the intended one | the per-field case in `rebuild_places_each_carried_field`, `masm_mint_shell.rs` |

Diagnosability regresses accordingly: during an incident the on-chain error no longer localizes the
cause. The mitigation is off-chain — the relayer pre-validates with the Rust mirror
(`MintIntent::from_deposit_intent`), which rejects each of these with its own typed error and
should never submit such a note.

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
| R-ADMIN-1 | `set_attester` is administrator-gated: it carries no role of its own, so the account's role-based authority resolves it to the built-in `ADMIN` role — whose sole seeded member is the bootstrap administrator's account — and a sender without that role is rejected. |
| R-ADMIN-2 | `set_min_burn_size` is administrator-gated (unmapped, so it resolves to the built-in `ADMIN` role). |
| R-ADMIN-3 | `pause` / `unpause` require the `DOM_PAUSER` role. |
| R-ADMIN-4 | Domain config is build-seeded with no runtime writer; the mint path derives the faucet identifier from its native account id. |

## Component slices — `CMP-<x>`

Labels for the faucet's functional pieces (originally built as incremental slices). They name
*what* the piece is; the code that implements each lives where the comment sits.

| Id | Component |
|---|---|
| CMP-A5 | On-token transfer policy: the stock `BasicBlocklist` is the active send + receive policy, administered by `BLK_MANAGER`. |
| CMP-A6 | `XReserveDomainConfig` — the faucet's build-seeded domain-config fields (`domain`, `source_domain`, `xreserve_contract`); the identifier is derived, not stored. |
| CMP-A9 | The stock `mint_and_send` supply-increasing surface, gated by `mint_policy::check_policy`. |
| CMP-A10 | The burn security policy, run on every `receive_and_burn`: stock `MinBurnAmount::check_policy` with the ≥1 floor invariant enforced by the builder and admin note. |
| CMP-A15 | `XReserveStablecoinBuilder` — the Rust builder that composes the full faucet account and rejects an invalid wiring (e.g. no deny guard, non-Public faucet) at build time. |
| CMP-B1 | The stock `MintNote` transport plus the account's attestation mint policy. |
| CMP-B2 | `XReserveBurnNote` construction (the public withdrawal note). |
| CMP-B3 | `receive_and_burn` consumption of the burn note. |
| CMP-F2 | The administrator-gated `set_min_burn_size` setter (unmapped, so the account's role-based authority resolves it to the built-in `ADMIN` role). |
| CMP-F3 | The custom `DOM_PAUSER`-gated pause/unpause. |
| CMP-F5 | Role management (role-based access control): `grant_role`/`revoke_role` membership rotation (CIR-ADMIN-3) plus the BUILD-SEEDED `DOM_PAUSER.admin_role = DOM_MANAGER` delegation. Driven by the STOCK `RbacActionNote`, whose single allowlisted script root also carries `set_role_admin` and `renounce_role` — so the delegation graph is runtime-MUTABLE and self-renounce is reachable; both are accepted. See IMPL-DEV-24. |

## Invariants — `INV-<name>`

Security/correctness properties the faucet must uphold. The faucet-binding ones:

| Invariant | Property |
|---|---|
| INV-MINT-SECURITY | `xreserve_mint` is the **only** supply-increasing surface, gated by an allowlisted-attester signature; the stock `mint_and_send` path is a deny guard. |
| INV-SUPPLY-CONSERVATION | `token_supply += amount` exactly once per mint and `-= amount` once per burn. |
| INV-NONCE-REPLAY | `usedNonces` is keyed by a Poseidon2 hash-to-Word of the nonce; assert-zero-then-set; replays are rejected. |
| INV-PUBLIC-BURN-OBSERVABILITY | The burn note is Public, with its payload in `NoteStorage.items` and a fixed 32-bit tag. |
| INV-TWO-BLOCK-BURN | A burn note is created in block N and consumed in block ≥ N+1; a same-block create+consume is erased. |
| INV-NO-ECRECOVER | No key recovery on-chain; ECDSA is verified against an explicit candidate pubkey, read from the `DC-15` key array at the index the note carries. |
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
| DC-3 | **Retired, superseded by DC-15.** Was: attester commitment = `Poseidon2(affine pubkey, 16 u32-LE felts)` → one Word, the `xReserveAttesters` key. Nothing commits to a pubkey any more, so `pubkey_commitment` is deleted on both sides and the `xReserveAttesters` slot is gone. |
| DC-4 | Nonce keying: `nonce` (bytes32) → Poseidon2 hash-to-Word → storage-map key. |
| DC-5 | `amount`/`fee` uint256 → AssetAmount: byte-swap, assert high-4-limbs zero, `floor(x / 10^scale_exp)`, reject if over `AssetAmount::MAX` (no saturation). |
| DC-6 | AccountId ↔ bytes32 packaging (the "R-B" right-aligned layout; see DEV-10). |
| DC-7 | `XReserveBurnNote` payload codec `(amount, destDomain, destRecipient, salt)` in `NoteStorage.items`. Shipped as Rust only (`xreserve/encoding/burn_note.rs`); there is no `burn_items.masm`. |
| DC-8 | Burn-evidence package assembly (`burnTxId` + `note_id` + `nullifier` + `block_num` + proof-strength labels). Owned by the off-chain **listener**, not this crate. |
| DC-9 / DC-10 / DC-11 / DC-12 | Circle JSON request/response schema types (off-chain Rust type definitions). Not on-chain. |
| DC-13 | Optional decoders for Circle-returned binary blobs (`TransferSpec`/`BurnIntent`/`WithdrawHookData`); off-chain validation only, non-gating. |
| DC-14 | The mint-note carried payload and the on-chain reconstruction of the DepositIntent preimage. The note carries only what the faucet cannot derive — `nonce`, `localToken`, `localDepositor`, `remoteRecipient`, `maxFee`, `hookDataLen` and `hookData`; the faucet writes `magic`, `version`, `amount` (from the note's asset value), `remoteDomain` (from its config slot), `remoteToken` (from its own id) and a zero `feeAmount` into the canonical `240 + hookDataLen`-byte preimage before hashing. Owned by the faucet (01); the felt offsets are 04's (`mint_intent.masm`). Requires `DEPOSIT_SCALE_EXP == 0` and a 20-byte right-aligned EVM address in `localToken` / `localDepositor` — see `DEV-5` and `Q-EVM-ADDR-1`, both **OPEN**. |
| DC-15 | The attester public-key array (`xReserveAttesterKeys`), superseding `DC-3`. The 16 affine felts of one secp256k1 key are stored as four words at array entries `PUBKEY_ARRAY_ENTRIES * attester_idx + 0..3`; the mint transport carries only the 1-felt `attester_idx`, which must be a `u32` but is otherwise unbounded. **Presence is the allowlist** — a non-zero key is enabled, an all-zero key is disabled or never written, so the two are indistinguishable on the read path exactly as the old disabled and absent markers were. The wire/ingress form stays the 33-byte compressed SEC1 pubkey; the codec decompresses it to affine `qx‖qy` (v16, vm#3342). Rotate by writing a NEW index and zeroing the old one — overwriting a key in place fails any in-flight note naming that index (liveness, not safety). |

## Naming decisions — `NS-<n>`

| Id | Decision |
|---|---|
| NS-1 | The canonical bytes32→key MASM procedure is `xreserve::mint_intent::hash_nonce`; the Rust routine is `bytes32_to_storage_map_key`. |
| NS-2 | **Retired** (see the ownership map). The on-chain DepositIntent parser is gone: the faucet writes the message rather than reading it. |
| NS-3 | The canonical on-chain DepositIntent realization is `xreserve::deposit_intent::rebuild`; the `DC-5` reducer moved to the same module when `xreserve::encoding` was dissolved. The nonce hash went to `xreserve::mint_intent` instead, with the admissibility checks that read it (NS-1, amended three times). |

## Module-layout & implementation decisions

| Id | Decision |
|---|---|
| D-1A | The module-realization rule: one module per WIRE FORM directly under `asm/standards/xreserve/`, each holding that format's constants and the procedures that realize them. No owner-grouping directory — ownership is a column in the map, not a path segment. |
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
| DEV-1 (Q-CRY-1) | Verify deposit attestations against an allowlisted pubkey instead of EVM `ecrecover`. **Still OPEN, and the shape has changed under an explicitly flagged assumption:** the pubkey is no longer relayer-supplied. It lives in the faucet's own `DC-15` key array and the note carries only an index into it, so the commitment allowlist this item originally described no longer exists. The assumption is that Circle is content for the attester key set to be on-chain administrator state rather than per-note wire data; if Circle wants the key back on the wire, `DC-3` and `pubkey_commitment` must be restored from history. Nothing here is approved or resolved. |
| DEV-2 (Q-BUR-1/2) | Use a public `XReserveBurnNote` as the burn-event substitute (Miden has no event log). |
| DEV-5 (Q-CRY-6) | Cap `amount` at `AssetAmount::MAX = 2^63 − 2^31` at 6-dp scale instead of full uint256; the exact cap/scale/dust tolerance await Circle. |
| DEV-6 (Q-INFRA-5) | Bound `hookData` length (default within the 1024-felt `NoteStorage` limit); the exact cap awaits Circle. |
| DEV-7 (Q-BUR-1/4) | The burn-evidence package (how a completed burn is proven to Circle: tx id, note id, nullifier, block number). Open. |
| DEV-8 (Q-MIN-*) | Permissionless relay + single custom `xreserve_mint`; MVP `feeAmount == 0`; the relayer-fee split awaits Circle. |
| DEV-9 (Q-CRY-5) | Key `usedNonces` by a Poseidon2 commitment of the nonce; the enabled marker stays a plain flag. |
| DEV-10 (Q-CRY-3/4) | Encode a Miden AccountId as bytes32 via the right-aligned "R-B" layout (16 zero bytes ‖ prefix u64 BE ‖ suffix u64 BE); lossless, no keccak fallback. Applies to `remoteRecipient` and `remoteToken`/identifier. |

Beyond these, `Q-<...>` labels in comments/fixtures mark a value or choice as awaiting Circle:
- `Q-DOM-1` — which remote-domain id does Circle assign Miden? (so any test `domain` value is a placeholder, never the real value).
- `Q-BLK-1` (**OPEN** — Circle-owned) — confirm the transfer-blocklist semantics: blocked means full freeze including redemption; mint or transfer to a blocked recipient strands at consume; pause halts all transfers. See `docs/CIRCLE-SEMANTICS-TRANSFER-BLOCKLIST.md`.
- `Q-ADMIN-1` — is the canonical attester-allowlist key type `address` or `bytes32`? (Under `DC-15` the on-chain store is keyed by an array index and holds the raw affine key, so this question now bears only on Circle's own admin-facing form.)
- `Q-CRY-4` — does the AccountId↔bytes32 encoding (`DEV-10`) apply to `remoteToken` / the faucet's bytes32 identifier as well as to `remoteRecipient`?
- `Q-DA-QUORUM` (**OPEN** — Circle-owned) — the current transport carries one attestation; confirm whether the production design remains single-signer or requires a quorum.
- `Q-EVM-ADDR-1` (**OPEN** — Circle-owned) — `DC-14` carries `localToken` and `localDepositor` as 20 bytes each, on the assumption that both bytes32 fields always hold a right-aligned EVM address. Confirm that holds for every source domain Circle will enable. A source chain with a wider address makes such a deposit unmintable under `DC-14` until a new transport ships; the relayer detects it at compress time and never submits the note, so it degrades to an off-chain error rather than a failed transaction.
- `Q-FEE-MVP` — confirm the MVP's fail-loud `feeAmount==0` reject (the CIR-FEE-2 relayer-credit split is deferred to mainnet/production-final; see `F2`). Distinct from the narrower `Q-MIN-2`, which covers only the zero-fee note structure. Question to Circle pending (orchestrator-owned).

## Circle requirement ids — `CIR-<AREA>-<n>`

`CIR-*` are numbered requirements from Circle's own requirements matrix (external material not in
this repo). They survive only in a few test-assertion strings and register rows; the ones
referenced here:

| Id | Requirement |
|---|---|
| CIR-ADMIN-3 | Role rotation: the Domain Manager rotates the Domain Pauser; the built-in `ADMIN` role stands where Circle's `onlyOwner` does. Satisfied by `grant_role`/`revoke_role` through the stock `RbacActionNote`, over the build-seeded delegation. Since the admin-surface finalization there is no ownership component: `ADMIN` is the faucet's sole authority handle and rotates by grant-then-revoke of itself. Note the delegation is EXCLUSIVE — `ADMIN` cannot grant, revoke or re-point `DOM_PAUSER`, which `DOM_MANAGER` governs (see IMPL-DEV-24). |
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
| IMPL-DEV-1 | The sole pause surface is the stock `PausableManager`, gated on `DOM_PAUSER` by the account's per-procedure role map — so the administrator, who holds everything else, has no pause path. |
| IMPL-DEV-2 | On-chain role symbols `DOM_PAUSER`/`DOM_MANAGER` are ≤12-char aliases of Circle's `DOMAIN_PAUSER`/`DOMAIN_MANAGER` (Miden's `RoleSymbol` limit). |
| IMPL-DEV-3 | Per-setter admin roles were replaced with a single administrator gate: the setters carry no role of their own and resolve to the built-in `ADMIN` role, seeded on the bootstrap administrator's account (which also matches Circle). `ADMIN` membership is account-bound, and since the admin-surface finalization it is the account's ONLY authority handle — there is no ownership lifecycle beside it; see `IMPL-DEV-23`. |
| IMPL-DEV-4 | The burn-pause assertion emits the stock `ERR_PAUSABLE_IS_PAUSED`, not a custom string. |
| IMPL-DEV-6 | Attestation uses the keccak256 precompile + `verify_prehash` against a key read from the `DC-15` array instead of EVM `ecrecover`; the signature `v` byte is unused. |
| IMPL-DEV-7 | The burn note uses a fixed placeholder tag until Circle assigns one. |
| IMPL-DEV-8 | The burn payload carries `{amount, dest_domain, dest_recipient, salt}` with the depositor in `metadata.sender`. |
| IMPL-DEV-12 | Cosmetic fix: an `AccountId`-out-of-range error message once said "15-byte region" while the shipped layout is 16-byte-padded; the message now describes the shipped right-aligned bytes32 layout. |
| IMPL-DEV-16 | The identifier-init procedure and note are removed. The mint path decodes `remoteToken` and compares it directly with the faucet's native account id, so there is no identifier slot or initialization window. |
| IMPL-DEV-20 | xUSDC ships as a policed fungible asset carrying the stock `BasicBlocklist` as the active send + receive policy, administered by `BLK_MANAGER`. |
| IMPL-DEV-21 | Mint rejects any nonzero `feeAmount` with `ERR_XRESERVE_FEE_NONZERO`. The relayer-credit fee split is deferred behind the OPEN `Q-FEE-MVP` Circle confirmation. |
| IMPL-DEV-22 | Self-renounce is reachable through the stock `RbacActionNote`. A sole `ADMIN` can renounce and leave administrator-gated procedures unrecoverable except by redeploy; `Q-ADMIN-RENOUNCE` stays OPEN. |
| IMPL-DEV-23 | Admin roles use Miden RBAC (`grant_role`/`revoke_role`) rather than Circle's single address slots. There is no ownership component; seeded `ADMIN` membership is the faucet's administrative authority, and rotation is grant-successor before revoke-predecessor. `Q-ADMIN-RBAC-EQUIV` stays OPEN. |
| IMPL-DEV-24 | The stock `RbacActionNote` is allowlisted as one script root carrying `GRANT_ROLE`/`REVOKE_ROLE`/`SET_ROLE_ADMIN`/`RENOUNCE_ROLE`; all four selectors are reachable. The allowlist is 8 roots and the composed account's callable surface is 61. |
| IMPL-DEV-25 | The stock `Authority` component exposes account `freeze`/`unfreeze` roots, but the keyless allowlist faucet has no note-script or tx-script path that reaches them. |
| IMPL-DEV-26 | The stock `authority::get_authority` accessor is read-only, and the transfer-policy dispatch wrappers are live because the account wires `BasicBlocklist` as its transfer policy. |

## Revision findings — `F<n>` / `G<n>` / `L<n>`

Findings from an internal revision pass. Most are historical, but a few are referenced by
name because the code or validation records anchor on them:

| Id | Meaning |
|---|---|
| F1 | The stock `mint_and_send` path dispatching `mint_policy::check_policy` is the sole supply surface. |
| F2 | Deposit-intent validation rejects nonzero `feeAmount`; the relayer-credit split remains deferred behind the OPEN `Q-FEE-MVP` Circle confirmation. |
| F4 | xUSDC ships as a policed asset: the stock `BasicBlocklist` is the active send + receive transfer policy and the account id has `AssetCallbackFlag::Enabled`. |
| F5 | The transaction-level auth boundary for the permissionless-mint model (a non-allowlisted note and tx-script must both be rejected). |
| F6 | The administrator-gated setters are intentionally **not** pause-gated (matching Circle's `onlyOwner`). |
| F7 | The production burn note is same-block-erasable, which could starve Circle's burn discovery — kept OPEN as a Circle/DEV-7 decision, evidenced by a real-node run. |
| L1 | An exported parity helper must not carry `@account_procedure` or become a callable account root. |

## Local-node validation rows — `LNV` rows `A`–`L`

The `xusdc-validation` crate runs a real-local-node acceptance matrix. Each row is a scenario:

| Row | Scenario |
|---|---|
| A | Deploy the production faucet to a fresh node; the node recognizes the account. |
| B | Identifier init-once (first succeeds, second rejected). |
| C | Admin suite: attester set/rotation, `set_min_burn_size`, `set_max_supply`, pause/unpause, role rotation, non-authorized negatives. |
| D | Mint happy path (both hookData variants); recipient consumes the emitted P2ID note. |
| E | Mint negatives: replayed nonce, forged sig, unwritten/zeroed attester index, non-zero fee, tampered payload — each rejected with no state change. |
| F | Auth boundary: a non-allowlisted note and tx-script are both rejected. |
| G | Burn two-block (Circle read path): committed, tag-discoverable, retrievable after consume, supply decrements. |
| H | Burn same-block (F7 evidence): client-side consume executes but user-RPC submission is rejected — evidence for the DEV-7 decision, no acceptability verdict. |
| I | Burn negatives: below-min, wrong-asset, while-paused — each rejected. |
| J | Conservation ledger: `token_supply == Σ minted − Σ burned`. |
| K | Network-transaction-builder liveness: does the node auto-execute routed+allowlisted consumptions (observed: yes). |
| L | Clean logs: no unexplained ERROR/panic lines across the service logs. |

The matrix is built in slices `LNV-1`–`LNV-5`:

| Slice | Rows covered |
|---|---|
| LNV-1 | The harness foundation + rows `A`/`B` (deploy the mint-ready faucet and inspect its seeded configuration). |
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
| TV-ATT-1 | Felt shapes: digest = 8 felts, pubkey = 16 affine felts (decompressed from the 33-byte compressed wire key), signature = 17 felts. |
| TV-ATT-2 | **Retired** with `DC-3`. Nothing commits to a pubkey any more — the allowlist is the key array itself (`DC-15`), so there is no commitment to pin against miden-crypto `PublicKey::to_commitment`. |
| TV-ATT-3 | Raw keccak (not EIP-712): the signature covers `keccak256(full payload)` with no domain prefix. |

**dual-implementation vectors (`TV-DUAL-*`)** — `-1`/`-2`/`-3` assert Rust↔MASM agreement (run
in `tests/masm_dual.rs`); `-4` is Rust-only because `DC-7` has no MASM side.

| Id | Checks |
|---|---|
| TV-DUAL-1 | `hash_nonce`: Rust and MASM produce the identical key Word on every vector. |
| TV-DUAL-2 | **Retired** with the MASM witness verifier (see the ownership map's `DC-5` rider). The amount conversion is Rust-only; its vectors still drive the Rust unit tests in `amount.rs`. |
| TV-DUAL-3 | DepositIntent parse: Rust and MASM agree on accept/reject and the 60-felt preimage. Rust-only on the mint path after `DC-14` — the MASM parser is retired (`NS-2`), so the MASM leg is `TV-DUAL-6`. |
| TV-DUAL-4 | Burn-note items: the Rust-emitted burn note's `NoteStorage.items` match the Rust codec and the golden felts (an emit-vs-codec check within Rust — `DC-7` is Rust-only, there is no MASM burn-item codec). |
| TV-DUAL-5 | **Retired** with `DC-3` and `TV-ATT-2`. There is no commitment left to agree on; the attestation felts the transport carries are still pinned by `TV-ATT-1`, and the key the faucet reads back out of the `DC-15` array is proved by an executing mint. |
| TV-DUAL-6 | `DC-14` preimage reconstruction, in three parts: the Rust round trip (`to_deposit_intent_bytes` after `from_deposit_intent` returns the original bytes); MASM/Rust parity (the felts `rebuild` writes equal the Rust reconstruction's); and per-field placement (mutating one carried field moves exactly that field's bytes). |

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
| §5.1 | The stock `mint_and_send` effects behind the attestation policy. |
| §5.2 | The sole-supply-surface property (`INV-MINT-SECURITY`). |
| §5.5 | `XReserveAttesterAdmin` — home of the `xReserveAttesterKeys` array (`DC-15`) and `minBurnSize` slots. |
| §5.6 | The `usedNonces` nonce registry. |
| §5.9 | The three stored domain-config fields are build-seeded; the identifier is derived from the native account id. |
| §5.12 | The admin setters and pause. |
| §5.13 | The builder's slot-presence guard. |
| §6.6 | (shared-encoding spec) the `burn_note` item codec (`DC-7`). |
| §6.7 | (shared-encoding spec) the `attestation` surface signatures. |
| §7 | (faucet spec) the consumed encoding boundary; (shared-encoding spec) data shapes (byte widths / felt counts). |
| §8.1 | (shared-encoding spec) DepositIntent validation order. |
| §8.2 | (shared-encoding spec) uint256 → AssetAmount reduction order. |
| §11.2 | The full-matrix real-node acceptance gate (the LNV matrix above). |
