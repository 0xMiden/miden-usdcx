# xUSDC faucet — on-chain component specification

This is the specification for the on-chain part of Circle's **xReserve / xUSDC** on Miden: the
hand-written-MASM faucet account and its note scripts. It is written to match the **shipped
code** in `asm/standards/`; where the code takes a provisional position on an item Circle has
not yet confirmed, that is called out as OPEN (see `docs/spec/GLOSSARY.md`, `DEV-*`/`Q-*`).

Short identifiers used below (`R-MINT-15`, `D5c`, `INV-MINT-SECURITY`, …) are defined once in
`docs/spec/GLOSSARY.md`.

## 1. What this component is

xUSDC is a Miden **fungible faucet** account. Native USDC stays locked 1:1 in Circle's xReserve
contract on the source chain; this faucet mints xUSDC on Miden against a Circle-attested
**DepositIntent**, and burns xUSDC when a holder withdraws. It is built by reusing Miden's
standard `FungibleFaucet` machinery and **replacing the supply-changing surfaces with custom,
fully-gated MASM**:

- The standard `mint_and_send` path is **denied** (`mint_deny_guard`), so the only way supply
  can rise is the custom `xreserve_mint` procedure, which requires a valid attester signature.
- Burns run through the standard `receive_and_burn` path, but a custom **burn policy**
  (`burn_policy`) gates every burn on `amount > 0` and `amount ≥ minBurnSize`.

The account is `AccountType::Public`, 6-decimal, symbol "xUSDC". The Rust
`XReserveStablecoinBuilder` (in `crates/xusdc-encoding`) composes the account and rejects an
invalid wiring (e.g. a faucet without the deny guard, or a non-Public faucet) at build time.

## 2. On-chain modules (`asm/standards/`)

### `xreserve/` — the faucet account component

| Module | Role |
|---|---|
| `xreserve_mint` | The custom mint: the verify-once-then-write-once pipeline (`D5a`–`D5e`) and the sole supply-increasing surface. |
| `deposit_intent_parser` | The faucet-side mint preconditions (`D5a`/`D5b`/`D5c`): domain/identifier compares, amount/fee bounds, nonce replay guard. Delegates the structural DepositIntent parse to the encoding library. |
| `attestation_verify` | The attestation check (`D5d`): keccak the payload, gate the attester pubkey against the allowlist, ECDSA-verify the signature. |
| `mint_deny_guard` | The active mint policy — an unconditional trap that denies the stock `mint_and_send` path. |
| `burn_policy` | The active burn policy — `amount > 0` and `amount ≥ minBurnSize`. |
| `domain_config` | The owner-gated, init-once four-field domain configuration. |
| `attester_admin` | The owner-gated `set_attester` allowlist setter. |
| `min_burn_admin` | The owner-gated `set_min_burn_size` setter. |
| `pause_admin` | The `DOM_PAUSER`-gated custom pause / unpause. |
| `xreserve_mint_note_entry` | The account-side transport shim (`receive_and_mint`) the mint note calls into. |
| `encoding/` | The shared encoding library (`xreserve::encoding::*`): bytes32→key hashing, uint256→amount reduction, DepositIntent parse, pubkey commitment. Owned by the encoding crate; the faucet consumes it by reference. |

### `notes/` — the note scripts

Public note scripts that drive account procedures when consumed: the mint note
(`xreserve_mint_note`), and the admin notes (`domain_init`, `set_attester`, `set_min_burn_size`,
`pause`/`unpause`, role management, ownership transfer). The mint note is a thin transport into
`receive_and_mint`; the admin notes cross into the account and call the matching setter.

## 3. Mint

A relayer submits a DepositIntent (the Circle-attested deposit record) plus an attestation
attachment (fee amount, attester pubkey, signature). The mint runs as a strict
**verify-once-then-write-once** pipeline; any verify failure aborts the whole transaction with
no writes, so a failed mint never consumes the nonce.

1. **Pause gate** — a paused faucet must not mint (`assert_not_paused` runs first, because the
   custom mint bypasses the stock policy where the pause check normally lives).
2. **`D5a` — structural + addressing** (`R-MINT-1..8`): parse the fixed-offset DepositIntent
   header; check magic, version, non-zero `amount`/`localToken`/`localDepositor`, the length
   relation, and that the intent's `remoteDomain`/`remoteToken` match the faucet's configured
   domain/identifier.
3. **`D5b` — amount/fee** (`R-MINT-9..11`): reduce `amount`, `maxFee`, and the operator
   `feeAmount` from uint256 to an `AssetAmount`; require `amount ≥ maxFee`. In the MVP the
   operator `feeAmount` must be zero (see fee handling below).
4. **`D5c` — replay** (`R-MINT-12`): derive the nonce key and assert `usedNonces[key]` is empty.
   This stage only reads; the nonce is marked used later, in `D5e`.
5. **`D5d` — attestation** (`R-MINT-13..14`): keccak the full payload, require the attester's
   pubkey commitment to be enabled in the `xReserveAttesters` allowlist, and ECDSA-verify the
   signature over the digest. The same pubkey region feeds both the allowlist lookup and the
   signature check, so an allowlisted pubkey cannot be paired with a foreign signature.
6. **`D5e` — effects** (`R-MINT-15`): guard `token_supply + amount ≤ max_supply` (before any
   write), then apply the atomic effects in order — mark the nonce used, emit a P2ID recipient
   note carrying `amount − feeAmount` of xUSDC to the recipient AccountId, and raise
   `token_supply` by the full `amount`.

The stock `mint_and_send` path is denied (`R-MINT-16`), which makes `xreserve_mint` provably the
only supply-increasing surface (`INV-MINT-SECURITY`). This property is proved at the
procedure-root level, not by inspecting a single instruction.

**Fee handling.** The MVP mints a single recipient note and raises supply by the full amount, so
a non-zero fee would over-count supply against the minted assets. Both the parser and the
effects assert `feeAmount == 0`. When Circle confirms the relayer-fee design (DEV-8), the
`feeAmount ≤ maxFee` compare and a relayer-credit note leg are restored.

**Attestation model** (DEV-1, `INV-NO-ECRECOVER`): Miden has no `ecrecover`, so the signer is
not recovered on-chain. Instead the relayer supplies the candidate pubkey, the faucet checks a
`Poseidon2(pubkey)` commitment against an allowlist, and verifies the raw secp256k1 signature
over `keccak256(payload)` (65-byte `r‖s‖v`, `v` unused; not EIP-712).

## 4. Burn

A holder creates a public `XReserveBurnNote` carrying `(amount, destDomain, destRecipient,
salt)` in the note's storage items, with the depositor in `metadata.sender`. Creating the note
moves the assets out of the holder's vault, so the holder's balance is checked at **creation**
(`R-BURN-5`), not re-checked at consume.

The faucet consumes the note in a **later block** (`receive_and_burn`, block ≥ N+1). The stock
burn wrapper checks pause first (`R-BURN-3`), then dispatches the custom burn policy, which
requires `amount > 0` (`R-BURN-1`) and `amount ≥ minBurnSize` (`R-BURN-2`). Consuming the note
decrements `token_supply`.

The note is always **Public** (`R-BURN-6`, `INV-PUBLIC-BURN-OBSERVABILITY`) so the burn is
observable to Circle. A same-block create+consume erases the note with no store record, making
the burn unverifiable (`R-BURN-4`); the design requires the two-block discipline. Exactly how a
completed burn is proven to Circle (the burn-evidence package) is OPEN (DEV-7, finding `F7`).

## 5. Admin

- **Ownership**: `Ownable2Step` (two-step owner transfer).
- **Owner-gated setters**: `set_attester` (allowlist), `set_min_burn_size`, and `domain_init`
  are gated on the account owner. They are intentionally **not** pause-gated (finding `F6`), so
  the owner can, e.g., disable a compromised attester while the faucet is paused.
- **Pause**: `pause`/`unpause` are gated on the `DOM_PAUSER` role (not the owner) — Circle's
  distinct-pauser-role model. A pause halts both mint and burn-consume.
- **Roles**: role-based access control with a `DOM_MANAGER` role that administers `DOM_PAUSER`.
  Since v16 (protocol #3215) the stock RBAC gates `grant_role`/`revoke_role`/`set_role_admin` on
  the managed role's *effective admin* — its delegated admin role, else the built-in `ADMIN`,
  which the builder seeds to the owner's account — so membership rotation runs owner (`ADMIN`) →
  `DOM_MANAGER` → `DOM_PAUSER`. (`ADMIN` membership is account-bound: it does not auto-follow an
  ownership transfer — the ratified rotation runbook re-seats it via grant/revoke; see
  `IMPL-DEV-23`.) The delegation graph itself is **build-seeded and frozen**: the
  runtime `set_role_admin` note was removed from the note-script allowlist (S21 disposition flip,
  human-ratified 2026-07-14), so no on-chain sender can re-point or clear any role's admin. The
  stock `rbac::set_role_admin` procedure remains composed but is present-but-unreachable
  (`tests/account_callable_surface.rs`), and role rotation is `grant_role`/`revoke_role` only —
  matching Circle's fixed `DomainManageable.sol` admin graph (see `IMPL-DEV-24` in the glossary).
- **Domain config** (`domain_init`, `R-ADMIN-4`): a single init-once write of four fields —
  `domain` and `identifier` (read by the mint's `D5a` compare) plus `source_domain` and
  `xreserve_contract` (deploy-time identity, read off-chain). The `identifier` slot doubles as
  the init-once sentinel, so a second init traps.

## 6. Domain-config field representation

`identifier` is stored as the Poseidon2 bytes32→key Word, because the mint compares the hashed
form. `xreserve_contract` is stored losslessly as its raw 8×u32-LE packed limbs across two value
slots, because it has no on-chain compare and must be readable from storage by off-chain
services. `domain` and `source_domain` are u32 scalars in element 0 of their slot words. Every
scalar and every packed limb is u32-checked before any write.

## 7. What is consumed from the encoding library

The faucet does not re-implement encoding. It consumes `xreserve::encoding::*` by reference:
`bytes32_to_key` (nonce/identifier keying), `uint256_to_asset_amount` (amount reduction),
`parse_deposit_intent` (structural parse), `pubkey_commitment` (attester keying). See the
encoding spec at `docs/spec/ENCODING-COMPONENT-SPEC.md` and the data contracts `DC-1..DC-7` in the
glossary.

## 8. Invariants (see the glossary for the full list)

The security-critical properties this component upholds: `INV-MINT-SECURITY` (sole supply
surface, attestation-gated), `INV-SUPPLY-CONSERVATION` (supply moves exactly once per op),
`INV-NONCE-REPLAY` (assert-zero-then-set), `INV-PUBLIC-BURN-OBSERVABILITY`, `INV-TWO-BLOCK-BURN`,
`INV-NO-ECRECOVER`, `INV-PAUSE`, and the encoding invariants (`INV-DEPOSITINTENT-PARSE`,
`INV-UINT256-TO-ASSETAMOUNT`, `INV-BYTES32-HASH-TO-WORD`, `INV-ACCOUNTID-ENCODING`).

## 9. Validation

Behaviour is checked at two levels: the `xusdc-encoding` crate assembles and **executes** the
MASM under a mock chain (unit and cross-implementation "Rust == MASM" tests), and the
`xusdc-validation` crate runs the whole mint/burn/admin matrix against a **real local node** (the
`LNV` rows `A`–`L`). The real-node matrix is the acceptance gate; its PASS verdict is a human
decision, never self-declared.

## 10. Open items

Everything Circle still owns stays OPEN and is not marked approved: the AccountId↔bytes32
encoding (DEV-10), the amount cap/scale (DEV-5), the `hookData` bound (DEV-6), the
burn-evidence package (DEV-7), the relayer-fee design (DEV-8), the nonce keying
(DEV-9), the assigned domain id (`Q-DOM-1`), and the attester quorum (`Q-DA-QUORUM`). See the
glossary and `docs/spec/ENCODING-COMPONENT-SPEC.md` for the encoding-side open decisions.
