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
**DepositIntent**, and burns xUSDC when a holder withdraws. Since the Wave-1 S1 recomposition it
is built the way the canonical stock bridge faucet is built — **stock transport and effects,
custom policies as the gates**:

- Mints ride the **stock `MintNote` + stock `mint_and_send`**; the ENTIRE attestation gate
  (`D5a`–`D5d` plus the ratified assert-match binding) is the faucet's active **attestation mint
  policy** (`mint_policy::check_policy`), dispatched fail-closed by the stock policy manager on
  every mint. Every supply increase passes the attestation policy (`INV-MINT-SECURITY`,
  restated); the former mint-deny guard dissolved — its job (trapping the stock path) dissolved
  because the stock path IS now the gated path.
- Burns run through the standard `receive_and_burn` path gated by the **stock `MinBurnAmount`
  policy** with the floor seeded `≥ 1` (builder-rejected below 1; the admin note asserts the
  same floor), which preserves the former `amount > 0` zero-burn invariant by construction.

The account is `AccountType::Public`, 6-decimal, symbol "xUSDC". The Rust
`XReserveStablecoinBuilder` (in `crates/xusdc-encoding`) composes the account and rejects an
invalid wiring (e.g. a faucet whose active mint policy is not the attestation policy, a zero
min-burn floor, a missing domain-config seed, or a non-Public faucet) at build time.

## 2. On-chain modules (`asm/standards/`)

### `xreserve/` — the faucet account component

| Module | Role |
|---|---|
| `mint_policy` | The **attestation mint policy** (`check_policy`, the ACTIVE mint policy the stock `mint_and_send` dispatches): reads the mint note's DepositIntent + attestation attachments (hash-verified), runs `D5a`–`D5d` by reference, enforces the assert-match binding (note-claimed recipient/amount/tag/type must equal their attested derivations), and marks the nonce used — its only state write. |
| `deposit_intent_parser` | The faucet-side mint preconditions behind the single `validate` entry (`D5a`/`D5b`/`D5c`): the staged length derivation and its word-count binding, domain/identifier compares, amount/fee bounds, nonce replay guard. The identifier comparand is DERIVED here from the native account id (`compute_own_id_bytes32`) and compared as packed bytes32 limbs, not read from storage and not hashed. Delegates the structural DepositIntent parse to the encoding library. |
| `attestation_verify` | The attestation check (`D5d`): keccak the payload, gate the attester pubkey against the allowlist, ECDSA-verify the signature. |
| `attester_admin` | The authority-gated `set_attester` allowlist setter. |
| `encoding/` | The shared encoding library (`xreserve::encoding::*`): bytes32→key hashing, uint256→amount reduction, DepositIntent parse, pubkey commitment. Owned by the encoding crate; the faucet consumes it by reference. |

The burn floor and its setter are **stock**: the `MinBurnAmount` policy component carries the
floor slot, its `check_policy` is the active burn policy, and the admin note calls its stock
`set_min_burn_amount` (behind the note-side floor guard).

### `notes/` — the note scripts

Public note scripts that drive account procedures when consumed. The mint note is the **stock
miden-standards `MintNote`** (no custom mint script exists); the faucet-owned admin notes are thin,
root-pinned scripts (`set_attester`, `set_min_burn_size` — which asserts the
floor then calls the stock `set_min_burn_amount` —, and `set_max_supply`) that cross into the
account and call the matching setter. Pausing, the transfer blocklist and role management ship
**no faucet-owned script**: they use the stock `PauseActionNote`, `BlocklistConfigNote` and
`RbacActionNote`, each of which covers every one of its actions behind one script root and calls the
stock component the account installs. There is no ownership note — the faucet installs no ownership
component.

## 3. Mint

A relayer submits a **stock `MintNote`** whose storage embeds the attested output (the P2ID
recipe to the intent's recipient with the nonce-key serial, the reduced amount as this faucet's
asset, the recipient's account-target tag) and whose attachments carry the Circle-signed
transport: the DepositIntent preimage (scheme 4), the attestation `[feeAmount, pubkey,
signature]` (scheme 5), and the network routing target (scheme 2). The stock MINT script calls
the stock `mint_and_send`, which dispatches the **attestation mint policy** first; the policy
runs a strict **verify-once-then-write-once** pipeline, and any failure aborts the whole
transaction with no writes, so a failed mint never consumes the nonce.

1. **Pause gate** — the stock policy dispatcher runs `assert_not_paused` before the policy, so a
   paused faucet never even dispatches the attestation gate.
2. **Transport shape** — the policy locates the three attachments (exactly three, one per
   scheme) and hash-verifies the intent and the 11-word attestation into two of its own local
   regions. It hands the intent's committed word count to `D5a`, which binds it to the intent's
   own embedded `hookDataLen`. Every verify stage below then reads those two regions by pointer.
   Nothing is read back from the advice provider, so what the note committed to is exactly what
   gets verified.
3. **`D5a` — structural + addressing** (`R-MINT-1..8`): derive the preimage length from the
   embedded `hookDataLen` and bind it to the committed word count; parse the fixed-offset
   DepositIntent header; check magic, version, non-zero `amount`/`localToken`/`localDepositor`,
   the length relation, and that the intent's `remoteDomain`/`remoteToken` match the faucet's
   configured domain/identifier.
4. **`D5b` — amount/fee** (`R-MINT-9..11`): reduce `amount`, `maxFee`, and the operator
   `feeAmount` from uint256 to an `AssetAmount`; require `amount ≥ maxFee`. In the MVP the
   operator `feeAmount` must be zero (see fee handling below).
5. **`D5c` — replay** (`R-MINT-12`): derive the nonce key and assert `usedNonces[key]` is empty.
6. **`D5d` — attestation** (`R-MINT-13..14`): keccak the full payload, require the attester's
   pubkey commitment to be enabled in the `xReserveAttesters` allowlist, and ECDSA-verify the
   signature over the digest. The same pubkey region feeds both the allowlist lookup and the
   signature check, so an allowlisted pubkey cannot be paired with a foreign signature.
7. **Assert-match binding** (ratified): the policy rebuilds the note-creation arguments with the
   standard `p2id::prepare_note` over the attested target and the nonce-key serial, and every
   value the note supplied must equal what that recipe returns — `RECIPIENT` (one word compare
   covering script root, storage target, and serial policy), the tag (the attested recipient's
   account target), and the note type (public). The asset value must be
   `[attested amount, 0, 0, 0]`. The policy never overrides — it keeps the note
   honest.
8. **Nonce write** — the policy marks the nonce used (its ONLY state write), then returns.
9. **Stock effects** (`R-MINT-15` semantics, stock-owned): `mint_and_send` enforces the supply
   cap discipline, binds the note's asset to this faucet, creates the recipient note, mints, and
   raises `token_supply` — the same audited implementation every stock faucet runs.

The former deny guard is gone by construction: with the attestation policy as the ACTIVE mint
policy and the allowed-mint set exactly `{that root}`, every supply increase passes the
attestation policy (`INV-MINT-SECURITY`, restated), and an execution without the attested note
transport (e.g. a bare tx-script `mint_and_send`) fail-closes in the policy's kernel reads.

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
burn wrapper checks pause first (`R-BURN-3`), then dispatches the **stock `MinBurnAmount`**
policy, which requires `amount ≥ minBurnSize` (`R-BURN-2`); the floor is `≥ 1` at all times
(builder-rejected below 1 at composition, note-guarded at the only runtime setter path), so a
zero-amount burn is unacceptable on every path (`R-BURN-1` preserved by construction). Consuming
the note decrements `token_supply`.

The note is always **Public** (`R-BURN-6`, `INV-PUBLIC-BURN-OBSERVABILITY`) so the burn is
observable to Circle. A same-block create+consume erases the note with no store record, making
the burn unverifiable (`R-BURN-4`); the design requires the two-block discipline. Exactly how a
completed burn is proven to Circle (the burn-evidence package) is OPEN (DEV-7, finding `F7`).

## 5. Admin

- **Ownership**: none. There is no `Ownable2Step` component and no owner slot; the built-in `ADMIN`
  role is the account's single authority handle, and rotating it is a grant and a revoke of that
  role through the standard role-action note. The handover is single-step — there is no
  nominate-then-accept confirmation.
- **Administrator-gated setters**: `set_attester` (allowlist), the stock
  `set_min_burn_amount` (behind the note-side floor guard) and `set_max_supply` all resolve through
  the account-wide authority to the `ADMIN` role. They are
  intentionally **not** pause-gated (finding `F6`), so the administrator can, e.g., disable a
  compromised attester while the faucet is paused.
- **Pause**: the stock `PausableManager`'s `pause`/`unpause`, gated on the `DOM_PAUSER` role (not
  the administrator) — Circle's distinct-pauser-role model, expressed through the account's per-procedure
  role map rather than a hand-written wrapper. A pause halts both mint and burn-consume.
- **Transfer blocklist**: the stock `BlocklistManager`'s `block_account`/`unblock_account`, gated on
  the `BLK_MANAGER` role held by an external administrator with no other capability. The stock
  procedure does not validate its target, so blocking the faucet against itself is reachable on
  chain; the faucet's note factory refuses to build such a note, and the state is recoverable with
  an unblock note (which carries no assets, so no transfer policy runs).
- **Authority**: `Authority::RbacControlled`. The four manager procedures above carry their roles in
  the account's procedure-role map; every other authority-gated procedure carries none and so
  resolves to the built-in `ADMIN` role, whose sole seeded member is the bootstrap administrator's
  account. That keeps the administrator-gated setters with one holder while keeping pausing and
  blocklisting away from it. `ADMIN` membership is account-bound: it is the whole of the faucet's
  administrative authority, with no second handle behind it.
- **Roles**: role-based access control with a `DOM_MANAGER` role that administers `DOM_PAUSER`.
  Since v16 (protocol #3215) the stock RBAC gates `grant_role`/`revoke_role`/`set_role_admin` on
  the managed role's *effective admin* — its delegated admin role, else the built-in `ADMIN`,
  which the builder seeds to the bootstrap administrator's account — so membership rotation runs
  `ADMIN` → `DOM_MANAGER` → `DOM_PAUSER`. Role management is the **standard role-action note**,
  whose single script root carries `grant_role`, `revoke_role`, `set_role_admin` and
  `renounce_role` alike; allowlisting is per root, so admitting it admits all four. Two
  consequences are accepted and pinned by test. The delegation graph is **runtime-mutable**: a
  role's effective admin may re-point the role it administers, and because delegation is exclusive,
  `ADMIN` has no authority at all over a role that was delegated away (`DOM_MANAGER`, not `ADMIN`,
  governs `DOM_PAUSER`). And any holder may **renounce** its own membership, ungated — including
  the sole `ADMIN`, which empties the role permanently, since the role administers itself and
  nobody would be left to grant it back. Recovery from that state is a redeploy. See
  `IMPL-DEV-24` in the glossary; the seam is driven end to end in
  `tests/w2admin_surface_finalization.rs`.
- **Domain config** (`R-ADMIN-4`; `DEC-4` REVERSED 2026-08-03): `domain`, `source_domain`, and
  `xreserve_contract` are **build-seeded** by the account builder, and there is no runtime writer
  for any of them. The `identifier` has no slot at all. The account id derives from the initial
  storage commitment, so the faucet's own id could never be seeded into that storage — rather than
  writing it after deployment, the mint path DERIVES it at check time from
  `native_account::get_id` (`account_id_to_bytes32(get_id())`, the provisional `Q-CRY-4` own-id
  position, enforced but still Circle-OPEN) and compares the packed bytes32 directly. Nothing has to be initialized, so a
  freshly deployed faucet mints immediately and there is no pre-init window to front-run. See
  `DECISION-DEC4-REVERSAL-IDENTIFIER-DERIVE.md`.

## 6. Domain-config field representation

`identifier` is not stored at all — the mint path derives it, in the packed bytes32 limb form the
compare uses (no hash on either side). `xreserve_contract` is stored losslessly as its raw 8×u32-LE packed limbs across two value
slots, because it has no on-chain compare and must be readable from storage by off-chain
services. `domain` and `source_domain` are u32 scalars in element 0 of their slot words. The
three build-seeded fields are typed u32/bytes32 at the builder boundary (Rust-validated); the
identifier needs no validation at all, since the only value it can ever take is the account's own
id, and the MASM derivation is byte-parity-proven against the Rust `account_id_to_bytes32`
encoder (`tests/own_id_identifier_derive.rs`).

## 7. What is consumed from the encoding library

The faucet does not re-implement encoding. It consumes `xreserve::encoding::*` by reference:
`bytes32_to_key` (nonce keying), `verify_uint256_to_asset_amount` (the amount
witness verify), `pubkey_commitment` (attester
keying). See the
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
