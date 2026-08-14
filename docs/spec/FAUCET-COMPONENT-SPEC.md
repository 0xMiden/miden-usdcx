# xUSDC faucet — on-chain component specification

This is the specification for the on-chain part of Circle's **xReserve / xUSDC** on Miden: the
hand-written-MASM faucet account and its note scripts. It is written to match the **shipped
code** in `crates/xusdc-encoding/asm/`; where the code takes a provisional position on an item Circle has
not yet confirmed, that is called out as OPEN (see `docs/spec/GLOSSARY.md`, `DEV-*`/`Q-*`).

Short identifiers used below (`R-MINT-15`, `INV-MINT-SECURITY`, …) are defined once in
`docs/spec/GLOSSARY.md`.

## 1. What this component is

xUSDC is a Miden **fungible faucet** account. Native USDC stays locked 1:1 in Circle's xReserve
contract on the source chain; this faucet mints xUSDC on Miden against a Circle-attested
**DepositIntent**, and burns xUSDC when a holder withdraws. It is built the way the canonical stock
bridge faucet is built: **stock transport and effects, custom policies as the gates**.

- Mints ride the **stock `MintNote` + stock `mint_and_send`**; structural, amount, replay, and
  attestation checks plus the assert-match binding form the faucet's active **attestation mint
  policy** (`mint_policy::check_policy`), dispatched fail-closed by the stock policy manager on
  every mint. Every supply increase passes the attestation policy (`INV-MINT-SECURITY`) because
  the stock path is now the gated path.
- Burns run through the standard `receive_and_burn` path gated by the **stock `MinBurnAmount`
  policy** with the floor seeded `≥ 1` (builder-rejected below 1; the admin note asserts the
  same floor), which preserves the `amount > 0` zero-burn invariant by construction.

The account is `AccountType::Public`, 6-decimal, symbol "xUSDC". The Rust
`XReserveStablecoinBuilder` (in `crates/xusdc-encoding`) composes the account and rejects an
invalid wiring (e.g. a faucet whose active mint policy is not the attestation policy, a zero
min-burn floor, a missing domain-config seed, or a non-Public faucet) at build time.

## 2. On-chain modules (`crates/xusdc-encoding/asm/`)

### `xreserve/` — the faucet account component

| Module | Role |
|---|---|
| `mint_policy` | The **attestation mint policy** (`check_policy`, the ACTIVE mint policy the stock `mint_and_send` dispatches): reads and hash-verifies the mint note's transport attachment, binds its word count, rebuilds the signed DepositIntent preimage, runs the remaining validation stages, enforces that the note recipient, amount, tag, and type match their attested derivations, and marks the nonce used — its only state write. |
| `deposit_intent` | Circle's wire form and the faucet's on-chain realization of it. `rebuild` (`DC-14`) writes the message the attestation signed, from the note's mint intent plus the fields only this account can supply — the configured domain and its own account id, both read here rather than passed in, so no caller-supplied value can reach them. It also holds the `DC-5` reducer and declares the domain-config slot id. |
| `mint_intent` | What the mint note actually carries (`DC-14`): the carried felt offsets, the widths of the values they hold, and `validate` — the two preconditions the signature cannot express (the fee ceiling and the nonce replay guard), both statements about the carried fields alone. It hashes the carried nonce (`hash_nonce`) and declares the used-nonces slot id. |
| `packed_mem` | The primitives `rebuild` writes the u32-LE-packed region with: guarded limb copies, and the big-endian u64 / account-id stores. It knows no wire offsets, which is why it is separable from the layout at all. |
| `attestation_verify` | Keccaks the payload, checks the attester pubkey against the allowlist, and verifies the ECDSA signature. |
| `attester_admin` | The authority-gated `set_attester` allowlist setter. |

The burn floor and its setter are **stock**: the `MinBurnAmount` policy component carries the
floor slot, its `check_policy` is the active burn policy, and the admin note calls its stock
`set_min_burn_amount` (behind the note-side floor guard).

### `notes/` — the note scripts

Public note scripts that drive account procedures when consumed. The mint note is the **stock
miden-standards `MintNote`** (no custom mint script exists); the faucet-owned admin notes are thin,
root-pinned scripts (`set_attester`, `set_min_burn_size` — which asserts the floor then calls the
stock `set_min_burn_amount` —, and `set_max_supply`) that cross into the account and call the
matching setter. Pausing, the transfer blocklist and role management ship
**no faucet-owned script**: they use the stock `PauseConfigNote`, `BlocklistConfigNote` and
`RbacConfigNote`, each of which covers every one of its actions behind one script root and calls the
stock component the account installs. There is no ownership note — the faucet installs no ownership
component.

## 3. Mint

A relayer submits a **stock `MintNote`** whose storage embeds the attested output (the P2ID
recipe to the intent's recipient with the nonce-key serial, the reduced amount as this faucet's
asset, the recipient's account-target tag) and whose attachments carry the Circle-signed
transport: one merged attachment (scheme 4) containing `[pubkey, signature]` followed by the
**carried mint payload** and its `hookData` tail, plus the network routing target (scheme 2). The
stock MINT script calls the stock `mint_and_send`, which dispatches the **attestation mint policy**
first; the policy runs a strict **verify-once-then-write-once** pipeline, and any failure aborts the
whole transaction with no writes, so a failed mint never consumes the nonce.

The note does **not** carry Circle's DepositIntent. It carries only the fields the faucet cannot
derive, and the faucet rebuilds the signed preimage itself (`DC-14`). That is what makes most of the
addressing and structural validation below unnecessary: a field the faucet writes cannot disagree
with the attestation, because a divergent value produces a different digest. The trade — those
rejects stop being separately diagnosable — is spelled out under `R-MINT-*` in the glossary.

1. **Pause gate** — the stock policy dispatcher runs `assert_not_paused` before the policy, so a
   paused faucet never even dispatches the attestation gate.
2. **Transport shape** (`R-MINT-8`) — the policy locates exactly two attachments and hash-verifies
   the transport into one local region. Its first 9 words carry the fixed-width attestation, the
   next 6 the carried payload, and the rest the packed `hookData`. A floor check makes the fixed
   prefix readable, then the embedded `hookDataLen` is bound to the committed word count by an
   **exact** equality — so trailing padding cannot hide data, a smuggled section cannot ride along,
   and a length claim cannot reach past the committed bytes. This binding runs **before** anything
   reads the payload, because the reconstruction copies `hookData` out of that region. Nothing is
   read back from the advice provider, so what the note committed to is exactly what gets verified.
3. **Admissibility** (`R-MINT-3`, `R-MINT-10`, `R-MINT-12`): the policy takes the amount from the
   note's own asset value, pinning the asset word's upper elements zero, the amount non-zero and
   within the protocol's `FUNGIBLE_ASSET_MAX_AMOUNT` — the standards constant, not a local copy.
   (The stock `fungible_asset::value_into_amount` would have said all three in one call, but it is
   private in the pinned library and its public sibling `to_amount` documents that it does not
   validate.) `mint_intent::validate` then requires `amount ≥ maxFee`, a single felt compare — both
   values are `AssetAmount`s by construction — and asserts `usedNonces[hash_nonce]` is empty,
   handing back the hashed nonce the binding and the nonce write both need. Neither check needs the
   message, which is why both run before it exists: one relates the carried ceiling to the note's
   own asset, the other the carried nonce to this faucet's history. The operator `feeAmount` is not
   part of the message and is handled offchain, so there is no fee to check here (see fee handling
   below).
4. **Preimage reconstruction** (`DC-14`, subsuming `R-MINT-1..2` and `R-MINT-6..7`):
   `deposit_intent::rebuild` validates the carried recipient's account-id structure before writing
   it — a structurally invalid id would rebuild a perfectly consistent message and then mint a note
   nobody can consume, so that one cannot be left to the signature. The writer supplies `magic`,
   `version`, the amount, the configured `remoteDomain` and its own id as `remoteToken`; it copies
   the carried `localToken`, `localDepositor`, `remoteRecipient`, `maxFee`,
   `hookDataLen` and `hookData` into their canonical offsets, and writes an explicit zero into every
   other felt of the region. The identifier and the domain are read inside the writer, not passed to
   it.
5. **Attestation verification** (`R-MINT-13..14`): keccak the full **rebuilt** payload — the same
   `240 + hookDataLen` bytes Circle signed — require the attester's
   pubkey commitment to be enabled in the `xReserveAttesters` allowlist, and ECDSA-verify the
   signature over the digest. The same pubkey region feeds both the allowlist lookup and the
   signature check, so an allowlisted pubkey cannot be paired with a foreign signature.
6. **Assert-match binding** (ratified): the policy rebuilds the note-creation arguments with the
   standard `p2id::prepare_note` over the attested target and the nonce-key serial, and every
   value the note supplied must equal what that recipe returns — `RECIPIENT` (one word compare
   covering script root, storage target, and serial policy), the tag (the attested recipient's
   account target), and the note type (public). The asset value must be
   `[attested amount, 0, 0, 0]`. The policy never overrides — it keeps the note
   honest.
7. **Nonce write** — the policy marks the nonce used (its ONLY state write), then returns.
8. **Stock effects** (`R-MINT-15` semantics, stock-owned): `mint_and_send` enforces the supply
   cap discipline, binds the note's asset to this faucet, creates the recipient note, mints, and
   raises `token_supply` — the same audited implementation every stock faucet runs.

With the attestation policy as the active mint policy and the allowed-mint set exactly `{that root}`,
every supply increase passes the attestation policy (`INV-MINT-SECURITY`), and an execution without
the attested note transport (e.g. a bare tx-script `mint_and_send`) fail-closes in the policy's
kernel reads.

**Fee handling.** `feeAmount` is an argument of Circle's `mint` call, not a field of the
DepositIntent — the signed message carries only `maxFee`, the ceiling the depositor authorized. So a
fee is never attested, and the faucet has nothing to rebuild it from. Circle's mint spends it in one
place: the recipient is credited `amount − feeAmount`, a relayer is credited `feeAmount`, and supply
rises by the full `amount`. The MVP relayer charges nothing, so `feeAmount` is zero, every one of
those terms collapses onto what this faucet already does, and the value is carried nowhere.

A non-zero fee is therefore not a transport change. It splits one credit into two, which needs a
second output-note leg and an identified relayer to credit — a policy change, deferred with the
relayer-fee design (`CIR-FEE-2`, `DEV-8`, `Q-FEE-MVP`).

**Attestation model** (DEV-1, `INV-NO-ECRECOVER`): Miden has no `ecrecover`, so the signer is
not recovered on-chain. Instead the relayer supplies the candidate pubkey, the faucet checks a
`Poseidon2(pubkey)` commitment against an allowlist, and verifies the raw secp256k1 signature
over `keccak256(payload)` (65-byte `r‖s‖v`, `v` unused; not EIP-712).

## 4. Burn

A holder creates a public `XReserveBurnNote` carrying `(amount, destDomain, destRecipient,
salt)` in a scheme-tagged note attachment — for the felt count, field offsets, attachment scheme,
word count and slot order see `DC-7` in `docs/spec/GLOSSARY.md`. The depositor is in
`metadata.sender`. Creating the note
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
- **Administrator-gated setters**: `set_attester` (allowlist), the stock `set_min_burn_amount`
  (behind the note-side floor guard), `set_max_supply`, and the stock
  `ConstantFeeManager::set_note_fee` all resolve through
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
- **Domain config** (`R-ADMIN-4`): `domain`, `source_domain`, and `xreserve_contract` are
  **build-seeded** by the account builder and have no runtime writer. There is no identifier slot
  or init procedure: the mint path compares the decoded `remoteToken` directly with the faucet's
  native account id. The bytes32 packaging remains the provisional, Circle-OPEN `Q-CRY-4`
  position.

## 6. Domain-config field representation

The identifier is not stored: the mint path **writes** the native faucet account id into the
preimage as `remoteToken`, so there is nothing to compare and nothing that could have been seeded
wrong. `xreserve_contract` is a source-chain address, stored as the 8×u32-LE packed limbs of its
bytes32 across two value slots. `domain` and `source_domain` are u32 scalars in element 0 of their
slot words. The three build-seeded fields are typed u32/`ForeignChainAddress` at the builder
boundary; the address keeps the wire form's full 32 bytes, so a source chain whose addresses are
not EVM-shaped is expressible here — the same widening `DC-14` carries.

## 7. What is consumed from the encoding library

The faucet does not re-implement encoding. It consumes the shared codecs by reference:
`mint_intent::hash_nonce` (nonce keying), `attestation_verify::pubkey_commitment` (attester
keying), and the `DC-1` / `DC-14` felt offsets the preimage writer stores at. The `DC-5` amount reduction is not among them: with
`DEPOSIT_SCALE_EXP == 0` the faucet writes the amount from the note's own asset value rather than
verifying a witness against a staged uint256, so the MASM verifier had no caller and is deleted
(reopening `DEV-5` restores it from history — see the ownership map's `DC-5` rider). See the
encoding spec at `docs/spec/ENCODING-COMPONENT-SPEC.md` and the data
contracts `DC-1..DC-7` and `DC-14` in the glossary.

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

Two of these now bind the **wire format** rather than just a validation rule, which changes what it
costs to settle them. `DEV-5`: `DC-14` reconstructs the uint256 `amount` by zero-extending the
note's `AssetAmount`, which is lossless only while `DEPOSIT_SCALE_EXP == 0` — a non-zero scale
leaves the original value unrecoverable (the dropped dust is not carried), so it needs a new
transport, not a constant change. A parity assertion pins the constant to zero so the change fails a
test rather than shipping a broken digest. `DEV-10`: the faucet now **emits** the bytes32 AccountId
packaging instead of only reading it, so a change in Circle's packaging is likewise a transport
change.
