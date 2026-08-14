# xUSDC shared encoding — component specification

This is the specification for the shared encoding layer: the codecs that translate between
Circle's external wire formats (bytes32, uint256, secp256k1 attestations, the DepositIntent
message, the burn-note payload) and Miden's on-chain types (felts, Words, `AssetAmount`,
`AccountId`). It is written to match the shipped code:

- **Rust:** `crates/xusdc-encoding/src/xreserve/encoding/` (`bytes32.rs`, `amount.rs`,
  `account_id.rs`, `attestation.rs`, `deposit_intent.rs`, `mint_intent.rs`, `burn_note.rs`,
  `error.rs`).
- **MASM:** `crates/xusdc-encoding/asm/xreserve/deposit_intent.masm` (the `DC-1` wire layout, the shared codecs,
  and `rebuild` — the faucet-owned `DC-14` writer), `crates/xusdc-encoding/asm/xreserve/mint_intent.masm`
  (the `DC-14` carried shape, plus the checks and the nonce hash that read it), and
  `crates/xusdc-encoding/asm/xreserve/packed_mem.masm` (the layout-agnostic primitives `rebuild` writes the
  packed region with). There is no `encoding/` submodule: a format's constants and the procedure
  that realizes them live together.

Two codecs are implemented on **both** sides: the bytes32 hash-to-Word and the attestation
staging each have a Rust and a MASM leg, and a
cross-implementation suite (`TV-DUAL-1`, `-5`) proves the two agree on every golden
vector. The **burn-note payload codec (`DC-7`) is Rust-only** — there is no MASM burn-item codec — so
its vector (`TV-DUAL-4`) is an emit-vs-codec check within Rust (the Rust-created burn note vs the Rust
codec vs the golden felts), not a Rust↔MASM comparison. The faucet consumes the MASM side by
reference; the off-chain services consume the Rust side.

Short identifiers (`DC-1`, `TV-AMT-3`, `NS-1`, …) are defined in `docs/spec/GLOSSARY.md`.

## Data contracts

The codec decisions the crate owns are `DC-1`..`DC-7` plus `DC-14` (see the glossary for one-line
definitions). In summary:

| Contract | What it encodes |
|---|---|
| DC-1 | **DepositIntent** — a fixed 240-byte big-endian header + variable `hookData`; on-chain it is 60 u32-LE-packed felts (4 wire bytes per felt). Field offsets are in `deposit_intent.masm` / `deposit_intent.rs`. |
| DC-2 | **depositAttestation** — the raw 65-byte `r‖s‖v` secp256k1 signature over `keccak256(payload)` (not EIP-712). |
| DC-3 | **Attester commitment** — `Poseidon2(affine pubkey, 16 u32-LE felts: qx_le_u32[8] ‖ qy_le_u32[8])` → one Word, used as the `xReserveAttesters` allowlist key. The Circle-facing ingress form stays the 33-byte compressed SEC1 pubkey; the SEC1→affine decompression is the protocol's own (v16 supersession, vm#3342 — the v15 preimage was the 33 compressed bytes as 9 felts). |
| DC-4 | **Nonce keying** — the DepositIntent `nonce` (bytes32) → Poseidon2 hash-to-Word → storage-map key. |
| DC-5 | **amount/fee reduction** — a uint256 → `AssetAmount`: byte-swap to numeric order, assert the high half is zero, floor-divide by `10^scale_exp`, and reject if the quotient exceeds `AssetAmount::MAX`. It traps; it never saturates. |
| DC-6 | **AccountId ↔ bytes32** — the right-aligned layout (16 zero bytes ‖ prefix u64 BE ‖ suffix u64 BE); lossless, fail-closed decode. See `DEV-10` (OPEN). |
| DC-7 | **Burn-note payload** — `(amount, destDomain, destRecipient, salt)`, carried in a scheme-tagged note attachment. Shipped Rust-only; there is no `burn_items.masm`. Felt count, field offsets, attachment scheme, word count and slot order: see `DC-7` in `docs/spec/GLOSSARY.md`. |
| DC-14 | **Mint intent + DepositIntent reconstruction** — the mint note carries only the DepositIntent fields the faucet cannot derive; the faucet rebuilds the signed `DC-1` preimage before hashing it. See *Reconstruction reference* below. |

## Core routines

| Routine | Contract |
|---|---|
| `hash_nonce` (MASM) / `bytes32_to_storage_map_key` (Rust) | Poseidon2 `hash_elements` over the 8 u32-LE limbs of a bytes32 → one canonical Word. The raw fallible `TryFrom<[u8;32]>` is **not** used on this path (`NS-1`, `DC-4`, `INV-BYTES32-HASH-TO-WORD`). |
| `pubkey_commitment` (MASM) / `PublicKey::to_commitment` (Rust) | Poseidon2 over the 16 u32-LE affine-coordinate limbs of the pubkey → the allowlist commitment Word (`DC-3`; sponge capacity domain tag `16 % 8 = 0`). The Rust side IS miden-crypto's `ecdsa_k256_keccak::PublicKey` — this crate mirrors no part of it: the 33-byte compressed wire key is read with the stock `Deserializable`, `SequentialCommit::to_elements` gives the 16 affine felts, and `to_commitment` gives the Word. The MASM side hashes the 16 already-staged felts. |
| `uint256_to_asset_amount` (Rust) | The `DC-5` reduction (`INV-UINT256-TO-ASSETAMOUNT`), `y = floor(x / 10^DEPOSIT_SCALE_EXP)`. The scale is not a parameter: `DEPOSIT_SCALE_EXP` is the crate's single constant, fixed at `0` because `DC-14`'s zero-extension is invertible at no other scale, and it is applied here rather than threaded through callers. The arithmetic IS the standards' `EthAmount::scale_to_asset_amount`, called directly; this routine only adapts it to `EncodingError`. **Rust-only:** the MASM witness verifier is removed, because under `DC-14` the uint256 never reaches the chain — see the ownership map's `DC-5` rider before reopening `DEV-5`. |
| `DepositIntent` `Deserializable` / `TryFrom<&[u8]>` (Rust) | Structural DepositIntent validation (magic, version, non-zero `amount`/`localToken`/`localDepositor`, the length relation, the hookData bound), and the narrowing of every field to the domain type a mintable deposit must hold: the bytes32 identifiers as account ids, the source-chain fields as EVM addresses, the two uint256 amounts through `uint256_to_asset_amount`. Circle's encoder can emit opaque bytes32 in the identifier fields and how an AccountId is registered into them stays OPEN (`DEV-10`, `Q-EVM-ADDR-1`) — but a deposit whose identifiers do not read as account ids is unmintable under any layout, so it is refused here rather than carried. The `DepositIntentHeader` owns its own `Serializable`/`Deserializable` for the field block; `DepositIntent` adds `hookDataLen` and the tail. **Rust-only since `DC-14`** — the on-chain parser is retired (`NS-2`), because the faucet writes those fields instead of reading them. It is the compress-side entry and the relayer's pre-validate (`INV-DEPOSITINTENT-PARSE`). |
| `MintIntent::to_deposit_intent` (Rust) / `rebuild` (MASM) | The `DC-14` reconstruction (`NS-3`). Both take the carried payload plus the three derived values and produce the canonical `240 + hookDataLen` bytes — on the Rust side by rebuilding the `DepositIntent`, whose own `Serializable` owns the byte layout; the MASM side writes them as u32-LE-packed felts straight into the region keccak will hash. The conformance property is the round trip, not a field-by-field compare — see *Reconstruction reference*. |
| AccountId ↔ bytes32 (`account_id.rs`) | The `DC-6` lossless encode/decode with a fail-closed inverse. The ENCODE is the stock `EthEmbeddedAccountId::to_bytes32`, called directly; only the decode is this crate's, as an extension trait on the same stock type. |
| Burn-note items (`burn_note.rs`) | The `DC-7` deterministic encode/decode. |

## Reconstruction reference (`DC-14`)

A mint note no longer contains the message its signature covers, so this section is what a third
party needs in order to check one. Given a mint note and the faucet's account id and configured
domain, the signed bytes are recoverable exactly.

**Mint intent**, 24 felts starting at word 9 of the scheme-4 transport attachment, followed by
`ceil(hookDataLen / 4)` packed `hookData` felts:

| felt | field |
|---|---|
| 0..8 | `nonce`, 8 u32-LE-packed limbs |
| 8..13 | `localToken`, the address's 20 bytes as 5 packed limbs |
| 13..18 | `localDepositor`, likewise |
| 18, 19 | `remoteRecipient` as an `AccountId` — `[prefix, suffix]`, not bytes32 |
| 20 | `maxFee` as an `AssetAmount` felt |
| 21 | `hookDataLen`, a semantic u32 |
| 22..24 | zero padding to the word boundary |

**Rebuild** the `DC-1` preimage as `240 + hookDataLen` big-endian bytes. Every byte not named below
is zero:

| wire bytes | value |
|---|---|
| 0..4 | `magic` |
| 4..8 | `version` |
| 32..40 | the note's asset amount, as a big-endian u64 (bytes 8..32 stay zero — this is the uint256 zero-extension, exact only because `DEPOSIT_SCALE_EXP == 0`) |
| 40..44 | the faucet's configured `remoteDomain` |
| 60..76 | the faucet's own account id, `prefix` then `suffix`, each a big-endian u64 (`DC-6` right-aligned in the `remoteToken` bytes32) |
| 92..108 | the carried `remoteRecipient`, same packaging |
| 120..140 | the carried `localToken`, right-aligned in its bytes32 |
| 152..172 | the carried `localDepositor`, likewise |
| 196..204 | the carried `maxFee`, as a big-endian u64 right-aligned in its uint256 |
| 204..236 | the carried `nonce` |
| 236..240 | `hookDataLen` |
| 240.. | `hookData` |

`feeAmount` does not appear: it is not part of the `DC-1` message and no longer travels on the wire.

The digest is then plain `keccak256` over those bytes (`DC-2` — no EIP-712 domain, no prefix), and
the attestation is the raw 65-byte `r‖s‖v` over it.

**What makes this sound.** Every carried field lands in exactly one disjoint byte range at a fixed
offset, and each is bounded by its own type — so distinct payloads always produce distinct
preimages, and one signature can never authorize two different mints. Conversely, a field the faucet
writes cannot diverge from what Circle signed without changing the digest. The property worth
testing is therefore the round trip (`TV-DUAL-6`), not a field-by-field comparison.

## Validation order

- **DepositIntent parse** (`§8.1` of the old spec; now `INV-DEPOSITINTENT-PARSE`): bounds/truncation
  guard first, then magic, version, non-zero fields, then the `len == 240 + hookDataLen` relation.
- **DepositIntent reconstruction** (`DC-14`): bind the attachment's committed word count to the
  carried `hookDataLen` **first** — the writer copies `hookData` out of that region, so an
  overstated length would otherwise read past what the note committed to — then derive and range-check
  the amount, then write. Every felt of the region is written before it is read, so no value can
  survive from an earlier call.
- **uint256 → AssetAmount** (`DC-5`): guard limbs are valid u32s → assert the high half is zero →
  take the low half as u128 → floor-divide by `10^scale_exp` → cap at `AssetAmount::MAX`.

## Testing

- **Unit / vector tests** per codec (`TV-B32-*`, `TV-AMT-*`, `TV-AID-*`, `TV-DI-*`, `TV-BN-*`,
  `TV-ATT-*` — see the glossary).
- **Rust↔MASM agreement** (`TV-DUAL-1`/`-2`/`-3`/`-5`, in `tests/masm_dual.rs`): the Rust codec and
  the assembled-and-executed MASM must produce the identical Word / amount / accept-reject on every
  vector. The MASM tests **execute** (not merely assemble). `TV-DUAL-4` is the burn-note vector; since
  `DC-7` has no MASM side it checks Rust emit-vs-codec parity (in `tests/xreserve_burn.rs`) instead.
  `TV-DUAL-6` covers `DC-14` in `tests/masm_mint_shell.rs`: the Rust round trip, MASM/Rust preimage
  parity, per-field placement, and that the writer overwrites a deliberately poisoned region. Its
  vector rows are generated for one fixed synthetic faucet id and domain, because the real id is a
  hash over the account's own code — see the ownership map's anti-duplication note.
- Golden vectors are generated by `crates/xusdc-encoding/src/bin/gen_vectors.rs`; constant parity
  between the Rust and MASM constants is enforced by `tests/constant_parity.rs`.

## Open items

The encoding layer inherits the Circle-owned OPEN decisions: the amount cap/scale (`DEV-5`), the
`hookData` bound (`DEV-6`), the AccountId↔bytes32 encoding (`DEV-10`), the nonce keying
(`DEV-9`), and the 20-byte-EVM-address assumption `DC-14` rests on (`Q-EVM-ADDR-1`). None are
marked approved. See the glossary.

`DEV-5` and `DEV-10` now constrain the **wire format** through `DC-14`, not just a validation rule:
resolving either against the current assumption requires a new transport, because the faucet emits
those encodings rather than reading them. `Q-EVM-ADDR-1` is the same shape. `DEV-6` is unaffected —
`hookData` still travels, and its bound is still the open question.
