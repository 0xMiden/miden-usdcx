# xUSDC shared encoding — component specification

This is the specification for the shared encoding layer: the codecs that translate between
Circle's external wire formats (bytes32, uint256, secp256k1 attestations, the DepositIntent
message, the burn-note payload) and Miden's on-chain types (felts, Words, `AssetAmount`,
`AccountId`). It is written to match the shipped code:

- **Rust:** `crates/xusdc-encoding/src/xreserve/encoding/` (`bytes32.rs`, `amount.rs`,
  `account_id.rs`, `attestation.rs`, `deposit_intent.rs`, `burn_note.rs`, `error.rs`).
- **MASM:** `asm/standards/xreserve/encoding/` (`mod.masm` procedure bodies + `layout.masm`
  constants).

Most codecs are implemented on **both** sides: `bytes32_to_key`, the amount conversion (Rust
`uint256_to_asset_amount` computing the quotient, MASM `verify_uint256_to_asset_amount` proving
it as a witness through the linked standards conversion verifier), and
the attestation staging each have a Rust and a MASM leg, and a
cross-implementation suite (`TV-DUAL-1`, `-2`, `-3`, `-5`) proves the two agree on every golden
vector. The **burn-note payload codec (`DC-7`) is Rust-only** — there is no MASM burn-item codec — so
its vector (`TV-DUAL-4`) is an emit-vs-codec check within Rust (the Rust-created burn note vs the Rust
codec vs the golden felts), not a Rust↔MASM comparison. The faucet consumes the MASM side by
reference; the off-chain services consume the Rust side.

Short identifiers (`DC-1`, `TV-AMT-3`, `NS-1`, …) are defined in `docs/spec/GLOSSARY.md`.

## Data contracts

The seven codec decisions the crate owns are `DC-1`..`DC-7` (see the glossary for one-line
definitions). In summary:

| Contract | What it encodes |
|---|---|
| DC-1 | **DepositIntent** — a fixed 240-byte big-endian header + variable `hookData`; on-chain it is 60 u32-LE-packed felts (4 wire bytes per felt). Field offsets are in `layout.masm` / `deposit_intent.rs`. |
| DC-2 | **depositAttestation** — the raw 65-byte `r‖s‖v` secp256k1 signature over `keccak256(payload)` (not EIP-712). |
| DC-3 | **Attester commitment** — `Poseidon2(affine pubkey, 16 u32-LE felts: qx_le_u32[8] ‖ qy_le_u32[8])` → one Word, used as the `xReserveAttesters` allowlist key. The Circle-facing ingress form stays the 33-byte compressed SEC1 pubkey; this crate owns the SEC1→affine decompression (v16 supersession, vm#3342 — the v15 preimage was the 33 compressed bytes as 9 felts). |
| DC-4 | **Nonce keying** — the DepositIntent `nonce` (bytes32) → Poseidon2 hash-to-Word → storage-map key. |
| DC-5 | **amount/fee reduction** — a uint256 → `AssetAmount`: byte-swap to numeric order, assert the high half is zero, floor-divide by `10^scale_exp`, and reject if the quotient exceeds `AssetAmount::MAX`. It traps; it never saturates. |
| DC-6 | **AccountId ↔ bytes32** — the right-aligned layout (16 zero bytes ‖ prefix u64 BE ‖ suffix u64 BE); lossless, fail-closed decode. See `DEV-10` (OPEN). |
| DC-7 | **Burn-note payload** — `(amount, destDomain, destRecipient, salt)` encoded into `NoteStorage.items` (18 felts). Shipped Rust-only; there is no `burn_items.masm`. |

## Core routines

| Routine | Contract |
|---|---|
| `bytes32_to_key` (MASM) / `bytes32_to_storage_map_key` (Rust) | Poseidon2 `hash_elements` over the 8 u32-LE limbs of a bytes32 → one canonical Word. The raw fallible `TryFrom<[u8;32]>` is **not** used on this path (`NS-1`, `DC-4`, `INV-BYTES32-HASH-TO-WORD`). |
| `pubkey_commitment` | Poseidon2 over the 16 u32-LE affine-coordinate limbs of the pubkey → the allowlist commitment Word (`DC-3`; sponge capacity domain tag `16 % 8 = 0`), identical to miden-crypto 0.28 `PublicKey::to_commitment`. The Rust side takes the 33-byte compressed wire key and decompresses to affine internally; the MASM side hashes the 16 already-staged felts. |
| `uint256_to_asset_amount` (Rust) / `verify_uint256_to_asset_amount` (MASM) | The `DC-5` reduction (`INV-UINT256-TO-ASSETAMOUNT`). `scale_exp` is bounded to `0..=18`. Rust computes `y = floor(x / 10^scale_exp)`; the MASM side takes that `y` as an explicit witness and proves the same floor identity via the standards `verify_u256_to_asset_amount_conversion` (multiply-and-verify, no on-chain division). |
| `parse_deposit_intent` | Structural DepositIntent validation (magic, version, non-zero `amount`/`localToken`/`localDepositor`, the length relation) and the returned compare fields. The faucet adds the domain/identifier compares (`NS-2`, `INV-DEPOSITINTENT-PARSE`). |
| AccountId ↔ bytes32 (`account_id.rs`) | The `DC-6` lossless encode/decode with a fail-closed inverse. |
| Burn-note items (`burn_note.rs`) | The `DC-7` deterministic encode/decode. |

## Validation order

- **DepositIntent parse** (`§8.1` of the old spec; now `INV-DEPOSITINTENT-PARSE`): bounds/truncation
  guard first, then magic, version, non-zero fields, then the `len == 240 + hookDataLen` relation.
- **uint256 → AssetAmount** (`DC-5`): guard limbs are valid u32s → assert the high half is zero →
  take the low half as u128 → floor-divide by `10^scale_exp` → cap at `AssetAmount::MAX`.

## Testing

- **Unit / vector tests** per codec (`TV-B32-*`, `TV-AMT-*`, `TV-AID-*`, `TV-DI-*`, `TV-BN-*`,
  `TV-ATT-*` — see the glossary).
- **Rust↔MASM agreement** (`TV-DUAL-1`/`-2`/`-3`/`-5`, in `tests/masm_dual.rs`): the Rust codec and
  the assembled-and-executed MASM must produce the identical Word / amount / accept-reject on every
  vector. The MASM tests **execute** (not merely assemble). `TV-DUAL-4` is the burn-note vector; since
  `DC-7` has no MASM side it checks Rust emit-vs-codec parity (in `tests/xreserve_burn.rs`) instead.
- Golden vectors are generated by `crates/xusdc-encoding/src/bin/gen_vectors.rs`; constant parity
  between the Rust and MASM constants is enforced by `tests/constant_parity.rs`.

## Open items

The encoding layer inherits the Circle-owned OPEN decisions: the amount cap/scale (`DEV-5`), the
`hookData` bound (`DEV-6`), the AccountId↔bytes32 encoding (`DEV-10`), and the nonce keying
(`DEV-9`). None are marked approved. See the glossary.
