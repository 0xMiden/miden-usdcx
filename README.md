# xusdc-miden

The Miden-side implementation of Circle's **xReserve / xUSDC** — a hand-written-MASM faucet
contract that mints xUSDC on Miden against Circle-attested deposits and burns it for withdrawals,
plus the Rust encoding library and validation harness that support it.

> xUSDC is Circle's xReserve stablecoin, **not** standard USDC and **not** CCTP. Native USDC stays
> locked 1:1 in Circle's xReserve contract on the source chain; this repository is only the Miden
> side.

## What's here

| Path | What it is |
|---|---|
| `crates/xusdc-encoding/asm/xreserve/` | The faucet library — hand-written MASM. The **attestation mint policy** (`mint_policy` — the active mint policy the stock `mint_and_send` dispatches), the attestation verify, and the attester allowlist admin. |
| `crates/xusdc-encoding/asm/components/faucet_extension/` | What the faucet adds on top of the stock fungible faucet: the attestation mint policy and the attester allowlist setter, and nothing else. |
| `crates/xusdc-encoding/asm/notes/` | The public admin note scripts, one Miden project each (the mint note is the STOCK miden-standards `MintNote`). |
| `crates/xusdc-encoding/` | Rust crate: the encoding library (the Rust mirror of the MASM codecs — bytes32 hashing, uint256→amount reduction, DepositIntent parse), the `XReserveStablecoinBuilder` that composes the faucet account, golden test vectors, the `build.rs` that assembles every MASM project above, and the **execute** test suite. |
| `crates/xusdc-genesis/` | Rust crate: the genesis tool — builds the genesis xUSDC faucet fully offline (its id deterministic before any network exists) from the role-account ids extracted out of the config-referenced `.mac` files, and emits the node's genesis inputs: the faucet's `.mac` account file, a `genesis.toml` fragment referencing every account, and an id summary. |
| `crates/xusdc-validation/` | Rust crate: the local-node validation harness that deploys the production faucet to a real Miden node and drives the mint/burn/admin acceptance matrix (rows `A`–`L`). |
| `docs/` | `ARCHITECTURE.md`: how the faucet fits together, the mint and burn paths, and where the trust boundaries sit. `DEVIATIONS.md`: where the implementation deliberately deviates from Circle's spec, plus the known open items. Auditors: start with these two. |

## How it works

xUSDC is a Miden fungible-faucet account built the way the canonical stock bridge faucet is built —
**stock transport and effects, custom fully-gated policies**. Native USDC stays locked 1:1 in
Circle's xReserve contract on the source chain; this account mints xUSDC against a Circle-attested
deposit and burns it on withdrawal.

- **Mint.** A relayer submits a STOCK miden-standards `MintNote` whose storage embeds the attested
  output (the P2ID recipe to the intent's recipient, the reduced amount, the recipient's tag) and
  whose attachments carry the Circle-signed transport (the `DepositIntent`, the attestation — fee,
  attester pubkey, signature —, and the network routing target). The stock script calls the stock
  `mint_and_send`, which dispatches the faucet's **attestation mint policy** first — a strict
  **verify-once-then-write-once** pipeline: pause gate (the dispatcher's) → attachment hash-verify →
  structural/addressing checks → amount/fee reduction → nonce replay guard → keccak-then-ECDSA
  attestation check against the attester allowlist → the assert-match binding (the note's claimed
  output must EQUAL its attested derivation); the policy marks the nonce used, and the stock path
  enforces the supply cap, emits the P2ID note, and raises `token_supply`. Any check that fails
  aborts the whole transaction with no writes, so a failed mint never consumes its nonce. The
  attestation policy is the only allowed mint policy, which makes it the gate **every** supply
  increase passes. **Do not deposit with `hookData` longer than 3,840 bytes.** The deposit cannot be
  claimed on Miden, and the USDC remains locked on the source chain.
- **Burn.** A holder creates a **Public** `XReserveBurnNote` carrying `(destDomain,
  destRecipient)`; creating the note moves the assets out of the holder's vault (so the balance
  is checked at creation). In a **later block** the faucet consumes the note (`receive_and_burn`):
  pause is checked, then the burn policy requires both attachments and `amount ≥ minBurnSize` (the floor
  is always ≥ 1 — builder-rejected below one and note-guarded at the setter — so zero burns are
  unacceptable on every path), and consuming the note decrements `token_supply`. The note is always
  public and two-block so Circle can observe the withdrawal.
- **Encoding.** The codecs that translate Circle's wire formats to Miden types are **written once** in
  MASM and mirrored in Rust — `bytes32` hashing, `uint256`→amount reduction,
  the `DepositIntent` parse, and the attester **pubkey commitment** (`DC-3`, a Poseidon2 hash over the
  already-packed pubkey felts) — with a cross-implementation test (`TV-DUAL-1`/`-2`/`-3`/`-5`) proving
  they agree on every golden vector. The remaining codecs are **Rust-only** (the relayer/harness side):
  the burn-note payload (`DC-7`, checked for Rust emit-vs-decode parity), the AccountId↔bytes32 mapping
  (`DC-6`), and the attestation byte→felt packing of the **digest and signature** plus the pubkey's
  SEC1→affine decompression and packing (`DC-2`/`DC-3`; the 33-byte compressed wire key stages as
  16 affine felts since v16). `TV-DUAL-5` compares each side's final `pubkey_commitment` Word against the miden-crypto
  oracle — the MASM proc hashes the vector's pre-packed felts (there is no MASM pubkey packer), while
  the Rust leg packs the raw key itself — so the byte→felt packing runs only in Rust, with no MASM
  counterpart to diff against. The keccak digest and the ECDSA signature check themselves are not
  encoding codecs — they run on-chain in the faucet's attestation verifier.
- **Identity.** The faucet's identifier — the value every deposit intent's `remoteToken` is checked
  against — is the faucet's OWN account id in the frozen bytes32 packaging, derived on chain by the
  mint path rather than stored. Nothing seeds it, so the faucet mints from the moment it exists.
- **Admin.** Pure role-based: `ADMIN` administers every seeded role directly and gates
  `set_min_burn_amount` (a zero floor is refused at note-building time), `set_max_supply`
  and note fees. `ATTEST_ADMIN` gates `set_attester`; `DOM_PAUSER` pauses and `DOM_UNPAUSER`
  unpauses the flag that halts mint and burn-consume. There is no ownership component or owner slot.
  Rotation is a grant then a revoke through the stock `RbacConfigNote`, whose root also exposes
  re-pointing a role's administrator and self-renounce, both accepted and pinned by tests.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full pipeline.

## Start here

Audit note for OpenZeppelin: the existing `withdrawal-listener-attester` is being replaced by the
lightweight attester introduced in [PR #194](https://github.com/0xMiden/miden-usdcx/pull/194).
[PR #195](https://github.com/0xMiden/miden-usdcx/pull/195) fixes withdrawal-term validation in the
existing implementation; [PR #217](https://github.com/0xMiden/miden-usdcx/pull/217) carries those
checks into the replacement and verifies the encoded bytes and signing hash. As of September 10,
2026, both replacement PRs are open; #217 leaves signing and submission out of scope and awaits a
captured Circle response for its two reference tests.

- **What the faucet does and how it's built:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- **The encoding contracts:** the codecs in `crates/xusdc-encoding/src/xreserve/encoding/`, each of
  which documents its own wire form alongside the MASM module that mirrors it.

## Build and test

The MASM is not compiled by a Rust-contract toolchain; it is assembled and **executed** by the test
suite. Everything below runs offline — the toolchain is pinned in `Cargo.lock` — from the repo root:

```sh
cargo build  --locked -p xusdc-encoding                       # compile the crate AND assemble every .masm — a MASM error fails here
cargo test   --locked -p xusdc-encoding --release             # THE gate: EXECUTE the MASM, full suite
cargo fmt    --all -- --check                                 # formatting
cargo clippy --workspace --locked -- -D warnings              # lints
```

`build.rs` assembles every `.masm` during `cargo build`, so a broken module fails the build rather
than a test. The primary gate (`cargo test -p xusdc-encoding --release`) links those assembled
packages into the faucet account and runs the mint/burn/admin behaviour — including the Rust↔MASM
cross-implementation vectors — against a mock chain.

### Real-local-node validation — **parked; live-node rows operator-run**

`crates/xusdc-validation` deploys the production faucet to a **real Miden node** and drives the
mint/burn/admin acceptance matrix (rows `A`–`L`). The crate is currently **parked outside the
workspace** (`exclude` in the root `Cargo.toml`): it still carries the v16-alpha
`miden-client` pins (`=0.16.0-alpha.1`, which itself pins protocol `=0.16.0-alpha.4`) and
predates the current encoding API, so it does not build against this tree. It un-parks with a
deliberate migration onto the workspace's `=0.16.1` protocol pin plus the released
`miden-client 0.16.0`.

The **live-node** rows — the real four-service-stack deploy/drive that needs the node binaries on
`PATH` and loopback ports `57291–57294` free — stay `#[ignore]`d in the default suite and are
operator-run.

Each gate binary bootstraps genesis, starts the four-service node stack (validator, ntx-builder,
sequencer, tx prover), runs its rows, and tears the stack down:

```sh
# LIVE-NODE commands (operator-run, P1b-b — need the node binaries on PATH):
cargo run -p xusdc-validation --bin lnv1_rows_ab      # rows A/B — deploy + identifier init-once
cargo run -p xusdc-validation --bin lnv2_rows_cf      # rows C/F — admin suite + auth boundary
cargo run -p xusdc-validation --bin lnv3_rows_de      # rows D/E — mint lifecycle + negatives
cargo run -p xusdc-validation --bin lnv4_rows_gj      # rows G/H/I/J — burn two-block + F7 + conservation
cargo run -p xusdc-validation --bin lnv5_full_matrix  # the consolidated A–L §11.2 gate run on one fresh node
cargo run -p xusdc-validation --bin lnv_stack -- up [label]   # bring a stack up and leave it running (`-- down <run-root>` to stop)
```

See [`crates/xusdc-validation/README.md`](crates/xusdc-validation/README.md) for the full run
notes. **The gate PASS is a human decision — the binaries never declare it.**

## Key design points

- **Every supply increase passes the attestation mint policy**, and it requires a valid attester
  signature; the stock `mint_and_send` path is deny-guarded.
- **Burns are public, two-block notes** so Circle can observe them.
- **The dual codecs are written once** in MASM and mirrored in Rust — bytes32
  hashing, amount reduction, the `DepositIntent` parse, and the attester pubkey commitment — each
  proven Rust==MASM on every golden vector; the rest (AccountId, burn payload, and the attestation
  digest/compressed-pubkey/signature packing) is Rust-only.
- Several items remain **OPEN pending Circle** (`DEV-*` / `Q-*` in the glossary) — the code takes a
  documented provisional position on each; none are marked approved.

Ground rules for anyone changing this repo are in [`CLAUDE.md`](CLAUDE.md).
