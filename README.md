# xusdc-miden

The Miden-side implementation of Circle's **xReserve / xUSDC** — a hand-written-MASM faucet
contract that mints xUSDC on Miden against Circle-attested deposits and burns it for withdrawals,
plus the Rust encoding library and validation harness that support it.

> xUSDC is Circle's xReserve stablecoin, **not** standard USDC and **not** CCTP. Native USDC stays
> locked 1:1 in Circle's xReserve contract on the source chain; the faucet implements the Miden side. The optional CCTP worker completes upstream
> native-USDC burns through the separately deployed immutable Arc helper.

## What's here

| Path | What it is |
|---|---|
| `crates/xusdc-encoding/asm/xreserve/` | The faucet library — hand-written MASM. The **attestation mint policy** (`mint_policy` — the active mint policy the stock `mint_and_send` dispatches), the attestation verify, and the attester allowlist admin. |
| `crates/xusdc-encoding/asm/components/faucet_extension/` | What the faucet adds on top of the stock fungible faucet: the attestation mint policy and the attester allowlist setter, and nothing else. |
| `crates/xusdc-encoding/asm/notes/` | The public admin note scripts, one Miden project each (the mint note is the STOCK miden-standards `MintNote`). |
| `crates/xusdc-encoding/` | Rust crate: the encoding library (the Rust mirror of the MASM codecs — bytes32 hashing, uint256→amount reduction, DepositIntent parse), the `XReserveStablecoinBuilder` that composes the faucet account, golden test vectors, the `build.rs` that assembles every MASM project above, and the **execute** test suite. |
| `crates/xusdc-genesis/` | Rust crate: the genesis tool — builds the genesis xUSDC faucet fully offline (its id deterministic before any network exists) from the configured role-account ids, generates and prefunds the distributor that holds the initial supply, records the consumed deposit nonces, and writes the `.mac` account files the node's genesis config takes. |
| `crates/xusdc-validation/` | Rust crate: the local-node validation harness that deploys the production faucet to a real Miden node and drives the mint/burn/admin acceptance matrix (rows `A`–`L`). |
| `crates/cctp-deposit-relayer/` | Optional incoming CCTP discovery and Arc helper submission worker. |
| `contracts/cctp-deposit-helper/` | Immutable Solidity receive-and-deposit helper with local Circle reference integration tests and pinned tooling. |
| `docs/` | `ARCHITECTURE.md`: how the faucet fits together, the mint and burn paths, and where the trust boundaries sit. `DEVIATIONS.md`: where the implementation deliberately deviates from Circle's spec, plus the known open items. Auditors: start with these two. |

## Incoming CCTP worker

`crates/cctp-deposit-relayer` independently discovers configured finalized EVM/Solana burns,
obtains Circle attestations and submits their original bytes to one immutable Arc helper. It uses
one serial loop, one SQLite journal and a dedicated gas sender. Omitted sources cause no discovery
RPC. The existing xReserve-to-Miden relayer, withdrawal services and portal remain independent.

Run the incoming worker and the [xReserve-to-Miden publisher](crates/xreserve-deposit-relayer/README.md)
as separate services. For a bounded run, initialize the publisher with
`--init-state-at-current-head` before any intended deposit, then start it with
`--require-head-watermark` before starting new burns. Provision its public Miden courier account,
complete keystore and finite fee balance separately from the worker's Arc gas sender.

Clone the integration branch and build only the worker graph:

```sh
git clone --branch feat/cctp-bridging-in https://github.com/0xMiden/miden-usdcx.git
cd miden-usdcx
cargo build --release --locked -p cctp-deposit-relayer
cargo test --locked -p cctp-deposit-relayer -p usdcx-kms-signer -p usdcx-telemetry
mkdir -p runtime/cctp
cp crates/cctp-deposit-relayer/config.example.json runtime/cctp/profile.local.json
chmod 700 runtime/cctp
chmod 600 runtime/cctp/profile.local.json
```

The example deliberately fails validation. Replace the RPC/Circle URLs, helper address/runtime
hash, destination messenger, signer and immutable KMS ARN; choose explicit gas/fee limits; replace
the Solana genesis/program/native-USDC mint and retained finalized start signature/slot. The source
start is inclusive. Use a host journal path inside `runtime/cctp` for a native process, or
`/data/journal.sqlite` in the container. The disabled public candidate in
`contracts/cctp-deposit-helper/deployments/arc-testnet.candidate.json` supplies historical public
identities for rechecking, not approval to start or burn. Omit sources served by another preferred
route. Providers must retain the chosen source boundary and support finalized Arc reads/logs.

Use the normal AWS credential chain. The locked SDK enables SSO for a human-operated session;
`AWS_PROFILE=miden-usdcx` requires an operator-managed AWS config and a current `aws sso login`
session. SSO expires and is not an unattended service identity. An approved workload role through
IMDS, including an existing Roles Anywhere credential helper endpoint, remains supported. This
build does not enable `credential_process`. Do not put static credentials, SSO caches or certificate
keys in this repository or image. Pin an existing compatible KMS key's immutable ARN and verify
its public key/address. Previous Miden or Circle message signing does not consume an Arc EOA nonce;
any previous Arc signed-transaction history must be reconciled before reuse.

Check the exact locked Rust credential path without signing or creating a journal:
`cargo run --locked -p usdcx-kms-signer --example inspect_key -- eu-north-1 <immutable-key-arn>`.
It performs only DescribeKey/GetPublicKey, validates the key metadata and prints the derived public
EVM address. Compare it with the independently pinned sender before initialization.

Initialize once with a dedicated sender whose latest and pending Arc nonces are both zero, with
no offline signed Arc transaction, old journal or competing sender process:

```sh
target/release/cctp-deposit-relayer --config runtime/cctp/profile.local.json --init
target/release/cctp-deposit-relayer --config runtime/cctp/profile.local.json
```

Initialization exits without sending. A failure after journal creation can leave an empty valid
journal: inspect the error and preserve it before deciding how to continue. Ordinary restarts use
the same complete journal and profile without `--init`. The entire serialized configuration except
the journal path is bound to the journal, including endpoint credentials, source order, gas caps
and KMS identity. Changing any of these requires stopping/fencing and manual reconciliation.

The journal commits exact signed transaction bytes before broadcast. One unresolved sender nonce
blocks further signing; only identical bytes may be rebroadcast. Canonical finalized receipts
settle that nonce. A paid revert remains manual across restarts, and there is no automatic fee
replacement or paid retry. Unknown sender nonce use or stale pending work requires manual recovery.
Third-party CCTP completion never releases an owned sender nonce. A source page larger than queue
capacity retains its cursor and logs the blockage while admitted work continues; operator review
is required if the page cannot fit even after the queue drains.

Use only intact-journal restarts, one host/process and no other user of that sender key. Old/lost
backups and cross-host recovery require fencing the old sender and manual reconciliation; equal
RPC nonces cannot reconstruct missing signed attempts. Keep the complete consistent SQLite journal.
Logs are the operator interface; there is no HTTP hint/status/readiness service or daily spend
budget. A finite dedicated gas balance and small per-transaction ceilings bound operator exposure.

For rootful Docker on Linux without user-namespace remapping, prepare a separate private
container profile from the repository root. Keep the native host-owned `0600` profile and its
`0700` directory unchanged:

```sh
install -m 0600 runtime/cctp/profile.local.json runtime/cctp/profile.container.input.json
```

Edit `profile.container.input.json` for the container paths, including `/data/journal.sqlite`,
and the required settings before first initialization. With GNU `install`, create an owner-only
copy for UID/GID 10002, then build and run the Linux amd64 image:

```sh
sudo install -o 10002 -g 10002 -m 0600 runtime/cctp/profile.container.input.json runtime/cctp/profile.container.json
docker build --platform linux/amd64 -f crates/cctp-deposit-relayer/Dockerfile -t cctp-worker:local .
docker run --rm --network none cctp-worker:local --help
docker volume create cctp-worker-data
docker run --name cctp-worker-init --rm -v "$PWD/runtime/cctp/profile.container.json:/run/cctp/profile.json:ro" -v cctp-worker-data:/data cctp-worker:local --config /run/cctp/profile.json --init
docker run --name cctp-worker --restart unless-stopped --stop-timeout 30 -v "$PWD/runtime/cctp/profile.container.json:/run/cctp/profile.json:ro" -v cctp-worker-data:/data cctp-worker:local --config /run/cctp/profile.json
docker stop --time 30 cctp-worker
docker start cctp-worker
```

Docker Desktop, rootless Docker and user-namespace remapping can map ownership differently.
Before initialization, verify that the effective container user can read the mounted `0600`
profile and any other private credential mounts under that platform's mapping; do not assume the
rootful Linux ownership recipe.

Supply the approved AWS workload environment/mounts to both initialization and service containers;
the commands above intentionally contain no credentials. The image runs as UID/GID 10002. A named
volume inherits `/data` ownership; a bind-mounted journal directory must be writable by that UID,
including SQLite WAL/SHM sidecars. Mount the whole directory, never only the database file. Keep
private profiles and state outside the build context; the narrow ignored `runtime/cctp` directory
is available for local use. Choose host memory/CPU limits appropriate to the selected runtime.
SIGTERM requests bounded shutdown. Reuse the same volume/profile on restart and never clear a
journal or rerun initialization to resolve unknown nonce use, a paid revert or a lost RPC reply.
Stop and reconcile source occurrence, exact signed bytes, canonical receipt and sender nonce with
the operator; there is no automatic paid retry, fee replacement, refund or recipient change.
The independent systemd example requires its own OS user, private config and durable SQLite path.
Configure telemetry with
`--export-filter cctp_deposit_relayer=info`. Trusted finalized RPC history, Circle transaction
association, dependency-upgrade review, real Arc/source/provider/KMS/funding qualification and final
Miden delivery remain operational boundaries; local Ethereum fixtures do not prove them.

The public deployment candidate remains disabled until its qualification record is complete.
The focused CCTP workflow checks the worker on Linux and helper tooling on macOS ARM64. Image
build/linkage, nonroot journal checks, actual runtime SIGTERM/restart, provider capability and the
selected KMS credential path each need source-bound results before service operation is qualified.

## Incoming CCTP helper

The helper package preserves its `contracts/`, `tests/`, `scripts/` and generated `modules/` layout.
From `contracts/cctp-deposit-helper`, run `python3 tooling/bootstrap.py`, then
`python3 tooling/run-local-gates.py`. Bootstrap retrieves pinned Arc Foundry, Solidity compilers
and library sources; the verified bootstrap platform is macOS ARM64. Reference sources are
materialized from the immutable archives in `reference/PROVENANCE.json`, with archive, source
and retained-license hashes checked on every run. `--offline` uses the verified archive cache
and existing npm packages. Run integrity tests with
`python3 -m unittest discover -s tooling -p test_bootstrap.py`. The local gates build the pinned
Circle reference contracts, run concrete, fuzz, invariant and integration tests, and own
and stop a loopback-only Arc Anvil instance for runtime checks. `scripts/Deploy.s.sol` performs
nonbroadcast preflight; local validation does not establish a live deployment or an end-to-end
public-testnet bridge.

Generate/check the shared compiler ABI and run the real worker against a fresh loopback fixture:

```sh
node tooling/generate-abi.cjs
node tooling/generate-abi.cjs --check
node tooling/run-worker-integration.cjs
tooling/forge build --ast
CCTP_ARC_RPC_URL=https://rpc.testnet.arc.network node tooling/check-public-deployment.cjs /tmp/cctp-public-check.json
```

The worker runner resolves the repository and Cargo JSON test executable, owns ephemeral ports and
processes, and keeps generated test keys in memory. It executes three genuine local source burns,
including identical messages with distinct CCTP nonces, through the pinned Circle/helper/xReserve
contracts. Its token and Gateway are local stand-ins; it never uses AWS or public RPC and does not
qualify public Arc or Miden delivery. Optional first argument selects a parent output directory.
The public checker is read-only, pins one finalized Arc block and verifies exact compiler runtime
with immutables, all getters, dependencies and reserve views. Its result alone does not earn the
five deployment qualification flags, prove source-history capacity or authorize a source burn.

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
predates the current encoding API, so it does not build against this tree. Re-enabling it requires
a separate migration to the workspace's protocol `=0.17.1` and client/SQLite store `=0.17.3`
releases, including the current encoding API.

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
