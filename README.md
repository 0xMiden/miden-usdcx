# USDCx on Miden

The Miden implementation of Circle's xReserve integration. Native USDC remains locked in Circle's
source-chain reserve; the Miden faucet mints USDCx against deposit attestations and burns it for
withdrawals. This uses xReserve, not standard USDC issuance or CCTP.

## Repository

| Path | Contents |
|---|---|
| `crates/xusdc-encoding/` | Shared codecs, faucet builder, note factories, golden vectors, and Rust and MASM execution tests. |
| `crates/xusdc-encoding/asm/xreserve/` | Hand-written MASM for mint and burn validation, deposit reconstruction, attestation verification, and attester administration. |
| `crates/xusdc-encoding/asm/components/` | Faucet components exposing the mint and burn policies and the attester setter. |
| `crates/xusdc-encoding/asm/notes/` | Administrative note scripts. Mint and burn use standard Miden note scripts. |
| `crates/xreserve-deposit-relayer/` | Deposit validation, Circle API client, mint-note construction, and submission coordination. |
| `crates/withdrawal-listener-attester/` | Withdrawal validation, signing, evidence assembly, and Circle API submission. |
| `crates/xusdc-validation/` | Local-node validation harness, currently excluded from the workspace. |

## Minting and burning

A relayer submits a standard `MintNote` with a committed attachment containing the attestation and
mint-intent fields. The faucet verifies the attachment, checks the amount, fee ceiling, recipient,
and nonce, reconstructs the signed deposit message, and verifies the attester's signature.
It binds the output note to the attested recipient and amount, then records the used nonce.
The standard faucet enforces the supply cap and creates the recipient's note. A failed transaction
rolls back all writes, including the nonce marker.

**Do not deposit with `hookData` longer than 3,840 bytes.** The deposit cannot be claimed on Miden,
and the USDC remains locked on the source chain.

A holder creates a public burn note. On consumption, the faucet requires routing and withdrawal
attachments, verifies the withdrawal commitment and size, and enforces the minimum burn amount.
It applies transfer policies, destroys the asset, and reduces supply. The withdrawal attester
validates the destination fields, takes the amount from the burned asset, and establishes
consumption before signing a withdrawal.
Same-block creation and consumption can prevent later note discovery; public visibility alone
does not guarantee durable burn evidence.

Administration uses role-based access control. `DOM_PAUSER` authorizes pause, `DOM_UNPAUSER`
authorizes unpause, `ATTEST_ADMIN` manages attesters, and `BLK_MANAGER` manages the blocklist.
`ADMIN` manages other setters and initially administers all roles.
Authorized role changes can change membership and role administrators after deployment.

Audit note for OpenZeppelin: the existing `withdrawal-listener-attester` is being replaced by the
lightweight attester introduced in [PR #194](https://github.com/0xMiden/miden-usdcx/pull/194).
[PR #195](https://github.com/0xMiden/miden-usdcx/pull/195) fixes withdrawal-term validation in the
existing implementation; [PR #217](https://github.com/0xMiden/miden-usdcx/pull/217) carries those
checks into the replacement and verifies the encoded bytes and signing hash. As of September 10,
2026, both replacement PRs are open; #217 leaves signing and submission out of scope and awaits a
captured Circle response for its two reference tests.

## Encoding

Rust and MASM share golden vectors for nonce hashing, public-key commitments, and deposit-message
reconstruction. Rust parses Circle's deposit bytes and converts amounts, account IDs, attestations,
and withdrawal payloads. The faucet reconstructs the signed deposit message from the mint intent
and its own state, then checks its Keccak-256 digest and secp256k1 signature.

Pending Circle decisions, including amount semantics, account-ID encoding, and burn evidence,
remain OPEN. See [architecture](docs/ARCHITECTURE.md) for the trust boundaries and
[deviations and open items](docs/DEVIATIONS.md) for the audited assumptions.

## Build and test

Run from the repository root:

```sh
cargo build --locked -p xusdc-encoding
cargo test --workspace --locked --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

`build.rs` assembles the MASM projects during compilation. The encoding tests execute the assembled
faucet and notes on a mock chain; assembly errors fail the build. On-chain code is hand-written
MASM, with no Rust-contract build path.

The validation harness uses an older client/protocol combination and is excluded from workspace
builds and tests. Its live-node commands require dependency migration before use; see the
[harness documentation](crates/xusdc-validation/README.md).

Contributor instructions are in [CLAUDE.md](CLAUDE.md).
