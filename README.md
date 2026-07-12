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
| `asm/standards/xreserve/` | The faucet account component — hand-written MASM. Custom mint (`xreserve_mint`), burn policy, admin setters (pause, attester allowlist, min-burn, domain config), and the shared `encoding/` library. |
| `asm/standards/notes/` | The public note scripts: the mint note and the admin notes. |
| `crates/xusdc-encoding/` | Rust crate: the encoding library (the Rust mirror of the MASM codecs — bytes32 hashing, uint256→amount reduction, DepositIntent parse), the `XReserveStablecoinBuilder` that composes the faucet account, golden test vectors, and the assemble-and-**execute** test suite. |
| `crates/xusdc-validation/` | Rust crate: the local-node validation harness that deploys the production faucet to a real Miden node and drives the mint/burn/admin acceptance matrix (rows `A`–`L`). |
| `docs/spec/` | The specification: the faucet component spec, the shared-encoding spec, and the **identifier glossary**. |
| `docs/governing/` | The pins, module-ownership map, MASM structure conventions, and toolchain-grounding reports the code is built against. |
| `canary/` | Grounding reports proving each Miden primitive the faucet relies on actually executes on the pinned toolchain. |

## Start here

- **What the faucet does and how it's built:** [`docs/spec/FAUCET-COMPONENT-SPEC.md`](docs/spec/FAUCET-COMPONENT-SPEC.md).
- **What every short identifier in the code means** (`R-MINT-15`, `D5c`, `DEV-10`, …):
  [`docs/spec/GLOSSARY.md`](docs/spec/GLOSSARY.md).
- **The encoding contracts** (`DC-1`..`DC-7`): [`docs/spec/ENCODING-COMPONENT-SPEC.md`](docs/spec/ENCODING-COMPONENT-SPEC.md).
- **What each doc in the repo is for:** [`docs/DOCS-INVENTORY.md`](docs/DOCS-INVENTORY.md).

## Build and test

The MASM is not compiled by a Rust-contract toolchain; it is assembled and executed by the test
suite. The primary gate assembles every `.masm`, links it into the faucet account, and runs the
mint/burn/admin behaviour against a mock chain:

```sh
cargo test --locked -p xusdc-encoding --release   # assemble + execute the MASM, run the full suite
cargo test --locked -p xusdc-encoding --test masm_structure   # MASM source-convention conformance
```

Real-local-node validation lives in `xusdc-validation` and requires a running Miden node stack; see
[`crates/xusdc-validation/README.md`](crates/xusdc-validation/README.md).

## Key design points

- **`xreserve_mint` is the only surface that can raise supply**, and it requires a valid attester
  signature; the stock `mint_and_send` path is deny-guarded.
- **Burns are public, two-block notes** so Circle can observe them.
- **Encoding is written once** in `xreserve::encoding` (MASM) and mirrored in Rust; a
  cross-implementation test proves the two agree on every golden vector.
- Several items remain **OPEN pending Circle** (`DEV-*` / `Q-*` in the glossary) — the code takes a
  documented provisional position on each; none are marked approved.

Ground rules for anyone changing this repo are in [`CLAUDE.md`](CLAUDE.md).
