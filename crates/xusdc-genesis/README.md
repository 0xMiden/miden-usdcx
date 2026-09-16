# xusdc-genesis

Builds the genesis xUSDC faucet fully **offline** — before any network exists — and writes its
`.mac` account file. Account-id derivation hashes the account seed plus the code and storage
commitments (no chain state, vault contents excluded), so the faucet id this tool prints is the
id the network will boot with, deterministically reproducible from the config.

The faucet is the ONLY account this tool builds, and its `.mac` file is the only file output.
The six role accounts — the network **operator** plus the five faucet role holders the
`XReserveStablecoinBuilder` seeds, **owner** (`ADMIN`), **attest_admin**, **pauser**,
**unpauser**, **blocklist_manager** — are referenced in the config as paths to their
externally-produced `.mac` files (producing them is out of scope here). Each file is read
PURELY to extract its account id: reading the id from the actual account file keeps the
faucet's role slots and the genesis account set consistent by construction, where a
hand-copied bare id could not be cross-checked. Nothing else is taken from the files — no
account state, no secret material.

The faucet is built as the network's NATIVE fee faucet: its id is ground while the fee
parameters carry the operator's id as a placeholder, then
`XReserveStablecoinBuilder::build_genesis_account` rebinds the fee-asset slot to the asset the
faucet itself issues.

## Usage

```sh
cargo run -p xusdc-genesis -- --config <config.json> [--out-dir <dir>]
```

Outputs:

- `usdcx-faucet.mac`, written to `--out-dir` (or the config's `output_dir`) — the faucet as a
  protocol `AccountFile`, at **nonce one** with no seed (it exists at genesis, it is never
  deployed in a transaction, and this tool's output cannot be used to deploy it anywhere else);
- a stdout listing: the faucet id as hex and as bech32 for mainnet, testnet, and devnet, plus
  the role ids extracted from the referenced account files.

## Config reference

JSON, unknown fields rejected:

```json
{
  "accounts": {
    "operator":          "accounts/operator.mac",
    "owner":             "accounts/owner.mac",
    "attest_admin":      "accounts/attest_admin.mac",
    "pauser":            "accounts/pauser.mac",
    "unpauser":          "accounts/unpauser.mac",
    "blocklist_manager": "accounts/blocklist_manager.mac"
  },
  "faucet": {
    "seed": "0x<64 hex>",
    "max_supply": 1000000000000,
    "token_supply": 250000000,
    "domain": 7,
    "min_burn_amount": 1,
    "verification_base_fee": 500
  },
  "output_dir": "optional/default/out/dir"
}
```

- `accounts.<role>` — the path to that role's protocol `AccountFile` (`.mac`); relative paths
  resolve against the config file's directory. The file is read purely to extract the account
  id. Role-collision rules are enforced by the `XReserveStablecoinBuilder` itself.
- `faucet.seed` — the faucet's 32-byte account seed (`0x` + 64 hex chars).
- `faucet` — the remaining `XReserveStablecoinBuilder` inputs: the supply cap and initial
  supply (base units, 6 decimals; `token_supply <= max_supply`), the Circle domain id, the
  optional minimum burn amount, and the network's `verification_base_fee` used to price the
  fee schedule.

**`verification_base_fee` parity:** the value is baked into the faucet's fee schedule at build
time and MUST equal the `[fee_parameters] verification_base_fee` the network operator puts in
the node's `genesis.toml` — the tool cannot enforce this, so keep the two in sync by hand.

## Assembling the node's genesis (the operator's job)

This tool does NOT write the node's `genesis.toml` — that file is the network operator's
artifact. A typical fragment referencing this tool's output next to the role `.mac` files looks
like:

```toml
native_faucet = "usdcx-faucet.mac"

[[account]]
path = "operator.mac"

[[account]]
path = "owner.mac"

# ... one [[account]] entry per remaining role ...
```

with the paths resolving from wherever the operator keeps the genesis inputs. Every account
injected at genesis (the faucet included — this tool already emits it that way) must be in
genesis form: **nonce one, no seed** — a genesis account exists from block zero, it is not
deployed.

## Determinism and the golden id

`tests/determinism.rs` freezes the faucet id derived from the test fixture (fixed faucet
parameters plus six deterministically generated role `.mac` files — test-only code standing in
for the external account tooling). The id moves on every protocol bump BY DESIGN (it hashes the
code commitment); the frozen test is the alarm, and a refreeze must be a deliberate act.
