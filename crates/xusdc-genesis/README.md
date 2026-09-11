# xusdc-genesis

Derives the xUSDC genesis accounts fully **offline** — before any network exists — and emits
everything the node's genesis needs. Account-id derivation hashes the account seed plus the code
and storage commitments (no chain state, vault contents excluded), so the ids this tool prints
are the ids the network will boot with, deterministically reproducible from the config.

It builds seven accounts:

- six basic wallets: the network **operator** plus the five faucet role holders the
  `XReserveStablecoinBuilder` seeds — **owner** (`ADMIN`), **attest_admin**, **pauser**,
  **unpauser**, **blocklist_manager**;
- the **xUSDC faucet**, built as the network's NATIVE fee faucet: its id is ground while the fee
  parameters carry the operator's id as a placeholder, then
  `XReserveStablecoinBuilder::build_genesis_account` rebinds the fee-asset slot to the asset the
  faucet itself issues.

## Usage

```sh
cargo run -p xusdc-genesis -- --config <config.json> [--out-dir <dir>]
```

Outputs, written to `--out-dir` (or the config's `output_dir`):

- `usdcx-faucet.mac` and one `<role>.mac` per wallet — protocol `AccountFile`s;
- `genesis.toml` — a plain-text fragment for the node's genesis config
  (`native_faucet = "usdcx-faucet.mac"` plus one `[[account]] path = "<role>.mac"` per wallet);
- `accounts.json` — a machine-readable summary of every id;
- a stdout listing per account: the id as hex and as bech32 for mainnet, testnet, and devnet.

The node consumes `genesis.toml` together with the `.mac` files it references when constructing
the genesis block; all seven accounts enter the chain at **nonce one** with no seed — they exist
at genesis, they are never deployed in a transaction, and this tool's output cannot be used to
deploy them anywhere else.

## Config reference

JSON, unknown fields rejected:

```json
{
  "accounts": {
    "operator":          { "seed": "0x<64 hex>", "public_key": "0x<hex, optional>" },
    "owner":             { "seed": "0x<64 hex>" },
    "attest_admin":      { "seed": "0x<64 hex>" },
    "pauser":            { "seed": "0x<64 hex>" },
    "unpauser":          { "seed": "0x<64 hex>" },
    "blocklist_manager": { "seed": "0x<64 hex>" }
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

- `seed` — the 32-byte account seed (`0x` + 64 hex chars). All seven must be distinct.
- `public_key` (optional, wallets only) — the hex of a protocol `PublicKey` serialization,
  Falcon512-Poseidon2 only. When present, the holder keeps the secret and the tool never sees
  it. When absent, the tool generates the key pair deterministically from the seed (seeded
  ChaCha20) and embeds the secret in that account's `.mac` file.
- `faucet` — the `XReserveStablecoinBuilder` inputs: the supply cap and initial supply (base
  units, 6 decimals; `token_supply <= max_supply`), the Circle domain id, the optional minimum
  burn amount, and the network's `verification_base_fee` used to price the fee schedule. When
  `token_supply` is non-zero the operator's genesis vault holds exactly that amount of the
  faucet's asset, matching the faucet's issued-supply tracker.

## SECURITY

A config in which any account omits `public_key` **seeds real key material**: the account's
secret key is derived from its `seed` and written into its `.mac` file. Treat such a config
file — and the emitted `.mac` files — as secrets: anyone holding them controls the accounts.
For production, supply `public_key` for every wallet so no secret ever exists in this tool.

## Determinism and the golden ids

`tests/determinism.rs` freezes the ids the committed `tests/fixtures/dev-config.json` derives.
They move on every protocol bump BY DESIGN (the id hashes the code commitment); the frozen test
is the alarm, and a refreeze must be a deliberate act.
