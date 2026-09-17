# xusdc-genesis

Builds the genesis xUSDC faucet **offline** — before any network exists — and writes its `.mac`
account file. The faucet id hashes the account seed plus the code and storage commitments (no
chain state), so the id the tool prints is the id the network boots with, reproducible from the
config.

The config names the five role holders the `XReserveStablecoinBuilder` seeds — **owner**
(`ADMIN`), **attest_admin**, **pauser**, **unpauser**, **blocklist_manager** — by bare account
id (hex or bech32).

## Usage

```sh
cargo run -p xusdc-genesis -- --config <config.json> [--out-dir <dir>]
```

Writes `usdcx-faucet.mac` (nonce one, no seed) into `--out-dir` (or the config's `output_dir`)
and prints the faucet id (hex + bech32 for mainnet/testnet/devnet) plus the configured role
ids.

## Config

JSON, unknown fields rejected:

```json
{
  "accounts": {
    "owner":             "0x6aeeb7cba03918516870e95568b77b",
    "attest_admin":      "0x... or bech32",
    "pauser":            "0x... or bech32",
    "unpauser":          "0x... or bech32",
    "blocklist_manager": "0x... or bech32"
  },
  "faucet": {
    "seed": [7, 7, "... 32 bytes total ..."],
    "max_supply": 1000000000000,
    "token_supply": 250000000,
    "domain": 7,
    "min_burn_amount": 1,
    "verification_base_fee": 500,
    "attesters": [[2, 121, "... 33 bytes total ..."]]
  },
  "output_dir": "optional/out/dir"
}
```

`accounts.<role>` is that role's account id, as `0x`-prefixed hex or as bech32. `faucet.seed`
is the faucet's 32-byte account seed as a JSON byte array; amounts are base units (6 decimals,
`token_supply <= max_supply`); `domain` is the Circle domain id. `attesters` (optional) lists
the deposit attester public keys to allowlist at build time, each as a JSON byte array of the
key's 33 compressed SEC1 bytes; when empty or absent the allowlist is seeded later through
`set_attester` notes.

`verification_base_fee` is baked into the faucet's fee schedule and MUST equal the
`[fee_parameters] verification_base_fee` the network operator puts in the node's `genesis.toml`
— the tool cannot enforce this.

## Node genesis (the network operator's artifact)

The operator's `genesis.toml` needs only the faucet:

```toml
native_faucet = "usdcx-faucet.mac"
```

The role accounts are NOT injected at genesis — their holders deploy them with their first
transaction.

## Golden id

`tests/determinism.rs` freezes the faucet id derived from the fixed test fixture. It moves on
every protocol bump BY DESIGN (it hashes the code commitment); a refreeze must be a deliberate
act.
