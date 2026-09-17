# xusdc-genesis

Builds the genesis xUSDC faucet **offline** — before any network exists — and writes its `.mac`
account file. The faucet id hashes the account seed plus the code and storage commitments (no
chain state), so the id the tool prints is the id the network boots with, reproducible from the
config.

The config references the six role accounts — the mint **relayer** plus the five holders the
`XReserveStablecoinBuilder` seeds: **owner** (`ADMIN`), **attest_admin**, **pauser**,
**unpauser**, **blocklist_manager** — as paths to their `.mac` files; each file is read purely
to extract its account id.

## Usage

```sh
cargo run -p xusdc-genesis -- --config <config.json> [--out-dir <dir>]
```

Writes `usdcx-faucet.mac` (nonce one, no seed) into `--out-dir` (or the config's `output_dir`)
and prints the faucet id (hex + bech32 for mainnet/testnet/devnet) plus the extracted role ids.

## Config

JSON, unknown fields rejected; relative `.mac` paths resolve against the config file's
directory:

```json
{
  "accounts": {
    "relayer":           "accounts/relayer.mac",
    "owner":             "accounts/owner.mac",
    "attest_admin":      "accounts/attest_admin.mac",
    "pauser":            "accounts/pauser.mac",
    "unpauser":          "accounts/unpauser.mac",
    "blocklist_manager": "accounts/blocklist_manager.mac"
  },
  "faucet": {
    "seed": [7, 7, "... 32 bytes total ..."],
    "max_supply": 1000000000000,
    "token_supply": 250000000,
    "domain": 7,
    "min_burn_amount": 1,
    "verification_base_fee": 500,
    "attesters": [[2, 121, "... 33 bytes total ..."]],
    "used_nonces": [[85, 133, "... 32 bytes total ..."]]
  },
  "output_dir": "optional/out/dir"
}
```

`faucet.seed` is the faucet's 32-byte account seed as a JSON byte array; amounts are base units
(6 decimals, `token_supply <= max_supply`); `domain` is the Circle domain id. `attesters`
(optional) lists the deposit attester public keys to allowlist at build time, each as a JSON
byte array of the key's 33 compressed SEC1 bytes; when empty or absent the allowlist is seeded
later through `set_attester` notes.

`used_nonces` (optional) lists the Circle deposit nonces whose deposits the genesis state already
honours - the balances seeded at genesis are backed by them - each as a JSON byte array of the
nonce's 32 bytes. The faucet records them as consumed, so the relayer cannot mint them a second
time. The nonces do not feed the id: run the tool once without them to learn the faucet id, make
the deposits against that id, then add their nonces and run it again. The second run prints the
same id, and its `.mac` is the one to put into genesis.

`verification_base_fee` is baked into the faucet's fee schedule and MUST equal the
`[fee_parameters] verification_base_fee` the network operator puts in the node's `genesis.toml`
— the tool cannot enforce this.

## Node genesis (the network operator's artifact)

The operator assembles the node's `genesis.toml` referencing this tool's output next to the
role `.mac` files, e.g.:

```toml
native_faucet = "usdcx-faucet.mac"

[[account]]
path = "relayer.mac"

# ... one [[account]] entry per remaining role ...
```

Accounts injected at genesis must be at nonce one with no seed.

## Golden id

`tests/determinism.rs` freezes the faucet id derived from the deterministic test fixture. It
moves on every protocol bump BY DESIGN (it hashes the code commitment); a refreeze must be a
deliberate act.
