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
    "owner":              "0x6aeeb7cba03918516870e95568b77b",
    "attest_admins":      ["0x... or bech32"],
    "pausers":            ["0x... or bech32", "0x... several holders allowed"],
    "unpausers":          ["0x... or bech32"],
    "blocklist_managers": ["0x... or bech32"]
  },
  "faucet": {
    "seed": [7, 7, "... 32 bytes total ..."],
    "token_supply": 250000000,
    "domain": 10007,
    "min_burn_amount": 1,
    "verification_base_fee": 500,
    "attesters": [[2, 121, "... 33 bytes total ..."]],
    "used_nonces": [[85, 133, "... 32 bytes total ..."]]
  },
  "output_dir": "optional/out/dir"
}
```

`accounts.owner` is the single `ADMIN` holder's account id; the four operational role fields
each list zero or more holders (absent means empty — the role is then populated later through
the standard role-action note). Every id is `0x`-prefixed hex or bech32, and every listed
holder is seeded as a member of its role. `faucet.seed`
is the faucet's 32-byte account seed as a JSON byte array; `token_supply` is the initial supply
in base units (6 decimals); the supply cap is not configurable and is set to the maximum asset
amount; `domain` is the Circle domain id, 10007 for Miden. `attesters` (optional) lists the
deposit attester public keys to allowlist at build time, each as a JSON byte array of the key's
33 compressed SEC1 bytes; when empty or absent the allowlist is seeded later through
`set_attester` notes.

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

The operator's `genesis.toml` needs only the faucet:

```toml
native_faucet = "usdcx-faucet.mac"
```

The role accounts are NOT injected at genesis — their holders deploy them with their first
transaction.
