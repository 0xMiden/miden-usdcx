# Deposit relayer

Reads Circle deposit attestations and sends mint notes to the Miden faucet.
The faucet checks Circle's signature and mints the tokens.

To run it together with the withdrawal attester, use the [bridge bundle](../xusdc-bridge/README.md).

## Setup

Get the Circle URL, Miden RPC URL, domain, faucet ID and Circle deposit public key from Miden.
Use values for the same network. Prepare a funded Miden relayer account and put its signing key
in `<MIDEN_DATA_DIR>/keystore/`. This service does not create or fund the account.

The relayer's account key signs Miden transactions. `--attester-public-key` is Circle's public
key for deposits. Neither is one of the withdrawal attester's AWS KMS keys.

## Build and run

Use the Rust version in the repository's `rust-toolchain.toml`:

```sh
cargo build --locked --release -p xreserve-deposit-relayer
./target/release/xreserve-deposit-relayer --help
```

Replace every `<...>` with your deployment settings. The page size and timing values below are examples.

```sh
./target/release/xreserve-deposit-relayer \
  --circle-url '<CIRCLE_URL>' \
  --page-size 100 \
  --request-timeout 30s \
  --poll-interval 5s \
  --remote-domain '<MIDEN_CIRCLE_DOMAIN>' \
  --miden-node-url '<MIDEN_RPC_URL>' \
  --miden-data-dir '<ABSOLUTE_MIDEN_DATA_DIR>' \
  --expiration-delta 64 \
  --faucet-account-id '<FAUCET_ID>' \
  --relayer-account-id '<RELAYER_ID>' \
  --attester-public-key '<CIRCLE_DEPOSIT_PUBLIC_KEY_HEX>' \
  --state-file '<ABSOLUTE_PROGRESS_FILE>'
```

Account IDs accept hex or bech32. The public key is compressed secp256k1 hex (33 bytes).
Create the progress file's parent directory before starting.

## Operating it

Run one instance for the relayer account and its files. Keep the data directory, including
`store.sqlite3` and `keystore/`, and the progress file on persistent storage. Back them up
while stopped. Restart with the same files; do not delete state to clear an error.

Logs use `RUST_LOG`, defaulting to `info`. Watch for skipped attestations and check actual mint
outcomes: a submitted transaction means the mint notes reached Miden, not that the faucet
consumed them. This service does not track that later step. Skipped attestations are not
automatically revisited after a configuration fix.

The relayer relies on its configured Miden node when checking transaction inclusion and which
deposits have already minted. Use the node approved for the deployment.
