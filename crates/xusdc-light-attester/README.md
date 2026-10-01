# Withdrawal attester

Watches burns on Miden, checks Circle's proposed withdrawal, signs it with two AWS KMS keys,
and submits it to Circle. Progress and signed requests are saved in SQLite.

To run it together with the deposit relayer, use the [bridge bundle](../xusdc-bridge/README.md).

## Setup

1. Create two distinct AWS KMS keys with `ECC_SECG_P256K1` and `SIGN_VERIFY` in the same Region.
   Send their public keys to Miden so we can register them with Circle for mainnet.
   Wait for registration confirmation. See the [key setup commands](../xusdc-bridge/README.md#signing-keys).
2. Give the service `kms:DescribeKey`, `kms:GetPublicKey` and `kms:Sign` access to those two keys,
   through its AWS role and the KMS key policies. It does not need key administration permissions.
3. Get the network settings from Miden: URLs, faucet ID and deployment block, verified anchor,
   finality depth, fee limits and forwarding addresses. Do not copy testnet settings into mainnet.

Use full key ARNs, not aliases. The expected public keys are compressed secp256k1 hex (33 bytes),
not the DER/base64 form AWS exports. Miden supplies the checked values. Both keys must match
those registered with Circle; their order does not matter.

## Build and run

Use the repository's pinned Rust toolchain:

```sh
cargo build --locked --release -p xusdc-attester
./target/release/xusdc-attester --help
```

Replace every `<...>` below. Timing values are examples.

```sh
./target/release/xusdc-attester \
  --signer-provider aws-kms \
  --aws-kms-region '<AWS_REGION>' \
  --aws-kms-key-arn '<KEY_ARN_1>' '<KEY_ARN_2>' \
  --aws-kms-operation-timeout 10s \
  --expected-signing-public-key '<PUBLIC_KEY_1_HEX>' \
  --expected-signing-public-key '<PUBLIC_KEY_2_HEX>' \
  --miden-rpc-url '<MIDEN_RPC_URL>' \
  --circle-url '<CIRCLE_HTTPS_URL>' \
  --request-timeout 30s \
  --faucet-account-id '<FAUCET_HEX_ID>' \
  --faucet-deployment-block '<DEPLOYMENT_BLOCK>' \
  --trusted-anchor-block '<ANCHOR_BLOCK>' \
  --trusted-anchor-commitment '<ANCHOR_COMMITMENT>' \
  --minimum-finality-depth-blocks '<FINALITY_DEPTH>' \
  --max-withdrawal-fee '<FIXED_FEE_LIMIT>' \
  --max-withdrawal-fee-bps '<ADDITIONAL_FEE_BASIS_POINTS>' \
  --cctp-forwarding-max-fee '<CCTP_FEE_LIMIT>' \
  --cctp-forwarder-address '<XRESERVE_ADDRESS_ON_ARC>' \
  --cctp-token-messenger-address '<TOKEN_MESSENGER_V2_ADDRESS_ON_ARC>' \
  --poll-interval 1s \
  --store-path '<ABSOLUTE_DATABASE_PATH>'
```

The faucet ID and anchor commitment use `0x`-prefixed lowercase hex. The anchor must be at or
before faucet deployment. Create the database's parent directory first.

Fee amounts use the smallest USDC unit (one million per USDC). The allowed fee is the fixed
amount plus the configured basis points of the burn amount. The CCTP cap must be positive and
below the fixed fee limit. This version requires all forwarding settings, even for direct routes.

## Restarts and holds

Keep the database on persistent storage. Run one attester per database and reuse it on restart.
Stop with SIGTERM or Ctrl-C and let the current cycle finish. Back up while stopped before
upgrading; do not delete the database, change its anchor, or assume every older version is compatible.

A hold survives restart and needs investigation. With the service stopped, list holds:

```sh
./target/release/xusdc-attester release-holds \
  --store-path '<ABSOLUTE_DATABASE_PATH>' \
  --faucet-account-id '<FAUCET_HEX_ID>' \
  --trusted-anchor-block '<ANCHOR_BLOCK>' \
  --trusted-anchor-commitment '<ANCHOR_COMMITMENT>'
```

To release a reviewed hold, add `--note-id '<NOTE_ID>'`. Repeat the flag for several holds.
Before releasing a held withdrawal, check with Circle that it did not accept the saved request.
Release discards that old signed request; the next run prepares and signs again.
The command cannot check Circle for you. Never run it automatically on startup.

Logs use `RUST_LOG`, defaulting to `info`. Monitor holds, failed withdrawals and stalled discovery.
This version cannot discover burn notes created and consumed within the same block.
Startup success alone does not prove Circle registration or successful settlement.
