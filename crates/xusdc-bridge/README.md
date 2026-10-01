# Run both bridge services

`xusdc-bridge` runs the deposit relayer and withdrawal attester in one process. Their code and
saved state stay separate. Use this binary for a single Gateway service deployment.

## Signing keys

Before mainnet setup, Gateway must create two different AWS KMS ECDSA keys in the same Region.
Use secp256k1 (`ECC_SECG_P256K1`) and `SIGN_VERIFY`. As a key administrator, run this once for
each key, using a different description. Do not create replacements if the keys already exist.
Save each full ARN returned:

```sh
aws kms create-key --region '<AWS_REGION>' \
  --key-spec ECC_SECG_P256K1 --key-usage SIGN_VERIFY \
  --description '<SIGNER_NAME>' --query KeyMetadata.Arn --output text
```

Download the public keys:

```sh
aws kms get-public-key --region '<AWS_REGION>' --key-id '<KEY_ARN_1>' \
  --output json > withdrawal-key-1.public.json
aws kms get-public-key --region '<AWS_REGION>' --key-id '<KEY_ARN_2>' \
  --output json > withdrawal-key-2.public.json
```

Send both public-key files to Miden. We will pass them to Circle for mainnet registration and
provide the compressed public-key hex values for the command below. Wait for our confirmation
before processing live withdrawals. Never send private keys or AWS credentials.

Give the service's AWS role only `kms:DescribeKey`, `kms:GetPublicKey` and `kms:Sign` access on
those keys. The role and key policies must allow it. Use renewable machine credentials, not a
developer's SSO session. Both keys are used by the same process, not two independent operators.

AWS references: [key creation](https://docs.aws.amazon.com/cli/latest/reference/kms/create-key.html)
and [public-key export](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html).

## Build and run

Use the repository's pinned Rust toolchain:

```sh
cargo build --locked --release -p xusdc-bridge
./target/release/xusdc-bridge --help
```

For deployment, agree the Linux CPU architecture with Gateway and build for that host. Docker
is optional; if Gateway uses it, mount persistent storage and pass AWS access at runtime.
Do not put credentials in the image.

Get all network settings from Miden. The relayer also needs an existing funded Miden account
and its key in `<MIDEN_DATA_DIR>/keystore/`. That key and Circle's deposit public key are
separate from the two withdrawal keys above.

Replace every `<...>` below. Use absolute paths and create their parent directories first.
The page size, timeout, polling and shutdown values are examples, not measured hosting requirements.

```sh
./target/release/xusdc-bridge \
  --miden-rpc-url '<MIDEN_RPC_URL>' \
  --circle-url '<CIRCLE_HTTPS_URL>' \
  --faucet-account-id '<FAUCET_HEX_ID>' \
  --shutdown-grace 5m \
  --relayer \
    --page-size 100 \
    --request-timeout 30s \
    --poll-interval 5s \
    --miden-data-dir '<ABSOLUTE_MIDEN_DATA_DIR>' \
    --expiration-delta 64 \
    --relayer-account-id '<RELAYER_ID>' \
    --attester-public-key '<CIRCLE_DEPOSIT_PUBLIC_KEY_HEX>' \
    --state-file '<ABSOLUTE_RELAYER_PROGRESS_FILE>' \
  --attester \
    --signer-provider aws-kms \
    --aws-kms-region '<AWS_REGION>' \
    --aws-kms-key-arn '<KEY_ARN_1>' '<KEY_ARN_2>' \
    --aws-kms-operation-timeout 10s \
    --expected-signing-public-key '<PUBLIC_KEY_1_HEX>' \
    --expected-signing-public-key '<PUBLIC_KEY_2_HEX>' \
    --request-timeout 30s \
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
    --store-path '<ABSOLUTE_ATTESTER_DATABASE_PATH>'
```

Shared settings go first, then `--relayer`, then `--attester`. Do not repeat shared settings
inside a group. The bundle uses the attester's Miden Circle domain for both services.
The individual [relayer](../xreserve-deposit-relayer/README.md) and
[attester](../xusdc-light-attester/README.md) guides explain their settings and limitations.

## Running the service

- Run one active bundle for the account and files. Do not run the standalone services beside it.
- Keep the relayer data directory, progress file and attester database on persistent storage.
  Use separate paths, restrict access to the keystore, and back up while stopped.
- Send SIGTERM to stop. The relayer finishes its current page; the attester finishes its cycle.
  If shutdown exceeds `--shutdown-grace`, the process exits with an error. Set Gateway's stop
  timeout longer than this grace period. A forced stop is not a clean shutdown.
- A fatal service exit stops the pair. Restart with the same files. Normal retryable errors
  still use each service's retry loop. Do not delete state to clear errors.
- Capture logs (`RUST_LOG=info` by default) and monitor actual mint and withdrawal progress.
  A running process alone does not show that the bridge is working.

For held withdrawals, stop the bundle and use the standalone attester's
[hold command](../xusdc-light-attester/README.md#restarts-and-holds) from the same source version.
Build it with `cargo build --locked --release -p xusdc-attester` if needed.
Do not release holds automatically on restart.
