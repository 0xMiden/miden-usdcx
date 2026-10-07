# Run the USDCx bridge

Gateway runs `usdcx-bridge` as one process with two services:

- The deposit relayer reads Circle's deposit attestations and submits mint notes to the Miden
  USDCx faucet.
- The withdrawal attester verifies burns on Miden, signs withdrawals with Gateway's two AWS KMS
  keys, and submits them to Circle.

Use `ghcr.io/0xmiden/miden-usdcx-bridge:v0.17.1`, available for `linux/amd64` and `linux/arm64`.
Run one instance per network, with separate testnet and mainnet configuration, keys and durable
volumes. Never share stores with another bridge or standalone worker.

## Get the network configuration

Ask **Philipp on Slack** for this network's values:

- Miden RPC URL, Circle xReserve HTTPS URL, and USDCx faucet account ID.
- Circle's deposit signing public key, already enabled on the faucet.
- Faucet deployment block, a verified block number and hash (the trusted anchor), and minimum
  finality depth. The anchor must be at or before deployment; finality depth counts blocks above
  a burn before submission.
- Approved withdrawal fee limits, CCTP forwarding fee limit, and the xReserve and TokenMessengerV2
  contract addresses on Arc for that environment.

Ask Philipp to arrange secure provisioning of a funded Miden relayer account, already on chain,
and its SDK-format signing key. Install the key as described below; the bridge creates neither.

## Create Gateway's withdrawal keys

Gateway must create **two distinct AWS KMS keys** in one Region, with key spec `ECC_SECG_P256K1`
and usage `SIGN_VERIFY`. Keep both enabled; use full key ARNs. Share their public-key exports with
Philipp so Circle registers both before startup. Private keys stay in KMS and must never be shared.

The bridge needs compressed SEC1 public keys (33-byte hex). AWS exports DER/base64; ask Philipp
for the matching hex values. These are Gateway's withdrawal keys. **Circle's deposit public key**
goes in `--relayer-attester-public-key`.

Grant the container's workload role `kms:DescribeKey`, `kms:GetPublicKey` and `kms:Sign` on both
keys, including permission in their key policies. Configure AWS credentials inside the container
through Gateway's platform, such as ECS task roles or EKS workload identity. Make sure credentials
are available inside the container, not just on the host. Do not put access keys in the image or
command line.

Allow outbound access to Miden RPC, Circle, AWS KMS and the workload credential provider. The
service listens on no inbound ports and has no HTTP health endpoint.

## Prepare storage and start

On the Linux host, replace `<NETWORK>` with `testnet` or `mainnet`. Prepare durable storage owned
by UID/GID `10001`, which the image runs as:

```sh
USDCX_NETWORK='<NETWORK>'
USDCX_DATA_DIR="/srv/usdcx/$USDCX_NETWORK"
sudo install -d -m 0700 -o 10001 -g 10001 \
  "$USDCX_DATA_DIR" \
  "$USDCX_DATA_DIR/relayer" \
  "$USDCX_DATA_DIR/relayer/miden" \
  "$USDCX_DATA_DIR/relayer/miden/keystore" \
  "$USDCX_DATA_DIR/attester"
```

Install the SDK-format relayer key in `$USDCX_DATA_DIR/relayer/miden/keystore`, owned by
`10001:10001` and readable only by that user. Preserve the whole directory across restarts.

In the same shell, replace every `<PLACEHOLDER>` below. Add Gateway's platform-specific credential
mounts or environment settings; the command does not supply AWS credentials. Page size and timing
values are examples.

```sh
docker run -d --name "usdcx-bridge-$USDCX_NETWORK" --stop-timeout 360 \
  --mount "type=bind,src=$USDCX_DATA_DIR,dst=/data" \
  --env RUST_LOG=info \
  ghcr.io/0xmiden/miden-usdcx-bridge:v0.17.1 \
  run \
  --miden-rpc-url '<MIDEN_RPC_URL>' \
  --circle-url '<CIRCLE_XRESERVE_HTTPS_URL>' \
  --faucet-account-id '<USDCX_FAUCET_ID>' \
  --relayer-page-size 100 \
  --relayer-request-timeout 30s \
  --relayer-poll-interval 5s \
  --relayer-miden-data-dir /data/relayer/miden \
  --relayer-expiration-delta 64 \
  --relayer-account-id '<RELAYER_ACCOUNT_ID>' \
  --relayer-attester-public-key '<CIRCLE_DEPOSIT_PUBLIC_KEY_HEX>' \
  --relayer-state-file /data/relayer/progress.json \
  --signer-provider aws-kms \
  --aws-kms-region '<AWS_REGION>' \
  --aws-kms-key-arn '<GATEWAY_KEY_ARN_1>' '<GATEWAY_KEY_ARN_2>' \
  --aws-kms-operation-timeout 10s \
  --expected-signing-public-key '<GATEWAY_PUBLIC_KEY_1_HEX>' \
  --expected-signing-public-key '<GATEWAY_PUBLIC_KEY_2_HEX>' \
  --attester-request-timeout 30s \
  --faucet-deployment-block '<DEPLOYMENT_BLOCK>' \
  --trusted-anchor-block '<ANCHOR_BLOCK>' \
  --trusted-anchor-commitment '<ANCHOR_COMMITMENT>' \
  --minimum-finality-depth-blocks '<FINALITY_DEPTH>' \
  --max-withdrawal-fee '<FIXED_FEE_LIMIT>' \
  --max-withdrawal-fee-bps '<FEE_BASIS_POINTS>' \
  --cctp-forwarding-max-fee '<CCTP_FEE_LIMIT>' \
  --cctp-forwarder-address '<XRESERVE_ADDRESS_ON_ARC>' \
  --cctp-token-messenger-address '<TOKEN_MESSENGER_V2_ADDRESS_ON_ARC>' \
  --attester-poll-interval 1s \
  --attester-store-path /data/attester/store.sqlite3
```

Use canonical `0x`-prefixed lowercase hex for the faucet ID and 32-byte anchor commitment.
Fee units: `1000000` = 1 USDC; 1 basis point = 0.01%. The withdrawal fee limit is the fixed fee
plus basis points of the burned amount and must cover Circle and CCTP fees. The CCTP limit must
be positive.

Watch startup with `docker logs -f "usdcx-bridge-$USDCX_NETWORK"`. Wait for
`deposit relayer and withdrawal attester started` before enabling deposits. This confirms startup,
not a completed bridge transfer.

All options:

```sh
docker run --rm --network none ghcr.io/0xmiden/miden-usdcx-bridge:v0.17.1 run --help
```

## Stop, restart and upgrade

```sh
docker stop "usdcx-bridge-$USDCX_NETWORK"
docker start "usdcx-bridge-$USDCX_NETWORK"
```

Stop sends SIGTERM and drains the current page and withdrawal cycle. Keep the platform's stop
timeout above the process's five-minute limit (360 seconds above). If either service exits
unexpectedly, both stop with an error. Restart with the same volume and configuration.

Before upgrading, stop and securely back up the entire data directory, including the keystore.
Confirm the image version with Philipp for the deployed faucet; updating the service does not
update the faucet. Client 0.17.2 upgrades its store version, which older clients cannot open;
coordinate rollback with Philipp.

## Troubleshooting

Use the logs and exit status to check configuration, AWS permissions, outbound access and directory
ownership. A locked store may mean another instance is running. For persistent errors, send Philipp
the network, image tag, logs and affected transaction or note IDs on Slack; never send secrets.

Contact Philipp for held withdrawals; restarting does not release them. Do not automatically
release holds, delete state or change the anchor to clear an error. Stop the bridge before agreed
maintenance; the image's `release-holds --help` describes that command.
