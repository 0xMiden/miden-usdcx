# Run the USDCx bridge

`usdcx-bridge` runs two services in one process:

- The deposit relayer reads Circle's deposit attestations and submits mint notes to the Miden
  USDCx faucet.
- The withdrawal attester verifies burns on Miden, signs withdrawals with two AWS KMS
  keys, and submits them to Circle.

Use `ghcr.io/0xmiden/miden-usdcx-bridge:v0.17.1`, available for `linux/amd64` and `linux/arm64`.
Run one instance per network, with separate testnet and mainnet configuration, keys and durable
volumes. Never share stores with another bridge or standalone worker.

## Network configuration

Supply these values for the target network:

- Miden RPC URL, Circle xReserve HTTPS URL, and USDCx faucet account ID.
- Circle's deposit signing public key, already enabled on the faucet.
- Faucet deployment block, a verified block number and hash (the trusted anchor), and minimum
  finality depth. The anchor must be at or before deployment; finality depth counts blocks above
  a burn before submission.
- Approved withdrawal fee limits, CCTP forwarding fee limit, and the xReserve and TokenMessengerV2
  contract addresses on Arc for that environment.

Provision a funded Miden relayer account on chain and install its SDK-format signing key as
described below. The bridge does not create or fund the account.

## Set up withdrawal signing

Create **two distinct AWS KMS keys** in one Region, with key spec `ECC_SECG_P256K1` and usage
`SIGN_VERIFY`. Keep both enabled and use full key ARNs. Both public keys must be registered with
Circle for the target network before startup. Private keys stay in KMS and must never be shared.

Set `--expected-signing-public-key` to each key's compressed SEC1 public key (33-byte hex), not
the DER/base64 export returned by AWS. These are the withdrawal keys. **Circle's deposit public
key** is separate and goes in `--relayer-attester-public-key`.

Grant the container's workload role `kms:DescribeKey`, `kms:GetPublicKey` and `kms:Sign` on both
keys, including permission in their key policies. Configure AWS credentials inside the container
through your deployment platform, such as ECS task roles or EKS workload identity. Make sure
credentials are available inside the container, not just on the host. Do not put access keys in
the image or command line.

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

In the same shell, replace every `<PLACEHOLDER>` below. Add your platform's credential
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
  --aws-kms-key-arn '<KMS_KEY_ARN_1>' '<KMS_KEY_ARN_2>' \
  --aws-kms-operation-timeout 10s \
  --expected-signing-public-key '<SIGNING_PUBLIC_KEY_1_HEX>' \
  --expected-signing-public-key '<SIGNING_PUBLIC_KEY_2_HEX>' \
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
Choose the fee limits using the [fee setup guide](FEES.md), which shows how to retrieve Circle's
current fees, add a buffer and convert the results into CLI values.

Watch startup with `docker logs -f "usdcx-bridge-$USDCX_NETWORK"`. Wait for
`deposit relayer and withdrawal attester started` before enabling deposits. This confirms startup,
not a completed bridge transfer.

All options:

```sh
docker run --rm --network none ghcr.io/0xmiden/miden-usdcx-bridge:v0.17.1 run --help
```

## Configuration flags

These tables describe `usdcx-bridge run` in v0.17.1. **Required** means there is no default.
Only the relayer polling interval and expiration delta have defaults. KMS settings are required
because `aws-kms` is the only supported signer. Durations accept values such as `30s` or `500ms`;
paths below refer to locations inside the container.

### Shared network settings

| Flag | Required or default | What to supply |
| --- | --- | --- |
| `--miden-rpc-url` | Required | Miden RPC URL for the target network, including `https://` or `http://`. |
| `--circle-url` | Required | Circle xReserve HTTPS API base URL for that environment. |
| `--faucet-account-id` | Required | Deployed USDCx faucet ID in canonical `0x`-prefixed lowercase hex. Both services use this faucet. |

### Deposit relayer

| Flag | Required or default | What to supply |
| --- | --- | --- |
| `--relayer-page-size` | Required | Deposits per Circle page, from `1` to `1000`. One page is submitted as one mint transaction. |
| `--relayer-request-timeout` | Required | Positive timeout for each relayer request to Circle. |
| `--relayer-poll-interval` | Optional; `5s` | Wait between polls after catching up with the deposit feed. |
| `--relayer-miden-data-dir` | Required | Durable directory for the Miden client store and relayer keystore. |
| `--relayer-expiration-delta` | Optional; `64` | Blocks allowed for mint transaction inclusion before retrying the page. Integer from `1` to `65535`. |
| `--relayer-account-id` | Required | Funded account that creates mint notes, as `0x`-prefixed hex or bech32. Its key must be in the keystore. |
| `--relayer-attester-public-key` | Required | Circle's deposit signing key, already enabled on the faucet. Compressed SEC1 hex, optionally prefixed with `0x`. Not a withdrawal KMS key. |
| `--relayer-state-file` | Required | Durable file recording progress through Circle's deposit feed. |

### Withdrawal attester

Fee amounts use USDC base units: `1000000` = 1 USDC. One basis point = 0.01%.
The [fee setup guide](FEES.md) explains how the three fee settings work together.

| Flag | Required or default | What to supply |
| --- | --- | --- |
| `--attester-request-timeout` | Required | Positive timeout for each attester request to Circle. |
| `--attester-poll-interval` | Required | Positive delay between attester cycles. |
| `--attester-store-path` | Required | Durable SQLite file. Its parent directory must exist and only one attester may open it. |
| `--faucet-deployment-block` | Required | Faucet deployment height, where a fresh store starts scanning. An existing store retains its scan start. |
| `--trusted-anchor-block` | Required | Verified checkpoint height at or before faucet deployment. |
| `--trusted-anchor-commitment` | Required | That checkpoint's 32-byte block commitment in canonical lowercase `0x` hex. Keep the original anchor for an existing store. |
| `--minimum-finality-depth-blocks` | Required | Positive number of blocks above a burn before it can be submitted. |
| `--max-withdrawal-fee` | Required | Fixed part of the total fee allowance per withdrawal, in USDC base units. |
| `--max-withdrawal-fee-bps` | Required | Extra allowance as whole basis points of the burned amount, added to the fixed part. |
| `--cctp-forwarding-max-fee` | Required | Positive cap in USDC base units for the additional CCTP transfer. Required even when only direct destinations are used. |
| `--cctp-forwarder-address` | Required | Nonzero `0x` address of xReserve on Arc for the target environment. |
| `--cctp-token-messenger-address` | Required | Nonzero `0x` address of TokenMessengerV2 on Arc for that environment. Must differ from the xReserve address. |

### Withdrawal signing

| Flag | Required or default | What to supply |
| --- | --- | --- |
| `--signer-provider` | Required | `aws-kms`. No other provider is supported. |
| `--aws-kms-region` | Required | AWS Region containing both keys. |
| `--aws-kms-key-arn` | Required | Two distinct full key ARNs after this single flag: `ARN1 ARN2`. Do not use aliases. |
| `--aws-kms-operation-timeout` | Required | Positive deadline for each KMS operation, including retries. |
| `--expected-signing-public-key` | Required, exactly twice | One compressed SEC1 public key per flag. These must match the two KMS keys registered with Circle. |

`-h` / `--help` and `-V` / `--version` are optional and print information without starting services.
`RUST_LOG` is an optional environment variable, not a CLI flag; the example sets it to `info`.

## Stop, restart and upgrade

```sh
docker stop "usdcx-bridge-$USDCX_NETWORK"
docker start "usdcx-bridge-$USDCX_NETWORK"
```

Stop sends SIGTERM and drains the current page and withdrawal cycle. Keep the platform's stop
timeout above the process's five-minute limit (360 seconds above). If either service exits
unexpectedly, both stop with an error. Restart with the same volume and configuration.

Before upgrading, stop and securely back up the entire data directory, including the keystore.
Use an image version compatible with the deployed faucet; updating the service does not update
the faucet. Client 0.17.2 upgrades its store version, which older clients cannot open. Keep a
backup from before the upgrade if rollback is needed.

## Troubleshooting

Use the logs and exit status to check configuration, AWS permissions, outbound access and directory
ownership. A locked store may mean another instance is running.

Investigate held withdrawals before releasing them; restarting does not release them. Do not
automatically release holds, delete state or change the anchor to clear an error. Stop the bridge
before releasing holds; the image's `release-holds --help` describes that command.

### Hold maintenance flags

`usdcx-bridge release-holds` runs once and exits; it does not start either service or require KMS.
Without note IDs it only lists holds. Supply IDs only after checking that Circle did not accept
any saved withdrawal request: releasing that hold deletes the request and permits new preparation.

| Flag | Required or default | What to supply |
| --- | --- | --- |
| `--store-path` | Required | Existing attester SQLite file. This command uses `--store-path`, not `--attester-store-path`. |
| `--faucet-account-id` | Required | Faucet ID saved in that store. |
| `--trusted-anchor-block` | Required | Original anchor height saved in that store. |
| `--trusted-anchor-commitment` | Required | Original anchor commitment saved in that store. |
| `--note-id` | Optional | A held note ID to release. Repeat for multiple IDs. |
| `--note-ids-file` | Optional | File of held note IDs to release. The first word on each line is read as an ID. |
| `-h` / `--help` | Optional | Show help without opening the store. |
