# Run the USDCx bridge

`usdcx-bridge` is one service that handles deposits and withdrawals. Run one binary or Docker
container with one `run` command. It starts both workers:

- The deposit relayer reads Circle's deposit attestations and submits mint notes to the Miden
  USDCx faucet.
- The withdrawal attester verifies burns on Miden, signs withdrawals with two AWS KMS
  keys, and submits them to Circle.

The faucet is the Miden contract that creates (mints) and destroys (burns) USDCx.

You do not need to start or configure separate relayer and attester binaries. All flags below
belong to `usdcx-bridge run`; their prefixes identify which worker uses them. The process starts
work only after both workers pass startup checks, and stops both if either exits unexpectedly.

Use `ghcr.io/0xmiden/miden-usdcx-bridge:v0.17.1`, available for `linux/amd64` and `linux/arm64`.
Run one instance per network, with separate testnet and mainnet configuration, keys and durable
volumes. Never share stores with another bridge or standalone worker.

## Gather the configuration

Supply these values for the target network:

- From the network deployment configuration: Miden RPC URL, faucet ID and deployment block,
  verified checkpoint (the trusted anchor), and agreed finality depth. Do not guess these values.
- From Circle's configuration for that environment: xReserve API URL, deposit signing public key,
  and xReserve and TokenMessengerV2 addresses on Arc. The deposit key must be enabled on the faucet.
- From your infrastructure: durable storage paths, a public relayer account and its keystore, and two
  AWS KMS withdrawal keys. The sections below explain storage and KMS setup.
- From current Circle fee quotes and the deployment's fee policy: the three withdrawal fee limits.
  Use the [fee setup guide](FEES.md); fees differ by destination and withdrawal amount.

Use a public Miden relayer account that is already deployed on the target network. **Miden funds
this account to cover the transaction fees for submitting mint notes.** Coordinate initial funding
and top-ups with Miden Ops; the operator is not expected to pay these fees. The bridge does not
create or automatically fund the account.

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

Obtain the relayer account ID and its complete Miden SDK 0.17.2 keystore directory securely from
whoever provisions the account. Copy the directory's contents into
`$USDCX_DATA_DIR/relayer/miden/keystore`, preserving filenames. Set ownership to `10001:10001`,
directory permissions to `0700` and key-file permissions to `0600`. This is separate from the
withdrawal KMS keys. Preserve the whole directory across restarts.

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

This is the complete flag reference for the single `usdcx-bridge run` command in v0.17.1.
Pass all required flags together, as in the Docker command above. **Required** means there is no default.
Only the relayer polling interval and expiration delta have defaults. KMS settings are required
because `aws-kms` is the only supported signer. Durations accept values such as `30s` or `500ms`;
paths below refer to locations inside the container.

Fee amounts use USDC base units: `1000000` = 1 USDC. One basis point = 0.01%.
The [fee setup guide](FEES.md) explains how the three fee settings work together.

| Flag | Required or default | Purpose and how to choose the value |
| --- | --- | --- |
| `--miden-rpc-url` | Required | RPC URL supplied for the target Miden network, including `https://` or `http://`. Used by both workers. |
| `--circle-url` | Required | Circle xReserve HTTPS API base URL for the matching environment. Used by both workers. |
| `--faucet-account-id` | Required | Deployed USDCx faucet ID from the network configuration, in canonical lowercase `0x` hex. Used by both workers. |
| `--relayer-page-size` | Required | Deposits per Circle page, from `1` to `1000`. One page becomes one mint transaction. The example uses `100`; size for expected traffic and transaction limits. |
| `--relayer-request-timeout` | Required | Positive timeout for each relayer request to Circle. The example uses `30s`; allow for network latency. |
| `--relayer-poll-interval` | Optional; `5s` | Wait between polls after catching up with the deposit feed. |
| `--relayer-miden-data-dir` | Required | Durable directory for the Miden client store and relayer keystore. |
| `--relayer-expiration-delta` | Optional; `64` | Blocks allowed for mint transaction inclusion before retrying the page. Integer from `1` to `65535`. |
| `--relayer-account-id` | Required | ID of the deployed, funded public Miden account that creates mint notes, as `0x` hex or bech32. Install its keystore and coordinate fee funding with Miden Ops. |
| `--relayer-attester-public-key` | Required | Deposit signing public key supplied by Circle and enabled on the faucet. Compressed SEC1 hex, optionally prefixed with `0x`. Not a withdrawal KMS key. |
| `--relayer-state-file` | Required | Durable file recording progress through Circle's deposit feed. |
| `--attester-request-timeout` | Required | Positive timeout for each attester request to Circle. The example uses `30s`; allow for network latency. |
| `--attester-poll-interval` | Required | Positive delay between attester cycles. The example uses `1s`; choose according to RPC and Circle request limits. |
| `--attester-store-path` | Required | Durable SQLite file. Its parent directory must exist and only one attester may open it. |
| `--faucet-deployment-block` | Required | Deployment height from the network's faucet deployment record. A fresh store starts scanning here; an existing store retains its scan start. |
| `--trusted-anchor-block` | Required | Verified checkpoint height from the network configuration, at or before faucet deployment. |
| `--trusted-anchor-commitment` | Required | That checkpoint's verified 32-byte block commitment, in canonical lowercase `0x` hex. Keep the original anchor for an existing store. |
| `--minimum-finality-depth-blocks` | Required | Positive number of blocks above a burn before submission. Use the network's agreed withdrawal finality depth. |
| `--max-withdrawal-fee` | Required | Fixed part of the withdrawal fee allowance, in USDC base units. Size from Circle quotes using the fee guide. |
| `--max-withdrawal-fee-bps` | Required | Extra allowance as whole basis points of the burned amount. Choose with the fixed allowance using the fee guide. |
| `--cctp-forwarding-max-fee` | Required | Positive cap for an additional CCTP transfer, in USDC base units. Size using the fee guide; required but not added for direct routes. |
| `--cctp-forwarder-address` | Required | Nonzero `0x` address of xReserve on Arc, confirmed for the target Circle environment. |
| `--cctp-token-messenger-address` | Required | Nonzero `0x` address of TokenMessengerV2 on Arc, confirmed for that environment. Must differ from the xReserve address. |
| `--signer-provider` | Required | `aws-kms`. No other provider is supported. |
| `--aws-kms-region` | Required | AWS Region containing both keys. |
| `--aws-kms-key-arn` | Required | Two distinct full key ARNs after this single flag: `ARN1 ARN2`. Do not use aliases. |
| `--aws-kms-operation-timeout` | Required | Positive deadline for each KMS operation, including retries. The example uses `10s`; allow for KMS request latency and retries. |
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
