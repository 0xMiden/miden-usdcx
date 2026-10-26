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

Use `ghcr.io/0xmiden/miden-usdcx-bridge:<TAG>` and follow the README at the matching release tag.
Replace `<BRIDGE_IMAGE>` below with the image you deploy.

To build from source instead, run this command from the repository root and use
`usdcx-bridge:local` as `<BRIDGE_IMAGE>`:

```sh
docker build -f crates/usdcx-bridge/Dockerfile -t usdcx-bridge:local .
```

Images up to v0.17.2 do not include live hold management and require `--signer-provider aws-kms`.
That flag is no longer accepted by the CLI documented here.

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
service listens on no inbound ports and has no HTTP health endpoint. The optional local admin
socket is described below.

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

Obtain the relayer account ID and its complete Miden SDK 0.17.3 keystore directory securely from
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
  '<BRIDGE_IMAGE>' \
  run \
  --miden-rpc-url '<MIDEN_RPC_URL>' \
  --circle-url '<CIRCLE_XRESERVE_HTTPS_URL>' \
  --faucet-account-id '<USDCX_FAUCET_ID>' \
  --relayer-page-size 10 \
  --relayer-request-timeout 30s \
  --relayer-poll-interval 5s \
  --relayer-miden-data-dir /data/relayer/miden \
  --relayer-expiration-delta 64 \
  --relayer-account-id '<RELAYER_ACCOUNT_ID>' \
  --relayer-attester-public-key '<CIRCLE_DEPOSIT_PUBLIC_KEY_HEX>' \
  --relayer-state-file /data/relayer/progress.json \
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
docker run --rm --network none '<BRIDGE_IMAGE>' run --help
```

To use remote proving, add `--relayer-prover-url '<HTTP(S)_PROVER_URL>'` and choose a page size
up to `40`. Without a prover URL, proving is local and pages are capped at `10`. Smaller page
sizes are kept. The optional `--relayer-prover-timeout` defaults to `30s` and covers connection
setup and proving, not transaction submission. Allow outbound access to the configured prover.

Use a prover compatible with the deployed Miden version. It receives transaction witness data,
including account state and note contents, but not the relayer's secret key. Use HTTPS outside
a trusted local network. Startup does not check prover availability. A remote proving error or
timeout logs a warning and falls back to the same transaction locally, which may still contain
40 deposits and need substantial memory and time. Only an explicit expired-submission rejection
reduces later pages to 10 until restart. Smaller settings stay smaller; remote proving remains
the first choice. The unfinished page is retried on the next scan.
Remote proving does not extend expiration or remove node size limits. The 40-note cap was tested
with ordinary deposits without hook data; larger payloads may need smaller pages.

## Configuration flags

These are the configuration flags for the single `usdcx-bridge run` command.
Pass all required flags together, as in the Docker command above. **Required** means there is no default.
The relayer polling interval, expiration delta and remote proving timeout have defaults. The
attester signs with keys in AWS KMS, so the KMS settings are required. Durations accept values such as `30s` or `500ms`;
paths below refer to locations inside the container.

Fee amounts use USDC base units: `1000000` = 1 USDC. One basis point = 0.01%.
The [fee setup guide](FEES.md) explains how the three fee settings work together.

| Flag | Required or default | Purpose and how to choose the value |
| --- | --- | --- |
| `--miden-rpc-url` | Required | RPC URL supplied for the target Miden network, including `https://` or `http://`. Used by both workers. |
| `--circle-url` | Required | Circle xReserve HTTPS API base URL for the matching environment. Used by both workers. |
| `--faucet-account-id` | Required | Deployed USDCx faucet ID from the network configuration, in canonical lowercase `0x` hex. Used by both workers. |
| `--relayer-page-size` | Required | Deposits per Circle page, from `1` to `1000`. Initially capped at `10` without a prover URL, or `40` with one. Smaller values are kept. One page becomes one mint transaction. |
| `--relayer-prover-url` | Optional; local proving | HTTP(S) endpoint of a compatible remote transaction prover. |
| `--relayer-prover-timeout` | Optional; `30s` | Positive timeout for remote connection setup and proving. Unused with local proving. |
| `--relayer-request-timeout` | Required | Positive timeout for each relayer request to Circle. The example uses `30s`; allow for network latency. |
| `--relayer-poll-interval` | Optional; `5s` | Wait between polls after catching up with the deposit feed. |
| `--relayer-miden-data-dir` | Required | Durable directory for the Miden client store and relayer keystore. |
| `--relayer-expiration-delta` | Optional; `64` | Maximum blocks allowed for mint transaction inclusion before retrying the page. Protocol rules can shorten this lifetime. Integer from `1` to `65535`. |
| `--relayer-account-id` | Required | ID of the deployed, funded public Miden account that creates mint notes, as `0x` hex or bech32. Install its keystore and coordinate fee funding with Miden Ops. |
| `--relayer-attester-public-key` | Required | Deposit signing public key supplied by Circle and enabled on the faucet. Compressed SEC1 hex, optionally prefixed with `0x`. Not a withdrawal KMS key. |
| `--relayer-state-file` | Required | Durable file recording progress through Circle's deposit feed. |
| `--attester-request-timeout` | Required | Positive timeout for each attester request to Circle. The example uses `30s`; allow for network latency. |
| `--attester-poll-interval` | Required | Positive delay between attester cycles. The example uses `1s`; choose according to RPC and Circle request limits. |
| `--withdrawal-limit-message-prefix` | Optional, paired with the retry interval | Exact, case-sensitive start of Circle's limit error `message`. Confirm it with Circle for the deployment; do not guess a prefix from other errors. |
| `--withdrawal-limit-retry-interval` | Optional, paired with the message prefix | Positive delay between limit retries, for example `5m`. No default; agree the interval with the operator and Circle. |
| `--attester-store-path` | Required | Durable SQLite file. Its parent directory must exist and only one attester may open it. |
| `--faucet-deployment-block` | Required | Deployment height from the network's faucet deployment record. It is only checked against the anchor: startup fails if the anchor is after it. |
| `--trusted-anchor-block` | Required | Verified checkpoint height from the network configuration, at or before faucet deployment. A fresh store starts scanning here; an existing store continues from the last block it verified. |
| `--trusted-anchor-commitment` | Required | That checkpoint's verified 32-byte block commitment, in canonical lowercase `0x` hex. Keep the original anchor for an existing store. |
| `--minimum-finality-depth-blocks` | Required | Positive number of blocks above a burn before submission. Use the network's agreed withdrawal finality depth. |
| `--max-withdrawal-fee` | Required | Fixed part of the withdrawal fee allowance, in USDC base units. Size from Circle quotes using the fee guide. |
| `--max-withdrawal-fee-bps` | Required | Extra allowance as whole basis points of the burned amount. Choose with the fixed allowance using the fee guide. |
| `--cctp-forwarding-max-fee` | Required | Positive cap for an additional CCTP transfer, in USDC base units. Size using the fee guide; required but not added for direct routes. |
| `--cctp-forwarder-address` | Required | Nonzero `0x` address of xReserve on Arc, confirmed for the target Circle environment. |
| `--cctp-token-messenger-address` | Required | Nonzero `0x` address of TokenMessengerV2 on Arc, confirmed for that environment. Must differ from the xReserve address. |
| `--aws-kms-region` | Required | AWS Region containing both keys. |
| `--aws-kms-key-arn` | Required | Two distinct full key ARNs after this single flag: `ARN1 ARN2`. Do not use aliases. |
| `--aws-kms-operation-timeout` | Required | Positive deadline for each KMS operation, including retries. The example uses `10s`; allow for KMS request latency and retries. |
| `--expected-signing-public-key` | Required, exactly twice | One compressed SEC1 public key per flag. These must match the two KMS keys registered with Circle. |
| `--admin-socket` | Optional; disabled | Unix socket path for live hold management, for example `/data/attester/admin.sock`; see [Hold management while running](#hold-management-while-running). |

`-h` / `--help` and `-V` / `--version` are optional and print information without starting services.
`RUST_LOG` is an optional environment variable, not a CLI flag; the example sets it to `info`.
The optional `OTEL_*` variables export spans; [Tracing](#tracing) lists them.

## Stop, restart and upgrade

### Automatic retries after Circle's withdrawal limit

With both withdrawal-limit flags set, a matching prepare or submission rejection waits and retries
automatically. Without them, prepare and submission 400 responses keep the existing manual-hold
behavior. Existing holds are not converted automatically; inspect them before using hold release.
An uncertain submission keeps its original signed request until Circle confirms the outcome. A
verified expired outcome can be prepared again when due. Other submission 400s still require a
manual hold.

A blocked burn stops new prepares and new POSTs behind it, including uncertain resends. Recovery
runs before fresh withdrawals; after a wait clears, these two phases are not globally ordered by
burn age. A large withdrawal can delay smaller ones for much of Circle's
rolling window; one above the entire limit may never fit and needs investigation. The service does
not calculate available capacity or let smaller withdrawals pass. Accepted withdrawals continue
status checks, and live hold management remains available. Waiting for the limit is not a manual
hold and cannot be bypassed with hold release.

Retry deadlines survive restarts. A store with waiting withdrawals requires both flags on startup;
changing the interval does not shorten an already saved deadline. Each fresh prepare retry can use
both KMS signers. Choose the interval and waiting-age alerts for Circle's actual window, which need
not be the same in every environment.

This feature upgrades the attester store. Older binaries cannot open the upgraded store. Back up
before upgrading; do not restore an old backup without reconciling any withdrawals sent since it.

### Restarting the container

```sh
docker stop "usdcx-bridge-$USDCX_NETWORK"
docker start "usdcx-bridge-$USDCX_NETWORK"
```

Stop sends SIGTERM and drains the current page and withdrawal cycle. Keep the platform's stop
timeout above the process's five-minute limit (360 seconds above). A signal during startup lets it
finish under the same limit, and the bridge then stops before doing any work. If either service
exits unexpectedly, both stop with an error. Restart with the same volume and configuration.

Before upgrading, stop and securely back up the entire data directory, including the keystore.
Use an image version compatible with the deployed faucet; updating the service does not update
the faucet. When upgrading from v0.17.2 or earlier, remove `--signer-provider` from the `run`
command; it is no longer accepted. SDK store upgrades can prevent older clients from opening the
store. Keep a backup from before the upgrade if rollback is needed.

## Tracing

Logs go to stdout, filtered by `RUST_LOG` (default `info`). Setting an OTLP endpoint also exports
the relayer's and attester's spans over OpenTelemetry, using gRPC with the system's root
certificates for TLS:

| Option / variable | Meaning |
| --- | --- |
| `--otel-exporter-otlp-endpoint` / `OTEL_EXPORTER_OTLP_ENDPOINT` | Where to send the spans, for example `https://api.honeycomb.io:443`. Export is off when it is unset or blank. `--otel-exporter-otlp-traces-endpoint` / `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` takes precedence when both are set. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Headers sent with each export, for example `x-honeycomb-team=<API_KEY>`. |
| `--otel-service-name` / `OTEL_SERVICE_NAME` | The exported `service.name`; defaults to `usdcx-bridge`. |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, for example `deployment.environment=testnet`. |
| `--export-filter` / `USDCX_EXPORT_FILTER` | Which spans and events are exported, in `RUST_LOG` syntax, for example `warn,usdcx_bridge=info,xreserve_deposit_relayer=info,xusdc_attester=info,miden_client=debug` to add the node client's spans. Defaults to the services' own at `info` and above and only warnings from their dependencies. An invalid value stops startup. |

The other standard `OTEL_EXPORTER_OTLP_*` variables, such as the timeout and compression, apply as
well. `RUST_LOG` does not filter the export, so lowering the log level never removes the spans the
alerts are built on.

The attester's startup is an `attester.startup` span. Each cycle is an `attester.cycle` span, with
`attester.discover`, `attester.recover`, `attester.submit` and `attester.poll` under it for its
phases. Each burn the attester prepares, and each saved withdrawal it sends or checks with Circle,
is an `attester.withdraw` span carrying `note.id`. A cycle span fails only when the cycle as a whole
could not do its work: discovery failed, the chain diverged or the store failed. A failure confined
to one burn, such as a hold, a withdrawal Circle reports as failed, or a prepared withdrawal that
fails verification, fails only that burn's `attester.withdraw` span. Every failed span
carries `failure.class` (`integrity`, `actionable` or `transient`) and `failure.kind`.

The relayer's spans are `relayer.startup`, a `relayer.scan` root per scan and a `relayer.page` span
per page under it. Each page carries `deposits.unminted.count` and
`deposits.unminted.oldest_age_secs`, for deposits on chain that the faucet has not minted yet.
[The relayer's README](../xreserve-deposit-relayer/README.md#tracing) describes them and its failure
kinds.

Every cycle span also carries the attester's progress, zeros included:

| Field | Meaning |
| --- | --- |
| `block.number` | The last block the attester verified. |
| `tip.number` | The node's latest committed block. Left out when the node could not be read. |
| `tip.stale_duration_secs` | Seconds since the last verified block was made. It grows when the node stops producing blocks or the attester stops verifying them, and while a new store catches up from the trusted anchor. |
| `burns.held.count` | Burns held before submission. |
| `withdrawals.held.count` | Withdrawals held after Circle rejected them. |
| `withdrawals.failed.count` | Withdrawals Circle reported as failed. |
| `withdrawals.pending.count` | Withdrawals being sent, or accepted by Circle and not final yet. |
| `burns.unfinished.count` | Consumed burns not paid out yet: waiting for depth, waiting to be submitted, or submitted and not final. Held and failed burns are left out. |
| `burns.unfinished.oldest_age_blocks` | The last verified block minus the block that consumed the oldest unfinished burn; 0 when there is none. |
| `withdrawals.limit.count` | Burns waiting for Circle's withdrawal limit; 0 when none wait. |
| `withdrawals.limit.note_id` | The earliest waiting burn. Left out when none wait. |
| `withdrawals.limit.retry_at` | Its next retry time in Unix seconds. Left out when none wait. |

## Troubleshooting

Use the logs and exit status to check configuration, AWS permissions, outbound access and directory
ownership. A locked store may mean another instance is running.

Investigate held withdrawals before releasing them; restarting does not release them. Do not
automatically release holds, delete state or change the anchor to clear an error. Use the optional
local admin socket below, or stop the bridge before using the offline `release-holds` command.

### Hold management while running

Administration is disabled by default. To enable it, add
`--admin-socket /data/attester/admin.sock` to `usdcx-bridge run`. The attester creates the socket
readable and writable only by its own user, and removes it on shutdown. Anyone who can open the
socket can release holds, so keep its directory private to the service's container user. A socket
file left by a stopped attester is replaced at startup; any other file at that path stops startup.

Run these commands inside the running container, as the service's user:

```sh
usdcx-bridge admin --socket /data/attester/admin.sock holds
usdcx-bridge admin --socket /data/attester/admin.sock holds --after <NOTE_ID>
usdcx-bridge admin --socket /data/attester/admin.sock release-holds --hold <NOTE_ID>:<EVENT_SEQ> --circle-not-accepted
```

Listing shows the faucet and trusted anchor, each hold's `event_seq`, and `next_after` if there is
another page. Check that this is the intended faucet, then copy one hold's note ID and event sequence
into `--hold`. The event sequence prevents an old command from releasing a newer hold on the same
burn. Release holds one at a time; each request succeeds or fails independently.

Before releasing a held signed withdrawal, check with Circle that it was not accepted, then add
`--circle-not-accepted`. A missing withdrawal ID is not proof. Burn holds do not need that flag.
Success means the hold was released, not that the withdrawal was paid. If a command times out or
says the hold changed, list holds again and check the current state before trying another release.
A note ID that has no hold is answered `hold_not_found`: listing again will not show it, so check
the note ID.
Commands wait for any active signing or Circle request to finish and do not skip the normal retry
delay. The client never retries a release automatically.

The standalone `xusdc-attester` accepts the same commands and flags. The existing offline
`release-holds` command still accepts a list or file, but requires the service to be stopped.

For other local clients, each connection carries one JSON request line and one JSON reply line:
`{"op":"holds","after":"<NOTE_ID>"}` (the cursor is optional) or
`{"op":"release","note_id":"<NOTE_ID>","expected_event_seq":123,"circle_not_accepted":true}`. The
reply is `{"ok":…}` or `{"error":{"code":…,"message":…}}`.

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
