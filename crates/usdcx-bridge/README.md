# USDCx bridge service

`usdcx-bridge` runs the existing deposit relayer and withdrawal attester as one deployable
service. This is a product decision to reduce the number of services operators manage. Their
logic and stores remain independent; the supervisor coordinates startup and shutdown.

## Docker image

The release workflow publishes `ghcr.io/0xmiden/miden-usdcx-bridge:<RELEASE_TAG>` for
`linux/amd64` and `linux/arm64`. Use a published release tag or its digest for upgrades and
rollbacks. Publishing requires GHCR package access from this repository; make the package public
if operators should pull it without authentication. Adding this workflow does not publish a release.

A V2 fee faucet needs a bridge build with the V2 callback libraries, even if its account ID stays
the same. Use a release tested with that faucet version. Run separate bridge instances for testnet
and mainnet, each with its own network configuration, identities and stores. Updating the bridge
does not upgrade the faucet.

Before upgrading, stop the bridge and back up the relayer's SDK store. Client 0.17.2 updates its
store version; older clients cannot reopen it.

For a local build from the repository root:

```sh
just build-bridge-image linux/arm64 usdcx-bridge:local
# Use linux/amd64 for an x86-64 image.
```

The image runs as UID/GID `10001`, includes CA certificates, and stores state below `/data`. It
listens on **no inbound ports** and currently has **no HTTP health endpoint**. Logs go to stdout;
`RUST_LOG` controls their level, and [Tracing](#tracing) covers exporting spans. Startup checks
cover configuration, local state, the attester's chain/KMS checks, and that the faucet has enabled
the relayer's Circle deposit public key. They do not prove that every external request or
transaction will succeed. The relayer key must be installed before start.

## AWS KMS access

Provide a workload IAM role through the platform's normal AWS SDK credential provider, such as
an ECS task role, EKS workload identity or an EC2 instance role reachable from the container.
An IAM role attached to the host is insufficient if its credential provider is unavailable inside
the container. Do not put access keys in the image or CLI, or use a human SSO session for the service.

Grant the workload `kms:DescribeKey`, `kms:GetPublicKey` and `kms:Sign` only for the two approved
full key ARNs. Each key policy must allow that role; cross-account access needs both the workload
policy and the key policies. Both keys must be distinct, enabled, registered with Circle, in the
configured Region, and use `ECC_SECG_P256K1` with `SIGN_VERIFY`.

Pass both ARNs and both registered compressed 33-byte public keys below. Startup checks key
metadata and public keys. Each withdrawal makes one `Sign` call per key and verifies the returned
signatures locally. The private signing keys remain in KMS.

## Run

Prepare durable `/srv/usdcx/relayer/miden/keystore` and `/srv/usdcx/attester` directories owned
by `10001:10001`, mode `0700`. Install the funded relayer account's key in the keystore before
starting. Supply reviewed network identities and fee limits; the timing values below are examples.
Replace `<RELEASE_TAG>` with a published image tag.

```sh
docker run --name usdcx-bridge --stop-timeout 360 \
  --mount type=bind,src=/srv/usdcx,dst=/data \
  --env RUST_LOG=info \
  'ghcr.io/0xmiden/miden-usdcx-bridge:<RELEASE_TAG>' \
  run \
  --miden-rpc-url '<MIDEN_RPC_URL>' \
  --circle-url '<CIRCLE_XRESERVE_URL>' \
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
  --aws-kms-key-arn '<KEY_ARN_1>' '<KEY_ARN_2>' \
  --aws-kms-operation-timeout 10s \
  --expected-signing-public-key '<PUBLIC_KEY_1_HEX>' \
  --expected-signing-public-key '<PUBLIC_KEY_2_HEX>' \
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

| Configuration | Supply |
| --- | --- |
| Network and Circle | RPC URL, HTTPS Circle URL and faucet ID, each given once and used by both workers; outbound access to RPC, Circle, KMS and the workload credential provider. |
| Deposit relayer | Funded account ID and installed Miden key, registered Circle deposit public key, page size and durable progress/SDK paths. |
| Withdrawal attester | Two KMS ARNs, Region, expected public keys, faucet deployment block, authenticated anchor, finality depth, withdrawal/CCTP fee limits and forwarding addresses. |
| Runtime | Workload identity, writable durable `/data`, optional `RUST_LOG` and `OTEL_*` variables; no inbound port or health URL. |

The relayer's own flags start with `--relayer-`. The attester's timeout, poll interval and store
path start with `--attester-`; its other flags keep their own names. For every supported flag, run
the image with `run --help`.

Run one instance against these stores, without standalone workers beside it. Wait for
`deposit relayer and withdrawal attester started` before enabling deposits. The relayer progress
file is validated and saved without advancing its watermark during startup; a malformed or
unwritable file prevents that message. Installing the relayer authentication key remains an operator
prerequisite. Later transient scan failures are logged and retried.

`docker stop usdcx-bridge` sends SIGTERM. Shutdown drains the current page and withdrawal cycle,
with a five-minute process limit; keep the host timeout above five minutes. If either worker exits
unexpectedly, the supervisor stops the other and exits with an error. Restart with the same volume
and configuration. Never delete state to clear an operational error.

## Tracing

Logs go to stdout, filtered by `RUST_LOG` (default `info`). Setting an OTLP endpoint also exports
the relayer's and attester's spans over OpenTelemetry, using gRPC with the system's root
certificates for TLS:

| Variable | Meaning |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Where to send the spans, for example `https://api.honeycomb.io:443`. Export is off when it is unset or blank. `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` takes precedence when both are set. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Headers sent with each export, for example `x-honeycomb-team=<API_KEY>`. |
| `OTEL_SERVICE_NAME` | The exported `service.name`; defaults to `usdcx-bridge`. |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, for example `deployment.environment=testnet`. |

The other standard `OTEL_EXPORTER_OTLP_*` variables, such as the timeout and compression, apply as
well. `RUST_LOG` does not filter the export: it always carries the relayer's and attester's spans
and events at `info` and above, and only warnings from their dependencies.

The attester's startup is an `attester.startup` span. Each cycle is an `attester.cycle` span, with
`attester.discover`, `attester.recover`, `attester.submit` and `attester.poll` under it for its
phases and an `attester.withdraw` span, carrying `note.id`, for each burn it submits. A cycle span
fails only when the cycle as a whole could not do its work: discovery failed, the chain diverged or
the store failed. A failure confined to one burn never fails the cycle span. Every failed span
carries `failure.class` (`integrity`, `actionable` or `transient`) and `failure.kind`.

## Release held withdrawals

The attester holds a burn that Circle refuses to prepare, and leaves it held until an operator
releases it. Stop the bridge first, because only one process may open the attester store, then run
`release-holds` from the same image against the same volume:

```sh
docker run --rm \
  --mount type=bind,src=/srv/usdcx,dst=/data \
  'ghcr.io/0xmiden/miden-usdcx-bridge:<RELEASE_TAG>' \
  release-holds \
    --store-path /data/attester/store.sqlite3 \
    --faucet-account-id '<USDCX_FAUCET_ID>' \
    --trusted-anchor-block '<ANCHOR_BLOCK>' \
    --trusted-anchor-commitment '<ANCHOR_COMMITMENT>'
```

Without `--note-id` it lists the holds. Add `--note-id '<NOTE_ID>'` once per hold to release.
Release a held withdrawal only after checking that Circle did not accept its saved request, then
start the bridge again.
