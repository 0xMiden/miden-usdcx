# USDCx bridge service

`usdcx-bridge` runs the deposit relayer and withdrawal attester in one process. It uses the real
service implementations and keeps their stores separate. The supervisor starts both services, handles
SIGTERM/Ctrl-C and stops the pair if either service exits unexpectedly.

## Linux ARM64 artifact

Build from the repository root on a machine with Docker Buildx:

```sh
./scripts/build-bridge-arm64.sh
```

This creates `dist/usdcx-bridge-linux-arm64` and a manifest containing its source commit, source
tree, platform and SHA-256. The build refuses a dirty checkout and the Dockerfile refuses any
platform except `linux/arm64`.

The raw binary requires ARM64 glibc Linux, such as Debian 12, with the dynamic loader,
glibc, `libgcc_s.so.1` and a CA certificate bundle installed. The supplied image includes these.

To build the runtime image instead:

```sh
docker buildx build --file crates/usdcx-bridge/Dockerfile \
  --platform linux/arm64 --target runtime --load \
  -t usdcx-bridge:local .
```

The image runs as UID/GID `10001`, includes CA certificates, stores state below `/data`, and
contains no AWS credentials.

## AWS KMS access

The attester requires two distinct, enabled AWS KMS keys registered with Circle. Both must use
`ECC_SECG_P256K1` and `SIGN_VERIFY`, and both full key ARNs must be in the configured Region.
Do not create replacement keys during deployment.

Give the service workload role access only to the two approved key ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
    "Resource": ["<KEY_ARN_1>", "<KEY_ARN_2>"]
  }]
}
```

The KMS key policies must allow the same role. If the role and keys are in different AWS
accounts, both the role policy and each key policy are required.

Use renewable workload credentials: an ECS task role, EKS service-account role/web identity, or
an EC2 instance profile. The Rust AWS SDK obtains and refreshes these credentials itself. Do not
put access keys in the image, command line or environment, and do not use a human SSO session for
the service.

At startup the binary calls `DescribeKey` and `GetPublicKey` for both ARNs. It refuses a disabled,
wrong-type or unexpected key. Each withdrawal then makes one `Sign` call per key and verifies both
returned signatures locally. The two `--expected-signing-public-key` values are the compressed
33-byte secp256k1 public keys registered with Circle.

## State and configuration

Mount durable storage at `/data`. Before first start, place the funded relayer account key in the
Miden keystore below `/data/relayer/miden/keystore/`. Restrict the volume to the service user. The
attester private keys stay in KMS and are never written to this volume.

For the raw binary or a host bind mount, create `/data/relayer/miden/keystore` and
`/data/attester` before starting. Keep the directories durable, writable only by the service user,
and mode `0700`; the container uses UID/GID `10001`.

Use deployment values supplied and reviewed by Miden. The example timing values below are safe
starting points, not network identities or fee policy:

```sh
/usr/local/bin/usdcx-bridge \
  --miden-rpc-url '<MIDEN_RPC_URL>' \
  --circle-url '<CIRCLE_XRESERVE_URL>' \
  --faucet-account-id '<USDCX_FAUCET_ID>' \
  --relayer \
    --page-size 100 \
    --request-timeout 30s \
    --poll-interval 5s \
    --miden-data-dir /data/relayer/miden \
    --expiration-delta 64 \
    --relayer-account-id '<RELAYER_ACCOUNT_ID>' \
    --attester-public-key '<CIRCLE_DEPOSIT_PUBLIC_KEY_HEX>' \
    --state-file /data/relayer/progress.json \
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
    --max-withdrawal-fee-bps '<FEE_BASIS_POINTS>' \
    --cctp-forwarding-max-fee '<CCTP_FEE_LIMIT>' \
    --cctp-forwarder-address '<XRESERVE_ADDRESS_ON_ARC>' \
    --cctp-token-messenger-address '<TOKEN_MESSENGER_V2_ADDRESS_ON_ARC>' \
    --poll-interval 1s \
    --store-path /data/attester/store.sqlite3
```

Common options must appear before `--relayer`; relayer options go between `--relayer` and
`--attester`; attester options follow `--attester`. Run `usdcx-bridge --help` for the exact CLI.

Run exactly one instance against these stores. Do not run either standalone service beside it.
Wait for `deposit relayer and withdrawal attester started` before enabling deposits. Send
`SIGTERM` to stop. The process waits up to five minutes for the current page and withdrawal cycle
to finish; set the host termination timeout above five minutes. Reuse the same volume on restart.
Never delete state to clear an operational error.
