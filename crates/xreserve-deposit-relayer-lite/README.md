# xReserve deposit relayer

This service reads xReserve deposit attestations from Circle. It creates xUSDC mint notes and
submits them to Miden.

## Status

The service requires a Miden client that supports protocol v0.16. No compatible client release is
available. The service validates its command-line arguments and then exits with an error.

## Run

Pass all deployment settings as command-line arguments:

```sh
just run-relayer-lite \
  --circle-url https://xreserve-api-testnet.circle.com \
  --page-size 100 \
  --request-timeout 30s \
  --poll-interval 5s \
  --remote-domain 10001 \
  --faucet-account-id 0x222222222222221122222222222222 \
  --relayer-account-id 0x111111101111111111111111111111 \
  --attester-public-key 03a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f \
  --state-file target/relayer-lite-state
```

The Circle domain identifier and the account identifiers depend on the deployment. The attester
public key must use compressed SEC1 format.

`--state-file` holds a small JSON document recording how far the relayer got:

```json
{
  "watermark": "0x1e1c…",
  "scan": {
    "head": "0x8a30…",
    "resume": "eyJ2YWx1ZXMiOnsi…"
  }
}
```

Circle serves the feed newest first, so every scan starts at the head of the feed and walks back
until it reaches `watermark` — the newest attestation the last completed scan handled. `scan` is
present only while a scan is unfinished, and it records the head that scan started at along with
Circle's cursor for the page it stopped on. The next poll then resumes at that page instead of
re-minting the ones already on chain, and both fields are dropped once `watermark` moves up to
`head`. A backlog therefore costs one pass per outage rather than one per restart.

Deleting the file is safe, just slow — the next run scans the whole feed, and the faucet refuses
the deposits it has already minted.
