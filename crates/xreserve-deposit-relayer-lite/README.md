# `xreserve-deposit-relayer-lite`

A minimal deposit relayer: poll Circle's attestation feed, mint each attested deposit at the xUSDC
faucet, advance the cursor. The minimal sibling of `xreserve-deposit-relayer` (issue #160); both
coexist until a separate decision retires one.

## The design in one paragraph

**Delivery is at-least-once, and the cursor is the only state.** Every authoritative check — the
DepositIntent parse, the amount reduction, the `usedNonces` replay guard, the attester allowlist,
the ECDSA verify — is on-chain in the faucet's mint policy, so a duplicate submit is refused rather
than double-minted, and a relayer bug can withhold a mint but never authorize one. Each cycle
fetches one page, builds the mint notes (skipping malformed entries with a warning — one bad
attestation must never wedge the feed), submits them in one transaction, waits for it to be
included on chain, and only then advances the persisted cursor. A crash at any point replays at
most one page, whose duplicates the chain absorbs.

```
loop {
    page  = circle.fetch_page(cursor)
    notes = build_notes(page.attestations)     // skip what will not decode, warn
    miden.submit_notes(notes)                  // ONE tx: build, prove, submit, wait for inclusion
    cursor = page.next; store.set_cursor(cursor)
}
```

## It does not start yet

The `miden` leg needs a `miden-client` for protocol v0.16, and there is no such release. The binary
validates its config and exits non-zero rather than run a relayer that polls without minting —
which would look healthy in every log except the chain's.

## Running

```sh
just run-relayer-lite                     # against the shipped ./relayer.toml (a working example)
just test-relayer-lite
```

Config is six required values (see `relayer.toml`, commented); everything else is a constant in the
code. Unknown keys are refused. No credential and no real endpoint is committed — Circle's auth
scheme and Miden's remote-domain id are Circle-owned and OPEN.
