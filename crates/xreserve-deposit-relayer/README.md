# xReserve deposit relayer

This service reads xReserve deposit attestations from Circle. It creates xUSDC mint notes and
submits them to Miden.

## How it fits

```text
Circle attestation feed        GET /v1/remote-domains/{domain}/attestations, newest first
        |
relayer                        decode each DepositIntent, build one mint note per deposit,
        |                      drop the deposits the faucet has already minted
        |
relayer account transaction    one page of mint notes as the transaction's output notes
        |
public mint notes              routed at the faucet's network account
        |
xUSDC faucet                   verify the Circle signature, check the nonce, mint to the recipient
```

The relayer is a courier. It does not decide whether a deposit gets minted: the faucet does, and
it decides on the note's contents alone. The relayer's job is to get every attested deposit in
front of the faucet exactly as Circle signed it, and to keep doing so across failures and restarts.

The service is one synchronous loop: poll Circle, build notes, drop the already-minted ones,
submit, wait for inclusion, record progress, sleep. The Miden client's asynchronous API is driven to completion on a single-threaded
runtime, so there is never more than one page in flight.

## Authorization and trust

### Who signs what

Two accounts are involved and only one of them has a key.

- **The relayer account** is an ordinary account the operator creates ahead of time. Its
  signing key lives in the keystore under `--miden-data-dir`. The relayer uses it to sign exactly
  one kind of transaction: one that creates a page of mint notes as the account's own output notes.
  It does not sign anything on the faucet's behalf.
- **The faucet** is a public network account with no signing key. Nobody signs for it. The network
  consumes the relayer's mint notes against it, and the faucet authorizes each mint itself: it
  admits only allowlisted note scripts, rebuilds the Circle-signed DepositIntent from the note's
  attachments and its own state, checks the signature against its on-chain attester-commitment map,
  and refuses a deposit nonce it has already used.

So the relayer account holds no mint authority. It is not on any faucet allowlist or role map, and
the faucet never looks at who sent a mint note. Any account could submit the same notes and the
faucet would accept or refuse them identically. That is deliberate: the relayer is outside the
faucet's security boundary, and replacing, restarting or running a second relayer needs no change
on chain.

### What the relayer trusts

- **Circle's feed** is fetched without authentication, because Circle has not published a scheme.
  Nothing it returns is trusted: a forged or altered attestation fails the faucet's signature check.
- **The attester public key** is configuration, not something the feed carries. The mint note
  needs the key alongside the signature; the faucet derives a commitment from it and requires that
  commitment to be enabled in its attester map. The relayer does not verify signatures itself, so
  a wrong key is not caught off chain — every mint transaction lands, and every mint note is
  refused when the faucet consumes it. When the faucet's attester is rotated (by the
  `ATTEST_ADMIN` role), restart the relayer with the new key.
- **The Miden node** is the operator's own. The relayer treats a transaction as done once that node
  reports it committed in a block; it does not seek independent finality. It also takes the
  faucet's used-nonce map from that node, so a node that lied about it could make the relayer skip
  a deposit it wrongly reports as minted — a liveness failure, not a mint the faucet did not
  authorize.

### What a broken relayer can and cannot do

A compromised or buggy relayer cannot mint anything Circle did not sign, mint a deposit twice,
redirect a deposit to another recipient, or change its amount — the recipient, amount and serial
number of the output note are all derived from the signed intent and checked by the faucet. What it
can do is stop relaying (mints halt until it is fixed; the USDC stays locked on the source chain
and no deposit is lost), or waste its own proving work on notes the faucet refuses.

### Replay

There are two replay layers and the relayer relies on the second.

- Each mint note gets a fresh random serial number, so rebuilding the same deposit yields a
  distinct note rather than a collision. The note's nullifier stops that one note being consumed
  twice.
- The faucet's used-nonce map stops the *deposit* being minted twice, however many notes carry it.

That is why the relayer keeps no per-deposit ledger of its own: the faucet's used-nonce map is the
ledger. The relayer reads it before submitting (next section), and whatever slips past that read is
refused on chain.

## Skipping deposits that are already minted

Before a page is proven, the relayer reads the faucet's used-nonce map for every deposit on the
page and drops the ones already minted. A replay of the feed — after a crash, or after the state
file is lost — therefore costs reads rather than proofs, and a page whose deposits are all minted
submits nothing at all.

The faucet is watched by the Miden client alongside the relayer's own account: every sync keeps
its storage current in the client's local store, and the read is answered from there, after a sync
at the start of the check. It is watched rather than imported so the client does not also pull the
notes addressed to the faucet, which are every mint note on chain.

A "minted" answer is final, since the faucet only ever adds to its used-nonce map. A "not minted"
answer can be overtaken: a mint note already on chain for the same deposit may be consumed before
the new one. The faucet refuses the second of the two, so that case costs one proof and nothing
more.

## Transactions and inclusion

The service submits each page of mint notes from the relayer's own account as a single transaction
and waits for the node to include it in a block before it records the page as done, so a page whose
transaction never lands is retried rather than skipped.

A page is one transaction, which is what makes that retry clean: no part of a failed page is
already on chain, so the retry cannot build a second mint note for a deposit that already minted.
`--page-size` therefore sets the proof size and the retry unit as well as the Circle request:
turning it down buys cheaper proofs and less work to redo, at the cost of more requests to walk a
backlog. Circle's largest page (1000) is below the protocol's per-transaction output-note ceiling,
and the build fails if that ever stops being true.

Every mint transaction carries an expiration block, `--expiration-delta` blocks past the one it was
built against. That is what bounds the wait: once the chain reaches the expiration block without
the transaction in it, no later block can carry it, so the relayer gives up and retries the page. A
transaction the node discards ends the wait the same way. A larger delta tolerates a slower chain;
a smaller one notices a lost transaction sooner.

Landing on chain is not the same as minting. The relayer is done with a page once its notes exist;
the faucet consumes them afterwards in network transactions of its own, and a note it refuses — a
duplicate that slipped past the used-nonce check, a wrong attester key, a paused faucet — simply
stays unconsumed. The relayer does not
watch for that.

## Malformed attestations

An attestation that cannot become a mint note — its payload is not a DepositIntent, or the intent
is addressed to a different faucet or domain — is logged at `error` and skipped, and the rest of
the page still mints. Such a failure depends only on the attestation and the configuration, so
retrying would never help, and holding up the page would stall every deposit behind it.

A skipped deposit is not revisited: the scan moves past it like any other. If it was skipped
because of the relayer's configuration rather than the deposit itself, fix the configuration and
remove the state file (see below) to replay the feed.

## Run

Pass all deployment settings as command-line arguments:

```sh
just run-relayer \
  --circle-url https://xreserve-api-testnet.circle.com \
  --page-size 100 \
  --request-timeout 30s \
  --poll-interval 5s \
  --remote-domain 10001 \
  --miden-node-url http://127.0.0.1:57291 \
  --miden-data-dir target/relayer-miden \
  --expiration-delta 64 \
  --faucet-account-id 0x222222222222221122222222222222 \
  --relayer-account-id 0x111111101111111111111111111111 \
  --attester-public-key 03a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f \
  --state-file target/relayer-state
```

The Circle domain identifier and the account identifiers depend on the deployment. The faucet must
be a public account, since the mint notes are routed to it as a network account. The attester
public key must use compressed SEC1 format.

The relayer account must already exist on chain, and its signing key must already be in the
keystore directory. Neither is created here. Everything that can be refused — an unreachable node,
an unreadable keystore, a relayer account or faucet the node does not know — is refused at startup,
before the first Circle request, so the service never reads the feed unless it can also mint.

Logs are a tree per page — the page, its Circle request, the notes it built and the transaction
that carried them — filtered by `RUST_LOG` (default `info`).

`--miden-data-dir` holds the Miden client's own state:

- `store.sqlite3`, the SQLite store the client syncs the chain into: block headers, the relayer
  account and the transactions it submitted, and a full copy of the faucet's storage — including
  the used-nonce map, which gains one entry per deposit ever minted and so grows for the faucet's
  lifetime.
- `keystore/`, the directory the relayer account's signing key is read from.

The keystore has to survive a restart, because without the signing key the relayer cannot mint at
all. The store does not: the client rebuilds it from the node, so losing it costs a re-sync rather
than correctness. That re-sync includes downloading the faucet's whole used-nonce map, so the first
start on a fresh data directory takes longer the more deposits the faucet has minted; a store
carried over from an earlier run only syncs what changed since.

Nothing in the data directory is read back to resume work: a restart picks up from the page
recorded in the state file below and fetches that page again. The deposits on it that already
minted are dropped by the used-nonce check rather than proven a second time.

## Progress

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

The watermark is a stop condition rather than a cursor sent to Circle, because Circle's
`pageAfter` only walks towards older entries — the wrong way for a feed that grows at its head. A
resumed scan finishes the walk it began before taking on anything newer, so what has been handled
is always one contiguous run of the feed and a single watermark can describe it.

The file is replaced atomically (write, fsync, rename), so a crash leaves the old state or the new
one, never a torn one. A file that exists but is not a state is an error, not a first run, since
treating it as one would replay the whole feed silently.

Deleting the file is safe. The next run scans the whole feed, and the used-nonce check drops every
deposit the faucet has already minted, so the replay costs Circle requests and local reads rather
than a proof per deposit.

The state file and the Miden store are independent: the state file says how far the relayer walked
the feed; the store holds the chain, including which deposits minted. Either can be lost on its own.
