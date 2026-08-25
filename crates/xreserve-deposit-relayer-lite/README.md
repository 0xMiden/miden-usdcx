# `xreserve-deposit-relayer-lite`

A minimal deposit relayer: poll Circle, build the xUSDC mint note, submit it at the faucet.

This is a **sibling** of `crates/xreserve-deposit-relayer`, not a replacement for it. Both do the
same job; this one does it under one different assumption. The design and its trade-offs are
`docs/PLAN-RELAYER-LITE.md`; issue #160 is the motivation.

## The one decision everything follows from

**Delivery is at-least-once, not exactly-once.**

The faucet's on-chain `usedNonces` assert is the authoritative replay guard, so a duplicate submit is
*refused*, not minted twice. That makes exactly-once a fee optimization rather than a correctness
property — and removes, in one stroke, the submission state machine, the claim protocol, the
crash-recovery sweep and the re-fetch retry queue the sibling crate carries.

**Money-safety is unchanged.** The DepositIntent parse, the amount reduction, the nonce replay
guard, the attester-allowlist check and the ECDSA verification are all on-chain and faucet-owned. A
bug here can withhold a mint. It cannot authorize one.

## The cycle

```
read cursor  ->  GET one page of attestations
  per attestation:
      decode + check messageHash == keccak256(payload)   -- bad? log and SKIP
      already in the submitted set?                      -- yes? SKIP
      build the mint note                                -- refused? log and SKIP
      submit                                             -- transient? HOLD the page, retry next cycle
                                                         -- accepted? record the nonce, durably
advance the cursor if the page finished  ->  sleep  ->  repeat
```

Two rules replace an entire retry subsystem:

1. **A bad element is skipped, never fatal to the page.** The sibling collects the page through
   `collect::<Result<_>>()?`, so one malformed attestation fails the whole fetch and the cursor never
   advances — the service wedges permanently. That is the bug (#160) this design does not have, and
   `tests/cycle.rs::a_malformed_attestation_does_not_wedge_the_page` is its regression test.
2. **A transient failure ends the cycle without advancing the cursor.** The next cycle re-fetches the
   same page; the submitted-nonce set skips what already went through.

## State

One SQLite file, two relations — one of which never exceeds a single row:

| Table | Holds |
|---|---|
| `submitted` | the 32-byte nonce of every deposit handed to the chain — a duplicate *filter*, not a ledger |
| `cursor` | one row: where the last completed scan got to in Circle's feed |

No status column, no tx id, no timestamps, no state machine. `mark_submitted` runs the moment a
submit is accepted, so a crash loses at most the one in-flight submit.

## It does not start yet

`submit::production_submit_port()` returns an error, and `main` exits non-zero on it, because handing
a note to a node needs a `miden-client` for protocol v0.16 and **there is no such release**. A no-op
submit would look healthy in every log and metric except the chain's; a simulated one would make the
tests evidence about themselves. Everything else is assembled and waiting behind that one binding.

## Running it

```sh
just run-relayer-lite                        # against the shipped ./relayer.toml
just run-relayer-lite path/to/my.toml        # or your own

cargo run -p xreserve-deposit-relayer-lite -- relayer.toml   # path defaults to ./relayer.toml
```

Logging is `tracing`, rendered by `tracing-forest` as one tree per cycle. Set `RUST_LOG=debug` for
per-attestation detail, or `trace` to see individual store reads (the default is `info`).

`relayer.toml` in this directory is a **working example**: it parses, validates, and gets as far as
the missing submit port, so it is a real demonstration rather than a template that needs editing
before it does anything. A test asserts it stays that way. Copy it and replace the four identity
values to point at something real.

The required keys are `circle_base_url`, `remote_domain`, `faucet_account_id`,
`relayer_account_id`, `attester_pubkey_hex` and `store_path`. Everything else has a default:
`poll_page_size` (100), `poll_interval_ms` (5000), `request_timeout_ms` (30000),
`max_response_bytes` (8 MiB), `api_auth_header` (`Authorization`), and the optional
`api_auth_token`. **Unknown keys are refused rather than ignored** — a mistyped key that silently
kept its default is how an operator ends up debugging a value they thought they set.

**No credential and no real endpoint is committed.** Circle's auth scheme and Miden's remote-domain
id are Circle-owned and still OPEN, so the shipped values are placeholders.

## Tests

```sh
cargo test --locked -p xreserve-deposit-relayer-lite
```

36 tests, all behavioural. No test reads the crate's own source text. Circle is a recording fake
installed at the `Transport` seam — it binds no socket, so it runs anywhere, and it asserts on the
exact request the client built. **No Circle endpoint is contacted live and no Miden behaviour is
faked.** Payloads come from `xusdc-encoding`'s canonical golden vectors, re-addressed through that
crate's own header builder, so no test restates a byte offset or a field layout.

## What it gives up

Deliberate, and listed in full in §7 of the plan: duplicate submits are possible after a crash
(bounded to one in-flight submit, refused by the chain); there is no per-deposit audit trail; there
are no metrics counters; only one instance may run; a persistently-transient deposit blocks its page.
