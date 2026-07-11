# LNV-5 Row-L surfaced finding — sequencer gRPC-server panics at 30-minute connection age

**Status: DISPOSITION APPLIED (operator decision, anneal round 2) — candidate (2) below,
"stack-config fix + full re-run".** The harness now starts the sequencer with
`--rpc.grpc.max-connection-age 604800s` (one week; `stack.rs`
`SEQUENCER_MAX_CONNECTION_AGE`, unit-tested), using the node's own v0.15.1 CLI flag — no node,
production, or MASM code was patched, and the row-L panic detector/classifier is byte-for-byte
unchanged. The ENTIRE consolidated matrix was re-run on a fresh stack
(`local-node-data/lnv5/run-1783774851`): **all 12 rows PASS, zero panic lines across every
service log** (round-1 panicked at exactly ~30m03s of connection age ×3). The production-posture
note below STANDS for the §11.2 record: a default-configured `miden-node v0.15.1` will panic on
any gRPC connection reaching 30 minutes of age.

---

Original round-1 finding (row L legitimately FAILED on consolidated run
`local-node-data/lnv5/run-1783765804`; surfaced per validator-not-fixer, disposition was
reserved for the human gate):

## What row L flagged

Six panic lines in `sequencer.log` — three panic EVENTS, each emitting the tracing `ERROR panic`
line plus the raw thread line:

```
2026-07-11T11:00:07.794484Z ERROR panic panic=true info=panicked at …/tonic-0.14.6/src/transport/server/mod.rs:891:20:
`async fn` resumed after completion
thread 'tokio-rt-worker' (1979483) panicked at …/tonic-0.14.6/src/transport/server/mod.rs:891:20:
```

(events at `11:00:07`, `11:05:44`, `11:30:12`; full log archived under the run root). Every other
scanned line matched the triage table; the other eleven matrix rows PASSED on the same run.

## Mechanism (source-confirmed at the pins)

- `miden-node v0.15.1` starts its RPC server with a per-connection age limit:
  `DEFAULT_MAX_CONNECTION_AGE = Duration::from_mins(30)`
  (`miden-node` v0.15.1 `crates/utils/src/clap.rs:13`) wired via
  `.max_connection_age(…)` on the tonic server builder (`crates/rpc/src/server/mod.rs:177`).
- tonic **0.14.6** (the node build's lock) implements that limit in
  `connection_timeout_future` (`src/transport/server/mod.rs:891`). When the age elapses the
  future completes — and the connection serve loop polls it again, hitting Rust's
  `async fn resumed after completion` panic on the tokio worker. A tonic-internal defect in the
  connection-lifecycle path, outside the request stack (the node's `CatchPanicLayer` guards
  request handling, not this future).
- Correlation: each panic lands ≈ **30m03s** after a harness client connection was established
  (stack-start client → 11:00:07; rows-C/F client → 11:05:44; a rows-G/J-era connection →
  11:30:12). The panic is task-scoped: the sequencer kept producing blocks and every subsequent
  matrix row committed and PASSED.

## Why LNV-1..4 never saw it

Their standalone runs live ≤ ~25 minutes — no gRPC connection ever reached the 30-minute age
limit. The ~70-minute consolidated run is the first with long-lived connections; the archived
LNV-1..4 log vocabulary (which the row-L triage table enumerates) contains zero panic lines.

## Why this is NOT triaged away

Row L's model deliberately gives panics no triage lane (only ERROR patterns tied to deliberate
negatives, and WARNs, are triage-able): a node panic during the gate run is exactly what the row
exists to surface for human judgment. The panic is **attributable to our connections** (their
age), not to any transaction's content or to faucet logic — but "cosmetic infrastructure panic"
is a call the §11.2 gate owner makes, not the validator.

## Production relevance

Any long-lived gRPC client of `miden-node v0.15.1` — the withdrawal attester, a relayer holding
a pooled connection ≥ 30 minutes — will trip this server-side panic (connection dropped +
panic noise in node logs; the client transparently reconnects). Panic noise in production logs
can mask real faults and will likely page operators.

## Candidate dispositions (decision reserved for the human gate)

1. **Accept-as-surfaced:** judge the gate on rows A–K + this documented artifact (row L FAIL
   stands as the honest machine verdict for this run).
2. **Stack-config fix slice + full re-run:** start the harness sequencer with
   `--grpc.max_connection_age <long>` (harness `stack.rs`, NOT production code), re-run the
   whole matrix fresh; row L then evidences a clean log surface, and this document keeps the
   30-minute finding on the §11.2 record for production posture.
3. **Upstream:** report/track the tonic resumed-after-completion defect (tonic > 0.14.6 /
   miden-node bump) — outside this repo's scope.
