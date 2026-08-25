# `xreserve-deposit-relayer-lite` — a minimal alternate relayer: plan + test matrix

**Status:** RATIFIED and **IMPLEMENTED** — `crates/xreserve-deposit-relayer-lite`, built 2026-08-26.
D-1, D-2, D-3, D-3a (companion cursor table), D-4, D-5, D-6 and D-7 were all accepted as
recommended; D-8 (retiring the sibling crate) remains out of scope and undecided. As built: **1,151
source lines (719 code) across 8 files, and 1,044 test lines across 4 files — 36 tests, all green**,
against a sibling of 7,296 / 12,379. That is an **82% cut in code**. Four deviations from the plan as
written are recorded in §11.
**Issue:** [#160 — Refactor deposit relayer for simplicity](https://github.com/0xMiden/miden-usdcx/issues/160).
**Base:** `sergerad-simplify-relayer` @ `c269baa`.
**Scope:** ONE new crate, `crates/xreserve-deposit-relayer-lite`, built as a **sibling** of
`crates/xreserve-deposit-relayer`. The existing crate is **not touched by this plan** — not deleted,
not edited. The two coexist until a separate, later decision retires one.
**Out of scope:** the faucet MASM, `xusdc-encoding`, `withdrawal-listener-attester`,
`xusdc-validation`, and the Miden submit adapter (still blocked on a `miden-client` for v0.16 —
see §8).

---

## 0 · Summary, and the one decision everything else follows from

The existing relayer is **7,296 lines of source across 32 files, and 12,379 lines of tests across
38 files**. This plan targets **~600 lines of source across 6 files, and ~510 lines of tests across
4 files** — roughly a **92% reduction** — for the same externally-observable job: turn each
Circle-attested deposit into an `XUsdcMintNote` submitted at the faucet.

The reduction is not achieved by writing the same design more tersely. It follows from **one
decision**, and every deletion below is downstream of it:

> **The lite relayer is at-least-once, not exactly-once.**

The existing crate spends a six-state SQLite submission machine
(`src/idempotency/store.rs:58-72`), a stale-`Pending` reclaim sweep, an atomic claim protocol, and a
messageHash-keyed re-fetch retry queue on guaranteeing each deposit is submitted exactly once. But
the faucet's on-chain `usedNonces` assert-then-set already makes a duplicate submit *harmless* — it
is refused, and the port already models that answer as `MintSubmitted::AlreadyMinted`
(`src/cycle/submit.rs:86-92`). The existing crate's own module docs concede the point: its store is
"a LIVENESS backstop, never a safety one" (`src/lib.rs:26-31`).

So exactly-once is a **fee-and-noise optimization, not a correctness property**. Paying ~2,900 lines
(store + retry + recovery) for it is the wrong trade for a service whose stated worst case is "it
goes offline". Accept at-least-once and the persistence collapses to two values, the retry subsystem
collapses to "don't advance the cursor", and the concurrency machinery has nothing left to protect.

**Money-safety is unchanged by this plan.** Every authoritative check — the DepositIntent parse, the
amount reduction, the nonce replay guard, the attester-allowlist membership test, and the ECDSA
verification — is on-chain and faucet-owned. A lite-relayer bug can withhold a mint. It cannot
authorize one. That is the same blast radius the existing crate has.

---

## 1 · What the lite crate keeps, drops, and delegates

| Concern | Existing | Lite | Why |
|---|---|---|---|
| DepositIntent codec | `xusdc-encoding` by reference | **same, by reference** | single-owner rule (ground rule 3). Never forked. |
| Mint-note bytes | `XUsdcMintNote::builder()` | **same, by reference** | ditto. `src/miden/mint_note.rs:145-157` is already a thin delegation; lite copies that shape. |
| Startup identity validation | `MintIdentities::from_config` | **kept** (~30 lines) | a typo in `faucet_account_id` or `attester_pubkey_hex` costs every mint until noticed. Cheap insurance. |
| Response-size ceiling / timeouts | `circle/transport.rs` (402 lines) | **kept, as reqwest settings** (~15 lines) | worth having; does not need a bespoke transport trait. |
| `messageHash == keccak256(payload)` | `validate/envelope.rs` (139 lines) | **kept** (~12 lines, `sha3`) | avoids spending a fee on a note the chain will refuse. |
| Persistence | SQLite, 6-state machine + claim protocol (~1,300 lines) | **SQLite, one nonce table + a one-row cursor table** (~60 lines) | §2. The engine was never the problem — the state machine on top of it was. |
| Retry queue + re-fetch by messageHash | `cycle::drive_retry_queue` + store support | **DROPPED** | replaced by "don't advance the cursor" (§3). |
| Stale-`Pending` reclaim | `reclaim_stale_pending` + `RecoveryPolicy` | **DROPPED** | no `Pending` state exists to strand. |
| Concurrency hardening | `touch_failed_timestamp`, two-driver boundary | **DROPPED** | single-instance deployment, per #160. |
| Error type | 53-variant enum + 836 hand-written lines (`error/mod.rs` 563 + `error/render.rs` 273) | **`anyhow` + `.context()`** | it is a binary; no public API needs typed variants. §5. |
| Observability | `EventSink`/`RelayerEvent`/`WriteEventSink` + metrics (569 lines) + `&dyn` threading | **`tracing` + `tracing-subscriber`** | §5. |
| Rate governor (5/35 QPS) | `circle/rate.rs` (148 lines) | **DROPPED** | one paginated GET per `poll_interval_ms` cannot approach 5 QPS. |
| Backoff/retry module | `circle/retry.rs` (183 lines) | **~10-line loop** | one call site. |
| Full pagination surface | `BatchQuery` with `pageBefore`/`from`/`to` (387 lines) | **`pageSize` + `pageAfter` only** | the forward poll is the only caller; the rest is modeled-but-unused by its own admission (`circle/pagination.rs:55-60`). |
| `/v1/info` domain-token fast-fail | `circle/info.rs` + `validate/domain_token.rs` | **DROPPED** | the chain enforces it. |
| Unused Circle endpoints | 3 coded, never called | **not ported** | #160. |

---

## 2 · Store: SQLite, one nonce table

```sql
PRAGMA journal_mode = WAL;

-- the duplicate FILTER: which deposits we have already handed to the chain
CREATE TABLE IF NOT EXISTS submitted (
    nonce BLOB NOT NULL PRIMARY KEY CHECK (length(nonce) = 32)
) STRICT;

-- where we are in Circle's feed. Exactly one row, forever.
CREATE TABLE IF NOT EXISTS cursor (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
    page_after TEXT    NOT NULL CHECK (length(page_after) > 0)
) STRICT;
```

Four operations, and no fifth: `is_submitted(&[u8; 32]) -> bool`, `mark_submitted(&[u8; 32])`,
`cursor() -> Option<String>`, `set_cursor(&str)`. **~60 lines including the schema.**

* **`submitted` is a duplicate *filter*, not a ledger.** No status column, no tx id, no timestamps,
  no state machine. A nonce is present or it is not. That single bit is the whole of what the lite
  relayer remembers about a deposit, and it is a fee optimization — the authoritative replay guard
  is the faucet's on-chain `usedNonces`.
* **`mark_submitted` runs per attestation, immediately after a submit is accepted**, not once per
  cycle. This is strictly better than the batch-write design it replaces: a crash now loses at most
  the in-flight submit rather than a page of them. SQLite's transaction gives that for free — there
  is no write protocol to hand-roll.
* **Membership is an indexed lookup**, so nothing is loaded into memory at boot. Growth is a disk
  concern only (~4 MB at 100k deposits) and needs no bounded ring, no compaction, and no scale test.
* **Schema versioning** is `PRAGMA user_version`, set at open. One integer; no migration framework.
  There is exactly one schema and no upgrade path is planned — if the schema ever changes, the
  honest move for a rebuildable duplicate-filter is to refuse to start and let an operator decide.

**Why SQLite rather than a file.** The lite crate's needs are: durable across restart, atomic per
write, cheap incremental insert, membership query. A JSON or line-delimited file gives none of them
without hand-rolling temp-file/`fsync`/`rename`, torn-write detection, and a corruption class — more
code than the store above, and code whose failure mode is silent data loss. `rusqlite` is already in
`Cargo.lock` and the pinned cache (the sibling crate compiles it), so choosing it adds **no new
dependency and no new build cost**. Binary formats (`bincode`, `postcard`) were considered and
rejected: they save ~3 MB at 100k deposits, which is irrelevant, while still rewriting the whole file,
still hand-rolling durability, and costing both a new dependency and all inspectability.

**Not human-readable, deliberately** — nothing but the relayer reads it. Operator inspection is
`sqlite3 state.db 'SELECT hex(nonce) FROM submitted'`, which matters more than usual here because
§7.2 deletes the per-deposit audit trail.

> **Open point for the approver (D-3a).** "One table" is literally achievable with a single
> key-value table holding both the nonces and the cursor. It is **not** what is written above,
> because it costs the typed 32-byte BLOB key and its `length(nonce) = 32` constraint, and mixes two
> unrelated concerns in one relation. The design above is one table for the nonce set plus a
> one-row companion for the cursor — **two relations, one of which never exceeds a single row.**
> Say the word if you want the literal single-table form instead.

---

## 3 · The cycle

```rust
loop {
    page, next = circle.get_attestations(cursor = store.cursor(), page_size = N)

    for att in page {                               // per-element; NEVER collect::<Result<_>>
        intent = decode(att.payload)   else { warn!(); continue }   // PERMANENT: chain would refuse
        verify att.message_hash == keccak256(att.payload)
                                       else { warn!(); continue }   // PERMANENT
        if store.is_submitted(intent.nonce)         { continue }

        note = build_mint_note(...)    else { warn!(); continue }   // PERMANENT
        match submit(note) {
            Accepted(_) | AlreadyMinted => store.mark_submitted(intent.nonce),  // durable NOW
            Transient(_)                => return Retry,   // cursor NOT advanced
        }
    }

    if next.is_some() && page_fully_handled { store.set_cursor(next) }
    sleep(poll_interval) unless more_pages
}
```

Three properties, and each replaces a whole subsystem:

1. **Per-element handling fixes the #160 wedge bug.** The existing poll does
   `.collect::<Result<Vec<_>, _>>()?` (`src/circle/attestation_fetch.rs:175-182`), so ONE malformed
   attestation fails the whole page fetch and the cursor never advances — the service is stuck
   forever. Lite logs and skips the bad element. **This is a behavioural fix, not a port.**
2. **A transient failure ends the cycle without advancing the cursor.** Next cycle re-fetches the
   same page; the `submitted` set skips what already went through. That is the entire retry
   subsystem, replaced by an early return. No re-fetch-by-messageHash, no `Failed` pool.
3. **Permanent vs transient is the only error distinction that survives**, and it is exactly the
   split the submit port already models (`TransientSubmit` vs `FatalSubmit`,
   `src/cycle/submit.rs:106-112`). Permanent → skip (the chain would refuse it anyway).
   Transient → stop and retry the page.

**Known limitation (accepted):** a deposit that fails *transiently but permanently in practice*
(e.g. a node that refuses one specific note forever while accepting others) blocks its page. The
existing crate's retry queue tolerates this; lite does not. Mitigation is a **warning, not
machinery**: after K consecutive cycles ending on the same cursor, `error!` loudly and let an
operator decide. Escalation beyond that is out of scope.

---

## 4 · Layout and line budget

```
crates/xreserve-deposit-relayer-lite/
  Cargo.toml
  README.md                 ~40   what it is, how it differs from the sibling, how to run it
  src/
    main.rs                ~130   config load, tracing init, identity validation, ctrl-c, the loop
    config.rs               ~70   one serde struct + one validating constructor
    circle.rs              ~180   reqwest client, serde schemas, Link-header next cursor, one GET
    store.rs                ~60   the §2 schema + its four operations
    mint.rs                 ~90   build_mint_note (delegates to xusdc-encoding) + AttesterPubkey
    submit.rs               ~60   the MintSubmit seam (§8)
  tests/
    support/mod.rs         ~150   axum mock Circle + fixtures
    cycle.rs               ~180
    store.rs                ~60
    circle.rs              ~120
                          ─────
                   src ~590 · tests ~510
```

`circle.rs` keeps the `Link`-header cursor parse (Circle returns `next` in an RFC-8288 `Link`
header, not the JSON body — `src/circle/pagination.rs:1-14`), including the load-bearing rule that
an **absent** header means final page while a **present but unparseable** one is an error. That
distinction is real and cheap; it is kept.

---

## 5 · Dependencies — all verified present in `Cargo.lock` AND the pinned offline cache

The gate runs `--locked --offline`, so a dependency the pinned cache does not carry breaks *every*
offline command. Each of these was checked in both places at `c269baa`:

| Crate | Version in `Cargo.lock` | In pinned cache | Replaces |
|---|---|---|---|
| `anyhow` | 1.0.103 | ✅ (already a workspace dep) | the 836-line hand-written error module |
| `tracing` | 0.1.44 | ✅ | `EventSink` + `RelayerEvent` + `WriteEventSink` |
| `tracing-subscriber` | 0.3.23 | ✅ | `WriteEventSink::stderr` + `render()` |
| `reqwest` | 0.13.4 | ✅ (workspace dep) | the `HttpTransport` trait + `circle/transport.rs` |
| `serde`/`serde_json` | 1 / 1.0.150 | ✅ (workspace deps) | config file + Circle JSON bodies |
| `rusqlite` | 0.37.0 | ✅ (workspace dep, `bundled`) | the §2 store — **already compiled for the sibling crate; no new dependency and no new build cost** |
| `hex`, `sha3`, `rand` | workspace deps | ✅ | unchanged roles |
| `miden-protocol` | `=0.16.0-rc.4` | ✅ | unchanged pin (ground rule 5) |
| `xusdc-encoding` | path | — | unchanged, by reference |
| **dev:** `axum` 0.8.9 + `tower` 0.5.3 | ✅ | ✅ | the mock Circle server |
| **dev:** `rstest`, `assert_matches`, `tempfile` | workspace devs | ✅ | unchanged roles |

`tracing`/`tracing-subscriber`/`anyhow` are added to `[workspace.dependencies]` per the
`workspace-shared-dependencies` skill (`anyhow` is already there). **`thiserror` is available
(2.0.18) but is deliberately NOT used**: with `anyhow` in a binary there is no public error API to
type. This is a deviation from #160's suggestion and is called out for approval in §9.

> **Correction to an earlier suggestion in discussion:** `httpmock`/`wiremock` **cannot** be used.
> They are absent from the pinned cache (breaking the offline gate) and, being socket servers, they
> cannot bind in the audit/CI sandbox, which denies `bind(127.0.0.1:0)` with `EPERM`. The lite tests
> therefore reuse the existing, proven pattern: an **axum `Router` driven in-process through tower's
> `ServiceExt::oneshot`**, installed behind the HTTP seam. No test binds a socket; no test contacts
> Circle live.

---

## 6 · Test matrix

Behavioural only. **No test reads the crate's own source text** — the existing suite's
source-grepping assertions (`tests/cycle_no_silent_drops.rs:424`, `tests/circle_auth_contract.rs:163`,
`tests/circle_production_transport.rs:280`) are not ported in any form (#160).

Legend — **G** = gating (must pass to merge).

### 6.1 Cycle behaviour (`tests/cycle.rs`)

| ID | Case | Setup | Assert | G |
|---|---|---|---|---|
| T-C1 | happy path | mock serves 3 valid attestations, submit accepts all | 3 notes submitted; 3 nonces in `submitted`; cursor = page's `next` | ✅ |
| T-C2 | **#160 wedge bug — the regression test** | page of 3 where element 2 has an undecodable payload | elements 1 and 3 ARE submitted; cursor ADVANCES; cycle returns Ok | ✅ |
| T-C3 | bad keccak binding | element whose `messageHash != keccak256(payload)` | that element skipped, others submitted, cursor advances | ✅ |
| T-C4 | duplicate within a page | same nonce twice on one page | submitted exactly ONCE | ✅ |
| T-C5 | duplicate across cycles | cycle 1 submits nonce N; cycle 2 re-serves it | second cycle submits 0 notes | ✅ |
| T-C6 | transient submit → cursor held | submit returns `TransientSubmit` on element 2 | cursor NOT advanced; element 1's nonce IS recorded; cycle ends early | ✅ |
| T-C7 | transient recovery | T-C6, then submit succeeds next cycle | element 1 NOT re-submitted; elements 2,3 submitted; cursor then advances | ✅ |
| T-C8 | fatal submit → skip | submit returns `FatalSubmit` for element 2 | 1 and 3 submitted; cursor advances; 2 never retried | ✅ |
| T-C9 | note build refused | intent addressed to a different faucet | skipped with a warning; cursor advances | ✅ |
| T-C10 | final page | response with NO `Link` header | cursor left unchanged; loop sleeps | ✅ |
| T-C11 | multi-page scan | 2 pages then final | both pages processed; cursor ends at last `next`; no sleep between pages | |
| T-C12 | empty page | `data: []` | no submits; cursor advances if `next` present | |
| T-C13 | Circle 5xx | mock returns 500 | cycle returns Err; cursor unchanged; loop continues (does not exit) | ✅ |

### 6.2 Store (`tests/store.rs`)

Every case opens a REAL database on a `tempfile` directory — "survives a restart" is only provable
against a file a second, independent handle can reopen, so no test uses an in-memory database. This
matches the sibling crate's rule.

| ID | Case | Assert | G |
|---|---|---|---|
| T-S1 | survives a restart | `mark_submitted` + `set_cursor`, DROP the handle, reopen | both values are still there | ✅ |
| T-S2 | first boot | open against a path with no file | file is created; `is_submitted` is false for all; `cursor()` is `None` — not an error | ✅ |
| T-S3 | re-marking is idempotent | `mark_submitted(N)` twice | second call is a no-op, NOT an error (an at-least-once relayer WILL re-mark after a crash) | ✅ |
| T-S4 | cursor never accumulates | `set_cursor` three times | `cursor()` returns the newest; the table holds exactly ONE row | ✅ |
| T-S5 | unknown `user_version` | open a db stamped with a future version | refuses to start with a clear error — never silently treats it as empty, which would re-submit every historical deposit | ✅ |

**Deleted relative to a file-based store, because SQLite owns them:** crash-atomicity of the write,
torn/corrupt-file recovery, and the 100k-entry scale test (membership is an indexed lookup, so
nothing is parsed into memory at boot). Testing those would be testing SQLite.

### 6.3 Circle client (`tests/circle.rs`)

| ID | Case | Assert | G |
|---|---|---|---|
| T-H1 | query construction | request path is `/v1/remote-domains/{d}/attestations` with `pageSize` + `pageAfter` | ✅ |
| T-H2 | auth header injection | configured token appears in the configured header; absent when unconfigured | ✅ |
| T-H3 | `Link` header parse | `next` extracted from a realistic RFC-8288 header | ✅ |
| T-H4 | absent `Link` | → `None` (final page), NOT an error | ✅ |
| T-H5 | unparseable `Link` | → error (must NOT be silently read as final page) | ✅ |
| T-H6 | oversize response | body beyond `max_response_bytes` is refused | ✅ |
| T-H7 | schema drift | unexpected/missing JSON fields produce a clear decode error | |

### 6.4 Config + startup (in `tests/cycle.rs`)

| ID | Case | Assert | G |
|---|---|---|---|
| T-G1 | bad `faucet_account_id` | startup fails with a message naming the FIELD | ✅ |
| T-G2 | bad `attester_pubkey_hex` (not hex / not 33 bytes / not a curve point) | startup fails, field named — 3 parameterized cases (`rstest`) | ✅ |
| T-G3 | missing config file | clear error, non-zero exit | ✅ |
| T-G4 | no submit adapter | startup fails loudly (§8) — never starts with a no-op submit | ✅ |

**Not tested, deliberately:** rate limiting (dropped), `/v1/info` (dropped), the retry queue
(dropped), multi-driver claims (dropped), metrics counters (dropped). Live Circle is never
contacted (Circle legs remain `REQUIRES CIRCLE CONFIRMATION`); Miden behaviour is never faked.

---

## 7 · What is sacrificed — stated plainly, for the approver

1. **Duplicate submits are possible**, bounded to the single in-flight submit a crash interrupts
   (the store marks each nonce durably at the moment its submit is accepted). Cost: one transaction
   fee and a log line. The chain refuses the duplicate. **Not a money-safety change.**
2. **No per-deposit audit trail.** No tx id, no status history, no timestamps. "What happened to
   deposit X" is answered by `grep`ping structured `tracing` output or by looking on-chain. If an
   operator requirement demands durable per-deposit records, that is a scoped addition — one
   nullable column on the `submitted` table — not a return to the six-state machine.
3. **No metrics counters.** Deferred to the monitoring slice (`P4-OPS`), which is where that
   decision belongs anyway.
4. **Single-instance only.** SQLite's own locking keeps two processes from corrupting the file, but
   nothing stops them both submitting the same deposit — there is no claim protocol, by design
   (§0). Run one. A boot-time lock is a cheap follow-up if that ever needs enforcing.
5. **A persistently-transient deposit blocks its page** (§3).
6. **The `/v1/info` fast-fail and the pre-submit domain/token check are gone.** Malformed deposits
   reach the chain and are refused there, costing a fee.
7. **Circle wire-surface fidelity is reduced** to what the forward poll actually uses.

---

## 8 · The one thing that does not change: the Miden submit is still blocked

There is **no `miden-client` release for protocol v0.16** (the workspace manifest records why
`crates/xusdc-validation` is parked for exactly this reason). So the lite crate keeps the same seam:
a small `MintSubmit` trait in `submit.rs`, and a `production_submit_port()` that returns an error so
`main` **refuses to start** rather than run with a no-op submit that would look healthy in every log
except the chain's.

**Nothing in the lite crate fakes Miden behaviour.** Tests drive the trait with a scripted adapter
(explicitly non-gating for Miden acceptance); the real adapter and its real-local-node proof are a
later slice, unchanged by this plan. Ground-rule position is identical to the existing crate's —
Circle may be mocked, Miden may not.

---

## 9 · Decisions needed from the approver before Phase 1

| # | Question | Recommendation |
|---|---|---|
| D-1 | Crate name `xreserve-deposit-relayer-lite`? | accept; rename freely, it is cosmetic |
| D-2 | At-least-once instead of exactly-once (§0) — **the load-bearing decision** | accept: the chain is the authoritative dedup |
| D-3 | SQLite cut to one nonce table + a one-row cursor table (§2) | accept — the engine was never the cost, the six-state machine on top of it was |
| D-3a | Collapse to a literal single key-value table instead? (§2 open point) | decline — it costs the typed 32-byte BLOB key and its `length = 32` constraint, and mixes two concerns in one relation |
| D-4 | `anyhow` rather than `thiserror` (#160 suggested `thiserror`) | `anyhow` — it is a binary with no public error API. Reverting to `thiserror` costs ~50 lines, not 836, so either satisfies #160's intent |
| D-5 | `tracing` for logging — **#160 does not mention it**; this is a proposal, not a requirement of the issue | accept; `eprintln!` is the fallback if the team prefers no logging framework yet |
| D-6 | Drop metrics entirely, deferring to `P4-OPS`? | accept |
| D-7 | Does the sibling crate join `[workspace] members`? | yes — otherwise it is outside the `--locked` gate |
| D-8 | Is the existing crate retired if lite proves out, and when? | **out of scope here**; propose a follow-up decision after lite runs against a real node |

`DEV-*` / `Q-*` items (DEV-5 cap/scale, DEV-7 burn evidence, DEV-10 AccountId encoding) are
Circle-owned and **stay OPEN** (ground rule 6). This plan neither resolves nor re-labels any of them.

---

## 10 · Phasing and acceptance gates

**Phase 0 — this document.** Approval. No code. ← *we are here*

**Phase 1 — skeleton + store + config.** `Cargo.toml`, `config.rs`, `store.rs`, workspace
membership. Gate: T-S1…T-S5, T-G1…T-G3.

**Phase 2 — Circle half.** `circle.rs` + the axum mock support. Gate: T-H1…T-H7.

**Phase 3 — mint + submit seam + the loop.** `mint.rs`, `submit.rs`, `main.rs`. Gate: T-C1…T-C13,
T-G4. **T-C2 (the #160 wedge-bug regression) must be green.**

**Phase 4 — docs + measurement.** `README.md`; record final line counts against the §4 budget; if
source exceeds **800 lines**, that is a signal the design drifted and is re-reviewed, not waved
through.

Acceptance commands, from the repo root (the same offline gate the rest of the workspace uses; there
is no CI workflow directory in this repo, so these are run locally):

```sh
cargo build  --locked -p xreserve-deposit-relayer-lite
cargo test   --locked -p xreserve-deposit-relayer-lite
cargo fmt    --all -- --check
cargo clippy --workspace --locked -- -D warnings
```

The existing `xreserve-deposit-relayer` must remain green throughout — this plan does not touch it.

Per ground rule 8, commits are conventional and signed, and **nothing is pushed and no PR is opened
without explicit human approval.**

---

## 11 · Deviations from this plan, as built

Four, all recorded rather than quietly absorbed.

**D-A · Eight source files, not six.** The plan's own `tests/` layout requires integration tests,
which can only reach a **library** target — a `[[bin]]` cannot be imported. So `src/lib.rs` (30
lines, module declarations only) exists to provide one, and the cycle moved out of `main.rs` into
`src/cycle.rs` so the tests can drive it. `main.rs` is now wiring only.

**D-B · The §4 line budget was missed: 1,151 lines (719 code) against ~590.** Honestly reported
rather than waved through, per Phase 4. Two causes, no design drift:

* `circle.rs` is 404 lines against a budgeted 180, because it carries the `Transport` seam (D-C)
  that the budget assumed would not be needed.
* The budget counted *lines*; 300 of the 1,151 are doc comments (26%, against the sibling's 38%).
  On code alone the figure is **719 against ~590**.

The 800-line tripwire is therefore breached on total lines and cleared on code. **Open for the
approver:** trim doc comments further, or accept 26% as the floor for a documented public API.

**D-C · The mock Circle is a recording fake, not axum + tower.** The plan (and §5) specified an
in-process axum router. Once the crate had a `Transport` trait, that seam sat *above* HTTP, so an
axum router would have exercised nothing the fake does not — while costing two dev-dependencies.
`axum` and `tower` were dropped from the manifest entirely. The sandbox constraint that ruled out
`httpmock`/`wiremock` is unchanged and still respected: **no test binds a socket.**

**D-D · No hand-rolled percent-encoding.** A first cut carried ~55 lines of hand-written
`urlencode`/`urldecode`. They are gone: `reqwest` re-exports `Url`, whose `query_pairs_mut` and
`query_pairs` do both jobs correctly and for free. This is #160's fifth complaint — "we could just
generate that using Rust tooling" — applied to URLs rather than errors, and it removed a place where
bugs would have lived silently.
