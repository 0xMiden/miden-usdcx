# Persistence choice — the idempotency seam (`src/idempotency/`)

The component spec leaves the idempotency store's persistence technology **`RIV`** (requires
implementer's validation): it says *what* must survive — the submitted-nonce log and the
per-remote-domain `Link` cursor, across a restart — and leaves *how* to the slice that builds it.
This is that decision, and the reasoning behind it, recorded so a later slice (the withdrawal
listener needs the same durable cursor) does not re-derive it or quietly diverge.

It is guarded by `tests/persistence_choice_doc.rs`: if the crate stops declaring what this file says
it uses, the gate fails.

## Decision

**SQLite**, via **`rusqlite` 0.37** with the **`bundled`** feature — one file, WAL journal,
`synchronous = FULL`, opened by `IdempotencyStore::open`.

## What the store actually has to guarantee

Two things, and the second one is the one that picks the technology:

1. **Durability across a restart (T-RLY-03).** The cursor and the nonce log must survive `kill -9`
   and a power cut, not merely a clean shutdown. A store that can lose the cursor re-walks (or skips)
   a window of attestations; a store that can lose the nonce log re-attempts a mint. The task states
   it flatly: do not weaken the store into a cache that can lose the cursor.

2. **An ATOMIC claim (T-RLY-09).** The dedup this seam exists for is not a lookup — it is a *claim*.
   "Read whether the nonce was submitted, then write that it was" is a read-then-write race: two
   observers (two poll tasks; two relayer processes an operator points at one file during a
   deploy/rollover) can both read *no* and both mint. The check and the insert must be **one atomic
   step**.

Requirement 2 is what rules out the file-based options — not performance, not scale.

## The alternatives, and why they lost

| Option | Durable across restart? | Atomic claim? | Offline (`--locked`) | Verdict |
|---|---|---|---|---|
| **SQLite (`rusqlite`)** | yes — WAL + `synchronous = FULL` fsyncs each commit | **yes** — `BEGIN IMMEDIATE` + `nonce_key` PRIMARY KEY | **cached** | **chosen** |
| `serde_json` file | only with a careful write-temp + fsync + rename dance, hand-rolled | **no** — read-modify-write of the whole map; two writers lose one of the two claims (and a torn write loses everything) | cached | rejected |
| `bincode` file | same as above | **no** — same read-modify-write | cached | rejected |
| `sled` / `redb` | yes | yes (embedded KV with atomic ops) | **not in the pinned cargo cache** — declaring one breaks every `--locked --offline` command in the repo (see `DEFERRED-DEPENDENCIES.md`) | rejected |
| `sqlx` (SQLite) | yes | yes | **not cached**; also async-first, which the store does not need | rejected |
| in-memory map / cache | **no** — loses the cursor on restart, which is the one thing forbidden | n/a | n/a | rejected |

A JSON or bincode file *could* be made durable (write to a temp file, `fsync`, `rename`, `fsync` the
directory). It cannot be made **atomic across processes** without hand-rolling a lock file and its
crash-recovery — i.e. without writing a worse database. SQLite is that database, already written,
already audited, already in this workspace's dependency graph.

## Why `bundled`

`libsqlite3-sys` compiles SQLite from the amalgamation it ships, so the build depends on no system
`libsqlite3` (this box has `libsqlite3.so.0` but no `libsqlite3.so` to link against — a
system-linked build would not link at all) and the store's engine cannot drift with the host's SQLite
version. It is also exactly what `miden-client-sqlite-store` — already in this workspace's graph, on
the same `rusqlite 0.37` — does, so the two cannot pull incompatible feature sets of the same crate.
`array` / `vtab` are deliberately not enabled: the store needs neither.

The pinned cargo cache carries `rusqlite 0.37.0` + `libsqlite3-sys 0.35.0`, so the offline gate
(`cargo build/test/clippy --locked --offline`, root `CLAUDE.md` ground rule 1 / G0) still resolves the
whole graph with no crates.io access. This is a **discharged** dependency, not a deferred one — the
wall `DEFERRED-DEPENDENCIES.md` documents was checked before the crate was declared, not after.

## How the guarantees are configured

| Setting | Value | Why |
|---|---|---|
| `journal_mode` | `WAL` | a reader (an operator query, a metrics scrape) never blocks the writer |
| `synchronous` | `FULL` | a committed claim / cursor advance is **fsynced before the call returns** — `kill -9` cannot take back a mint the relayer believes it recorded |
| `busy_timeout` | 5 s | the loser of a race for the same nonce waits for the winner's commit and then observes it, instead of failing |
| write transactions | `BEGIN IMMEDIATE` | the write lock is taken up front, so the claim's check-then-insert (and every status transition's read-check-write) cannot interleave with another process's |
| `submitted_nonce.nonce_key` | `PRIMARY KEY` | one nonce, one record — enforced by the storage engine, not by an `if` |
| `user_version` | `STORE_SCHEMA_VERSION` | a file written by a build with a different layout is **refused at open**, never read with the wrong columns |
| tables | `STRICT` | a foreign writer cannot leave a string where a blob belongs |

There is deliberately **no in-memory mode**, not even for tests: every test opens a real file in a
`tempfile` directory, and the restart tests prove durability by dropping the handle and reopening the
path. A store that can lose the cursor is not this store, and a test suite that quietly used one
would be testing something else.

## The ephemeral-path trap, and how the constructor closes it

Choosing SQLite brings one sharp edge, and it is worth naming because it nearly turned the whole
choice into a lie: **SQLite's ephemeral databases are spelled as ordinary filenames.**

| Path an operator could configure | What SQLite opens | What it costs |
|---|---|---|
| `:memory:` | an in-memory database | everything, on close |
| `""` (empty) | a private temporary database | everything — SQLite deletes it on close |
| `file:store?mode=memory` (and `&cache=shared`) | an in-memory database, via URI | everything, on close |

Each opens cleanly, accepts a claim, accepts a cursor advance — and loses both on restart. The relayer
would then re-scan the attestation window and re-attempt every mint in it (the on-chain `usedNonces`
assert would reject the duplicates, so no double mint — but the store would have failed at the one job
it has).

`IdempotencyStore::open` closes this with **two independent doors**:

1. **The reserved names are refused before anything is opened** — `:memory:` and an empty filename,
   compared case-insensitively and whitespace-trimmed. That is stricter than SQLite (which would
   cheerfully create a file named `:MEMORY:`), and deliberately so: the operator who typed it meant
   the in-memory database.
2. **The opened database is then asked where it landed** (`pragma_database_list`). A database with no
   file behind it is refused, whatever its spelling. This is the door that catches the URI forms, and
   it **cannot** be replaced by clearing `SQLITE_OPEN_URI`: the pinned `libsqlite3-sys` compiles the
   amalgamation with `-DSQLITE_USE_URI`, so URI filenames are interpreted no matter what the open
   flags say. (The flag is cleared anyway, as a statement of intent.)

A `file:` URI naming a REAL file is durable, and is accepted — the guard rejects databases that
vanish, not a syntax. `tests/idempotency_durable_path.rs` pins every case, including a probe that
proves the premise still holds against the pinned SQLite (a `mode=memory` URI really does lose its
data), so the guard cannot outlive its reason without a test saying so.

## What this is NOT

The store is a **liveness** backstop. The authoritative defence against a double mint is on-chain —
`xreserve_mint` asserts the nonce is absent from `usedNonces` and sets it in the same transaction
(R-MINT-15, INV-MINT-SECURITY). If this store were wiped, the chain would still refuse every
duplicate mint; what would happen is wasted transactions and a re-walked attestation window. That is
the correct reading of "durability" here: SQLite is chosen to keep the relayer *live and cheap*, not
to keep the protocol *safe*.

## What the atomic claim buys, concretely

The claim is not only how a *first* mint is deduped — it is also how a *retry* is acquired. A failed
attempt moves back to `Failed`, and the only way out of `Failed` is `claim_nonce`, which flips it to
an owned `Pending` inside the same `BEGIN IMMEDIATE` transaction that checked it. There is no
`Failed → Submitted` edge, precisely so that "read that it was not submitted, then submit" — the
read-then-write race — cannot be spelled at all. With a JSON/bincode file, that retry acquisition
would have exactly the same race as the first claim, and two observers could both mint the retry.

## Cross-references

- `src/idempotency/` — `mod.rs` (the seam's narrative), `record.rs` (the `SubmissionStatus` machine),
  `store.rs` (the claim + the transitions), `cursor.rs` (the resume point), `recovery.rs` (the
  stale-claim reclaim + the retry work list), `rows.rs` (the row codec that refuses a row it cannot
  read). Split per BUILDER-GATES G3.
- `tests/idempotency_claim.rs` — the store portion of T-RLY-09 (a re-observed nonce yields no second
  submission) + the atomic first-claim and retry-claim races that the rejected file-based options
  would fail. `tests/idempotency_restart.rs` — T-RLY-03 (restart durability, the cursor, the
  crash-before-cursor-advance replay). `tests/idempotency_status_machine.rs` — the machine's edges.
- `DEFERRED-DEPENDENCIES.md` — the offline `--locked` gate that rules out `sled` / `redb` / `sqlx`.
- Root `Cargo.toml` `[workspace.dependencies]` — where `rusqlite` is pinned once, for this crate and
  the listener that will need the same store.
