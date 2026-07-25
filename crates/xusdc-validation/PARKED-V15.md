> **[SUPERSEDED 2026-07-21 — UN-PARKED (P1b-a).]** The re-enable trigger below has fired: the
> v16-alpha `miden-client` / `miden-client-sqlite-store` `=0.16.0-alpha.1` releases (which pin
> protocol `=0.16.0-alpha.4`, matching the workspace) now exist. This crate has been restored to
> `workspace.members`, its manifest bumped to the v16 family, and its client- and protocol-touching
> call sites ported (steps 1–3 below, DONE). `cargo build --workspace --locked` compiles the lib,
> the `lnv*` binaries, and the `#[ignore]`d `tests/rows_*.rs`; `cargo test --workspace --locked`
> runs its non-ignored tests. Step 4 (re-running the live LNV row gates against a **v16** node stack
> and extending `VALIDATION-RECORD.md`) is the operator-run **P1b-b** step and remains open. This
> file is kept as the historical parking record; the binding status is the un-park itself.

# PARKED at v0.15.3 — the LNV harness awaits a v0.16 `miden-client`

**Status (2026-07-13, the v16 migration — `docs/MIGRATION-V16-ALPHA2.md` rows R1/R2):** this
crate is PARKED. It was removed from `workspace.members` and added to `workspace.exclude` in the
root `Cargo.toml`; the crate directory itself is byte-intact at its v0.15.3 state.

## Why

`xusdc-validation` is the real-local-node validation harness (LNV rows A–L). It consumes
`miden-client` / `miden-client-sqlite-store` `=0.15.3` — and **no v0.16 client release exists**
(protocol team, 2026-07-13: "as soon as we have node and client updated & alpha-released, we'll
let you know"). There is likewise no v0.16 node, so no LNV leg can run against the v16 code at
all. The rest of the workspace moved to crates.io `=0.16.0-alpha.2` (MockChain—`miden-testing`—is
the v16 verification harness); this crate cannot follow yet.

The workspace `[patch.crates-io]` git-pin block existed solely to unify `miden-client`'s
crates.io protocol-family requirements onto the workspace's pinned protocol copy; it left with
this crate (map row R2).

## Intentionally non-building standalone

The manifest keeps its `workspace = true` dependency entries and its v0.15.3 git pins. Parked, it
is **not expected to build on its own** — `workspace.exclude` only keeps cargo invocations inside
this directory from claiming membership of the v16 workspace. Do not "fix" the manifest while
parked.

## What still works / what this crate's record means

- The **v15 LNV record stands as the v15 evidence**: `VALIDATION-RECORD.md` in this crate
  (LNV-1..5, 12/12 rows green against the four-service v0.15.1 local node stack). Nothing in the
  v16 migration touches or re-litigates it.
- The v16 code is verified by the MockChain gate (`cargo test --locked -p xusdc-encoding
  --release`), per the migration map §8.

## Re-enable trigger

The protocol team announces the v16-alpha `miden-client` (+ the matching node release).

## Re-enable steps

1. Restore `"crates/xusdc-validation"` to `workspace.members` and drop it from
   `workspace.exclude` (root `Cargo.toml`).
2. Bump this crate's manifest pins to the v16 family: the protocol crates to the workspace's
   crates.io pin, `miden-client`/`miden-client-sqlite-store` to their v16 releases, and
   `miden-crypto` to the family's 0.28.
3. Adapt to the v16 API deltas recorded in `docs/MIGRATION-V16-ALPHA2.md` (this crate consumes
   the same renamed surfaces: `account_delta()`→`account_patch()`, note builders,
   `AccountBuilderSchemaCommitmentExt` moved to `account::inspection`, etc.).
4. Re-run the LNV row gates (`cargo run -p xusdc-validation --bin …` per this crate's README)
   against the v16 node stack and extend `VALIDATION-RECORD.md` with the v16 run.
