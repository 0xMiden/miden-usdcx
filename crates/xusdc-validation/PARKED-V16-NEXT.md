# PARKED at the v16-alpha family — the LNV harness awaits a client for protocol `next`

**Status (2026-07-28, the V16-NOW migration — `docs/MIGRATION-V16-NEXT.md`):** this crate is
PARKED for the second time. It was removed from `workspace.members` and added to
`workspace.exclude` in the root `Cargo.toml`; the crate directory itself is byte-intact at its
v16-alpha state (protocol/standards/tx `=0.16.0-alpha.4`, `miden-client` /
`miden-client-sqlite-store` `=0.16.0-alpha.1`) apart from this file. `PARKED-V15.md` is kept
byte-intact as the historical v15 record; its "UN-PARKED" banner describes the earlier P1b-a
un-park and is superseded by THIS record.

## Why

`xusdc-validation` is the real-local-node validation harness (LNV rows A–L). It consumes
`miden-client` / `miden-client-sqlite-store`, and the newest client releases (`=0.16.0-alpha.1`)
pin protocol `=0.16.0-alpha.4`. The rest of the workspace migrated to the protocol monorepo's
`next` branch at the frozen git rev `dbe4e38797207ce09fee1668ea204aafec275f63` — a graph no
released client can join: keeping this crate a member would force two incompatible copies of the
protocol family into one workspace. There is likewise no node release for the `next` graph, so no
LNV leg could run against the migrated code even if it compiled.

MockChain (`miden-testing` at the same frozen rev) is the verification harness for the migrated
workspace; every migrated behavior gate runs there
(`cargo test --locked -p xusdc-encoding --release`).

## Intentionally non-building standalone

The manifest keeps its v16-alpha dependency entries (including `workspace = true` entries whose
table lives in the root manifest). Parked, it is **not expected to build on its own** —
`workspace.exclude` only keeps cargo invocations inside this directory from claiming membership
of the migrated workspace. Do not "fix" the manifest while parked.

## What still works / what this crate's record means

- The **v15 LNV record stands as the v15 evidence**: `VALIDATION-RECORD.md` (LNV-1..5, 12/12 rows
  green against the four-service v0.15.1 local node stack). The **v16-alpha port** (P1b-a) stands
  as the compile-and-unit-test evidence for the alpha.4 family; the operator-run live-node leg
  (P1b-b) remained open when this park landed. Nothing in the V16-NOW migration touches or
  re-litigates either record.
- The deployed devnet v1 faucet Circle tests against is untouched by this park — it runs deployed
  artifacts, not this workspace.

## Re-enable trigger

The V16-FINAL migration (FUTURE-FIXES row FF-3): the workspace moves off the frozen `next` git rev
onto the released `v0.16.0` crates.io family **and** a matching `miden-client`/node pair exists.

## Re-enable steps

1. Restore `"crates/xusdc-validation"` to `workspace.members` and drop it from
   `workspace.exclude` (root `Cargo.toml`).
2. Bump this crate's manifest pins to the released v0.16.0 family: the protocol crates to the
   workspace's crates.io pin, `miden-client`/`miden-client-sqlite-store` to their v0.16 releases.
3. Adapt to the API deltas recorded in `docs/MIGRATION-V16-NEXT.md` — this crate consumes the same
   renamed surfaces (`AccountBuilder::with_auth_component` removal, the `Library`→`Package` rename
   wave, the `AuthNetworkAccount` constructor rework with its mandatory fee-policy configuration).
4. Adapt the admin rows to the standard admin components AND to the re-gated setters.

   **Expected-gate constants (behavioural, not cosmetic).** The admin setters — `set_attester`,
   `set_min_burn_size`/`set_min_burn_amount`, `set_max_supply` — and, since the 2026-07-31
   admin-surface finalization, `identifier_init` too, no longer resolve to an owner. There is no
   `Ownable2Step` component and no owner slot at all. They carry no role of their own, so the
   account's role-based authority resolves them to the built-in `ADMIN` role and an unauthorized
   sender is rejected with `ERR_SENDER_LACKS_ROLE`, not `ERR_SENDER_NOT_OWNER`. These rows still
   expect the owner error and will fail against a current faucet:
   - `src/assertions_cf.rs:53` — `ERR_NOT_OWNER` is defined and used as a setter's expected gate.
   - `src/assertions_cf.rs` C6 assertion — requires at least one negative expecting `ERR_NOT_OWNER`.
   - `src/rows_cf.rs` C6 negatives — two rows carry `expected_gate: ERR_NOT_OWNER`.
   - `src/sanity/admin.rs` — the `set_attester` rejection asserts `ERR_NOT_OWNER`.

   These were left as-is rather than changed blind: the crate is excluded from the workspace and
   cannot be compiled or executed against the current pins, so an untested edit to an assertion
   would be a guess. `ERR_LACKS_ROLE` already exists in `assertions_cf.rs` and is what they should
   use — and it is now what EVERY admin row should expect. There are no ownership-slot procedures
   left: `identifier_init` moved onto the account-wide authority, and `transfer_ownership` /
   `accept_ownership` were deleted with the component. Every reference this crate carries to them
   (`src/sanity/admin.rs`, `src/sanity/admin_restore.rs`, `src/deploy.rs`, `src/sanity/driver.rs`,
   `src/sanity/record.rs`) names a procedure or note factory that no longer exists; the ownership
   rows must be dropped, and administrator rotation re-expressed as a grant and a revoke of the
   `ADMIN` role through the stock `RbacActionNote`.

   **The standard admin components.** While this crate was parked, the faucet
   replaced its two hand-written role-gated admin wrappers with the stock `PausableManager` and
   `BlocklistManager`, driven by the stock `PauseActionNote` and `BlocklistConfigNote`. The
   references this crate still carries to `xreserve::pause_admin::{pause,unpause}` and
   `xreserve::blocklist_admin::{block_account,unblock_account}` (`src/rows_cf.rs`, `src/rows_gj.rs`,
   `src/assertions_cf.rs`, `src/sanity/admin.rs`, `src/sanity/admin_restore.rs`) name procedures
   that no longer exist; point them at the stock manager roots and build the notes through
   `PauseActionNote` / `XReserveBlocklistConfigNote`. Role management likewise moved to the stock
   `RbacActionNote` (one script root carrying grant, revoke, set-role-admin and renounce), so the
   references to the deleted bespoke `grant_role` / `revoke_role` note factories must be re-pointed
   at it. The note-script allowlist is 9 roots, not 14, and the callable surface is 70, not 75.
5. Re-run the LNV row gates (`cargo run -p xusdc-validation --bin …` per this crate's README)
   against the matching node stack and extend `VALIDATION-RECORD.md` with the run.
