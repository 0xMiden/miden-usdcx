# Deferred dependencies — `xreserve-deposit-relayer`

This crate is built in slices. Some dependencies named in the component design belong to a **later**
slice and are intentionally **not declared** in `Cargo.toml` yet, because declaring them now would
break this repository's offline build gate. This file records each such deferral — WHAT, WHY, WHICH
slice introduces it, and HOW that slice must provision it — so the future slice does not hit the same
wall. It is enforced by `tests/deferred_dependencies_doc.rs` (the guard fails if this record goes
missing or loses a required element, or if the discharge below is undone).

Operator decision (round 5 escalation → round 6 ratification): the reqwest deferral below was
ACCEPTED. **It is now DISCHARGED** — see the status block.

---

## `reqwest` — Circle HTTP client (DEFERRED → **DISCHARGED** in the Circle-facing slice)

### Status: DISCHARGED (the Circle-facing HTTP client slice)

The deferral named the **Circle-facing HTTP client slice** as the one that would declare `reqwest`,
once its environment provisioned the crate offline (option 1 below: pre-seed the cargo cache). That
slice is the one that ships `circle::{client, schema, attestation_fetch, info}`, and its environment
now carries **`reqwest 0.13.4`** and its full `hyper`/`rustls`/`h2` closure in the pinned cargo
cache. `reqwest` is therefore declared — in the **root `[workspace.dependencies]`** (so the later
off-chain services cannot drift onto a different HTTP stack) and consumed by this crate — and the
offline gate still passes: `cargo build/test/clippy --locked --offline` resolves the whole graph from
the cache, with no crates.io access.

Two facts the next reader needs:

- **reqwest 0.13's feature names differ from 0.12's.** TLS is **`rustls`** (0.12: `rustls-tls`), and
  `RequestBuilder::query` — how every Circle query param is built — sits behind its own **`query`**
  feature. The declared set is `default-features = false, features = ["rustls", "json", "query"]`.
- **The mock Circle server is built from `axum` + `tokio`** (dev-dependency), because `wiremock` /
  `httpmock` / `mockito` are **not** in the pinned cache and would reintroduce exactly the failure
  this deferral was about. Do not add them.

The record below is kept verbatim as the WHY — it is the reason the earlier slices carry no reqwest,
and the reason any future dependency must clear the offline gate before it is declared.

### The original deferral (historical record)

- **What.** The `reqwest` HTTP client. In the relayer design it is the Circle-facing transport used
  by `circle::client` to fetch deposit attestations (`GET /v1/info`, `/v1/attestations/*`,
  `/v1/remote-domains/{d}/attestations` — `CMP-D1`/`CMP-D3`/`CMP-D4`).

- **Why deferred (the offline-gate constraint).** This repository's build/test/lint gate runs
  **offline against a pinned cache**: `cargo build/test/clippy --locked --offline` (root
  `CLAUDE.md`, ground rule 1 / G0 — the toolchain is pinned in `Cargo.lock` and nothing may reach
  crates.io). `reqwest` and its transitive TLS graph (e.g. `aws-lc-rs`, `hyper-rustls`) are **not in
  that pinned cache**. Cargo must **resolve** a declared registry package **even when it is optional
  and its feature is disabled**, so any `reqwest` entry in the manifest/`Cargo.lock` makes *every*
  offline workspace command fail with:

  ```
  error: no matching package named `reqwest` found
  location searched: crates.io index
  ```

  This was verified across three rounds: a plain dependency (round 3), an `optional = true`
  feature-gated dependency (round 4), and a from-cache reproduction of the auditor's clean offline
  environment (round 5). No manifest form (required, optional, dev-dependency, or target-gated)
  avoids the resolution step, so there is no way to keep `reqwest` in the lock and pass the offline
  gate from the current pinned cache. Hence the deferral.

- **Which slice introduces it.** The **Circle-facing HTTP client slice** — the first slice that
  actually issues Circle requests (it builds `circle::client` / `circle::attestation_fetch`). That
  slice, not this scaffold, adds `reqwest` to `Cargo.toml`. Suggested feature set when it does:
  `default-features = false, features = ["json", "rustls"]` (rustls-based TLS so the build carries no
  system-OpenSSL dependency).

- **How to provision it offline there (do this BEFORE declaring reqwest).** The Circle slice must
  make `reqwest` + its full transitive graph resolvable under `--locked --offline`, by **one** of:

  1. **Pre-seed the cargo cache.** With network available once, run the declaring crate's build/test
     so cargo downloads `reqwest` and its graph into the registry cache
     (`~/.cargo/registry/{cache,src,index}`), then commit the updated `Cargo.lock`. The pinned
     offline environment for that slice must be built from a cache that already contains those
     `.crate` files (bake them into the environment image / cache snapshot).
  2. **Vendor the sources.** Run `cargo vendor` to write `reqwest` + its dependency sources into a
     repository `vendor/` directory and add the generated `[source.crates-io] replace-with = ...`
     stanza to `.cargo/config.toml`. Offline resolution then reads the vendored sources from the
     repo (no crates.io access). This makes the graph fully self-contained but adds a large
     `vendor/` tree — weigh it against the pre-seeded-cache option.

  Either way, re-run the full offline gate (`build`/`test`/`clippy`/workspace-`clippy`/`fmt`, all
  `--locked --offline`) in the target environment to confirm `reqwest` resolves before handoff.

- **Scope the scaffold slice kept.** Circle HTTP behavior stayed OUT of scope there; the scaffold
  wired only `tokio`/`serde`. No Circle endpoint, credential, or Miden domain is committed even now —
  `Q-API-AUTH` / `Q-DOM-1` stay OPEN (`REQUIRES CIRCLE CONFIRMATION`): the client ships an auth-header
  *injection point* fed from config, never a baked-in key, and the base URL is configuration whose
  default is the documented testnet host.

- **Cross-references.** `crates/xreserve-deposit-relayer/Cargo.toml` (the `[dependencies]` comment
  block points here); the root `Cargo.toml` `[workspace.dependencies]` (where `reqwest` and `axum`
  are pinned); the relayer component spec §1.4 / §4 (`circle::client`, `CMP-D1`/`D3`/`D4`).
