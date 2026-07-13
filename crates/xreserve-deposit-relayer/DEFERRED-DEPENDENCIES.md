# Deferred dependencies — `xreserve-deposit-relayer`

This crate is built in slices. Some dependencies named in the component design belong to a **later**
slice and are intentionally **not declared** in `Cargo.toml` yet, because declaring them now would
break this repository's offline build gate. This file records each such deferral — WHAT, WHY, WHICH
slice introduces it, and HOW that slice must provision it — so the future slice does not hit the same
wall. It is enforced by `tests/deferred_dependencies_doc.rs` (the guard fails if this record goes
missing or loses a required element).

Operator decision (round 5 escalation → round 6 ratification): **the reqwest deferral below is
ACCEPTED.** Do not re-add reqwest — or any other crates.io dependency — to this slice.

---

## `reqwest` — Circle HTTP client (DEFERRED)

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

- **Scope this slice keeps.** Circle HTTP behavior stays OUT of scope here; the scaffold only wires
  `tokio`/`serde`. No Circle endpoint, credential, or Miden domain is committed — `Q-API-AUTH` /
  `Q-DOM-1` stay OPEN (`REQUIRES CIRCLE CONFIRMATION`).

- **Cross-references.** `crates/xreserve-deposit-relayer/Cargo.toml` (the `[dependencies]` comment
  block points here); the relayer component spec §1.4 / §4 (`circle::client`, `CMP-D1`/`D3`/`D4`).
