# xUSDC on Miden — Implementation Monorepo

Circle **xReserve / xUSDC** (NOT standard USDC, NOT CCTP) on Miden: native USDC stays locked 1:1 in Circle's xReserve contract on the source chain; this repo implements the Miden side — the hand-written-MASM xUSDC faucet contract (mint against Circle deposit attestations, burn for withdrawal), the Rust encoding library that mirrors the faucet's MASM codecs, and the real-local-node validation harness. (The partner off-chain services — deposit relayer, withdrawal listener/attester, monitoring — which will consume that encoding library, are later units of the wider program and are **not** in this repository.)

## Non-negotiable ground rules

1. **MASM-first.** All on-chain code (faucet, encoding module, note scripts) is **hand-written MASM**. Rust exists ONLY for off-chain services, mirrors, tests, harnesses, and tooling. There is NO `cargo miden build` / Rust-contract path in this repo (the `rust-sdk-patterns` skill family was deliberately excluded — see `.claude/skills/README.md`).
2. **Plan first, build after approval.** Builders produce a plan + test matrix and STOP for human/audit approval before any source edit.
3. **The governing docs bind every builder:** `docs/governing/CANONICAL-OWNERSHIP-MAP.md` (owners, layout, names) and `docs/governing/BUILDER-GATES.md` (G0–G8, G-MASM, G-RUST). Read both before any work. The specs and governing docs under `docs/` are the source of truth for this repository.
4. **Frozen decisions (do not revisit, do not alias):**
   - NS-1: bytes32→Word MASM proc = `xreserve::encoding::bytes32_to_key` (the Rust routine keeps `bytes32_to_storage_map_key`).
   - NS-2: the shared DepositIntent parser = 04-owned `xreserve::encoding::parse_deposit_intent`; faucet owns only mint-specific assertions.
   - DC-7: `encoding/burn_items.masm` = 04-owned burn-item codec home (deferred past the first slice). [SUPERSEDED 2026-06-30 → P5-04 codec: DC-7 shipped as RUST (`crates/xusdc-encoding/src/xreserve/encoding/burn_note.rs`), NOT a .masm file — there is no burn_items.masm]
   - Layout: **SELF-CONTAINED** components; two-root tree `asm/standards/xreserve/…` + `asm/account_components/faucets/…`. [SUPERSEDED → as built, the `asm/account_components/` root was not materialized: the faucet component ships under `asm/standards/xreserve/` and its note scripts under `asm/standards/notes/`. See the Layout section below for the tree as built.]
5. **Version pins (ledger: `docs/governing/V15-DEVNET-BASELINE.md`):** Miden **v0.15 + devnet**. `protocol v0.15.3` (`681fc9058`) → assembler crates **0.23.3** (seed `Cargo.lock`); `miden-node v0.15.0` (`29a876c3`, the TAG is the pin); devnet RPC `https://rpc.devnet.miden.io`. Miden testnet (v0.14) is NOT the validation network. `miden-vm`/`miden-assembly` follow their own `0.23.x` cadence — never pin a "miden-vm v0.15" tag.
6. **Circle-owned open decisions stay OPEN** (`DEV-*`/`Q-*`, e.g. DEV-5 cap/scale, DEV-7 burn evidence, DEV-10 AccountId encoding): implement per the frozen spec, keep the OPEN labels, never mark them approved/resolved.
7. **Single-owner rule:** every shared format/routine has exactly one owner (the map); consumers pin by reference. One canonical golden-vector artifact drives both MASM and Rust tests; MASM tests must EXECUTE, not just assemble.
8. Git: conventional commits, signed; **never push, publish, or open PRs without explicit human approval.**

## Skills & agents

`.claude/skills/` (36, auto-discovered) is mandatory checklist material per the gates — 31 protocol-local skills pinned from `0xMiden/protocol#2927` @ `5bc1655d` + 5 Miden app-developer skills. Provenance, pinned obligations (checked-arithmetic + u32-assert for the reducer; constant-parity for DC-1), and deliberate exclusions: `.claude/skills/README.md`. Reviewer agents: `.claude/agents/{code-reviewer,security-reviewer}.md`. Commands: `/review-plan`, `/review-security`, `/deps-audit`, `/pr-enhance`.

## Layout (created only via approved plans)

```
asm/standards/xreserve/      # faucet account component (xreserve::*): custom mint, burn policy, admin setters
  encoding/                  # shared encoding library — mod.masm (procedures) + layout.masm (constants)
asm/standards/notes/         # public note scripts — the mint note and the admin notes
crates/xusdc-encoding/       # Rust: the encoding mirror, the faucet-account builder, golden vectors, assemble-and-execute tests
crates/xusdc-validation/     # Rust: the real-local-node validation harness (LNV rows A–L)
docs/governing/  docs/spec/  # governing conventions + pins; the spec, glossary, and encoding spec
canary/                      # grounding reports: each Miden primitive the faucet relies on, proven to execute
```

(This is the tree as built. The off-chain partner services — relayer, listener, monitoring — are
later units of the wider program and are not in this repository.)

Build order: **04 shared encoding → 01 faucet → 02 relayer → 03 listener → local-node/devnet validation → 05 monitoring** (frontend deferred). Each unit: plan → audit → build → consortium → Codex audit → human approval.

> [SUPERSEDED → faucet §11: the **faucet's own local-node validation is part of unit 01** (its own gate, BEFORE the off-chain relayer/listener) — do NOT defer the faucet's node-validation to the end. The trailing "local-node/devnet validation" step above is the **system E2E** (whole-flow), not the faucet's unit gate.]

## Working in this repo (onboarding — for a human or a local coding agent)

New here? Read the specs before the code. `README.md` is the top-level orientation;
`docs/spec/FAUCET-COMPONENT-SPEC.md` is what the faucet does, `docs/spec/ENCODING-COMPONENT-SPEC.md`
is the shared codecs, and `docs/DOCS-INVENTORY.md` maps every doc in the repo.

**Looking for where a requirement, invariant, or decision id is implemented and verified?
`docs/REQUIREMENTS-TRACEABILITY.md` is the index** — it maps every id (`CIR-*`, `INV-*`, `DEV-*`,
`R-MINT-*`, `DC-*`, …) to the procedure or function that implements it and the test that verifies
it. Inline comments deliberately carry prose, not ids, so this index is the only place the two are
tied together.

### Code comments ↔ docs

Inline code comments carry plain-English prose only — each comment stands on its own with no
external lookups. The short stable IDs — a requirement (`R-MINT-15`), an invariant
(`INV-MINT-SECURITY`), a mint pipeline stage (`D5c`), a data contract (`DC-1`), or a
still-Circle-owned open question (`DEV-10`) — are defined in `docs/spec/GLOSSARY.md` and mapped
to their implementing procedure/function and verifying test in
`docs/REQUIREMENTS-TRACEABILITY.md`. A tripwire test
(`crates/xusdc-encoding/tests/comment_hygiene_tripwire.rs`) keeps the ids out of comments.

### Build / test / validate

Run from the repo root; everything except the node harness is offline (toolchain pinned in
`Cargo.lock`):

```sh
cargo build  --locked -p xusdc-encoding                       # compile the encoding crate (Rust; MASM is assembled by the test gate, not here)
cargo test   --locked -p xusdc-encoding --release             # THE gate: assemble + EXECUTE the MASM, full suite
cargo test   --locked -p xusdc-encoding --test masm_structure # MASM source-convention conformance
cargo fmt    --all -- --check                                 # formatting
cargo clippy --workspace --locked -- -D warnings              # lints
```

`cargo test -p xusdc-encoding --release` is the real build-and-behaviour gate: it assembles every
`.masm`, links it into the faucet account, and executes the mint/burn/admin behaviour on a mock chain.
There is no `cargo miden build` / Rust-contract path — the on-chain code is hand-written MASM (ground
rule 1). Real-local-node validation lives in `crates/xusdc-validation`; each gate binary bootstraps,
starts, and tears down its own four-service node stack (the four v0.15.1 node binaries must be on
`PATH`), so it is separate from the offline gate above. See `crates/xusdc-validation/README.md` for
the per-row `cargo run -p xusdc-validation --bin …` commands.

### Pairing tips

- Plan first, build after approval (ground rule 2); the governing docs bind every change
  (`docs/governing/CANONICAL-OWNERSHIP-MAP.md`, `docs/governing/BUILDER-GATES.md`).
- Shared formats have exactly one owner (the ownership map); consumers pin by reference — don't fork a
  codec.
- `DEV-*` / `Q-*` items are Circle-owned and stay OPEN; implement per spec, never mark them approved.
- `.claude/skills/` holds the mandatory checklist skills; reviewer agents are in `.claude/agents/`.

> **`AGENTS.md` and `CLAUDE.md` are kept byte-identical** so a local agent gets the same onboarding
> whether it reads `AGENTS.md` (e.g. Codex) or `CLAUDE.md` (e.g. Claude Code). `CLAUDE.md` is
> canonical — edit it, then copy it over `AGENTS.md`.
