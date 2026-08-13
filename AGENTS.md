# xUSDC on Miden — Implementation Monorepo

Circle **xReserve / xUSDC** (NOT standard USDC, NOT CCTP) on Miden: native USDC stays locked 1:1 in Circle's xReserve contract on the source chain; this repo implements the Miden side — the hand-written-MASM xUSDC faucet contract (mint against Circle deposit attestations, burn for withdrawal), the Rust encoding library that mirrors the faucet's MASM codecs, and the real-local-node validation harness. (The partner off-chain services — deposit relayer, withdrawal listener/attester, monitoring — which will consume that encoding library, are later units of the wider program and are **not** in this repository.)

## Non-negotiable ground rules

1. **MASM-first.** All on-chain code (faucet, encoding module, note scripts) is **hand-written MASM**. Rust exists ONLY for off-chain services, mirrors, tests, harnesses, and tooling. There is NO `cargo miden build` / Rust-contract path in this repo (the `rust-sdk-patterns` skill family was deliberately excluded — see `.claude/skills/README.md`).
2. **Plan first, build after approval.** Builders produce a plan + test matrix and STOP for human/audit approval before any source edit.
3. **The governing docs bind every builder:** `docs/governing/CANONICAL-OWNERSHIP-MAP.md` (owners, layout, names) and `docs/governing/BUILDER-GATES.md` (G0–G8, G-MASM, G-RUST). Read both before any work. The specs and governing docs under `docs/` are the source of truth for this repository.
4. **Frozen decisions (do not revisit, do not alias):**
   - NS-1 (amended): bytes32→Word MASM proc = `xreserve::mint_intent::hash_nonce` — the `xreserve::encoding` module is gone, its contents folded into the two modules that own the wire forms. The Rust routine keeps `bytes32_to_storage_map_key`.
   - NS-3 (supersedes NS-2): the on-chain DepositIntent realization is 01-owned at `xreserve::deposit_intent::rebuild` — the faucet **writes** the signed preimage (DC-14) instead of parsing it, so the NS-2 parser is retired and must not be reintroduced. The Rust `DepositIntent` decode is unaffected.
   - DC-7: the burn-item codec is 04-owned and ships in Rust at `crates/xusdc-encoding/src/xreserve/encoding/burn_note.rs`; there is no `burn_items.masm`.
   - Layout: **SELF-CONTAINED** components; the faucet component ships under `asm/standards/xreserve/` and its note scripts under `asm/standards/notes/`.
5. **Version pins:** Workspace manifests and `Cargo.lock` are authoritative. Protocol-family crates pin `0xMiden/protocol@4971ec4b38fb1f54e8f73969e6da81ee0cbf850c` (`v0.16.0-beta.1`).
6. **Circle-owned open decisions stay OPEN** (`DEV-*`/`Q-*`, e.g. DEV-5 cap/scale, DEV-7 burn evidence, DEV-10 AccountId encoding): implement per the frozen spec, keep the OPEN labels, never mark them approved/resolved.
7. **Single-owner rule:** every shared format/routine has exactly one owner (the map); consumers pin by reference. One canonical golden-vector artifact drives both MASM and Rust tests; MASM tests must EXECUTE, not just assemble.
8. Git: conventional commits, signed; **never push, publish, or open PRs without explicit human approval.**

## Skills & agents

`.claude/skills/` (36, auto-discovered) is mandatory checklist material per the gates — 31 protocol-local skills pinned from `0xMiden/protocol#2927` @ `5bc1655d` + 5 Miden app-developer skills. Provenance, pinned obligations (checked-arithmetic + u32-assert for the reducer; constant-parity for DC-1), and deliberate exclusions: `.claude/skills/README.md`. Reviewer agents: `.claude/agents/{code-reviewer,security-reviewer}.md`. Commands: `/review-plan`, `/review-security`, `/deps-audit`, `/pr-enhance`.

## Layout (created only via approved plans)

```
asm/standards/xreserve/      # faucet account component (xreserve::*): the mint policy, the attestation verify, the attester admin
  deposit_intent.masm        # Circle's wire form + `rebuild`, the on-chain realization of it (DC-1, DC-14)
  mint_intent.masm           # what the mint note actually carries (DC-14) — constants only
asm/standards/notes/         # public note scripts — the mint note and the admin notes
crates/xusdc-encoding/       # Rust: the encoding mirror, the faucet-account builder, golden vectors, assemble-and-execute tests
crates/xusdc-validation/     # Rust: the real-local-node validation harness (LNV rows A–L)
docs/governing/  docs/spec/  # governing conventions + pins; the spec, glossary, and encoding spec
```

(This is the tree as built. The off-chain partner services — relayer, listener, monitoring — are
later units of the wider program and are not in this repository.)

Build order: **04 shared encoding → 01 faucet (including its local-node validation) → 02 relayer → 03 listener → system E2E validation → 05 monitoring** (frontend deferred). Each unit: plan → audit → build → consortium → Codex audit → human approval.

## Working in this repo (onboarding — for a human or a local coding agent)

New here? Read the specs before the code. `README.md` is the top-level orientation;
`docs/spec/FAUCET-COMPONENT-SPEC.md` is what the faucet does, and
`docs/spec/ENCODING-COMPONENT-SPEC.md` is the shared codecs.

### Code comments ↔ docs

Inline code comments carry plain-English prose only — each comment stands on its own with no
external lookups. Stable requirement, invariant, data-contract, and open-question IDs are defined
in `docs/spec/GLOSSARY.md`.

### Build / test / validate

Run from the repo root; everything except the node harness is offline (toolchain pinned in
`Cargo.lock`):

```sh
cargo build  --locked -p xusdc-encoding                       # compile the encoding crate (Rust; MASM is assembled by the test gate, not here)
cargo test   --locked -p xusdc-encoding --release             # THE gate: assemble + EXECUTE the MASM, full suite
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
