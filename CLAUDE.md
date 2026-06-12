# xUSDC on Miden — Implementation Monorepo

Circle **xReserve / xUSDC** (NOT standard USDC, NOT CCTP) on Miden: native USDC stays locked 1:1 in Circle's xReserve contract on the source chain; this repo implements the Miden side — the xUSDC faucet contract (mint against Circle deposit attestations, burn for withdrawal) and the partner off-chain services.

## Non-negotiable ground rules

1. **MASM-first.** All on-chain code (faucet, encoding module, note scripts) is **hand-written MASM**. Rust exists ONLY for off-chain services, mirrors, tests, harnesses, and tooling. There is NO `cargo miden build` / Rust-contract path in this repo (the `rust-sdk-patterns` skill family was deliberately excluded — see `.claude/skills/README.md`).
2. **Plan first, build after approval.** Builders produce a plan + test matrix and STOP for human/audit approval before any source edit. The governing builder task lives at `agentic-template/ai-tasks/circle-integration/05-agent-tasks/TASK-P5-04-SHARED-ENCODING-BUILDER.md`.
3. **The governing docs bind every builder:** `docs/governing/CANONICAL-OWNERSHIP-MAP.md` (owners, layout, names) and `docs/governing/BUILDER-GATES.md` (G0–G8, G-MASM, G-RUST). Read both before any work. `docs/` files are **read-only mirrors** — the canonical sources live in the agentic-template program tree (banner in each file); never edit mirrors, re-sync with `tools/sync-mirrors.sh`.
4. **Frozen decisions (do not revisit, do not alias):**
   - NS-1: bytes32→Word MASM proc = `xreserve::encoding::bytes32_to_key` (the Rust routine keeps `bytes32_to_storage_map_key`).
   - NS-2: the shared DepositIntent parser = 04-owned `xreserve::encoding::parse_deposit_intent`; faucet owns only mint-specific assertions.
   - DC-7: `encoding/burn_items.masm` = 04-owned burn-item codec home (deferred past the first slice).
   - Layout: **SELF-CONTAINED** components; two-root tree `asm/standards/xreserve/…` + `asm/account_components/faucets/…`.
5. **Version pins (ledger: `docs/governing/V15-DEVNET-BASELINE.md`):** Miden **v0.15 + devnet**. `protocol v0.15.3` (`681fc9058`) → assembler crates **0.23.3** (seed `Cargo.lock`); `miden-node v0.15.0` (`29a876c3`, the TAG is the pin); devnet RPC `https://rpc.devnet.miden.io`. Miden testnet (v0.14) is NOT the validation network. `miden-vm`/`miden-assembly` follow their own `0.23.x` cadence — never pin a "miden-vm v0.15" tag.
6. **Circle-owned open decisions stay OPEN** (`DEV-*`/`Q-*`, e.g. DEV-5 cap/scale, DEV-7 burn evidence, DEV-10 AccountId encoding): implement per the frozen spec, keep the OPEN labels, never mark them approved/resolved.
7. **Single-owner rule:** every shared format/routine has exactly one owner (the map); consumers pin by reference. One canonical golden-vector artifact drives both MASM and Rust tests; MASM tests must EXECUTE, not just assemble.
8. Git: conventional commits, signed; **never push, publish, or open PRs without explicit human approval.**

## Skills & agents

`.claude/skills/` (36, auto-discovered) is mandatory checklist material per the gates — 31 protocol-local skills pinned from `0xMiden/protocol#2927` @ `5bc1655d` + 5 Miden app-developer skills. Provenance, pinned obligations (checked-arithmetic + u32-assert for the reducer; constant-parity for DC-1), and deliberate exclusions: `.claude/skills/README.md`. Reviewer agents: `.claude/agents/{code-reviewer,security-reviewer}.md`. Commands: `/review-plan`, `/review-security`, `/deps-audit`, `/pr-enhance`.

## Layout (created only via approved plans)

```
asm/standards/xreserve/           # product root (xreserve::*)
  encoding/                       # 04-owned: layout.masm, bytes32.masm, uint256.masm, account_id.masm, (later) burn_items.masm
  notes/                          # note scripts (later units)
asm/account_components/faucets/   # the xUSDC faucet component (later unit)
<rust workspace>                  # off-chain mirror + test harness crates (shape per approved plan)
docs/governing/  docs/spec/       # read-only mirrors (see rule 3)
```

Build order: **04 shared encoding → 01 faucet → 02 relayer → 03 listener → local-node/devnet validation → 05 monitoring** (frontend deferred). Each unit: plan → audit → build → consortium → Codex audit → human approval.
