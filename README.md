# xusdc-miden

Implementation monorepo for **Circle xReserve / xUSDC on Miden** — the Miden-side faucet contract (hand-written MASM), the shared encoding layer, and the partner off-chain services (deposit relayer, withdrawal listener/attester, monitoring).

**Status:** pre-implementation. The spec program (Phases 1–4.3) is complete, audited, and finalized in the `agentic-template/ai-tasks/circle-integration/` program tree; this repo was bootstrapped 2026-06-11 with all governing docs (mirrored, read-only) and the full curated AI-resource set. The first build slice is **04 shared encoding** (plan-gated — see `CLAUDE.md`).

| Where | What |
|---|---|
| `CLAUDE.md` | Ground rules every agent must follow (MASM-first, pins, frozen decisions, plan gate) |
| `docs/governing/` | Read-only mirrors: ownership map, builder gates, v0.15/devnet pin ledger, MASM research report, grounding-spike report |
| `docs/spec/04-shared-encoding/` | Read-only mirrors of the frozen Phase 4 spec package for the first slice |
| `.claude/skills/` | 36 curated skills (31 pinned from `0xMiden/protocol#2927` + 5 Miden app-developer) — provenance in its README |
| `.claude/agents/`, `.claude/commands/` | Reviewer agents (#2927) + audit slash commands (`agent-tools`) |
| `tools/sync-mirrors.sh` | Re-sync the `docs/` mirrors from their canonical sources |

No source code exists yet by design: builders must have their plan audited and approved before the first edit.
