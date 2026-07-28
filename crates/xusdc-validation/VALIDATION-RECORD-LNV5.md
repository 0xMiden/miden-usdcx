# LNV-5 Validation Record — the consolidated §11.2 full-matrix gate run (rows A–L)

One deterministic pass over the WHOLE validation matrix on ONE fresh local `miden-node v0.15.1` stack: deploy → admin → mint → burn → conservation (the LNV-1..4 drivers composed in matrix order on the same node), then row K (ntx-builder liveness) and row L (clean logs) derived from that single run. Generated deterministically by the gate command below — re-running it on a fresh node regenerates this record. **Validator-not-fixer:** a failing row is a SURFACED finding, never a faucet hot-fix. **Row H stays a Circle/DEV-7 EVIDENCE packet — no acceptability decision.**

- Built from `main` @ `29dbcc4e50f2083942f3d1d0744e34abff63830c`; run root `/home/agent/work/usdcx-cleanup/miden-usdcx/local-node-data/lnv5/run-1783774851` (gitignored: node data, client stores, full logs, machine evidence).
- Pins (unchanged from LNV-1; full toolchain/dep ledger: `VALIDATION-RECORD.md` §2 — LNV-5 adds NO new dependencies): `miden-node` **v0.15.1** installed binaries, four-service loopback stack (sequencer RPC 57291, validator 57292, ntx-builder 57293, tx-prover 57294), isolated local genesis; `miden-client` **=0.15.3** (crates.io); protocol family git `681fc905…` (= v0.15.3 tag).

## Reproduction (the one command)

```bash
cargo run -p xusdc-validation --bin lnv5_full_matrix
```

Requirements: the four v0.15.1 node binaries on `PATH`, loopback ports 57291–57294 free. The command bootstraps a FRESH genesis, runs the whole A–L matrix, tears the stack down, and writes this record + the three evidence packets + `evidence-lnv5.json`.

## Result

| row | title | verdict |
|---|---|---|
| A | deploy + recognize | PASS |
| B | domain_init init-once | PASS |
| C | admin suite (C1–C6) | PASS |
| D | mint happy path | PASS |
| E | mint negatives | PASS |
| F | auth boundary (F5) | PASS |
| G | burn two-block (Circle read-path) | PASS |
| H | burn same-block (F7 RIV evidence) | PASS |
| I | burn negatives | PASS |
| J | conservation ledger | PASS |
| K | ntx-builder liveness (path N) | PASS |
| L | clean logs | PASS |

**GATE VERDICT: PENDING HUMAN ACCEPTANCE (§11.2).** Every matrix row passed its assertion suite on this run, and per the charter the PASS is a HUMAN decision, never self-declared: a human reproduces from a fresh node with the command above, inspects this record, the archived logs, and the evidence packets, and declares the gate outcome.

## Sub-run identities (one node, four slice subjects)

| slice | faucet | counterparty |
|---|---|---|
| rows A/B | `0x82e3c8fb54d533311d40e3f446d4cd` | deploy tx `0xfd123371f64709ea87be98e5699ef81065ce2796fab4ed7d6cd4c72a57b81cb6` @ block 71 |
| rows C/F | `0xf4858ff6df3a31512b8f1e101016d6` | — |
| rows D/E | `0x583da6a2c9ec8ef13e47e0351b975b` | recipient `0x33ad55a6f766e1914923609834e604` |
| rows G–J | `0xcbe044fc2bcad991386b7cb29c1705` | holder `0x27fc127c813084315d0d9240b33a3f` |

Each LNV slice deploys its own production-composition faucet on the SHARED fresh chain (state isolation per network account); the drivers, assertions, and evidence shapes are exactly the LNV-1..4 ones, re-executed in matrix order against one node.

## Rows C/F — committed admin effects (path N) + auth boundary

- C1 attester rotation: A enabled [1, 0, 0, 0] → rotated [0, 0, 0, 0]; B enabled [1, 0, 0, 0]; mint-by-A REJECTED; mint-by-B ACCEPTED.
- C2 min burn size: raised to 50 (read back 50), below-min burn rejected; lowered to 10 (read back 10), at-min burn accepted.
- C3 max supply: committed cap 300 (read back 300); over-cap mint rejected, within-cap accepted.
- C4 pause/unpause (F6): paused [1, 0, 0, 0] (mint+burn rejected; owner setters STILL commit while paused: attester marker [1, 0, 0, 0], min_burn 7), unpaused [0, 0, 0, 0] (mint accepted again).
- C5 role rotation: DOM_PAUSER granted [1, 0, 0, 0] → new pauser paused [1, 0, 0, 0] → revoked [0, 0, 0, 0] → revoked pauser's pause rejected.
- C6 non-authorized senders: 3 admin ops rejected at the proc gate, each note also UNCONSUMED node-side after a watch window.
- Row F: the non-allowlisted note (stock P2ID at the faucet) and the tx-script transaction are both REJECTED (the frozen F5 auth boundary).

## Rows D/E — mint lifecycle

| variant | amount | token_supply | note block → consume block |
|---|---|---|---|
| empty-hookData | 100 | 0 → 100 | 1006 → 1043 |
| hookData-bearing | 150 | 100 → 250 | 1081 → 1118 |

Mint negatives (each client-side REJECTED, zero state change):

- replayed-nonce → `deposit intent nonce has already been used` (supply 250 → 250).
- forged-signature → `deposit attestation signature verification failed` (supply 250 → 250).
- non-allowlisted-attester → `deposit attester pubkey commitment is not allowlisted` (supply 250 → 250).
- nonzero-fee → `mint fee amount must be zero` (supply 250 → 250).
- tampered-payload → `deposit attestation signature verification failed` (supply 250 → 250).

## Rows G/H/I/J — burn lifecycle + conservation

- Row G (two-block, the Circle read-path): burn note `0x387d6378252adee6968417df4c0057f179d4dd319b69989840afe89922be9d26` (tag `0x4255524E`) committed @ block 1461, consumed @ block 1462; token_supply 100 → 0; committed-before-consume true, SyncNotes-discovered true, STILL `GetNotesById`-retrievable after consume true, nullifier recorded true. Byte-exact capture: `LNV5-BURN-GETNOTESBYID-CAPTURE.hex`.
- Row H (F7 same-block RIV — EVIDENCE for Circle/DEV-7, which stays OPEN): note `0x78fb8e84cdb1ccd6e0ebd1ca0207e3bad190e7a23b47666dff0ada6e7b2d44d8`; client-side consume accepted true, executed supply delta Some(100); user-RPC submission REJECTED true; on-chain supply 100 → 100 (unchanged); committed note found false, nullifier false, SyncNotes false. Full packet: `LNV5-F7-EVIDENCE-PACKET.md`.
- Row I burn negatives (each client-side REJECTED, zero state change):
  - below-min → `burn amount is below the minimum burn size` (supply 100 → 100).
  - wrong-asset → `the faucet is not the origin of the asset` (v16 asset::validate_origin; supply 100 → 100).
  - while-paused → `the contract is paused` (supply 100 → 100).
- Row J conservation: Σminted 100 − Σburned 100 == final token_supply 0; holder final balance 0.

## Row K — ntx-builder liveness (path N)

**VERDICT: YES — the ntx-builder auto-executes.** 16 path-N commits observed (2 mint / 1 burn / 13 admin); 102 node-side `executing network transaction` markers in `ntx-builder.log`. Posture: path N LIVE: the node's ntx-builder auto-executes routed+allowlisted consumptions against the network-account faucet (mint, burn, and admin all observed committing on this run); client-side execution (path C) remains open to any permissionless relayer and stays the harness posture for probes/negatives

Full verdict + evidence: `LNV5-NTX-LIVENESS-VERDICT.md`.

## Row L — clean logs

Definition: ZERO unexplained ERROR lines and ZERO panic lines across every archived service log of the whole run, with every WARN triaged + explained. Lines produced by our DELIBERATE negatives (the node-side rejections that ARE those negatives' evidence) are triaged against the explicit pattern table below; a failing POSITIVE cannot hide there because every positive commit is guarded by its own row's bounded committed-effect poll. Anything unmatched fails the row.

| service log | lines | ERROR-level | WARN-level | bytes |
|---|---|---|---|---|
| bootstrap-node | 4 | 0 | 0 | 935 |
| bootstrap-ntx-builder | 2 | 0 | 0 | 726 |
| bootstrap-validator | 3 | 0 | 0 | 541 |
| ntx-builder | 1068 | 234 | 6 | 270279 |
| sequencer | 2782 | 2 | 0 | 2655255 |
| tx-prover | 27 | 0 | 0 | 19972 |
| validator | 4 | 0 | 0 | 630 |

Scan result: **0 unexpected ERROR lines, 0 panics, 0 untriaged warnings** (236 expected-error lines and 6 warnings triaged).

Triage table (every matched pattern, with its explanation):

| level | pattern | occurrences | triage |
|---|---|---|---|
| ERROR | all notes failed to be executed | 234 | the ntx-builder attempting a deliberately-unconsumable routed allowlisted note — the rows-A/B second domain_init (init-once) and the rows-C6 non-authorized-sender admin notes; the on-chain MASM gate rejecting them NODE-SIDE is the negative's evidence (doomed notes are retried with backoff, so the line recurs). A failing POSITIVE cannot hide here: every positive commit is guarded by its row's bounded committed-effect poll |
| ERROR | Network transactions may not be submitted by users yet | 1 | the Row-H F7 RIV deliberately SUBMITS the faucet's consume of a never-committed burn note via user RPC and records the node's rejection as evidence that a committed same-block create+consume is unreachable on this stack; the sequencer logs that deliberate rejection here |
| ERROR | Graceful shutdown timed out; exiting process | 1 | teardown: the harness SIGTERMs the four services in reverse start order and a service exceeding the grace window logs this while exiting — shutdown lifecycle, not attributable to any transaction |
| WARN | RPC connection failed while opening block subscription, retrying | 5 | startup ordering: the ntx-builder starts before the sequencer RPC listens and retries its block subscription with backoff until the sequencer is up |
| WARN | block subscription failed, reconnecting | 1 | teardown ordering: the sequencer stops first (reverse start order), dropping the ntx-builder's block subscription |

## Deliverables of this run

1. THIS record (generated; per-row PASS/FAIL + ids/blocks + triage).
2. `LNV5-F7-EVIDENCE-PACKET.md` — the Circle/DEV-7 same-block-erasure evidence (no acceptability decision).
3. `LNV5-NTX-LIVENESS-VERDICT.md` — the row-K verdict + deployment posture.
4. `LNV5-BURN-GETNOTESBYID-CAPTURE.hex` — the byte-exact `GetNotesById` burn capture (examples repo / Njord input).
5. `/home/agent/work/usdcx-cleanup/miden-usdcx/local-node-data/lnv5/run-1783774851/evidence-lnv5.json` — the machine-readable evidence (full observations, verdicts, log manifest) + the archived logs under the same run root.
