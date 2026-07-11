# LNV-4 Validation Record — matrix rows G (burn two-block) + H (F7 same-block RIV) + I (burn negatives) + J (conservation)

Real-node validation of the PRODUCTION `XReserveBurnNote` lifecycle against a fresh local
`miden-node v0.15.1` stack. Extends the LNV-1 harness (`crates/xusdc-validation`); reuses the
LNV-1/2/3 toolchain, node topology, and path-N execution model (see `VALIDATION-RECORD.md`,
`VALIDATION-RECORD-LNV2.md`, `VALIDATION-RECORD-LNV3.md`). **Validator-not-fixer:** a defect surfaces
as a failing row, never a faucet hot-fix. No production MASM/Rust was changed.

**Row H is a Circle/DEV-7 EVIDENCE packet — it records what survives a same-block burn against the
PRODUCTION note; it makes NO acceptability decision and does NOT resolve DEV-7 (which stays OPEN).**

Authoritative spec: `TASK-P5-01-PHASE4-LOCAL-NODE-VALIDATION-PLAN-BUILDER.md`, rows **G/H/I/J** + the
F7 grounding (`xreserve_burn.rs` same-block erasure; the MockChain analog is STOCK-`BurnNote`
canary-only — this is the first RIV against the PRODUCTION `XReserveBurnNote`).

## Result: **GATE ROWS G + H + I + J PASS** (pending human acceptance)

```
LNV-4 rows G/H/I/J — run root: local-node-data/lnv1/run-1783711863
faucet:   0xbb405fd9fe431bd1135a292de098cb   (network account, PUBLIC)
holder:   0x0a8770f581c324b114fb42884cddc9   (keyed BasicWallet, the burner)
  G burn two-block (Circle read-path): PASS
  H burn same-block (F7 RIV evidence): PASS
  I burn negatives:                    PASS
  J conservation ledger:               PASS
LNV-4 rows G/H/I/J: ALL ROWS PASS
```

Full machine evidence: `<run_root>/evidence-gj.json` (gitignored; excerpts below). Run: 2026-07-10.
The arc is deterministic — state transitions and reject reasons below are identical across runs
(faucet/holder ids are seeded fresh per run). The byte-exact `GetNotesById` capture deliverable (note
+ inclusion proof) is committed at `crates/xusdc-validation/LNV4-BURN-GETNOTESBYID-CAPTURE.hex`.

> **Round-2 revision (auditor REVISE → addressed):** two MAJOR findings fixed. (1) Row H was an
> unsubmitted client-side execute; it now performs a REAL-NODE round-trip — it SUBMITS the faucet's
> consume via user RPC and records the node's rejection (`SubmitProvenTx → InvalidArgument: "Network
> transactions may not be submitted by users yet"`), proving a COMMITTED same-block create+consume is
> unreachable on this network-account stack — and asserts the executed supply delta EQUALS the burned
> amount (the supply-delta behavior), not merely that a never-committed note is absent. (2) The
> `GetNotesById` deliverable now captures the FULL response envelope (note bytes AND
> `NoteInclusionProof` bytes), not the note bytes + block number alone. Five new assertion negatives
> pin these (RED 35 passed/5 failed → GREEN 40 passed/0 failed). Re-validated on a fresh real node.

## Pins (unchanged from LNV-1/2/3)

- `miden-node` **v0.15.1** installed binaries (`/usr/local/bin`), four-service loopback stack
  (validator 57292 + ntx-builder 57293 + sequencer RPC 57291 + remote tx-prover 57294), isolated
  local genesis (`miden-validator bootstrap`, never `--network`).
- `miden-client` **=0.15.3** (crates.io); protocol family git rev `681fc905…` (= v0.15.3 tag).
- Built on `main` @ `30ca0bf` (LNV-3 rows D/E merge) — branch `feat/phase4-local-node-validation`.

## Execution model (LNV-2/3 posture, reused + burn extensions)

- **The committed mint (to the holder) and the Row-G two-block burn commit via path N (the
  ntx-builder).** The Row-G burn note is emitted from the HOLDER wallet (a regular-account tx the user
  RPC accepts) carrying the burned xUSDC + the `NetworkAccountTarget(faucet)` routing attachment; the
  running ntx-builder auto-executes the faucet's consumption. **Network notes are identified by the
  routing ATTACHMENT, not the tag** (`miden-standards` `network_note::is_network_note`: public +
  decodable `NetworkAccountTarget`), so the fixed `0x4255524E` burn tag does not impede routing — the
  ntx-builder log confirms `executing network transaction … num_notes=1 … num_failed=0` for the burn
  note. This also discharges the F5-deferred **ntx-builder liveness (row K) for the BURN path**.
- **The Row-I negatives run CLIENT-SIDE** (`execute_transaction`, no submission). A trap is the
  reject proof; because nothing is submitted, committed `token_supply` cannot move — read back
  before/after to prove zero state change.
- **The Row-H F7 RIV both executes CLIENT-SIDE and SUBMITS to the node.** The client-side execute
  records what a same-block/never-committed consume would apply (accepted; supply delta == amount);
  the user-RPC submit of the faucet consume is REJECTED by the node — the real-node round-trip
  proving a committed same-block create+consume is unreachable here (the stock client cannot present
  the `x-miden-network-tx-auth` header, and the ntx-builder consumes only COMMITTED notes → always
  strictly-later-block).

## Row G — burn two-block (the Circle read-path proof)

| field | value |
|---|---|
| burned amount | 100 (units) |
| `token_supply` | 100 → **0** (−100) |
| holder vault balance | 100 → **0** (custody-traced: burned into the note) |
| burn note tag | `1112887886` = **`0x4255524E`** (fixed xUSDC burn tag ✓) |
| note id | `0x71978f89d4a52f11f9451d9f9582dfe359a7adddc473e892bdd1f1ebd13d54dc` |
| note single asset | 100, issued by THIS faucet ✓ |
| committed-before-consume | **true** (`GetNotesById` returned it at block N) |
| discovered by `SyncNotes` (tag `0x4255524E`) | **true** (the Circle discovery path) |
| note commit block N → consume block N+1 | **345 → 346** (strictly two-block ✓) |
| found-after-consume (`GetNotesById`) | **true** — the committed note PERSISTS post-consume |
| nullifier recorded after consume | **true** (a real, non-replayable committed spend) |
| `GetNotesById` inclusion-proof block | 345 (== commit block ✓) |

The two-block Circle read-path is proven on a real node: the production `XReserveBurnNote` is a real
committed public note (block N), tag-discoverable via `SyncNotes`, and STILL retrievable via
`GetNotesById` (full note + inclusion proof) AFTER the faucet consumes it — the durable burn-event
observability Circle's withdrawal attester relies on (contrast the MockChain C1 caveat: the
persistence there was a non-pruning TODO artifact; on the real node it is genuine). The faucet's
`token_supply` fell by exactly the burned amount and the nullifier is recorded — the burn is real,
committed, and non-replayable. **Byte-exact `GetNotesById` capture** — the FULL response envelope:
the 346-byte `Note` AND the 15-byte `NoteInclusionProof` (`59010000000010ffff000000000000`, decoding
to inclusion block 345) — committed at `LNV4-BURN-GETNOTESBYID-CAPTURE.hex` (the examples-repo /
Njord deliverable; the proof half is what the withdrawal attester needs to verify on-chain inclusion).

## Row H — F7 same-block-erasure RIV (Circle/DEV-7 EVIDENCE PACKET — no acceptability decision)

The RIV question: can the production `XReserveBurnNote` be created + consumed within one block so its
burn event is erased (starving Circle discovery) while the supply delta still applies? The real-node
answer is captured in three parts against the PRODUCTION note (the MockChain canary
`c2_same_block_erasure_unauthenticated_consume` was STOCK-`BurnNote` only):

| # | what was probed | observed |
|---|---|---|
| 1 | client-side unauthenticated consume | **ACCEPTED** — the production burn note is a VALID burn |
| 1 | executed-tx supply delta | **−100** = exactly the burned amount (the supply-delta behavior) |
| 2 | **SUBMIT the faucet consume via user RPC** (real-node round-trip) | **REJECTED** by the node: `SubmitProvenTx → InvalidArgument: "Network transactions may not be submitted by users yet"` |
| 3 | on-chain `token_supply` | 100 → **100** (UNCHANGED — nothing committed) |
| 3 | committed note (`GetNotesById`) | **NOT FOUND** — the note never committed |
| 3 | on-chain nullifier | **NOT RECORDED** |
| 3 | `SyncNotes` (tag `0x4255524E`) discovery | **DOES NOT DISCOVER IT** |

(burn note tag `0x4255524E`, note id `0xa76f168485f727b301073db3f931bec9461ec0576b04c88f2b9ed73ff36ba0e2`.)

**The real-node finding (the DEV-7 evidence, no acceptability judgment):**
- **A COMMITTED same-block create+consume of the production burn note is UNREACHABLE on this v0.15.1
  stack.** The faucet is a network account: post-deploy the node REJECTS a user-submitted consume
  (row H's submit round-trip captures exactly this rejection); the stock `miden-client` cannot present
  the `x-miden-network-tx-auth` header (only `authorization: Bearer`); and the ntx-builder — the only
  commit path — subscribes to COMMITTED blocks, so the burn note is ALWAYS committed + discoverable
  before it is consumed (Row G's strictly-later-block 345 → 346). So the same-block-erasure risk does
  **not materialize** through any available path — the production burn is a two-block, discoverable
  event in practice.
- **What WOULD survive an unauthenticated/never-committed consume** (the discovery-starvation the RIV
  is about): the burn is valid and applies a supply delta of exactly the burned amount, but leaves
  **NO committed note and NO on-chain nullifier** — Circle's `SyncNotes` / `GetNotesById` discovery is
  **STARVED**. This is the client-side evidence (the account-state delta is `−100` while the note is
  absent from the note tree), the production-note analog of the MockChain canary.

**This is the evidence packet for Circle; it does NOT decide whether same-block erasure is acceptable
for the withdrawal flow — DEV-7 stays OPEN.** (A Circle-facing mitigation, e.g. mandating the
two-block read-path of Row G, is a Circle/DEV-7 decision, not this gate's.) Raw responses + the full
node rejection captured verbatim in `evidence-gj.json` (`observations.h`).

## Row I — burn negatives (each REJECTED + zero state change)

Committed `token_supply` = **100** throughout; each negative left it unchanged. All three built with
public APIs; no faucet gate re-implemented.

| negative | gate (single source of truth) | verdict | supply |
|---|---|---|---|
| below-min (burn 5 < `min_burn_size` 10) | `burn_policy::check_policy` R-BURN-2 `ERR_XRESERVE_BURN_BELOW_MIN` ("burn amount is below the minimum burn size") | REJECTED | 100 → 100 |
| while-paused (burn 50 while paused) | stock `pausable::assert_not_paused` `ERR_PAUSABLE_IS_PAUSED` ("the contract is paused"; code-only trap) | REJECTED | 100 → 100 |
| wrong-asset (asset issued by a different faucet) | stock kernel `fungible_asset::validate_origin` `ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN` ("the origin of the fungible asset is not this faucet"; code-only trap) | REJECTED | 100 → 100 |

Negative construction:
- **below-min** — `min_burn_size` was raised to 10 via a real `set_min_burn_size` admin note (path N);
  a burn of 5 traps at the xreserve-owned R-BURN-2 policy (which carries the message).
- **while-paused** — the faucet was paused via a real DOM_PAUSER `pause` note (path N); a valid burn
  (50 ≥ min) traps at the stock pause gate BEFORE the burn policy runs, then the faucet was unpaused
  (path N) so Row G ran against an unpaused faucet.
- **wrong-asset** — the harness `burn_note_wrong_asset` builds the production burn transport (reused
  stock `BurnNote` consume script, fixed burn tag, DC-7 items, `NetworkAccountTarget(faucet)` bind)
  with ONLY the vault asset's issuer swapped to a second (undeployed) faucet id, so
  `faucet::burn → validate_origin` traps (a faucet can only burn its OWN token). Coverage is keyed on
  the negative's LABEL (not the shared code-only trap shape), the LNV-3 audit lesson.

## Row J — conservation ledger

`token_supply == Σ(minted) − Σ(burned)` for this slice's mint→burn arc:

| quantity | value |
|---|---|
| Σ minted (committed) | 100 |
| Σ burned (committed) | 100 (the Row-G two-block burn) |
| final committed `token_supply` | **0** = 100 − 100 ✓ |
| holder final balance | **0** = 100 (received) − 100 (burned) ✓ |
| per-step supply reads | after-mint = 100 → after-two-block-burn = 0 |

The Row-H same-block RIV and the Row-I rejected negatives NEVER committed, so they contribute nothing
to the conserved ledger — conservation is over the COMMITTED mints and burns only. The final supply
and the holder's custody balance are both exactly Σminted − Σburned.

## Node lifecycle / logs

- Fresh isolated genesis; four services started + torn down within the run. Port 57291 free at exit
  (verified: no residual `miden-*` processes, no listener on 57291-57294).
- Node logs (`<run_root>/logs/*.log`, gitignored): validator / ntx-builder / tx-prover **0 ERROR**;
  sequencer **2 ERROR**, both EXPECTED + triaged:
  1. `rpc:submit_proven_tx: … "Network transactions may not be submitted by users yet" …
     account.id=0xbb40…` — the **INTENTIONAL Row-H submit-probe rejection** (the node correctly
     refusing the faucet's user-submitted network-account consume). This IS the Row-H evidence, not a
     defect: the RIV deliberately submits an un-committable tx to capture the constraint. Attributable
     to the Row-H probe by design.
  2. `Graceful shutdown timed out; exiting process` — teardown SIGTERM→SIGKILL, benign, not
     transaction-attributable (identical to the LNV-3 finding).
- ntx-builder **6 WARN** = startup `block subscription` RPC-retry transients (before the sequencer RPC
  bound), benign. No panic / unexpected tx-execution ERROR across the run.

## Test-first evidence (assertion layer, sandbox-safe default suite)

- `crates/xusdc-validation/tests/rows_gj.rs` — synthetic Row-G/H/I/J negatives written BEFORE the
  driver; each breaks exactly one surface its row-check exists to reject, plus a green-shape
  acceptance per row and an err_code-branch tripwire (a stock/kernel reject may surface code-only).
  Round 2 added five negatives pinning the revision: the Row-H supply-delta-equals-amount, the
  user-RPC submission rejected, the non-empty rejection error, and the Row-G inclusion-proof capture.
- Round-1 RED (stubbed assertions): **2 passed; 33 failed** → GREEN: **35 passed; 0 failed**.
  Round-2 RED (revision checks absent): **35 passed; 5 failed** → GREEN: **40 passed; 0 failed**
  (1 ignored — the real-node E2E). `ANNEAL_TEST_CMD = cargo test -p xusdc-validation --test rows_gj`.
- The real-node E2E (`lnv4_rows_gj_against_real_local_node`) is `#[ignore]`d (needs loopback binds);
  the §11.2 claim rides on the real run above + the human gate, never on the default suite.

## Scope

IN: rows G + H + I + J drivers/assertions + the F7 evidence packet + the byte-exact `GetNotesById`
capture (this record). OUT (later slices): the consolidated gate run + rows K/L + the final record
(LNV-5), any production-code fix, testnet, resolving DEV-7, Circle keys/endpoints. No new MASM; the
frozen note-script allowlist untouched; no push/merge.

## Status: **GATE ROWS G + H + I + J PASS — pending human acceptance** (HARD HUMAN GATE)

**HARD HUMAN GATE — the human accepts + reviews the evidence packets (esp. the F7/DEV-7 packet in Row
H) before merge. No push/merge.** DEV-7 remains OPEN: Row H is the evidence, not a decision.
