# LNV-3 Validation Record — matrix rows D (mint happy path) + E (mint negatives)

Real-node validation of the PRODUCTION `XReserveMintNote` lifecycle against a fresh local
`miden-node v0.15.1` stack. Extends the LNV-1 harness (`crates/xusdc-validation`); reuses the
LNV-1/2 toolchain, node topology, and path-N execution model (see `VALIDATION-RECORD.md` and
`VALIDATION-RECORD-LNV2.md`). **Validator-not-fixer:** a defect surfaces as a failing row, never a
faucet hot-fix. No production MASM/Rust was changed.

Authoritative spec: `TASK-P5-01-PHASE4-LOCAL-NODE-VALIDATION-PLAN-BUILDER.md`, rows **D** and **E**.

## Result: **GATE ROWS D + E PASS** (pending human acceptance)

```
LNV-3 rows D/E — run root: local-node-data/lnv1/run-1783690302
faucet:    0xde12d803ec542751307d390a4e2f58   (network account, PUBLIC)
recipient: 0x4225e7aaa2c3bd3132faf41d660691   (keyed BasicWallet)
  D mint happy path: PASS
  E mint negatives: PASS
LNV-3 rows D/E: ALL ROWS PASS
```

Full machine evidence: `<run_root>/evidence-de.json` (gitignored; excerpts below). Run: 2026-07-10.
The arc is deterministic — block progression, state transitions, and reject messages below are
identical across runs (faucet/recipient ids are seeded fresh per run).

> **Round-2 revision (auditor REVISE → addressed):** the Row-E coverage check now requires each of
> the five negatives by its canonical LABEL, not by its gate error. Previously `assert_e` checked only
> that *some* negative carried `ERR_XRESERVE_SIG_INVALID`, so either forged-signature or
> tampered-payload alone satisfied coverage for both — a driver could drop one silently. Coverage is
> now keyed on the label (the two signature-gate vectors are DISTINCT attack surfaces). Two new
> tests (`e_requires_the_forged_signature_negative` / `e_requires_the_tampered_payload_negative`)
> prove each is required independently. New D/E source is rustfmt-clean.

## Pins (unchanged from LNV-1/2)

- `miden-node` **v0.15.1** installed binaries (`/usr/local/bin`), four-service loopback stack
  (validator 57292 + ntx-builder 57293 + sequencer RPC 57291 + remote tx-prover 57294), isolated
  local genesis (`miden-validator bootstrap`, never `--network`).
- `miden-client` **=0.15.3** (crates.io); protocol family git rev `681fc905…` (= v0.15.3 tag).
- Built on `main` @ `2c9f67a` (P5-01 F2 merge) — this branch is `feat/phase4-local-node-validation`.

## Execution model (LNV-2 posture, reused)

- **Row D happy-path mints commit via path N (the ntx-builder).** Each `XReserveMintNote` is emitted
  from the owner/relayer wallet (a regular-account tx user RPC accepts) carrying the F5 routing
  attachment; the running ntx-builder auto-executes the faucet's consumption. The driver polls
  `GetAccount` for the committed effect, then the RECIPIENT wallet consumes the emitted P2ID note in
  a strictly-later block (the two-block flow).
- **Row E negatives run client-side (`execute_transaction`, no submission).** A trap is the reject
  proof; because nothing is submitted the committed `token_supply` / nonce registry cannot move —
  read back before/after to prove zero state change.

## Row D — mint happy path (both variants: committed via path N, recipient-consumed)

| variant | hookLen | amount | token_supply | usedNonces[nonce] | note serial == key | P2ID | tag | note asset | recipient bal | note blk → consume blk |
|---|---|---|---|---|---|---|---|---|---|---|
| empty-hookData | 0 | 100 | 0 → **100** | `[1,0,0,0]` | ✓ (matches) | ✓ | `0xd0000000` ✓ | 100 (this faucet) | 0 → **100** | 15 → **18** (2-block ✓) |
| hookData-bearing | 10 | 150 | 100 → **250** | `[1,0,0,0]` | ✓ (matches) | ✓ | `0xd0000000` ✓ | 150 (this faucet) | 100 → **250** | 22 → **25** (2-block ✓) |

- `feeAmount = 0` on both (production attachment hardcodes it; the F2 path is exercised by Row E).
- The emitted note serial equals `bytes32_to_key(nonce)` (the mint's `SERIAL_NUM`), verified against
  the nonce-derived key — the note is discovered by its ASSET AMOUNT, never by the serial, so the
  serial check is independent.
- `token_supply == Σ minted == 250`; recipient vault custody-traced 0 → 100 → 250 across the two
  variant consumes (block-provable inclusion proofs; the consume is always a strictly-later block).
- Both variants share ONE `domain_init` (`di-pos-empty-hookdata` and `di-pos-hookdata` carry the same
  `remoteDomain` 7 + `remoteToken`), so the hookData-bearing mint validates against the same domain
  config — the bounded-hookData variant the matrix requires.

## Row E — mint negatives (each REJECTED + zero state change)

Committed `token_supply` = **250** throughout; each negative left it unchanged. All five are
xreserve-OWNED gates and carried the message text on the client-side trap (confirming the LNV-2
posture: only STOCK miden-standards gates surface code-only).

| negative | gate error (observed verbatim) | observed err_code | verdict | supply | nonce marker |
|---|---|---|---|---|---|
| replayed-nonce | `deposit intent nonce has already been used` | 13740426797483372479 | REJECTED | 250 → 250 | `[1,0,0,0]` (already-used) |
| forged-signature | `deposit attestation signature verification failed` | 15407036517211357943 | REJECTED | 250 → 250 | `[0,0,0,0]` (unset) |
| non-allowlisted-attester | `deposit attester pubkey commitment is not allowlisted` | 3646155793185588349 | REJECTED | 250 → 250 | `[0,0,0,0]` (unset) |
| nonzero-fee (F2) | `mint fee amount must be zero` | 3143187394162941550 | REJECTED | 250 → 250 | `[0,0,0,0]` (unset) |
| tampered-payload | `deposit attestation signature verification failed` | 15407036517211357943 | REJECTED | 250 → 250 | `[0,0,0,0]` (unset) |

Negative construction (all built with public APIs; no faucet gate re-implemented):

- **replayed-nonce** — a fresh `XReserveMintNote` carrying the empty-hookData variant's
  ALREADY-COMMITTED nonce; D5c reads `usedNonces[key]` set → replay trap. Its marker stays `[1,0,0,0]`
  (the reject neither re-wrote nor double-minted).
- **forged-signature** — attester A's real pubkey (allowlist-valid, so gate 1 passes) with a
  WELL-FORMED ECDSA signature over the WRONG digest (`AttesterKey::attestation_over_digest`); D5d
  `verify_prehash` runs to completion and rejects → SIG_INVALID. (A byte-mangled sig could instead
  trap inside verify on a malformed scalar; a well-formed-but-wrong sig is deliberate.)
- **non-allowlisted-attester** — attester B (never allowlisted; only A is) signs self-consistently;
  D5d gate 1 (`pubkey_commitment` lookup) → BAD_PK_COMMITMENT.
- **nonzero-fee (F2)** — a valid A attestation, but the harness `mint_note_with_fee` injects a
  non-zero `feeAmount` into the scheme-1 attestation attachment (production hardcodes eight zero
  limbs — DEV-8 MVP). The limbs are derived from the trusted amount-field packing so the on-chain
  `uint256_to_asset_amount` reducer yields a non-zero reduced fee (5) → D5b F2 guard fires. The
  observed `mint fee amount must be zero` reject CONFIRMS the fee reached the guard non-zero.
- **tampered-payload (attachment↔commitment mismatch)** — A signs one payload; the note carries a
  DIFFERENT one (SAME nonce, INFLATED amount 40 → 80) the attestation never signed. The attachment
  hash-verifies (it commits to the note's real content), D5a/b/c pass, then D5d `verify_prehash` over
  `keccak256(note payload) ≠ signed digest` → SIG_INVALID. The distinct tamper surface from
  forged-signature that the same gate catches.

## Node lifecycle / logs

- Fresh isolated genesis; four services started + torn down within the run. Port 57291 free at exit
  (verified: no residual `miden-*` processes, no listener on 57291).
- Node logs (`<run_root>/logs/*.log`, gitignored): validator / ntx-builder / tx-prover **0 ERROR**;
  sequencer 1 ERROR = `Graceful shutdown timed out` (teardown SIGTERM→SIGKILL, benign, not
  attributable to any transaction). No panic / tx-execution ERROR across the run.

## Test-first evidence (assertion layer, sandbox-safe default suite)

- `crates/xusdc-validation/tests/rows_de.rs` — synthetic Row-D/E negatives written BEFORE the driver;
  each breaks exactly one surface its row-check exists to reject, plus green-shape acceptance and an
  err_code-branch tripwire.
- RED (stubbed assertions): `2 passed; 23 failed`. GREEN (real assertions): `25 passed; 0 failed`.
- The real-node E2E (`lnv3_rows_de_against_real_local_node`) is `#[ignore]`d (needs loopback binds);
  the §11.2 claim rides on the real run above + the human gate, never on the default suite.

## Scope

IN: rows D + E drivers/assertions (this record). OUT (later slices): burn rows G/H/I (LNV-4), the
consolidated conservation run + row K/L (LNV-5), any production-code fix. No new MASM; the frozen
note-script allowlist untouched; no Circle keys/endpoints; no push/merge.

## Status: **GATE ROWS D + E PASS — pending human acceptance** (HARD HUMAN GATE)
