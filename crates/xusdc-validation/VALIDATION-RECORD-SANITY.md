# xUSDC Faucet — v16 E2E Sanity Validation Record

The pre-deploy confidence gate: a cohesive run driving the xUSDC faucet's core on-chain functionality against a real Miden node, with fund-correctness (the P0 scale-0 identity, mint/burn amounts + destinations, replay, supply-cap, attestation gates) proven end-to-end, plus DC-8 burn-evidence readiness and a clean-node-log gate. The DESTRUCTIVE admin surface runs ONLY on a fresh LOCAL faucet we own — NEVER against a deployed faucet. **Validator-not-fixer:** a failing check is a SURFACED finding that BLOCKS the deploy, never a faucet hot-fix.

- Node: **miden-node 0.16.0-alpha.2 (v16 start-test-node.sh cached binaries)** — RPC `http://127.0.0.1:57291`.
- Faucet under test: `0x22c015510392b09170dc544bce3549` (a FRESH production faucet deployed on the running LOCAL node — the FULL suite incl. the destructive admin surface, against a faucet we own and throw away with the test node).
- Owner `0xc6004a53d10b7391027185188db6d2`; mint recipient `0xfa03e7698062e411671a871cf773db`; burn holder `0xc35e42311c36f0917ec2fb9c0a07b5`.
- Local test attester commitment `0x0cbce74e398d0ff87f5b3a512f90f790961171eee23e1c7dbff475db18038825` (a throwaway key the harness generated + allowlisted — NEVER a Circle key).

## Mandated amounts + the scale-0 identity (P0 regression)

The shipped faucet mints under `DEPOSIT_SCALE_EXP = 0` — the reducer does NO 10^6 division, so minted units EQUAL the raw 6-decimal deposit amount. Proven with a round amount and a NON-round amount so any residual rescale is caught:

| flow | deposit amount (6-dec smallest units) | expected minted units |
|---|---|---|
| mint (round) | 100000000 (100 xUSDC) | 100000000 |
| mint (non-round) | 123456789 | 123456789 |
| burn | 50000000 (50 xUSDC) | supply −50000000 |

## Result — 41/41 checks passed

| id | area | assertion | verdict | evidence |
|---|---|---|---|---|
| MINT-ROUND | mint | 100 xUSDC (round): token_supply rises by EXACTLY the deposit amount (scale-0 identity) | PASS | supply 0 → 100000000 (Δ 100000000, expected 100000000) |
| MINT-ROUND-NONCE | mint | 100 xUSDC (round): usedNonces[nonce] marker written | PASS | marker [1, 0, 0, 0] |
| MINT-ROUND-DEST | mint | 100 xUSDC (round): recipient receives a P2ID of EXACTLY 100000000 units | PASS | recipient 0xfa03e7698062e411671a871cf773db ← 100000000 units |
| MINT-NONROUND | mint | 123.456789 xUSDC (P0 regression): token_supply rises by EXACTLY the deposit amount (scale-0 identity) | PASS | supply 100000000 → 223456789 (Δ 123456789, expected 123456789) |
| MINT-NONROUND-NONCE | mint | 123.456789 xUSDC (P0 regression): usedNonces[nonce] marker written | PASS | marker [1, 0, 0, 0] |
| MINT-NONROUND-DEST | mint | 123.456789 xUSDC (P0 regression): recipient receives a P2ID of EXACTLY 123456789 units | PASS | recipient 0xfa03e7698062e411671a871cf773db ← 123456789 units |
| NEG-WRONG-ATTESTER | attestation | a mint by a non-allowlisted attester is REJECTED | PASS | REJECTED with the 'deposit attester pubkey commitment is not allowlisted' gate (err_code: 3646155793185588349) |
| NEG-FORGED-SIG | attestation | a mint with a forged signature is REJECTED | PASS | REJECTED with the 'deposit attestation signature verification failed' gate (err_code: 15407036517211357943) |
| NEG-REPLAY | fund-safety | a replayed nonce is REJECTED (no double-mint) | PASS | REJECTED with the 'deposit intent nonce has already been used' gate (err_code: 13740426797483372479) |
| NEG-OVER-CAP | fund-safety | a mint exceeding the faucet's CURRENT cap (1000000000000, supply 223456789) is REJECTED | PASS | REJECTED with the 'mint amount exceeds the faucet supply cap' gate (err_code: 6332190719720770534) |
| NEG-NO-SUPPLY-MOVE | fund-safety | no rejected mint moved token_supply | PASS | supply 223456789 → 223456789 (unchanged) |
| BURN-FUND | burn | the holder holds the minted xUSDC before burning | PASS | holder balance 50000000 (need ≥ 50000000) |
| BURN-AMOUNT | burn | token_supply decrements by EXACTLY the burned amount | PASS | supply 273456789 → 223456789 (Δ -50000000 expected) |
| BURN-STRUCT | burn | the burn note is a correct public XReserveBurnNote | PASS | tag 0x4255524E, one NetworkAccountTarget → faucet, amount=50000000 destDomain=3 (DC-7 decoded) |
| BURN-ATTESTER | burn | the burn note is discoverable + decodable by the withdrawal attester | PASS | attester validate_discovery ACCEPTED (depositor 0xc35e42311c36f0917ec2fb9c0a07b5, amount 50000000); decode_burn_payload OK |
| BURN-DISCOVER | burn | the committed burn note is discoverable by exact-tag SyncNotes on the node | PASS | SyncNotes(tag 0x4255524E) returned note 0x962ec34a43b75fa951313593a2e1d24996383fe3adec0d0cfac016688a396f5e |
| BURN-EVIDENCE | burn | the DC-8 evidence packet (note_id/nullifier/block_num/burnTxId) assembles via the attester's assemble_evidence | PASS | DC-8 packet assembled: note_id=0x962ec34a43b75fa951313593a2e1d24996383fe3adec0d0cfac016688a396f5e, nullifier=0x4899693d8328bce22c43c75529ce1334dca4fd0eceb7fc7bb96420fa4c639674, block_num=94, burnTxId=0x25212ba928ee73900594656e6e0d55c9a195e83329d950afb634e3d3532c70e8 |
| ADMIN-PAUSE | admin | pause sets is_paused | PASS | is_paused = true |
| ADMIN-PAUSE-MINT | admin | a mint while paused is REJECTED | PASS | REJECTED with the 'the contract is paused' gate (err_code: 13643929038179635348) |
| ADMIN-PAUSE-BURN | admin | a burn while paused is REJECTED | PASS | REJECTED with the 'the contract is paused' gate (err_code: 13643929038179635348) |
| ADMIN-UNPAUSE | admin | unpause clears is_paused | PASS | is_paused = false |
| ADMIN-UNPAUSE-MINT | mint | mint after unpause: token_supply rises by EXACTLY the deposit amount (scale-0 identity) | PASS | supply 223456789 → 323456789 (Δ 100000000, expected 100000000) |
| ADMIN-UNPAUSE-MINT-NONCE | mint | mint after unpause: usedNonces[nonce] marker written | PASS | marker [1, 0, 0, 0] |
| ADMIN-UNPAUSE-MINT-DEST | mint | mint after unpause: recipient receives a P2ID of EXACTLY 100000000 units | PASS | recipient 0xfa03e7698062e411671a871cf773db ← 100000000 units |
| ADMIN-ATTESTER-DISABLE | admin | set_attester(enabled=0) removes the attester from the allowlist | PASS | attester allowlist marker cleared |
| ADMIN-ATTESTER-ROTATED-OUT | admin | a mint by the rotated-out (disabled) attester is REJECTED | PASS | REJECTED with the 'deposit attester pubkey commitment is not allowlisted' gate (err_code: 3646155793185588349) |
| ADMIN-ATTESTER-REENABLE | admin | set_attester(enabled=1) re-adds the attester to the allowlist | PASS | attester allowlist marker set again |
| ADMIN-MINBURN-RAISE | admin | set_min_burn_size raises the minimum (read back) | PASS | min_burn_size = 50000001 |
| ADMIN-MINBURN-REJECT | admin | a burn below the raised minimum is REJECTED | PASS | REJECTED with the 'burn amount is below the minimum burn size' gate (err_code: 2620300556345216793) |
| ADMIN-MINBURN-LOWER | admin | set_min_burn_size lowers the minimum (read back) | PASS | min_burn_size = 1 |
| ADMIN-BURN-OK-FUND | burn | the holder holds the minted xUSDC before burning | PASS | holder balance 50000000 (need ≥ 50000000) |
| ADMIN-BURN-OK-AMOUNT | burn | token_supply decrements by EXACTLY the burned amount | PASS | supply 373456789 → 323456789 (Δ -50000000 expected) |
| ADMIN-MAXSUPPLY-RAISE | admin | set_max_supply mutates + reads back the cap | PASS | max_supply = 3000000000000 |
| ADMIN-MAXSUPPLY-ENFORCE | admin | a mint exceeding the MUTATED (tightened) max_supply is REJECTED | PASS | REJECTED with the 'mint amount exceeds the faucet supply cap' gate (err_code: 6332190719720770534) |
| ADMIN-MAXSUPPLY-BELOW-SUPPLY | admin | set_max_supply BELOW the current token_supply is REJECTED (the mutability guard) | PASS | REJECTED with the 'new max supply is less than current token supply' gate (err_code: 12945332764232818723) |
| ADMIN-OWNER-GATE | admin | a non-owner admin note is REJECTED | PASS | REJECTED with the 'note sender is not the owner' gate (err_code: 7385238526269899403) |
| ADMIN-OWNER-TRANSFER | admin | transfer_ownership (step 1) commits | PASS | pending owner ← 0xb082dba0f816701161fcae85ee0993 |
| ADMIN-OWNER-ACCEPT | admin | accept_ownership (step 2) completes the 2-step transfer | PASS | owner ← 0xb082dba0f816701161fcae85ee0993 |
| ADMIN-OWNER-RESTORE | admin | ownership restored to the ORIGINAL owner (the ephemeral wallet retains no control) | PASS | owner = 0xc6004a53d10b7391027185188db6d2; the ephemeral wallet retains no control [transfer-back from the ephemeral wallet: committed] |
| ADMIN-POLICY-RESTORE | admin | faucet policy restored to the pre-run deployment values (unpaused, attester allowlisted, min/max) | PASS | min_burn_size ← 0; max_supply ← 1000000000000 |
| NODE-LOGS-CLEAN | logs | the node's four v16 service logs are present, non-empty, and free of unexpected ERROR / panic / untriaged-WARN lines | PASS | all 4 required service logs present + non-empty; 0 unexpected ERROR, 0 panic, 0 untriaged WARN (5 triaged-WARN lines) |

**GATE VERDICT: PENDING HUMAN ACCEPTANCE.** Every check passed its assertion on this run. Per the charter the PASS is a HUMAN decision: a human reproduces from a fresh node, inspects this record + the node logs, and declares the gate outcome (and only then does the deploy proceed).

## Coverage

- Mint (deposit direction): scale-0 identity round + non-round, correct recipient, supply rise, nonce marker.
- Burn (withdrawal direction): supply decrement, correct public `XReserveBurnNote` (tag `0x4255_524E`, one `NetworkAccountTarget` → faucet, DC-7 payload), attester-consumable via the withdrawal attester's own `validate_discovery` / `decode_burn_payload`, and DC-8 evidence (`note_id`/`nullifier`/`block_num`/`burnTxId`) assembled by the attester's own `assemble_evidence` over a LIVE `BurnEvidenceReads` adapter.
- Attestation + fund-safety negatives: wrong-attester, forged signature, replayed nonce, over-cap — each rejected client-side, none moved supply.
- Admin (FRESH local faucet ONLY): pause (mint+burn rejected) → unpause (mint AND burn work), attester rotation (disabled attester's mint rejected + re-enabled), `set_min_burn_size` (below-min rejected, at/above-min accepted), `set_max_supply` (mutate + read back + tightened-cap ENFORCED on a mint + below-current-supply guard), owner-gating, `transfer_ownership` + `accept_ownership`, then a best-effort restore. This DESTRUCTIVE surface runs ONLY here — against a faucet we own and throw away.
- Node logs (local runs): the run's four service logs scanned for unexpected ERROR/panic/untriaged-WARN lines (the clean-log gate).

## Reproduction

**This record** was produced by the FRESH-deploy LOCAL full gate (deploys the production faucet on the loopback node, then drives the WHOLE matrix incl. the destructive admin surface) against `http://127.0.0.1:57291` (node miden-node 0.16.0-alpha.2 (v16 start-test-node.sh cached binaries)). Reproduce it with:

```bash
# in the v16 client repo: ./scripts/start-test-node.sh --background   (RPC http://127.0.0.1:57291)
cargo run --release --locked -p xusdc-validation --bin sanity_e2e -- --rpc-url http://127.0.0.1:57291
```

For reference, the two modes (there is NO destructive-admin path against a deployed faucet):

- **LOCAL full gate** — a fresh deploy on the loopback node; the ONLY mode that runs the destructive admin surface, against a throwaway faucet:

```bash
# in the v16 client repo: ./scripts/start-test-node.sh --background   (RPC 127.0.0.1:57291)
cargo run --release --locked -p xusdc-validation --bin sanity_e2e -- --rpc-url http://127.0.0.1:57291
```

- **DEVNET (or local existing-faucet) non-destructive re-check** — targets an ALREADY-deployed faucet and NEVER mutates it; the allowlisted attester secret is read from a FILE / env, never argv:

```bash
SANITY_ATTESTER_SECRET=$(cat allowlisted-attester.hex) \
cargo run --release --locked -p xusdc-validation --bin sanity_e2e -- \
    --rpc-url https://rpc.devnet.miden.io --faucet-id <DEPLOYED_FAUCET_ID>
```
