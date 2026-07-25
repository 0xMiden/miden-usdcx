# CDR-1 — V16 CONFORMANCE RE-WALK (post-migration gate; RE-RUN off the cdrfix base)

**Role.** One row per load-bearing id from the conformance spine — the Phase-4
`PHASE4-COVERAGE-MATRIX.md` (48 `CIR-*` + the 33-entry Miden family, incl. the standalone
upstream-ledger rows U1/U2, with the DEFERRED GFE-1/2 group supplemental; see the §8 count
disclosure), the 23 Circle-owned `DEV-*`/`Q-*`,
the 22 `PHASE4-GLOBAL-INVARIANTS.md` `INV-*`, and every `IMPL-DEV-*` row of the Circle-facing
`IMPLEMENTATION-DEVIATION-REGISTER.md` — each re-judged against the **v0.16.0-alpha.2 migrated
tree** (this RE-RUN: branch `cdr/v16-verify` off `implementation` @ `076a720`, the cdrfix
merge). The id universe and row order follow `SWEEP-V3-COVERAGE.md` exactly (the proven
Phase-4.2 walk); what is re-judged here is not spec coverage but **whether the v16 migration
left each obligation discharged**.

**RE-RUN provenance.** The first walk (branch `cdr/v16` off `f979afd`, rounds 1-4) ended
**STOP on three rows** — CIR-FEE-2 (the unratified relayer-credit deferral) and
CIR-ADMIN-3 + CIR-STATE-7 (the S21 delegation-transition capability). Both root causes were
resolved by human decision + the `cdrfix` slice (PR #17 `73030ce`, merged @ `076a720`): the
runtime `set_role_admin` note was REMOVED from the allowlist (13 → 12 roots; ratification
artifact `DECISION-SETROLEADMIN-NOTE-REMOVAL.md`, human 2026-07-14, reversing the earlier S21
acceptance) and the CIR-FEE-2 fail-loud MVP deferral was RATIFIED (2026-07-14, pegged to the
new `Q-FEE-MVP`, not Q-MIN-2). This re-run independently reproduces the walk against the
actual `076a720` tree; every prior STOP row is re-derived below and now resolves to **HOLDS**
(§8). Non-vacuity of the removal-enforcement tests was re-demonstrated in this run: re-adding
the former note root to `allowed_note_scripts()` turns
`set_role_admin_is_unreachable_from_every_allowlisted_note` and
`set_role_admin_former_note_root_is_not_admissible_via_either_allowlist` RED (asserting the
exact 12-root S21-removal message), then reverted.

**Behavioural oracle.** The full v16 suite, green at this re-run's frozen-behaviour baseline:
`cargo test --locked -p xusdc-encoding --release` → **434 passed / 0 failed / 0 ignored**
(exit 0); `cargo test --locked -p xreserve-deposit-relayer --release` → **323 / 0 / 0**
(exit 0). (Counts grew from the first walk's 430/197 because PR #17 added the
removal-enforcement tests and the merged relayer slices R4/R5 added their suites.)
Every `test @ path:Lstart-Lend` cited below is a member of that green run (line spans from the
`cdr/v16-verify` working tree). MockChain sufficiency at alpha.2 is source-verified in
`docs/MIGRATION-V16-ALPHA2.md` §8.

**Verdict vocabulary.**
- **HOLDS** — the obligation is DISCHARGED at v16 by the cited evidence (a passing test, or an
  audit/SOP/record that genuinely discharges a non-test obligation), meaning unchanged.
- **CHANGED-RECONCILED** — the tests are green but the thing the id stood for MOVED at v16;
  the row carries a one-line Circle-conformance argument + cite, and appears on the
  NEEDS-HUMAN list (report §5).
- **PARKED** — the obligation is explicitly deferred, UNDISCHARGED, and never counted as
  HOLDS, with a recorded trigger. Exactly TWO recorded parking formulas are used, and every
  PARKED row names its formula:
  - **PARKED (RIV-inherited; §7a)** — the task text's named instance: the real-node (RIV/LNV)
    leg is inherited from the v15 LNV record; re-validation trigger: the v16-alpha
    `miden-client` (+node) ships.
  - **PARKED (unit-unbuilt; §7b)** — the obligation is owned by a later, unbuilt program unit
    (withdrawal listener, monitoring/ops SOPs, external audit, runbooks — none in this
    repository). CARRIED (Phase-4 spec assignment intact, `SWEEP-V3-COVERAGE.md` PRESENT);
    discharge trigger: that unit's own build gate. The v16 migration touched no surface of
    these units (their conformance debt is unchanged, not created, by the migration).
  VOCABULARY NOTE — **the §7b mapping is RATIFIED (human, 2026-07-14 round-2 gate),
  CONDITIONALLY**: the task mandates the four verdict values HOLDS / CHANGED-RECONCILED /
  PARKED / STOP and names the RIV case as PARKED's instance. The first issue of this packet
  invented two extra labels (NOT-YET-BUILT, PARTIAL) — an unauthorized contract extension.
  This re-issue maps them INTO the mandated vocabulary: later-unit rows are PARKED under
  formula §7b (still undischarged, still non-conformance), and each split-obligation row is
  broken into its legs on separate table lines (the CIR-FEE precedent), counted once under its
  WORST leg. The ratification's two conditions: (1) EVERY §7b row names its OWNING future unit
  + its re-validation trigger — satisfied this pass (each §7b verdict row's note cell names
  both, and the §7b ledger maps every id to its owner); (2) Round-F spot-checks a sample of
  §7b rows to confirm each is genuinely owned by an unbuilt unit and not a current-faucet gap
  mislabeled PARKED (any such row must be reclassified and surfaced).
- **STOP** — the obligation is NOT satisfied at v16 and no accurate, recorded human/Circle
  approval covers it. Two shapes appeared in the FIRST walk — a migration regression (the S21
  delegation-transition case, CIR-ADMIN-3/CIR-STATE-7) and a standing undischarged Circle MUST
  (CIR-FEE-2) — and both were resolved by ratified decisions + the cdrfix slice before this
  re-run. **This re-run has ZERO STOP rows** (§8); the vocabulary is kept because any future
  row failing its evidence would still halt the gate.

**Evidence forms** (exactly one per row): a passing `test @ path:Lstart-Lend`; the audit/SOP/
record that discharges a non-test obligation; one of the two PARKED formulas (§7a/§7b — the
carry record names the spec assignment); or, for a STOP row, the exact evidence of
non-satisfaction.
Rows whose obligation splits across a built repo leg and an unbuilt later-unit leg are broken
into TWO table lines (the CIR-FEE precedent): the repo leg HOLDS with its discharging test,
the unbuilt leg is PARKED (unit-unbuilt; §7b) — and the id is TALLIED ONCE, under its worst
leg (PARKED), never under HOLDS.

---

## §1 — Circle requirements (`CIR-*`), 48 rows

| Id | v16 evidence | Verdict | Note |
|---|---|---|---|
| CIR-DEPLOY-1 (faucet portion) | `build_produces_deny_active_public_faucet @ crates/xusdc-encoding/tests/builder_api.rs:120-161`; the composed account executes the full lifecycle (`assembled_faucet_full_lifecycle @ tests/assembled_faucet_e2e.rs:253-951`) | HOLDS | frontend portion stays DEFERRED (tracked, matrix §3) |
| CIR-DEPLOY-2 | `production_supply_raising_root_set_is_exactly_mint @ tests/mint_root_surface.rs:219-303` (S19-hardened: now ALSO root-level set-equality against the `@account_procedure`-filtered interface) + `deny_mint_and_send_traps @ tests/mint_deny.rs:134-160` + `reject_attestation_not_allowlisted_fails_closed @ tests/xreserve_mint.rs:384-409` | HOLDS | the `{mint}`-only supply surface survived S12/S13/S24's stock-root additions (none supply-raising — §6) |
| CIR-DEPLOY-3 | carried: `TASK-P4-MONITORING-ADMIN-OPS` assignment (SWEEP-V3 PRESENT); the external audit engagement does not exist yet — this CDR packet is a pre-audit input, not the audit | PARKED (unit-unbuilt; §7b) | undischarged until the third-party audit runs (pre-mainnet gate); owner: the external-audit engagement; trigger: the pre-mainnet third-party audit |
| CIR-DEPLOY-6 | `domain_init_reinit_traps @ tests/domain_config.rs:333-348` + `domain_init_reinit_leaves_all_fields_unchanged @ :354-398` + `domain_init_domain_over_u32_traps @ :711-721` | HOLDS | RCC Q-DOM-1 stays OPEN (placeholder domain values) |
| CIR-DEPLOY-8 | `aid_rt_extracts_account_id @ tests/mint_recipient_account_id.rs:90-109` + the R-B layout regression pin `src/xreserve/encoding/account_id.rs:179-185` | HOLDS | DEV-10 / S1-NDA L22 stays OPEN — layout provisional, unchanged at v16 |
| CIR-STATE-1 | `domain_init_writes_all_four_fields @ tests/domain_config.rs:272-324` + `domain_init_domain_at_u32_max_succeeds @ :506-525` | HOLDS | — |
| CIR-STATE-2 | vault model in force: `burn_note_insufficient_balance_rejects_create @ tests/xreserve_burn.rs:273-306` (balance lives in the vault, not a map) | HOLDS | RCC DEV-4 stays OPEN |
| CIR-STATE-3 | `d5c_replay_rejects @ tests/masm_mint_shell.rs:395-416` + `mint_note_replayed_nonce_rejects_no_writes @ tests/xreserve_mint_note.rs:353-412` | HOLDS | RCC DEV-9 stays OPEN |
| CIR-STATE-4 | `set_attester_enables_attestation @ tests/xreserve_mint.rs:828-904` + `d5d_non_allowlisted_rejects @ tests/masm_mint_shell.rs:597-613` + `tv_dual_5_pubkey_commitment @ tests/masm_dual.rs:421-470` | **CHANGED-RECONCILED** | the allowlist KEY derivation moved: `Poseidon2(33B compressed, 9 felts)` → `Poseidon2(affine qx‖qy, 16 felts)` (vm#3342, S16). Circle-conformance argument: the Circle-wire ingress (33-byte compressed key) and the allowlist SEMANTICS (commitment-keyed enable/disable) are byte-identical; only the internal preimage moved — operator-approved DC-2/DC-3 supersession, `docs/MIGRATION-V16-ALPHA2.md` §10 item 1 (2026-07-13) |
| CIR-STATE-5 | `set_min_burn_owner_succeeds @ tests/set_min_burn.rs:115-135` + `burn_below_min_rejects @ tests/burn_policy.rs:124-145` | HOLDS | — |
| CIR-STATE-6 (faucet supply-exposure leg) | the faucet exposes `token_supply` and MockChain reads it (`d5e_happy_conservation @ tests/mint_effects.rs:59-132`); real-node read PARKED (RIV-inherited, LNV rows D/J, §7a) | HOLDS (this leg) | the id is tallied once, under the worst leg (next line) |
| CIR-STATE-6 (monitoring leg — the Circle-facing `GetAccount` supply watch) | carried: monitoring assignment (SWEEP-V3 PRESENT) | PARKED (unit-unbuilt; §7b) | tallied here; owner: the monitoring unit (05); trigger: the monitoring unit's build gate |
| CIR-STATE-7 | ownership HOLDS (`owner_two_step_transfer_rotates_authority @ tests/ownable2step_admin.rs:74-141` + every owner-gated setter test); the owner's ROLE-administration authority no longer degrades ON-CHAIN at `076a720`: the CURRENT-`ADMIN`-member owner retains grant/revoke (`owner_can_still_grant_pauser @ tests/role_admin.rs:562-611`, `owner_can_still_revoke_pauser @ :613-658`), and the delegation configuration that authority is conditional on is IMMUTABLE post-deploy — the runtime `set_role_admin` note is removed (12-root allowlist, `production_faucet_note_allowlist_is_exactly_the_12_ratified_roots @ tests/f5_network_account_auth.rs:173-211`), the proc is unreachable from every allowlisted note (`set_role_admin_is_unreachable_from_every_allowlisted_note @ tests/account_callable_surface.rs:555-584`, MAST sweep resolved by path), the former root is not admissible via either allowlist (`set_role_admin_former_note_root_is_not_admissible_via_either_allowlist @ :590-610`), and the preserved former note is consumed-and-REJECTED with state unchanged (`set_role_admin_note_is_rejected_as_non_allowlisted @ tests/f5_admin_notes.rs:1382-1415`) | **HOLDS** (was STOP in the first walk) | the prior STOP's failure mode — a mutable delegation anchor reaching ADMIN-excluded states (owner self-lockout, rogue-Manager re-delegation) — is structurally MOOTED by the ratified S21 flip (`DECISION-SETROLEADMIN-NOTE-REMOVAL.md`, human 2026-07-14; register IMPL-DEV-24): no on-chain sender can re-point any role's admin. Non-vacuity re-demonstrated this run (RED on a 13-root allowlist). SCOPE (the ratified S2 divergence, operator-approved 2026-07-13 — map §10 decision 2, row S2): the owner's RBAC anchor is its `ADMIN` MEMBERSHIP, which is ACCOUNT-BOUND — it does NOT auto-follow `transfer_ownership`/`accept_ownership`; the rotation runbook re-seats it (grant-new/revoke-old by an ADMIN member, `builder.rs` KNOWN DIVERGENCE doc). **HOLDS RATIFIED (human, 2026-07-14 round-2 gate) — rationale recorded verbatim: "behavior is correct, the S2 divergence is operator-approved, the seams are individually tested, and the composition is ORTHOGONAL STORAGE (owner slot vs role_config — independent). This does NOT block the implementation→main engineer PR."** The combined transfer→ADMIN-re-seat test is SCHEDULED as the named deferred slice `TASK-S2-ADMIN-RESEAT-TEST` (report §6 deferred-slice ledger; trigger: **must land BEFORE the internal MASM security audit**) |
| CIR-MINT-PRE-1 | `d5d_forged_sig_rejects @ tests/masm_mint_shell.rs:580-593` + `d5d_non_allowlisted_rejects @ :597-613` + `d5d_seam_both_arrangements_reject @ :622-639` + `reject_forged_signature_fails_closed @ tests/xreserve_mint.rs:475-508` | HOLDS | verify-then-allowlist mechanism unchanged; commitment preimage note under CIR-STATE-4 |
| CIR-MINT-PRE-2..7 | `r_mint_rejects @ tests/masm_mint_shell.rs:119-137` (parametrized over R-MINT-1..8) + `domain_init_then_wrong_domain_mint_rejects @ tests/domain_config.rs:906-949` + `domain_init_then_wrong_identifier_mint_rejects @ :955-995` | HOLDS | — |
| CIR-MINT-PRE-8/9 | `d5b_happy_amount_fee @ tests/masm_mint_shell.rs:213-241` + `d5b_amount_fee_rejects @ :250-276` + `reject_fee_over_max_fails_closed @ tests/xreserve_mint.rs:625-650` | HOLDS | MVP `feeAmount==0` gate subsumes PRE-9 (IMPL-DEV-21 — a RATIFIED deferral since 2026-07-14, pegged to the pending Q-FEE-MVP) |
| CIR-MINT-PRE-10 | `d5c_replay_rejects @ tests/masm_mint_shell.rs:395-416` + `d5c_unrelated_seeded_nonce_passes @ :421-465` | HOLDS | — |
| CIR-MINT-PRE-11 | `r_mint_rejects` (R-MINT-8 case) @ tests/masm_mint_shell.rs:119-137 + relayer `t_rly_11_preimage_felt_count @ crates/xreserve-deposit-relayer/tests/deposit_intent_validate.rs:250-270` | HOLDS | — |
| CIR-MINT-STATE-1..4 | MockChain: `happy_end_to_end_mints_once @ tests/xreserve_mint.rs:180-296` (nonce→note→supply order asserted); `mint_note_drives_attested_mint_end_to_end @ tests/xreserve_mint_note.rs:252-348` | HOLDS | real-node RIV leg PARKED (§7; LNV rows D/E) |
| CIR-MINT-POST-1 | `d5e_happy_conservation @ tests/mint_effects.rs:59-132` + `token_supply_raise_write_integrity_static_sweep @ tests/mint_deny.rs:313-378` | HOLDS | conservation RIV leg PARKED (§7; LNV row J) |
| CIR-MINT-POST-3 | carried: monitoring assignment (SWEEP-V3 PRESENT); DEV-3 OPEN | PARKED (unit-unbuilt; §7b) | event-reconstruction monitor unbuilt; v16 touched no monitoring surface (debt unchanged, not created); owner: the monitoring unit (05); trigger: the monitoring unit's build gate |
| CIR-BURN-PRE-1 | `burn_note_consumed_by_faucet_decrements @ tests/xreserve_burn.rs:225-268` + `recipient_burns_full_balance @ :317-355` | HOLDS | RCC DEV-2 stays OPEN |
| CIR-BURN-PRE-4 | `burn_note_insufficient_balance_rejects_create @ tests/xreserve_burn.rs:273-306` | HOLDS | — |
| CIR-BURN-PRE-2/3 | `burn_zero_amount_rejects @ tests/burn_policy.rs:214-235` + `burn_below_min_rejects @ :124-145` + `burn_paused_rejects @ :262-309` | HOLDS | — |
| CIR-BURN-STATE-1 | `only_receive_and_burn_lowers_supply @ tests/xreserve_receive_and_burn.rs:87-104` + `burn_consume_composition_decrements_once @ :269-298` | HOLDS | N1D re-verified on the re-vendored alpha.2 fixtures (`pinned_standards_single_faucet_burn_caller @ :140-152`, `pinned_standards_single_supply_decrement_write @ :160-172`) |
| CIR-BURN-POST-1 | `burn_note_is_public_with_fixed_tag @ tests/xreserve_burn.rs:96-120` + `burn_note_payload_schema @ :125-161` | HOLDS | RCC DEV-2 (tag placeholder, IMPL-DEV-7) |
| CIR-WITHDRAW-1/2/3 | carried: listener assignment (`SWEEP-V3-COVERAGE.md` PRESENT); the withdrawal listener is not built (not in this repository) | PARKED (unit-unbuilt; §7b) | v16 touched no listener surface (debt unchanged, not created); owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| CIR-WITHDRAW-4 | carried: listener assignment; RCC Q-CRY-2 OPEN | PARKED (unit-unbuilt; §7b) | off-chain `k256` signing service unbuilt; owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| CIR-ATTESTER-1 | `d5d_happy_attestation @ tests/masm_mint_shell.rs:548-573` + `d5d_forged_sig_rejects @ :580-593` | HOLDS | verify-vs-supplied-pubkey model unchanged; RCC DEV-1; S16 preimage note under CIR-STATE-4 |
| CIR-ATTESTER-2 | carried: listener assignment (two distinct signer sets) | PARKED (unit-unbuilt; §7b) | owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| CIR-ATTESTER-3/4 | carried: listener + ops assignment (≥2 burn attesters / quorum) | PARKED (unit-unbuilt; §7b) | owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| CIR-ATTESTER-5/6 (faucet rotation-mechanism leg) | `set_attester_add_then_retire_rotation @ tests/xreserve_mint.rs:977-1065` | HOLDS (this leg) | the id is tallied once, under the worst leg (next line) |
| CIR-ATTESTER-5/6 (ops leg — KMS/HSM custody SOPs + rotation drill) | carried: ops assignment | PARKED (unit-unbuilt; §7b) | tallied here; owner: the ops SOP/runbook program; trigger: the ops SOP/runbook slice |
| CIR-NONCE-1 | `d5c_replay_rejects @ tests/masm_mint_shell.rs:395-416` + `tv_dual_1_bytes32_to_key @ tests/masm_dual.rs:133-162` (the commitment keying) | HOLDS | RCC DEV-9 |
| CIR-FEE-1/3 (bounds; 6 dp) | `tv_dual_2_uint256_reducer @ tests/masm_dual.rs:167-246` (6-dp reduce) + `d5b_happy_amount_fee @ tests/masm_mint_shell.rs:213-241` / `d5b_amount_fee_rejects @ :250-276` (maxFee bounds) | HOLDS | matrix row CIR-FEE-1/2/3 split here so FEE-2 cannot ride the reducer's evidence |
| **CIR-FEE-2 (relayer credit — a Circle MUST)** | recorded, RATIFIED deferral: the fail-loud `feeAmount==0` reject IS the MVP contract (`reject_nonzero_fee_below_maxfee_fails_closed @ tests/xreserve_mint.rs:657-682`, `d5e_nonzero_fee_traps @ tests/mint_effects.rs:140-150` — rejection proven, never a silent accept); the relayer-credit split is a documented, Circle-gated deferral, priority P2, gated on **mainnet/production-final**. Deferral record: register IMPL-DEV-21 (RATIFIED DEFERRAL, human 2026-07-14) + repo `docs/spec/GLOSSARY.md` rows `F2`, `CIR-ADMIN`-table `CIR-FEE-2`, and the pending `Q-FEE-MVP` | **HOLDS (as a recorded deferral)** (was STOP in the first walk) | the first walk's STOP stands corrected by a human decision, not by code: the missing recorded ratification now EXISTS (2026-07-14). The prior Q-MIN-2 peg was a mischaracterization — canonical Q-MIN-2 covers only the zero-fee note *structure*; the reject decision is pegged to its OWN pending Circle confirmation, **Q-FEE-MVP**. The MUST itself remains deferred (not implemented) — that is the recorded, ratified position for the testnet MVP; the mainnet gate re-opens it |
| CIR-HOOK-1/2 | `happy_end_to_end_with_hookdata @ tests/xreserve_mint.rs:514-618` + relayer `t_rly_11_preimage_exactly_1024_felts_accepted @ crates/xreserve-deposit-relayer/tests/deposit_intent_validate.rs:272-299` / `t_rly_11_oversized_preimage_rejected @ :301-311` | HOLDS | RCC DEV-6 |
| CIR-HOOK-3 | no-keccak-fallback pinned: `src/xreserve/encoding/account_id.rs` fail-closed decode tests (`:124`,`:179-185`) | HOLDS | AccountId fits 32B losslessly; fallback not needed |
| CIR-ADMIN-1 | `set_attester_owner_succeeds @ tests/set_attester.rs:104-137` + `set_attester_former_admin_dom_pauser_non_owner_rejects @ :160-163` + `set_attester_dom_manager_non_owner_rejects @ :167-170` | HOLDS | RCC Q-ADMIN-1 (key type) |
| CIR-ADMIN-2 | `set_min_burn_owner_succeeds @ tests/set_min_burn.rs:115-135` + the three non-owner rejects `@ :137-156` | HOLDS | — |
| CIR-ADMIN-3 | BOTH halves verify at `076a720`. Manager-rotates-Pauser: `dom_manager_grants_pauser_then_new_pauser_halts_mint @ tests/role_admin.rs:222-269`, `dom_manager_revokes_pauser_then_pause_rejects @ :271-320` (capability-proven in real pause power). Owner backstop: the CURRENT-`ADMIN`-member owner retains grant/revoke (`owner_can_still_grant_pauser @ :562-611`, `owner_can_still_revoke_pauser @ :613-658`), and that backstop can no longer be stripped ON-CHAIN — the delegation-transition class that broke it (rogue-Manager `set_role_admin(DOM_PAUSER, DOM_PAUSER)` self-administration; owner self-lockout cycles) is unreachable on-chain: the runtime `set_role_admin` note is REMOVED (`rbac_set_role_admin_is_present_on_the_account @ tests/account_callable_surface.rs:531-553` pins the proc stays composed; `set_role_admin_is_unreachable_from_every_allowlisted_note @ :555-588` MAST-sweeps all 12 notes by path; `set_role_admin_former_note_root_is_not_admissible_via_either_allowlist @ :590-614`; `set_role_admin_note_is_rejected_as_non_allowlisted @ tests/f5_admin_notes.rs:1382-1415` + `set_role_admin_note_is_rejected_regardless_of_note_args @ :1421-1445` consume the preserved former note and prove REJECTED, state unchanged; fixture integrity `former_set_role_admin_note_script_still_compiles_to_the_former_root @ :1362-1376`) | **HOLDS** (was STOP in the first walk) | matches Circle MORE closely than the v15 shape: Circle's `DomainManageable.sol` has no admin-graph re-pointing function either — rotation is membership-only on both sides. Ratification: `DECISION-SETROLEADMIN-NOTE-REMOVAL.md` (human 2026-07-14, two adversarial conformance audits, NO REFUTATION); register IMPL-DEV-24; GLOSSARY CIR-ADMIN-3 + CMP-F5 rows updated. The `grant_role`/`revoke_role` rotation seam and the `DOM_PAUSER.admin_role = DOM_MANAGER` build seed are intact (`shipped_delegation_reads_back @ tests/role_admin.rs:506-560`). SCOPE: across an ownership transfer the backstop follows the ratified S2 runbook (ADMIN membership is account-bound — see CIR-STATE-7's scope note). **HOLDS RATIFIED (human, 2026-07-14 round-2 gate — same verbatim rationale as CIR-STATE-7: orthogonal storage, individually tested seams, operator-approved S2)**; the combined-seam test is the scheduled deferred slice `TASK-S2-ADMIN-RESEAT-TEST` (report §6; trigger: before the internal MASM security audit) |
| CIR-ADMIN-4 | `dom_pauser_pause_halts_mint @ tests/pause_admin.rs:253-272` + `dom_pauser_pause_halts_burn @ :362-404` + `is_paused_publicly_readable @ :694-722` | HOLDS | #2944 moved the `is_paused` slot into the base `Pausable` component the builder now installs — same slot NAME, all halt-gates read it (`production_components_carry_is_paused_slot @ tests/builder_api.rs:400-425`, load-bearing since #3047 made a missing slot a silent no-op); pause-event surface stays OPEN (row 23 of §3) |
| CIR-ADMIN-5 | the ACTUAL obligation (the joint-approval process SOP) is unbuilt; what exists is the design record that enforcement is deliberately off-chain (`pause_admin.masm:53-54`; IMPL-DEV-13) — a rationale, not the SOP | PARKED (unit-unbuilt; §7b) | ops deliverable; owner: the ops SOP/runbook program; trigger: the ops SOP/runbook slice |
| CIR-API-1..6 (deposit-side / relayer leg) | contract suites green — `tests/circle_fetch_contract.rs:35-450` (t_rly_01/02/05/06), `tests/circle_pagination_contract.rs:43-542` (t_rly_03/04), `tests/circle_auth_contract.rs:40-335` (t_rly_10), `tests/circle_status_policy_contract.rs:37-360` (t_rly_07/17/18) | HOLDS (this leg) | RCC Q-API-AUTH / Q-INFO-PARAM; the id is tallied once, under the worst leg (next line) |
| CIR-API-1..6 (withdrawal-side / listener leg, incl. `burnTxId`) | carried: listener assignment | PARKED (unit-unbuilt; §7b) | tallied here; owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| CIR-EVIDENCE-1 | DEV-7 OPEN (highest-risk); LNV row H evidence packet inherited from v15 (F7 same-block erasure) | PARKED | §7 ledger; later-unit (listener) consumes the decision |
| CIR-EVIDENCE-2 (supply-exposure leg) | as CIR-STATE-6's faucet leg (supply exposed + MockChain-read) | HOLDS (this leg) | RIV leg §7a; the id is tallied once, under the worst leg (next line) |
| CIR-EVIDENCE-2 (monitoring leg) | carried: monitoring assignment | PARKED (unit-unbuilt; §7b) | tallied here; owner: the monitoring unit (05); trigger: the monitoring unit's build gate |
| CIR-EVIDENCE-3 | `burn_note_payload_schema @ tests/xreserve_burn.rs:125-161` (amount/destDomain/destRecipient/salt in `NoteStorage.items`, depositor = `metadata.sender`) | HOLDS | RCC DEV-2; shape recorded as IMPL-DEV-8 |
| CIR-OPS-1/2/3 | carried: monitoring assignment (discrepancy thresholds) | PARKED (unit-unbuilt; §7b) | owner: the monitoring unit (05); trigger: the monitoring unit's build gate |
| CIR-OPS-4/5/6 | carried: ops assignment (SLA / rolling cap / 24×7; RCC Q-OPS-5) | PARKED (unit-unbuilt; §7b) | owner: the ops SOP/runbook program; trigger: the ops SOP/runbook slice |
| CIR-DEPLOY-4 | carried: ops assignment (upgrade-governance SOP/runbook) | PARKED (unit-unbuilt; §7b) | this CDR packet instantiates the "diff audit" half of the pattern for a dependency migration, but the standing runbook the requirement demands does not exist yet; owner: the ops SOP/runbook program; trigger: the ops SOP/runbook slice |
| CIR-DEPLOY-5 | carried: ops assignment (1-hour emergency-disclosure runbook) | PARKED (unit-unbuilt; §7b) | owner: the ops SOP/runbook program; trigger: the ops SOP/runbook slice |

## §2 — Miden capabilities / gaps (33 load-bearing, incl. the standalone U1/U2 ledger rows; the GFE-1/2 DEFERRED group supplemental), matrix §2 order

| Id | v16 evidence | Verdict | Note |
|---|---|---|---|
| MC-MINT-1 / GMS-3(G3) | `tv_dual_5_pubkey_commitment @ tests/masm_dual.rs:421-470` (MASM ≡ Rust ≡ crypto-0.28 `to_commitment`) + `d5d_non_allowlisted_rejects @ tests/masm_mint_shell.rs:597-613` + `invalid_pubkey_rejects @ src/xreserve/encoding/attestation.rs:199` (the new SEC1→affine seam fail-closes) | **CHANGED-RECONCILED** | the commitment allowlist's KEY format moved (S16, vm#3342). Argument: no-recover model intact; Circle-wire inputs byte-identical; only the 3 derived `att` vector fields regenerated via the committed generator — operator-approved supersession (map §10 item 1, 2026-07-13) |
| MC-MINT-2 / GMS-2(G2) | `tv_dual_3_parse_deposit_intent @ tests/masm_dual.rs:356-413` + `r_mint_rejects @ tests/masm_mint_shell.rs:119-137` + `tv_circle_differential_real_bytes @ tests/masm_dual.rs:628-795` | HOLDS | Circle-wire families (`di`) byte-identical at v16 (map §11 vector diff) |
| MC-MINT-3 / GMS-4(G4) | `tv_dual_2_uint256_reducer @ tests/masm_dual.rs:167-246` + `d5e_cap_boundary_accepts @ tests/mint_effects.rs:154-169` / `d5e_over_cap_rejects @ :198-214` | HOLDS | RCC DEV-5 |
| MC-MINT-4 / GMS-6(G6) | as CIR-STATE-3 | HOLDS | — |
| MC-MINT-5 / GMS-1(G1) | `happy_end_to_end_mints_once @ tests/xreserve_mint.rs:180-296` + `second_mint_to_distinct_recipient @ tests/assembled_faucet_e2e.rs:962-1100` | HOLDS | RIV leg PARKED (§7) |
| MC-MINT-6 / GOS-5(G12) | carried: monitoring assignment (reconstruction monitor; DEV-3) | PARKED (unit-unbuilt; §7b) | owner: the monitoring unit (05); trigger: the monitoring unit's build gate |
| MC-MINT-7 / GMS-10(G8) | `deny_mint_and_send_traps @ tests/mint_deny.rs:134-160` + `denied_path_no_supply_effect @ :168-211` + `production_build_still_denies_stock_mint @ tests/set_attester.rs:92-98` | HOLDS | S18 rewrote the manager CONSTRUCTION only; the deny-root registration is unchanged (`production_composition_installs_one_xreserve_and_one_manager @ tests/builder_api.rs:577-610`) |
| MC-BURN-1 / GMS-9(G7) | as CIR-BURN-PRE-2/3 + CIR-BURN-STATE-1 | HOLDS | — |
| MC-BURN-2 / GMS-12(G9) | `burn_note_is_public_with_fixed_tag @ tests/xreserve_burn.rs:96-120` + `burn_note_is_never_private @ :166-188` | HOLDS | RCC DEV-2 |
| MC-BURN-3 / GMS-11(G9) | `production_burn_note_same_block_consume_is_erased @ tests/xreserve_burn.rs:366-447` (the negative proof) | HOLDS | two-block discipline unchanged; LNV G/H legs §7 |
| MC-BURN-4 / GOS-2(G11) | carried: listener assignment (validate-then-sign; RCC Q-CRY-2) | PARKED (unit-unbuilt; §7b) | owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| MC-EV-1 / GUP-1(U1) | avoided via the DEV-7 default; U1 OPTIONAL-UPSTREAM carried | HOLDS | OPEN, unchanged |
| MC-EV-2 | carried: listener assignment (burn-evidence package) | PARKED (unit-unbuilt; §7b) | owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| MC-EV-3 / GOS-4(G13) | carried: monitoring assignment (supply monitor) | PARKED (unit-unbuilt; §7b) | owner: the monitoring unit (05); trigger: the monitoring unit's build gate |
| MC-EV-4 | as CIR-STATE-2 (vault model) | HOLDS | RCC DEV-4 |
| MC-EV-5 | tag pinned `burn_note_is_public_with_fixed_tag @ tests/xreserve_burn.rs:96-120`; exact-tag discovery is an LNV-G real-node behaviour | PARKED (discovery leg) | §7; MockChain tag identity HOLDS |
| MC-ADM-1..5 / GMS-7/8 | the F5 admin-note matrix `tests/f5_admin_notes.rs` (all 57 green: setters, pause, roles, ownership, per-note root pins — incl. the converted former-set_role_admin rejection tests) | **CHANGED-RECONCILED** | every non-role admin capability HOLDS unchanged; the role-administration leg CHANGED at v16 and is reconciled by ratified decision: the runtime `set_role_admin` capability was REMOVED (12-note admin surface, graph frozen at the seed — `DECISION-SETROLEADMIN-NOTE-REMOVAL.md`, human 2026-07-14, IMPL-DEV-24); rotation is `grant_role`/`revoke_role`, matching Circle's membership-only model |
| MC-CR-1..7 / GMS-4/5 | `tv_dual_1_bytes32_to_key @ tests/masm_dual.rs:133-162`, `tv_dual_2_uint256_reducer @ :167-246`, `tv_dual_3_parse_deposit_intent @ :356-413`, `tv_dual_5_pubkey_commitment @ :421-470` + the TV-* unit suites in `src/xreserve/encoding/*` | HOLDS | the pubkey packing leg re-typed to affine-16 per the ratified S16 (note under MC-MINT-1); keccak/ECDSA/bytes32/uint256/AccountId legs byte-identical |
| MC-INF-1/2/3 / GOS-1/2 (relayer leg) | BUILT + green in this repo (323/323 at this re-run's baseline) | HOLDS (this leg) | the id is tallied once, under the worst leg (next line) |
| MC-INF-1/2/3 / GOS-1/2 (listener + monitoring legs) | carried: listener/monitoring assignments | PARKED (unit-unbuilt; §7b) | tallied here; owner: the monitoring unit (05); trigger: the monitoring unit's build gate |
| MC-FEE-1 / GREQ-1(U2) | non-issue (xUSDC ≠ fee token); U2 CONDITIONAL-UPSTREAM carried | HOLDS | — |
| MC-FEE-2 | deliberately NOT wired — ratified basic-asset decision (IMPL-DEV-20, F4): `production_build_registers_no_transfer_policy @ tests/basic_asset_tripwire.rs:60-104` + `invoke_wrappers_are_inert_and_the_asset_stays_basic @ tests/account_callable_surface.rs:469-514` | HOLDS | the P2 blocklist row is superseded by the ratified F4 decision (2026-07-08); Q-PRV-5 OPEN |
| GMS-5(G5) | `tv_dual_1_bytes32_to_key @ tests/masm_dual.rs:133-162` | HOLDS | — |
| GMS-8(G7) setters | `set_attester_owner_succeeds_while_paused @ tests/set_attester.rs:181-222` (F6) + `set_min_burn_owner_succeeds_while_paused @ tests/set_min_burn.rs:184-221` | HOLDS | — |
| GMS-13 | `build_produces_deny_active_public_faucet @ tests/builder_api.rs:120-161` + `build_rejects_non_public_account_type @ :168-189` + the S18 seam proofs (`production_composition_installs_one_xreserve_and_one_manager @ :577-610`, `seam_rejects_a_smuggled_foreign_policy_companion @ :617-658`) | HOLDS | the builder's public API was re-typed at v16 (S18, deleted upstream config types) with root-first rejection semantics UNCHANGED — mapped + operator-approved (map §10 item 3) |
| GOS-3(P3) | carried: listener + ops assignment (≥2 burn-attester key services) | PARKED (unit-unbuilt; §7b) | owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| GFE-1 / GFE-2 (P4-FE) | DEFERRED (tracked, matrix §3) — confirmed still explicitly deferred, not silently dropped | HOLDS (as DEFERRED) | — |
| GUP-1(U1) | OPTIONAL-UPSTREAM carried; not MVP-blocking | HOLDS | — |
| GREQ-1(U2) | CONDITIONAL-UPSTREAM carried | HOLDS | — |
| P1 | carried: ops assignment (external audit engagement) | PARKED (unit-unbuilt; §7b) | owner: the external-audit engagement; trigger: the pre-mainnet third-party audit |
| P2 | carried: ops assignment (optional Guardian multisig; INV-GUARDIAN-OPTIONAL below) | PARKED (unit-unbuilt; §7b) | explicitly optional; owner: the optional Guardian decision; trigger: the Guardian build decision (explicitly optional) |
| P3 | carried: ops assignment (KMS/HSM SOPs, rotation drills); the faucet rotation MECHANISM is green (CIR-ATTESTER-5/6 repo leg) | PARKED (unit-unbuilt; §7b) | owner: the ops SOP/runbook program; trigger: the ops SOP/runbook slice |
| P4 | carried: ops assignment (cap/SLA/monitoring SOPs) | PARKED (unit-unbuilt; §7b) | owner: the ops SOP/runbook program; trigger: the ops SOP/runbook slice |
| U1 | the standalone upstream-ledger row (SWEEP-V3 `:104`): the OPTIONAL-UPSTREAM tx-lookup RPC ask — carried in the ledger, consumed by the listener only IF upstream ships it (`PHASE4-OPEN-DECISIONS.md` §D); explicitly not MVP-blocking; no v16 delta (the upstream ask is version-independent) | HOLDS (carried OPTIONAL-UPSTREAM) | the twin GUP-1(U1) row above covers the consumer-side assignment; this row is the ledger item itself |
| U2 | the standalone upstream-ledger row (SWEEP-V3 `:105`): the CONDITIONAL-UPSTREAM fee-leg compliance kernel change — relevant only IF xUSDC ever becomes the chain fee token (it is not; INV-NO-FEE-TOKEN-ASSUMPTION HOLDS above); carried in the ledger, monitoring tracks it; no v16 delta | HOLDS (carried CONDITIONAL-UPSTREAM) | the twin GREQ-1(U2) row above covers the tracker-side assignment; this row is the ledger item itself |

## §3 — Circle-owned `DEV-*` / `Q-*` (23 rows) — the stays-OPEN re-walk

The obligation for every row is identical: the item is CARRIED and OPEN, with **no approval
marker introduced by the migration**. Evidence common to all rows: the repo ledger
`docs/spec/GLOSSARY.md:198-215` (every row labelled OPEN/provisional), the migration map's
closing rule (`docs/MIGRATION-V16-ALPHA2.md` §12: "The `DEV-*`/`Q-*` Circle-owned items remain
OPEN throughout — nothing in this migration resolves or approves any of them"), and a
zero-hit sweep for approval language over the v16 diff surface. Per-row deltas only:

| Id | v16 delta | Verdict |
|---|---|---|
| DEV-1 (Q-CRY-1) | none to the deviation itself; its REALIZATION's commitment preimage moved (S16 — recorded in register IMPL-DEV-6) | HOLDS (OPEN) |
| DEV-2 (Q-BUR-1/2) | none | HOLDS (OPEN) |
| DEV-3 (Q-INFRA-4) | none (later-unit) | HOLDS (OPEN) |
| DEV-4 (Q-PRV-4) | none | HOLDS (OPEN) |
| DEV-5 (Q-CRY-6) | none (reducer byte-identical; `amt` vectors byte-identical) | HOLDS (OPEN) |
| DEV-6 (Q-INFRA-5) | none (1024-felt bound unchanged) | HOLDS (OPEN) |
| DEV-7 (Q-BUR-3/4) | none; LNV row-H evidence packet inherited (§7) | HOLDS (OPEN) |
| DEV-8 (Q-MIN-1/2/5) | none (fee-zero MVP gate unchanged; IMPL-DEV-21) | HOLDS (OPEN) |
| DEV-8-fee | none (CONDITIONAL-UPSTREAM + RCC carried) | HOLDS (OPEN) |
| DEV-9 (Q-CRY-5) | none (nonce keying byte-identical; `b32`/`bn` vectors byte-identical) | HOLDS (OPEN) |
| DEV-10 (Q-CRY-3/4) | none (`aid` vectors byte-identical; R-B layout untouched) | HOLDS (OPEN) |
| Q-CRY-2 | none (later-unit) | HOLDS (OPEN) |
| Q-DA-QUORUM | none | HOLDS (OPEN) |
| Q-ADMIN-1 | none | HOLDS (OPEN) |
| Q-DOM-1 | none (test domain values remain placeholders) | HOLDS (OPEN) |
| Q-DOM-2 | none (later-unit) | HOLDS (OPEN) |
| Q-DOM-3 | none (later-unit) | HOLDS (OPEN) |
| Q-API-AUTH | none (relayer auth-header surface unchanged, `t_rly_10` suite green) | HOLDS (OPEN) |
| Q-INFO-PARAM | none (`t_rly_04` suite green) | HOLDS (OPEN) |
| Q-OPS-1 | none (later-unit) | HOLDS (OPEN) |
| Q-OPS-3 | none | HOLDS (OPEN) |
| Q-OPS-5 | none | HOLDS (OPEN) |
| Pause-event surface (CIR-ADMIN-4) | none — `is_paused` stays the observable (`is_paused_publicly_readable @ tests/pause_admin.rs:694-722`); the slot's INSTALLER moved (#2944), its name and readability did not | HOLDS (OPEN) |

Implementation-era open items (not in the 23; carried so nothing is silently dropped):
`Q-MIN-2` (the zero-fee note structure), `Q-FEE-MVP` (NEW — the fail-loud fee reject's own
Circle confirmation, split out of the Q-MIN-2 mischaracterization; IMPL-DEV-21), `Q-PRV-5`
(basic asset, IMPL-DEV-20), `Q-ADMIN-RENOUNCE` / `Q-ADMIN-OWNER-RENOUNCE` (IMPL-DEV-22), and
`Q-ADMIN-RBAC-EQUIV` — the last now TIGHTENED by the S21 flip (both sides are fixed-graph +
membership-rotation-only; register IMPL-DEV-23/24; Circle disclosure is operator-side, an FYI
not a gate). All OPEN, none approved.

## §4 — Global invariants (`INV-*`, 22 rows)

| Id | v16 evidence | Verdict | Note |
|---|---|---|---|
| INV-MINT-SECURITY | `production_supply_raising_root_set_is_exactly_mint @ tests/mint_root_surface.rs:219-303` (S19-hardened both-layer set-equality) + `apply_mint_effects_root_is_not_a_callable_account_surface @ :182-214` + `deny_mint_and_send_traps @ tests/mint_deny.rs:134-160` | HOLDS | the full 62-root account surface additionally frozen (`production_account_callable_surface_is_frozen @ tests/account_callable_surface.rs:254-303`); none of the v16 stock additions is supply-raising (§6) |
| INV-SUPPLY-CONSERVATION | `d5e_happy_conservation @ tests/mint_effects.rs:59-132` + `only_receive_and_burn_lowers_supply @ tests/xreserve_receive_and_burn.rs:87-104` + `no_local_supply_decrement_surface @ tests/mint_deny.rs:283-302` | HOLDS | RIV leg §7 (LNV J) |
| INV-NONCE-REPLAY | `d5c_replay_rejects @ tests/masm_mint_shell.rs:395-416` + `mint_note_replayed_nonce_rejects_no_writes @ tests/xreserve_mint_note.rs:353-412` | HOLDS | — |
| INV-PUBLIC-BURN-OBSERVABILITY | `burn_note_is_public_with_fixed_tag @ tests/xreserve_burn.rs:96-120` + `burn_note_is_never_private @ :166-188` + `burn_note_payload_schema @ :125-161` | HOLDS | — |
| INV-TWO-BLOCK-BURN | `production_burn_note_same_block_consume_is_erased @ tests/xreserve_burn.rs:366-447` | HOLDS | — |
| INV-CIRCLE-CANONICAL-WITHDRAWAL | carried: binds the (unbuilt) listener; spec-level conformance proven at Phase-4.2, implementation pending | PARKED (unit-unbuilt; §7b) | no v16 surface; owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| INV-NO-ECRECOVER | `d5d_happy_attestation @ tests/masm_mint_shell.rs:548-573` + `d5d_forged_sig_rejects @ :580-593` + `d5d_seam_both_arrangements_reject @ :622-639` | HOLDS | verify-vs-candidate-pubkey + commitment-allowlist model unchanged; preimage note under §1 CIR-STATE-4 |
| INV-BYTES32-HASH-TO-WORD | `tv_dual_1_bytes32_to_key @ tests/masm_dual.rs:133-162` | HOLDS | `b32` vectors byte-identical |
| INV-UINT256-TO-ASSETAMOUNT | `tv_dual_2_uint256_reducer @ tests/masm_dual.rs:167-246` + `d5e_over_cap_rejects @ tests/mint_effects.rs:198-214` | HOLDS | — |
| INV-VAULT-MODEL | `burn_note_insufficient_balance_rejects_create @ tests/xreserve_burn.rs:273-306` | HOLDS | — |
| INV-NO-FEE-TOKEN-ASSUMPTION | discharged by inspection: the invariant forbids ASSUMING xUSDC is the chain fee token, and no repo surface does (zero fee-token references in `asm/`/`crates/`); U2 CONDITIONAL-UPSTREAM carried in the ledger | HOLDS | miden-testing `verification_base_fee` defaults 0 both versions (map §8) — no fee leg entered any assertion |
| INV-BURN-EVIDENCE-TRUST | carried: DEV-7 OPEN; the proof-strength-labelled evidence package binds the (unbuilt) listener; LNV row-H packet inherited (§7) | PARKED (unit-unbuilt; §7b) | owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| INV-OFFCHAIN-BURN-SIGNING | carried: binds the (unbuilt) listener | PARKED (unit-unbuilt; §7b) | owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| INV-ACCOUNTID-ENCODING | `aid_rt_extracts_account_id @ tests/mint_recipient_account_id.rs:90-109` + `aid_rej_out_of_range_traps @ :118-131` + the fail-closed pad tests `src/xreserve/encoding/account_id.rs:124,:179-185` | HOLDS | DEV-10 OPEN; S23 re-ordered the upstream version/low-byte error precedence — the Circle-frozen vector stays byte-identical, `aid_rej_non_canonical_traps_protocol_version @ :141-152` asserts the exact v16 error, `aid_low_byte_traps_protocol_low_byte @ :158-170` keeps the low-byte assertion alive (same strictness, +1 test) |
| INV-DEPOSITINTENT-PARSE | `tv_dual_3_parse_deposit_intent @ tests/masm_dual.rs:356-413` + `extract_is_read_only @ tests/mint_recipient_account_id.rs:262-287` | HOLDS | 60-felt packing unchanged |
| INV-NOTE-MODEL-CURRENT | `burn_note_payload_schema @ tests/xreserve_burn.rs:125-161` (`NoteStorage.items`, Public) + `mint_note_carries_scheme1_attestation_and_scheme2_target_to_faucet @ tests/f5_network_account_auth.rs:283-328` (attachments retained — S15) | HOLDS | #2283 (P2ID ≥1 asset) satisfied by construction — every repo P2ID carries the minted asset (S7) |
| INV-GUARDIAN-OPTIONAL | zero Guardian dependency in the workspace (no crate, no import) | HOLDS | — |
| INV-CIRCLE-CONFIRMATION-GATES | §3 above: 23/23 OPEN, zero approval markers introduced | HOLDS | — |
| INV-BURN-HOLDER-BALANCE-AT-CREATE | `burn_note_insufficient_balance_rejects_create @ tests/xreserve_burn.rs:273-306` + `recipient_burns_full_balance @ :317-355` | HOLDS | — |
| INV-REMOTEDEPOSITOR-VS-SOURCEDEPOSITOR | carried: binds the (unbuilt) listener | PARKED (unit-unbuilt; §7b) | owner: the withdrawal-listener unit (03); trigger: the listener unit's build gate |
| INV-DEPOSIT-ATTESTATION-RAW-KECCAK | `t_rly_20_accept_canonical_raw_keccak_vectors @ crates/xreserve-deposit-relayer/tests/envelope_validate.rs:86-109` + `t_rly_20_reject_non_raw_keccak_digest @ :138-165` + `t_rly_20_fixture_signature_cryptographically_covers_the_raw_keccak_digest @ :274-321` | HOLDS | signature wire (65B `r‖s‖v` = 17 felts) byte-identical at v16; only the PUBKEY staging moved (S16) |
| INV-BURN-SENDER-PRIVACY-LEAK | documented exposure unchanged: depositor = `metadata.sender` (`src/note/xreserve_burn.rs:71-72`) | HOLDS | — |

Repo-local addition: **INV-PAUSE** (repo GLOSSARY) — `dom_pauser_pause_halts_mint @
tests/pause_admin.rs:253-272` + `dom_pauser_pause_halts_burn @ :362-404` +
`burn_paused_rejected_through_composition @ tests/xreserve_receive_and_burn.rs:345-392` —
HOLDS; made newly load-bearing by #3047 (a dropped `Pausable` would now no-op, not trap), which
is exactly what `production_components_carry_is_paused_slot` tripwires.

## §5 — Deviation-register rows (`IMPL-DEV-*`, 23) — doubles as the CDR-3 cite-resolution walk

Every "what shipped" cite below was re-resolved against the `076a720` tree this re-run (the
register itself was re-anchored — see the report §3; the register's numbering is CANONICAL and
the repo GLOSSARY mirror now agrees: 21 = fee, 22 = renounce, 23 = RBAC, 24 = set_role_admin
removal, 25 = S12 freeze/unfreeze, 26 = S24 roots). Verdict = does the registered deviation
still describe the shipped v16 code?

| Id | v16 cite (re-anchored, resolves) | Verdict | Note |
|---|---|---|---|
| IMPL-DEV-1 | `owner_has_no_pause_path @ tests/pause_admin.rs:204-218` + `builder_installs_no_stock_pause_manager @ tests/builder_api.rs:358-387`; slot: alpha.2 `pausable/mod.rs:22-35` | **CHANGED-RECONCILED** (row text) | the remediation itself HOLDS (Domain-Pauser-only pause intact); the row's two v15 claims — "is_paused is FungibleFaucet-installed" and "set_role_admin stays owner-only / DOM_MANAGER owner-administered" — were STALE at v16 and are corrected in the register (this re-run; the set_role_admin correction now records the S21 flip → IMPL-DEV-24) |
| IMPL-DEV-2 | `builder.rs:63-64`, `pause_admin.masm:22`, parity `constant_parity.rs:357-368` | HOLDS | — |
| IMPL-DEV-3 | `owner_controlled_authority_parity @ tests/constant_parity.rs:576-604` | HOLDS | — |
| IMPL-DEV-4 | alpha.2 `policy_manager.masm:357-358`; `burn_paused_rejects @ tests/burn_policy.rs:262-309` asserts the stock error | HOLDS | — |
| IMPL-DEV-5 | `xreserve_mint.masm:115-118` own pause gate; `deny_mint_and_send_traps` | HOLDS | — |
| IMPL-DEV-6 | `attestation.rs:83-96`; `attestation_verify.masm:107,:132` | HOLDS (v16 note added) | commitment preimage 33B/9-felt → affine-16 recorded IN the row (S16 supersession) |
| IMPL-DEV-7 | `xreserve_burn.rs:33-34` | HOLDS | Q-BUR-1 OPEN |
| IMPL-DEV-8 | `burn_note.rs:27-32`; `xreserve_burn.rs:71-72` | HOLDS | — |
| IMPL-DEV-9 | `xreserve_mint.masm:192-194` (mask `0xfffc0000`) | HOLDS | — |
| IMPL-DEV-10 | `xreserve_mint.masm:199-201` (`SERIAL_NUM` = the nonce-derived key) | HOLDS | — |
| IMPL-DEV-11 | `error.rs:1-4,:88-100` | HOLDS | string `MasmError` surface unchanged at v16 |
| IMPL-DEV-12 | `error.rs:57-61` + regression `account_id.rs:179-185` | HOLDS (resolved) | register status updated to "resolved — message fixed" |
| IMPL-DEV-13 | `pause_admin.masm:53-54` | HOLDS | — |
| IMPL-DEV-14 | `min_burn_admin.masm:24-27` | HOLDS | — |
| IMPL-DEV-15 | `builder.rs:132-134` (`mutability_config`, still FungibleFaucet-installed at v16 — `production_components_carry_mutability_config_slot @ tests/builder_api.rs:435-470`) + `build_rejects_immutable_max_supply @ :248-265` | HOLDS | — |
| IMPL-DEV-16 | `domain_config.masm:108` vs `attester_admin.masm:55` | HOLDS | — |
| IMPL-DEV-20 | `production_build_registers_no_transfer_policy @ tests/basic_asset_tripwire.rs:60-104` | HOLDS | Q-PRV-5 OPEN; reinforced at v16 by `invoke_wrappers_are_inert_and_the_asset_stays_basic` |
| IMPL-DEV-21 | `deposit_intent_parser.masm:39,:132,:191-194` (`ERR_XRESERVE_FEE_NONZERO`); `reject_nonzero_fee_below_maxfee_fails_closed @ tests/xreserve_mint.rs:657-682` | HOLDS (deferral RATIFIED) | status re-pegged: RATIFIED DEFERRAL (human 2026-07-14), mainnet-gated, pending Q-FEE-MVP (Q-MIN-2 peg corrected — it covers only the zero-fee note structure) |
| IMPL-DEV-22 | `builder.rs::allowed_note_scripts()` (renounce omitted); `production_faucet_note_allowlist_is_exactly_the_12_ratified_roots @ tests/f5_network_account_auth.rs:173-211` | HOLDS (cite refreshed) | the allowlist is 12 roots since the S21 flip (13 at the 2026-07-10 ratification); the row's core claim — no self-renounce, stock proc present-but-unreachable — is unchanged and the register now records the 12-root count |
| IMPL-DEV-23 | seeded RBAC `builder.rs::seeded_dom_roles_rbac` + the proc-level S21 characterization set (`role_admin.rs:771-973` — every `set_role_admin` test is now an explicitly-labelled PROC-LEVEL pin; in production the proc is unreachable) | **CHANGED-RECONCILED** (resolved by ratified decision) | the row no longer asserts any runtime re-delegation guarantee: the earlier "unbreakable backstop" acceptance was REVERSED (S21 flip, human 2026-07-14) and the row records the removal → IMPL-DEV-24; mirrored into the repo GLOSSARY IMPL-DEV-23 with the same content |
| IMPL-DEV-24 (NEW in the register this re-run; shipped by PR #17) | the removal row: `rbac_set_role_admin_is_present_on_the_account @ tests/account_callable_surface.rs:531-553` + `set_role_admin_is_unreachable_from_every_allowlisted_note @ :555-588` + `set_role_admin_former_note_root_is_not_admissible_via_either_allowlist @ :590-614` + `set_role_admin_note_is_rejected_as_non_allowlisted @ tests/f5_admin_notes.rs:1382-1415` (+ `set_role_admin_note_is_rejected_regardless_of_note_args @ :1421-1445`, fixture pin `@ :1362-1376`) | HOLDS (ratified) | human-ratified 2026-07-14 (`DECISION-SETROLEADMIN-NOTE-REMOVAL.md`); GLOSSARY mirror IMPL-DEV-24; non-vacuity re-demonstrated this run (RED on 13 roots, reverted) |
| IMPL-DEV-25 (register row NEW this re-run; capability ratified 2026-07-13) | S12 freeze/unfreeze: `authority_freeze_and_unfreeze_are_present_on_the_account @ tests/account_callable_surface.rs:305-329` + `freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note @ :331-373` + `freeze_and_unfreeze_are_not_admissible_via_either_allowlist @ :375-400` + both entry vectors EXECUTED and rejected (`the_auth_component_rejects_a_non_allowlisted_note @ :402-435`, `the_auth_component_rejects_any_tx_script_via_the_empty_allowlist @ :437-467`) | HOLDS (ratified) | human-ratified 2026-07-13 (map row S12); GLOSSARY mirror IMPL-DEV-25 (migration-time label "IMPL-DEV-21", renumbered by CDR-3) |
| IMPL-DEV-26 (register row NEW this re-run; capability ratified 2026-07-13) | S24 roots: `invoke_wrappers_are_inert_and_the_asset_stays_basic @ tests/account_callable_surface.rs:469-514` + `get_authority_is_read_only_on_the_account @ :616-694` (EXECUTED read-only proof — closes the first walk's doc-backed gap, IMPL-DEV-22-era) + `production_account_callable_surface_is_frozen @ :254-303` | HOLDS (ratified) | human-ratified 2026-07-13 (map row S24); GLOSSARY mirror IMPL-DEV-26 (migration-time label "IMPL-DEV-22", renumbered by CDR-3) |

## §6 — MANDATORY sub-sweep (a): v16-introduced capabilities (per SEMANTIC S-row)

Rule applied: each capability v16 *introduced* that had no v15 test resolves to a test proving
it is BOUNDED as intended, or is flagged NEEDS-HUMAN. ("Green suite" alone discharges nothing
here.)

| S-row | New capability at v16 | Bounding proof (all green in the 434) | Ratification state |
|---|---|---|---|
| S21 (stock proc gate change) | at PROC level, a `DOM_MANAGER` holder passes the stock `set_role_admin(DOM_PAUSER, …)` gate (v15: owner-only). In PRODUCTION the proc is unreachable (next row) | proc-level characterization pins, all green and explicitly labelled as such: `set_role_admin_dom_manager_can_redelegate_pauser @ tests/role_admin.rs:813-839`, rejects `set_role_admin_owner_direct_rejects @ :801-804` (exact `ERR_SENDER_NOT_ROLE_ADMIN`), `set_role_admin_dom_pauser_rejects @ :841-844`, `set_role_admin_stranger_rejects @ :847-850`, `dom_manager_cannot_administer_dom_manager @ :857-906`, `owner_reaches_set_role_admin_through_dom_manager @ :908-973` | ratified as part of the S21 flip disposition (2026-07-14): the stock semantics stay pinned loud (the `dom_pauser_can_renounce_own_role` treatment) while the capability is production-unreachable |
| **S21 (delegation-TRANSITION capability — the first walk's STOP driver)** | every effective-admin holder held the power to RE-POINT the managed role's admin to an arbitrary role — including states permanently excluding `ADMIN` (owner self-lockout cycles; rogue-Manager self-administered pauser). v15 had NO such capability | **REMOVED at the source (the resolution this re-run confirms):** the `set_role_admin` note is no longer allowlisted, so NO sender reaches the proc — `set_role_admin_is_unreachable_from_every_allowlisted_note @ tests/account_callable_surface.rs:555-588` (MAST sweep over all 12 notes, resolved by path), `set_role_admin_former_note_root_is_not_admissible_via_either_allowlist @ :590-614`, `rbac_set_role_admin_is_present_on_the_account @ :531-553` (the proc pin — surface unchanged), and the preserved former note consumed-and-REJECTED (`tests/f5_admin_notes.rs:1382-1445`, `ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED`, state asserted unchanged). Non-vacuity re-demonstrated this run: with the former root re-added (13 roots) the sweep + admissibility tests go RED with the exact S21-removal assertion, then reverted | **RATIFIED 2026-07-14** (`DECISION-SETROLEADMIN-NOTE-REMOVAL.md` — reverses the earlier acceptance; two independent adversarial Circle-conformance audits, NO REFUTATION; register IMPL-DEV-24). The unverified-recoverability question is structurally MOOTED — a guarantee, not a runbook |
| S2 | The built-in `ADMIN` role is seeded to the owner's ACCOUNT (v15: owner super-admin qua owner status, no seed) | operator condition "ADMIN resolves to the owner — NO new capability" verified for the seeded configuration: the owner gains nothing beyond its v15 authority (`grant_role_owner_on_delegated_role_traps @ tests/f5_admin_notes.rs:816-839` — the owner has NO super-admin over the delegated role); the seed reads back exactly (`shipped_delegation_reads_back @ tests/role_admin.rs:506-560`; replica fidelity `support_replica_carries_delegation_seed @ tests/set_min_burn.rs:223-289`). CAVEAT the seed also CHANGED one v15 property: v15 owner authority followed ownership automatically; v16 `ADMIN` membership is ACCOUNT-BOUND and does not auto-follow `transfer_ownership`/`accept_ownership` — the ratified S2 rotation-runbook divergence (grant-new/revoke-old by an ADMIN member). The S2 row mandated "document and test": documented (builder.rs KNOWN DIVERGENCE, IMPL-DEV-23 both mirrors, FAUCET-SPEC §5); the combined transfer→ADMIN-rotation TEST is the SCHEDULED deferred slice `TASK-S2-ADMIN-RESEAT-TEST` (report §6 ledger; trigger: before the internal MASM security audit) | operator-approved at the migration gate (map §10 decision 2); the test leg RATIFIED as a named deferred slice (human, 2026-07-14 round-2 gate — CIR-STATE-7/CIR-ADMIN-3 HOLDS not blocked) |
| S12 | `authority::freeze`/`unfreeze` become callable account roots (v15: `Authority` exported only `assert_authorized`) | present: `authority_freeze_and_unfreeze_are_present_on_the_account @ tests/account_callable_surface.rs:305-329`; UNREACHABLE: `freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note @ :331-373` (MAST scan, exhaustive over the 12), `freeze_and_unfreeze_are_not_admissible_via_either_allowlist @ :375-400`, both entry vectors EXECUTED and rejected `@ :402-435,:437-467`; whole surface frozen `production_account_callable_surface_is_frozen @ :254-303` | HUMAN-RATIFIED 2026-07-13 (S12; register IMPL-DEV-25) |
| S24 | `authority::get_authority` + `policy_manager::invoke_send_policy`/`invoke_receive_policy` callable roots | `invoke_wrappers_are_inert_and_the_asset_stays_basic @ tests/account_callable_surface.rs:469-514` (no transfer policy/callback slots appear; `AssetCallbackFlag::Disabled` on the minted asset) + `get_authority_is_read_only_on_the_account @ :616-694` (EXECUTED read-only proof — the first walk's doc-backed gap is closed) + `production_build_registers_no_transfer_policy @ tests/basic_asset_tripwire.rs:60-104` (F4) + `production_supply_raising_root_set_is_exactly_mint` (F1) | HUMAN-RATIFIED 2026-07-13 round 9 (S24; register IMPL-DEV-26) |
| S13 | stock `FungibleFaucet` re-exports `has_procedure` (+1 callable root; the stock BurnNote reflects on it) | inside the frozen 62-root literal surface (`production_account_callable_surface_is_frozen`); read-only reflection, exercised by the whole burn suite (`burn_note_consumed_by_faucet_decrements @ tests/xreserve_burn.rs:225-268` via the re-pinned stock BurnNote root) | ratified under the stock-surface discipline (map §10 item 5 list) |
| S18 | new builder error path `PolicyCompanionMismatch` (a BOUND, not a capability — rejects smuggled companions) | `seam_rejects_a_smuggled_foreign_policy_companion @ tests/builder_api.rs:617-658` (exact `{expected: 2, found: 3, recognized: 2}`) + `production_composition_installs_one_xreserve_and_one_manager @ :577-610` | operator-approved (map §10 decision 3) |
| S16 | none (representation change); the NEW fallible SEC1→affine seam fail-closes on an off-curve key | `invalid_pubkey_rejects @ src/xreserve/encoding/attestation.rs:199` | operator-approved (map §10 decision 1) |
| S1 | none (slot provenance moved); the pause tripwire became LOAD-BEARING (#3047: missing slot now silently no-ops) | `production_components_carry_is_paused_slot @ tests/builder_api.rs:400-425` (set-equality-strict) | mapped, no ratification needed (no capability) |
| S23 | none (upstream error-precedence reorder) | `aid_rej_non_canonical_traps_protocol_version @ tests/mint_recipient_account_id.rs:141-152` + `aid_low_byte_traps_protocol_low_byte @ :158-170` (keeps the low-byte assertion alive) | mapped |
| S3/S4/S5/S6/S7/S8/S9/S10/S11/S14/S15/S17/S19/S22 | no account-surface capability introduced (recipe/ABI/infrastructure/annotation rows); S19 is capability-PRESERVING (the 17-proc interface pinned byte-equal in membership to v15) | the frozen-surface + count-parity gates: `production_account_callable_surface_is_frozen`, `production_supply_raising_root_set_is_exactly_mint` (S19-hardened), 12-root allowlist set-equality (`production_faucet_note_allowlist_is_exactly_the_12_ratified_roots @ tests/f5_network_account_auth.rs:173-211`), empty tx-allowlist (`production_faucet_tx_script_allowlist_is_exactly_empty @ :218-230`) | mapped |

**Result:** every v16-introduced capability resolves to bounding tests + an existing human
ratification — including the S21 delegation-TRANSITION capability, the first walk's sole
exception, which is now REMOVED at the source (the note is not allowlisted; unreachability
machine-enforced and re-proven non-vacuous this run) under the 2026-07-14 ratification.
The S2 ownership-transfer divergence's test leg — the sweep's one residue — is RESOLVED by the
2026-07-14 round-2 human ratification: CIR-STATE-7/CIR-ADMIN-3 stay HOLDS (orthogonal-storage
rationale) and the combined test is the scheduled deferred slice `TASK-S2-ADMIN-RESEAT-TEST`
(trigger: before the internal MASM security audit). No unratified capability remains.

## §7 — MANDATORY sub-sweep (b): the PARKED ledgers

### §7a — parked-RIV ledger (formula: RIV-inherited)

Every id whose obligation (in whole or part) is the real-node RIV. Formula for all rows:
**conformance INHERITED from the v15 LNV record** (`crates/xusdc-validation` —
`VALIDATION-RECORD.md`, slices LNV-1..5, 12/12 rows green on a real v0.15 node); **re-validation
deferred to the v16 LNV re-run; trigger: the v16-alpha `miden-client` (+node) ships** (the crate
is parked — root `Cargo.toml:4-9` R1, `crates/xusdc-validation/PARKED-V15.md`).

| Id(s) | LNV row(s) inherited | RIV portion parked |
|---|---|---|
| CIR-MINT-STATE-1..4, MC-MINT-5/GMS-1 | D, E | atomic mint order + negatives on a real node |
| CIR-MINT-POST-1, INV-SUPPLY-CONSERVATION | J | conservation ledger `token_supply == Σminted − Σburned` |
| CIR-EVIDENCE-1, DEV-7, INV-BURN-EVIDENCE-TRUST | H | the F7 same-block-erasure evidence packet (no acceptability verdict — Circle-owned) |
| CIR-STATE-6, CIR-EVIDENCE-2, MC-EV-3 | D, J | real-node `GetAccount.token_supply` read |
| MC-EV-5 | G | exact-tag `SyncNotes` discovery |
| MC-BURN-3/GMS-11 (real-node leg) | G, H | two-block create→consume + same-block reject on a real node |
| CIR-ADMIN-1/2/3/4 (real-node leg), MC-ADM-1..5 | C | the admin suite incl. rotation drill + non-authorized negatives |
| CIR-DEPLOY-6 (real-node leg) | B | init-once on a real node |
| CIR-DEPLOY-1 (faucet deploy leg) | A | production faucet deploy + account recognition |
| F5 auth boundary (real-node leg) | F | non-allowlisted note + tx-script rejected on a real node |
| (node liveness / logs) | K, L | network-tx-builder auto-consume; clean service logs |

MockChain twins of every parked row above are green at v16 (cited in §1/§2/§4), so the parking
is strictly the real-node leg, explicit and time-boxed to the client release.

### §7b — parked unit-unbuilt ledger (formula: unit-unbuilt)

Every id (or split leg) whose obligation is owned by a later, unbuilt program unit. Formula for
all rows: **CARRIED and UNDISCHARGED** (Phase-4 spec assignment intact, `SWEEP-V3-COVERAGE.md`
PRESENT; the v16 migration touched no surface of these units); **discharge trigger: the owning
unit's own build gate** (each unit builds plan → audit → build → consortium per the roadmap).
Never counted toward HOLDS; the per-row classification is RATIFIED (human, 2026-07-14
round-2 gate) subject to Round-F's spot-check condition (the vocabulary note above /
report §5 item 7). The 24 tallied rows (verdict cells marked
`PARKED (unit-unbuilt; §7b)` in §1/§2/§4):

| Owning unbuilt unit | Ids |
|---|---|
| Withdrawal listener (03) | CIR-WITHDRAW-1/2/3, CIR-WITHDRAW-4, CIR-ATTESTER-2, CIR-ATTESTER-3/4, CIR-API-1..6 (listener leg), MC-BURN-4/GOS-2, MC-EV-2, GOS-3(P3), INV-CIRCLE-CANONICAL-WITHDRAWAL, INV-OFFCHAIN-BURN-SIGNING, INV-REMOTEDEPOSITOR-VS-SOURCEDEPOSITOR, INV-BURN-EVIDENCE-TRUST (evidence-package leg) |
| Monitoring (05) | CIR-STATE-6 (monitoring leg), CIR-MINT-POST-3, CIR-EVIDENCE-2 (monitoring leg), CIR-OPS-1/2/3, MC-MINT-6/GOS-5, MC-EV-3/GOS-4, MC-INF-1/2/3 (listener+monitoring legs) |
| Ops SOPs / runbooks | CIR-ATTESTER-5/6 (ops leg), CIR-ADMIN-5, CIR-OPS-4/5/6, CIR-DEPLOY-4, CIR-DEPLOY-5, P3, P4 |
| External audit / optional guardian | CIR-DEPLOY-3, P1, P2 |

## §8 — Completeness + STOP check (re-run result: ZERO STOP)

- Rows walked (MECHANICALLY recounted this re-issue — split-obligation ids count once, under
  the worst leg; the FEE pair counts once): **48 CIR + 33 Miden-family + 23 DEV/Q + 22 INV +
  23 IMPL-DEV = 149 spine ids**, plus 2 supplemental rows outside the tally (the DEFERRED
  GFE-1/2 group — HOLDS as DEFERRED — and the repo-local INV-PAUSE — HOLDS). COUNT
  disclosure: the Miden family follows `SWEEP-V3-COVERAGE.md` §2's 33 load-bearing entries —
  31 walk rows plus the STANDALONE upstream-ledger rows U1 and U2 (added in this re-issue;
  an earlier draft folded them into their GUP-1/GREQ-1 twins and stated "31"), with the GFE
  group tracked separately as PRESENT-as-DEFERRED (supplemental here). The IMPL-DEV family
  grew to 23 with the register rows 24/25/26. Zero blank evidence cells; zero blank
  verdicts.
- Verdicts over the 149 use ONLY the mandated vocabulary: **HOLDS 113** (only rows with actual
  discharging evidence — tests, inspection-checkable invariants, the stays-OPEN ledger
  obligations, or a RATIFIED recorded deferral; incl. the 23 OPEN-carried DEV/Q) ·
  **CHANGED-RECONCILED 5** (CIR-STATE-4, MC-MINT-1, MC-ADM-1..5, IMPL-DEV-1 row text,
  IMPL-DEV-23 — each resolved by an existing ratification, confirm-and-cite only) ·
  **PARKED 31** — 2 RIV-class (CIR-EVIDENCE-1; MC-EV-5's discovery leg — both §7a) + 24
  unit-unbuilt (§7b) + 5 split-obligation ids tallied under their worst (unit-unbuilt) leg
  (CIR-STATE-6, CIR-ATTESTER-5/6, CIR-API-1..6, CIR-EVIDENCE-2, MC-INF-1/2/3 — each repo leg
  HOLDS on its own line, uncounted) · **STOP 0**. Family split: CIR 48 = 31/1/16(1 §7a +
  15 §7b incl. 4 worst-leg)/0 · Miden 33 = 20/2/11(1 §7a + 10 §7b incl. 1 worst-leg)/0 ·
  DEV-Q 23 = 23/0/0/0 · INV 22 = 18/0/4(§7b)/0 · IMPL-DEV 23 = 21/2/0/0. Both supplemental
  rows HOLD. PARKED rows are UNDISCHARGED deferrals with recorded triggers — none is counted
  as conformance; the §7b classification mapping is RATIFIED (human, 2026-07-14 round-2 gate)
  subject to Round-F's spot-check condition (vocabulary note above; report §5 item 7).
- **Prior-STOP re-derivation (the re-run's core mandate) — all three now HOLDS:**
  1. **CIR-FEE-2** → **HOLDS as a recorded, RATIFIED deferral** (human 2026-07-14): the
     fail-loud `feeAmount==0` reject IS the MVP contract; the relayer-credit split is
     mainnet-gated, P2; pegged to the new pending **Q-FEE-MVP** (the prior Q-MIN-2 peg was a
     mischaracterization, corrected in register IMPL-DEV-21 + repo GLOSSARY F2/CIR-FEE-2).
  2. **CIR-ADMIN-3** → **HOLDS (human-RATIFIED 2026-07-14, round-2 gate)**: rotation =
     grant/revoke (capability-proven in real pause power); the owner backstop can no longer be
     stripped ON-CHAIN — the delegation graph is build-seeded and FROZEN (the runtime
     `set_role_admin` note removed, 12-root allowlist; unreachability machine-enforced by
     `account_callable_surface.rs` + `f5_admin_notes.rs`, all green, non-vacuity
     re-demonstrated RED-on-13-roots this run) — scoped by the ratified S2 account-bound-ADMIN
     divergence (ratification rationale recorded verbatim in the row; deferred slice
     `TASK-S2-ADMIN-RESEAT-TEST` scheduled, trigger: before the internal MASM security audit).
  3. **CIR-STATE-7** → **HOLDS (human-RATIFIED 2026-07-14, round-2 gate — rationale verbatim
     in the row)**: the owner-self-lockout / rogue-Manager re-delegation transition class is
     structurally unreachable on-chain (same evidence set); the unverified-recoverability
     question is MOOTED, not runbooked.
  Ratification artifacts confirmed (not re-opened): `DECISION-SETROLEADMIN-NOTE-REMOVAL.md`
  (RATIFIED human 2026-07-14 — reverses the earlier S21 acceptance; register IMPL-DEV-24;
  GLOSSARY IMPL-DEV-24) and the CIR-FEE-2 deferral records (register IMPL-DEV-21; GLOSSARY
  F2 / Q-FEE-MVP).
- The PARKED (unit-unbuilt) set (24 ids + 5 worst-leg ids) is undischarged conformance DEBT of
  the unbuilt program units, unchanged by the migration. No golden Circle-wire vector moved (map §11:
  `circle-depositintent-groundtruth.json` 0-line diff; only the 3 approved `att` fields
  regenerated). Behaviour remains frozen and every runtime gate green.
- **STOP check: PASS — zero STOP rows.** Any row above failing its cited evidence in a future
  re-verification re-halts the gate per the vocabulary rule.
