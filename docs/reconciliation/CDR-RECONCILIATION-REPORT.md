# CDR RECONCILIATION REPORT — the post-migration conformance & documentation gate

**Role.** The single consolidated verdict for the CDR gate that runs AFTER the v0.16.0-alpha.2
migration merged to `implementation` and BEFORE the implementation→main PR opens. It rolls up
the three reconciliations — **CDR-1** conformance re-walk (`CDR-1-CONFORMANCE-REWALK.md`),
**CDR-2** documentation/comment sweep (`V16-DOC-DELTA.md`), **CDR-3** deviation-register
reconciliation (§3 below) — surfaces the NEEDS-HUMAN items (§5), and states residual risk
(§6). Produced on branch `cdr/v16-verify` off `implementation` @ **`076a720`** (pre-flight
verified: `docs/MIGRATION-V16-ALPHA2.md` present; workspace on crates.io `=0.16.0-alpha.2`;
`xusdc-validation` parked per R1; **the cdrfix base confirmed** — `allowed_note_scripts()`
returns 12 roots and `asm/standards/notes/xreserve_set_role_admin_note.masm` is absent).

**RE-RUN provenance.** This is the CDR gate's re-run off the updated base. The first run
(branch `cdr/v16` off `f979afd`, four rounds) ended **STOP on three rows** — CIR-FEE-2 and
CIR-ADMIN-3 + CIR-STATE-7 (the S21 delegation-transition capability) — and escalated. Both
root causes were resolved by non-delegable human decisions plus the `cdrfix` slice (PR #17
`73030ce`, merged @ `076a720`): the runtime `set_role_admin` note was REMOVED (13 → 12 roots;
`DECISION-SETROLEADMIN-NOTE-REMOVAL.md`, RATIFIED human 2026-07-14, reversing the earlier S21
acceptance) and the CIR-FEE-2 fail-loud MVP deferral was RATIFIED (2026-07-14, pegged to the
new pending `Q-FEE-MVP`). The first run's branch was never merged, so its doc corrections were
re-applied / re-derived here (V16-DOC-DELTA §2a/2b). This re-run reproduced the full walk
against the actual `076a720` tree — it did not trust the resolution note.

**Why this gate exists.** The migration's Round-F verification traced hunks 1:1 to map rows —
structurally blind to a stale doc that SHOULD change but has no hunk, and to conformance
obligations that no hunk names. This gate closes both: every load-bearing id re-judged, every
v16-changed prose surface swept, the Circle-facing register re-anchored and mirrored into the
repo.

**Approval reality (unchanged).** No Circle approval exists for any `DEV-*`/`Q-*`; nothing in
this pass resolves or approves any Circle-owned item (re-walked row by row, CDR-1 §3 —
23/23 OPEN; `Q-FEE-MVP` added as a NEW pending Circle question, not an approval). Behaviour is
FROZEN: this pass changed prose/records only, proven by identical pass counts (§4).

---

## 1. CDR-1 — conformance re-walk (verdict: **PASS — zero STOP rows**)

Full table: `CDR-1-CONFORMANCE-REWALK.md`. Summary (CR = CHANGED-RECONCILED; only HOLDS
claims discharge). Verdicts use ONLY the task-mandated vocabulary (HOLDS / CHANGED-RECONCILED / PARKED / STOP).
PARKED carries two recorded formulas — §7a RIV-inherited and §7b unit-unbuilt (the later-unit
obligations; undischarged, trigger = the owning unit's build gate) — and split-obligation ids
are broken into per-leg table lines (the CIR-FEE precedent), tallied once under the worst leg.
The §7b classification mapping replaces the first issue's unauthorized NOT-YET-BUILT/PARTIAL
labels; it is RATIFIED (human, 2026-07-14 round-2 gate) subject to Round-F's §7b spot-check
condition (§5 item 7).

| Family | Ids | HOLDS | CR | PARKED (§7a / §7b-pure / §7b-worst-leg) | STOP | blanks |
|---|---|---|---|---|---|---|
| `CIR-*` (matrix §1+§5) | 48 | 31 | 1 | 16 (1 / 11 / 4) | 0 | 0 |
| Miden family (matrix §2) | 33 (+ the DEFERRED GFE-1/2 group, supplemental, HOLDS) | 20 | 2 | 11 (1 / 9 / 1) | 0 | 0 |
| `DEV-*`/`Q-*` | 23 | 23 (all OPEN-carried) | 0 | 0 | 0 | 0 |
| `INV-*` | 22 (+ repo INV-PAUSE, supplemental, HOLDS) | 18 | 0 | 4 (0 / 4 / 0) | 0 | 0 |
| Register `IMPL-DEV-*` | 23 | 21 | 2 | 0 | 0 | 0 |
| **Total (spine)** | **149** | **113** | **5** | **31** | **0** | **0** |

(Mechanically recounted; the Miden 33 = 31 walk rows + the standalone upstream-ledger rows
U1/U2, with the GFE group supplemental — count disclosure in CDR-1 §8.)

- **The three prior STOP rows all re-derive to HOLDS against the actual v16 code** (CDR-1 §8):
  - **CIR-FEE-2** → HOLDS as a recorded, RATIFIED deferral (human 2026-07-14): the fail-loud
    `feeAmount==0` reject IS the MVP contract; the relayer-credit split is mainnet-gated, P2;
    the reject's own Circle confirmation is the NEW pending **Q-FEE-MVP** (the prior Q-MIN-2
    peg was a mischaracterization, corrected in the register + GLOSSARY).
  - **CIR-ADMIN-3** → HOLDS: rotation = `grant_role`/`revoke_role`, capability-proven in real
    pause power; the owner backstop can no longer be stripped ON-CHAIN — the delegation graph
    is build-seeded and frozen (the runtime `set_role_admin` note removed; 12-root allowlist).
    Scoped by the ratified S2 divergence across ownership transfer (next bullet block).
  - **CIR-STATE-7** → HOLDS: the owner-self-lockout / rogue-Manager re-delegation transition
    class is structurally unreachable on-chain; the unverified-recoverability question is
    MOOTED (a structural guarantee, not a runbook).
  Evidence (all green in the 434, cited with line spans in CDR-1):
  `account_callable_surface.rs::{rbac_set_role_admin_is_present_on_the_account,
  set_role_admin_is_unreachable_from_every_allowlisted_note (MAST sweep resolved by PATH),
  set_role_admin_former_note_root_is_not_admissible_via_either_allowlist}` +
  `f5_admin_notes.rs::{set_role_admin_note_is_rejected_as_non_allowlisted,
  set_role_admin_note_is_rejected_regardless_of_note_args,
  former_set_role_admin_note_script_still_compiles_to_the_former_root}`.
  **Non-vacuity re-demonstrated this run:** re-adding the former note root to
  `allowed_note_scripts()` (13 roots) turned the MAST sweep + admissibility tests RED with the
  exact S21-removal assertion ("the swept note scripts must be EXACTLY the 12-root
  note-script allowlist …"); the demonstration edit was then reverted and the full suite
  re-ran green with identical counts (§4).
- **Re-confirmations** (the first run's non-STOP escalation companions): S12 freeze/unfreeze
  and S24 stock roots hold with their 2026-07-13 ratifications (CDR-1 §6); the
  `get_authority` read-only bounding test EXISTS and is green
  (`get_authority_is_read_only_on_the_account` — the first walk's doc-backed gap is closed);
  the 62-root callable-surface pin is intact (`production_account_callable_surface_is_frozen`);
  the S13 `has_procedure` disposition unchanged; the S16 attester-commitment
  CHANGED-RECONCILED argument re-confirmed (Circle-wire ingress byte-identical). The
  `DOM_PAUSER.admin_role = DOM_MANAGER` build seed (`seeded_dom_roles_rbac`) and the
  grant/revoke rotation seam are intact (`shipped_delegation_reads_back`,
  `dom_manager_grants_pauser_then_new_pauser_halts_mint`,
  `dom_manager_revokes_pauser_then_pause_rejects` — all green).
- **HUMAN RATIFICATION (2026-07-14, round-2 gate)** — CIR-STATE-7 + CIR-ADMIN-3 = HOLDS,
  recorded verbatim: *"behavior is correct, the S2 divergence is operator-approved, the seams
  are individually tested, and the composition is ORTHOGONAL STORAGE (owner slot vs
  role_config — independent). This does NOT block the implementation→main engineer PR."* The
  conformance verdicts are NOT re-opened; the combined-seam test is the scheduled deferred
  slice `TASK-S2-ADMIN-RESEAT-TEST` (§6 ledger).
- **SCOPE of the restored owner backstop (the ratified S2 divergence — stated, not hidden):**
  the owner's RBAC anchor is its seeded `ADMIN` MEMBERSHIP, which is ACCOUNT-BOUND — it does
  NOT auto-follow `transfer_ownership`/`accept_ownership`; the ratified rotation runbook
  re-seats it (grant-new/revoke-old by an ADMIN member; operator-approved 2026-07-13, map §10
  decision 2, `builder.rs` KNOWN DIVERGENCE doc). Until that runbook leg runs, the new owner
  holds the owner-gated surfaces but not RBAC administration. The S2 row mandated "document and
  test": documented in both mirrors + the spec this pass; the combined transfer→ADMIN-rotation
  TEST cannot land inside this frozen-behaviour, identical-pass-count pass — it is the
  ratified, NAMED deferred slice `TASK-S2-ADMIN-RESEAT-TEST` (§6 ledger; trigger: before the
  internal MASM security audit; §5 item 8 RESOLVED).
- **The PARKED (unit-unbuilt) set — 24 ids + 5 worst-leg split ids** (listener, monitoring,
  ops SOPs/runbooks, external audit; §7b ledger) are carried-but-UNDISCHARGED obligations of
  unbuilt program units — truthfully excluded from HOLDS; unchanged by the migration and by
  this re-run.
- The 5 `CHANGED-RECONCILED` rows reduce to the operator-ratified **S16** delta (CIR-STATE-4,
  MC-MINT-1), the ratified S21-flip admin-surface change (MC-ADM-1..5), and the two
  register-row-text reconciliations (IMPL-DEV-1, IMPL-DEV-23) — every one resolved by an
  EXISTING human ratification; confirm-and-cite only (§5).
- **New-capability sweep** (CDR-1 §6): every v16-introduced capability resolves to bounding
  tests + an existing human ratification — including the S21 delegation-transition capability,
  now REMOVED at the source. The sweep's one residue (the S2 combined transfer→ADMIN-rotation
  test) is RESOLVED by the 2026-07-14 ratification as the scheduled deferred slice
  `TASK-S2-ADMIN-RESEAT-TEST` (§5 item 8, §6 ledger).
- **Parked-RIV ledger** (CDR-1 §7): every id whose obligation includes the real-node leg is
  explicitly marked "conformance INHERITED from the v15 LNV record (LNV-1..5, 12/12);
  re-validation trigger: the v16-alpha `miden-client` (+node) ships" — time-boxed, with the
  MockChain twin green at v16 in every case.

## 2. CDR-2 — doc & comment reconciliation (verdict: PASS)

Full record: `V16-DOC-DELTA.md`. Because the first run's branch never merged, its corrections
had to be re-landed here: **16 first-walk corrections re-applied verbatim** (the S16 prose
inversions in ENCODING-SPEC/GLOSSARY/README and six Rust comment/message sites, the README
validation-harness PARKED rewrite, 3 gate-hygiene rustdoc-link fixes, the DOCS-INVENTORY
completeness rows), **9 new-this-base gate-hygiene rustdoc-link fixes** (PR #17's
`builder.rs` doc + the relayer idempotency module — the doc gate was not clean at this
re-run's baseline), **6 re-run-specific corrections** (the post-flip `role_admin.rs`
module-doc grounding — the seed cite re-anchored to alpha.2 `rbac.masm:196-211` and the
"never stripped" claim grounded in the note-removal freeze; the FAUCET-SPEC §5 Roles v16
paragraph; the GLOSSARY IMPL-DEV renumber + register-row mirror-in; the migration-map
renumber annotations; the builder.rs allowlist row-label comment tidy — sweep-up item 2,
comment-only), **5 S21 surface groups verified already-corrected by PR #17** (no edit), and
**7 round-2 audit repairs** (V16-DOC-DELTA §2d: the relayer's "allowlist is keyed by the
33-byte key" phrasings — `mint_note.rs`, `error.rs`, `mint_note_boundaries.rs`,
`mint_support/mod.rs` — corrected to the DC-3 commitment-derivation statement, plus the
pre-flip `f5_admin_notes.rs` section row labels 13/11/12 → 12/10/11). Every §1 grep is now a
LITERAL runnable command with the three disclosed exclusions encoded as `--exclude-dir` flags
(no hand-applied filters), and the grep set gained the "keyed by" + row-label patterns.
Key adjudications:

- The first walk's own "conditional backstop / escalated STOP" caveat wording would be STALE
  on this base — it was NOT re-applied; the replacements state the post-flip frozen-graph
  reality. A dedicated grep confirms no escalation-era wording survives anywhere in the tree.
- The predicted "`assert_not_paused` runs first" staleness remains adjudicated NOT stale
  (custom mint's own pause gate runs first, `xreserve_mint.masm:113-118`; the stock burn
  wrapper checks pause first, alpha.2 `policy_manager.masm:357-358`).
- New surface since the first run: the merged relayer slices' `RIV-ADVICE-KEY.md` retains
  v15-era shape figures under an explicit up-front v16 disclaimer — adjudicated
  verified-current (a reconciliation record deliberately preserving its original finding text).
- `docs/governing/*` untouched; golden vectors untouched; the migration map's narrative
  untouched except the four bracketed `[renumbered → …]` cross-reference annotations required
  by the CDR-3 numbering reconciliation.

## 3. CDR-3 — deviation-register reconciliation (verdict: PASS)

Register: `usdcx-cleanup/07-implementation-readiness/IMPLEMENTATION-DEVIATION-REGISTER.md`
(planning tree — in scope for accuracy edits). The first run's register edits did not persist
(they were rolled back with the pre-flip escalation wording); this re-run redid the
reconciliation from scratch against `076a720`:

1. **IMPL-DEV numbering reconciliation (sweep-up item 1 — the mirrors now AGREE).** The
   register's numbering is CANONICAL (it is the older, Circle-facing legal record). Canonical
   scheme: **21 = fee reject · 22 = renounce omission · 23 = RBAC vs address slots · 24 =
   set_role_admin note removal (PR #17, identical in both trees) · 25 = S12 freeze/unfreeze ·
   26 = S24 stock roots**. Old→new mapping: repo-GLOSSARY migration-time "IMPL-DEV-21" (S12)
   → **IMPL-DEV-25**; "IMPL-DEV-22" (S24) → **IMPL-DEV-26**. Applied in BOTH mirrors: the repo
   GLOSSARY table renumbered (back-pointers name the migration-time ids) and rows 21/22/23
   mirrored IN; the register gained rows 24/25/26; the migration map's four migration-time
   pointers carry bracketed renumber annotations. `git grep` for each IMPL-DEV id now resolves
   to the same row everywhere; no code references the renumbered ids (grep-verified — code
   references only IMPL-DEV-1/7/12/20/24).
2. **Cite re-anchoring** — every register "what shipped" cite re-resolved against `076a720`
   (a dedicated verification pass walked all ~40 code citations); 16 stale line refs
   re-anchored (v15-era `rbac.masm:314-333` → alpha.2 `:196-211`, `access.rs:9` → `:10-11`,
   `xreserve_mint.masm:283/350-352/357` → `:113-118/:192-194/:199-201`, `error.rs`,
   `pause_admin.masm`, `min_burn_admin.masm`, `domain_config.masm`, `attester_admin.masm`,
   `constant_parity.rs`, `builder.rs`, `policy_manager.masm`, `attestation.rs`/
   `attestation_verify.masm`, and the IMPL-DEV-22 root count 13 → 12). Per-row resolution walk:
   CDR-1 §5.
3. **Stale-claim corrections in IMPL-DEV-1** — its v15 claims ("`is_paused` is
   FungibleFaucet-installed @ v0.15.3", "`set_role_admin` stays owner-only; `DOM_MANAGER`
   stays owner-administered") now state the #2944 `Pausable` provenance and the S21 flip
   (effective-admin gate + note REMOVED → graph frozen, → IMPL-DEV-24).
4. **IMPL-DEV-21 (fee) re-pegged** — the ratified deferral recorded (human 2026-07-14;
   fail-loud reject IS the MVP contract; mainnet-gated, P2) and the Q-MIN-2 mischaracterization
   corrected to the pending **Q-FEE-MVP** (sweep-up confirmation: the repo GLOSSARY already
   carried the F2/CIR-FEE-2/Q-FEE-MVP records from PR #17 — confirmed consistent).
5. **IMPL-DEV-23 rewritten** — the "owner backstop unbreakable" premise recorded as proven
   FALSE and the acceptance REVERSED (S21 flip); the row now points at IMPL-DEV-24 and the
   TIGHTENED Q-ADMIN-RBAC-EQUIV (both sides fixed-graph + membership-only), AND carries the
   ratified S2 companion in full: `ADMIN` membership is ACCOUNT-BOUND across ownership
   transfer (rotation-runbook re-seat; the mandated combined test recorded as an OUTSTANDING
   debt). The same S2 caveat is mirrored in the repo GLOSSARY IMPL-DEV-23 and the FAUCET-SPEC
   §5 Roles paragraph. IMPL-DEV-22's Deviation cell no longer claims a current 13-root
   allowlist (13 at the 2026-07-10 ratification, 12 since the flip — both cells now agree).
   The stale "unbreakable"/"upstream-forced" claims in `DECISION-RENOUNCE-ROLE-OMISSION.md`'s
   v16 UPDATE are annotated with an explicit ⚠️⚠️ SUPERSEDED block (the ratified historical
   text is preserved, the retracted claims are enumerated).
6. **v16 rows added** — **IMPL-DEV-24** (the removal — enforcement tests, rationale, the
   2026-07-14 ratification, FYI-only Circle routing), **IMPL-DEV-25** (S12), **IMPL-DEV-26**
   (S24 incl. the executed `get_authority` read-only proof), each carrying its ratification
   and bounding tests.
7. **IMPL-DEV-6 extended** — the S16 preimage change (33B/9-felt → affine-16) recorded in the
   row with the operator-approved DC-2/DC-3 supersession framing (Circle-wire ingress
   unchanged).
8. **IMPL-DEV-12 closed** — the stale "15-byte region" message is fixed in the shipped code
   (`xreserve/encoding/error.rs:57-62`, regression-pinned `account_id.rs:179-185`); status now
   "✅ resolved — message fixed (verified at v16)". Action items refreshed accordingly.
9. **Mirror into the repo**: the repo `docs/spec/GLOSSARY.md` IMPL-DEV table now carries
   register-aligned rows **1, 2, 3, 4, 6, 7, 8, 12, 16, 20, 21, 22, 23, 24, 25, 26**
   (`docs/spec/GLOSSARY.md:250-265`) — every register row referenced in this repo is present
   under the SAME number, and every v16 register row (21-26) is mirrored.

**Cite-resolution check:** every register "what shipped" line-ref resolves to real v16 code
(walked in CDR-1 §5); every v16-relevant register row is present in the repo GLOSSARY IMPL-DEV
table; the IMPL-DEV numbering agrees across register and repo GLOSSARY. PASS.

## 4. Verification transcript (frozen behaviour + gates)

All commands run at the repo root on `cdr/v16-verify`; exit codes captured directly (no
masking pipes — each command's output redirected whole to a log, `$?` read immediately).

```
Phase-0 baseline (the cdrfix base, before any reconciliation edit):
cargo test --locked -p xusdc-encoding --release          → exit 0   434 passed / 0 failed / 0 ignored
cargo test --locked -p xreserve-deposit-relayer --release → exit 0  323 passed / 0 failed / 0 ignored

After ALL reconciliation edits (incl. the reverted non-vacuity demonstration):
cargo test --locked -p xusdc-encoding --release          → exit 0   434 passed / 0 failed / 0 ignored   (IDENTICAL)
cargo test --locked -p xreserve-deposit-relayer --release → exit 0  323 passed / 0 failed / 0 ignored   (IDENTICAL)
cargo fmt --all -- --check                               → exit 0
cargo clippy --workspace --locked -- -D warnings         → exit 0
cargo doc --no-deps --workspace --locked                 → exit 0   0 warnings
```

- Pass counts IDENTICAL to baseline → no reconciliation edit perturbed runtime. (Counts grew
  from the FIRST run's 430/197 because PR #17 added the removal-enforcement tests and the
  merged relayer R4/R5 slices added their suites — a base change, not a this-pass change.)
- The non-vacuity demonstration (RED with the former root re-added: 2 failed —
  `set_role_admin_is_unreachable_from_every_allowlisted_note`,
  `set_role_admin_former_note_root_is_not_admissible_via_either_allowlist`) was fully
  reverted before the final green run; the diff carries no trace of it.
- `cargo doc` gate is genuinely green: the first walk's 3 relayer rustdoc-link warnings were
  re-fixed AND the nine private-item-link warnings this base added (one via PR #17's
  `builder.rs` doc, eight via the merged relayer idempotency module) are fixed this pass
  (V16-DOC-DELTA §2a gate-hygiene table) — the gate was NOT clean at this re-run's baseline
  and is not explained away.
- Diff surface: docs/spec/{GLOSSARY, FAUCET-, ENCODING-COMPONENT-SPEC}.md, README.md,
  docs/MIGRATION-V16-ALPHA2.md (4 bracketed renumber annotations only),
  docs/reconciliation/* (this packet), comment/message-only edits in
  `crates/xusdc-encoding` (src + tests) and `crates/xreserve-deposit-relayer` (src doc-comment
  sites incl. `miden/mint_note.rs`, `error.rs`, the idempotency doc-links; 4 test comment
  sites), and the planning-tree register + decision-doc annotation. Zero
  `.masm` files, zero constants, zero test expectations or inputs, zero golden vectors, zero
  `docs/governing/*`, zero edits to the parked `crates/xusdc-validation` (byte-intact per R1).

## 5. NEEDS-HUMAN (ratification/confirmation items — NOT self-ratified here)

The two decisions that resolved the prior STOPs are ALREADY human-ratified (2026-07-14); per
the re-run charter they are **confirmed-and-cited, not re-opened**. What remains for the human
is confirmation-grade, not decision-grade:

| # | Item | Status | What the human is asked to do |
|---|---|---|---|
| 1 | **The S21 flip resolution** (CIR-ADMIN-3, CIR-STATE-7 → HOLDS; capability removed; this packet's re-derivation incl. the RED non-vacuity re-demonstration) | RATIFIED 2026-07-14 (`DECISION-SETROLEADMIN-NOTE-REMOVAL.md`) — independently reproduced here | CONFIRM the re-derivation matches the ratified decision (12 roots, seed intact, rejection proven, records aligned) |
| 2 | **The CIR-FEE-2 ratified deferral** (fail-loud MVP contract; mainnet-gated; Q-FEE-MVP peg) | RATIFIED 2026-07-14 — register/GLOSSARY records confirmed consistent this run | CONFIRM; the Circle-facing Q-FEE-MVP question remains orchestrator-owned and OPEN |
| 3 | **S16 CHANGED-RECONCILED argument** (CIR-STATE-4, MC-MINT-1): attester-commitment preimage 33B/9-felt → affine-16; Circle-wire inputs byte-identical | operator-APPROVED 2026-07-13 (map §10 item 1) | CONFIRM at Stage-2 that the migration-gate approval covers the re-walk's re-statement (no new decision) |
| 4 | **The IMPL-DEV numbering reconciliation** (register canonical; GLOSSARY 21/22 → 25/26; rows 21-26 mirrored; map annotations) | done this pass — an editorial de-collision, ratified content carried VERBATIM under the canonical ids | RATIFY the renumber (the register is the legal-settlement record; its numbering was treated as canonical per the orchestrator's directive) |
| 5 | **Register accuracy edits** (§3 items 2-8: cite re-anchors, IMPL-DEV-1/23 corrections, the renounce-decision SUPERSEDED annotation, IMPL-DEV-6 S16 note, IMPL-DEV-12 closure, rows 24/25/26) | done this pass — records-accuracy; no disposition invented (every disposition traces to an existing ratification) | RATIFY (the register header calls itself settle-ready; accuracy edits deserve explicit sign-off) |
| 6 | **Parked-RIV acceptance** (CDR-1 §7a): the real-node conformance legs ride the v15 LNV record until the v16 client ships | explicit + time-boxed | ACCEPT the parking window (or direct an earlier partial re-run) |
| 7 | **The verdict-vocabulary mapping** (CDR-1 vocabulary note + §7b): later-unit obligations classified PARKED (unit-unbuilt); split rows per-leg, tallied under the worst leg | **✅ RESOLVED — RATIFIED (human, 2026-07-14 round-2 gate), CONDITIONALLY.** Condition (1) satisfied this pass: every §7b row names its owning unit + re-validation trigger. Condition (2) is a Round-F obligation: spot-check a §7b sample — any row that is actually a CURRENT-FAUCET gap is NOT PARKED and must be reclassified and surfaced | Round-F executes the spot-check; no further human action unless it finds a mislabeled row |
| 8 | **The S2 combined transfer→ADMIN-rotation test** — the ratified S2 divergence's mandated "document and test" test leg | **✅ RESOLVED — RATIFIED (human, 2026-07-14 round-2 gate): CIR-STATE-7/CIR-ADMIN-3 stay HOLDS (orthogonal-storage rationale, recorded verbatim in CDR-1); the test is the NAMED deferred slice `TASK-S2-ADMIN-RESEAT-TEST`** (§6 ledger; trigger: must land BEFORE the internal MASM security audit; sequence specified in the ledger — grant-new BEFORE revoke-old, no zero-ADMIN window) | none — the slice is scheduled; the trigger gates the internal MASM security audit |

## 6. Residual risk + observations

1. **Alpha pre-release** (map §12): `0.16.0-alpha.2` APIs may move before v0.16.0 final; a
   later bump re-runs a lighter pass of the migration map AND of this CDR (the S-row → grep
   derivation in `V16-DOC-DELTA.md` §1 is reusable as-is).
2. **The real-node gap is the biggest inherited risk**: every RIV row rides v15 evidence.
   Mitigated by MockChain twins green at v16 + source-verified MockChain sufficiency (map §8);
   closed only by the v16 LNV re-run (trigger explicit, §5 item 6). Note the LNV re-run's
   admin-suite row (LNV row C) must be UPDATED at re-enable time for the 12-note admin
   surface (no set_role_admin drill; the parked crate still encodes the v15 13-note surface).
3. **DEFERRED-SLICE LEDGER** (the named follow-up slices this gate spawns, each with its
   trigger — per the 2026-07-14 round-2 human ratification):
   | Slice | What it delivers | Trigger |
   |---|---|---|
   | `TASK-CONFORMANCE-MANIFEST` | the machine-checkable conformance manifest (CDR phase 2; deliberately NOT built in this run per the RE-RUN sweep-up item 3 — unreachability is already ENFORCED by the removal-enforcement tests, re-adding the note → RED, re-demonstrated this run, plus the 12-root tripwire; CDR-1's id → evidence rows are its seed) | after this CDR PASSes |
   | `TASK-S2-ADMIN-RESEAT-TEST` | the combined transfer→ADMIN-re-seat proof (human-directed, 2026-07-14): `transfer_ownership` → new owner LACKS `ADMIN` → old owner (still ADMIN) grants `ADMIN` to the new owner (**grant-new BEFORE revoke-old — NO zero-ADMIN window**) → revoke old owner → new owner has full authority, old owner de-authorized, and at NO point are there zero ADMIN members | **must land BEFORE the internal MASM security audit** |
4. **Repo `CLAUDE.md`/`AGENTS.md` stale on the relayer** (out of CDR scope — pre-v16
   staleness, flagged, not edited): both still say the deposit relayer "is not in this
   repository" and omit `crates/xreserve-deposit-relayer` from the Layout/gate sections, while
   the crate exists here with 323 green tests. Recommend a separate onboarding-doc refresh
   (CLAUDE.md is canonical; copy over AGENTS.md).
5. **`docs/governing/` mirrors carry v15 shapes by design** (DC-2/DC-3 rows of
   `CANONICAL-OWNERSHIP-MAP.md`, the V15 baseline ledger): NOT edited per the read-only rule
   (the ownership map's S21-flip annotation was added by PR #17, not this pass); the binding
   v16 supersession record is the map's S16 row. A separate mirror-refresh may re-mirror them
   after v0.16.0 final.
6. **Planning-tree sync**: this pass edited two gitignored planning-tree records directly (the
   register; the renounce decision's SUPERSEDED annotation) per the CDR-3 charter. They live
   outside this repo's diff — the orchestrator should treat them as part of this round's
   review surface.

## 7. Final status

**PASS.**

- **CDR-1: zero STOP rows** — 149 spine ids walked (+2 supplemental), zero blanks; the three
  prior STOP rows
  independently re-derive to HOLDS against `076a720` (the ratified S21 removal is
  machine-enforced and re-proven non-vacuous; the CIR-FEE-2 deferral is recorded and
  ratified); every v16-introduced capability is bounded + ratified (the S2 combined-seam test
  directed as §5 item 8); the unit-unbuilt PARKED debt is explicit and unchanged.
- **CDR-2: swept and grep-clean** — the first walk's stranded corrections re-landed, the
  post-flip surfaces corrected or verified, every remaining grep hit adjudicated in-table.
- **CDR-3: the register resolves against v16** — cites re-anchored, stale claims corrected,
  v16 rows added, the fee re-peg and the S21 reversal recorded, and the IMPL-DEV numbering
  reconciled across both mirrors (register canonical).
- **Frozen behaviour proven** — 434 + 323, counts identical before/after, all gates exit 0.

The round-2 gate's three residual NEEDS-HUMAN items are now **HUMAN-RATIFIED (2026-07-14)**
and recorded: CIR-STATE-7/CIR-ADMIN-3 = HOLDS (orthogonal-storage rationale, verbatim in
CDR-1), the §7b PARKED mapping (conditional — condition 1 satisfied this pass, condition 2 is
Round-F's §7b spot-check), and the owner-backstop comment qualifications (applied,
comment-only, counts identical). The remaining §5 items are confirmations of already-ratified
decisions plus records-accuracy sign-off. No undecided conformance question remains. Per the
ratification's routing: Round-F re-audits (incl. the §7b spot-check + frozen-behaviour
identical pass count) → CDR PASS → the **human** opens the implementation→main engineer PR;
the deferred slices run per the §6 ledger (`TASK-CONFORMANCE-MANIFEST` after the PASS;
`TASK-S2-ADMIN-RESEAT-TEST` before the internal MASM security audit).
