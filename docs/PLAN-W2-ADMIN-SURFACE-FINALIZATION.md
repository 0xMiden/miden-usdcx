# Admin-surface finalization — removing `Ownable2Step`, and the `RbacActionNote` question: integration plan

**Status:** RATIFIED 2026-07-31 and IMPLEMENTED. Both open decisions were resolved as recorded in
`§8`: **D-OWN-GATE = (a)** move the identifier initializer's gate to `authority::assert_authorized`,
and **D-RBAC-FORM = (a) ADOPT** the stock `RbacActionNote`. Final numbers as built: callable surface
**70**, note-script allowlist **9**. The implementation and its effects proof are in
`crates/xusdc-encoding/tests/w2admin_surface_finalization.rs`; the Phase-1 grounding harness that
produced the evidence below was replaced by it.
**Base:** `feat/w2-admin-config-notes` @ `a92edf7` (PR #50 head, UNMERGED). If #50 changes in review,
rebase and re-verify the deltas before Phase 2.
**Protocol pin read for every claim below:** `0xMiden/protocol` @ `4971ec4b38fb1f54e8f73969e6da81ee0cbf850c`,
resolved locally at `~/.cargo/git/checkouts/protocol-4ada628cdf2b267c/4971ec4`.
**Phase-1 grounding evidence:** a 17-test harness on TEST-ONLY compositions, which proved the
§3.2 finding and enumerated the §4.1 capability exposure by execution. It has served its purpose and
is superseded by the shipped suite named above.

---

## 0 · One-paragraph summary, and the one thing that blocks the ratified scope

Two changes are on the table. **D-OWN** (already human-DECIDED = REMOVE): drop the `Ownable2Step`
component, its two ownership notes and their factories, leaving pure role-based administration.
**D-RBAC-FORM** (OPEN, the human's call): replace the faucet's two bespoke `grant_role` /
`revoke_role` notes with the stock `RbacActionNote`.

D-OWN was scoped as a pure subtraction — five callable rows out, two allowlist roots out, no new
component, no MASM change, because "the owner-gated setters already resolve through the RBAC `ADMIN`
role". **That premise holds for every setter except one.**
`xreserve::identifier_init::init_identifier` does not go through the account-wide authority at
all: it calls `exec.ownable2step::assert_sender_is_owner` directly
(`asm/standards/xreserve/identifier_init.masm:83`). Drop the component and that procedure's first
instruction reads a storage slot the account no longer declares, so the identifier-init note traps
in the kernel and the faucet can never be initialized. This is executed, not argued:
`the_identifier_initializer_traps_without_the_ownership_component` fails with
`ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME`, while the control leg
`the_identifier_initializer_lands_on_the_shipped_composition` shows the same note landing on the
shipped faucet. **So D-OWN costs one authorized MASM edit (§3.2) and two re-pinned roots — not
zero.** That is the only correction this plan makes to the ratified scope, and it needs an explicit
sign-off (D-OWN-GATE) before Phase 2.

Everything else in D-OWN is exactly as scoped: **−5 callable rows (75 → 70)** and **−2 allowlist
roots (12 → 10)**, both re-derived from the composition rather than counted by hand.

---

## 1 · What the pinned protocol actually gives us

Read at the pin, not inferred.

| Piece | Source at the pin | Shape that matters |
|---|---|---|
| `Ownable2Step` | `src/account/access/ownable2step.rs` | five callable procedures; **one** storage slot (`…::ownable2step::owner_config`), holding `[owner_suffix, owner_prefix, nominated_suffix, nominated_prefix]` |
| `authority::assert_authorized` | `asm/standards/access/authority.masm:113-172` | dispatches on the stored discriminator. The `OwnerControlled` branch `exec`s `ownable2step::assert_sender_is_owner` — **inlined into the `Authority` package**, so removing the `Ownable2Step` *component* does not break linking; under `RbacControlled` (our mode) the branch is simply never executed |
| `RbacActionNote` | `src/note/rbac_action.rs`, `asm/standards/notes/rbac_action.masm` | **ONE script root**, four selectors: `GRANT_ROLE=0`, `REVOKE_ROLE=1`, `SET_ROLE_ADMIN=2`, `RENOUNCE_ROLE=3` (`rbac_action.masm:21-24`, dispatch `:79-112`). All authorization is delegated to the called `rbac` procedures against the note sender (`:52-53`) |
| `rbac::set_role_admin` | `asm/standards/access/rbac.masm:158-173` | gated by `assert_sender_is_role_admin` on the **target role's current effective admin** (`:162`), resolved at `:430-442` (configured delegate, else the built-in `ADMIN`) |
| delegation exclusivity | `rbac.masm:20-22`, verbatim | "Delegation is exclusive: once a role's admin is delegated to another role, the `ADMIN` role no longer has any authority over it." |
| `rbac::renounce_role` | `rbac.masm:261-276` | **no admin gate at all**; the cleared account is hardwired to the note sender (`:265`). Traps `ERR_ACCOUNT_NOT_IN_ROLE` (via `set_membership_internal:546-548`) if the sender does not hold the role |
| `RoleBasedAccessControl::new` | `src/account/access/rbac.rs:156-164`, `:258-261` | cannot seed a delegated admin — the admin field is hard-zeroed at construction. This is why the hand-seeded component stays regardless of either decision |
| `AllowlistConfigNote` | `src/note/allowlist_config.rs` | **OUT OF SCOPE.** The faucet has no transfer allowlist; it must never enter the composition or the allowlist |

All of the `RbacActionNote` gating facts above were re-confirmed at the pin for this plan and match
the prior analysis (`RBACACTIONNOTE-ADOPTION-DOWNSIDES-2026-07-30.md`); nothing in that document is
contradicted here.

---

## 2 · Composition: before → after

Shipped today (`crates/xusdc-encoding/src/account/xreserve/builder/mod.rs:533-543`):

```
FungibleFaucet
Pausable::unpaused()
xreserve component            # attestation_verify, attester_admin, deposit_intent_parser,
                              # encoding, identifier_init, mint_policy
MinBurnAmount companion
BasicBlocklist companion
TokenPolicyManager
PausableManager
BlocklistManager
Ownable2Step::new(owner)      # <- D-OWN removes this line
seeded_dom_roles_rbac(...)
XReserveAdminAuthority        # Authority::RbacControlled
```

After D-OWN (both `RbacActionNote` branches share this component set):

```
FungibleFaucet                            unchanged
Pausable::unpaused()                      unchanged
xreserve component                        identifier_init GATE CHANGED (§3.2); every other module byte-identical
MinBurnAmount companion                   unchanged
BasicBlocklist companion                  unchanged
TokenPolicyManager                        unchanged
PausableManager                           unchanged
BlocklistManager                          unchanged
                                          Ownable2Step REMOVED  (−5 callable rows, −1 storage slot)
seeded_dom_roles_rbac(...)                unchanged
XReserveAdminAuthority                    unchanged
```

**No new component.** The two branches of D-RBAC-FORM differ ONLY in the note-script allowlist —
proven by `adopting_the_standard_role_note_costs_one_allowlist_root_and_no_surface`, which asserts
the two component sets have an identical callable surface.

---

## 3 · D-OWN — remove `Ownable2Step` (recommend AS RATIFIED, with the §3.2 gate)

### 3.1 The exact removal

| What leaves | Count | Evidence |
|---|---|---|
| `ownable2step::{accept_ownership, get_nominated_owner, get_owner, renounce_ownership, transfer_ownership}` | −5 callable rows | `the_ownership_component_contributes_exactly_five_callable_rows` reads them off the component |
| `…::ownable2step::owner_config` storage slot | −1 slot, and no other component declares it | `the_ownership_component_owns_exactly_one_slot_that_nothing_else_declares` |
| `XReserveTransferOwnershipNote` + `XReserveAcceptOwnershipNote` roots | −2 allowlist roots | `the_finalized_allowlist_is_the_shipped_one_minus_the_two_ownership_notes` |
| `asm/standards/notes/xreserve_{transfer,accept}_ownership_note.masm` + `src/note/xreserve_admin/ownership.rs` | 3 files deleted | Phase 3 |

Callable surface **75 → 70**, note-script allowlist **12 → 10**, both re-derived from a real
composition by `dropping_the_ownership_component_yields_exactly_seventy_callable_procedures`, which
additionally asserts the removal deletes those five rows **and nothing else** and introduces no new
row. Every surviving allowlist root is asserted byte-identical to its shipped root.

**Rotation after removal.** `ADMIN` membership is already account-bound and already does NOT follow
the owner slot (the known divergence documented in `builder/rbac_seed.rs` since the authority flip),
so removing the owner slot removes a handle that had already stopped carrying authority. Rotation is
`grant_role(ADMIN, new)` + `revoke_role(ADMIN, old)` — unchanged from today's runbook. What is
genuinely lost is the two-step nominate/accept handshake for that rotation: an `ADMIN` grant is
single-step and takes effect immediately. That is the substance of the D-OWN decision and it is
already ratified.

### 3.2 THE GATE — `init_identifier` gates on the owner slot directly

`asm/standards/xreserve/identifier_init.masm` is the only faucet-owned module that imports
`miden::standards::access::ownable2step`, and its first instruction is
`exec.ownable2step::assert_sender_is_owner` (`:83`). It never consults the account-wide authority,
so the D-1 flip left it untouched — the very reason the previous plan wrote "the procedures that
gate on the owner slot directly — `identifier_init`, `transfer_ownership`, `accept_ownership` —
keep the owner error".

Consequence, executed on a real chain: with the component dropped, the identifier-init note traps
`ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME` (the account has no `owner_config` slot to read), while the
same note sent by the same account lands on the shipped composition. A faucet whose identifier can
never be seeded is a faucet whose mint path can never accept a deposit intent — this is not a
cosmetic gap.

Options, for ratification as **D-OWN-GATE**:

- **(a) Move the gate to the account-wide authority (recommended).** Replace
  `exec.ownable2step::assert_sender_is_owner` with `exec.authority::assert_authorized`, exactly the
  shape `xreserve::attester_admin::set_attester` already uses (`attester_admin.masm:57`).
  `init_identifier` is `@account_procedure` and is entered by `call`, which is what
  `assert_authorized` requires for its `caller`-based role lookup. It carries no entry in the
  procedure-role map, so it resolves to `ADMIN` — **the same account** that holds the owner slot
  today. Identity preserved; the rejection error changes from `ERR_SENDER_NOT_OWNER` to
  `ERR_SENDER_LACKS_ROLE`, the same substitution the authority flip already made for every other
  setter.
  Cost: `::xreserve::identifier_init::init_identifier`'s MAST root moves, and with it the
  identifier-init note-script root (it binds transitively). `mint_root_surface.rs` pins **paths**,
  not hexes, so it stays green; `XRESERVE_IDENTIFIER_INIT_NOTE_SCRIPT_ROOT_HEX` must be
  re-materialized, and every re-materialized number called out in the diff.
- **(b) Keep `Ownable2Step` solely to serve this one gate.** Rejected as a recommendation: it
  forfeits the entire decision (the five rows and the slot stay) to preserve one deploy-time gate
  whose authorized identity does not change under (a).
- **(c) Drop `init_identifier`.** Out of the question — the identifier is the account-id fixpoint
  and the mint path's deposit-intent compare reads it.

**This is a MASM edit inside the frozen-adjacent xreserve component, so it is surfaced rather than
taken.** It touches no mint/burn/attestation/reserve procedure, no Circle-signed wire format and no
golden vector; `identifier_init` is deploy-time configuration. But it moves two pinned roots, so it
needs the human's explicit yes.

---

## 4 · D-RBAC-FORM — the OPEN decision (do NOT resolve in-loop)

`RbacActionNote` is **one script root carrying four actions**. Allowlisting is per root, so
admitting it admits all four. This is not a reading of the source, it is measured: all four actions
produce the same script root (`the_standard_role_note_is_one_root_for_all_four_actions`).

### 4.1 Branch (a) — ADOPT the stock note

Deltas on top of D-OWN: allowlist **10 → 9** (drop the two bespoke role notes, add the one stock
root); callable surface **unchanged at 70** (the note calls role procedures the account already
exposes). Both asserted by `adopting_the_standard_role_note_costs_one_allowlist_root_and_no_surface`.
Two MASM note scripts and their two Rust factories are deleted.

**What adoption preserves.** Rotation — the only admin action the faucet performs in normal
operation — is identical. `the_standard_note_grants_and_revokes_exactly_as_the_bespoke_notes_do`
executes a grant and a revoke of `DOM_PAUSER` through the stock note, sent by `DOM_MANAGER`, and
asserts the same membership word and the same member-count movements the bespoke notes produce.

**What adoption ADDS — the full capability enumeration, each item executed:**

| New capability | Mechanism at the pin | Demonstrated by |
|---|---|---|
| `set_role_admin` becomes reachable — the administrator graph stops being frozen | `rbac.masm:158-173`, gated on the target role's **current effective admin** | `adopting_the_standard_note_lets_a_delegated_admin_repoint_the_graph`: `DOM_MANAGER` re-points `role_config[DOM_PAUSER].admin_role` from itself to `BLK_MANAGER`, and the write lands |
| `ADMIN` is **locked out** of any exclusively-delegated role, so "only `ADMIN` may restructure" is inexpressible | delegation is exclusive (`rbac.masm:20-22`); the gate is the delegate, not `ADMIN` | `the_administrator_role_cannot_repoint_an_exclusively_delegated_role`: the owner/`ADMIN` account attempting the same re-point traps `ERR_SENDER_NOT_ROLE_ADMIN` |
| `renounce_role` becomes reachable — self-only, **ungated**, no administrator involved | `rbac.masm:261-276`, no `assert_sender_is_role_admin` | `adopting_the_standard_note_lets_a_holder_renounce_its_own_role`: the sole `DOM_PAUSER` clears its own membership and the role is left with zero members |
| the renounce **brick path** is real, not theoretical | an emptied role's capability is unreachable until an admin re-grants | `a_renounced_role_leaves_its_capability_unreachable`: after the renounce, the former pauser's pause note traps `ERR_SENDER_LACKS_ROLE` and the faucet stays unpaused |
| renounce takes **no target argument** at all | note storage is `[selector, role_symbol]` | `renounce_is_self_only_and_traps_for_a_non_holder` (also: a non-holder traps `ERR_ACCOUNT_NOT_IN_ROLE`) |

The sharpest reachable state, composing rows 1–3: a compromised `DOM_MANAGER` key can re-point
`DOM_PAUSER`'s admin at a role only the attacker holds, and `ADMIN` has no authority to grant,
revoke or re-point `DOM_PAUSER` afterwards. Under the frozen graph the same compromised key can only
add and remove `DOM_PAUSER` members — damaging, but reversible by `ADMIN`. Separately, a sole
`ADMIN` that renounces leaves the top of the administrator tree permanently empty.

### 4.2 Branch (b) — HOLD adoption

Keep the two bespoke notes; the administrator graph stays frozen at the build seed. Under (b) this
slice is D-OWN only: allowlist 10, surface 70, and the stock note stays inadmissible — executed by
`without_adoption_the_standard_role_note_is_rejected_at_the_allowlist`, where the auth component
rejects an `RbacActionNote` with `ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED` before either new
action can run.

### 4.3 The trade, stated plainly

Under (a) the frozen-graph guarantee is lost, `ADMIN` is locked out of the delegated subtree, and
self-renounce becomes reachable — **for zero member-rotation capability gained**, because grant and
revoke already cover every rotation the faucet performs (§4.1 measures that equivalence). The gain
is standardization: one stock root instead of two bespoke MASM scripts, two fewer files to audit.
This is a capability and Circle-conformance call (it reverses the frozen-graph design and touches
the administrator-equivalence question), so it belongs to the human and the reviewer meeting.
**The builder does not pick it.**

---

## 5 · Combined surface and allowlist deltas

Callable procedures (`account_callable_surface.rs::FROZEN_ACCOUNT_SURFACE`):

| Composition | xreserve | stock | total |
|---|---|---|---|
| shipped today | 11 | 64 | **75** |
| D-OWN only | 11 | 59 | **70** |
| D-OWN + adopt the stock note | 11 | 59 | **70** |

Note-script allowlist (`XReserveStablecoinBuilder::allowed_note_scripts`):

| Composition | roots | delta |
|---|---|---|
| shipped today | **12** | — |
| D-OWN only | **10** | −`transfer_ownership`, −`accept_ownership` |
| D-OWN + adopt the stock note | **9** | additionally −`grant_role`, −`revoke_role`, +`RbacActionNote` |

`AllowlistConfigNote::script_root()` stays absent in every branch, alongside the already-pinned
`NetworkAccountConfigNote` / `FeeSponsorshipNote` absences.

---

## 6 · Behavior preservation, action by action

| Action | Today | After (both branches) | Preserved? |
|---|---|---|---|
| mint / burn / attestation / reserve | — | **untouched** — no file on those paths is edited | **YES, byte-identical**; the frozen-core empty-diff proof is a Phase-4 gate |
| Circle-signed wire formats, golden vectors | — | untouched | **YES, byte-identical** |
| `set_attester` (`ADMIN`) | `assert_authorized` → RBAC, unmapped → `ADMIN` | identical | **YES** — executed without the ownership component by `the_administrator_gated_attester_setter_survives_the_removal` |
| pause / unpause (`DOM_PAUSER`) | `PausableManager` gated on `DOM_PAUSER` | identical | **YES** — executed by `the_role_gated_pause_action_survives_the_removal` |
| block / unblock (`BLK_MANAGER`) | `BlocklistManager` gated on `BLK_MANAGER` | identical — neither manager reads the owner slot | **YES** |
| `set_max_supply` / `set_min_burn_amount` / policy setters / `freeze` | `assert_authorized` → `ADMIN` | identical | **YES** |
| `init_identifier` | `ownable2step::assert_sender_is_owner`, `ERR_SENDER_NOT_OWNER` | **(D-OWN-GATE (a))** `authority::assert_authorized` → `ADMIN`, `ERR_SENDER_LACKS_ROLE` | **identity YES, error and root NO** — see §3.2 |
| ownership rotation | `transfer_ownership` → `accept_ownership`, two-step | grant/revoke on `ADMIN`, single-step | **NO, intended** — this is D-OWN |
| role rotation (grant / revoke) | two bespoke notes | **(a)** stock note, same effects · **(b)** unchanged | **YES** both branches (measured under (a)) |
| `set_role_admin` reachability | unreachable (no note allowlisted) | **(a) REACHABLE** · **(b)** unreachable | **(a) NO, intended-if-ratified** · **(b) YES** |
| `renounce_role` reachability | unreachable | **(a) REACHABLE** · **(b)** unreachable | **(a) NO, intended-if-ratified** · **(b) YES** |

Remaining note-script roots are unmoved except where a note is deliberately deleted, and — under
D-OWN-GATE (a) — the identifier-init root, which moves with the gate it wraps. The finalized
allowlist is asserted to be a strict subset of the shipped one, so nothing else can move silently.

---

## 7 · The grounding harness shipped with this plan (zero production change)

`crates/xusdc-encoding/tests/w2admin_surface_finalization_grounding.rs` (17 tests) proves the plan by
**building and executing** the proposed compositions on MockChain. It touches no shipped file:
`build_components`, the shipped allowlist and every production MAST root are read, never modified,
and the shipped faucet is the control leg. The compositions are assembled in
`crates/xusdc-encoding/tests/support/surface_finalization.rs` by filtering and re-wrapping what the
production builder already returns — the ownership-free allowlist is derived by SUBTRACTION from the
shipped set, so a surviving root cannot be silently re-materialized inside the harness.

Deleting both files leaves the shipped faucet byte-identical.

The harness is non-vacuous by construction: reverting the ownership filter or the allowlist swap
turns 7 of the 17 tests red, including the identifier-init trap, the 70-row count and every executed
capability demonstration.

---

## 8 · Decision points for ratification

| id | Question | Recommendation |
|---|---|---|
| **D-OWN** | Remove `Ownable2Step`: −5 callable rows (75 → 70), −2 allowlist roots (12 → 10), owner slot dropped, rotation becomes grant/revoke on `ADMIN`. | **Proceed as ratified.** Every delta is re-derived from a real composition (§3.1), and every administrator- and role-gated action is executed without the component. |
| **D-OWN-GATE** | `init_identifier` gates on the owner slot DIRECTLY, so the removal breaks it (§3.2, executed). Move its gate to `authority::assert_authorized` (→ `ADMIN`, same identity), accepting that its procedure root and its note-script root re-materialize? | **(a) move the gate.** The alternatives are keeping the component (forfeits D-OWN) or dropping the initializer (impossible). **NEW — this is the one correction to the ratified scope and needs an explicit yes.** |
| **D-RBAC-FORM** | Adopt the stock `RbacActionNote` (one root, four actions) in place of the two bespoke role notes? | **NOT the builder's call.** Both branches are costed and executed (§4). For the record, the evidence supports (b) HOLD: (a) buys standardization and loses the frozen graph plus `ADMIN`'s authority over the delegated subtree plus renounce-freedom, for zero rotation capability gained. Human + reviewer-meeting decision. |
| **D-ID** | The finalized faucet gets a new account id (the ownership slot leaves the initial storage commitment). | **Accepted, already.** One pre-deploy composition: the removal and any note change land together, so only the final composition is ever deployed. |

`DEV-*` / `Q-*` items referenced anywhere here stay **OPEN and Circle-owned**; nothing in this plan
marks one approved.

---

## 9 · Phase-3 impact list (what the implementation touches)

Deleted: `asm/standards/notes/xreserve_{transfer,accept}_ownership_note.masm`,
`crates/xusdc-encoding/src/note/xreserve_admin/ownership.rs` (+ its `pub use`), and — under
D-RBAC-FORM (a) — `asm/standards/notes/xreserve_{grant,revoke}_role_note.masm` and
`src/note/xreserve_admin/roles.rs`.

Edited: `builder/mod.rs` (drop the `Ownable2Step` push + its doc paragraphs),
`builder/network_auth.rs` (the allowlist rows + the prose that enumerates them),
`builder/rbac_seed.rs` (prose only), and — under D-OWN-GATE (a) —
`asm/standards/xreserve/identifier_init.masm` (the gate, its `use` line and its `Panics if` block).

Re-materialized pins, each to be called out explicitly in the diff, never slipped:
`account_callable_surface.rs` (75 → 70 rows), `surface_count_prose_conformance.rs` (the
`(11, 64, 75, 12)` tuple and the superseded-token list), the allowlist size in every suite that
asserts it (`config_note_absence.rs`, `f5_network_account_auth.rs`, `s12_expiration_tx_script_allowlist.rs`,
`account_surface_unreachable.rs`, `wave1_recomposition.rs`, `support/w2admin.rs`'s ratified
constants), and — under D-OWN-GATE (a) — `XRESERVE_IDENTIFIER_INIT_NOTE_SCRIPT_ROOT_HEX` plus its
`constant_parity` / `f5_admin_notes.rs` rows.

Suites that lose or rewrite content: `ownable2step_admin.rs` (deleted with the component),
the ownership legs of `f5_admin_notes.rs` and `account_surface_unreachable.rs`, the
`err_sender_not_owner()` expectations in `identifier_init.rs` / `assembled_faucet_e2e.rs` (they
become the role error), and `support/mod.rs`'s `err_sender_not_owner` helper (unused once the last
direct owner gate is gone). `mint_root_surface.rs` pins paths, not hexes, so it stays as is.

Out of the workspace but not out of scope for the record: `crates/xusdc-validation/src/sanity/{admin,admin_restore}.rs`
drive the ownership notes. The crate is PARKED (excluded from `workspace.members`), so it does not
build in the gate; its un-parking checklist must carry this removal.

Docs to follow the numbers: `docs/spec/FAUCET-COMPONENT-SPEC.md`, `docs/spec/GLOSSARY.md`,
`docs/REQUIREMENTS-TRACEABILITY.md`, `docs/DOCS-INVENTORY.md`.

---

## 10 · Phases after ratification

- **Phase 2 — RED.** Move the executed legs of §7 onto the ratified composition: the surface and
  allowlist pins at their new values, the admin-effects suite without the ownership component, the
  identifier-init suite on its new gate, and (branch (a) only) the role-note effects. Red before the
  edit. The frozen-core tripwires stay green and UNEDITED throughout.
- **Phase 3 — implement** the ratified branch per §9, re-materializing every pin listed there.
- **Phase 4 — verify.** `cargo build --workspace --locked --release`;
  `cargo test -p xusdc-encoding --release --locked` (incl. `--test masm_structure`), 0 failed;
  `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`;
  plus the frozen-core empty-diff proof (`git diff` restricted to the mint/burn/attestation/reserve
  MASM and the golden vectors must be EMPTY).

---

## 11 · Open items, none blocking the plan

1. The finalized faucet's account id is not computable until the composition is built — expected.
2. Under D-OWN-GATE (a), the two moved roots must be independently re-derived by the auditor from a
   fresh build, not copied from this plan.
3. `RoleBasedAccessControl` still cannot seed a delegated admin at construction, which is the sole
   reason the hand-seeded component exists. Worth an upstream issue either way.
4. The upstream question behind D-RBAC-FORM stands: can the stock note expose grant/revoke without
   `set_role_admin` and `renounce` (per-selector gating, or a grant/revoke-only variant)? A yes turns
   branch (a) into a clean win with no capability cost, and the decision should be revisited then.


---

## 12 · Ratified outcome and what shipped

| id | Ratified | Shipped |
|---|---|---|
| **D-OWN** | REMOVE `Ownable2Step` | component, its 5 callable rows and its owner slot gone; the two ownership note scripts and `note/xreserve_admin/ownership.rs` deleted |
| **D-OWN-GATE** | (a) move the gate | `identifier_init.masm` now `exec.authority::assert_authorized` → `ADMIN`; trap moved `ERR_SENDER_NOT_OWNER` → `ERR_SENDER_LACKS_ROLE` |
| **D-RBAC-FORM** | (a) ADOPT the stock note | the two bespoke role note scripts and `note/xreserve_admin/roles.rs` deleted; `RbacActionNote::script_root()` allowlisted; the role-admin graph is now runtime-mutable and self-renounce is reachable, both accepted |
| **D-ID** | accepted | the composition change re-derives the account id; one pre-deploy composition |

**Re-materialized pins, each called out rather than slipped:**

| Pin | From | To |
|---|---|---|
| `account_callable_surface.rs::FROZEN_ACCOUNT_SURFACE` | 75 rows (11 xreserve + 64 stock) | **70** rows (11 xreserve + **59** stock) |
| `XReserveStablecoinBuilder::allowed_note_scripts` | 12 roots | **9** roots |
| `surface_count_prose_conformance.rs` tuple | `(11, 64, 75, 12)` | **`(11, 59, 70, 9)`** |
| `XRESERVE_IDENTIFIER_INIT_NOTE_SCRIPT_ROOT_HEX` | `0xaf63dbce…416c348b` | **`0x440573e0c726f4bdade6df0de040bcbdaa08912c87e6df2da846bf050c8bd7f2`** |
| `builder_api.rs` component-count pin | 11 components | **10** components |
| `support/w2admin.rs` ratified constants | 12 / 75 | **9 / 70** |

The `init_identifier` procedure root moved with its gate (that is what carries the note-script root
above); `mint_root_surface.rs` pins paths, not hexes, and stayed green. No other note-script root
moved — `constant_parity` and `f5_admin_notes` confirm the remaining pins unchanged.

**Suites reworked rather than deleted:** `role_admin.rs`, `f5_admin_notes.rs` and
`assembled_faucet_e2e.rs` now drive grant and revoke through the stock role-action note, keeping
every capability-seam assertion. Deleted as obsolete: `ownable2step_admin.rs`, the ownership and
former-`set_role_admin` sections of `f5_admin_notes.rs`, and the `set_role_admin`-unreachability
section of `account_surface_unreachable.rs` (that procedure is reachable now, by ratified decision).

**Phase-4 gates, all green:** `cargo build --workspace --locked --release`;
`cargo test -p xusdc-encoding --release --locked` (43 binaries, 0 failed) incl.
`--test masm_structure` (52 passed); `cargo clippy --workspace --all-targets --locked -- -D warnings`;
`cargo fmt --all -- --check`; and the frozen-core empty-diff proof — `git status` over the
mint/burn/attestation/reserve MASM, the encoding crate's `xreserve` module, the mint/burn note
codecs and the golden vectors is EMPTY.

### 12.1 · Follow-up landed with the implementation

**The administrator seam is driven, not described.** `ADMIN` is now the account's only authority
handle, so the sequence that replaces the ownership handshake is pinned end to end in
`tests/w2admin_surface_finalization.rs`, capability-first at every step:
`the_administrator_role_hands_over_by_grant_then_revoke` (the successor is refused, is granted
`ADMIN`, then lands an administrator-gated write; the predecessor is revoked and its write stops
landing), `only_an_administrator_can_grant_the_administrator_role` (the role administers itself, so
the handover cannot be hijacked), and
`a_sole_administrator_that_renounces_leaves_the_authority_tree_empty` — the accepted catastrophic
boundary, executed: the role empties, every administrator-gated procedure dies with it, no one can
grant it back, and recovery is a redeploy. That test also shows what survives: a role delegated away
(`DOM_PAUSER`, governed by `DOM_MANAGER`) is untouched, which is what exclusive delegation buys.

**Governing docs follow the change** (§9's list, discharged): `docs/spec/FAUCET-COMPONENT-SPEC.md`
(§5 Admin + the note-script and procedure tables), `docs/spec/GLOSSARY.md` (CMP-F5 and
IMPL-DEV-16/22/23/24 — the superseded rationale is struck through, not deleted, so the provenance
survives), `docs/REQUIREMENTS-TRACEABILITY.md` (CIR-ADMIN-3, IMPL-DEV-24, CMP-F5 re-pointed at the
shipped procedures and tests), `docs/DOCS-INVENTORY.md` (both plan records listed; the count notes
carry the new numbers), and `crates/xusdc-validation/PARKED-V16-NEXT.md` (the re-enable checklist no
longer claims `identifier_init`/`transfer_ownership`/`accept_ownership` are owner-gated — the first
moved gates and the other two no longer exist). Stale prose in `tests/role_admin.rs` that described
production `set_role_admin` as unreachable now says the opposite, because it is.

### 12.2 · The terminology and fixture sweep

Removing the ownership component retired a word, not just a component: there is no "owner" on this
faucet, and prose that still used it pointed readers at a model the code no longer has. The sweep
covered `README.md`, `docs/spec/GLOSSARY.md` (R-ADMIN-1, CIR-ADMIN-3, IMPL-DEV-1/3/25),
`docs/CIRCLE-SEMANTICS-TRANSFER-BLOCKLIST.md`, the shipped Rust API docs (the note factories, the
builder, `XReserveAdminAuthority`, the builder error type), and the test prose across the admin,
blocklist, identifier, supply-cap and burn suites. Historical records — the migration and
reconciliation docs, this plan's own before-text, and statements about what upstream or v15 did —
keep their original wording, because they describe what was true then.

Two API-visible strings moved with it: the builder's blocklist-isolation error now reports a
collision with `"ADMIN"` rather than `"owner"`, and `support::err_sender_not_owner` is gone —
nothing raises that error any more, which is the point.

The burn-oracle test fixture also stopped mirroring the shipped account: it still installed the
ownership component, giving the burn, pause and min-burn suites an owner slot and five callable
procedures production does not have. It no longer does, and
`set_min_burn.rs::support_replica_carries_delegation_seed` — the existing replica-fidelity pin —
now asserts the absence, so the divergence cannot come back unnoticed.
