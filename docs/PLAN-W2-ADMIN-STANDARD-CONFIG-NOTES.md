# W2-ADMIN — adopting the standard admin config notes: integration plan

**Status:** RATIFIED 2026-07-30 and IMPLEMENTED. All six decisions were ratified as recommended
except D-OWN, which was ratified as **keep `Ownable2Step` this slice** — so the D-OWN deltas below
do not apply: the callable surface stays 75 and the note-script allowlist is 12 (not 10). The
implementation, its effects proof and the frozen-core root diff are in
`crates/xusdc-encoding/tests/w2admin_production_admin_effects.rs` and the round-2 evidence.
**Base:** `implementation` @ `a5b7dd3` (post-#44 v16 `0.16.0-beta.1` pin, post-#45 `masm_structure` fix).
**Protocol pin read for every claim below:** `0xMiden/protocol` @ `4971ec4b38fb1f54e8f73969e6da81ee0cbf850c`,
resolved locally at `~/.cargo/git/checkouts/protocol-4ada628cdf2b267c/4971ec4`.
**Verified green before planning:** `cargo test --locked -p xusdc-encoding --release` (exit 0) and
`--test masm_structure` (52 passed).

---

## 0 · One-paragraph summary

Replace the two hand-rolled role-gated admin wrappers (`xreserve::pause_admin`,
`xreserve::blocklist_admin`) and their four note scripts with the stock `PausableManager` /
`BlocklistManager` components driven by the stock `PauseActionNote` / `BlocklistConfigNote`, and
flip the account-wide gate from `Authority::OwnerControlled` to
`Authority::RbacControlled { procedure_roles }` so the four stock manager procedures keep exactly
today's role gates (`DOM_PAUSER` for pause/unpause, `BLK_MANAGER` for block/unblock). The mint,
burn, attestation and reserve core is untouched. **One real behavior regression is unavoidable in
the stock path and needs an explicit decision: the stock blocklist manager has no self-block
guard** (§5, D-SELFBLOCK).

---

## 1 · What the pinned protocol actually gives us

Every line reference below was read at the pin, not inferred.

| Piece | Source | Shape that matters |
|---|---|---|
| `BlocklistConfigNote` | `miden-standards/src/note/blocklist_config.rs` | enum `BlocklistConfig::{BlockAccount{account}, UnblockAccount{account}}`; `NUM_STORAGE_ITEMS = 3`, storage `[selector, account_suffix, account_prefix]`; note is always `Public`, asset-less, tagged `NoteTag::with_account_target(target)`; **authorization is bound to the note sender** |
| `blocklist_config.masm` | `asm/standards/notes/blocklist_config.masm` | dispatches selector → `call.manager::block_account` / `call.manager::unblock_account`; asserts the per-action storage item count; unknown selector traps |
| `PauseActionNote` | `miden-standards/src/note/pause_action.rs` | enum `PauseAction::{Pause, Unpause}`; `NUM_STORAGE_ITEMS = 1`, storage `[selector]`; same public/asset-less/sender-bound model |
| `pause_action.masm` | `asm/standards/notes/pause_action.masm` | selector → `call.manager::pause` / `call.manager::unpause` |
| `PausableManager` | `src/account/access/pausable/manager.rs` | unit struct, **installs ZERO storage slots**; `pause_root()` / `unpause_root()`; needs `Pausable` (for `is_paused`) + `Authority` |
| `BlocklistManager` | `src/account/policies/transfer/blocklist/manager.rs` | unit struct, **installs ZERO storage slots**; `block_account_root()` / `unblock_account_root()`; needs `Authority` + a component owning `blocked_accounts` (our `BasicBlocklist`) |
| manager MASM bodies | `asm/.../pausable/manager.masm`, `.../blocklist/manager.masm` | each proc is exactly `exec.authority::assert_authorized` then the unauthenticated primitive — i.e. **structurally the same two-line shape as our custom wrappers**, with the role lookup moved from a MASM constant into account storage |
| `Authority::RbacControlled` | `src/account/access/authority.rs` | `{ procedure_roles: BTreeMap<AccountProcedureRoot, RoleSymbol> }`; adds ONE map storage slot (`…::authority::procedure_roles`) |
| `authority::assert_authorized` | `asm/standards/access/authority.masm` | under RBAC: resolves the **calling** procedure root via `caller`, looks it up in `procedure_roles`; **a mapped procedure asserts that role, an UNMAPPED procedure falls back to `ADMIN`** |
| `RoleBasedAccessControl::new` | `src/account/access/rbac.rs:~156` | signature is `new(initial_admins: BTreeSet<AccountId>, role_members: BTreeMap<RoleSymbol, BTreeSet<AccountId>>)` — **two arguments**, not the one the scoping note recorded |
| `RbacActionNote` | `asm/standards/notes/rbac_action.masm` | ONE script root, FOUR selectors: `GRANT_ROLE=0`, `REVOKE_ROLE=1`, `SET_ROLE_ADMIN=2`, `RENOUNCE_ROLE=3` |
| `AllowlistConfigNote` | `src/note/allowlist_config.rs` | **OUT OF SCOPE.** Structurally parallel to the blocklist note and easy to confuse; the faucet has no transfer allowlist. It must never enter the composition or the allowlist. |

Two consequences worth stating up front:

- **The manager adoption is storage-neutral.** Both managers install zero slots, `Pausable` and
  `BasicBlocklist` are *already* installed today. So the new account id (faucet v2) is caused
  **only** by the `Authority` mode flip (which adds the `procedure_roles` map slot) and, if
  ratified, by dropping `Ownable2Step`'s slots — not by the managers.
- **The keyless network-account sender model composes.** `asm/standards/auth/network_account.masm`
  `assert_transaction_allowed` gates on the note-script allowlist and the tx-script allowlist
  **only** — it never inspects a routing attachment. The stock config notes carry no
  `NetworkAccountTarget` attachment (they route via `NoteTag::with_account_target`), and that is
  fine: our own notes' attachment was always documented as routing-only. This closes the scoping
  doc's open build-time item #2 at the source level; the grounding harness (§7) closes it by
  execution.

## 2 · Composition: before → after

Current `build_components()` order (`crates/xusdc-encoding/src/account/xreserve/builder/mod.rs`):

```
FungibleFaucet
Pausable::unpaused()
xreserve component          # attestation_verify, attester_admin, blocklist_admin, deposit_intent_parser,
                            # encoding, identifier_init, mint_policy, pause_admin
MinBurnAmount companion
BasicBlocklist companion
TokenPolicyManager
Ownable2Step::new(owner)
seeded_dom_roles_rbac(...)  # hand-built RoleBasedAccessControl component
Authority::OwnerControlled
```

After:

```
FungibleFaucet                                       unchanged
Pausable::unpaused()                                 unchanged
xreserve component                                   MINUS blocklist_admin + pause_admin modules
MinBurnAmount companion                              unchanged
BasicBlocklist companion                             unchanged
TokenPolicyManager                                   unchanged
PausableManager                                      NEW  (zero storage)
BlocklistManager                                     NEW  (zero storage)
[Ownable2Step::new(owner)]                           D-OWN
seeded RoleBasedAccessControl                        unchanged mechanism, see §4
XReserveAdminAuthority  →  Authority::RbacControlled REPLACES Authority::OwnerControlled
```

Deleted source files: `asm/standards/xreserve/{pause_admin,blocklist_admin}.masm`,
`asm/standards/notes/xreserve_{pause,unpause,block_account,unblock_account}_note.masm`, their two
`pub mod` lines in `asm/standards/xreserve/mod.masm`, their four Rust note factories in
`crates/xusdc-encoding/src/note/xreserve_admin/`, and the two MASM role-symbol constants
(`DOM_PAUSER_ROLE`, `BLK_MANAGER_ROLE`) plus their `constant_parity` rows — the role symbols move
from hard-coded MASM literals into the `procedure_roles` storage map, which is where they belong.

Patterns mirrored, per the reviewers' standing asks: the typed-component-with-`From` shape of
`miden-standards`' own components (`impl From<Authority> for AccountComponent`,
`impl IntoIterator for AccessControl`); "import, do not copy" for every stock piece; the
`procedure_roles` map is built by a constructor that takes no map from the caller, so a
mis-mapped or missing manager procedure is impossible **by construction** rather than guarded by a
runtime assert.

## 3 · The procedure → role map (D-1)

`XReserveAdminAuthority::new()` builds exactly these four entries and nothing else:

| Procedure root | Role | Gate today |
|---|---|---|
| `PausableManager::pause_root()` | `DOM_PAUSER` | `xreserve::pause_admin::pause` hard-codes `DOM_PAUSER` |
| `PausableManager::unpause_root()` | `DOM_PAUSER` | `xreserve::pause_admin::unpause` hard-codes `DOM_PAUSER` |
| `BlocklistManager::block_account_root()` | `BLK_MANAGER` | `xreserve::blocklist_admin::block_account` hard-codes `BLK_MANAGER` |
| `BlocklistManager::unblock_account_root()` | `BLK_MANAGER` | `xreserve::blocklist_admin::unblock_account` hard-codes `BLK_MANAGER` |

**Everything else stays UNMAPPED and therefore falls back to `ADMIN`.** That is the identity-
preserving choice, because the RBAC seed already makes `ADMIN`'s single member the owner's account.
The unmapped, authority-gated set is:

`xreserve::attester_admin::set_attester` · `fungible_faucet::set_max_supply` ·
`fungible_faucet::set_description` / `set_logo_uri` / `set_external_link` ·
`min_burn_amount::set_min_burn_amount` · `policy_manager::set_{mint,burn,send,receive}_policy` ·
`authority::freeze` / `unfreeze` · the four `network_account` allowlist mutators and the two fee
mutators (present-but-unreachable rows).

Today all of these gate on the `Ownable2Step` owner; after the flip they gate on `ADMIN`, whose
only member is that same account. **Same identity, different mechanism.** The one operational
difference: `transfer_ownership` + `accept_ownership` no longer moves this authority, because
`ADMIN` membership does not follow the owner slot — a divergence the repo already documents in
`builder/rbac_seed.rs` and handles in the rotation runbook via `grant_role`/`revoke_role`.

**Deliberately NOT mapped, though PhilippG asked for it** (`r3656780734`): `set_attester` →
a dedicated `ATTESTER_ADMIN` role. Mapping it would move that capability off the owner and is a
real capability change, so it is offered as a ratifiable option (D-ATTESTER) rather than taken
silently. Recommendation: keep it unmapped in this slice; add `ATTESTER_ADMIN` as a follow-up once
Circle confirms who holds it.

## 4 · RBAC seeding

Keep `seeded_dom_roles_rbac` as-is. Reason: `RoleBasedAccessControl::new(initial_admins,
role_members)` seeds **membership** but leaves every seeded role's delegated admin unset (→ `ADMIN`).
The shipped design deliberately delegates `DOM_PAUSER`'s administration to `DOM_MANAGER`
(`role_config[DOM_PAUSER] = [1, DOM_MANAGER, 0, 0]`), and the stock constructor cannot express a
delegated admin at construction. So:

- if the ratified role-admin graph keeps the `DOM_PAUSER → DOM_MANAGER` delegation, the hand-seeded
  component must stay (it is not "hand-rolled RBAC" — it reuses the stock code, slot names and
  metadata verbatim and only writes the maps the stock `From` impl leaves empty);
- if the delegation is dropped, `RoleBasedAccessControl::new` covers the whole seed and the custom
  file can go. That is a role-graph change and needs ratification, so it is folded into D-RBAC.

Either way this is worth raising upstream: **`RoleBasedAccessControl` has no constructor that seeds
a delegated admin**, which is the only reason a hand-built component exists here.

## 5 · Behavior preservation, action by action

| Action | Today | After | Preserved? |
|---|---|---|---|
| pause | `XReservePauseNote` → `call xreserve::pause_admin::pause` → `rbac::assert_sender_has_role(DOM_PAUSER)` → `pausable::pause` | `PauseActionNote{Pause}` → `call PausableManager::pause` → `assert_authorized` → RBAC → `DOM_PAUSER` → `pausable::pause` | **YES** — same `is_paused` slot, same role, same halt effect on mint and burn |
| unpause | mirror of pause | `PauseActionNote{Unpause}` | **YES** |
| unblock | `XReserveUnblockAccountNote` → `blocklist_admin::unblock_account` → `BLK_MANAGER` → `blocklist::unblock_account` | `BlocklistConfigNote{UnblockAccount}` → `BlocklistManager::unblock_account` → `assert_authorized` → `BLK_MANAGER` → same primitive | **YES** — same `blocked_accounts` slot write |
| block | same shape **plus** a self-block guard: the target must not equal the faucet's own id (`ERR_XRESERVE_CANNOT_BLOCK_SELF`) | `BlocklistConfigNote{BlockAccount}` → `BlocklistManager::block_account` → `assert_authorized` → `BLK_MANAGER` → same primitive | **NO — the guard is lost.** See D-SELFBLOCK |
| owner-gated setters (`set_attester`, `set_max_supply`, `set_min_burn_amount`, the policy setters) | `authority::assert_authorized` → OwnerControlled → owner | `assert_authorized` → RBAC, unmapped → `ADMIN` = the same account | **YES for identity**; rotation mechanism changes (§3) |
| `freeze` / `unfreeze` | owner | `ADMIN` (unmapped, and it bypasses the frozen flag exactly as before) | **YES** |
| mint / burn / attestation / reserve | — | **untouched** | **YES, byte-identical** — no file on those paths is edited; roots proven unmoved by `constant_parity`, `mint_root_surface`, `masm_dual`, `basic_asset_tripwire` |
| note-storage malformation | custom notes assert an exact item count | stock notes assert an exact per-action item count and trap on an unknown selector | **YES, equivalent** |
| wrong-sender rejection | `ERR_SENDER_LACKS_ROLE` from `rbac::assert_sender_has_role` | the same `rbac` assertion, reached through `assert_authorized` | **YES** (same underlying assertion and error) |

### D-SELFBLOCK — the one real regression

`asm/standards/xreserve/blocklist_admin.masm` rejects blocking the faucet's own account id. Read at
the pin, neither `BlocklistManager::block_account` nor the underlying
`miden::standards::faucets::policies::transfer::blocklist::block_account` primitive performs *any*
target validation — the primitive's doc explicitly says the wrappers add only the auth check. So the
stock path lets `BLK_MANAGER` block the faucet itself, which — with `BasicBlocklist` active as both
the send and the receive policy — freezes the faucet as a transfer party and halts `mint_and_send`
and `receive_and_burn` alike.

Bounding it honestly: the action is **recoverable**. `BlocklistConfigNote{UnblockAccount}` carries no
assets, so consuming it dispatches no transfer policy and it lands even while the faucet is
self-blocked. And a hostile `BLK_MANAGER` can already block every user, so the guard was
protection against operator error, not against a hostile role holder.

Options:
- **(a) Accept the loss, pinned by an explicit test** (recommended). Ship the stock path, and add a
  MockChain test that *documents* the new reachable state and proves recovery via the unblock note,
  so the change is audited rather than silent. Additionally refuse to *construct* a self-block note
  in our own note factory (off-chain belt-and-braces; not a gate, since `BLK_MANAGER` can hand-roll
  a note).
- **(b) Upstream the guard** into `miden-standards`' `block_account`. Correct long-term, and
  PhilippG offered to open protocol issues; it blocks this slice on an upstream merge.
- **(c) Keep a thin custom `block_account` wrapper.** Rejected: `blocklist_config.masm` calls the
  *manager's* root, so a custom wrapper forces the custom block note back and forfeits the entire
  point for the block half.

Recommendation: **(a) now + (b) as a follow-up issue.** This needs Phil's explicit ratification —
it is the only line in this plan that changes what the faucet permits.

## 6 · Surface and allowlist delta

Callable surface (`account_callable_surface.rs`, currently `FROZEN_ACCOUNT_SURFACE: [&str; 75]`):

- **−4 xreserve:** `blocklist_admin::{block_account, unblock_account}`, `pause_admin::{pause, unpause}` (15 → 11)
- **+4 stock:** `pausable::manager::{pause, unpause}`, `…transfer::blocklist::manager::{block_account, unblock_account}`
- **−5 if D-OWN removes `Ownable2Step`:** `accept_ownership`, `get_nominated_owner`, `get_owner`, `renounce_ownership`, `transfer_ownership`

Total: **75 → 75** with `Ownable2Step` kept, **75 → 70** with it removed. Note that removing
`Ownable2Step` while keeping `Authority` does **not** break linking: `authority.masm`'s
`OwnerControlled` branch is inside the shipped `Authority` package and simply becomes unreachable
under `RbacControlled`.

Note-script allowlist (`XReserveStablecoinBuilder::allowed_note_scripts`, currently 14 roots):

| Change | Roots |
|---|---|
| −2 | `XReservePauseNote`, `XReserveUnpauseNote` |
| +1 | `PauseActionNote::script_root()` |
| −2 | `XReserveBlockAccountNote`, `XReserveUnblockAccountNote` |
| +1 | `BlocklistConfigNote::script_root()` |
| −2 if D-OWN removes `Ownable2Step` | `XReserveTransferOwnershipNote`, `XReserveAcceptOwnershipNote` |
| ±0 / ±1 per D-RBAC option | see below |

**12 roots** with `Ownable2Step` kept, **10** with it removed. Every remaining root's hash
re-materializes anyway (the MAST roots move with the composition). `AllowlistConfigNote::script_root()`
must be **absent**, alongside the already-pinned `NetworkAccountConfigNote` / `FeeSponsorshipNote`
absences. The count is CC-frozen (`CC-SURFACE-1`), so the new number needs the scheduled human
ratification — it is not a number this slice may pick.

## 7 · Grounding harness shipped with this plan (Phase 1 evidence, zero production change)

`crates/xusdc-encoding/tests/w2admin_standard_admin_grounding.rs` proves the plan is implementable
by *executing* the proposed stock stack on MockChain, on a **test-only** composition. It does not
touch `build_components`, the allowlist, any MAST root, or any shipped file. It covers:

- the stock notes' and managers' exact shapes and root distinctness at the pin;
- `AllowlistConfigNote` is a distinct root and is absent from the shipped allowlist;
- `XReserveAdminAuthority::new()` → `Authority::RbacControlled` → `AccountComponent` →
  `AccountStorage` → `Authority::try_from_storage` round-trips **exactly** the four proposed
  entries with the right role symbols;
- the role-symbol felts equal the values today's MASM hard-codes, so the role identity survives the
  mechanism change;
- `set_attester` is **not** mapped (the identity-preserving choice of §3 is asserted, not assumed);
- **end-to-end execution:** a real `PauseActionNote{Pause}` sent by the `DOM_PAUSER` holder pauses
  the account; `{Unpause}` clears it; a real `BlocklistConfigNote{BlockAccount}` sent by the
  `BLK_MANAGER` holder writes `blocked_accounts[target] = 1`; `{UnblockAccount}` clears it;
- **role isolation, both directions:** the `ADMIN`/owner account cannot pause and cannot block; the
  `DOM_PAUSER` holder cannot block; the `BLK_MANAGER` holder cannot pause; an unrelated account can
  do neither;
- **the unmapped→`ADMIN` fallback is real**, executed against a procedure with no map entry;
- **D-SELFBLOCK is proven, not asserted:** the stock `block_account` accepts the account's *own* id
  and the write lands, and the unblock note still lands afterwards (recovery holds).

## 8 · Decision points for ratification

| id | Question | Recommendation |
|---|---|---|
| **D-1** | RBAC authority mode + the exact procedure→role map | **Adopt** `Authority::RbacControlled` with exactly the four entries in §3; everything else unmapped → `ADMIN`. Grounded and executed by §7. |
| **D-RBAC** | `RbacActionNote` bundles 4 selectors — `GrantRole`, `RevokeRole`, **`SetRoleAdmin`**, **`RenounceRole`**. Allowlisting its single root exposes all four, re-introducing a runtime-mutable role-admin graph (frozen at the S21 flip) and self-renounce (deliberately omitted per Circle's EVM admin model). | **(a) Keep the graph FROZEN** — retain the current `grant_role`/`revoke_role` notes, do **not** allowlist `RbacActionNote`. Revisit when upstream offers per-selector gating or a selector-subset note. Gated on Phil's C-5 reply + Circle's stance. |
| **D-OWN** | Remove `Ownable2Step` in favor of pure RBAC? Drops the 2-step transfer→accept handshake and `renounce_ownership`; makes `ADMIN` membership the sole authority handle. | **Phil's call.** Removal is coherent (`ADMIN` already *is* the owner account and the setters already resolve through `ADMIN` after the flip) and is what PhilippG asked for; keeping it costs 5 surface rows + 2 allowlist roots and leaves two authority handles that can drift apart. Slight lean to **remove**, contingent on Circle accepting single-step rotation. |
| **D-SELFBLOCK** | The stock blocklist manager has no self-block guard (§5). | **(a) accept + pin by test + upstream (b) as a follow-up.** The only permission change in the slice. |
| **D-ATTESTER** | Map `set_attester` → a dedicated `ATTESTER_ADMIN` role (PhilippG `r3656780734`)? | **Not in this slice** — keep it unmapped (`ADMIN`) so the capability stays with today's holder; revisit once Circle names the holder. |
| **D-SCOPE** | Full overhaul in one slice? | **Yes, forced.** The config notes `call` the managers, and the managers gate on `Authority`, so tier-1 and tier-2 cannot be separated (§1). Consequence: a faucet v2 account id — accepted, Circle re-registration is out-of-band. |

## 9 · Remaining unknowns (all build-time, none blocking the plan)

1. **The faucet v2 account id** is not computable until the composition is built — expected, not a risk.
2. **The re-pinned MAST roots** (every allowlisted note root and the 4 new manager procedure roots on
   the production account) must be re-materialized in Phase 3 and independently re-derived by the
   auditor. The grounding harness pins the *stock* roots but not the production account's.
3. **The `constant_parity` suite loses two rows** (the `DOM_PAUSER` / `BLK_MANAGER` MASM literals) as
   those constants disappear with the wrapper files. The suite stays green; its *content* changes,
   which is expected and must be called out in the Phase 3 diff, not slipped in.
4. **`RoleBasedAccessControl` cannot seed a delegated admin** (§4) — resolved for us by keeping the
   hand-seeded component, but worth an upstream issue.

## 10 · Phase plan after ratification

- **Phase 2 — RED.** Extend §7's harness onto the *production* composition: the four EFFECTS tests
  (block/unblock/pause/unpause via the stock notes against the real faucet), the frozen-core
  tripwires unchanged, the new note-script allowlist, the new surface list. Red before the edit.
- **Phase 3 — implement.** Delete the six MASM files + four Rust note factories, add the two
  managers + `XReserveAdminAuthority` to `build_components`, re-materialize the allowlist and the
  surface pins, update `constant_parity` and the prose-conformance counts.
- **Phase 4 — verify.** `cargo build --workspace --locked --release`,
  `cargo test --locked -p xusdc-encoding --release` (incl. `masm_structure`),
  `clippy --workspace --locked -- -D warnings`, `fmt --all -- --check`; plus the frozen-core
  empty-diff proof on every mint/burn/attestation/reserve root and every wire vector.

## Ratified outcome

D-1 adopt as proposed · D-RBAC keep the role graph frozen (no `RbacActionNote`) · D-OWN **keep
`Ownable2Step` this slice** · D-SELFBLOCK accept, with the note-factory refusal and a test that
documents the reachable state and proves recovery · D-ATTESTER keep `set_attester` unmapped ·
D-SCOPE full overhaul in one slice, faucet v2 accepted.

Deferred, tracked only: adopting `RbacActionNote`; removing `Ownable2Step`; an `ATTESTER_ADMIN`
role; and upstreaming the self-block guard to `miden-standards`. `DEV-*` / `Q-*` items referenced
here stay OPEN and Circle-owned.

## One consequence beyond the plan's own text, worth restating

Flipping the authority to its role-based mode changes the rejection **error** every
authority-gated setter raises for an unauthorized sender: `ERR_SENDER_NOT_OWNER` becomes
`ERR_SENDER_LACKS_ROLE`, because the gate now resolves through the administrator role rather than
the owner slot. The authorized identity is unchanged. The procedures that gate on the owner slot
directly — `identifier_init`, `transfer_ownership`, `accept_ownership` — keep the owner error.

The same flip means a completed ownership transfer no longer moves authority over those setters:
administrator membership is account-bound and does not follow the owner slot, so after
`accept_ownership` the new owner cannot set the burn floor and the old owner still can, until the
administrator role is granted and revoked through the role notes. §3 flagged this; it is pinned by
`ownable2step_admin.rs::owner_two_step_transfer_rotates_the_owner_slot_but_not_the_administrator`.
