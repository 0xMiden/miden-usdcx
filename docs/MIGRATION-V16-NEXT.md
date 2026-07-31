# MIGRATION-V16-NEXT — the v16-alpha family → protocol-`next` @ `dbe4e38` (V16-NOW, migration #1 of 2)

**Scope.** Moves every miden workspace pin from the crates.io v0.16.0-alpha family
(protocol/standards/tx `=0.16.0-alpha.4`, testing `=0.16.0-alpha.2`) to ONE frozen git rev of the
protocol monorepo's `next` branch. Behavior-preserving **in effect**: everything that behaved X at
the old pins behaves X at the new pin, with exactly three pre-ratified dispositions layered on top
(the temporary surface growth, the provisional zero-fee configuration, and the `custom()`
composition switch — §5). Migration #2 (**V16-FINAL**) lands later, onto the cut `v0.16.0`
release, and REVERTS what this migration temporarily ratifies (§9).

Precedent and shape: `docs/MIGRATION-V16-ALPHA2.md` (the previous migration's record).

## 1. Pin ledger (old → new)

### 1.1 Direct dependency pins

| Crate / manifest | Old | New |
|---|---|---|
| `miden-protocol` (xusdc-encoding, dep + relayer dep/dev + listener dep) | crates.io `=0.16.0-alpha.4` | git `https://github.com/0xMiden/protocol` @ rev `dbe4e38797207ce09fee1668ea204aafec275f63` |
| `miden-standards` (xusdc-encoding dep + dev; relayer dev) | crates.io `=0.16.0-alpha.4` | same git rev |
| `miden-tx` (xusdc-encoding dev) | crates.io `=0.16.0-alpha.4` | same git rev |
| `miden-testing` (xusdc-encoding dev) | crates.io `=0.16.0-alpha.2` | same git rev |
| `miden-processor` (xusdc-encoding dev) | crates.io `=0.25.3` | crates.io `=0.25.8` |
| `miden-crypto` (xusdc-encoding, optional + dev) | `0.28` | `0.28` (unchanged — the pin's own workspace requires 0.28) |

All four protocol-monorepo crates carry the IDENTICAL rev — a mixed graph would put two
`miden-protocol` packages in one workspace and break type unification. The pin is a frozen `rev`,
never `branch = "next"` (a branch pin floats and invalidates every root re-pin;
`grep -rn 'branch *=' Cargo.toml crates/*/Cargo.toml` is empty).

**VM-family yank rationale.** The git graph requires the `0.25` assembler/VM family. On crates.io,
**0.25.0–0.25.7 are all yanked**; `=0.25.8` is the only live 0.25.x, so the whole family
(`miden-assembly`, `miden-assembly-syntax`, `miden-assembly-syntax-cst`, `miden-core`,
`miden-core-lib`, `miden-processor`, `miden-prover`, `miden-verifier`, `miden-air`,
`miden-ace-codegen`, `miden-debug-types`, `miden-mast-package`, `miden-package-registry`,
`miden-project`, `miden-utils-*`) lands uniformly on `0.25.8` in the lock. A mixed family does not
even compile (verified during discovery: `miden-processor 0.25.8` against `miden-debug-types
0.25.3` fails on `PackageDebugInfo::get_location`). The protocol repo's own `Cargo.lock` at the
pin still carries 0.25.7 — a pre-yank resolution; fresh resolutions cannot use it.

### 1.2 Resolved-family record (the `cargo tree` evidence)

`cargo tree --workspace --locked -e normal,dev` resolves EXACTLY ONE version of every `miden-*`
crate:

- the 7 protocol-monorepo crates (`miden-protocol`, `miden-standards`, `miden-tx`,
  `miden-testing`, `miden-tx-batch`, `miden-block-prover`, `miden-agglayer`) all at
  `v0.16.0-beta.1` from `git+https://github.com/0xMiden/protocol?rev=dbe4e38797207ce09fee1668ea204aafec275f63`;
- the VM/assembler family uniformly at `v0.25.8` (`miden-assembly`, `miden-assembly-syntax`,
  `miden-assembly-syntax-cst`, `miden-core`, `miden-core-lib`, `miden-processor`, `miden-prover`,
  `miden-verifier`, `miden-air`, `miden-ace-codegen`, `miden-debug-types`, `miden-mast-package`,
  `miden-package-registry`, `miden-project`, `miden-utils-core-derive`,
  `miden-utils-diagnostics`, `miden-utils-indexing`, `miden-utils-sync`) — no other 0.25.x in the
  graph;
- the crypto family at `v0.28.0` (`miden-crypto`, `miden-crypto-derive`, plus its 0.28-line
  satellites `miden-field`, `miden-lifted-air`, `miden-lifted-stark`, `miden-serde-utils`,
  `miden-stark-transcript`, `miden-stateful-hasher`);
- independents: `miden-formatting v0.1.1`, `miden-miette(-derive) v8.0.0`, `miden-rowan v0.16.4`.

No `[patch.crates-io]` block was needed: with the validation crate parked, nothing pulls the
protocol family from crates.io, so the four git pins resolve the whole family unambiguously.

**k256-stack remediation (decided path: hold the transitives).** Against the empty clippy
baseline, a full lock regeneration would have bumped `generic-array` 0.14.7 → 0.14.9, whose
deprecation of `GenericArray::as_slice` surfaces 3 new warnings at our call sites. The lock was
instead updated with **minimal churn** (only what the new graph forces), which keeps
`generic-array` at exactly the `0.14.7` the baseline lock carried — zero code churn, zero
suppression, no `#[allow(deprecated)]` anywhere.

## 2. Phase-0 record — baseline + claim verification

### 2.1 Baseline at `8a3fb04` (the behavior contract's denominator)

- `cargo build --workspace --locked --release` → exit 0
- `cargo test --workspace --locked --release` → exit 0: **1580 passed / 0 failed / 6 ignored** (117 suites)
- `cargo clippy --workspace --all-targets --locked --release` → exit 0, **empty warning inventory**

Post-park baseline (the validation crate excluded, still on alpha.4 — proving the park is
independent of the bump): build/test/clippy all green, **1390 passed / 0 failed / 0 ignored**
(the validation crate carried 190 tests and all 6 `#[ignore]`s).

### 2.2 Carried-claim verification (every CORRECTED PHASE-0 FACT re-verified at the pin)

| Claim | Verdict |
|---|---|
| Baseline 1580/0/6, clippy empty | **CONFIRMED** (above) |
| Post-park denominator 1390 | **CONFIRMED** (above) |
| `as_library` → `as_package`: 9 sites | **CONFIRMED** — 9 lines / 18 occurrences in 3 files |
| `with_dynamically_linked_library` → `…_package`: 3 files | **REFUTED in count, mechanical either way** — 5 files, 15 occurrences |
| `AssetId`→`AssetClass` / `AssetVaultKey`→`AssetId` trap rename: 0 sites | **CONFIRMED** — zero mentions of either name in our crates; nothing to adapt, nothing mis-meaning |
| FF-1 moot: #3422 removed `From<AccountId> for [Felt; 2]` | **CONFIRMED** — the pin's HEAD commit IS #3422; the impl is gone from `account_id/mod.rs` and `account_id/v1/mod.rs`; no `for [Felt; 2]` impl remains anywhere at the pin. Our `account_id_to_felts` uses only `prefix()`/`suffix()` accessors (both survive) and keeps `[prefix, suffix]` order — untouched. |
| Park not done in round 1 | **CONFIRMED** — done here (§4) |
| FF-2 still blocked | **CONFIRMED** — no u256→amount export in `miden-standards` at the pin (§8) |
| FF-4 config-note family exists | **CONFIRMED in substance, naming corrected** — see §8 |
| RBAC `empty()` removal, ≤18 sites, `rbac_seed.rs` hot spot | **REFUTED in detail, moot in effect** — `empty()` never existed (alpha.4 had `new(AccountId)` / `with_admins(…)`, both removed; the pin's only ctor is `new(admins, role_members)`). Our repo hand-builds the RBAC component from accessors that are ALL unchanged at the pin — **zero RBAC call sites break and the seeded storage stays byte-identical**. The pin ctor was deliberately NOT adopted: it hardcodes every role's `admin_role` to 0 and cannot express the seeded `DOM_PAUSER.admin_role = DOM_MANAGER` delegation. |
| VM family `=0.25.8`, 0.25.0–0.25.7 yanked | **CONFIRMED** via the crates.io index (§1.1) |
| k256 stack: 3 new `GenericArray::as_slice` deprecations | **AVOIDED STRUCTURALLY** — minimal-churn lock keeps `generic-array 0.14.7`; the warnings never appear (§1.2) |
| Harness classes forced by the pin | **CONFIRMED** — `MockChain::build_tx_context` is REMOVED at the pin (→ `build_transaction`/`MockTransactionBuilder`); `assemble_library_from_root` now returns `Box<Package>`; `miden_protocol::assembly` re-exports `Package`, not `Library` (§3) |
| ROOT_HEX surface shape | **CONFIRMED + completed** — the full re-measured enumeration is §6 |
| ~33 upstream-error-string sites | **CONFIRMED as the encoding-crate framing** — 31 sites in `crates/xusdc-encoding/tests` (25 hardcoded upstream MASM strings + 6 typed VM-error asserts) + 2 canary constant asserts = 33. Repo-wide the surface is larger (53 more sites live in the PARKED validation crate and stay parked). Every asserted upstream string survives at the pin except `ERR_NO_NOMINATED_OWNER`, which upstream deleted — nothing here asserts it, and the no-nomination case still REJECTS (via "note sender is not the nominated owner"): no polarity change. Zero error-string updates were needed; the executed suite is the proof. |
| ~11 `.masm` files import changed upstream modules | **REFUTED (in the safe direction)** — every `use` in every production `.masm` under `asm/` resolves at the pin, and every invoked upstream procedure keeps its name and stack signature: **zero forced MASM edits**. The one value-level change is the P2ID root constant (§6). |

### 2.3 Environment notes

- Gates need network on first resolution (the git pin + new transitives; no pre-provisioned
  `--offline` cache exists for the `next`-HEAD graph). `--locked` still binds: the committed
  `Cargo.lock` is the reproducibility anchor. This applies to the auditor uid too (cold per-user
  cargo cache).
- House gates adopted from `CLAUDE.md`/`AGENTS.md`: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --locked -- -D warnings`, and the masm_structure conformance test.

## 3. Mechanical inventory (compiler-forced renames/moves — no behavior change)

1. `AccountComponentCode::as_library()` → `as_package()` — 9 lines / 18 occurrences
   (`src/account/xreserve/builder/mod.rs`, `tests/builder_api.rs`, `tests/support/mod.rs`).
2. `CodeBuilder::with_dynamically_linked_library` → `with_dynamically_linked_package` — 15
   occurrences in 5 files.
3. **Harness class 1 (`build_tx_context` → `build_transaction`)**: the pin removes
   `MockChain::build_tx_context(input, note_ids, unauthenticated_notes) -> Result<TransactionContextBuilder>`
   in favor of the infallible `MockChain::build_transaction(input) -> MockTransactionBuilder`,
   with input notes supplied via `.authenticated_input_note(s)` / `.unauthenticated_input_note(s)`
   and execution unchanged (`.build()?.execute().await`). **96 call sites** adapted, each a pure
   construction-plumbing hunk (no assertion, polarity, pinned value, or test-semantics change);
   the per-site list is in the round report.
4. **Harness class 2 (`Library` → `Package` walk)**: `assemble_library_from_root` returns
   `Box<Package>`; `miden_protocol::assembly` re-exports `Package` (no `Library`);
   `AccountComponentCode::as_package()` replaces the `AsRef<Library>` view. Touched:
   `tests/support/mod.rs`, `tests/masm_dual.rs`, `tests/mint_root_surface.rs` (type/import swaps
   only — the `manifest.exports()` shape is identical).
5. `TransactionContextBuilder::extend_expected_output_notes(vec![x])` →
   `MockTransactionBuilder::expected_output_note(x)` — 4 single-element sites.
6. **Sanctioned CLASS 6 (ratified by Phil, 2026-07-29 round-2 revise):** the
   `AuthNetworkAccount` multi-component adaptation forced by
   `From<AuthNetworkAccount> for AccountComponent` → `IntoIterator` (the value now expands into
   the auth component + its registered fee-policy components) — 6 sites: 3×
   `components.push(auth.into())` → `components.extend(auth)` (installs ALL yielded components,
   in yield order), 3× single-component extraction `.into_iter().next()` at sites that inspect
   ONLY the auth component's own storage/code and build no account. Construction plumbing only —
   no assertion, polarity, or pinned value changes; the per-hunk no-drop/no-reorder proof is in
   §11.3.
7. `Auth::NetworkAccount` (miden-testing fixture) gained a required `fee_policy_manager` field —
   moot for the shipped tree: the posture phase replaces the fixture with the production
   composition (§5.3).
8. Upstream deltas verified NO-OP for us: `ownable2step::accept_ownership` dropped its dedicated
   no-nomination assert (the sender-mismatch assert covers the case; polarity unchanged; nothing
   here asserted the deleted string); `blocklist/owner_controlled.masm` renamed to `manager.masm`
   (we import only the parent module); `AccountBuilder::with_auth_component` removed (only the
   parked validation crate called it).

### 3.1 The SIX sanctioned tripwire-edit classes (the ratified fence)

The original task fenced five classes; the sixth — forced by the pin's component-expansion API —
was **ratified by Phil (2026-07-29, round-2 revise)**. Exhaustive; every tripwire hunk in this
migration classifies into exactly one (the per-hunk walk is §11.2):

1. Authorized re-materialization: root-hash values, pin-table values, the pinned-standards
   fixtures + `PROVENANCE.md` + their checksums/anchor.
2. Authorized additive exact-set tightening in the named pin files (none were needed — the pins
   were already exact-set).
3. The A1 ratified growth rows: additive membership rows in `account_callable_surface.rs` +
   `account_surface_unreachable.rs` (+ the count ground truth in
   `surface_count_prose_conformance.rs`), exactly the enumerated set, on the S12/S21 precedent
   representation.
4. The sanctioned NEW test files (`config_note_absence.rs`, `fee_policy_provisional_pin.rs`,
   and — added by round 4's test-first protocol — the evidence-ledger integrity tripwire
   `migration_evidence_ledger.rs`, which edits no tripwire file) + the REQUIRED `custom()`
   composition switch in `tests/support/mod.rs`.
5. Mechanical harness-adaptation hunks: `build_tx_context` → `build_transaction` /
   `MockTransactionBuilder`, and the `Library` → Package-API walk (incl. the
   `expected_output_note` and rename waves) — construction plumbing only.
6. The `AuthNetworkAccount` multi-component adaptation (item 6 above) — construction plumbing
   only.

## 4. The park (OPEN-RECON-1)

`crates/xusdc-validation` moved from `workspace.members` to `workspace.exclude`, byte-intact, with
the parking record `crates/xusdc-validation/PARKED-V16-NEXT.md` (why, the observable re-enable
trigger = V16-FINAL/FF-3 with a client/node pair, and the un-park steps — precedent
`PARKED-V15.md`). No client release exists for the `next` graph (`miden-client =0.16.0-alpha.1`
pins protocol `=0.16.0-alpha.4`), so the crate cannot cross with the rest. The park landed FIRST,
on the unchanged alpha.4 graph, and the full gates were re-run green (1390/0/0) before any pin
moved — the park is provably independent of the bump. The deployed devnet v1 faucet Circle tests
against is untouched (it runs deployed artifacts, not this workspace).

MockChain (`miden-testing` at the frozen rev) is the verification harness for everything that
crossed; no local-node/LNV leg runs in this slice.

## 5. The three ratified dispositions (pre-decided; executed exactly)

### 5.1 A1 — the temporary surface growth (two ratified reachability tiers)

At the pin the stock `AuthNetworkAccount` unconditionally exports 10 procedures beyond the auth
procedure, and the mandatory fee policy adds its dispatch target. The composed account's callable
surface grows **64 → 75**; the ratified inventory (verified row-by-row at the pin, §7):

- 4 allowlist mutators (`add_allowed_note_script`, `remove_allowed_note_script`,
  `add_allowed_tx_script`, `remove_allowed_tx_script`) — upstream #3355;
- 6 fee procedures (`estimate_note_fee`, `get_fee_asset_id`, `get_fee_policy`, `set_fee_policy`,
  `add_allowed_fee_policy`, `remove_allowed_fee_policy`) — upstream #3351;
- 1 fee-policy procedure (`basic_constant_fee::compute_note_fee`).

**The growth adds NO new authorized entry point**, and its reachability posture is the ratified
two-tier split (Phil, 2026-07-29 round-3 revise; verified against the protocol source at the
pin):

> The 11 forced additions fall in two reachability tiers.
> **Tier A — truly unreachable:** the 4 `#3355` admin mutators. No note or tx can reach them
> under the frozen 14-root note-script allowlist + 1-root tx-script allowlist (same disposition
> as the S12 freeze/unfreeze + S21 set_role_admin precedents).
> **Tier B — internally-active-but-inert, direct-entry-unreachable:** the 6 `#3351` fee
> procedures + the `compute_note_fee` policy callback. None is a new externally-authorized entry
> point (none in the note/tx-script allowlist, so no outside caller reaches them directly). BUT
> the fee-estimation path IS executed internally on every input note during
> `auth_network_transaction` (`collect_sponsored_fees` -> `estimate_note_fee_internal` -> dyncall
> to `compute_note_fee`). With `BasicConstantFeePolicy` scheduling an explicit ZERO fee for all
> 14 allowlisted roots, that execution computes a zero fee and is functionally inert (doubly so
> on the zero-base-fee MockChain). The 14-root schedule is required precisely because this path
> runs on every note.

The keyless faucet's entire authorization model is the note/tx-script allowlist, and that
allowlist does not change: the 14-root note-script allowlist and the 1-root tx-script allowlist
stay FROZEN, exact, and membership-identical. `account_callable_surface.rs` re-freezes the
literal 75-path surface; `account_surface_unreachable.rs` proves each tier's posture (presence
for all 11; the exhaustive MAST sweep + both-allowlist non-membership for Tier A's
unreachability; the no-direct-reference sweep + both-allowlist non-membership for Tier B's
no-external-entry, with the internal dyncall acknowledged); the executing rejection legs (any
non-allowlisted note/tx-script is rejected) run unchanged.

**Storage-layout delta — 4 slots, EXPLICITLY RATIFIED.** The auth component's storage grows by
the three fee-policy slots the `FeePolicyManager` owns (`active_fee_policy_proc_root` value,
`allowed_fee_policy_proc_roots` map, `fee_asset_id` value — appended after the two allowlist
slots), and the `BasicConstantFeePolicy` component adds its own `fee_schedule` map slot. Slots
are name-keyed at this protocol version; the pre-existing slots keep their names and contents
(no index shift to adapt), which the whole suite proves behaviorally.

The original task enumerated "+3 fee storage slots"; the count at the pin is **4**. The 4-slot
envelope was **ratified by Phil (2026-07-29, round-2 revise — independently verified against the
protocol source at the pin)**: `AuthNetworkAccount` mandates a `FeePolicyManager`, which
mandates an active `FeePolicy`; `BasicConstantFeePolicy` is the only stock policy and carries
its own `fee_schedule` slot — the 4th slot is pin-forced (the only path to 3 slots would be a
custom MASM fee policy, which inverts the migration's purpose). All four slots revert together
at FF-5.

### 5.2 A2 — the provisional zero-fee configuration

Every `AuthNetworkAccount` constructor at the pin — including `custom()` — requires a
`FeePolicyManager` (an `AccountId` fee faucet + an ACTIVE `FeePolicy`); there is no none-variant.
The decided configuration, wired in `XReserveStablecoinBuilder::provisional_fee_policy_manager()`
and pinned by `tests/fee_policy_provisional_pin.rs`:

- Policy: **`BasicConstantFeePolicy` with an EXPLICIT ZERO fee scheduled for each of the 14
  allowlisted note-script roots** — NOT an empty schedule. At this pin the auth procedure prices
  EVERY consumed input note through the active fee policy regardless of the chain's base fee, and
  `BasicConstantFeePolicy` ABORTS on a script root with no schedule entry ("note script has no
  fee schedule entry") — an empty schedule would brick every note consume. The binding coupling
  invariant, stated once and pinned executably: **schedule ⊇ note-script allowlist** — every
  allowlisted root MUST carry a (zero) schedule entry, or an allowlisted note aborts fee
  estimation. The provisional config pins the two sets EQUAL (zero entries for exactly the 14
  roots, nothing else scheduled); `fee_policy_provisional_pin.rs` enforces both directions.
- `fee_faucet_id`: the placeholder constant `TBD_DEPLOY_FEE_FAUCET_ID_HEX` — the faucet's OWN id
  is the intended value but cannot exist at composition time (the id derives from the very
  storage this value initializes), so deploy-time configuration must replace it.
- No second allowed policy: the `allowed_fee_policy_proc_roots` map holds EXACTLY the active
  `BasicConstantFeePolicy` root (pinned at the component AND on-chain layers), so the owner-gated
  `set_fee_policy` (Tier B: direct-entry-unreachable) would have nothing to switch to even if it
  were ever driven.
- The config site carries a plain-English provisional comment.

> Fee economics for the keyless xReserve faucet are OPEN. Circle decides the real fee asset + policy before any fee-charging-chain deploy. This migration pins a zero-fee provisional config that is inert on MockChain (verification base fee = 0).

**MockChain inertness, verified at the pin:** `MockChain::builder()` initializes
`verification_base_fee = 0` ("no fees are required by default"); no test in this workspace sets a
base fee; the auth procedure's fee leg creates a TX_FEE note only on chains with a nonzero base
fee, and sponsored-fee collection only acts on FEE_SPONSORSHIP input notes, which the preserved
allowlist never admits. No MockChain tx charges, moves fee value, or changes an assert's
reachability — the full suite runs green with the config in place.

**Disambiguation:** the `#3351`/`FeePolicyManager` fee is the protocol network-transaction fee
mechanism. It is ORTHOGONAL to CC-FEE-1's DepositIntent `maxFee`/`feeAmount` wire semantics — the
MVP `feeAmount==0` hard reject and the signed `maxFee<=amount` compare are untouched by this
migration (the wire vectors are byte-identical and the R-MINT negative suites run unchanged).
`fee_faucet_id` is a STORAGE value, not a code root — it moves no callable-surface root.

### 5.3 A3 — the `custom()` composition (the fixture bypass)

Verified in upstream source at the pin: `AuthNetworkAccount::new()` force-inserts the
`NetworkAccountConfigNote` + `FeeSponsorshipNote` script roots into the note allowlist (and the
expiration script into the tx allowlist); `custom()` inserts NOTHING; the miden-testing
`Auth::NetworkAccount` fixture routes through `new()`. Consequences executed:

- The production `XReserveStablecoinBuilder::auth_component()` constructs via `custom(…)` +
  `with_allowed_tx_scripts([ExpirationTransactionScript::script_root()])` — the preserved 14-root
  note allowlist and 1-root tx allowlist, exactly.
- The test-support production fixture no longer uses `Auth::NetworkAccount`: the account is built
  with the production `auth_component()` itself (single-sourcing the composition the tests
  exercise with the composition that ships) and registered without an authenticator — identical
  to the fixture's behavior for a keyless network account (its authenticator is `None`).
- `tests/config_note_absence.rs` is the dedicated negative assert: the config-note and
  fee-sponsorship roots are ABSENT from the builder set, the component storage, and the built
  account's on-chain allowlist, which holds EXACTLY 14 roots. Introduced RED against the naive
  `new()`-based bridge composition (the roots WERE present — the red log is the posture proof
  that the assert bites), turned GREEN by the `custom()` switch. `with_allowed_tx_scripts` now
  EXTENDS instead of replacing — equivalent here because `custom()` starts the tx allowlist
  empty.

### 5.4 Why this is still behavior-preserving in effect

No new authorized entry point exists (the allowlists are membership-identical and exact); the fee
configuration is zero and inert on the only harness this workspace runs; every reject path
rejects the same inputs for the same causes (the ~33-site error-string surface re-verified, zero
loosened); the wire bytes are untouched (the vectors diff is empty). The growth and the
provisional config are flagged TEMPORARY and revert at V16-FINAL (§9).

## 6. Re-pin ledger (derivation-mandatory)

Every value in the repo that is a function of the dependency versions was re-derived at the pin
(never copied from a failure message without its derivation). The complete enumeration of the
candidate surface (measured in Phase 0): the 12 pinned admin note-script root constants under
`crates/xusdc-encoding/src/note/xreserve_admin/*.rs`, the two path-keyed tables
(`account_callable_surface.rs` 64→75 paths, `mint_root_surface.rs` 15 paths — paths, not hexes),
the `P2ID_SCRIPT_ROOT` felt-array constant in `asm/standards/xreserve/mint_policy.masm`, the two
recompiled "former root" constants, the vendored pinned-standards fixtures + checksums + version
anchor, and the miden-crypto-derived golden-vector leaves.

### 6.1 Values that MOVED (the complete list)

| Constant | File | Old | New | Upstream cause | Derivation |
|---|---|---|---|---|---|
| `XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX` | `src/note/xreserve_admin/ownership.rs` | `0x4480f83f0c08d6c0d7e3480c62f0dc296a29489fd631ce78615bacb017352104` | `0xbd3521ade61e55d119662701fb02c171177a698711ac1a1bfd7ae36f839152c1` | `ownable2step.masm`: the dedicated no-nomination assert (`ERR_NO_NOMINATED_OWNER`) was removed from `accept_ownership` (the sender-vs-nominated-owner compare covers the case) — the stock procedure's digest changed, and the note script `call`s it by root | recompile the shipped factory script and read `XReserveAcceptOwnershipNote::script_root()` (the parity test in `f5_admin_notes.rs` performs exactly this recompilation) |
| `POLICY_MANAGER_FNV1A` | `tests/xreserve_receive_and_burn.rs` | `17561546685770092653` | `9086050222570077779` | `policy_manager.masm` re-vendored at the pin (public-interface section reorg + doc wording; no procedure added/removed/re-signatured) | FNV-1a over the re-vendored bytes (the recipe in `PROVENANCE.md`; byte-identical `cp` + `diff` from the cargo git checkout) |
| version anchor → rev anchor | `tests/xreserve_receive_and_burn.rs` | `PINNED_STANDARDS_VERSION = "=0.16.0-alpha.4"` (parses `version = "…"`) | `PINNED_STANDARDS_REV = "dbe4e38797207ce09fee1668ea204aafec275f63"` (parses `rev = "…"`) | the dependency moved from a crates.io version pin to a frozen git rev — the `version` key no longer exists on the manifest lines the anchor binds to | the anchor's own design (re-keyed to the pin form; the non-vacuity companion test updated in lockstep) |

### 6.2 Values verified UNMOVED (re-derived, not assumed)

- The other **11 admin note-script root constants** (`config.rs` ×6, `roles.rs` ×2,
  `ownership.rs` transfer_ownership, `blocklist.rs` ×2): their parity tests recompile each
  shipped script at the new toolchain and pass against the existing pins — the 0.25.8 assembler
  did not re-key MAST, and none of their callee procedure bodies changed.
- **`P2ID_SCRIPT_ROOT`** (`asm/standards/xreserve/mint_policy.masm`): re-derived via
  `P2idNote::script_root()` at the pin → `[7131697192369665042, 13614976149584716721,
  15020972229364874097, 1084006998777425639]` — byte-for-byte the existing constant. Zero MASM
  edits in this migration.
- **`FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT_ROOT_HEX`** (`f5_admin_notes.rs` + the non-membership
  duplicate in `account_surface_unreachable.rs`): the preserved source still recompiles to
  `0x0c69fe1a…` (its callees — rbac grant/revoke path — are digest-stable at the pin).
- **`fungible.masm`** fixture: byte-identical at the pin; `FUNGIBLE_FNV1A` unchanged.
- The **golden-vector crypto leaves** (`b32.expected_key`, `att.packed_felts`,
  `att.expected_commitment`, `att.derivation`): miden-crypto stays `0.28.0`, so nothing moved —
  consistent with the wire-freeze gate (`git diff … tests/vectors/` is EMPTY).
- `FORMER_CUSTOM_MINT_NOTE_ROOT_HEX` (`wave1_recomposition.rs`): a historical value of a DELETED
  source (non-recompilable); used for non-membership only — kept as-is by design.

## 7. ROOT-DELTA + GROWTH RATIFICATION TABLE (for Phil, row-by-row)

### 7a. RE-MATERIALIZATION (every re-pinned value)

Exactly three values moved; the full old→new rows with upstream cause and derivation are §6.1
(one note-script root constant, one fixture checksum, the fixture provenance anchor re-keyed from
a crates.io version to the git rev). Every other candidate value was re-derived and verified
UNMOVED (§6.2) — in particular all remaining 11 admin note-script root pins, the P2ID root
constant in the mint-policy MASM, and every golden-vector leaf.

### 7b. GROWTH (every A1 row — two ratified reachability tiers per §5.1, TEMPORARY per §9)

The callable-procedure surface grows 64 → **75** — exactly these 11 rows and nothing else
(verified by set-equality against the frozen literal list at both the component layer and the
committed on-chain account):

| # | Procedure (component-wrapper path) | MAST root | Class / tier | Reachability argument |
|---|---|---|---|---|
| 1 | `…auth::network_account::add_allowed_note_script` | `0x83cf2a01c8bd05d7e59084e7c16577dee77a99300ab4e7141fb67e5bc616b0cf` | #3355 mutator / Tier A | TRULY UNREACHABLE: no allowlisted note references the root (exhaustive MAST sweep over all 14); not a member of either allowlist; the config note that drives it is NOT allowlisted (`config_note_absence.rs`) |
| 2 | `…auth::network_account::remove_allowed_note_script` | `0xb2a6e6e034c35baf49c915975b884d12698f97185635ce4090b43dfd89fded01` | #3355 mutator / Tier A | same |
| 3 | `…auth::network_account::add_allowed_tx_script` | `0x9e92292aa78054398787a82718d71d2d163a9aa8a2d2fb7458792e2fc6255b2c` | #3355 mutator / Tier A | same |
| 4 | `…auth::network_account::remove_allowed_tx_script` | `0xc1cc11b14268471327968fab4057f6dbdcc5a12e5cb25bbaddb29e2c5fbbc8dd` | #3355 mutator / Tier A | same |
| 5 | `…auth::network_account::estimate_note_fee` | `0xb0faa8a0f79c91c3d80399a3bc2298afa6dd7b570a634c09264ed8d196331d3c` | #3351 fee / Tier B | NO EXTERNAL ENTRY (not in either allowlist; no allowlisted note references it directly); the estimation path runs INTERNALLY on every input note via the auth procedure, computing the scheduled explicit zero — internally active but inert |
| 6 | `…auth::network_account::get_fee_asset_id` | `0x30a59816a7ba87c39f16beea4b7a0bb5176db3e8e8bea190a90595e86db10b3e` | #3351 fee / Tier B | same |
| 7 | `…auth::network_account::get_fee_policy` | `0x0b83d739e3469f1a4b832a8d15c6b54acf8dc854507b8f00cf6667a54adbb29f` | #3351 fee / Tier B | same |
| 8 | `…auth::network_account::set_fee_policy` | `0xda991a79b56f74d322f9a11858d0dc4fd550e7f5cf79821730de3b4bbaf33f20` | #3351 fee / Tier B | same |
| 9 | `…auth::network_account::add_allowed_fee_policy` | `0x13718a4dc7d1ffd9aa884aadf9a74ec0e1fab5159bebf6dda116df08dbcb9659` | #3351 fee / Tier B | same |
| 10 | `…auth::network_account::remove_allowed_fee_policy` | `0x19f5e03ef42650ffb776512497aa369541d39b11742eb3f18b6d43bb752a4e04` | #3351 fee / Tier B | same |
| 11 | `…fees::policies::basic_constant_fee::compute_note_fee` | `0xd4436136428c878a8ed42a0eef4c9e3f8da921f6c23983133d4baa0018df8e10` | fee-policy / Tier B | NO EXTERNAL ENTRY; the auth procedure dyncalls it internally on every input note (`collect_sponsored_fees` -> `estimate_note_fee_internal` -> dyncall), where it computes the scheduled explicit zero entry |

The executable proofs: `account_surface_unreachable.rs`
(`ratified_growth_rows_are_present…`, `tier_a_mutators_are_unreachable_from_every_allowlisted_note`,
`tier_b_fee_rows_are_not_referenced_by_any_allowlisted_note`,
`ratified_growth_rows_are_not_admissible_via_either_allowlist` — the last reads the tx-script
allowlist slot directly, so both-allowlist non-membership is asserted for all 11 rows) + the
generic executing rejection legs (any non-allowlisted note or tx-script is rejected, run
unchanged).

**Storage growth (enumerated the same way; all four revert together per FF-5):**

| Slot (name-keyed) | Owner component | Provisional value |
|---|---|---|
| `miden::standards::auth::network_account::active_fee_policy_proc_root` | AuthNetworkAccount | `BasicConstantFeePolicy::root()` |
| `miden::standards::auth::network_account::allowed_fee_policy_proc_roots` (map) | AuthNetworkAccount | exactly `{ BasicConstantFeePolicy::root() → [1,0,0,0] }` |
| `miden::standards::auth::network_account::fee_asset_id` | AuthNetworkAccount | `AssetId::new_fungible(TBD_DEPLOY_FEE_FAUCET_ID)` (placeholder `0xaaaaaaaaaaaaaa112aaaaaaaaaaaaa`) |
| `miden::standards::fees::policies::basic_constant_fee::fee_schedule` (map) | BasicConstantFeePolicy | exactly the 14 allowlisted note-script roots → `[0,0,0,1]` (explicit zero fee each) |

The 4-slot count (vs the task's estimated "+3") is **explicitly ratified by Phil (2026-07-29,
round-2 revise)**: the 4th slot is the mandatory active policy's own schedule slot, pin-forced
by the component composition (§5.1). The schedule ⊇ allowlist coupling holds by construction and
by pin: every one of the 14 allowlisted roots carries a zero entry, and nothing else is
scheduled. All four slots are pinned value-exactly by `fee_policy_provisional_pin.rs`
(component + on-chain layers, including the exactly-one-allowed-policy map). Slots are
name-keyed at this protocol version; no pre-existing slot moved or was renamed (no index shift
exists to adapt), which the full behavioral suite proves.

### 7c. Closing statements (explicit and exact)

- **Note-script allowlist membership unchanged: 14 roots before and after.**
- **Tx-script allowlist membership unchanged: 1 root** (the canonical expiration bounder).
- **Callable surface: 64 → 75, all 11 additions enumerated above, all TEMPORARY per FF-5.**

## 8. FUTURE-FIXES disposition (all five rows)

- **FF-1 — account-id felt order: MOOT, verified.** `#3422` (the pin's HEAD commit) removed
  `From<AccountId> for [Felt; 2]` from `crates/miden-protocol/src/account/account_id/mod.rs` and
  `…/account_id/v1/mod.rs`; no such impl remains at the pin (repo-wide grep). No canary is
  written; `account_id_to_felts` is untouched (accessor-based, `[prefix, suffix]`, same order the
  removed impl produced). This verification closes the tracker row.
- **FF-2 — standards-grade amount conversion: still BLOCKED.** `miden-standards` at the pin
  exports no u256→amount conversion (zero `u256`/`bytes32` hits in the crate). The closest
  primitive remains `miden-agglayer`'s `asset_conversion.masm`
  (`verify_u256_to_native_amount_conversion`, a verify-the-witness design) — byte-identical to
  alpha.4, in a crate the standards CodeBuilder does not link. Report-only; never a bump rider.
  [SUPERSEDED post-#44: the pin bump to `4971ec4b` picked up protocol #3423, which promoted the
  agglayer helpers into `miden-standards` (`miden::standards::utils`,
  `miden::standards::assets::asset_amount` — including `verify_u256_to_asset_amount_conversion`,
  the verify-the-witness conversion — and `miden::standards::interop::eth`), all linked by the
  standards CodeBuilder. UNBLOCKED: the faucet MASM now imports the generic helpers
  (byte-swap, limb merge, unaligned double-word load, pow10, build_felt) from the standards
  library instead of keeping local copies.]
- **FF-3 — V16-FINAL: deferred by definition.** This migration is #1 of 2. Parked/temporary
  state tied to FF-3 as the revert/re-enable vehicle: the validation crate + LNV harness
  (`PARKED-V16-NEXT.md`), the A1 growth + A2 provisional fee (FF-5, §9), and the crates.io
  `=0.16.0` flip itself.
- **FF-4 — upstream admin config/action notes: exist, adoption deferred to W2-ADMIN tier-2.**
  Corrected naming at the pin: there are no `PauseConfigNote`/`BlocklistConfigNote`; the family
  is `PauseActionNote`, `RbacActionNote`, `OwnerActionNote`, `FaucetPolicyActionNote` (all
  already present at alpha.4) plus the NEW `NetworkAccountConfigNote`, `FeeSponsorshipNote`, and
  `TX_FEE` note. The #3355 interaction is handled structurally by A1/A3: the mutator procedures
  are ratified Tier-A (truly unreachable) rows, and `custom()` keeps every config-style note root OUT of the
  note allowlist (`config_note_absence.rs` + the exact-set pins prove it).
- **FF-5 — revert the V16-NOW temporary growth + provisional fee: OPENED BY THIS MIGRATION.**
  What reverts at V16-FINAL / the S-FINAL auth-wrapper: the thin auth wrapper exposing only
  `auth_network_transaction`; `FROZEN_ACCOUNT_SURFACE` re-tightened from 75 back toward 64; the
  11 growth rows and their unreachability section removed; the provisional zero-fee config +
  `TBD_DEPLOY_FEE_FAUCET_ID_HEX` replaced by Circle's ratified fee economics; the 4 fee storage
  slots re-dispositioned accordingly. The executable tripwires the revert will flip:
  `fee_policy_provisional_pin.rs` and the 75-count surface pin. The ratification table (§7) is
  what the revert is checked against.

## 9. TEMPORARY-ratification framing

The A1 growth and the A2 provisional fee are TEMPORARY, tracked as FF-5 ("Revert the V16-NOW
temporary surface growth + provisional fee config"). `CIRCLE-CONFORMANCE.md` CC-SURFACE-1 carries
a TEMPORARY-GROWTH flag pointing at FF-5; G-AUDIT cannot pass while FF-5 is open. Neither tracker
file lives in this repo — the pointers exist so the grown count is treated as a flagged temporary
state, never as the new permanent contract. (Both referenced files are external trackers; nothing
in this repo marks anything Circle-approved, resolves no `DEV-*`/`Q-*` row, and the A2 register
note above DOCUMENTS a new open Circle decision — it approves nothing.)

## 9a. G3 file-size exemption — `builder/mod.rs` (human-ratified, split deferred to S2)

`crates/xusdc-encoding/src/account/xreserve/builder/mod.rs` stands at 810 lines against the G3
~500–700-line Rust ceiling. **Ratified exemption (Phil, 2026-07-29, round-3 revise):** the file
was ALREADY over the ceiling at the migration base (757 lines at `8a3fb04`); this
behavior-preserving migration added only the +53 lines of the FORCED provisional fee
configuration (the constant, the manager factory, and the `custom()` composition — all of it
pin-mandated). A mid-migration split would be out-of-scope churn inside a frozen-surface change;
**the split is deferred to S2** (the Rust hygiene slice already touching this module). This
recorded human exemption discharges the G3 gate for this migration. (BUILDER-GATES.md has no
exemptions register; this note is the record.)

## 9b. Lesson (process, recorded for the next stock-component migration)

The round-1 ratification envelope was under-counted ("+3 fee storage slots", five edit classes)
because it was ESTIMATED from the upstream change descriptions rather than DERIVED by fully
expanding the stock component composition. A stock component that expands via `IntoIterator`
(here: `AuthNetworkAccount` → auth component + every registered fee-policy component) must have
its envelope derived by full slot-by-slot and export-by-export expansion of everything the
composition yields — including the companion components' own storage — before the envelope is
frozen. Future stock-component migrations derive, not estimate.

## 10. Verification record

All gates run at the repo root against the working tree on `feat/v16-now-migration`
(base `8a3fb04`):

- `cargo build --workspace --locked --release` → **exit 0**.
- `cargo test --workspace --locked --release` → **exit 0: 1406 passed / 0 failed / 0 ignored**
  (104 suites; +1 test vs round 2 from the round-3 two-tier split, +5 from the round-4/5
  evidence-ledger integrity suite).
- `cargo clippy --workspace --all-targets --locked --release` → **exit 0, zero warnings**
  (matches the empty baseline inventory).
- `cargo clippy --workspace --locked -- -D warnings` (house gate) → **exit 0**.
- `cargo fmt --all -- --check` → **exit 0**.
- The masm_structure conformance test ran green inside the full suite (no `.masm` source
  changed; the only touched `.masm` is the vendored read-only fixture).

**Count reconciliation (line-item):**

| | passed | failed | ignored |
|---|---|---|---|
| Baseline @ `8a3fb04` (4 crates) | 1580 | 0 | 6 |
| − the parked validation crate | −190 | | −6 |
| Post-park (3 crates, alpha.4) | 1390 | 0 | 0 |
| + `config_note_absence.rs` (new) | +3 | | |
| + `fee_policy_provisional_pin.rs` (new) | +4 | | |
| + the growth-row proofs in `account_surface_unreachable.rs` (new; 4 since the round-3 tier split) | +4 | | |
| + the evidence-ledger integrity tests (`migration_evidence_ledger.rs`, new in round 4; +1 in round 5: the byte-for-byte baseline-diff correspondence test) | +5 | | |
| **Final @ the pin** | **1406** | **0** | **0** |

No test deleted, no assertion loosened, no `#[ignore]` added; the six baseline `#[ignore]`s were
all the parked crate's operator-run LNV legs.

**Wire freeze:** `git diff 8a3fb04..HEAD -- crates/xusdc-encoding/tests/vectors/` is **empty**
(0 bytes).

**Surface counts:** `FROZEN_ACCOUNT_SURFACE` re-frozen at **75** = 64 + the 11 enumerated A1 rows
(§7b); the note-script allowlist proves **14 roots exactly** and the tx-script allowlist **1
root** at the source, component, and on-chain layers.

**Graph:** exactly one version of every `miden-*` crate; the four dependency pins (+ their three
monorepo siblings) at the frozen rev; the VM family uniformly `0.25.8` (§1.2). Zero git
dependencies pin a branch (`grep -rn 'branch *=' Cargo.toml crates/*/Cargo.toml` → empty).

**Mutation demos (each demonstrated RED, then reverted; the full suite re-ran green after):**

1. Flipping the re-pinned `XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX` by one hex digit →
   `f5_admin_notes::accept_ownership_note_script_root_is_pinned` FAILED.
2. Sneaking `NetworkAccountConfigNote::script_root()` into
   `XReserveStablecoinBuilder::allowed_note_scripts()` → all three
   `config_note_absence.rs` tests FAILED (source, component, and on-chain layers).
3. Changing the provisional fee policy to a nonzero constant (`with_fee(root, 1)`) →
   `fee_policy_provisional_pin::fee_schedule_is_zero_for_exactly_the_allowlisted_roots` and
   `…built_account_fee_storage_matches_the_provisional_config` FAILED.

**Test-first record:** the two new test files landed BEFORE the posture change, compiled against
the naive `new()`-based bridge composition, and ran RED there (5 of 7 assertions failing — the
two green ones are source-literal pins, green by construction and documented as such); the
`custom()` switch + provisional configuration turned them GREEN with no test edits in between.

## 11. Round-2/3 evidence appendix (the corrected-envelope + two-tier revises)

Round-2 scope (Phil's ratification, 2026-07-29): documentation of the ratified 4-slot / 6-class
envelope, the fee-schedule semantics correction, this evidence appendix, the
`PARKED-V15.md` revert (the validation crate is byte-intact apart from `PARKED-V16-NEXT.md`),
and ONE additive assertion inside the sanctioned class-4 pin file
(`fee_policy_provisional_pin.rs`: the ON-CHAIN allowed-fee-policy map holds EXACTLY the active
`BasicConstantFeePolicy` root — the component-layer twin existed since round 1). No pin, wire
byte, allowlist, or migration mechanics changed.

Round-3 scope (Phil's ratification, 2026-07-29): the two-tier reachability posture (§5.1)
replacing the flat "unreachable" wording in the doc, the surface-pin comments, and the
`account_surface_unreachable.rs` growth section (the one MAST sweep split into the Tier-A
unreachability sweep + the Tier-B no-direct-reference sweep — no assertion dropped, and the
both-allowlist non-membership assert was STRENGTHENED to read the tx-script allowlist slot
directly, so the suite grew 1400 → 1401); the recorded G3 exemption for `builder/mod.rs` (§9a);
this evidence wiring to `MIGRATION-V16-NEXT-EVIDENCE.md`; and the corrected workspace
`Cargo.toml` no-patch rationale comment.

Round-4 scope (auditor REVISE): the evidence ledger regenerated FULLY VERBATIM from
`git diff --unified=3 8a3fb04` — every row now carries the file, the untruncated `@@` header,
and one class; the three sanctioned new test files appear as whole-file `@@ -0,0 +1,N @@` rows
(intent-to-add staged so git itself emits them); totals reconciled (168 rows / 165 hunks / 3
splits). The ledger's completeness and shape are now guarded executably by the NEW
`tests/migration_evidence_ledger.rs` (written test-first: RED against the round-3 ledger, GREEN
after regeneration), which also cross-checks each new-file row's stated line count against the
file's real line count. The §11.2 overview row for `account_surface_unreachable.rs` was
corrected to the two-tier shape.

Round-5 scope (auditor REVISE): the ledger tripwire gained its load-bearing leg —
`ledger_rows_match_the_baseline_diff_exactly` derives the expected `(file, full @@ header)` set
from `git diff --unified=3 8a3fb04` over the declared scope AT TEST TIME (new files synthesized
from their real line counts when untracked) and requires exact set equality with the ledger, so
a valid-looking but false coordinate/context, a dropped hunk, or a phantom row now fails the
suite (proven RED with the auditor's own `-999` false-coordinate mutation, GREEN on revert). The
`account_callable_surface.rs` overview row gained its missing class-6 mention.

### 11.1 Verbatim gate output

The FULL verbatim stdout+stderr of every gate command — the complete suite-by-suite
`cargo test` output for every suite included, nothing summarized — lives in
**`docs/MIGRATION-V16-NEXT-EVIDENCE.md`** §1 (captured in round 4, after the evidence-ledger
integrity suite joined; totals 1406 passed / 0 failed / 0 ignored across 104 suites, every exit
code 0; re-captured in round 5).

Mutation demos: demo 3 (nonzero fee) was RE-RUN in round 2 against the strengthened pin file —
`fee_schedule_is_zero_for_exactly_the_allowlisted_roots` and
`built_account_fee_storage_matches_the_provisional_config` FAILED under the mutation, and the
suite returned green after the revert. Demos 1 (root-constant flip) and 2 (config-note smuggle)
stand on their round-1 records (their code paths are unchanged this round).

### 11.2 Per-hunk tripwire classification (classes per §3.1)

The COMPLETE one-row-per-`@@`-hunk ledger — every `@@` hunk of `git diff 8a3fb04 -- <file>` for
every tripwire file and every ROOT_HEX-enumeration file, each row carrying its single sanctioned
class, with two-class hunks split into two rows and the class-6 iterator rows included — lives
in **`docs/MIGRATION-V16-NEXT-EVIDENCE.md`** §2. The file-level overview below summarizes the
same classification:

| File | Hunks → class |
|---|---|
| `tests/vectors/**` (Circle ground truth + golden vectors) | **ZERO hunks** (diff empty — the wire freeze) |
| `tests/constant_parity.rs` | **ZERO hunks** (untouched) |
| `tests/basic_asset_tripwire.rs` | **ZERO hunks** (untouched — its assertions never needed even a class-5 hunk) |
| `tests/wave1_recomposition.rs` | **ZERO hunks** (untouched; `FORMER_CUSTOM_MINT_NOTE_ROOT_HEX` unchanged by design) |
| `tests/account_callable_surface.rs` | class 3: the 11 growth rows + their two comment blocks, `[&str; 64]`→`[&str; 75]`, the 60-stock/75-root count prose (header + const doc + assert messages); class 6: the `components.push(auth.into())` → `components.extend(auth)` hunk in `production_components`; class 5: 3× `build_tx_context`→`build_transaction` chains |
| `tests/account_surface_unreachable.rs` | class 3: header addendum, S21 count-prose rewording, the V16-NOW two-tier growth section (`TIER_A_MUTATOR_ROWS` + `TIER_B_FEE_ROWS` + FOUR proof tests: presence, the Tier-A unreachability MAST sweep, the Tier-B no-direct-reference sweep, both-allowlist non-membership); class 6: the `extend(auth)` hunk + the `.into_iter().next()` extraction inside the non-admissibility test; class 5: 1× `build_transaction` chain; class 1: none (its `FORMER_SET_ROLE_ADMIN…HEX` literal is UNCHANGED) |
| `tests/surface_count_prose_conformance.rs` | class 3: ground-truth tuple `(15,49,64,14)`→`(15,60,75,14)`, superseded list += `"64-root"`, `"49 stock"` (+ era comment); class 6: 1× `push(auth.into())`→`extend(auth)` in `derive_surface_counts` |
| `tests/s12_expiration_tx_script_allowlist.rs` | class 6: 2× `.into()`→`.into_iter().next()` (auth-component extraction); class 5: 2× `build_transaction` chains |
| `tests/f5_network_account_auth.rs` | class 6: 1× `custom(…)` + `.into_iter().next()` in `stock_network_auth_proc_root` (with the provisional manager as the required ctor argument); class 5: 3× `build_transaction` chains + the removed now-unused `core::slice` import; class 4-adjacent doc: the header paragraph describing the fixture bypass |
| `tests/mint_root_surface.rs` | class 5: `as_ref::<Library>`→`as_package()` + the matching comment word |
| `tests/config_note_absence.rs` | class 4: NEW file, sanctioned in full |
| `tests/fee_policy_provisional_pin.rs` | class 4: NEW file, sanctioned in full (round 2 added the on-chain allowed-map exact assert — additive, same class) |
| `tests/support/mod.rs` | class 4: `add_network_faucet_account` + the production-fixture switch (the `Auth::NetworkAccount` bypass); class 5: `Library`→`Package` imports/types, 15× `build_transaction` chains, 2× `expected_output_note`, 1× `as_package`, removed unused import |
| `tests/support/mint_transport.rs` | class 5: 2× `build_transaction` chains |
| `tests/f5_admin_notes.rs` | class 5: 40× `build_transaction` chains + removed unused `core::slice` import (its `FORMER_SET_ROLE_ADMIN…HEX` and 11 of 12 root pins UNCHANGED; the accept_ownership pin lives in `src/…/ownership.rs`, class 1) |
| `tests/xreserve_receive_and_burn.rs` | class 1: `POLICY_MANAGER_FNV1A` re-checksum + the version→rev anchor re-key (const, parser, non-vacuity twin, doc comments); class 5: 2× `build_transaction` chains |
| `tests/fixtures/pinned-standards/{policy_manager.masm, PROVENANCE.md}` | class 1: byte-identical re-vendor at the pin + provenance rewrite (`fungible.masm` byte-identical, checksum unchanged) |
| R-MINT/R-BURN + remaining suites (`mint_policy_binding_e2e`, `mint_scale_conformance`, `xreserve_burn`, `burn_policy`, `masm_dual`, `assembled_faucet_e2e`, `pause_admin`, `role_admin`, `transfer_blocklist_e2e`, `transfer_blocklist_semantics`, `builder_api`) | class 5 ONLY: `build_transaction` chains (per-site log in the round report), `expected_output_note` (2), `as_package` (4), `with_dynamically_linked_package`, removed unused imports. **No assertion, polarity, or pinned value touched anywhere.** |

Outside the tripwire fence (not tripwire files; listed for completeness): the 4 manifests + lock
(the pin flip + park), `src/account/xreserve/builder/mod.rs` (the A2/A3 production composition —
the ratified dispositions themselves), `src/note/xreserve_admin/ownership.rs` (class 1: the one
moved root), `src/note/xreserve_admin/mod.rs` (class 5: one rename), the docs
(`MIGRATION-V16-NEXT.md`, `PARKED-V16-NEXT.md`, `DOCS-INVENTORY.md` rows).

### 11.3 The class-6 hunks — per-hunk no-drop / no-reorder proof

Upstream contract: `AuthNetworkAccount: IntoIterator` yields **the auth component FIRST, then
the components of every registered fee policy** (upstream doc + upstream's own
"auth component is yielded first" test). Per hunk:

1. `account_callable_surface.rs::production_components` — `extend(auth)` appends **all** yielded
   components in yield order. No-drop proof: the same file's set-equality pins the 75-path set
   INCLUDING `basic_constant_fee::compute_note_fee` (present only if the policy component was
   installed), and the on-chain layer re-proves it against `account.code().procedures()`.
2. `account_surface_unreachable.rs::production_components` — same hunk;
   `ratified_growth_rows_are_present_on_the_account` requires the `compute_note_fee` root on the
   committed account.
3. `surface_count_prose_conformance.rs::derive_surface_counts` — same hunk; the derived tuple
   equality `(15, 60, 75, 14)` fails on any dropped (→74) or duplicated (→76) component.
4. `s12…::auth_component_tx_script_allowlist_is_exactly_the_expiration_root` —
   `.into_iter().next()` deliberately takes ONLY the first (auth) component to inspect its own
   allowlist slot; **no account is composed here**, so nothing can be dropped from any account.
   Self-checking: if `next()` ever yielded a non-auth component, `allowlisted_keys` panics on
   the missing slot.
5. `s12…::auth_component_note_script_allowlist_is_untouched_by_s12` — identical reasoning.
6. `f5_network_account_auth.rs::stock_network_auth_proc_root` — `.into_iter().next()` +
   `.procedures().find(|(_, is_auth)| *is_auth)`; a non-auth component would fail the
   auth-procedure search loudly; no account composed.

Corroboration that the FULL expansion always reaches composed accounts: the production account
path (`support::add_network_faucet_account`) installs `with_components(auth_component()?)` —
every yielded component — and the independent on-chain pins prove all four fee slots AND the
75-procedure surface on the committed account (`fee_policy_provisional_pin.rs`,
`account_callable_surface.rs`).

### 11.4 No-extra-allowed-policy assertion (REVISE item 5)

`fee_policy_provisional_pin.rs` pins the allowed-fee-policy map to EXACTLY
`{ BasicConstantFeePolicy::root() → [1,0,0,0] }` at BOTH layers:
`auth_component_fee_slots_hold_the_provisional_config` (component storage, round 1) and
`built_account_fee_storage_matches_the_provisional_config` (on-chain committed account, the
round-2 additive assert). With no second allowed policy registered, the owner-gated
`set_fee_policy` — a Tier-B ratified row with no external entry point — has nothing to switch to
even in principle.
