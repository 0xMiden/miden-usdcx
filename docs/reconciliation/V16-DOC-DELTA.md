# V16 DOC & COMMENT RECONCILIATION — the CDR-2 delta record

**Role.** The CDR-2 deliverable of the post-migration Conformance & Documentation
Reconciliation (CDR) gate: for every SEMANTIC row of `docs/MIGRATION-V16-ALPHA2.md` (the
"S-ids"), the greps below were mechanically derived from the OLD internal each row replaced,
run over `asm/`, `crates/`, `docs/spec/`, `README.md`, and `docs/DOCS-INVENTORY.md`, and every
hit adjudicated: **stale → corrected** (§2), **still-true → verified-current** (§3, recorded so
the adjudication is auditable, with the v16 code line that proves it). Line numbers are as of
this branch (`cdr/v16-verify`, working tree).

**RE-RUN provenance.** The first CDR walk ran on branch `cdr/v16` off `f979afd` and ended STOP;
that branch was never merged, so its doc corrections did NOT reach `implementation`. This
re-run (off `076a720`, the cdrfix merge) re-applied every still-valid correction from the first
walk, RE-DERIVED the S21-affected corrections against the post-flip reality (the runtime
`set_role_admin` note is now REMOVED — the first walk's "conditional backstop / escalated
STOP" caveats would themselves be stale today), verified the S21 surfaces PR #17 had already
corrected, and re-ran every grep against the actual tree (which now also contains the merged
relayer R4/R5 slices).

**Behaviour frozen.** Every edit in §2 is prose (Markdown, `///`/`//` Rust doc/inline comments,
two assert *message* strings whose asserted values are unchanged named constants). The full
suite pass count is IDENTICAL before and after (434 + 323, exit 0 — see
`CDR-RECONCILIATION-REPORT.md` §4), proving no edit perturbed runtime.

**Scope guard.** `docs/governing/*` untouched (read-only mirrors); golden vectors untouched;
`docs/MIGRATION-V16-ALPHA2.md` body untouched EXCEPT four bracketed
`[renumbered → IMPL-DEV-25/26 …]` annotations on its migration-time GLOSSARY pointers (a
records-accuracy cross-reference fix required by the CDR-3 numbering reconciliation — the
map's historical narrative is not rewritten; the repo's established `[SUPERSEDED →]` annotation
pattern is followed).

---

## 1. The derived greps (per semantic row)

Run from the repo root. The auditor re-runs these EXACTLY; after this pass each must return
zero stale hits (hits that remain are the §3 verified-current sites, each with its
justification).

Every command below is LITERAL and runnable verbatim from the repo root — the three disclosed
exclusions (see "Grep transparency") are encoded as `--exclude-dir` flags, not applied by hand:
`--exclude-dir=xusdc-validation` (the parked v15 crate), `--exclude-dir=pinned-standards` (the
vendored stock fixtures), `--exclude-dir=vectors` (the golden-vector JSON).

| S-row | Grep(s) run (literal) |
|---|---|
| S16 (pubkey repr) | `grep -rn "9 felt\|nine felt\|9 limb\|9 u32\|9 % 8\|not hmerge\|33-byte\|9-felt\|PK(9)\|pubkey(9)\|pad(2)\|9 words\|36 felts\|9-word\|→ 9\|17 + 9\|compressed pubkey" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/spec/ README.md` — 73 hits, every one a §2 correction or a §3 adjudication |
| S16 (allowlist-keying claims) | `grep -rni "keyed by" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/spec/ README.md` — the round-2 audit's lesson: "the allowlist is keyed by the 33-byte key" phrasings assert the OLD preimage without any 9-felt keyword; every remaining hit either names the commitment as the key or says "derived from" (§2/§3) |
| S21/S2 (role authority) | `grep -rn "owner-only\|owner only\|owner-administered\|owner-gated\|set_role_admin" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/spec/ README.md` + the concept set `grep -rn "unbreakable\|never stripped\|upstream-forced\|backstop\|administers\|auto-follow" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/spec/ README.md` (the first walk's lesson: the false claim was phrased five different ways) |
| S21-flip (post-#17 staleness + stale counts/labels) | `grep -rn "escalated for\|re-ratification\|CIR-ADMIN-3 STOP\|13-root\|13 roots\|13 ratified\|allowlist row 13\|allowlist rows 3-13\|row 13)" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/spec/ README.md` — 2 hits after the round-2/round-3 repairs (`account_callable_surface.rs:508` and `xreserve_admin.rs:462`, both the explicit historical phrase "allowlist row 10 of the old 13-root set"); the round-2 audit's row-label finds (f5_admin_notes.rs section headers 13/11/12) are corrected (§2d), which removed the third hit an earlier draft of this row counted |
| S1/#2944 (pause slot) | `grep -rn "is_paused\|assert_not_paused\|FungibleFaucet.*install\|installs the .is_paused\|PausableManager\|runs first\|checks pause first" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/spec/ README.md` |
| S18 (policy manager API) | `grep -rn "PolicyRegistration\|MintPolicyConfig\|BurnPolicyConfig\|TokenPolicyManagerError\|with_mint_policy(" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/spec/ README.md` |
| S3 (asset constructor) | `grep -rn "create_fungible_asset\|fungible_to_amount" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/spec/ README.md` |
| S23 (id-validate order) | `grep -rn "low.byte\|low byte" docs/spec/ README.md` |
| S12/S24 (stock surface) | `grep -rn "IMPL-DEV-2[0-9]" --exclude-dir=xusdc-validation --exclude-dir=pinned-standards --exclude-dir=vectors asm/ crates/ docs/ README.md` (mirror-consistency check — drives the §2 GLOSSARY renumber; every id must resolve to the SAME row in the repo GLOSSARY and the register) |
| S9 (pinned fixtures) | `grep -n "registry\|0.16" crates/xusdc-encoding/tests/fixtures/pinned-standards/PROVENANCE.md` |
| S17 (import syntax in doc snippets) | `grep -rn "use miden" docs/spec/ README.md` + `grep -rn -- "->" docs/spec/ README.md` (the ASCII arrow only — `→` is prose) |

Adjudication discipline: hits inside strings/identifiers that are not prose claims (e.g.
`domain_config.masm`'s `pad(2)` stack trackers — a real 2-element pad on a different
procedure's boundary; `gen_vectors.rs:300`'s "the v16 supersession of the 9-felt compressed
preimage" — a correct historical reference) are not stale and are left alone.

**Grep transparency (carried from the first walk's round-2 audit repair).** The greps above run
with exactly THREE disclosed, adjudicated exclusions, none of which is a prose surface: (a)
`crates/xusdc-encoding/tests/vectors/*.json` — golden-vector DATA, frozen (its `derivation`
strings are generator output, regenerated only under the map's §10 decision 1); (b)
`crates/xusdc-encoding/tests/fixtures/pinned-standards/*.masm` — vendored byte-identical stock
fixtures (never hand-edited by rule); (c) `crates/xusdc-validation/**` — the PARKED v15 crate,
deliberately byte-intact per migration row R1 (its "9 words / pubkey(9)" comments are CORRECT
for the v0.15.3 code they document; they update at the v16 LNV re-enable, per `PARKED-V15.md`).
Every other hit is either corrected (§2) or adjudicated verified-current (§3) — nothing is
silently filtered.

## 2. Corrections (every edit this re-run made)

`file:Lstart-Lend (post-edit) | old claim | corrected claim | driving S-row`

### 2a. Re-applied from the first walk (stranded on the unmerged `cdr/v16`; still valid verbatim)

| Site (post-edit) | Old claim | Corrected claim | S-row |
|---|---|---|---|
| `docs/spec/ENCODING-COMPONENT-SPEC.md:32` | DC-3 = `Poseidon2(33-byte compressed pubkey)` → Word | DC-3 = `Poseidon2(affine pubkey, 16 u32-LE felts: qx‖qy)` → Word; ingress stays the 33-byte compressed SEC1 key, this crate owns the SEC1→affine decompression (v16 supersession, vm#3342) | S16 |
| `docs/spec/ENCODING-COMPONENT-SPEC.md:43` | `pubkey_commitment` = Poseidon2 over the 9 u32-LE limbs of the 33-byte compressed pubkey; "domain tag `9 % 8 = 1`, so this is not `hmerge`" | Poseidon2 over the 16 u32-LE affine limbs (domain tag `16 % 8 = 0`), identical to miden-crypto 0.28 `PublicKey::to_commitment`; Rust decompresses the 33-byte wire key internally, MASM hashes the 16 staged felts | S16 |
| `docs/spec/GLOSSARY.md:148` (DC-3 row) | `Poseidon2(33-byte compressed pubkey)` → one Word | `Poseidon2(affine pubkey, 16 u32-LE felts)` → one Word; ingress stays 33-byte compressed SEC1, decompressed before hashing (v16, vm#3342) | S16 |
| `docs/spec/GLOSSARY.md:377` (TV-ATT-1) | "pubkey = 9 felts" | "pubkey = 16 affine felts (decompressed from the 33-byte compressed wire key)" | S16 |
| `docs/spec/GLOSSARY.md:378` (TV-ATT-2) | commitment is `Poseidon2(33-byte pubkey)` | commitment is `Poseidon2(affine pubkey, 16 felts)` = `PublicKey::to_commitment` | S16 |
| `README.md:46-52` | "the attestation byte→felt packing of the digest, **compressed pubkey**, and signature (`DC-2`)" | "…of the digest and signature plus the pubkey's SEC1→affine decompression and packing (`DC-2`/`DC-3`; the 33-byte compressed wire key stages as 16 affine felts since v16)" | S16 |
| `README.md:87-116` ("Real-local-node validation") | presented `cargo run -p xusdc-validation --bin …` commands as CURRENTLY runnable from this workspace, contradicting the migration's R1 park (the crate is workspace-excluded and does not build against v16) | section retitled "**PARKED at v15 (inherited evidence)**": states the park + trigger up front, presents the v15 LNV records as the inherited real-node evidence, and reframes the command block as **re-enable-time** instructions per `PARKED-V15.md` | R1 park (first-walk audit-found) |
| `crates/xusdc-encoding/tests/masm_mint_shell.rs:535` | doc comment: seam-attack advice = `[pubkey(9), sig(17)]` | `[pubkey(16), sig(17)]` | S16 |
| `crates/xusdc-encoding/tests/xreserve_mint_note.rs:517` | assert MESSAGE: "the attestation is exactly 9 words: [fee(8), pubkey(9), sig(17), pad(2)]" (the asserted VALUE is the named constant `XRESERVE_MINT_ATTACHMENT_NUM_WORDS` = 11 at v16 — only the message lied) | "the attestation is exactly 11 words: [fee(8), pubkey(16), sig(17), pad(3)]" | S16 |
| `crates/xusdc-encoding/src/vectors.rs:146-148` (`AttVector` doc) | "the 33-byte compressed pubkey (→ 9 felts)" | "(decompressed → 16 affine felts, vm#3342)" | S16 |
| `crates/xusdc-encoding/src/note/xreserve_mint.rs:152` (`create` doc) | "packed 17 + 9 felts into the scheme-1 attestation attachment" | "packed 17 + 16 felts …" | S16 |
| `crates/xreserve-deposit-relayer/tests/envelope_validate.rs:207-209` | "the commitment is unit-04's `pubkey_commitment` (DC-3) over the 33-byte compressed pubkey" | "…Poseidon2 over the affine coordinates the 33-byte compressed pubkey decompresses to (16 felts since v16, vm#3342)…" | S16 (first-walk audit-found) |
| `crates/xreserve-deposit-relayer/tests/fixtures/mod.rs:142-144` | "the wire form the allowlist commitment is taken over" | "the wire form the allowlist commitment is derived from (decompressed to 16 affine felts before hashing since v16, vm#3342)" | S16 (first-walk audit-found) |
| `crates/xusdc-encoding/tests/support/mod.rs:211-212` | "…and the 9-word size assert on the hash-verified attestation attachment" | "…the 11-word size assert … (9 words at v15; grew with the 16-felt affine pubkey, S16)" | S16 (first-walk audit-found) |
| `crates/xusdc-encoding/tests/constant_parity.rs:354` | assert MESSAGE: "compressed-pubkey felt count parity (33 bytes -> 9 u32-LE felts; ATT commitment input)" (the asserted VALUE — `PUBKEY_FELTS` parity, 16 at v16 — was already correct; only the message lied) | "affine-pubkey felt count parity (qx\|\|qy -> 16 u32-LE felts; ATT commitment input)" | S16 (first-walk audit-found) |
| `crates/xusdc-encoding/tests/f5_mint_shim_negatives.rs:57-59` | "attestation-shaped attachment (9 words; content immaterial…)" — the helper genuinely builds 9 zero words, but the phrase implied 9 words IS the attestation shape | "(9 zero words — deliberately NOT the v16 11-word attestation shape; immaterial here: the shim traps on count/scheme selection before any size/hash check runs in these negatives)" — code unchanged (behaviour frozen) | S16 |

Gate-hygiene edits (driven by the `cargo doc --no-deps --workspace` no-warnings gate, not an
S-row — all doc-comment prose: the first walk's three relayer warnings re-applied, PLUS the
nine private-item-link warnings this base added — one from PR #17's `builder.rs` doc, eight
from the merged relayer idempotency module):

| Site (post-edit) | Old | Corrected | Driver |
|---|---|---|---|
| `crates/xreserve-deposit-relayer/src/circle/client.rs:15` | `` [`build_http_client`] `` (public module doc linking a private item) | plain-code reference "the crate-private `build_http_client`" | doc gate (re-applied) |
| `crates/xreserve-deposit-relayer/src/circle/schema.rs:215` | `` [`PageCursors`] `` (unresolved from this module) | path link `` [`PageCursors`](super::pagination::PageCursors) `` | doc gate (re-applied) |
| `crates/xreserve-deposit-relayer/src/error.rs:130` | `` [`Self::from_deposit_intent`] `` (private item) | plain-code reference | doc gate (re-applied) |
| `crates/xusdc-encoding/src/account/xreserve/builder.rs:423` | `` [`seeded_dom_roles_rbac`] `` (public `allowed_note_scripts` doc linking the private helper — new with PR #17's doc) | plain-code reference "`seeded_dom_roles_rbac` (crate-private)" | doc gate (new this base) |
| `crates/xreserve-deposit-relayer/src/idempotency/mod.rs:84-87` | `` [`clock`]/[`record`]/[`store`]/[`cursor`]/[`recovery`]/[`rows`] `` (public module doc linking six private submodules) | plain-code references | doc gate (new this base) |
| `crates/xreserve-deposit-relayer/src/idempotency/store.rs:71,:82` | `` [`BUSY_TIMEOUT`] `` / `` [`durable_path`] `` (private items) | plain-code references ("the crate-private …") | doc gate (new this base) |

Inventory-completeness edits (`docs/DOCS-INVENTORY.md` claims to list EVERY repo Markdown doc —
the migration-era docs were missing; re-applied and then extended in the round-4/round-5 audit
repairs): added a "Migration & reconciliation (`docs/`)" section (`MIGRATION-V16-ALPHA2.md` +
the three `docs/reconciliation/` CDR outputs), the `crates/xusdc-validation/PARKED-V15.md`
row, a `crates/xreserve-deposit-relayer/` section with ALL THREE relayer records
(`DEFERRED-DEPENDENCIES.md`; round 4 added `PERSISTENCE-CHOICE.md` and `RIV-ADVICE-KEY.md` —
the latter cross-referencing its §3 v16-disclaimer adjudication), and the Root-table
`AGENTS.md` row (round 5 — the tracked, byte-identical canonical copy of `CLAUDE.md` was
missing from the "every Markdown document" claim).

### 2b. Re-run-specific corrections (post-flip; NOT the first walk's wording)

| Site (post-edit) | Old claim | Corrected claim | S-row |
|---|---|---|---|
| `crates/xusdc-encoding/tests/role_admin.rs:5-14` (module doc) | "byte-identical to the post-state of an **owner-sent** stock `set_role_admin` (**rbac.masm:314-333**)" — a v15 sender + a v15 line ref; "`DOM_MANAGER.admin_role` stays 0" with no grounding for WHY it stays | "a stock `set_role_admin(DOM_PAUSER, DOM_MANAGER)` (alpha.2 `rbac.masm:196-211`)"; "stays 0 … and since the S21 disposition flip (human-ratified 2026-07-14) the whole delegation graph deploys FROZEN at this seed: the runtime `set_role_admin` note is removed from the allowlist, so no on-chain sender can re-point or clear any role's admin (GLOSSARY IMPL-DEV-24; enforced by `account_callable_surface.rs`)" | S21-flip |
| `crates/xusdc-encoding/tests/role_admin.rs:20-27` (module doc) | "…asserted as a POSITIVE … never a config read-back, **and never stripped**" — at the first walk this was the FALSE structural claim; at `076a720` it is TRUE again but ungrounded | keeps the POSITIVE claim and GROUNDS it: "Since the S21 flip the backstop cannot be stripped on-chain: stock delegation is EXCLUSIVE (alpha.2 `rbac.masm:20-22`), but with the `set_role_admin` note removed the delegation configuration is immutable post-deploy, so `ADMIN`'s authority over `DOM_MANAGER` … is structurally fixed at the seed" | S21-flip |
| `docs/spec/FAUCET-COMPONENT-SPEC.md:119-128` (§5 Roles) | "role-based access control with a `DOM_MANAGER` role that administers `DOM_PAUSER`" (nothing more — silent on the v16 effective-admin model AND on the S21 flip) | adds the v16 model AND the flip: effective-admin gating (owner → `ADMIN` → `DOM_MANAGER` → `DOM_PAUSER`), the delegation graph **build-seeded and frozen** (note removed, S21 flip 2026-07-14), `rbac::set_role_admin` present-but-unreachable (`tests/account_callable_surface.rs`), rotation `grant_role`/`revoke_role` only — matching Circle's fixed `DomainManageable.sol` graph (→ `IMPL-DEV-24`) | S21/S2 + S21-flip |
| `docs/spec/GLOSSARY.md:260-265` (IMPL-DEV table) | table carried "IMPL-DEV-21" = S12 freeze/unfreeze and "IMPL-DEV-22" = S24 roots — COLLIDING with the Circle-facing register's IMPL-DEV-21 (fee reject) / IMPL-DEV-22 (renounce omission); no fee/renounce/RBAC rows existed in the repo mirror | register-canonical numbering applied in BOTH mirrors: the S12 row → **IMPL-DEV-25**, the S24 row → **IMPL-DEV-26** (each keeps a back-pointer naming its migration-time id); register rows **21 (fee reject — the RATIFIED Q-FEE-MVP deferral), 22 (renounce omission — 12-root count refreshed), 23 (RBAC — the REVERSED S21 acceptance, → IMPL-DEV-24)** mirrored in; IMPL-DEV-24 (the removal, added by PR #17) unchanged | S12/S24/S21 (CDR-3 mirror) |
| `docs/MIGRATION-V16-ALPHA2.md:164-167,:490-492,:718-719` | "GLOSSARY IMPL-DEV-21" / "GLOSSARY IMPL-DEV-22" (migration-time labels, now resolving to the WRONG rows — fee/renounce — after the renumber) | each annotated `[renumbered → IMPL-DEV-25/26 by the CDR-3 register reconciliation, 2026-07-14]` — the historical narrative is untouched; `git grep IMPL-DEV-2x` now resolves consistently | CDR-3 numbering |
| `crates/xusdc-encoding/src/account/xreserve/builder.rs:429-434` (`allowed_note_scripts` initializer) | the "row N" comment labels read as stale/mislabeled: entries sit in historical insertion order (3, 12, 4, 6, 7, 8, 5, 9, 10, 11), which after the 13→12 renumber looks like leftover drift (the cdrfix auditor's cosmetic flag) | a head comment states the labels are the notes' STABLE allowlist identities (1-12, shared with `note::xreserve_admin` and the tests), NOT initializer positions; records the 13→12 renumber provenance (set_role_admin formerly row 10). Comment-only — initializer order untouched, zero MAST/behaviour impact | cosmetic (sweep-up item 2) |

### 2c. S21 surfaces already corrected by PR #17 — VERIFIED this re-run (no edit needed)

| Site | What #17 wrote | Verified against |
|---|---|---|
| `crates/xusdc-encoding/src/note/xreserve_admin.rs:8-14,:459-467` | module doc "rows 3-12 … deliberately NO `set_role_admin` note (S21 disposition flip)"; the factory replaced by the SET_ROLE_ADMIN — NO FACTORY section (former root + removal rationale + enforcement pointers); rows 10/11/12 renumbered | `allowed_note_scripts()` = 12 entries; the enforcement tests green; the former root pinned in `f5_admin_notes.rs:1317` |
| `crates/xusdc-encoding/tests/role_admin.rs:754-839` | every `set_role_admin` test re-documented as a PROC-LEVEL CHARACTERIZATION pin (production-unreachable; the `dom_pauser_can_renounce_own_role` treatment) | tests green; production unreachability enforced by `account_callable_surface.rs:531-614` |
| `crates/xusdc-encoding/src/account/xreserve/builder.rs:12-27` (module doc) + the `seeded_dom_roles_rbac` doc | the frozen-graph statement (no sender can re-point or clear any role's admin; rotation grant/revoke only; proc present-but-unreachable) | matches `DECISION-SETROLEADMIN-NOTE-REMOVAL.md` + the enforcement tests |
| `docs/spec/GLOSSARY.md:102` (CMP-F5), `:225` (CIR-ADMIN-3), `:263` (IMPL-DEV-24) | membership rotation + build-seeded delegation + the removal record | consistent with the register rows 23/24 after this re-run's CDR-3 edits |
| `crates/xusdc-encoding/tests/support/mod.rs` (fixture note docs), `tests/masm_structure.rs`, `tests/f5_network_account_auth.rs:173-230` | 12-root allowlist set-equality (renamed `…is_exactly_the_12_ratified_roots`), empty tx-allowlist | tests green in the 434 |

### 2d. Round-2 audit repairs (auditor-found + same-class comb)

| Site (post-edit) | Old claim | Corrected claim | S-row |
|---|---|---|---|
| `crates/xreserve-deposit-relayer/src/miden/mint_note.rs:13-15` (module doc) | "it is the key the operator was told the faucet's `xReserveAttesters` allowlist is keyed by" | "it is the key whose DC-3 commitment (Poseidon2 over the 16 affine felts it decompresses to, v16 vm#3342) the operator was told is enabled in the faucet's `xReserveAttesters` allowlist" | S16 (audit-found) |
| `crates/xreserve-deposit-relayer/src/miden/mint_note.rs:38-40` (`COMPRESSED_PUBKEY_LEN` doc) | "the ONLY attester-key form the allowlist is keyed by" | "the ONLY attester-key form the relayer handles (the allowlist itself is keyed by the DC-3 Poseidon2 commitment over the affine coordinates this key decompresses to — 16 felts since v16, vm#3342)" | S16 (audit-found) |
| `crates/xreserve-deposit-relayer/src/miden/mint_note.rs:80-82` (`from_hex` errors doc) | an uncompressed key is "not the one the allowlist is keyed by" | "not the form the allowlist commitment (DC-3) is derived from" | S16 (same-class comb) |
| `crates/xreserve-deposit-relayer/src/error.rs:316-320` (`BadAttesterPubkeyLength` doc) | "The allowlist the faucet checks against is keyed by the COMPRESSED SEC1 key (33 bytes)" | "The attester identity the faucet checks is derived from the COMPRESSED SEC1 key (33 bytes; the `xReserveAttesters` key is the DC-3 Poseidon2 commitment over the affine coordinates it decompresses to)" | S16 (same-class comb) |
| `crates/xreserve-deposit-relayer/tests/mint_note_boundaries.rs:124-126,:164` | "the 33-byte key the faucet's allowlist is keyed by"; "the UNCOMPRESSED SEC1 form, which is not what the allowlist is keyed by" | both re-phrased "…the allowlist commitment (DC-3) is derived from" | S16 (same-class comb) |
| `crates/xreserve-deposit-relayer/tests/mint_support/mod.rs:84-86` | "the key the faucet's allowlist is keyed by reaches the relayer through its config" | "the key the faucet's allowlist commitment (DC-3) is derived from reaches the relayer through its config" | S16 (same-class comb) |
| `crates/xusdc-encoding/tests/f5_admin_notes.rs:169,:1485,:1620` (section headers) | "DOMAIN_INIT (allowlist row 13)", "TRANSFER_OWNERSHIP (allowlist row 11)", "ACCEPT_OWNERSHIP (allowlist row 12)" — the pre-flip labels (#17 renumbered `xreserve_admin.rs` but missed these) | rows 12 / 10 / 11, matching `xreserve_admin.rs` and `builder.rs` | S21-flip (audit-found) |

Adjudicated NOT stale in the same class: `envelope_validate.rs:207` and `fixtures/mod.rs:9-11`
("the attester identity/the commitment … is the one the allowlist is keyed by") — both name the
COMMITMENT as the key, which is exactly the v16 keying.

### 2e. Round-3 qualifications (human ratification ITEM 3 — owner-backstop comments; comment/message-only)

Per the 2026-07-14 round-2 human ratification: every remaining unconditional owner-backstop
statement is qualified to the accurate v16 shape — the backstop is held by the owner ACCOUNT's
account-bound `ADMIN` MEMBERSHIP, which does NOT auto-follow `transfer_ownership`; a
post-transfer re-seat (grant-new BEFORE revoke-old per the runbook — no zero-ADMIN window) is
required. Assert MESSAGES were re-worded only where the message itself asserted the
unconditional claim (asserted VALUES unchanged; pass counts identical).

| Site (post-edit) | What was qualified | S-row |
|---|---|---|
| `crates/xusdc-encoding/tests/role_admin.rs:20-31` (module doc) | "`ADMIN`'s authority … structurally fixed at the seed" now followed by the HOLDER-side caveat (account-bound membership; runbook re-seat grant-new-before-revoke-old; post-transfer owner lacks RBAC administration until re-seated) | S2 (Item 3) |
| `crates/xusdc-encoding/tests/role_admin.rs:535` (assert message) | "DOM_MANAGER stays owner-administered: …" → "DOM_MANAGER stays ADMIN-administered (the seeded owner account's account-bound membership): …" | S2 (Item 3) |
| `crates/xusdc-encoding/tests/role_admin.rs:554-561` (`owner_can_still_grant_pauser` doc) | "the owner holds the stock ADMIN role" → "the owner ACCOUNT holds the stock ADMIN role (an account-bound membership — it does not auto-follow an ownership transfer; runbook re-seat, S2)" | S2 (Item 3) |
| `crates/xusdc-encoding/tests/role_admin.rs:604-612` (`owner_can_still_revoke_pauser` doc) | "The owner therefore retains…" → "The (seeded-ADMIN-member) owner therefore retains … (account-bound across ownership transfer — S2 runbook re-seat)" | S2 (Item 3) |
| `crates/xusdc-encoding/tests/role_admin.rs:851-855` (doc) + `:886` (assert message) | "self-expansion of the manager set is owner territory" → "ADMIN territory, i.e. the seeded owner account's (… account-bound per S2)"; message "(owner-administered)" → "(ADMIN-administered: the seeded owner account)" | S2 (Item 3) |
| `crates/xusdc-encoding/tests/set_min_burn.rs:215-221,:233-239` (docs/comments) + `:265` (assert message) | "(owner-administered)" → "(admin_role 0 → ADMIN, the seeded owner account)" + the account-bound/no-auto-follow caveat; message → "(resolves to ADMIN = the seeded owner account)" | S2 (Item 3) |
| `crates/xusdc-encoding/tests/assembled_faucet_e2e.rs:400` (assert message) | "role_config[DOM_MANAGER] is owner-administered ([1,0,0,0])" → "role_config[DOM_MANAGER] resolves to ADMIN, the seeded owner account ([1,0,0,0])" | S2 (Item 3) |

## 3. Verified-current (hits adjudicated NOT stale — the auditor's grep will still see these)

| Site | Claim | Why it is TRUE at v16 |
|---|---|---|
| `docs/spec/FAUCET-COMPONENT-SPEC.md:60-61` | mint pipeline: "`assert_not_paused` runs first, because the custom mint bypasses the stock policy where the pause check normally lives" | the custom mint still runs its own pause gate FIRST — `asm/standards/xreserve/xreserve_mint.masm:113-118` (`exec.pausable::assert_not_paused` before any verify stage) |
| `docs/spec/FAUCET-COMPONENT-SPEC.md:102` | "the stock burn wrapper checks pause first (`R-BURN-3`)" | alpha.2 `execute_burn_policy` still asserts pause before dispatching the custom policy (registry `policy_manager.masm:357-358`); `burn_paused_rejects` + `burn_paused_rejected_through_composition` green |
| `asm/standards/xreserve/xreserve_mint.masm:44-47` | "The standard FungibleFaucet component installs this value slot" | the slot in question is `TOKEN_CONFIG_SLOT` (token_config), which did NOT move at #2944 (only `is_paused` moved); alpha.2 fungible faucet still installs token_config |
| `crates/xusdc-encoding/tests/builder_api.rs:430,:456` | "`FungibleFaucet` still installs it (unlike `is_paused`, which #2944 moved out)" — about `mutability_config` | v16-aware as written (M13 comment truth-up) |
| `crates/xusdc-encoding/src/account/xreserve/builder.rs` (PAUSE PROVENANCE block) | `is_paused` installed by base `Pausable`, #2944 named | v16-aware as written |
| `asm/standards/xreserve/pause_admin.masm:3-10`, `crates/xusdc-encoding/tests/pause_admin.rs:1-20` | "the stock `PausableManager` gates pause on …" (historical rationale for the Domain-Pauser-only remediation) | historical-context prose about why PausableManager is absent — the absence itself is re-proven at v16 (`builder_installs_no_stock_pause_manager`, `owner_has_no_pause_path`) |
| the "owner-only" mentions in `role_admin.rs`, `xreserve_admin.rs`, `rbac`-adjacent test docs | "owner-only" appears only as "the v15 gate was owner-only" / "the owner-only gate is GONE" | v16-aware statements of the S21 change (the former note file is deleted; its preserved-source fixture in `f5_admin_notes.rs:1280-1330` documents itself as the FORMER note) |
| `asm/standards/xreserve/domain_config.masm:107` | "gate: owner-only" (domain_init) | still true — `domain_init` is `ownable2step::assert_sender_is_owner`-gated (`domain_config.masm:108`); #3215 changed role administration, not ownership gates |
| `crates/xusdc-encoding/src/bin/gen_vectors.rs:297-301` | "the v16 supersession of the 9-felt compressed preimage" | correct historical reference (describes the supersession itself) |
| `asm/standards/xreserve/encoding/mod.masm:83-84` | "moved from the compressed SEC1 form (9 felts) to the affine form at the v16 migration" | correct historical/supersession statement |
| `asm/standards/xreserve/domain_config.masm:75-175` + `asm/standards/notes/xreserve_domain_init_note.masm:44,:77,:102` + `tests/support/mod.rs:1811-1812` `pad(2)` trackers | stack-tracker `pad(2)` spans | a genuine 2-element pad on `domain_init`'s 16-element call boundary — unrelated to the S16 attachment pad |
| `crates/xreserve-deposit-relayer/RIV-ADVICE-KEY.md:61-63,:78,:89` | "36-felt (9-word) content … pubkey(9) … the 9-felt pubkey and 17-felt sig" | covered by the doc's OWN up-front v16 disclaimer (`:42-47`): "Two details in the sections below are v0.15-era and have since moved … now 11 words / 44 felts with a 16-felt affine candidate pubkey … not 9 words / a 9-felt compressed one" — a reconciliation record that deliberately preserves its original finding text under an explicit supersession header; the quoted spec lines are QUOTES |
| `crates/xusdc-encoding/tests/mint_deny.rs:318`, `tests/support/mod.rs:2530-2531`, `tests/basic_asset_tripwire.rs:15` | `create_fungible_asset` mentions | v16-aware: mint_deny.rs describes the #3255 move; support/mod.rs describes the STOCK v16 recipe the deny guard traps; tripwire names the stock factory's flag derivation |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/PROVENANCE.md` | re-vendor recipe | names the registry layout + the `=0.16.0-alpha.2` pin (S9d done at migration) |
| `docs/spec/*` / `README.md` MASM snippets | (none) | no `.masm` import-syntax examples exist in the repo docs, so S17 has no doc surface |
| `docs/spec/GLOSSARY.md:257` (IMPL-DEV-12) | message "now describes the shipped right-aligned bytes32 layout" | matches `xreserve/encoding/error.rs:57-62` + the `account_id.rs:179-185` regression pin |
| every hit in `crates/xusdc-validation/**` (e.g. `src/mintburn.rs`, `src/actors.rs` "pubkey(9) … 9 words") | v15 shapes | the PARKED v15 crate is deliberately byte-intact (migration R1); these comments are CORRECT for the v0.15.3 code they document and update at the v16 LNV re-enable (`PARKED-V15.md`) — editing them now would falsify the crate against its own pinned code |
| `crates/xusdc-encoding/tests/fixtures/pinned-standards/fungible.masm:238` (`pad(2)`) | stock `mint_and_send` Inputs tracker | vendored byte-identical registry fixture — never hand-edited by rule (its own tests command re-vendoring, not editing) |
| the remaining "33-byte compressed" mentions (`src/note/xreserve_mint.rs`, `src/xreserve/encoding/{attestation,error}.rs`, `src/bin/gen_vectors.rs:267`, `tests/support/mod.rs:861-867`, relayer `tests/fixtures/mod.rs`, `crates/xusdc-encoding/Cargo.toml:20`, `asm/standards/xreserve/encoding/mod.masm:33,:83-84`) | the 33-byte compressed SEC1 key as the wire/ingress form | TRUE at v16 — the Circle-facing ingress IS still the 33-byte compressed key (only the commitment PREIMAGE moved); each site either states the wire form or is explicitly v16-aware |
| `docs/spec/GLOSSARY.md:263`/register IMPL-DEV-24 "backstop unbreakable … retracted" | quotes of the retracted wording | retraction statements — they QUOTE the false claim to retract it |

## 4. Result

- Stale sites corrected this re-run: **16 re-applied first-walk corrections** (§2a: 12 S16
  sites + the README validation-harness rewrite + 3 gate-hygiene rustdoc links, plus the
  DOCS-INVENTORY completeness rows) **+ 9 new-this-base gate-hygiene rustdoc-link fixes**
  (§2a table: PR #17's `builder.rs` doc + the relayer idempotency module)
  **+ 6 re-run-specific corrections** (§2b: the
  `role_admin.rs` module-doc seed/backstop grounding, the FAUCET-SPEC §5 Roles v16+flip
  paragraph, the GLOSSARY IMPL-DEV renumber + register-row mirror-in, the migration-map
  renumber annotations, the builder.rs allowlist-comment tidy).
- S21 surfaces already corrected by PR #17 and VERIFIED here (no edit): **5 groups** (§2c).
- Round-2 audit repairs: **7 further corrections** (§2d — the relayer allowlist-keying phrasings
  the round-2 audit found plus the same-class comb, and the f5_admin_notes.rs pre-flip row
  labels), with 2 same-class sites adjudicated not-stale. The §1 grep set gained the
  "keyed by" and row-label patterns so the class cannot silently regress.
- Round-3 qualifications (human ratification ITEM 3): **7 site groups** (§2e — every remaining
  unconditional owner-backstop statement in `role_admin.rs`, `set_min_burn.rs`, and
  `assembled_faucet_e2e.rs` qualified to the account-bound-ADMIN shape; comment/message-only,
  pass counts identical).
- Sites adjudicated verified-current: **19 groups** (§3, incl. the parked v15 crate, the
  vendored stock fixtures, and the new relayer `RIV-ADVICE-KEY.md` disclaimer-covered record —
  disclosed exclusions/adjudications, not silent filters).
- The first walk's "escalated STOP / conditional backstop" caveat wording appears NOWHERE in
  the tree (it was never merged, and this re-run's replacements state the post-flip frozen-graph
  reality); the retracted "unbreakable backstop" phrasing survives only inside explicit
  retraction/quotation records.
- Golden vectors, `docs/governing/*`, MASM instructions, constants, and test expectations:
  untouched (frozen-behaviour proof in the report §4).
