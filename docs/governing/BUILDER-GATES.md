> **Reference document** — adapted from the internal xUSDC spec program; the shipped code and tests in this repo are the source of truth.

# BUILDER-GATES (GOVERNING — MASM-first)

Enforceable gates for every implementation unit. Phrased to be **mechanically checkable**, not matters of taste — agent self-assessment of "is this clean / did I review enough" is not gaugeable. Subjective calls (right abstraction? architecture buckling?) are **reserved for the human**.

**MASM-first premise.** The custom contracts are **hand-written MASM**. Assemble through `miden-standards`' `CodeBuilder` / `TransactionKernel::assembler()` path, create components with `AccountComponent::new`, load note scripts through `NoteScript::from_library_reference`, and execute behavior through MockChain plus the local-node gates. Do not use `cargo miden build` or a hand-built raw `Assembler` for the faucet.

**Protocol AI/MASM guidance.** Builder and critic agents must use the protocol-local skills pinned in `.claude/skills/` as mandatory checklist material. These skills are hygiene/review guidance, not runtime API evidence; if a skill conflicts with pinned repository evidence, stop and report the conflict.

## G0 — Objective gate runs BEFORE any human review
A unit is not eligible for human review until all of these are green (a green build/test is cheap; human attention is not):
- The unit's **source-backed build/assembly gate** is clean:
  - hand-written MASM contract → **assembles** via `CodeBuilder::compile_component_code` / `TransactionKernel::assembler()` using the pinned assembler dependency;
  - Rust harness/tooling/test crate → its `cargo` build/test is clean.
- The unit's **happy-path test passes** (written first — see G4). **For any owned routine with a MASM implementation, "passes" means the MASM is EXECUTED against its golden vectors** via `TransactionContext::execute_code` or MockChain; assemble-clean is necessary but not sufficient. **For a note-script unit, the happy path executes the full create→consume cycle**; for the public burn note, exercise the two-block create→consume.
- **MockChain** test green for on-chain behavior; **local-node validation green** where the unit touches notes, RPC, or lifecycle.
- Duplication scan clean (G1).
- File-size / structure check passes (G3).
- **Each gate pins a concrete command + expected-output substring** so G0 is CI-mechanizable.

## G-MASM — MASM conventions are source-backed, never invented
- Follow the MASM formatting, file-structure, constant placement, padding, and comment conventions in `.claude/skills/` and live `miden-standards` source. **No guessed MASM command or convention may gate a unit; do not fake an assembly pass.**
- Apply the PR #2927 MASM skills as additional mandatory checklists for each MASM unit: `cheap-masm-equivalents`, `checked-arithmetic`, `felt-construction`, `u32-assert-before-u32-ops`, `masm-error-constants`, `masm-explicit-stack-inputs`, `masm-locals-over-globals`, `masm-named-literals`, `masm-rust-constant-parity`, and **`advice-provider-hygiene`**. The builder's completion note must list which of these were checked and any resulting changes or conflicts.
- **`advice-provider-hygiene` is MANDATORY and security-critical for the `attestation_verify` proc and the `feeAmount` advice path** (consortium H1). Every advice/`NoteAttachment`-sourced value — the 17-felt ECDSA signature, the 9-felt candidate pubkey, and the operator `feeAmount` — MUST be validated against a kernel-trusted commitment (the pubkey-commitment `assert_eqw` + the keccak-bound signature, frozen faucet spec), use content-addressed advice-map keys, and **ERROR (not default) on missing advice**. A missed advice-commitment / missing-advice check on this path is an unlimited-mint authorization bypass — the worst failure mode in the faucet.
- **Pinned MASM facts:** core-lib imports use `miden::core::`; `@note_script` and `@locals(N)` are lowercase line-above attributes; `pub proc` exports a component procedure; `word("ns::label")` plus `[0..2]` yields the slot id; the runtime compile path uses `CodeBuilder` with no build dependency; and the pinned core library carries the Keccak/ECDSA precompiles.
- **`uint256→AssetAmount` reducer (DC-5, external Circle amount) — pinned obligations (consortium N11):** the Rust mirror MUST use **checked/overflowing arithmetic that surfaces overflow** on the scale / floor-div / cap path (no bare `*`/`-`/`+` on external values — `checked-arithmetic`); the MASM impl MUST `u32assert`/`u32assert2` the externally-supplied uint256 limbs **before** any `u32*` op (`u32-assert-before-u32-ops`); the golden vectors MUST include a cap-boundary case AND a limb-overflow case.

## G1 — Single ownership / no duplication (per language + cross-language conformance)
- Each owned routine in `CANONICAL-OWNERSHIP-MAP.md`: **≤ 1 MASM implementation** and **≤ 1 Rust implementation**, both conforming to the canonical byte/felt contract, **cross-checked by ONE canonical golden-vector artifact owned by shared-encoding(04)** (loaded by reference on both sides — see the map's Anti-duplication rule; a duplicate vector table also fails this scan).
- A second within-language definition of an owned thing — **even byte-identical** — fails (this is the cross-language drift seam: the relayer's off-chain mirror must conform to and be pinned to the 04 owner, not re-derived).
- Mechanical check: no duplicate definition of an owned routine outside its single per-language home (e.g., a second MASM `deposit_intent_parser::parse` proc, or a second Rust DepositIntent decoder). Wrappers that merely re-expose an owned routine also fail.
- **Cross-language constant parity (`masm-rust-constant-parity`):** the DC-1 layout offsets, packed magic `0x5a2e0acd`, and DC-5 cap/scale are MASM↔Rust constant pairs. Prefer `build.rs` codegen or change both sides in one unit and cross-check through canonical vectors. A one-sided constant edit fails this gate.

## G2 — Ownership map is the source of truth for boundaries
- No new shared concept / module boundary / cross-component interface without **first** adding it to `CANONICAL-OWNERSHIP-MAP.md` (human re-approves). No silent new shared shapes.

## G3 — Module/file size + structure
- Default file ceiling **~500–700 lines** for Rust. Split `.masm` logically by routine family rather than by a guessed line count.
- **D-1A module-realization rule:** procs whose canonical path is flat `xreserve::encoding::<name>` must live in `encoding/mod.masm`; per-file `.masm` files create nested module paths and wrapper aliases are banned.
- Tests live in their **own module/file**, not inline with implementation.

## G4 — Test discipline (happy path first)
- The **happy-path test is written first**, before any negative/edge/malformed case, and before the unit is considered done.
- Negative / malformed-input / replay / boundary cases follow — and do **not** substitute for happy-path coverage.
- Repeated setup is factored into **shared fixtures** (no copy-pasted setup).
- Encoding routines carry **deterministic golden vectors** (input → expected bytes/felts), including documented edges (cap boundary, limb overflow), in **ONE canonical artifact owned by shared-encoding(04)**. BOTH the MASM-side test and the Rust-side test **load those vectors by reference** (not hand-copied tables) and both **execute** against them — two executed runs over one vector set, not one executed + one assembled. A duplicate vector table outside the 04 home fails the G1 duplication scan, same as a duplicate routine (closes that drift seam at the test layer).
- **Negative/reject tests assert the SPECIFIC error**, not `is_err()` (`assert-specific-error-in-tests` + `masm-error-constants`, consortium N6): Rust via `assert_matches!` on the error variant/fields; MASM via asserting the trapping code equals the unit's named `ERR_*` constant — keyed to the frozen `R-MINT-*`/`R-BURN-*`/`R-ADMIN-*` ids (the faucet test-and-verification harness §4 — ALL reject rows incl. §4.A mint-deny, §4.C–§4.O, §4.K admin, and the burn/note rejects — is the binding catalog; the §4.C–§4.O span is illustrative, not the boundary).
- **Parametrize repeated reject families** (`parametrize-related-tests`, consortium N7): when ≥2 tests share a body and differ only by (mutation, expected `ERR_*`), express them as ONE `#[rstest]` with one `#[case::<name>]` per case — the assertion lives once and a missing case is visible (e.g. the §4.C 8-field DepositIntent reject table).

## G-RUST — off-chain Rust harness/tooling hygiene (#2927, consortium N4/N8)
The off-chain harness/tooling crates (relayer, listener, monitor, MASM loaders, test fixtures) are gated by the PR #2927 Rust skills as a mandatory per-unit checklist; the builder's completion note lists which were checked:
- API/design: `domain-newtypes-over-primitives`, `private-fields-with-accessors`, `non-exhaustive-public-types`, `validate-in-constructor`, `conversion-method-naming`, `use-bon-builder`, `intra-doc-links`, `workspace-shared-dependencies`. (Conform to / wrap the frozen 04 Rust signatures — do NOT edit the frozen spec; new harness types may newtype-wrap the raw `&[u8]`/`Word`/tuple boundaries.)
- **`return-error-not-panic` + `preserve-error-source` + `lowercase-error-messages` — MANDATORY on any code reachable from Circle/RPC/note input** (the relayer DepositIntent pre-validate, the listener JSON / burn-evidence decode, `AccountId↔bytes32`): surface failures as a typed `Result` — **no `unwrap`/`expect`/`panic!`/`unwrap_or_default` on external-derived data**; a missing required input is an error (never default-fabricated); preserve the source chain (`#[source]`/`#[from]`, no `.to_string()` flattening); lowercase, un-punctuated messages. A relayer/listener that panics or default-fabricates on a malformed Circle payload is a DoS and can mask a divergence from the 04 owner.

## G5 — Reality grounds the spec
- **Naming decisions are binding.** **NS-1** → canonical MASM proc `xreserve::encoding::bytes32_to_key` (do not add a MASM alias); **NS-2** → the DepositIntent parser is **01-owned `xreserve::deposit_intent_parser::parse`**, while 04 owns the layout and multi-consumer encoding primitives. **DC-7** ships as the Rust burn-note codec at `encoding/burn_note.rs`; there is no `burn_items.masm`. Any future unadjudicated split in the ownership map is a STOP condition: the builder must return to the human with no silent pick, dual name, or local alias.
- **Code wins over spec.** If running MASM/Rust cannot match the spec (a felt count, a Word layout, an RPC semantic that real `protocol`/`miden-vm`/node contradicts), the builder **STOPS and reports the contradiction** — it does not force code to fit a wrong spec, and does not silently diverge. The human decides whether to correct the frozen archive.
- **No hand-wavy Miden fake in a gating test.** A speed-only adapter fake is allowed only if labelled NON-GATING and paired with a real MockChain / local-node / source-backed check.
- **No local-node skip** after MockChain passes (where the unit touches notes/RPC/lifecycle).

## G6 — Open decisions stay open
- No Circle-owned `DEV-*`/`Q-*` may be marked approved/accepted/resolved anywhere. Contested Circle paths are built behind clearly-flagged assumptions or not at all until Circle answers.

## G7 — Concurrency
- Sequential builders at first; **no two agents edit the same module family in parallel**; no broad parallel implementation.

## G8 — Human merge gate (non-delegable)
- After G0 is green and the diagnostic critics have reported, **the human reads the diff and approves** before merge. A critic agent's "looks good" is **never** the gate. Agents draft and diagnose; the human approves.
