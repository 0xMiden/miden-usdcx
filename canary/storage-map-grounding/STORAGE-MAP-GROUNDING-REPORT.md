# Storage-Map Grounding Canary — Report (P5-01)

**Final status: `GROUNDED`.** The `StorageSlot::Map` read / write / empty-key primitive is proven
end-to-end with running code under MockChain on the pinned **Miden v0.15.3 / assembler 0.23.3**
stack, via the safe `CodeBuilder` + `miden-testing` path (no raw `Assembler`). All seven
`<questions_to_resolve>` are answered with running-code evidence plus a `file:line` source ground.

This canary is **scratch**: it writes a fixed marker at a fixed key, reads it back, and reads an
unset key. It decides **nothing** about the faucet's real storage layout, and touches no faucet
(`asm/standards/xreserve/`), 04, or D5a/D5b source. Its purpose is to retire the one toolchain item
`BUILDER-GATES.md:29` still lists PENDING — *"the map/schema storage path (`StorageSchema`/map
slots) for registries/allowlists"* — so **D5c (nonce registry)** and **D5d (attester allowlist)**
build on a proven primitive instead of guesswork.

| | |
|---|---|
| Pin (API ground truth) | `protocol v0.15.3` (`681fc9058`) → assembler family `0.23.3` |
| Safe path | `CodeBuilder::new()` → `compile_component_code` / `compile_tx_script`; `MockChain` |
| Gate | MockChain (NOT local-node) |
| Branch / commit | `canary/storage-map-grounding` / `4b0239f` (signed) |
| Result | `test result: ok. 1 passed; 0 failed` |

---

## 1. Files created (isolated scratch tree)

All under `xusdc-miden/canary/storage-map-grounding/` — an isolated Cargo workspace (own
`[workspace]` table) so the parent `xusdc-miden/Cargo.toml` is untouched:

```
canary/storage-map-grounding/
  Cargo.toml          # isolated workspace; path-deps -> ../../../protocol-pin-v0.15.3
  Cargo.lock          # seeded from the pin -> miden-core-lib / miden-assembly = 0.23.3
  asm/canary_map.masm # 1 map slot + write/read/read-unset procs; G-MASM house style
  src/lib.rs          # include_str! the .masm + path/label consts
  tests/map_canary.rs # MockChain gate: declare -> write -> read -> empty-key -> delta-assert
  STORAGE-MAP-GROUNDING-REPORT.md   # this file
  target/             # build artifacts (gitignored; reclaim via `cargo clean`)
```

The component MASM follows the live registry precedent
`protocol-pin-v0.15.3/crates/miden-standards/asm/standards/access/rbac.masm` (a storage Map used
as an access-control registry — the closest precedent to the nonce/allowlist use).

---

## 2. Questions resolved (each: answer + source `file:line` + running-code evidence)

All MASM/Rust source paths below are under `protocol-pin-v0.15.3/`. The running-code evidence is the
single passing test in §3.

### Q1 — Declare a map slot; reference its index from MASM
- **Rust declaration:** `StorageSlot::with_map(name: StorageSlotName, map: StorageMap)` —
  `crates/miden-protocol/src/account/storage/slot/storage_slot.rs:54`. The map starts empty via
  `StorageMap::new()` — `…/storage/map/mod.rs:71`. It is passed in the same `Vec<StorageSlot>` to
  `AccountComponent::new(code, slots, AccountComponentMetadata::new(name))` —
  `…/account/component/mod.rs:60`, `…/component/metadata/mod.rs:113` (metadata default
  `StorageSchema` suffices; **no explicit `StorageSchema` is required** for direct construction).
- **Bound by name:** `StorageSlotName::new(impl Into<Arc<str>>)` — `…/storage/slot/slot_name.rs:69`;
  the slot id is the first two felts of the hashed name — `…/storage/slot/slot_id.rs:41`. Same
  machinery as the proven value-slot path.
- **From MASM:** `pub const USED_SLOT = word("xusdc::canary::storage_map::used")` then
  `push.USED_SLOT[0..2]` yields `[slot_id_suffix, slot_id_prefix]`. Live precedent: `rbac.masm:37`
  + `:295`.
- **Evidence:** the tx wrote and read the slot, and the post-tx `StorageMapDelta` is keyed under
  the slot name `xusdc::canary::storage_map::used` (§3 output).

### Q2 — Write primitive (MASM)
- **`exec.native_account::set_map_item`** — `crates/miden-protocol/asm/protocol/native_account.masm:154-194`.
  Stack contract: **`Inputs: [slot_id_suffix, slot_id_prefix, KEY, VALUE] → Outputs: [OLD_VALUE]`**,
  `Invocation: exec`. Kernel impl: `asm/kernels/transaction/lib/account.masm:608` → `set_map_item_raw:1528`
  → `exec.smt::set:1549`. Live precedent `rbac.masm:328`.
- **Canary MASM (`map_write_marker`):** `push.MARKER` → `push.TEST_KEY` → `push.USED_SLOT[0..2]` →
  `exec.native_account::set_map_item` → `dropw`.
- **Evidence:** post-write read returned `MARKER`; the delta records `TEST_KEY -> Word([1,0,0,0])`.

### Q3 — Read primitive (MASM)
- **`exec.active_account::get_map_item`** — `crates/miden-protocol/asm/protocol/active_account.masm:370-401`.
  Stack contract: **`Inputs: [slot_id_suffix, slot_id_prefix, KEY] → Outputs: [VALUE]`**,
  `Invocation: exec`. Kernel impl: `…/lib/account.masm:562` → `get_map_item_raw:1619` →
  `exec.smt::get:1644`. Live precedent `rbac.masm:298`.
- **Canary MASM (`map_read_test`):** `push.TEST_KEY` → `push.USED_SLOT[0..2]` →
  `exec.active_account::get_map_item` → `swapw dropw` (restores the `call`-return depth of 16
  while keeping `VALUE` on top — the spike's value-slot idiom).
- **Evidence:** the in-MASM `assert_eqw` "test key must read MARKER after write" passed.

### Q4 — Empty/default value for an UNSET key = `EMPTY_WORD` `[0,0,0,0]` (load-bearing for D5c)
- **Source:** `StorageMap::get(&key) = self.entries.get(key).copied().unwrap_or_default()` →
  all-zero `Word` — `…/storage/map/mod.rs:137`. The kernel path returns the SMT empty-leaf value
  (`get_map_item_raw` → `exec.smt::get`) for a key never inserted. Live precedent comment
  `rbac.masm:123` ("the underlying role config map returns `Word::ZERO`").
- **Evidence (twice):** the in-MASM asserts "test key must read EMPTY_WORD **before** write" and
  "unset key must read EMPTY_WORD" both passed; and the `StorageMapDelta` has **exactly 1** changed
  entry — the never-written `UNSET_KEY` produced no entry. This is the exact assertion D5c's replay
  check needs (`usedNonces[KEY] == EMPTY_WORD` ⇒ not yet used).

### Q5 — Key/value cardinality = Word → Word
- **Source:** both kernel stack contracts (Q2/Q3) take `KEY` (Word) and write/return a Word; the
  Rust key type is `StorageMapKey(Word)` — `…/storage/map/key.rs:26`, constructed via
  `StorageMapKey::new(Word)` — `:39`.
- **NS-1 plug-in:** 04's `xreserve::encoding::bytes32_to_key` emits a `Word`, used directly as the
  map `KEY`.
- **Evidence:** the delta line `StorageMapKey(Word([11, 12, 13, 14])) -> Word([1, 0, 0, 0])` shows
  a Word key mapping to a Word value, and confirms MASM↔Rust key/value **parity** (the Rust delta
  lookup found the exact key the MASM pushed).

### Q6 — Post-tx map-state assertion
- **Path:** `executed.account_delta().storage().get(&slot_name)` → match `StorageSlotDelta::Map(d)`
  → `d.entries().get(&key)`. Sources: `AccountDelta::storage()` — `…/account/delta/mod.rs:161`;
  `AccountStorageDelta::get()` — `…/account/delta/storage.rs:47`; `StorageMapDelta` —
  `…/account/delta/storage.rs:462+`.
- **Evidence:** the test asserts the delta entry at `TEST_KEY` equals `MARKER` and passes; the
  observed delta is printed in §3. (Primary proof remains the in-MASM read-after-write `assert_eqw`;
  the delta is the independent Rust-side confirmation.)

### Q7 — Advice/host needs = advice-backed (via SMT), but MockChain auto-wires it; no manual wiring
- **Source:** the kernel map procs carry **no direct `adv_*` ops**; the advice dependency lives
  inside `smt::get` / `smt::set` (`…/lib/account.masm:1644`, `:1549`), which consume the map's
  merkle-path / leaf witnesses. The Rust doc is explicit: *"It is sufficient if just the
  accessed/modified items are present in the advice provider."* — `…/storage/map/mod.rs:34-36`.
- **Evidence:** the test wires **zero** advice/host setup — `MockChain::build_tx_context().execute()`
  auto-populated the storage-map SMT witnesses and the tx executed.
- **`advice-provider-hygiene` implication for D5c/D5d:** the witness comes from advice, but its
  integrity is bound by the **committed map root in account storage** (the SMT verifies inclusion),
  so a forged witness cannot inject a false value. D5c/D5d therefore need **no custom advice
  hygiene for the map reads themselves**. On a real node (non-MockChain), `TransactionInputs` builds
  these witnesses — covered later by the separate local-node-validation gate.

---

## 3. Exact commands + outputs

Run from the canary crate. `cargo` runs with the sandbox disabled because it must write its
package cache under `~/.cargo` and read the SSH signing key under `~/.ssh` (both blocked by the
default sandbox) — source reads were sandboxed/read-only.

**MockChain gate (executes the map ops — assemble-only would be invalid):**
```
$ cargo test --manifest-path canary/storage-map-grounding/Cargo.toml --test map_canary -- --nocapture
running 1 test
[canary] executed under MockChain (real tx, not assemble-only).
[canary] in-MASM assertions PASSED: (Q4) TEST_KEY read EMPTY_WORD before write; (Q2/Q3) TEST_KEY read MARKER after write; (Q4) UNSET_KEY read EMPTY_WORD.
[canary] nonce_delta = 1
[canary] (Q6) StorageMapDelta on slot 'xusdc::canary::storage_map::used': 1 changed entr(y/ies); TEST_KEY StorageMapKey(Word([11, 12, 13, 14])) -> Word([1, 0, 0, 0])
test storage_map_declare_write_read_empty_under_mockchain ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.35s
```

**Proof of EXECUTION (not assembly):** the first run failed at runtime with a VM `call`-contract
error before the fix — `when returning from a call, stack depth must be 16, but was 20` — resolved
with the trailing `swapw dropw` in the read procs. An assemble-only test could never surface this.

**Reproducible lock (G0 build hygiene):**
```
$ cargo build --locked --manifest-path canary/storage-map-grounding/Cargo.toml
    Finished `dev` profile [unoptimized + debuginfo] target(s)        # clean, no lock drift

$ grep -A1 'name = "miden-core-lib"' Cargo.lock      ->  version = "0.23.3"
$ grep -A1 'name = "miden-assembly"'  Cargo.lock      ->  version = "0.23.3"
```

**Isolation (no faucet/04/D5 touched by the canary commit):**
```
$ git show --stat HEAD --name-only | grep -E "asm/standards/xreserve|crates/xusdc-encoding|docs/"
  (none)
$ git status --porcelain        # the pre-existing docs/governing + docs/spec/04 edits remain
   M docs/...                    # UNSTAGED and were NOT committed by this canary
  ?? canary/storage-map-grounding/STORAGE-MAP-GROUNDING-REPORT.md
```

---

## 4. Verification gates

- **G0 (objective gate / execution):** `cargo test … --test map_canary` → `test result: ok. 1
  passed; 0 failed`; the output shows the write/read/empty-key steps executing under MockChain
  (per-step evidence). `cargo build --locked` clean; lock resolves the `0.23.3` family.
- **G-MASM (conventions are source-backed):** the component module follows the §2 / G-MASM house
  style — namespace-first `#` header, `# SECTION` + `# ===` banners, `#!` doc blocks
  (Description / Inputs / Outputs / Where / Panics if / Invocation), named Word consts
  (`USED_SLOT` / `TEST_KEY` / `UNSET_KEY` / `MARKER`, supported per `rbac.masm:44`,
  `pausable/mod.masm:22`), lowercase `# =>` trackers. Proc bodies mirror `rbac.masm`. The
  `BUILDER-GATES.md:29` PENDING row (map/schema storage path) is **RESOLVED** by this canary.
- **Isolation:** the canary commit changed only `canary/storage-map-grounding/*`; the faucet
  (`asm/standards/xreserve/`), 04 (`crates/xusdc-encoding`, `docs/spec/04-*`), D5a/D5b, and the
  `docs/governing` mirrors were not touched or staged.
- **Skills:** the full `MASM-AUTHORING-RESOURCES.md` §1 set was loaded; the slice exercises
  `masm-formatting`/`-file-structure`/`-doc-comments`/`-inline-comments`/`-constants`/
  `-named-literals`/`-explicit-stack-inputs`/`-padding`/`cheap-masm-equivalents`,
  `masm-rust-constant-parity` (the dual-declared `TEST_KEY`/`MARKER` are checked by the passing
  test), and **`advice-provider-hygiene`** (Q7). `u32-assert-*`/`checked-arithmetic`/
  `felt-construction`/`masm-locals-over-globals` are N/A (no arithmetic, no locals).

---

## 5. Notes / findings (scope boundaries, not defects)

1. **Adjacent primitives NOT grounded here (intentionally out of scope):**
   `get_initial_map_item` (read the map value as it was at tx start) is proven by the protocol's own
   `test_get_initial_map_item` but NOT by this canary; the **abort-on-replay** logic and any real
   key/marker **constant codegen** are D5c's to build.
2. **Constant parity:** `TEST_KEY` / `MARKER` are dual-declared (MASM consts + Rust consts) and the
   passing test is the parity check. For real shared constants D5c should prefer codegen/single
   source per `masm-rust-constant-parity`.
3. **tx-script error strings:** the ephemeral tx script uses inline `.err="…"` (test glue, mirroring
   the spike and the protocol's own map tests). The component module carries no asserts, so it needs
   no `ERR_*` consts.
4. **Single-tx design** (read-empty → write → read-marker in one tx) is faithful to D5c's
   replay-check-then-mark flow.

---

## 6. D5c readiness

**D5c (nonce registry) can proceed on this proven primitive — nothing is BLOCKED.** The exact shape
D5c needs is grounded end-to-end under MockChain on the pinned v0.15.3 / 0.23.3 stack:
- declare a `StorageSlot::Map` (`usedNonces`) — Q1;
- read `usedNonces[KEY]` via `active_account::get_map_item` — Q3;
- assert `== EMPTY_WORD` to reject replays — Q4 (proven twice);
- write the mark via `native_account::set_map_item` — Q2;
- with no manual advice/host wiring under MockChain — Q7.

D5d (attester allowlist) builds on the same primitive (membership = non-empty marker at the
attester key), with the live `rbac.masm` / `network_account` allowlist precedents as further
reference. The remaining D5c/D5d work (replay-abort control flow, real keys, real-node witness
validation via local-node-validation) is unit logic and a later gate, not a missing primitive.

---

## 7. STOP conditions honored

No real nonce-registry / allowlist / D5c / D5d logic; no real keys or business markers; no touch of
the faucet's `asm/standards/xreserve/`, 04, D5a/D5b, or their vectors; no precompile/attestation
work; no Cargo/pin changes beyond the isolated canary seed; no Circle `DEV-*`/`Q-*` resolved; no
weakened/skipped tests; commits in planned order; **no push / publish / PR.**
