# DECISION — DEC-4 reversal: derive the faucet identifier from the account's own id (faucet v2)

**Status:** implemented on branch `feat/id-derive-init-note-removal`; **awaiting human ratification before any deploy.**
**Date:** 2026-08-03 · **Ratified by:** Phil · **Supersedes:** DEC-4 ("runtime init minimized to identifier-only via the `identifier_init` note").

## What changed and why

The faucet's identifier is the value every deposit intent's `remoteToken` is checked against. Until
now it lived in a storage slot that an administrator wrote once, after deployment, through a
dedicated `identifier_init` admin note.

That design existed for one reason: the identifier is the faucet's OWN account id in the frozen
bytes32 packaging, and a Miden account id is a hash over the account's initial storage commitment.
An own-id identifier is therefore a fixpoint — it cannot be seeded into the storage it derives from
— so it had to be written after the account existed.

The reversal's insight is that the mint path never needed the STORED value. The
`AccountId`→bytes32 encoding is FROZEN (`DEV-10`, shared with Circle), so the same comparand can be
DERIVED at check time from `native_account::get_id`, and the MASM derivation can be proven byte for
byte against the Rust encoder. Nothing has to be written, so nothing has to be initialized.

What that buys:

- **No init-ordering hazard.** A freshly deployed faucet is mint-ready. There is no window in which
  the faucet is live, addressable, and rejecting every deposit because its slot is still empty.
- **No front-run surface.** The old init was open to whoever got there first (it was safe only
  because the procedure re-derived the expected value on-chain and refused anything else). With
  nothing to write, the question does not arise.
- **A smaller admin surface.** One note-script root and one callable account procedure leave the
  account: the allowlist goes 9 → **8** roots and the callable surface 62 → **61**.
- **Less storage.** The identifier slot is gone, so the composed account's declared `xreserve` slot
  set goes 7 → **6**.

This lands in **faucet v2** — the storage layout change moves the account id. Nothing is deployed,
so there is no migration.

The `AccountId`↔bytes32 packaging itself is unchanged and remains the **provisional** `Q-CRY-4`
position: whether Circle carries a Miden account id in `remoteToken` this way is still OPEN and
Circle-owned. This decision changes only where the comparand comes from, never what it is.

## What the mint path does now

`deposit_intent_parser::assert_deposit_intent` hashes the parsed `remoteToken` to its canonical key
(unchanged) and compares it against `compute_own_identifier_key` instead of against a slot read:

```
exec.encoding::bytes32_to_key          # the intent's remoteToken, hashed
exec.compute_own_identifier_key        # the faucet's own id, packed and hashed
assert_eqw.err=ERR_XRESERVE_WRONG_IDENTIFIER
```

The reject identity is **byte-unchanged** — same error name, same message
(`"deposit intent remote token does not match the faucet identifier"`), so `R-MINT-7` reads the same
to a relayer and to a reviewer. Only the comparand's source moved.

The derivation is the one that already shipped inside `identifier_init`'s anti-front-run binding,
relocated verbatim and split at its natural seam so both halves can be proven independently:

| Procedure | Form | Invocation |
|---|---|---|
| `deposit_intent_parser::compute_own_id_bytes32` | `[] → [B_UPPER, B_LOWER]` — the account id right-aligned into bytes32 (16 zero bytes, prefix u64 BE, suffix u64 BE), as the u32-LE-packed limbs `bytes32_to_key` consumes | `exec` (exported, NOT `@account_procedure`) |
| `deposit_intent_parser::compute_own_identifier_key` | `[] → [KEY]` — the above, hashed | `exec` (exported, NOT `@account_procedure`) |

Both are exported so the cross-language parity suite can EXECUTE them directly against the Rust
encoder; neither carries `@account_procedure`, so neither is callable on the deployed account. They
join the `FROZEN_EXEC_ONLY_EXPORTS` list (9 → 11) rather than the callable-root set.

**Execution context.** The comparand is read with `native_account::get_id`, where the old one used
`active_account::get_item`. Those agree only in the faucet's own account context — which is where
the compare runs: the stock `mint_and_send` dispatches `mint_policy::check_policy` (an
`@account_procedure` on the faucet), which `exec`s `assert_deposit_intent` in that same context.
`exec` does not switch context, so native == active on every path that reaches the compare.

## Evidence

The claim that carries the whole design is byte-parity with the frozen encoding. It is proven by
EXECUTING the MASM in transactions and comparing against Rust-computed values:

| Test | What it proves |
|---|---|
| `own_id_bytes32_packaging_matches_the_rust_encoding` | the on-chain packaging equals `account_id_to_bytes32(id)`, limb for limb, for 12 generated ids spanning both account types **plus** the production-composed faucet |
| `own_id_identifier_key_matches_the_rust_key` | the derived key equals `bytes32_to_storage_map_key(account_id_to_bytes32(id))` over the same spread |
| `native_account_id_matches_the_rust_felts_in_account_context` | the canary: `get_id` inside a `call`-invoked account procedure reports exactly `account_id_to_felts(id)` |
| `a_foreign_expected_key_traps` / `foreign_expected_bytes32_limbs_trap` | the parity assertions are not vacuous — feeding one account another's expected value traps with the driver's exact error |
| `distinct_accounts_derive_distinct_keys` | the derivation reads the id rather than returning a constant |

(all in `crates/xusdc-encoding/tests/own_id_identifier_derive.rs`)

And the behavioral consequences, through the real note transport on a production-composed faucet:

| Test | What it proves |
|---|---|
| `a_never_initialized_faucet_mints` | a faucet whose only bring-up note is the attester allowlist entry mints an own-id-bound intent — no identifier init exists anywhere in the flow |
| `a_foreign_remote_token_rejects_while_the_own_id_intent_mints` | a foreign `remoteToken` rejects with EXACTLY `ERR_XRESERVE_WRONG_IDENTIFIER` **while the same faucet accepts the own-id-bound intent** — the compare discriminates rather than refusing everything (which is what an uninitialized faucet used to do) |
| `the_wrong_identifier_error_text_is_unchanged` | the reject message is byte-identical to the pre-change one |
| `the_allowlist_drops_the_identifier_init_root_and_nothing_else` | the allowlist is exactly the eight surviving roots |
| `the_component_exports_no_identifier_initializer` | no `identifier_init` module survives on the assembled component |
| `the_composed_faucet_declares_no_identifier_slot` | the composed account declares no `xusdc::xreserve::domain_config::identifier` slot |
| `the_required_slot_contract_drops_the_identifier` | the builder's declared-slot contract no longer asks for it |

(all in `crates/xusdc-encoding/tests/id_derive_mint_and_removal.rs`)

## Ratification table (the human gate — Phil ratifies before any deploy)

### 1. Note-script allowlist — shrinks 9 → **8** (immutable post-deploy)

Materialized from the canonical `XReserveStablecoinBuilder::allowed_note_scripts()`. The removed row
is the former `identifier_init` note; every other root is unchanged from the ratified 9-root set.

| Row | Note | Script-root hex | Gate |
|---|---|---|---|
| 1 | `MintNote` (stock) | `0x89f864aab0b718d5e41fedd0b7baa5db7f4a7623284437a9db0e614f5cb02572` | attestation mint policy |
| 2 | `BurnNote` (stock) | `0xa06c9436eaef8c92726c463b22577a2017bcf3b4d6a65f09b8f8c128f40ac68a` | holder (own asset) |
| 3 | `set_attester` | `0x442a0c19b0bbce60630f7c52758b296a4ba74e6b7b02b6603f94481c161bc962` | ADMIN |
| 4 | `set_min_burn_size` | `0x7ae46ecf82c7968a867c88d982659ba55989c49238c5e1ba6fa1a8c6a1008566` | ADMIN |
| 5 | `set_max_supply` | `0x70b18f7063f760b727dd194df5699fd5aa3453ed53ffb317b91711d4c597e018` | ADMIN |
| 6 | `PauseActionNote` (stock) | `0xe2e4588e0d7a76ad53817669c10b7e7d149d501f5bb6148687f587f59c06b35f` | DOM_PAUSER |
| 7 | `BlocklistConfigNote` (stock) | `0x886d61a0c638ad270aa602b0d2d03b6a5d5f51772b6408cf102c032452304471` | BLK_MANAGER |
| 8 | `RbacActionNote` (stock) | `0x7594ac0eec7563cfcb25ee1c377c25dadf3a278974da7350f2d783d4fb1f31bf` | effective role admin |

| Removed row | Note | Why |
|---|---|---|
| — | `identifier_init` | there is no identifier to seed; the mint path derives it |

### 2. Callable account surface — shrinks 62 → **61**

The delta is exactly one row: `::xreserve::identifier_init::init_identifier`. The full frozen list is
the literal `FROZEN_ACCOUNT_SURFACE` in `crates/xusdc-encoding/tests/account_callable_surface.rs`
(2 xreserve + 59 stock), enforced by set equality against the composed account at both the
manifest-export and `@account_procedure`-filtered interface tiers.

| | Before | After |
|---|---|---|
| xreserve callable roots | 3 (`set_attester`, `init_identifier`, `check_policy`) | **2** (`set_attester`, `check_policy`) |
| stock callable roots | 59 | 59 (unchanged) |
| total | 62 | **61** |
| xreserve exec-only exports | 9 | **11** (+ `compute_own_id_bytes32`, `compute_own_identifier_key`) |

### 3. Declared `xreserve` storage slots — shrink 7 → **6**

`xusdc::xreserve::domain_config::identifier` is removed from `REQUIRED_XRESERVE_SLOT_LABELS`. The
surviving six are `domain`, `source_domain`, `xreserve_contract_hi`, `xreserve_contract_lo`,
`used_nonces`, `xreserve_attesters`.

### 4. Deleted surfaces

| Surface | Note |
|---|---|
| `asm/standards/xreserve/identifier_init.masm` | whole module (`init_identifier`, `compute_own_identifier_key`, the three `ERR_XRESERVE_IDENTIFIER_*` constants) |
| `asm/standards/notes/xreserve_identifier_init_note.masm` | the note script |
| `XReserveIdentifierInitNote` + its pinned root constant + `identifier_for` | `note/xreserve_admin/config.rs` |
| `IDENTIFIER_CONFIG_SLOT_LABEL`, the required-slot row, the composition-time emptiness check, `XReserveStablecoinBuilderError::IdentifierNotEmpty` | `account/xreserve/builder/` |
| `IDENTIFIER_CONFIG_SLOT` | `deposit_intent_parser.masm` |
| `crates/xusdc-encoding/tests/identifier_init.rs` | the mechanism it tested no longer exists |

## Supersedes / open questions

- **Supersedes DEC-4.** The traceability register's DEC-4 row now records the reversal and points
  here; `R-ADMIN-4` and the `§5.9` storage row in the glossary carry SUPERSEDED annotations rather
  than being rewritten, so the provenance survives.
- **`Q-CRY-4` stays OPEN.** Whether the faucet identifier IS the account id in the bytes32
  packaging is Circle's call. This decision assumes the same provisional answer the previous design
  assumed — it only stops storing the result. If Circle assigns a different identifier, the
  comparand goes back to a configured value and this record is superseded in turn.
- **`DEV-10` stays OPEN** as the `AccountId`↔bytes32 layout question it always was; the derivation
  consumes that layout, it does not fix it.

## Known follow-up

`crates/xusdc-validation` (the parked LNV harness) still encodes the identifier-init step in its
deploy flow. The crate is excluded from the workspace and deliberately frozen at its v16-alpha state
(`PARKED-V16-NEXT.md`), so it is not updated here; removing that step is an un-park obligation,
recorded in the parking record.
