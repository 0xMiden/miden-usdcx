# DECISION — F4 reversal: wire the stock v0.16 transfer blocklist into the xUSDC faucet (faucet v2)

**Status:** implemented on branch `feat/transfer-blocklist`; **awaiting human ratification before any deploy.**
**Date:** 2026-07-23 · **Supersedes:** the F4 basic-asset decision (`DECISION-F4-BASIC-ASSET-NO-TRANSFER-POLICY.md`, human-ratified 2026-07-08 — that doc's own comment pre-encoded this reversal path: a conscious re-decision + a faucet-v2 migration, IMPL-DEV-20).
**Provenance:** the mechanism ground truth is an adversarially-audited research pass (2 independent
refutation audits; standards-side verdicts all CONFIRMED) that verified every stock-component fact
(sources at file:line, the kernel callback semantics, the §1.5 flow-semantics matrix, the tripwire/
fixture/consumer inventories) against the workspace pins (`miden-standards`/`miden-protocol`
`0.16.0-alpha.4` in the cargo cache). Its findings are reflected inline throughout this record and are
re-verified executably by the tripwire + e2e suites cited below; the pinned registry sources outrank the
research if they ever disagree.

## What changed and why

Miden head-of-product + Philipp concluded xUSDC needs an **on-chain transfer blocklist**. This reverses
F4 (xUSDC-as-basic-asset). The faucet now composes the **stock `miden-standards` `BasicBlocklist`** as
the **ACTIVE send AND receive transfer policy** (one root, both kinds, empty initial blocklist), which
makes xUSDC a **policed** asset: the kernel dispatches the faucet's transfer policy on every
send/receive, so every counterparty must attach the faucet as a **foreign account** on transfer/consume.
Because registering a transfer policy requires the account id to be created `AssetCallbackFlag::Enabled`
(an **immutable** property of the account id), this is necessarily a **NEW account = faucet v2** (new
`bytes32` identifier → Circle re-registration; the deployed devnet faucet `mdev1ap2…` cannot be upgraded).

Administration is a **NEW dedicated `BLK_MANAGER` role** held by an EXTERNAL entity — **not** the owner
(Phil, 2026-07-23: an external party manages the blocklist for Miden and must have NO other admin
capability). The stock `BlocklistOwnerControlled` is owner-gated (the wrong identity) and is **NOT**
installed; instead a new thin role-gated MASM module `asm/standards/xreserve/blocklist_admin.masm`
mirrors the ratified `pause_admin.masm` pattern (`rbac::assert_sender_has_role(BLK_MANAGER)` + the stock
unauthenticated `blocklist::{block_account,unblock_account}` primitives). Capability isolation is
**two-way**: the holder can ONLY block/unblock; the owner (without the role) cannot block/unblock.

## Ratification table (the human gate — Philipp ratifies before any deploy)

### 1. Note-script allowlist — grows 12 → **14** (immutable post-deploy)

The complete immutable note-script allowlist (all 14 roots materialized from the canonical
`XReserveStablecoinBuilder::allowed_note_scripts()`). Rows 1–12 are the F5-ratified set (unchanged);
**rows 13–14 are the NEW BLK_MANAGER-gated transfer-blocklist notes and require ratification**. NO
`set_role_admin` / `renounce_role` note (the standing S21 removal).

| Row | Note | Script-root hex | Gate |
|---|---|---|---|
| 1  | `xreserve_mint_note`    | `0x530e20b39e77a111f00a162835823ff503202d05c182b98728387853e07d19d5` | attestation (mint shim) |
| 2  | `stock_burn_note`       | `0xdef956326ea56321c0de5de3c1ab2e3ffadcd2c972c8262bc16dfbcf044ec0c3` | holder (own asset) |
| 3  | `set_attester`          | `0x442a0c19b0bbce60630f7c52758b296a4ba74e6b7b02b6603f94481c161bc962` | owner |
| 4  | `set_min_burn_size`     | `0x87e7bb5161151a5d8f06dbace738b19116f7adc6f3e17efdaced03a84837cf84` | owner |
| 5  | `set_max_supply`        | `0x70b18f7063f760b727dd194df5699fd5aa3453ed53ffb317b91711d4c597e018` | owner |
| 6  | `pause`                 | `0xf505ce1232e61d9829825ee65a7db8d0cd5de182a7f16593aa212d5cf0d198a8` | DOM_PAUSER |
| 7  | `unpause`               | `0x8df1f866ebc97f423119ab04400e2c09a8680aac3bbb03f91a4fe271dfa9578c` | DOM_PAUSER |
| 8  | `grant_role`            | `0x39e47eb27d42b5eb91ff800800bf43b64f0c6ee761ddb02ed197112809513d8e` | effective role-admin (ADMIN) |
| 9  | `revoke_role`           | `0x109245c8d4f8c2873ff3c244fecf6db931e00d1ee0c7d61863107f4b78a4d9ba` | effective role-admin (ADMIN) |
| 10 | `transfer_ownership`    | `0x5bd39b30a487d6a385acd220c43a82980e63cfe37ba4d86efd58ffbd7a6c7c0a` | current owner |
| 11 | `accept_ownership`      | `0x4480f83f0c08d6c0d7e3480c62f0dc296a29489fd631ce78615bacb017352104` | nominated owner |
| 12 | `domain_init`           | `0x04f024d51f121941346180c762b18521505c3d42ab3cea43ebffe6e07041619d` | owner (init-once) |
| **13** | **`block_account`**   | `0xed7e56fde54ba1ffa244b92e048560db8233e3a744c4af95b8f363fc4214d9dc` | **BLK_MANAGER (NEW)** |
| **14** | **`unblock_account`** | `0xeed9a3d1ef3589a8039dcd3174e410e8ca1a0c0f977d4ecc412e226ba2a343d2` | **BLK_MANAGER (NEW)** |

(The roots are reproducible from the shipped note factories — the round-3 dump matches the pinned
constants in `crates/xusdc-encoding/src/note/xreserve_admin/blocklist.rs` (the
`block_account`/`unblock_account` factories in the `xreserve_admin` module tree, split out of the
former monolithic `xreserve_admin.rs` in round 6); rows 13–14 are also parity-tested by
`f5_admin_notes::{block,unblock}_account_note_script_root_is_pinned`.)

### 2. Callable-surface delta — grows 62 → **65** (the frozen account surface, `tests/account_callable_surface.rs`)

Three new callable roots, all ratified here:

- `::xreserve::blocklist_admin::block_account` (the BLK_MANAGER-gated wrapper)
- `::xreserve::blocklist_admin::unblock_account` (the BLK_MANAGER-gated wrapper)
- `::miden::standards::components::faucets::policies::transfer::basic_blocklist::check_policy` (the stock
  transfer-policy predicate — now LIVE, dispatched by the `invoke_send_policy`/`invoke_receive_policy`
  wrappers, which were present-but-inert under F4 and are S24-policed here).

The xreserve component's own frozen surface grows 17 → 19 (`tests/mint_root_surface.rs`); neither new proc
raises supply (both only write `blocked_accounts` behind the role gate).

### 3. Allowed-maps contents — blocklist-only (no re-activation path)

`allowed_send_policy_proc_roots` and `allowed_receive_policy_proc_roots` each contain **exactly the one
`BasicBlocklist::root()`** — the ratified active policy for both kinds. **No allow-all reserve**, no
runtime route to disable the blocklist (mirrors the F1/S21 no-re-activation posture; switching the policy
OFF would itself be a compliance event and would require a root we deliberately do not allow).
`set_send_policy`/`set_receive_policy` stay composed-but-pointless — the S-row disposition: the only
allowed root is the active one.

### 4. The BLK_MANAGER role

| Field | Value |
|---|---|
| RoleSymbol | `BLK_MANAGER` |
| Felt encoding (`RoleSymbol::new("BLK_MANAGER").as_element()`) | **`7907587873290749`** (parity-asserted MASM ↔ Rust, `tests/constant_parity.rs`) |
| admin_role | unset → resolves to the built-in `ADMIN` (the owner-held account) |
| Rotation / revocation | via the EXISTING allowlisted `grant_role` / `revoke_role` notes (owner as `ADMIN`) — zero new machinery |
| Holder (member) | the external entity's account id, supplied at **deploy time** via the builder's `blocklist_manager_holder` parameter (seeded role id 4, alongside DOM_PAUSER=2 / DOM_MANAGER=3) |

### 4b. Module registration + xreserve callable-root delta (HUMAN-AUTHORIZED existing-`.masm` edit)

The v0.25 assembler requires every module be declared with `pub mod` in the library root, so a new
`xreserve` module cannot be added without one line in the otherwise byte-frozen `mod.masm`. The
operator explicitly authorized this **module-registration line only** (all frozen tripwires stay
green; no other existing-`.masm` edit). Ratified rows:

| Row | Existing-`.masm` edit | Nature |
|---|---|---|
| MOD-1 | `asm/standards/xreserve/mod.masm`: `+ pub mod blocklist_admin` | module declaration the assembler requires to include the new file — non-behavioral (registers a file, changes no existing proc) |
| MOD-2 | `asm/standards/xreserve/mod.masm`: comment `17-root tripwire → 19-root tripwire` | comment sync to the new callable-root count (non-behavioral) |

**xreserve callable-root delta 17 → 19** (the `mint_root_surface.rs` frozen set): the two new
`blocklist_admin::block_account` / `blocklist_admin::unblock_account` wrappers are the only additions;
neither raises supply (both write only `blocked_accounts` behind the BLK_MANAGER role gate). This is
the same delta reflected in the whole-account surface 62 → 65 (§2 above).

### 5. The Enabled-flag statement

Every production-faucet construction site builds the account id `AssetCallbackFlag::Enabled` (deploy path
`crates/xusdc-validation/src/deploy.rs::build_faucet_account` + all MockChain fixtures via the
composition-derived flag). The Enabled flag is an **immutable** property of the account id: building
Disabled with the policy wired would make the callbacks **silently never fire** (the audited foot-gun) —
`tests/account_callable_surface.rs::invoke_wrappers_are_live_and_the_asset_is_policed` and the policed
`tests/basic_asset_tripwire.rs` make that impossible to miss.

## Follow-ups NOT done here (out of scope; separate, human-gated)

- [ ] The faucet-v2 **devnet deploy** (a new account id / new `bytes32` identifier).
- [ ] Circle **re-registration** of the new bytes32 identifier.
- [ ] The **Circle examples repo**, the **deposit relayer**, and the **withdrawal attester** retarget (the
      relayer's mint-note factories are unaffected by design — minting is the faucet's own tx).
- [ ] Any **OZ audit** scope update (the "feature-complete / frozen" Q3 answer is now invalid — scope
      grew by the policy wiring + 2 admin notes + the enlarged callable surface).
