# Wave-1 S1 — the faucet recomposition (stock MintNote + attestation MintPolicy + build-seeded config + stock MinBurnAmount)

**Status:** BUILT — awaiting human ratification of the re-materialized allowlist + callable
surface (this document) and merge. · **Baseline:** `implementation @ 7526244` ·
**Toolchain pin:** miden-protocol/miden-standards 0.16.0-alpha.4, miden-testing 0.16.0-alpha.2,
miden-client 0.16.0-alpha.1 (NO version bumps in this slice).

This slice executes the protocol reviewers' refactor asks (PhilippGackstatter's P1 mint rebuild
+ mmagician's P3 slim-surface principle, PR #21/#37) as one recomposition train, per the ratified
decisions in the Wave plan (`REFACTOR-WAVE-SLICE-PLAN.md`, research pack): assert-match recipient
binding, DEC-2 fee keep-zero, DEC-4 minimized identifier init, the zero-floor burn invariant,
the G slim-by-construction principle for every NEW component, rider A8 (attachment schemes ≥ 4),
and an untouched blocklist feature.

## 1. The recomposed shape

- **Mint** = the STOCK miden-standards `MintNote` consumed by the STOCK
  `FungibleFaucet::mint_and_send`, gated by the custom **attestation mint policy**
  (`xreserve::mint_policy::check_policy`) as the ACTIVE mint policy: the ENTIRE D5a–D5d
  attestation pipeline relocated into the policy dispatch, plus the ratified ASSERT-MATCH
  binding (the note-claimed output RECIPIENT / amount / tag / note-type must EQUAL their
  attested derivations — the policy never overrides), plus the nonce-ledger write (the policy's
  only state write). Supply arithmetic, cap discipline, issuer binding, and note emission are
  stock. The transport rides three attachments: scheme 4 = the DepositIntent preimage, scheme 5
  = the attestation `[feeAmount(8), pubkey(16), signature(17), pad(3)]` (11 words), scheme 2 =
  the stock `NetworkAccountTarget` (rider A8: the reserved value 1 and the standard values 2/3
  are not used for xUSDC payloads).
- **Init** (DEC-4) = `domain` / `source_domain` / `xreserve_contract` are BUILD-SEEDED by
  `XReserveStablecoinBuilder::with_domain_config` (required input; no runtime writer exists).
  Only the `identifier` — a provable fixpoint of the account id (the id derives from the initial
  storage commitment; the identifier is, pending Q-CRY-4, the faucet's own id as bytes32) — gets
  the ONE minimized, owner-gated, init-once `identifier_init` note. The fixpoint is enforced two
  ways (round-2 hardening): the builder **REJECTS** a non-empty declared identifier slot
  (`IdentifierNotEmpty`) so it can never be build-seeded, and `XReserveIdentifierInitNote::create`
  **derives** the seeded key from the faucet id
  (`bytes32_to_key(account_id_to_bytes32(faucet_id))`, the own-id fixpoint — the same key the
  deployed-faucet re-check path expects) rather than accepting an arbitrary Word, so an init note
  is bound to its target and cannot seed a foreign identity. (DEV-10 / Q-CRY-4 stay OPEN — this
  is the provisional own-id position.)
- **Burn** = the STOCK `MinBurnAmount` policy ACTIVE (its companion carries the floor slot);
  the zero floor (R-BURN-1 preserved by construction): the builder REJECTS `min_burn_size < 1`,
  and the reworked `set_min_burn_size` admin note asserts `new_min >= 1` BEFORE calling the
  stock `set_min_burn_amount` (which itself accepts 0) — so `amount ≥ min ≥ 1` on every path.
  The active burn policy the manager receives is ALWAYS the validated-floor `MinBurnAmount`
  (round-2 hardening): an explicit `with_active_burn_policy` override cannot lower the shipped
  floor — a wrong-root override is rejected (`MissingMinBurnAmountPolicy`), and a same-root
  override whose companion floor disagrees with the validated `min_burn_size` is rejected
  (`BurnPolicyFloorMismatch`), closing the same-root zero-floor bypass.
- **Blocklist**: untouched (BasicBlocklist active on send+receive, `BLK_MANAGER` RBAC admin);
  the builder's companion seam now recognizes exactly {1× xreserve (the attestation policy), 1×
  MinBurnAmount, 1× BasicBlocklist} — any other shape is a loud `PolicyCompanionMismatch`.

## 2. INV-MINT-SECURITY, restated (the F1 posture)

> **Every supply increase passes the attestation mint policy.**

Mechanized as three tripwires (`tests/wave1_recomposition.rs`):
1. the ACTIVE mint-policy slot holds exactly the `xreserve::mint_policy::check_policy` root;
2. the allowed-mint-policy map is EXACTLY `{that root}` (no reserved alternate — the gate can
   never be swapped at runtime);
3. the builder REJECTS any other active mint policy (`MissingAttestationMintPolicy`) — a
   policy-less build cannot exist.

The former `mint_deny_guard` DELETES: its job — trapping the stock path — dissolved because the
stock path IS now the gated path. A mint attempt outside the attested note transport (e.g. a
tx-script `mint_and_send`) fail-closes inside the policy's kernel active-note reads
(`tests/mint_policy_e2e.rs::tx_script_mint_and_send_cannot_mint`).

## 3. The re-materialized note-script allowlist (14 rows — FOR HUMAN RATIFICATION)

| Row | Note | Gate | Script root | Δ |
|---|---|---|---|---|
| 1 | **stock `MintNote`** (miden-standards) | attestation mint policy | `0xae85e0f6d5492e8aec711cec8b74855f3c8eb1c3800cc9db3fb1fadbd63860e8` | **CHANGED** (was the custom `XReserveMintNote`) |
| 2 | stock `BurnNote` | MinBurnAmount policy (+ blocklist receive gate) | `0xdef956326ea56321c0de5de3c1ab2e3ffadcd2c972c8262bc16dfbcf044ec0c3` | unchanged |
| 3 | `set_attester` | owner | `0x442a0c19b0bbce60630f7c52758b296a4ba74e6b7b02b6603f94481c161bc962` | unchanged |
| 4 | `set_min_burn_size` | owner (note asserts floor ≥ 1, then stock `set_min_burn_amount`) | `0x294eaebba6996fc3b0ffd6dd2869c6f36701c63de852010be0b5224c576d4bd6` | **ROOT CHANGED** (reworked script) |
| 5 | `set_max_supply` (stock proc) | owner | `0x70b18f7063f760b727dd194df5699fd5aa3453ed53ffb317b91711d4c597e018` | unchanged |
| 6 | `pause` | DOM_PAUSER | `0xf505ce1232e61d9829825ee65a7db8d0cd5de182a7f16593aa212d5cf0d198a8` | unchanged |
| 7 | `unpause` | DOM_PAUSER | `0x8df1f866ebc97f423119ab04400e2c09a8680aac3bbb03f91a4fe271dfa9578c` | unchanged |
| 8 | `grant_role` (stock rbac) | role admin | `0x39e47eb27d42b5eb91ff800800bf43b64f0c6ee761ddb02ed197112809513d8e` | unchanged |
| 9 | `revoke_role` (stock rbac) | role admin | `0x109245c8d4f8c2873ff3c244fecf6db931e00d1ee0c7d61863107f4b78a4d9ba` | unchanged |
| 10 | `transfer_ownership` (stock ownable2step) | current owner | `0x5bd39b30a487d6a385acd220c43a82980e63cfe37ba4d86efd58ffbd7a6c7c0a` | unchanged |
| 11 | `accept_ownership` (stock ownable2step) | nominated owner | `0x4480f83f0c08d6c0d7e3480c62f0dc296a29489fd631ce78615bacb017352104` | unchanged |
| 12 | **`identifier_init`** | owner, init-once | `0x4fb4fcba9ca98176d2ccbaadcf8399f7ccdaa0312630a9b29a0d76058d515b82` | **NEW ROOT** (replaces the four-field `domain_init`) |
| 13 | `block_account` | BLK_MANAGER | `0xed7e56fde54ba1ffa244b92e048560db8233e3a744c4af95b8f363fc4214d9dc` | unchanged |
| 14 | `unblock_account` | BLK_MANAGER | `0xeed9a3d1ef3589a8039dcd3174e410e8ca1a0c0f977d4ecc412e226ba2a343d2` | unchanged |

Deliberately OMITTED (unchanged decisions): `set_role_admin` (S21 flip — the delegation graph
deploys frozen), `renounce_role`. The tx-script allowlist stays exactly
`{ExpirationTransactionScript}` (S12).

**Deleted roots** (no longer allowlisted anywhere): the custom `XReserveMintNote` script
(`0x530e20b39e77a111f00a162835823ff503202d05c182b98728387853e07d19d5`), the four-field
`domain_init` note (`0x04f024d51f121941346180c762b18521505c3d42ab3cea43ebffe6e07041619d`), the
old `set_min_burn_size` script (`0x87e7bb5161151a5d8f06dbace738b19116f7adc6f3e17efdaced03a84837cf84`).

## 4. The callable account surface (64 roots — FOR HUMAN RATIFICATION)

19 → **15 xreserve roots** (−6 deleted, +2 new) and 46 → **49 stock roots** (+3 stock
`MinBurnAmount` procedures). The full path list is the executable table in
`tests/account_callable_surface.rs` (set-equality-pinned, two layers). Deltas:

- REMOVED: `xreserve_mint::mint`, `xreserve_mint_note_entry::receive_and_mint`,
  `mint_deny_guard::check_policy`, `burn_policy::check_policy`, `domain_config::domain_init`,
  `min_burn_admin::set_min_burn_size`.
- ADDED (custom): `mint_policy::check_policy`, `identifier_init::init_identifier`.
- ADDED (stock, the MinBurnAmount companion): its `check_policy` (the ACTIVE burn policy root,
  `0xae9639f38ca391c1038a4a05761a794c75caf1a936cab1ac1160b643020aa59a`), `set_min_burn_amount`
  (`0x4237dcf1355bb2f1c13c303b68611cf1bb90c0646085d7e6552f63b52a63abe4` — reachable ONLY through
  the floor-guarded allowlisted note), and `get_min_burn_amount` (a view).

G-principle (slim-by-construction) held for everything this slice INTRODUCED: the policy module
exposes ONE account procedure (`check_policy` — its helpers are private), the init module ONE
(`init_identifier`). No new fat surface; the full legacy sweep of inherited stock surface stays
S-FINAL (a later slice).

## 5. Deletion ledger (every removal and where its behavior went)

| Deleted | Behavior destination |
|---|---|
| `asm/standards/xreserve/xreserve_mint.masm` (534 L: `mint`, `apply_mint_effects`, helpers) | Verify chain (D5a–D5d) → dispatched from `mint_policy::check_policy` (stages unchanged, consumed by reference). Effects (supply guard/write, note emission, issuer bind) → the STOCK `mint_and_send`. Nonce write → the policy. Recipient extraction + `build_felt`/`swap_u32_bytes`/`load_field_words` → relocated verbatim as private helpers of `mint_policy.masm`. The supply-cap error `ERR_XRESERVE_SUPPLY_CAP` → the stock cap errors. |
| `asm/standards/xreserve/xreserve_mint_note_entry.masm` (195 L transport shim) | The attachment locate/hash-verify/re-surface read-path → inside `mint_policy::check_policy` (same kernel primitives, same element-0-first pop order); note storage staging → obsolete (the intent rides a scheme-4 attachment; the STOCK MintNote storage carries the attested output recipe instead). |
| `asm/standards/xreserve/mint_deny_guard.masm` | Dissolved — see §2. `ERR_XRESERVE_MINT_DENIED` deleted with it. |
| `asm/standards/xreserve/burn_policy.masm` | The STOCK `MinBurnAmount::check_policy` (R-BURN-2); R-BURN-1 (zero-burn) → the ≥ 1 floor invariant (builder + note guard). Custom burn errors → the stock below-min error. |
| `asm/standards/xreserve/min_burn_admin.masm` | The STOCK `set_min_burn_amount` (authority-gated), reached ONLY through the reworked floor-guarded note. |
| `asm/standards/xreserve/domain_config.masm` | Three fields → build-time seeding (`with_domain_config`); the identifier → `identifier_init.masm` (same owner gate, init-once sentinel, non-empty guard). The u32 scalar/limb guards → the Rust type system at the builder boundary (u32/[u8;32] parameters). `ERR_XRESERVE_DOMAIN_REINIT` → `ERR_XRESERVE_IDENTIFIER_REINIT`. |
| `asm/standards/notes/xreserve_mint_note.masm` | The STOCK MINT script (reflection-dispatched `mint_and_send`). |
| `asm/standards/notes/xreserve_domain_init_note.masm` | `xreserve_identifier_init_note.masm` (identifier-only). |
| Rust `XReserveMintNote` factory + pinned root + scheme-1 consts | `XUsdcMintNote` (builds the stock note + the three attachments; scheme consts 4/5, parity-pinned); the script-root identity is the STOCK `MintNote::script_root()` (allowlist row 1). |
| Rust `XReserveDomainInitNote` factory + pinned root | `XReserveIdentifierInitNote` (new pinned root). |
| Builder: `MINT_DENY_GUARD_PROC_PATH`, `BURN_POLICY_PROC_PATH`, `MIN_BURN_SIZE_SLOT_LABEL`, `xreserve_component_with_min_burn_size`, deny/burn-guard errors | `ATTESTATION_MINT_POLICY_PROC_PATH` + `MIN_BURN_SIZE_FLOOR` + `with_domain_config` + the MinBurnAmount companion (which owns the floor slot) + the renamed rejection variants. |
| Test files `mint_deny.rs`, `mint_effects.rs`, `mint_recipient_account_id.rs`, `f5_mint_shim_negatives.rs`, `xreserve_mint.rs`, `xreserve_mint_note.rs`, `domain_config.rs` | The semantics re-proven through the new transport in `mint_policy_e2e.rs` (the full negative matrix + routing proof), `wave1_recomposition.rs` (posture tripwires + happy path + replay/fee/recipient binding + floor guards), `identifier_init.rs` (the minimized init behaviors), and the reworked surface/allowlist/burn/admin suites. |

## 6. Frozen surfaces — untouched (git-diff-provable)

The Circle-signed wire formats did not change: the 240B+ DepositIntent byte layout
(`encoding/layout.masm` + the Rust codecs — zero diff), the attestation encoding (keccak
preimage, 65B r‖s‖v, 33B pubkey; the 44-felt attachment layout is unchanged inside its new
scheme-5 envelope), the AccountId↔bytes32 codec, the burn-note wire + tag (`xreserve_burn.rs`,
`burn.masm` untouched). The mint-note TRANSPORT (script root, storage shape, attachment schemes)
changed BY DESIGN; the Circle-signed bytes inside it did not.

## 7. Routing proof + devnet caveat

MockChain proves: the constructed mint note is Public, tagged `with_account_target(faucet)`,
carries the scheme-2 `NetworkAccountTarget` binding the faucet, and the faucet (a network
account under the stock `AuthNetworkAccount` allowlist) consumes it through the STOCK script
end-to-end (`mint_policy_e2e.rs::mint_note_routes_to_the_faucet_network_account`).
**Caveat for the deploy task:** the tag-based note DISCOVERY is ntx-builder (node service)
behavior outside MockChain's model — the live v2 validation must confirm the devnet ntx-builder
schedules stock MintNotes against the faucet (the same caveat the old custom note carried).

## 8. Open items (unchanged, still Circle-owned, still OPEN)

DEV-5 (cap/scale/dust — Circle-OPEN; the faucet ships the provisional scale-0 identity because
both denominations are 6-decimal, but the decision stays Circle's), DEV-7,
DEV-8/Q-FEE-MVP (fee keep-zero per DEC-2; the envelope keeps the zeroed feeAmount limbs),
DEV-9/Q-CRY-5, DEV-10, Q-DOM-1, Q-CRY-4 (identifier fixpoint — the minimized init note is the
DEC-4 residual; on-chain derivation when Circle confirms), Q-DA-QUORUM.
