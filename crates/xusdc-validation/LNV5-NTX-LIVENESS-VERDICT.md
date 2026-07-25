# LNV-5 ntx-builder Liveness Verdict (matrix row K — the F5-deferred check)

Question: with the routing attachment + exec hint, does the node's ntx-builder AUTO-execute the faucet's mint (and burn) consumptions? Produced from `main` @ `29dbcc4e50f2083942f3d1d0744e34abff63830c` on the LNV-5 consolidated run.

## VERDICT: YES

**Deployment posture:** path N LIVE: the node's ntx-builder auto-executes routed+allowlisted consumptions against the network-account faucet (mint, burn, and admin all observed committing on this run); client-side execution (path C) remains open to any permissionless relayer and stays the harness posture for probes/negatives

## On-chain evidence — 16 path-N commits (2 mint / 1 burn / 13 admin)

| kind | op | commit block | committed effect |
|---|---|---|---|
| admin | set_attester(A, enabled=1) | — | attester A allowlist marker [1,0,0,0] |
| admin | set_attester(A, enabled=0) [C1 rotation] | — | attester A allowlist marker [0,0,0,0] |
| admin | set_attester(B, enabled=1) [C1 rotation] | — | attester B allowlist marker [1,0,0,0] |
| admin | set_min_burn_size (C2 raise) | — | min_burn_size 50 |
| admin | set_min_burn_size (C2 lower) | — | min_burn_size 10 |
| admin | set_max_supply (C3) | — | max_supply 300 |
| admin | pause (C4, DOM_PAUSER) | — | is_paused [1,0,0,0] |
| admin | set_attester while paused (C4/F6) | — | attester allowlist marker [1,0,0,0] |
| admin | set_min_burn_size while paused (C4/F6) | — | min_burn_size 7 |
| admin | unpause (C4, DOM_PAUSER) | — | is_paused [0,0,0,0] |
| admin | role grant DOM_PAUSER (C5, DOM_MANAGER) | — | new-pauser membership [1,0,0,0] |
| admin | pause (C5, new DOM_PAUSER) | — | is_paused [1,0,0,0] |
| admin | role revoke DOM_PAUSER (C5, DOM_MANAGER) | — | new-pauser membership [0,0,0,0] |
| mint | mint empty-hookData | 1006 | token_supply 0 → 100; usedNonces[nonce] set; recipient P2ID emitted |
| mint | mint hookData-bearing | 1081 | token_supply 100 → 250; usedNonces[nonce] set; recipient P2ID emitted |
| burn | burn two-block | 1462 | token_supply 100 → 0; nullifier recorded: true |

## Node-side evidence — 102 `executing network transaction` markers in `ntx-builder.log`

    2026-07-11T13:06:15.396117Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x82e3c8fb54d533311d40e3f446d4cd note_ids=[NoteId(Word([16142072565392187985, 13219878611664896933, 18045816351384534041, 3090378325454268114]))] num_notes=1 account_id=V1(AccountIdV1 { suffix: 2107935263909268736, prefix: 9431603026429555505 })
    2026-07-11T13:06:21.391895Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x82e3c8fb54d533311d40e3f446d4cd note_ids=[NoteId(Word([16142072565392187985, 13219878611664896933, 18045816351384534041, 3090378325454268114]))] num_notes=1 account_id=V1(AccountIdV1 { suffix: 2107935263909268736, prefix: 9431603026429555505 })
    2026-07-11T13:06:30.393675Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x82e3c8fb54d533311d40e3f446d4cd note_ids=[NoteId(Word([16142072565392187985, 13219878611664896933, 18045816351384534041, 3090378325454268114]))] num_notes=1 account_id=V1(AccountIdV1 { suffix: 2107935263909268736, prefix: 9431603026429555505 })
    2026-07-11T13:06:39.394741Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x82e3c8fb54d533311d40e3f446d4cd note_ids=[NoteId(Word([16142072565392187985, 13219878611664896933, 18045816351384534041, 3090378325454268114]))] num_notes=1 account_id=V1(AccountIdV1 { suffix: 2107935263909268736, prefix: 9431603026429555505 })
    2026-07-11T13:06:51.392215Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x82e3c8fb54d533311d40e3f446d4cd note_ids=[NoteId(Word([16142072565392187985, 13219878611664896933, 18045816351384534041, 3090378325454268114]))] num_notes=1 account_id=V1(AccountIdV1 { suffix: 2107935263909268736, prefix: 9431603026429555505 })
    2026-07-11T13:07:03.422925Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x82e3c8fb54d533311d40e3f446d4cd note_ids=[NoteId(Word([16142072565392187985, 13219878611664896933, 18045816351384534041, 3090378325454268114]))] num_notes=1 account_id=V1(AccountIdV1 { suffix: 2107935263909268736, prefix: 9431603026429555505 })
    2026-07-11T13:07:18.422636Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x82e3c8fb54d533311d40e3f446d4cd note_ids=[NoteId(Word([16142072565392187985, 13219878611664896933, 18045816351384534041, 3090378325454268114]))] num_notes=1 account_id=V1(AccountIdV1 { suffix: 2107935263909268736, prefix: 9431603026429555505 })
    2026-07-11T13:07:39.409998Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x82e3c8fb54d533311d40e3f446d4cd note_ids=[NoteId(Word([16142072565392187985, 13219878611664896933, 18045816351384534041, 3090378325454268114]))] num_notes=1 account_id=V1(AccountIdV1 { suffix: 2107935263909268736, prefix: 9431603026429555505 })
    … 94 more (full log archived under the run root)
