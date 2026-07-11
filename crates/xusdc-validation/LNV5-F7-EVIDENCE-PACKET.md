# LNV-5 F7 Evidence Packet — same-block burn erasure RIV (Circle / DEV-7 input)

**This packet is EVIDENCE ONLY: it makes NO acceptability decision. DEV-7 stays OPEN — a Circle-owned decision.** Produced on a fresh local `miden-node v0.15.1` stack from `main` @ `29dbcc4e50f2083942f3d1d0744e34abff63830c` by `cargo run -p xusdc-validation --bin lnv5_full_matrix` (faucet `0xcbe044fc2bcad991386b7cb29c1705`, holder `0x27fc127c813084315d0d9240b33a3f`).

The RIV question (F7): can the production `XReserveBurnNote` be created + consumed within one block so its burn event is erased (starving Circle's `SyncNotes` / `GetNotesById` discovery) while the supply delta still applies?

## Lifecycle 1 — two-block burn (row G: the Circle read-path, PERSISTS)

| field | value |
|---|---|
| burn note id | `0x387d6378252adee6968417df4c0057f179d4dd319b69989840afe89922be9d26` |
| note tag | `0x4255524E` (the fixed xUSDC burn tag) |
| committed in block | 1461 |
| consumed by the faucet in block | 1462 (strictly later) |
| token_supply | 100 → 0 |
| committed + `GetNotesById`-retrievable BEFORE consume | true |
| `SyncNotes` (tag-filtered) discovery | true |
| STILL `GetNotesById`-retrievable AFTER consume | true |
| nullifier recorded on-chain after consume | true |

The committed note + nullifier PERSIST after consumption — the withdrawal attester's read-path holds. Byte-exact response capture (note + inclusion proof): `LNV5-BURN-GETNOTESBYID-CAPTURE.hex`.

## Lifecycle 2 — same-block / never-committed burn (row H: the erasure RIV)

Mechanism: the production XReserveBurnNote consumed as an unauthenticated input (the same-block/never-committed lifecycle, mirroring canary c2_same_block_erasure_unauthenticated_consume): (1) a client-side execute shows the burn is valid and applies a supply delta; (2) submitting the faucet's consume via user RPC is REJECTED by the node — a COMMITTED same-block create+consume is unreachable (network-account faucet; the ntx-builder consumes only COMMITTED notes → always strictly-later-block, Row G); (3) the note never commits → no committed note, no nullifier, not SyncNotes-discoverable. Evidence for DEV-7; no acceptability decision

| field | value |
|---|---|
| burn note id | `0x78fb8e84cdb1ccd6e0ebd1ca0207e3bad190e7a23b47666dff0ada6e7b2d44d8` (same production note shape, tag `0x4255524E`) |
| client-side (unauthenticated) consume executed | true — the production note IS a valid burn |
| supply delta the executed consume applies | Some(100) (== the burned amount) |
| SUBMITTING that consume via user RPC | rejected: true |
| the node's rejection (verbatim) | `RpcError(RequestError { endpoint: SubmitProvenTx, error_kind: InvalidArgument, endpoint_error: None, source: Some(Status { code: InvalidArgument, message: "Network transactions may not be submitted by users yet", metadata: MetadataMap { headers: {"content-type": "application/grpc", "date": "Sat, 11 Jul 2026 14:12:03 GMT", "access-control-expose-headers": "grpc-status,grpc-message,grpc-status-details-bin", "x-ratelimit-limit": "128", "x-ratelimit-remaining": "127", "vary": "origin, access-control-request-method, access-control-request-headers", "access-control-allow-credentials": "true"} }, source: None }) })` |
| on-chain token_supply | 100 → 100 (UNCHANGED — nothing committed) |
| committed note found on the node | false |
| nullifier recorded on-chain | false |
| `SyncNotes` (tag-filtered) discovery | false |
| raw `GetNotesById` evidence | `GetNotesById([0x78fb8e84cdb1ccd6e0ebd1ca0207e3bad190e7a23b47666dff0ada6e7b2d44d8]) -> [] (note not found: the never-committed burn note is absent from the note tree — Circle SyncNotes/GetNotesById discovery is starved)` |

## The real-node constraint (why a COMMITTED same-block create+consume is unreachable on this stack)

The faucet is a network account: post-deployment user-RPC submissions against it are rejected by `miden-node v0.15.1` (captured verbatim above), the stock `miden-client 0.15.3` cannot present the sequencer's `x-miden-network-tx-auth` header, and the ntx-builder — the only commit path — consumes only COMMITTED notes, which makes every committed burn consumption strictly-later-block (lifecycle 1). The same-block-erasure hazard therefore does not materialize through any path available on this stack, while the client-side execution shows what WOULD survive if a same-block consume ever committed: the supply delta only — no note, no nullifier, no discovery.

**DEV-7 remains OPEN with Circle: this packet records the evidence for that decision and decides nothing about acceptability.**
