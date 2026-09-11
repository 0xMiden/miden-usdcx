# Circle API fixtures

Circle API fixtures for request and response validation. `tests/fixture_fidelity.rs` checks
field formats, enums, and cardinality; `tests/schema_constraints.rs` checks malformed inputs.

## Happy path (3)

| Fixture | Endpoint | Shape |
|---|---|---|
| `prepare_withdrawal_200.json` | `POST /v1/prepare-withdrawal` (200) | `{batches: [{burnIntents[], encoded, messageHashToSign}]}` — a top-level `batches[]` **wrapper**, never a bare batch |
| `withdraw_201.json` | `POST /v1/withdraw` (201) | an **ARRAY** of `WithdrawalStatus` — one per submitted batch, never an object |
| `withdrawal_status_200.json` | `GET /v1/withdrawal/{id}` (200) | a single `WithdrawalStatus` — the same object `POST /v1/withdraw` returns in its array |

## Error / malformed (10)

| Fixture | Case |
|---|---|
| `prepare_withdrawal_400.json` | malformed request → HTTP 400 |
| `prepare_withdrawal_validation_mismatch.json` | a well-formed **200** whose `spec.value` / `destinationDomain` / `destinationRecipient` do NOT match the burn-note payload → validation aborts before signing |
| `prepare_withdrawal_missing_hash.json` | a 200 missing the required `messageHashToSign` |
| `withdraw_400.json` | invalid withdraw request → HTTP 400 |
| `withdraw_409.json` | `burnTxId` already tied to an active withdrawal → HTTP 409 (a conflict requiring recovery, **never** a success) |
| `withdraw_500.json` | server error → HTTP 500 (bounded retry) |
| `withdraw_failed_status.json` | a withdraw whose `status == failed` (terminal) — carries `failureReason`, no `transactionHash` |
| `withdrawal_status_404.json` | unknown `withdrawalId` → HTTP 404 |
| `withdraw_threshold_violating_sigs.json` | a **request** body whose three batches violate the signature rules three ways: `burnSignatures` of length 1 (below `minItems 2`), descending signer order, and a duplicate signer. See the note below — the three are caught in two different places, on purpose |
| `malformed_body.json` | a schema-violating response body: a snake_case key (`withdrawal_id`), an off-enum `status`, and a 63-hex (bad-length) `transferSpecHashes` entry |

## Where the three signature violations are caught

A single signature fails the wire schema's minimum count. Descending or duplicate signers
decode unchanged and must be rejected by quorum validation. The decoder must not sort or
deduplicate signatures.

## Error bodies

Error responses have no specified body schema. The fixtures use empty objects and test the
HTTP status. The conflict fixture supplies `withdrawalId` and `burnTxId` as recovery hints:
a withdrawal ID permits status polling; a burn ID alone requires reconciliation. Circle's
error-body and authentication specifications remain OPEN.

## The scenario the happy-path fixtures encode

The successful fixtures describe one withdrawal:
10.000000 xUSDC burned, with net `value` = `"9999000"` and `maxFee` = `"1000"` in smallest
token units. Net value plus fee equals the 10000000 units burned on Miden
(`remoteDomain` = `10001`, "typically greater than 10000") for
a final destination of Ethereum (`finalDestinationDomain` = `0`), not forwarded
(`useCircleForwarding` = `false`, `forwardingCalldata` = `"0x"`).

Encoding details:

* `remoteDepositor` is a Miden `AccountId` in the 32-byte layout (16 zero bytes, then the
  prefix big-endian, then the suffix) — the encoding is owned by `xusdc-encoding`, consumed here by
  reference, never re-derived.
* `forwardingContractAddress` is 20 zero **bytes** (`0x0000…0000`), not the literal `"0x0"` the
  OpenAPI prose suggests: the field's regex is `^0x[a-fA-F0-9]{40}$`, which `"0x0"` does not match.
  Where prose and regex disagree, the regex is the schema.
