# Circle mock fixtures — schema-frozen (§11.2)

The 13 fixtures the withdrawal listener/attester's Circle-facing tests run against: 3 happy-path +
10 error/malformed. They are **frozen against the OpenAPI**, not against this crate's structs — the
schemas in `CIRCLE-API-SURFACE.md` (§ "OpenAPI JSON schemas (exact, not compressed)") and
`CIRCLE-DATA-SCHEMAS.md` §10 are the source of truth, and `tests/fixture_fidelity.rs` re-derives
every field's regex / enum / cardinality constraint straight from those tables. **A fixture edited to
make a struct pass is a defect**: fix the struct.

This service releases real USDC, so the direction of the arrow matters. The fixture is the contract;
the Rust type is the thing under test.

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
| `prepare_withdrawal_validation_mismatch.json` | a well-formed **200** whose `spec.value` / `destinationDomain` / `destinationRecipient` do NOT match the burn-note payload → B5 aborts, does not sign |
| `prepare_withdrawal_missing_hash.json` | a 200 missing the required `messageHashToSign` |
| `withdraw_400.json` | invalid withdraw request → HTTP 400 |
| `withdraw_409.json` | `burnTxId` already tied to an active withdrawal → HTTP 409 (a conflict requiring recovery, **never** a success) |
| `withdraw_500.json` | server error → HTTP 500 (bounded retry) |
| `withdraw_failed_status.json` | a withdraw whose `status == failed` (terminal) — carries `failureReason`, no `transactionHash` |
| `withdrawal_status_404.json` | unknown `withdrawalId` → HTTP 404 |
| `withdraw_threshold_violating_sigs.json` | a **request** body whose three batches violate the signature rules three ways: `burnSignatures` of length 1 (below `minItems 2`), descending signer order, and a duplicate signer. See the note below — the three are caught in two different places, on purpose |
| `malformed_body.json` | a schema-violating response body: a snake_case key (`withdrawal_id`), an off-enum `status`, and a 63-hex (bad-length) `transferSpecHashes` entry |

## Where the three signature violations are caught

`withdraw_threshold_violating_sigs.json` carries three defects, and they are **not** all the same kind
of defect — so they are not all caught in the same place:

* **`burnSignatures` of length 1** violates the OpenAPI's `minItems: 2`. That is a *schema* rule, so
  the wire type refuses it: the fixture, as a whole, **does not decode** into a `WithdrawRequest`. This
  is the right outcome — it is a body Circle would reject, and it must never leave the process.
* **Descending signer order** and **a duplicate signer** violate the *quorum* contract (`DC-11`, §10.9:
  ascending signer-address order, no duplicates). No JSON schema can express those, so those two
  batches **do decode** — and the wire type must carry them **verbatim**, unsorted and
  un-deduplicated, so the quorum assembler (T-LA-09) can still see the defect it exists to catch. A
  wire type that tidied the list would repair the batch on its way out and hide the very thing the
  quorum check is for.

Both halves are pinned in `tests/schema_constraints.rs`.

## Why the error bodies are content-free

The OpenAPI documents **no error-body schema at all** — no `4xx`/`5xx` response content is defined
anywhere in the Circle sources this repo has (a genuine `NO EVIDENCE FOUND`, tracked under the same
`Q-API-AUTH`-adjacent Circle-owned gap). Inventing one (`{"error": …}`, `{"code": …}`) would be
exactly the fabrication the schema-frozen rule exists to prevent, so `prepare_withdrawal_400`,
`withdraw_400`, `withdraw_500` and `withdrawal_status_404` carry an **empty object**. What the
fixtures assert is the property that *is* documented: the **HTTP status** (encoded in the filename)
is the contract, and such a body must never decode as the endpoint's success shape.

`withdraw_409.json` is the one exception, and it invents nothing either: it carries only
`withdrawalId` and `burnTxId` — Circle's own `WithdrawalResponse` field names — because those are
precisely the two recovery hints the conflict path in `COMPONENT-SPEC.md §10.10` reads (`if
conflict.withdrawalId is present → recover by polling GET /v1/withdrawal/{withdrawalId}; if only
conflict.burnTxId is present → stop and mark reconciliation required`). No typed Circle error struct
exists in this crate: the conflict body is read as raw JSON, because declaring a type for it would be
declaring a schema Circle has not published.

## The scenario the happy-path fixtures encode

One coherent withdrawal, so the validation slice (T-LA-06) has a payload to compare against:
10.000000 xUSDC (`value` = `"10000000"`, the smallest-unit form; `"10.00"` in the request's decimal
`valueExcludingFees`) burned on Miden (`remoteDomain` = `10001`, "typically greater than 10000") for
a final destination of Ethereum (`finalDestinationDomain` = `0`), not forwarded
(`useCircleForwarding` = `false`, `forwardingCalldata` = `"0x"`).

Two byte-level notes, both load-bearing:

* `remoteDepositor` is a Miden `AccountId` in the unit-04 `bytes32` layout (16 zero bytes, then the
  prefix big-endian, then the suffix) — the encoding is owned by `xusdc-encoding`, consumed here by
  reference, never re-derived.
* `forwardingContractAddress` is 20 zero **bytes** (`0x0000…0000`), not the literal `"0x0"` the
  OpenAPI prose suggests: the field's regex is `^0x[a-fA-F0-9]{40}$`, which `"0x0"` does not match.
  Where prose and regex disagree, the regex is the schema.
