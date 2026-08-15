# Circle-facing semantics note — xUSDC transfer blocklist (faucet v2)

**Audience:** Circle · **Status:** for confirmation (Q-BLK-1, OPEN) · **Date:** 2026-07-23
This note states, in plain terms, what the on-chain transfer blocklist DOES on the Miden xUSDC faucet, so
Circle can confirm the behavior matches its compliance intent. The mechanics are kernel-verified (see the
flow matrix, §1.5 of the research report) and proven executable in `tests/transfer_blocklist_e2e.rs`.

## What "blocked" means (a FULL freeze — please confirm)

An account on the `blocked_accounts` map **cannot move xUSDC in any direction**:

- **Cannot send** — a blocked holder cannot create an asset-bearing note (the send callback checks the
  note creator).
- **Cannot receive/consume** — a blocked recipient cannot consume a note carrying xUSDC; the note
  **strands** (it stays unconsumed on-chain). NOTE ON RECOVERY: the shipped mint output and the tested
  transfer use the **stock P2ID** note script, which has **no reclaim path** (no reclaimer or
  reclaim-height storage) — the funds remain stranded and are recoverable only by **UNBLOCKING** the
  recipient so it can consume. (Sender-side reclaim would require a **P2IDE** note, a distinct script
  with reclaim storage; adopting P2IDE for the mint/transfer flow is a possible future option, not the
  current behavior.)
- **Cannot burn/redeem** — because creating a burn note is itself a send, a blocked holder **cannot
  redeem to the reserve either**. Blocking is therefore a **full freeze, including redemption.** This is
  the one semantic that most needs Circle's explicit sign-off: an EVM blacklist typically still allows
  some paths; here a block halts redemption too.

This matches Circle's EVM blacklist intent (transfers involving a blacklisted address are blocked), with
one modeling difference: a mint/transfer **TO** a blocked account **succeeds** at creation and **strands
at the recipient's consume** (the recipient is only checked when it tries to consume), rather than
reverting at send time.

## Pause is now a chain-wide freeze on xUSDC movement

With an active transfer policy, **pause halts ALL transfers** (send + receive + mint + burn), not just
mint/burn — the transfer-policy wrapper runs the pause check before dispatching. This matches Circle's
pause intent (its EVM pause halts transfers too); we call it out because it is broader than the pre-v2
pause, which halted only mint/burn.

## Administration — a dedicated external role, not the administrator

Block/unblock is gated on a dedicated **`BLOCK_LISTER`** role held by an **external entity** with **no
other admin capability** (it cannot set the attester, change max supply, pause, or administer any
other role). Miden (as the `ADMIN` holder) can rotate or revoke that entity through the standard
role-grant/revoke mechanism. `ADMIN` itself has **no** direct block/unblock power (two-way capability
isolation).

## Client-side consequence (for wallets / tooling holding xUSDC)

Because xUSDC is now a **policed** asset, every send/consume by a non-faucet account must load the faucet
as a **foreign account** so the kernel can run the transfer policy. Faucet-agnostic P2ID/basic-wallet
flows that worked against the basic asset will fail until updated. (Minting is unaffected — it is the
faucet's own transaction.)
