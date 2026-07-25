# RIV-ADVICE-KEY — the advice-map key, reconciled against the faucet's on-chain reader

## Status

**ADJUDICATED — human operator, 2026-07-13.** The builder hit G5's *code-wins-over-spec* STOP rule
(the running MASM contradicts the frozen spec), reported the contradiction, and stopped. The operator
reviewed it and directed the build to proceed on the reconciled key below. **The loop did not decide
this on its own authority**, and it is recorded here so no later agent silently "fixes" the code back
toward the stale paraphrase.

The `REQUIRES IMPLEMENTATION VALIDATION` label is **PRESERVED** — the adjudication settles *which key
the code uses*, not *that a note built this way mints*. Only **T-RLY-14**, the real-local-node submit
(R6), proves the latter. Nothing below is proven by a mock.

**Still owed to other parties.** The spec pack lives outside this repository
(`services-context-pack/relayer-spec/`) and its `COMPONENT-SPEC.md:215` still carries the pre-F5
paraphrase. The relayer cannot amend it — the spec owner (unit-01 / the frozen archive) must, or the
next agent to read the spec will re-derive the wrong key. That is the open cross-unit action item.

## Update — 2026-07-14 (the R5 revise; v0.16.0-alpha.2 base)

**The finding stands. The code it described does not, and never should have.**

The mint-note builder that first carried this note also shipped an advice-staging module
(`src/miden/advice.rs`, `populate_advice`) on the premise that the relayer publishes the advice
entries. It was audited and **adjudicated REVISE**, and the revised builder is a thin delegation to
unit-04's `XReserveMintNote::create` with **no advice surface of any kind**
(`src/miden/mint_note.rs`; the gate that keeps it out is `tests/relayer_has_no_advice_surface.rs`).

Why: the mint note is consumed by a **network transaction** the relayer does not build — the faucet
is a keyless network account, so the network's ntx-builder assembles that transaction and rebuilds
its advice map from the note's own ATTACHMENTS. There is no advice provider the relayer can reach, at
any protocol version. The in-repo proof is the driver that committed real mints against a live node:
`crates/xusdc-validation/src/mintburn.rs:190` is `XReserveMintNote::create(...)` and the whole of
`crates/xusdc-validation/src/rows_de.rs` contains the string "advice" zero times.

So the reconciled key below is **not the relayer's obligation** — it is a fact about how the faucet's
shim looks the attestation up, and it belongs to whoever builds the transaction that EMITS the note
(the submit leg, which is parked: no `miden-client` exists for v0.16). It is kept here because the
SPEC is still wrong in a way that will mislead that builder.

Two details in the sections below are v0.15-era and have since moved (the finding is unaffected —
both are unit-04's numbers, and the relayer restates neither): the attestation attachment is now
**11 words / 44 felts** with a **16-felt affine** candidate pubkey (`XRESERVE_MINT_ATTACHMENT_NUM_WORDS`
/ `PUBKEY_FELTS`, vm#3342 — see `docs/MIGRATION-V16-ALPHA2.md` S16), not 9 words / a 9-felt compressed
one; and `XReserveMintNote::attestation_attachment` is private again (nothing in the relayer needs to
rebuild an attachment in order to check one — the delegation tests compare whole notes).

## The reconciled key

```text
advice_map[ attachment.content().to_commitment() ] = attachment.content().to_elements()
```

One entry per attachment of the mint note — the scheme-1 attestation AND the scheme-2
`NetworkAccountTarget` routing bind. The key is the **commitment of the attachment's own content**: a
hash of the attested bytes themselves. The relayer does not choose it, cannot choose it, and never
invents one.

The value is that attachment's elements. For the attestation that is unit-04's frozen 36-felt
(9-word) content `[feeAmount(8 zero limbs — DEV-8 MVP), pubkey(9), signature(17), pad(2)]` — so the
9-felt candidate pubkey and the 17-felt signature travel INSIDE it, word-aligned, at unit-04's
offsets. That satisfies what the spec actually asks the relayer for: *"the 9-felt pubkey and 17-felt
sig are reachable in advice/attachments at submission time"* (`COMPONENT-SPEC.md:215`).

The relayer never restates that layout (G1 — a second definition of an owned format, even a
byte-identical one, is the cross-language drift seam the ownership map exists to close). Nor does it
need to: the attachment travels inside the note unit-04 built, and any party that must publish it
reads it back off that note (`note.attachments()`), rather than rebuilding it.

Implemented in this crate by **nobody** — see the 2026-07-14 update above.

## What the spec said, and why it is wrong

`relayer-spec/COMPONENT-SPEC.md:215` (pre-F5, and itself labelled `REQUIRES IMPLEMENTATION
VALIDATION`):

> the relayer places the 9-felt pubkey and the 17-felt signature into the advice map **keyed by the
> note commitment** so `xreserve_mint` can read them word-aligned.

The on-chain reader disagrees, and the on-chain reader is the one that has to find the data.
`asm/standards/xreserve/xreserve_mint_note_entry.masm` (`receive_and_mint`, the shim the note script
`call`s) does this:

1. `find_attachment(XRESERVE_MINT_ATTACHMENT_SCHEME)` → the attestation's index, `sc1_idx`;
2. `write_attachment_commitments_to_memory` → the note-committed attachment-commitments list;
3. loads the word at `commitments_base + sc1_idx * WORD_NUM_ELEMENTS` — the attestation's
   **commitment**;
4. `adv.push_mapval` on **that word**, and pops `[feeAmount(8), pubkey(9), signature(17)]` off the
   advice stack.

So the lookup word is the attachment commitment. An entry keyed by the note commitment would leave
step 4 with no entry under the word it actually pushes, and the mint would fail closed — every time,
for every deposit. The paraphrase predates F5 (which moved the attestation into a note attachment and
made the shim hash-verify it against the note-committed commitment); the key was never the relayer's
to pick, and after F5 it is a function of the attestation bytes.

Two consumers, one convention — and neither is free to key it differently:

| consumer | why it needs the entry |
| --- | --- |
| the **producer** tx that creates the note | `output_note::add_attachment` resolves each attachment's content out of the advice map **by its commitment**. An attachment missing from the map cannot be emitted at all — which is why the routing target is published too, not just the attestation. |
| the **faucet's** `receive_and_mint` | hash-verifies the content against the note-committed commitment, then re-surfaces that same entry to the advice stack (steps above). |

## What is NOT settled here

- **The consume side needs no advice from anyone.** The faucet's network tx consumes the note with
  *no consume-side advice staging*: the attachment travels inside the note, and the kernel resolves
  it. (Unit-04's own executing proof, `crates/xusdc-encoding/tests/xreserve_mint_note.rs`, consumes
  the real note with no tx script and no consume-side advice and still drives D5a→D5e.)
- **Who owns the producer side.** The entries above belong to the transaction that EMITS the note —
  and that is not this crate's to build (see the 2026-07-14 update). `COMPONENT-SPEC.md:401` sketches
  a relayer-side `populate_advice(builder: &mut TransactionRequestBuilder, …)`; that signature is
  doubly stale (it presumes the relayer stages advice at all, and 0.15.3's
  `TransactionRequestBuilder::extend_advice_map` consumed `self` besides). Recorded here so the spec
  owner can correct BOTH errors, and so whoever finally builds the producer transaction inherits the
  key rather than re-deriving it.
- **That the faucet accepts the note.** Only a real-node mint (T-RLY-14) proves that, and it is
  parked with the submit leg. The mint-note suite in this crate proves the note the relayer builds IS
  unit-04's note — nothing about Miden behaviour is faked to claim otherwise
  (`TEST-AND-VERIFICATION-HARNESS.md:277`: Miden behaviour must not be faked for acceptance).
