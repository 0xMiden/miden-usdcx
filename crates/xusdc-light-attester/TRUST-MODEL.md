# Light attester trust model

**We trust Miden's block signers. We do not trust the server that delivers those
blocks to us.** That server is what the code calls the RPC.

Think of the server as a delivery person. We check the signed contents of the
package instead of trusting what the delivery person says.

## 1. Start from one block we already trust

The operator gives the attester a known block number and its expected fingerprint,
called a hash. This starting block is the **anchor**.

The operator must confirm that fingerprint independently. If the potentially
dishonest server gets to choose our starting point, it could give us an invented
history. Checking that history against itself would prove nothing.

We also rely on the operator to configure the correct faucet account and the block
where scanning should begin. Startup cannot decide whether those choices are right.

## 2. Check every block after it

```text
Trusted starting block → checked block → checked block → …
```

For each new block, we check:

- Does it directly follow the previous trusted block?
- Does it have valid signatures from all the signers that the previous block authorizes?
- Do its notes and transaction records match the signed contents?

The previous checked block tells us which signing keys to accept. The server does
not get to choose new keys just for its response.

A server cannot change a note, remove a transaction, or skip a block and still pass
these checks, assuming the signatures and hashes cannot be forged. It can refuse
to deliver a block, but we will not skip that block and pretend we checked it.

## 3. Look for both parts of a burn

Within those checked blocks, we look for:

1. A public note using the expected burn program from our Miden library.
2. A later transaction showing that our faucet consumed that exact note.

Creating the note alone is not enough. We match it to the consumption using a
fingerprint derived from the note, called its nullifier. The evidence comes from
the checked transaction record, not just the server saying "this note was spent."

This establishes consumption on the chain we accepted. It does not yet establish
that the note's requested withdrawal amount and other details are valid.

## 4. Remember what we have checked

We save the notes, discovered consumptions and our checked position in SQLite.
Each block's discoveries and progress are saved together. If the next block fails,
the earlier saves survive, and we can retry from there.

After restarting, we trust that saved history instead of checking everything again.
**Our own machine and database must therefore remain trustworthy.** Format checks
cannot protect against someone rewriting the database or replacing it with an old copy.

## 5. Wait for more checked blocks

Suppose the faucet consumes the note in block **100**, and we require **10 more blocks**.

We must actually check the chain through block **110**. The server merely saying
"we're at 110" is not enough.

We also ask for the server's reported "proven height." That report must cover the
burn block, so at least 100 in this example. It can make us wait longer, but it
cannot replace those ten checked blocks. A dishonest high report cannot bypass
that waiting requirement. The report itself is not proof we independently verify.

## What this protects against, and what it does not

- **A dishonest delivery server:** it cannot rewrite signed history without breaking
  our checks. It can still hold back newer blocks or stop answering, delaying discovery.
- **Dishonest block signers:** not covered. We trust Miden's validators to sign valid
  history, not conflicting histories. We check signatures; we do not rerun all
  transactions or verify execution proofs. Correct burns still rely on those
  validators, the deployed faucet and the Miden libraries we depend on.
- **History conflicts:** no automatic recovery. If detected, an operator must stop,
  preserve the database, establish the correct chain independently, and check for
  any withdrawals already sent before recovering. We do not silently replace the anchor.
- **Notes we cannot see:** private notes and notes created and erased within one
  block cannot enter this discovery path. Detecting and reconciling missed withdrawals
  is still future work.

## What is still unfinished

**"The faucet consumed this note" does not mean "approve its requested withdrawal."**

Checking the asset, requested amount and other burn details, then signing and
submitting to Circle, remains unfinished. The waiting check exists but is not yet
connected to submission. Our future Circle signing keys are separate from Miden's
block-signing keys discussed above.

This describes the implemented startup, discovery and waiting checks. The executable
currently runs startup and exits; the full service cycle is not wired up yet.

For the code: [startup and discovery](src/attester.rs),
[saved state and waiting checks](src/store.rs), [server requests](src/chain.rs).
