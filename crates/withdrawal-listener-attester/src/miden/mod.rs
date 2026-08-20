//! `miden` — the **node-facing half** of the service: the `miden-client`-backed adapters behind the
//! two Miden reads this crate is built around.
//!
//! Everything else in this crate is pure. This module is where a real node's answers enter, and it
//! is deliberately the thinnest possible layer over them:
//!
//! * [`discovery`] — the exact-tag `SyncNotes` scan and the `GetNotesById` retrieval, mapped into
//!   the [`DiscoveryRecord`](crate::validate::DiscoveryRecord) B3 validates.
//! * [`evidence`] — the three burn-evidence reads, mapped into the records
//!   [`assemble_evidence`](crate::evidence::assemble_evidence) reasons over.
//!
//! # It translates; it does not judge
//!
//! Not one refusal lives here. A wrong tag, a private note, a script root that is not the burn
//! note's, a vault that disagrees with the payload, a self-contradicting evidence stream — every one
//! of those is decided by [`validate_discovery`](crate::validate::validate_discovery) or by the
//! evidence assembler, over records these adapters reported FAITHFULLY.
//!
//! That split is not tidiness. A adapter that quietly dropped the wrong-tag note, or filled in the
//! canonical script root when the node did not report one, would make the check that refuses it
//! untestable and, worse, vacuous: the value reaching the checklist would already be the value the
//! checklist wants. So the rule for this module is that it says what the node said, and the two
//! checkers say whether that is a burn.
//!
//! The one thing the adapters DO decide is which of the node's own rows are about the thing that
//! was asked for — the exact-32-bit tag on the scan, the exact nullifier inside a prefix-scanned
//! spend reply. Those are not judgements about a burn; they are the difference between reading this
//! note's answer and reading a stranger's.
//!
//! # Each port owns its error
//!
//! [`discovery::DiscoveryReadError`] and [`crate::evidence::EvidenceReadError`] have the same shape
//! — the RPC that failed, and the preserved cause — and are deliberately NOT merged. Each belongs
//! to the port it is the error of, so widening one cannot silently widen the other, and neither
//! becomes a crate-wide "something Miden-ish went wrong" that callers have to re-narrow.
//!
//! # NOT here: a running service
//!
//! These are adapters, not a daemon. There is no binary, no polling loop and no cursor: which block
//! range to scan, how often, and where the cursor is durably kept belong to the service binary,
//! which is blocked on a human key-custody decision rather than on engineering.

pub mod discovery;
pub mod evidence;
