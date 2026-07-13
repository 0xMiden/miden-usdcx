//! `build_mint_note` — the production `XReserveMintNote` (CMP-B1), in the exact post-F5 wire form
//! the faucet's `receive_and_mint` shim consumes.
//!
//! The relayer does not DEFINE that wire form; unit-04 does. The note is constructed by the shared
//! factory [`XReserveMintNote::create`], which owns the layout: `NoteType::Public` (forced), the
//! faucet account-target tag, the u32-LE-packed DepositIntent preimage as `NoteStorage.items`, and
//! the TWO F5 attachments — the scheme-1 attestation and the scheme-2 `NetworkAccountTarget`
//! routing bind. This module feeds that factory, surfaces its failures as the RIGHT `RelayerError`,
//! and fails closed if the note it gets back is not the note the faucet expects.
//!
//! What it takes IN is half the design. A [`MintNoteBuildRequest`] can only be built from a
//! [`ValidatedAttestation`] — the type that has already proved `messageHash == keccak256(payload)`.
//! That is not ceremony: the on-chain D5d verify is over `keccak256(payload)`, so a payload and
//! signature that were never bound to each other are *guaranteed* to fail on-chain, and a relayer
//! that accepted raw `&[u8]` + `[u8; 65]` could spend a Miden transaction proving nothing. The type
//! system carries the validation order (§8.1) all the way to the note.
//!
//! Three guards earn their place here:
//!
//! 1. **Typed structural rejects.** The factory wraps a codec failure in an opaque
//!    `NoteError::other_with_source`. Forwarding that would collapse every malformed payload into
//!    one indistinguishable "build failed", and the relayer's whole retry policy turns on telling
//!    permanent from transient. So the payload goes through unit-04's codec FIRST and its
//!    `EncodingError` is mapped to the field-specific variant (`PreimageTooLarge`, `BadMagic`,
//!    `ZeroAmount`, …) before the note is ever built.
//! 2. **The pinned script root** ([`check_script_root`]) — compared, never recomputed.
//! 3. **The attestation attachment** ([`attestation_attachment_of`]) — checked against unit-04's own
//!    attachment codec, so the relayer never restates the 04-owned layout (G1).

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{Note, NoteAttachment, NoteAttachmentScheme, NoteId, NoteScriptRoot};
use miden_protocol::{Felt, Word};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use xusdc_encoding::note::xreserve_mint::{
    MintAttestation, XReserveMintNote, XRESERVE_MINT_ATTACHMENT_SCHEME,
};
use xusdc_encoding::xreserve::encoding::deposit_intent_to_packed_felts;

use crate::circle::schema::ValidatedAttestation;
use crate::error::{Cause, RelayerError};

/// Everything the Miden half needs to build one mint note.
///
/// The attestation arrives ALREADY BOUND to its digest ([`ValidatedAttestation`]) — the payload and
/// the 65-byte `r‖s‖v` are read straight off it, never re-decoded and never re-derived. The
/// candidate pubkey is the operator's (it is the attester's key, not something Circle returns in
/// the attestation object), and the relayer only transports it: `Poseidon2(pubkey) ∈
/// xReserveAttesters` is checked ON-CHAIN at D5d, never here (INV-NO-ECRECOVER).
#[derive(Debug, Clone, Copy)]
pub struct MintNoteBuildRequest<'a> {
    producer: AccountId,
    faucet: AccountId,
    attestation: &'a ValidatedAttestation,
    pubkey: [u8; 33],
}

impl<'a> MintNoteBuildRequest<'a> {
    /// Bundles the note's two accounts with a validated attestation and the candidate pubkey.
    ///
    /// `producer` is the relayer's own account (the note's sender — it carries no authority);
    /// `faucet` is the xUSDC faucet network account the note is routed to and minted against.
    pub fn new(
        producer: AccountId,
        faucet: AccountId,
        attestation: &'a ValidatedAttestation,
        pubkey: [u8; 33],
    ) -> Self {
        Self {
            producer,
            faucet,
            attestation,
            pubkey,
        }
    }

    /// The relayer's producer account — the note's sender.
    pub fn producer(&self) -> AccountId {
        self.producer
    }

    /// The faucet network account the note targets.
    pub fn faucet(&self) -> AccountId {
        self.faucet
    }

    /// The validated attestation being relayed.
    pub fn attestation(&self) -> &ValidatedAttestation {
        self.attestation
    }

    /// The RAW DepositIntent payload — the exact bytes the binding check covered, and the exact
    /// bytes the on-chain D5a parse will see.
    pub fn deposit_intent(&self) -> &[u8] {
        self.attestation.payload()
    }

    /// The 65-byte `r‖s‖v` signature over `keccak256(payload)`.
    pub fn signature(&self) -> [u8; 65] {
        self.attestation.attestation()
    }

    /// The 33-byte compressed SEC1 candidate pubkey.
    pub fn pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
}

/// A mint note that has been built AND checked against the faucet's expectations: its script root is
/// the pinned one, and its scheme-1 attestation attachment is unit-04's codec output for the
/// attestation it relays.
#[derive(Debug, Clone)]
pub struct BuiltMintNote {
    note: Note,
    preimage_felt_len: usize,
}

impl BuiltMintNote {
    /// The note, ready to be emitted by the producer transaction.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// The note's id (its on-chain identity; the idempotency log records it against the nonce).
    pub fn id(&self) -> NoteId {
        self.note.id()
    }

    /// The note's script root — the pinned one by construction ([`build_mint_note`] refuses to
    /// return a note whose root is anything else).
    pub fn script_root(&self) -> NoteScriptRoot {
        self.note.recipient().script().root()
    }

    /// The felt count of the packed DepositIntent preimage carried in `NoteStorage.items`
    /// (60 header felts + `ceil(hookDataLen / 4)`; `≤ 1024` — T-RLY-11).
    pub fn preimage_felt_len(&self) -> usize {
        self.preimage_felt_len
    }

    /// The scheme-1 attestation attachment — the 9 words the faucet hash-verifies and pops off the
    /// advice stack. Present by construction.
    pub fn attestation_attachment(&self) -> &NoteAttachment {
        self.note
            .attachments()
            .iter()
            .find(|a| a.attachment_scheme() == attestation_scheme())
            .expect("the attestation attachment is checked present when the note is built")
    }

    /// Unwraps the note (the emit path takes it by value).
    pub fn into_note(self) -> Note {
        self.note
    }
}

/// The scheme-1 attestation attachment scheme, as the protocol type. The u16 is unit-04's
/// (`XRESERVE_MINT_ATTACHMENT_SCHEME`, parity-pinned against the MASM shim); it is a valid scheme by
/// construction, so the fallible constructor cannot fail here.
fn attestation_scheme() -> NoteAttachmentScheme {
    NoteAttachmentScheme::new(XRESERVE_MINT_ATTACHMENT_SCHEME)
        .expect("unit-04's mint attachment scheme is a valid attachment scheme")
}

/// Builds the production `XReserveMintNote` for one attested Circle deposit. **The service's entry
/// point.**
///
/// The note's serial number is drawn from the OS CSPRNG ([`OsEntropy`]): a serial number is what
/// makes two mints of the same DepositIntent two distinct notes, so it must be unpredictable and
/// must never repeat — not a policy each call site should be re-inventing. A test injects its own
/// source through [`build_mint_note_with_entropy`].
///
/// A rebuilt note is a NEW note. Safety against a replay comes from the faucet's on-chain
/// `usedNonces` assert-then-set — never from the note id, and never from this function.
///
/// # Errors
///
/// See [`build_mint_note_with_entropy`]; with the OS source, that includes
/// [`RelayerError::Entropy`] if the host cannot produce randomness.
pub fn build_mint_note(req: &MintNoteBuildRequest<'_>) -> Result<BuiltMintNote, RelayerError> {
    build_mint_note_with_entropy(req, &mut OsEntropy::default())
}

/// The serial-number entropy seam.
///
/// It exists so the FAILURE branch is reachable. The production source is the operating system, and
/// a test cannot take the OS's randomness away — without an injectable source, "the relayer survives
/// an entropy failure" would be an unfalsifiable claim about a service whose whole job is to keep
/// relaying.
pub trait SerialNumberEntropy {
    /// Draws the 128-bit seed for the note's serial-number coin.
    ///
    /// # Errors
    ///
    /// The underlying source's error, verbatim — the caller maps it, so the original cause survives.
    fn seed(&mut self) -> Result<[u32; 4], rand::Error>;
}

/// The production entropy adapter: it draws the seed from a CSPRNG **fallibly**.
///
/// It is generic over the RNG beneath it for one reason — so that the failure path is EXERCISABLE.
/// The only interesting decision in this adapter is `try_fill` over `fill`, and that decision is
/// invisible unless a test can hand it an RNG that refuses. With [`OsRng`] hard-wired, a regression
/// back to the panicking `fill` would pass every test that could be written, because no test can
/// take the operating system's randomness away.
#[derive(Debug, Clone, Copy, Default)]
pub struct CsprngEntropy<R>(R);

impl<R: RngCore> CsprngEntropy<R> {
    /// Wraps a CSPRNG as the note's serial-number source.
    pub fn new(rng: R) -> Self {
        Self(rng)
    }
}

impl<R: RngCore> SerialNumberEntropy for CsprngEntropy<R> {
    fn seed(&mut self) -> Result<[u32; 4], rand::Error> {
        let mut seed = [0u32; 4];
        // `try_fill`, NEVER `fill`. `Rng::fill` is the wrapper that PANICS when the source refuses
        // (rand 0.8; `OsRng` panics for the same reason), and aborting the process is the worst
        // available response here — a mint that was valid a microsecond ago is still valid, and the
        // host's entropy pool will very likely be back on the next attempt. The failure belongs in
        // the retry policy, not in a stack trace.
        self.0.try_fill(&mut seed[..])?;
        Ok(seed)
    }
}

/// The production source: the operating system's CSPRNG (`getrandom`), through the adapter above.
pub type OsEntropy = CsprngEntropy<OsRng>;

/// [`build_mint_note`] with the serial-number source injected — the seam a test builds a
/// REPRODUCIBLE note through, and the one that reaches the entropy-failure branch.
///
/// # Errors
///
/// - the field-specific DepositIntent variant (`BadMagic`, `ZeroAmount`, `PreimageTooLarge`, …) if
///   the payload does not survive unit-04's structural parse and the 1024-felt NoteStorage bound
///   (T-RLY-11). Checked BEFORE the serial number is drawn, so a permanently-bad payload is never
///   reported as a transient entropy fault the relayer would then retry forever;
/// - [`RelayerError::Entropy`] if `entropy` cannot produce a seed (the original cause preserved);
/// - [`RelayerError::NoteBuild`] if the factory refuses to build the note — most usefully when the
///   configured faucet is not a PUBLIC account, since the F5 routing attachment can only bind a
///   network account;
/// - [`RelayerError::ScriptRootMismatch`] if the built note's script root is not the pinned one;
/// - [`RelayerError::AttestationMismatch`] if the note's attestation attachment is not unit-04's
///   codec output for this attestation.
pub fn build_mint_note_with_entropy<E: SerialNumberEntropy>(
    req: &MintNoteBuildRequest<'_>,
    entropy: &mut E,
) -> Result<BuiltMintNote, RelayerError> {
    // Through unit-04's codec FIRST — the step that gives a malformed payload its field-specific
    // variant (T-RLY-11's `PreimageTooLarge` among them). It runs BEFORE the serial number is drawn
    // on purpose: a permanently-bad payload must report as itself, not as a transient entropy fault
    // the retry loop would then chase forever. The factory packs again internally; paying for that
    // twice is the price of not flattening the taxonomy.
    let preimage_felt_len = deposit_intent_to_packed_felts(req.deposit_intent())
        .map_err(RelayerError::from_deposit_intent)?
        .len();

    // The serial number's seed: four u32s widened into felts, so every limb is IN-FIELD by
    // construction — no reduction, no silent truncation of a u64 that happened to exceed the modulus
    // (`felt-construction`). The coin expands those 128 bits into the words it draws.
    let seed = entropy
        .seed()
        .map_err(|source| RelayerError::Entropy(Cause::new(source)))?;
    let mut rng = RandomCoin::new(Word::from(seed.map(Felt::from)));

    assemble(req, preimage_felt_len, &mut rng)
}

/// The build itself, once a serial-number source exists.
fn assemble<R: FeltRng>(
    req: &MintNoteBuildRequest<'_>,
    preimage_felt_len: usize,
    rng: &mut R,
) -> Result<BuiltMintNote, RelayerError> {
    // The factory owns the wire form: forced `NoteType::Public`, the faucet account-target tag, the
    // packed preimage as `NoteStorage.items`, and both F5 attachments.
    let attestation = MintAttestation::new(req.signature(), req.pubkey());
    let note = XReserveMintNote::create(
        req.producer(),
        req.faucet(),
        req.deposit_intent(),
        &attestation,
        rng,
    )
    .map_err(|source| RelayerError::NoteBuild(Cause::new(source)))?;

    // The two drift tripwires. Both ask whether the note we got back is one the DEPLOYED faucet will
    // accept — because a relayer that emits notes the network account cannot execute reports success
    // and mints nothing, which is the single failure mode this service exists to avoid.
    check_script_root(note.recipient().script().root())?;
    attestation_attachment_of(&note, &req.signature(), &req.pubkey())?;

    Ok(BuiltMintNote {
        note,
        preimage_felt_len,
    })
}

/// Refuses a script root that is not the PINNED one.
///
/// The root is never recomputed — it is compared. The pinned constant is what the deployed faucet's
/// `AuthNetworkAccount` note-script allowlist was cut against, and that allowlist is fixed at account
/// creation: a note whose root is not on it is executed by nobody. Failing the BUILD is the only
/// honest outcome, because the alternative — emitting the note — looks exactly like success until the
/// mint silently never happens.
///
/// # Errors
///
/// [`RelayerError::ScriptRootMismatch`], naming both roots.
pub fn check_script_root(actual: NoteScriptRoot) -> Result<(), RelayerError> {
    let pinned = XReserveMintNote::pinned_script_root();
    if actual != pinned {
        return Err(RelayerError::ScriptRootMismatch {
            expected: pinned.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

/// The note's scheme-1 attestation attachment, checked to BE unit-04's attachment for the
/// attestation `sig`/`pubkey` describe.
///
/// The oracle is [`XReserveMintNote::attestation_attachment`] — the 04-owned codec for the
/// `[feeAmount(8), pubkey(9), signature(17), pad(2)]` layout. The relayer never restates that layout
/// (G1: a second definition, even byte-identical, is the drift seam the ownership map closes); it
/// asks the owner what the attachment should be and compares.
///
/// One predicate, two questions. At BUILD time: "did the factory give me the content the faucet
/// expects?" — a cross-unit drift tripwire. In [`crate::miden::advice`]: "is the attestation I am
/// about to publish the one this note commits to?" — the crossed-wire guard.
///
/// # Errors
///
/// [`RelayerError::AttestationMismatch`] if the attachment is absent or is not that content.
pub fn attestation_attachment_of<'a>(
    note: &'a Note,
    sig: &[u8; 65],
    pubkey: &[u8; 33],
) -> Result<&'a NoteAttachment, RelayerError> {
    // What the 04 OWNER says this attestation's attachment is. The relayer builds no layout of its
    // own; it asks and compares.
    let owned = XReserveMintNote::attestation_attachment(&MintAttestation::new(*sig, *pubkey))
        .map_err(|source| RelayerError::NoteBuild(Cause::new(source)))?;

    let attachment = note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == attestation_scheme())
        .ok_or(RelayerError::AttestationMismatch)?;

    if attachment.as_elements() != owned.as_elements() {
        return Err(RelayerError::AttestationMismatch);
    }
    Ok(attachment)
}
