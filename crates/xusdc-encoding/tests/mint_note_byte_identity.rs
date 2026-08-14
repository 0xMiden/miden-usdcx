//! Mint-note byte-identity suite — the HARD GATE for any reshaping of the mint-note types.
//!
//! The mint note is the only supply-increasing message this crate emits, and every byte of it is
//! re-derived and assert-matched on-chain by the faucet's attestation mint policy. So a change to
//! how the Rust side HOLDS its values is only safe if the note it EMITS is unchanged: the same id,
//! the same nullifier, the same recipient recipe, the same attachment words in the same order.
//!
//! This suite freezes that emission. For every accept vector in the `mi` family — the empty-hookData
//! row and the non-empty-hookData row — it builds the production note at a FIXED serial and pins:
//!
//! - the note's `NoteId`,
//! - the note's nullifier,
//! - the recipient digest (the P2ID recipe the faucet re-derives),
//! - the attachments commitment (the hash the policy verifies the transport against),
//! - the serialized note's length and digest (everything above plus the metadata and the assets),
//! - the attachment scheme list with per-attachment word counts, in order.
//!
//! Every anchor is a string-exact `Debug`/`Display` rendering, following
//! `typing_builder_byte_identity.rs`. A single felt of drift — a reordered attachment section, a
//! dropped pad felt, a different serial derivation — flips one of them RED and names which.
//!
//! Re-freezing is a reviewed act, and the anchors below were last re-captured when two moves met on
//! this branch. `localToken` and `localDepositor` widened from a 20-byte address to the wire form's
//! full bytes32, so the carried payload gained four felts and the transport attachment is one word
//! longer — everything hashed over it moves, while the recipient recipe, which depends on neither
//! field, does not. The protocol-release migration then moved the recipient recipe itself, so the
//! id, the nullifier and the serialization move with it too; that move is confined to the protocol's
//! own derivation and changes nothing this crate ENCODES.
//!
//! The vector payload is used verbatim except for `remoteToken`, which is spliced to a deterministic
//! PUBLIC faucet id: the routing attachment can only bind a public network account, and the
//! artifact's synthetic faucet id is not one. The attestation bytes come from the frozen `att`
//! family; this factory never verifies a signature (the faucet does, on-chain), so what the
//! attestation must be here is well-formed, not valid.

mod support;

use miden_protocol::note::Note;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::Hasher;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use support::mint_transport::{note_rng, REMOTE_TOKEN_BYTE_OFF};
use support::{mint_note_from_payload, test_account_id, test_faucet_id};
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::vectors::{load, AttVector, MiVector};
use xusdc_encoding::xreserve::encoding::Signature;

/// The fixed serial-number seed the anchors were captured at (production draws a random serial; a
/// fixed one makes the note id, the nullifier and the whole serialization deterministic).
const RNG_SEED: u64 = 20_260_806;

/// The frozen anchors of one emitted mint note.
struct Anchors {
    vector: &'static str,
    note_id: &'static str,
    nullifier: &'static str,
    recipient_digest: &'static str,
    attachments_commitment: &'static str,
    serialized: &'static str,
    attachments: &'static str,
}

/// `mi-pos-empty-hookdata` + the `att-1` attestation.
const GOLDEN_EMPTY_HOOKDATA: Anchors = Anchors {
    vector: "mi-pos-empty-hookdata",
    note_id: "0xc65a724dce0b5971fef901aef725bf4ba7336916687c456c8b32dbeca58d9a48",
    nullifier: "0xde2ed6bad214d0706c143c18b0da5a3b0c8251f08734caa4dd416afb83e7193b",
    recipient_digest:
        "Word([1176885386095760737, 7141309783470215903, 6490412469362834449, 13801756655587511038])",
    attachments_commitment:
        "Word([353043364000201756, 2103906947509450114, 2847978362983062168, 17438370209489194753])",
    serialized: "843 bytes, digest Word([3449811486011593845, 3010906410555033109, 2351261109202290426, 13121967357539788815])",
    attachments: "[scheme=4 words=16, scheme=2 words=1]",
};

/// `mi-pos-hookdata` (ten bytes of hookData) + the `att-2` attestation.
const GOLDEN_HOOKDATA: Anchors = Anchors {
    vector: "mi-pos-hookdata",
    note_id: "0x505661a0fcbbb216de2d9e2a88ba7aa085108008287105e6e2453e1e8f706031",
    nullifier: "0x4d386aa89f6213d633af237c668734c7d58bb1735597d66c30a5f146ddc9c9b0",
    recipient_digest:
        "Word([18431265869439854198, 15724352411530353910, 5436862375304751880, 17786228380689675318])",
    attachments_commitment:
        "Word([17867121675036495872, 14584486229891685892, 2103155763186269017, 7340241149790238384])",
    serialized: "875 bytes, digest Word([14022250953414160237, 4242439243791055096, 15476406379804288216, 14674034305943930482])",
    attachments: "[scheme=4 words=17, scheme=2 words=1]",
};

/// Looks a family row up by id, so a renamed or removed vector fails loudly rather than silently
/// shrinking the coverage.
fn mi(id: &str) -> &'static MiVector {
    load()
        .families
        .mi
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("the canonical artifact is missing the mi vector {id}"))
}

fn att(id: &str) -> &'static AttVector {
    load()
        .families
        .att
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("the canonical artifact is missing the att vector {id}"))
}

/// The production mint note for a vector row, at the fixed serial.
fn note_for(vector_id: &str, attestation_id: &str) -> Note {
    let faucet_id = test_faucet_id(6);
    let mut payload = mi(vector_id).payload();
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32());

    let source = att(attestation_id);
    let attestation = DepositAttestation::new(Signature::new(source.sig()), source.public_key());

    mint_note_from_payload(
        test_account_id(5),
        faucet_id,
        &payload,
        attestation,
        &mut note_rng(RNG_SEED),
    )
    .expect("the production mint note must build for an accept vector")
}

/// Asserts every anchor at once, reporting all of the ones that moved rather than only the first —
/// a refactor that moves two of them should say so in one run.
fn assert_anchors(note: &Note, golden: &Anchors) {
    let serialized = note.to_bytes();
    let attachments = note
        .attachments()
        .iter()
        .map(|a| {
            format!(
                "scheme={} words={}",
                a.attachment_scheme().as_u16(),
                a.num_words()
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    let actual: [(&str, String); 6] = [
        ("note id", format!("{}", note.id())),
        ("nullifier", format!("{}", note.nullifier())),
        (
            "recipient digest",
            format!("{:?}", note.recipient().digest()),
        ),
        (
            "attachments commitment",
            format!("{:?}", note.attachments().to_commitment()),
        ),
        (
            "serialized note",
            format!(
                "{} bytes, digest {:?}",
                serialized.len(),
                Hasher::hash(&serialized)
            ),
        ),
        ("attachment shape", format!("[{attachments}]")),
    ];
    let expected = [
        golden.note_id,
        golden.nullifier,
        golden.recipient_digest,
        golden.attachments_commitment,
        golden.serialized,
        golden.attachments,
    ];

    let drifted: Vec<String> = actual
        .iter()
        .zip(expected)
        .filter(|((_, act), exp)| act != exp)
        .map(|((name, act), exp)| format!("  {name}:\n    frozen:   {exp}\n    emitted:  {act}"))
        .collect();

    assert!(
        drifted.is_empty(),
        "vector {}: the emitted mint note moved:\n{}",
        golden.vector,
        drifted.join("\n"),
    );
}

/// The empty-hookData accept row emits the frozen note, byte for byte.
#[test]
fn mint_note_bytes_are_frozen_for_the_empty_hookdata_vector() {
    assert_anchors(
        &note_for("mi-pos-empty-hookdata", "att-1"),
        &GOLDEN_EMPTY_HOOKDATA,
    );
}

/// The non-empty-hookData accept row emits the frozen note, byte for byte. The hookData tail is
/// what makes the transport attachment's word count a function of the payload, so it must be
/// pinned separately from the fixed-width row.
#[test]
fn mint_note_bytes_are_frozen_for_the_hookdata_vector() {
    assert_anchors(&note_for("mi-pos-hookdata", "att-2"), &GOLDEN_HOOKDATA);
}

/// Both accept rows are covered: a vector added to the `mi` accept family without an anchor here
/// would leave the gate blind to it.
#[test]
fn every_mi_accept_vector_is_anchored() {
    let anchored = [GOLDEN_EMPTY_HOOKDATA.vector, GOLDEN_HOOKDATA.vector];
    let accepts: Vec<&str> = load()
        .families
        .mi
        .iter()
        .filter(|v| v.kind == "accept")
        .map(|v| v.id.as_str())
        .collect();
    assert_eq!(
        accepts, anchored,
        "every mi accept vector must carry a frozen mint-note anchor",
    );
}
