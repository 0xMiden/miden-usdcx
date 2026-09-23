//! Local checks on a consumed burn's content before it is prepared with Circle.

use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset, NonFungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteScript, NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1, ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
};
use miden_protocol::transaction::{OutputNote, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::note::{BurnNote, NetworkAccountTarget, NoteExecutionHint, P2idNote};
use miden_usdcx::note::xreserve_burn::{
    XReserveBurnNote, XUsdcBurnAttachment, FIXED_XUSDC_BURN_TAG,
};
use miden_usdcx::xreserve::encoding::{CircleDomain, ForeignChainAddress, XReserveBurnItems};

use crate::burn::{BurnCandidate, DiscoveredBurn};

use super::support::{faucet_account_id, transaction, word};

fn sender() -> AccountId {
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap()
}

fn items() -> XReserveBurnItems {
    XReserveBurnItems {
        dest_domain: CircleDomain::new(9),
        dest_recipient: ForeignChainAddress::new([0xab; 32]),
    }
}

fn fungible(issuer: AccountId, amount: u64) -> Asset {
    FungibleAsset::new(issuer, amount).unwrap().into()
}

fn nft() -> Asset {
    NonFungibleAsset::from_parts(
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into().unwrap(),
        word(5),
    )
    .into()
}

fn routing(target: AccountId, hint: NoteExecutionHint) -> NoteAttachment {
    NetworkAccountTarget::new(target, hint).unwrap().into()
}

/// Keep assets, storage and attachments independent for content checks.
pub(super) struct NoteFixture {
    script: NoteScript,
    tag: u32,
    assets: Vec<Asset>,
    storage: Vec<Felt>,
    attachments: Vec<NoteAttachment>,
    items: XReserveBurnItems,
}

impl NoteFixture {
    pub(super) fn new() -> Self {
        let asset = fungible(faucet_account_id(), 100);
        Self {
            script: BurnNote::script(),
            tag: FIXED_XUSDC_BURN_TAG,
            assets: vec![asset],
            storage: asset.as_elements().to_vec(),
            attachments: vec![
                routing(faucet_account_id(), NoteExecutionHint::Always),
                NoteAttachment::from(&XUsdcBurnAttachment::new(items())),
            ],
            items: items(),
        }
    }

    fn set_items(&mut self, items: XReserveBurnItems) {
        self.attachments[1] = NoteAttachment::from(&XUsdcBurnAttachment::new(items.clone()));
        self.items = items;
    }

    pub(super) fn edit_attachment(&mut self, index: usize, edit: impl FnOnce(&mut Vec<Word>)) {
        let attachment = &self.attachments[index];
        let mut words = attachment.content().as_words().to_vec();
        edit(&mut words);
        self.attachments[index] =
            NoteAttachment::with_words(attachment.attachment_scheme(), words).unwrap();
    }

    pub(super) fn note(self, serial: u64) -> Note {
        self.with_serial(word(serial))
    }

    fn with_serial(self, serial: Word) -> Note {
        Note::with_attachments(
            NoteAssets::new(self.assets).unwrap(),
            PartialNoteMetadata::new(sender(), NoteType::Public).with_tag(NoteTag::new(self.tag)),
            NoteRecipient::new(serial, self.script, NoteStorage::new(self.storage).unwrap()),
            NoteAttachments::new(self.attachments).unwrap(),
        )
    }
}

fn discovered(note: Note) -> DiscoveredBurn {
    let burn_tx_id = transaction(faucet_account_id(), &[note.nullifier()]).id();
    let OutputNote::Public(note) = RawOutputNote::Full(note).into_output_note().unwrap() else {
        panic!("the fixture constructs a public note")
    };
    BurnCandidate::new(note, BlockNumber::from(1u32), faucet_account_id())
        .unwrap()
        .into_discovered(BlockNumber::from(2u32), burn_tx_id)
}

pub(super) fn discovered_burn(
    amount: u64,
    serial: Word,
    destination_domain: u32,
) -> DiscoveredBurn {
    let mut fixture = NoteFixture::new();
    let asset = fungible(faucet_account_id(), amount);
    fixture.assets = vec![asset];
    fixture.storage = asset.as_elements().to_vec();
    let mut payload = items();
    payload.dest_domain = CircleDomain::new(destination_domain);
    payload.dest_recipient = ForeignChainAddress::new(core::array::from_fn(|i| i as u8));
    fixture.set_items(payload);
    discovered(fixture.with_serial(serial))
}

/// Accepts valid request formats and rejects malformed withdrawal payloads before persistence.
#[tokio::test]
async fn burn_notes_are_validated() {
    check_note_content_cases();
}

fn check_note_content_cases() {
    #[derive(Clone, Copy)]
    enum Expected {
        CandidateRejected,
        Accepted,
    }

    use Expected::{Accepted, CandidateRejected};
    let unknown_hint = NoteExecutionHint::Unknown(Felt::new(123).unwrap());
    let unknown_attachment = routing(faucet_account_id(), unknown_hint);
    let decoded = NetworkAccountTarget::try_from(&unknown_attachment).unwrap();
    assert_eq!(NoteAttachment::from(decoded), unknown_attachment);

    type Case = (&'static str, fn(&mut NoteFixture), Expected);
    let cases: &[Case] = &[
        ("hand-built valid note", |_| {}, Accepted),
        (
            "reversed attachments",
            |n| n.attachments.reverse(),
            Accepted,
        ),
        (
            "unknown execution time",
            |n| {
                n.attachments[0] = routing(
                    faucet_account_id(),
                    NoteExecutionHint::Unknown(Felt::new(123).unwrap()),
                )
            },
            Accepted,
        ),
        (
            "after-block hint",
            |n| {
                n.attachments[0] = routing(
                    faucet_account_id(),
                    NoteExecutionHint::after_block(BlockNumber::from(1u32)),
                )
            },
            Accepted,
        ),
        (
            "block-slot hint",
            |n| {
                n.attachments[0] = routing(
                    faucet_account_id(),
                    NoteExecutionHint::on_block_slot(3, 1, 0),
                )
            },
            Accepted,
        ),
        (
            "routing padding is ignored",
            |n| n.edit_attachment(0, |w| w[0][3] = Felt::ONE),
            Accepted,
        ),
        (
            "first domain padding value is nonzero",
            |n| n.edit_attachment(1, |w| w[0][1] = Felt::ONE),
            CandidateRejected,
        ),
        (
            "second domain padding value is nonzero",
            |n| n.edit_attachment(1, |w| w[0][2] = Felt::ONE),
            CandidateRejected,
        ),
        (
            "third domain padding value is nonzero",
            |n| n.edit_attachment(1, |w| w[0][3] = Felt::ONE),
            CandidateRejected,
        ),
        (
            "other destination",
            |n| {
                let mut payload = items();
                payload.dest_domain = CircleDomain::new(u32::MAX);
                payload.dest_recipient = ForeignChainAddress::new([0; 32]);
                n.set_items(payload);
            },
            Accepted,
        ),
        (
            "no new minimum",
            |n| {
                let asset = fungible(faucet_account_id(), 0);
                n.assets = vec![asset];
                n.storage = asset.as_elements().to_vec();
            },
            Accepted,
        ),
        (
            "wrong script",
            |n| n.script = P2idNote::script(),
            CandidateRejected,
        ),
        ("wrong tag", |n| n.tag ^= 1, Accepted),
        (
            "missing withdrawal",
            |n| {
                n.attachments.pop();
            },
            CandidateRejected,
        ),
        (
            "missing routing",
            |n| {
                n.attachments.remove(0);
            },
            CandidateRejected,
        ),
        (
            "duplicate routing",
            |n| n.attachments[1] = n.attachments[0].clone(),
            CandidateRejected,
        ),
        (
            "duplicate withdrawal",
            |n| n.attachments[0] = n.attachments[1].clone(),
            CandidateRejected,
        ),
        (
            "extra attachment",
            |n| {
                n.attachments.push(NoteAttachment::with_word(
                    NoteAttachmentScheme::new(7).unwrap(),
                    Word::empty(),
                ))
            },
            CandidateRejected,
        ),
        (
            "wrong withdrawal scheme",
            |n| {
                n.attachments[1] = NoteAttachment::with_words(
                    NoteAttachmentScheme::new(7).unwrap(),
                    n.attachments[1].content().as_words().to_vec(),
                )
                .unwrap()
            },
            CandidateRejected,
        ),
        (
            "routing has extra word",
            |n| n.edit_attachment(0, |w| w.push(Word::empty())),
            CandidateRejected,
        ),
        (
            "wrong target",
            |n| n.attachments[0] = routing(sender(), NoteExecutionHint::Always),
            CandidateRejected,
        ),
        ("no carried asset", |n| n.assets.clear(), CandidateRejected),
        (
            "NFT instead of fungible",
            |n| {
                let asset = nft();
                n.assets = vec![asset];
                n.storage = asset.as_elements().to_vec();
            },
            CandidateRejected,
        ),
        (
            "fungible plus NFT",
            |n| n.assets.push(nft()),
            CandidateRejected,
        ),
        (
            "wrong issuer",
            |n| {
                let asset = fungible(sender(), 100);
                n.assets = vec![asset];
                n.storage = asset.as_elements().to_vec();
            },
            CandidateRejected,
        ),
        (
            "short stored asset",
            |n| {
                n.storage.pop();
            },
            CandidateRejected,
        ),
        (
            "extra stored asset field",
            |n| n.storage.push(Felt::ZERO),
            CandidateRejected,
        ),
        (
            "different stored asset",
            |n| n.storage = fungible(faucet_account_id(), 99).as_elements().to_vec(),
            CandidateRejected,
        ),
        (
            "short withdrawal",
            |n| {
                n.edit_attachment(1, |w| {
                    w.pop();
                })
            },
            CandidateRejected,
        ),
        (
            "long withdrawal",
            |n| {
                n.edit_attachment(1, |w| {
                    w.resize(XUsdcBurnAttachment::NUM_WORDS + 1, Word::empty())
                })
            },
            CandidateRejected,
        ),
        (
            "destination domain is not u32",
            |n| n.edit_attachment(1, |w| w[0][0] = Felt::new(u64::from(u32::MAX) + 1).unwrap()),
            CandidateRejected,
        ),
        (
            "destination recipient limb is not u32",
            |n| n.edit_attachment(1, |w| w[1][0] = Felt::new(u64::from(u32::MAX) + 1).unwrap()),
            CandidateRejected,
        ),
        (
            "destination is our own domain, left to Circle's prepare",
            |n| {
                let mut payload = items();
                payload.dest_domain = CircleDomain::MIDEN;
                n.set_items(payload);
            },
            Accepted,
        ),
    ];

    // Construct every adversarial note before evaluating the matrix.
    let cases: Vec<_> = cases
        .iter()
        .map(|(name, edit, expected)| {
            let mut fixture = NoteFixture::new();
            edit(&mut fixture);
            let accepted = matches!(expected, Accepted).then(|| {
                let [asset] = fixture.assets.as_slice() else {
                    panic!("accepted fixture carries one asset")
                };
                let asset = asset
                    .as_fungible()
                    .expect("accepted fixture carries one fungible asset");
                (fixture.items.clone(), u64::from(asset.amount()))
            });
            let note = fixture.note(10);
            let burn_tx_id = transaction(faucet_account_id(), &[note.nullifier()]).id();
            let OutputNote::Public(note) = RawOutputNote::Full(note).into_output_note().unwrap()
            else {
                panic!("the fixture constructs a public note")
            };
            (
                *name,
                BurnCandidate::new(note, BlockNumber::from(1u32), faucet_account_id()),
                burn_tx_id,
                *expected,
                accepted,
            )
        })
        .collect();
    let factory_note = XReserveBurnNote::create(
        sender(),
        faucet_account_id(),
        AssetAmount::new(100).unwrap(),
        items(),
        &mut RandomCoin::new(word(8)),
    )
    .unwrap();
    let discovered = discovered(factory_note);
    assert_eq!(
        (discovered.items(), discovered.amount()),
        (&items(), 100),
        "real xUSDC note factory"
    );
    for (name, candidate, burn_tx_id, expected, accepted) in cases {
        match expected {
            CandidateRejected => assert!(candidate.is_err(), "{name}"),
            Accepted => {
                let burn = candidate
                    .expect(name)
                    .into_discovered(BlockNumber::from(2u32), burn_tx_id);
                let (expected_items, expected_amount) = accepted.unwrap();
                assert_eq!(
                    (burn.items(), burn.amount()),
                    (&expected_items, expected_amount),
                    "{name}"
                );
            }
        }
    }
}
