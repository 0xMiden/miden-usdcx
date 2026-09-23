//! Local burn-content checks; the end-to-end signing boundary remains a roadmap stub.

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
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Word};
use miden_standards::note::{BurnNote, NetworkAccountTarget, NoteExecutionHint, P2idNote};
use xusdc_encoding::note::xreserve_burn::{
    XReserveBurnNote, XUsdcBurnAttachment, FIXED_XUSDC_BURN_TAG,
    XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS,
};
use xusdc_encoding::xreserve::encoding::{ForeignChainAddress, XReserveBurnItems};

use crate::burn::{validate_burn, BurnCandidate, DiscoveredBurn};

use super::discovery::start;
use super::support::{faucet_account_id, scan_limits, transaction, word, BlockFactory};

fn sender() -> AccountId {
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap()
}

fn items() -> XReserveBurnItems {
    XReserveBurnItems {
        dest_domain: 9,
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
struct NoteFixture {
    script: NoteScript,
    tag: u32,
    assets: Vec<Asset>,
    storage: Vec<Felt>,
    attachments: Vec<NoteAttachment>,
    items: XReserveBurnItems,
}

impl NoteFixture {
    fn new() -> Self {
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

    fn edit_attachment(&mut self, index: usize, edit: impl FnOnce(&mut Vec<Word>)) {
        let attachment = &self.attachments[index];
        let mut words = attachment.content().as_words().to_vec();
        edit(&mut words);
        self.attachments[index] =
            NoteAttachment::with_words(attachment.attachment_scheme(), words).unwrap();
    }

    fn note(self, serial: u64) -> Note {
        Note::with_attachments(
            NoteAssets::new(self.assets).unwrap(),
            PartialNoteMetadata::new(sender(), NoteType::Public).with_tag(NoteTag::new(self.tag)),
            NoteRecipient::new(
                word(serial),
                self.script,
                NoteStorage::new(self.storage).unwrap(),
            ),
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

/// Accepts valid request formats, refuses each proven content violation, and processes only
/// ready rows. Refusal writes must preserve pending work when the database cannot save them.
#[tokio::test]
async fn burn_notes_are_validated() {
    check_note_content_cases();
    ready_burns_are_processed(false).await;
    ready_burns_are_processed(true).await;
}

fn check_note_content_cases() {
    #[derive(Clone, Copy)]
    enum Expected {
        CandidateRejected,
        Refused,
        Accepted,
    }

    use Expected::{Accepted, CandidateRejected, Refused};
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
            |n| n.attachments[0] = routing(faucet_account_id(), NoteExecutionHint::None),
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
            "withdrawal padding is ignored",
            |n| {
                n.edit_attachment(1, |w| {
                    w[2][1] = Felt::ONE;
                    w[2][2] = Felt::ONE;
                    w[2][3] = Felt::ONE;
                })
            },
            Accepted,
        ),
        (
            "other destination",
            |n| {
                let mut payload = items();
                payload.dest_domain = u32::MAX;
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
                    w.resize(XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS + 1, Word::empty())
                })
            },
            CandidateRejected,
        ),
        (
            "withdrawal cannot decode",
            |n| n.edit_attachment(1, |w| w[0][0] = Felt::new(u64::from(u32::MAX) + 1).unwrap()),
            Refused,
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
    let validated = validate_burn(discovered(factory_note)).unwrap();
    assert_eq!(
        (validated.items, validated.amount),
        (items(), 100),
        "real xUSDC note factory"
    );
    for (name, candidate, burn_tx_id, expected, accepted) in cases {
        match expected {
            CandidateRejected => assert!(candidate.is_err(), "{name}"),
            Refused => {
                let burn = candidate
                    .expect(name)
                    .into_discovered(BlockNumber::from(2u32), burn_tx_id);
                assert!(validate_burn(burn).is_none(), "{name}");
            }
            Accepted => {
                let burn = candidate
                    .expect(name)
                    .into_discovered(BlockNumber::from(2u32), burn_tx_id);
                let burn = validate_burn(burn).expect(name);
                assert_eq!((burn.items, burn.amount), accepted.unwrap(), "{name}");
            }
        }
    }
}

async fn ready_burns_are_processed(fail_refusal_write: bool) {
    let good = discovered(NoteFixture::new().note(20));
    let mut invalid = NoteFixture::new();
    invalid.edit_attachment(1, |words| {
        words[0][0] = Felt::new(u64::from(u32::MAX) + 1).unwrap()
    });
    let invalid = discovered(invalid.note(21));
    let young = discovered(NoteFixture::new().note(22));
    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());
    factory.push(
        vec![
            OutputNote::Public(invalid.note().clone()),
            OutputNote::Public(good.note().clone()),
            OutputNote::Public(young.note().clone()),
        ],
        Vec::new(),
    );
    let consuming_tx = transaction(
        faucet_account_id(),
        &[invalid.nullifier(), good.nullifier()],
    );
    let expected_good = DiscoveredBurn::new(
        good.note().clone(),
        good.creation_block(),
        good.consumption_block(),
        consuming_tx.id(),
        faucet_account_id(),
    )
    .unwrap();
    factory.push(Vec::new(), vec![consuming_tx]);
    factory.push(
        Vec::new(),
        vec![transaction(faucet_account_id(), &[young.nullifier()])],
    );

    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, _) = start(&tempdir, 1, factory.blocks(), scan_limits(3, 3)).await;
    attester.discover_burns().await.unwrap();
    let checkpoint = attester.store.scan_state().unwrap();
    drop(attester);
    let store_path = tempdir.path().join("state.sqlite3");
    if fail_refusal_write {
        rusqlite::Connection::open(&store_path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_refusal BEFORE UPDATE OF status ON burns
             WHEN NEW.status = 'REFUSED'
             BEGIN SELECT RAISE(FAIL, 'injected refusal write failure'); END;",
            )
            .unwrap();
    }
    let (mut attester, controls) = start(&tempdir, 1, factory.blocks(), scan_limits(3, 3)).await;
    assert!(attester
        .validate_ready_burns(BlockNumber::from(1u32))
        .unwrap()
        .is_empty());
    let still_pending = attester
        .store
        .burns_ready_for_withdrawal(BlockNumber::from(3u32), 1)
        .unwrap();
    assert_eq!(still_pending.len(), 2);
    for burn in [&good, &invalid] {
        assert!(
            still_pending
                .iter()
                .any(|saved| saved.note_id() == burn.note_id()),
            "low proof-lag height must leave both burns pending"
        );
    }
    let result = attester.validate_ready_burns(BlockNumber::from(3u32));
    if fail_refusal_write {
        assert_eq!(
            result.unwrap_err().to_string(),
            "attester store query failed"
        );
    } else {
        let validated = result.unwrap();
        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].burn, expected_good);
        assert_eq!(validated[0].items, items());
        assert_eq!(validated[0].amount, 100);
    }
    assert_eq!(attester.store.scan_state().unwrap(), checkpoint);
    assert_eq!(
        *controls.scan_limit_requests.lock().unwrap(),
        0,
        "local validation does not call the RPC"
    );
    assert_eq!(
        *controls.requests.lock().unwrap(),
        [BlockNumber::GENESIS],
        "only startup fetches a block"
    );
    drop(attester);

    let connection = rusqlite::Connection::open(&store_path).unwrap();
    for (burn, expected_status) in [
        (&good, "DISCOVERED"),
        (&young, "DISCOVERED"),
        (
            &invalid,
            if fail_refusal_write {
                "DISCOVERED"
            } else {
                "REFUSED"
            },
        ),
    ] {
        let status: String = connection
            .query_row(
                "SELECT status FROM burns WHERE note_id = ?1",
                [burn.note_id().to_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, expected_status);
    }
}
