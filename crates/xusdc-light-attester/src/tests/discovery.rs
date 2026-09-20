//! Authenticated sequential discovery and loop-boundary tests.

use std::path::PathBuf;

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockBody, BlockHeader, BlockNumber, BlockSignatures, SignedBlock};
use miden_protocol::note::{Note, NoteAttachment, NoteAttachments, NoteType};
use miden_protocol::transaction::OrderedTransactionHeaders;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::Word;
use miden_standards::note::{BurnNote, NetworkAccountTarget, NoteExecutionHint, P2idNote};
use tokio_util::sync::CancellationToken;

use crate::attester::{Attester, DiscoverError};
use crate::burn::{BurnCandidate, BurnRefusal, DiscoveredBurn};
use crate::chain::ScanLimits;
use crate::config::Config;
use crate::store::{ScanCursor, ScanState, Store, StoreError, TrustedAnchor, CONFLICT, INVALID};

use super::support::{
    faucet_account_id, note, ready_circle, scan_limits, test_note, transaction, BlockFactory,
    ChainControls, TestChain,
};

const OTHER_ACCOUNT_ID: &str = "0x9b405fd9fe431bd1135a292de098cb";
const SIGNING_KEY_ONE: &str =
    "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SIGNING_KEY_TWO: &str =
    "0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

fn write_config(
    tempdir: &tempfile::TempDir,
    deployment_block: u32,
    anchor: &SignedBlock,
    finality_depth: u32,
) -> Config {
    let path = tempdir.path().join("attester.toml");
    let store_path = PathBuf::from("state.sqlite3");
    let config = format!(
        "circle_request_timeout_ms = 100\n\
         faucet_account_id_hex = \"{}\"\n\
         circle_api_base_url = \"https://circle.example.invalid\"\n\
         poll_interval_ms = 1\n\
         faucet_deployment_block = {deployment_block}\n\
         trusted_anchor_block = {}\n\
         trusted_anchor_commitment_hex = \"{}\"\n\
         minimum_finality_depth_blocks = {finality_depth}\n\
         expected_signing_public_keys_hex = [\"{SIGNING_KEY_ONE}\", \"{SIGNING_KEY_TWO}\"]\n\
         store_path = {:?}\n",
        faucet_account_id().to_hex(),
        anchor.header().block_num().as_u32(),
        anchor.header().commitment().to_hex(),
        store_path,
    );
    std::fs::write(&path, config).unwrap();
    Config::load(&path).unwrap()
}

pub(super) async fn start(
    tempdir: &tempfile::TempDir,
    deployment_block: u32,
    blocks: Vec<SignedBlock>,
    scan_limits: ScanLimits,
) -> (Attester, ChainControls) {
    let anchor = blocks[0].clone();
    let config = write_config(tempdir, deployment_block, &anchor, 1);
    let (chain, controls) = TestChain::new(blocks, scan_limits);
    let attester = Attester::start(config, Box::new(chain), ready_circle())
        .await
        .unwrap();
    (attester, controls)
}

/// Saves every authenticated block, matches faucet burns to public stock notes, and selects
/// ready burns only when both the saved chain and proof-lag height allow withdrawal.
#[tokio::test]
async fn burns_are_discovered_safely() {
    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());

    let before_deployment = note(BurnNote::script(), NoteType::Public, 1, 1);
    factory.push(vec![before_deployment.output], Vec::new());

    let burn_one = note(BurnNote::script(), NoteType::Public, 7, 2);
    let burn_two = note(BurnNote::script(), NoteType::Public, 8, 3);
    let private_burn = note(BurnNote::script(), NoteType::Private, 9, 4);
    let spoofed_tag = note(
        P2idNote::script(),
        NoteType::Public,
        xusdc_encoding::note::xreserve_burn::FIXED_XUSDC_BURN_TAG,
        5,
    );
    let wrong_target = {
        let burn = note(BurnNote::script(), NoteType::Public, 9, 50);
        let (assets, metadata, recipient, attachments) =
            burn.public_note.unwrap().into_note().into_parts();
        test_note(Note::with_attachments(
            assets,
            metadata.into_partial_metadata(),
            recipient,
            NoteAttachments::new(vec![
                NoteAttachment::from(
                    NetworkAccountTarget::new(
                        AccountId::from_hex(OTHER_ACCOUNT_ID).unwrap(),
                        NoteExecutionHint::Always,
                    )
                    .unwrap(),
                ),
                attachments.get(1).unwrap().clone(),
            ])
            .unwrap(),
        ))
    };
    let missing_withdrawal = {
        let burn = note(BurnNote::script(), NoteType::Public, 9, 51);
        let (assets, metadata, recipient, attachments) =
            burn.public_note.unwrap().into_note().into_parts();
        test_note(Note::with_attachments(
            assets,
            metadata.into_partial_metadata(),
            recipient,
            NoteAttachments::new(vec![attachments.get(0).unwrap().clone()]).unwrap(),
        ))
    };
    factory.push(
        vec![
            burn_one.output.clone(),
            burn_two.output.clone(),
            private_burn.output,
            spoofed_tag.output,
            wrong_target.output,
            missing_withdrawal.output,
        ],
        Vec::new(),
    );

    factory.push(
        Vec::new(),
        vec![transaction(
            AccountId::from_hex(OTHER_ACCOUNT_ID).unwrap(),
            &[burn_one.nullifier],
        )],
    );

    let later_burn = note(BurnNote::script(), NoteType::Public, 10, 6);
    let erased = note(BurnNote::script(), NoteType::Public, 11, 7);
    let consuming_tx = transaction(
        faucet_account_id(),
        &[burn_one.nullifier, burn_two.nullifier, erased.nullifier],
    );
    let consuming_tx_id = consuming_tx.id();
    factory.push(vec![later_burn.output], vec![consuming_tx]);
    factory.push(
        Vec::new(),
        vec![transaction(faucet_account_id(), &[later_burn.nullifier])],
    );
    let pending = note(BurnNote::script(), NoteType::Public, 12, 9);
    factory.push(vec![pending.output], Vec::new());

    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, controls) = start(&tempdir, 2, factory.blocks(), scan_limits(6, 4)).await;
    attester.discover_burns().await.unwrap();

    assert_eq!(
        *controls.requests.lock().unwrap(),
        (0u32..=6).map(BlockNumber::from).collect::<Vec<_>>()
    );
    assert_eq!(*controls.scan_limit_requests.lock().unwrap(), 1);
    let state = attester.store.scan_state().unwrap();
    assert_eq!(state.cursor.next_block, BlockNumber::from(7u32));
    assert_eq!(
        state.authenticated_parent.unwrap().block_num(),
        BlockNumber::from(6u32)
    );

    let candidates = attester.store.candidates().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].note_id(), pending.id);
    assert_eq!(candidates[0].note(), &pending.public_note.unwrap());

    assert_eq!(attester.store.discovered_burns().unwrap().len(), 3);
    let mut burns = attester
        .store
        .burns_ready_for_withdrawal(BlockNumber::from(4u32), 1)
        .unwrap();
    burns.sort_by_key(DiscoveredBurn::note_id);
    assert_eq!(burns.len(), 2);
    assert_eq!(burns[0].burn_tx_id(), consuming_tx_id);
    assert_eq!(burns[1].burn_tx_id(), consuming_tx_id);
    assert_eq!(
        burns
            .iter()
            .map(DiscoveredBurn::note_id)
            .collect::<Vec<_>>(),
        {
            let mut ids = vec![burn_one.id, burn_two.id];
            ids.sort();
            ids
        }
    );
    for original in [burn_one, burn_two] {
        let saved = burns
            .iter()
            .find(|burn| burn.note_id() == original.id)
            .unwrap();
        assert_eq!(saved.note(), &original.public_note.unwrap());
    }

    drop(attester);
    let (mut attester, restart_controls) =
        start(&tempdir, 2, factory.blocks(), scan_limits(6, 5)).await;
    assert_eq!(
        *restart_controls.requests.lock().unwrap(),
        [BlockNumber::GENESIS]
    );
    attester.discover_burns().await.unwrap();
    assert_eq!(
        *restart_controls.requests.lock().unwrap(),
        [BlockNumber::GENESIS]
    );
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(7u32)
    );
    assert_eq!(attester.store.candidates().unwrap().len(), 1);
    let burns = attester
        .store
        .burns_ready_for_withdrawal(BlockNumber::from(5u32), 1)
        .unwrap();
    assert_eq!(burns.len(), 3);
    assert!(burns.iter().any(|burn| burn.note_id() == later_burn.id));

    let burn_at_anchor = note(BurnNote::script(), NoteType::Public, 12, 8);
    let mut factory = BlockFactory::new();
    factory.push(vec![burn_at_anchor.output], Vec::new());
    let anchor_consumption = transaction(faucet_account_id(), &[burn_at_anchor.nullifier]);
    factory.push(Vec::new(), vec![anchor_consumption]);
    factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, _) = start(&tempdir, 0, factory.blocks(), scan_limits(2, 1)).await;
    attester.discover_burns().await.unwrap();
    assert_eq!(
        attester
            .store
            .discovered_burns()
            .unwrap()
            .iter()
            .map(DiscoveredBurn::note_id)
            .collect::<Vec<_>>(),
        [burn_at_anchor.id]
    );

    // A burn at block 2 needs verified block 4 for depth 2, regardless of reported heights.
    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());
    let burn = note(BurnNote::script(), NoteType::Public, 1, 10);
    factory.push(vec![burn.output], Vec::new());
    factory.push(
        Vec::new(),
        vec![transaction(faucet_account_id(), &[burn.nullifier])],
    );
    factory.push(Vec::new(), Vec::new());
    factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let config = write_config(&tempdir, 1, &factory.blocks()[0], 2);
    let (chain, controls) = TestChain::new(factory.blocks(), scan_limits(3, 3));
    let mut attester = Attester::start(config, Box::new(chain), ready_circle())
        .await
        .unwrap();
    attester.discover_burns().await.unwrap();
    assert_eq!(attester.store.discovered_burns().unwrap().len(), 1);
    for (proof_lag, depth) in [(3u32, 2), (3, 4), (1, 1)] {
        assert!(attester
            .store
            .burns_ready_for_withdrawal(proof_lag.into(), depth)
            .unwrap()
            .is_empty());
    }
    assert_eq!(
        attester
            .store
            .burns_ready_for_withdrawal(2u32.into(), 1)
            .unwrap()
            .len(),
        1
    );
    controls.requests.lock().unwrap().clear();
    *controls.scan_limits.lock().unwrap() = scan_limits(4, 4);
    attester.discover_burns().await.unwrap();
    assert_eq!(
        *controls.requests.lock().unwrap(),
        [BlockNumber::from(4u32)]
    );
    let ready = attester
        .store
        .burns_ready_for_withdrawal(2u32.into(), 2)
        .unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].note_id(), burn.id);
}

/// Proves candidate insertion, burn promotion, cursor movement, and authenticated-parent updates
/// share one transaction; skipped blocks, wrong parents, and repeated evidence change nothing.
#[test]
fn burns_and_scan_position_are_saved_together() {
    let mut factory = BlockFactory::new();
    let anchor = factory.push(Vec::new(), Vec::new());
    let child = factory.push(Vec::new(), Vec::new());
    let grandchild = factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path().join("state.sqlite3");
    let trusted_anchor = TrustedAnchor {
        block_num: BlockNumber::GENESIS,
        commitment: anchor.header().commitment(),
    };
    let mut store = Store::open_or_create(
        &path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::GENESIS,
        },
        trusted_anchor,
    )
    .unwrap();

    let burn_note = note(BurnNote::script(), NoteType::Public, 1, 20);
    let candidate = BurnCandidate::new(
        burn_note.public_note.clone().unwrap(),
        BlockNumber::GENESIS,
        faucet_account_id(),
    )
    .unwrap();
    let after_anchor = ScanState {
        cursor: ScanCursor {
            next_block: BlockNumber::from(1u32),
        },
        authenticated_parent: Some(anchor.header().clone()),
    };
    let after_child = ScanState {
        cursor: ScanCursor {
            next_block: BlockNumber::from(2u32),
        },
        authenticated_parent: Some(child.header().clone()),
    };
    let initial_state = store.scan_state().unwrap();
    assert!(store
        .burns_ready_for_withdrawal(BlockNumber::MAX, 0)
        .unwrap()
        .is_empty());
    // Even the first saved block must not skip a height. No stored parent can mask this check.
    assert_eq!(
        store
            .save_scan_progress(std::slice::from_ref(&candidate), &[], &after_child)
            .unwrap_err()
            .to_string(),
        CONFLICT
    );
    assert_eq!(store.scan_state().unwrap(), initial_state);
    assert!(store.candidates().unwrap().is_empty());
    assert!(store.discovered_burns().unwrap().is_empty());
    store
        .save_scan_progress(std::slice::from_ref(&candidate), &[], &after_anchor)
        .unwrap();
    for next_state in [&after_anchor, &after_child] {
        assert_eq!(
            store
                .save_scan_progress(std::slice::from_ref(&candidate), &[], next_state)
                .unwrap_err()
                .to_string(),
            CONFLICT
        );
        assert_eq!(store.scan_state().unwrap(), after_anchor.clone());
        assert_eq!(store.candidates().unwrap(), vec![candidate.clone()]);
        assert!(store.discovered_burns().unwrap().is_empty());
    }

    let second_note = note(BurnNote::script(), NoteType::Public, 2, 21);
    let second_candidate = BurnCandidate::new(
        second_note.public_note.unwrap(),
        BlockNumber::from(1u32),
        faucet_account_id(),
    )
    .unwrap();
    let tx = transaction(faucet_account_id(), &[candidate.nullifier()]);
    let burn = candidate
        .clone()
        .into_discovered(BlockNumber::from(1u32), tx.id());
    let header = child.header();
    let wrong_parent = ScanState {
        authenticated_parent: Some(BlockHeader::new(
            Word::empty(),
            header.block_num(),
            header.chain_commitment(),
            header.account_root(),
            header.nullifier_root(),
            header.note_root(),
            header.tx_commitment(),
            header.validator_config().clone(),
            header.fee_parameters().clone(),
            header.protocol_config_commitment(),
            header.next_protocol_config().cloned(),
            header.timestamp(),
        )),
        ..after_child.clone()
    };
    // The height is correct, but the new header must also link to the saved block.
    assert_eq!(
        store
            .save_scan_progress(
                std::slice::from_ref(&second_candidate),
                std::slice::from_ref(&burn),
                &wrong_parent,
            )
            .unwrap_err()
            .to_string(),
        CONFLICT
    );
    assert_eq!(store.scan_state().unwrap(), after_anchor.clone());
    assert_eq!(store.candidates().unwrap(), vec![candidate.clone()]);
    assert!(store.discovered_burns().unwrap().is_empty());

    // Both heights pass the temporal bounds, but promotion must retain the candidate's height.
    let mismatched_promotion = DiscoveredBurn::new(
        second_candidate.note().clone(),
        burn.creation_block(),
        burn.consumption_block(),
        transaction(faucet_account_id(), &[second_candidate.nullifier()]).id(),
        faucet_account_id(),
    )
    .unwrap();
    assert_eq!(
        store
            .save_scan_progress(
                std::slice::from_ref(&second_candidate),
                std::slice::from_ref(&mismatched_promotion),
                &after_child,
            )
            .unwrap_err()
            .to_string(),
        CONFLICT
    );
    assert_eq!(store.scan_state().unwrap(), after_anchor.clone());
    assert_eq!(store.candidates().unwrap(), vec![candidate.clone()]);
    assert!(store.discovered_burns().unwrap().is_empty());

    store
        .save_scan_progress(&[], std::slice::from_ref(&burn), &after_child)
        .unwrap();
    assert_eq!(
        store
            .save_scan_progress(
                std::slice::from_ref(&candidate),
                std::slice::from_ref(&burn),
                &after_child,
            )
            .unwrap_err()
            .to_string(),
        CONFLICT
    );
    assert_eq!(store.scan_state().unwrap(), after_child.clone());
    assert!(store.candidates().unwrap().is_empty());
    assert_eq!(store.discovered_burns().unwrap(), vec![burn.clone()]);
    assert_eq!(
        store
            .save_scan_progress(&[], &[], &after_anchor)
            .unwrap_err()
            .to_string(),
        CONFLICT
    );

    let conflicting_burn = DiscoveredBurn::new(
        burn.note().clone(),
        burn.creation_block(),
        burn.consumption_block(),
        transaction(
            faucet_account_id(),
            &[candidate.nullifier(), second_candidate.nullifier()],
        )
        .id(),
        faucet_account_id(),
    )
    .unwrap();
    let after_grandchild = ScanState {
        cursor: ScanCursor {
            next_block: BlockNumber::from(3u32),
        },
        authenticated_parent: Some(grandchild.header().clone()),
    };
    assert_eq!(
        store
            .save_scan_progress(std::slice::from_ref(&candidate), &[], &after_grandchild)
            .unwrap_err()
            .to_string(),
        CONFLICT
    );
    assert_eq!(store.scan_state().unwrap(), after_child.clone());
    assert!(store.candidates().unwrap().is_empty());
    assert_eq!(store.discovered_burns().unwrap(), vec![burn.clone()]);
    for duplicate in [&burn, &conflicting_burn] {
        assert_eq!(
            store
                .save_scan_progress(
                    std::slice::from_ref(&second_candidate),
                    std::slice::from_ref(duplicate),
                    &after_grandchild,
                )
                .unwrap_err()
                .to_string(),
            CONFLICT
        );
        assert_eq!(store.scan_state().unwrap(), after_child.clone());
        assert!(store.candidates().unwrap().is_empty());
        assert_eq!(store.discovered_burns().unwrap(), vec![burn.clone()]);
    }
    let invalid_parent = ScanState {
        cursor: ScanCursor {
            next_block: BlockNumber::from(3u32),
        },
        authenticated_parent: after_child.authenticated_parent.clone(),
    };
    assert_eq!(
        store
            .save_scan_progress(&[], &[], &invalid_parent)
            .unwrap_err()
            .to_string(),
        INVALID
    );
    assert_eq!(store.scan_state().unwrap(), after_child.clone());

    assert_eq!(
        store.refuse_burn(burn.note_id(), BurnRefusal::WrongTag),
        Ok(())
    );
    assert_eq!(
        store.refuse_burn(burn.note_id(), BurnRefusal::WrongTag),
        Err(StoreError::Conflict),
        "a refused burn is no longer pending work"
    );
    for (id, reason) in [
        (burn.note_id(), BurnRefusal::WrongTag),
        (second_candidate.note_id(), BurnRefusal::WrongTag),
    ] {
        assert_eq!(store.refuse_burn(id, reason), Err(StoreError::Conflict));
    }
    assert_eq!(
        store.save_scan_progress(
            std::slice::from_ref(&candidate),
            std::slice::from_ref(&burn),
            &after_child,
        ),
        Err(StoreError::Conflict)
    );
    assert_eq!(store.scan_state(), Ok(after_child.clone()));
    assert_eq!(store.discovered_burns(), Ok(vec![burn.clone()]));
    assert!(store.candidates().unwrap().is_empty());
    assert!(store
        .burns_ready_for_withdrawal(BlockNumber::MAX, 0)
        .unwrap()
        .is_empty());

    drop(store);
    let store = Store::open_or_create(
        &path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::GENESIS,
        },
        trusted_anchor,
    )
    .unwrap();
    assert_eq!(store.discovered_burns().unwrap(), vec![burn.clone()]);
    assert_eq!(store.scan_state().unwrap(), after_child);
    assert!(store
        .burns_ready_for_withdrawal(BlockNumber::MAX, 0)
        .unwrap()
        .is_empty());
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let refusal = connection
        .query_row(
            "SELECT status, refusal_reason FROM burns WHERE note_id = ?1",
            [burn.note_id().to_bytes()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap();
    assert_eq!(refusal, ("REFUSED".into(), "wrong_tag".into()));
    drop(connection);

    let changed_anchor = TrustedAnchor {
        commitment: Word::empty(),
        ..trusted_anchor
    };
    assert_eq!(
        Store::open_or_create(
            &path,
            faucet_account_id(),
            ScanCursor {
                next_block: BlockNumber::GENESIS,
            },
            changed_anchor,
        )
        .err()
        .unwrap()
        .to_string(),
        "configured trusted anchor differs from the store"
    );

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE burns SET note = x'00'", [])
        .unwrap();
    drop(connection);
    let store = Store::open_or_create(
        &path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::GENESIS,
        },
        trusted_anchor,
    )
    .unwrap();
    assert_eq!(store.discovered_burns().unwrap_err().to_string(), INVALID);
    drop(store);

    // The saved header is the next run's trust base, so one that does not decode blocks startup.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE attester_state SET authenticated_parent = x''", [])
        .unwrap();
    drop(connection);
    assert_eq!(
        Store::open_or_create(
            &path,
            faucet_account_id(),
            ScanCursor {
                next_block: BlockNumber::GENESIS,
            },
            trusted_anchor,
        )
        .err()
        .unwrap()
        .to_string(),
        INVALID
    );

    let malformed_candidate_path = tempdir.path().join("malformed-candidate.sqlite3");
    drop(
        Store::open_or_create(
            &malformed_candidate_path,
            faucet_account_id(),
            ScanCursor {
                next_block: BlockNumber::GENESIS,
            },
            trusted_anchor,
        )
        .unwrap(),
    );
    let connection = rusqlite::Connection::open(&malformed_candidate_path).unwrap();
    connection
        .execute(
            "INSERT INTO burns (note_id, nullifier, note, creation_block, status)
             VALUES (X'00', X'01', X'02', 0, 'CANDIDATE')",
            [],
        )
        .unwrap();
    drop(connection);
    let store = Store::open_or_create(
        &malformed_candidate_path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::GENESIS,
        },
        trusted_anchor,
    )
    .unwrap();
    assert_eq!(store.candidates().unwrap_err().to_string(), INVALID);

    let predeployment_path = tempdir.path().join("predeployment.sqlite3");
    let mut store = Store::open_or_create(
        &predeployment_path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::from(2u32),
        },
        trusted_anchor,
    )
    .unwrap();
    assert_eq!(
        store
            .save_scan_progress(
                &[BurnCandidate::new(
                    candidate.note().clone(),
                    BlockNumber::from(1u32),
                    faucet_account_id(),
                )
                .unwrap()],
                &[],
                &ScanState {
                    cursor: ScanCursor {
                        next_block: BlockNumber::from(3u32),
                    },
                    authenticated_parent: Some(BlockHeader::mock(2u32, None, None, &[])),
                },
            )
            .unwrap_err()
            .to_string(),
        CONFLICT
    );
}

/// Rejects missing, skipped, body-inconsistent, badly signed, and regressed chains. A bad block
/// never advances the cursor, while earlier verified blocks remain saved for the next attempt.
#[tokio::test]
async fn bad_blocks_are_rejected() {
    enum Expected {
        ReadFailure,
        Divergence,
    }

    let mut configured_factory = BlockFactory::new();
    let configured_anchor = configured_factory.push(Vec::new(), Vec::new());
    let mut served_factory = BlockFactory::new();
    let served_anchor = served_factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let config = write_config(&tempdir, 0, &configured_anchor, 1);
    let (chain, _) = TestChain::new(vec![served_anchor], scan_limits(1, 0));
    assert!(Attester::start(config, Box::new(chain), ready_circle())
        .await
        .is_err());

    let (header, _, signatures) = configured_anchor.clone().into_parts();
    let injected = note(BurnNote::script(), NoteType::Public, 1, 29);
    let tampered_body = BlockBody::new_unchecked(
        Vec::new(),
        vec![vec![(0, injected.output)]],
        Vec::new(),
        OrderedTransactionHeaders::new_unchecked(Vec::new()),
    );
    let tampered_anchor = SignedBlock::new_unchecked(header, tampered_body, signatures);
    let tempdir = tempfile::tempdir().unwrap();
    let config = write_config(&tempdir, 0, &configured_anchor, 1);
    let (chain, _) = TestChain::new(vec![tampered_anchor], scan_limits(1, 0));
    assert!(Attester::start(config, Box::new(chain), ready_circle())
        .await
        .is_err());

    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());
    let later_anchor = factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let config = write_config(&tempdir, 0, &later_anchor, 1);
    let (chain, _) = TestChain::new(factory.blocks(), scan_limits(2, 1));
    assert!(Attester::start(config, Box::new(chain), ready_circle())
        .await
        .is_err());

    let cases = [
        ("missing", 0u8, 1u32, Expected::ReadFailure),
        ("skipped", 1u8, 1u32, Expected::Divergence),
        ("bad body", 2u8, 1u32, Expected::Divergence),
        ("bad signature", 3u8, 1u32, Expected::Divergence),
        ("bad bootstrap body", 4u8, 2u32, Expected::Divergence),
    ];
    for (name, mutation, deployment_block, expected) in cases {
        let mut factory = BlockFactory::new();
        factory.push(Vec::new(), Vec::new());
        factory.push(Vec::new(), Vec::new());
        factory.push(Vec::new(), Vec::new());
        let mut blocks = factory.blocks();
        let mut missing = false;
        match mutation {
            0 => missing = true,
            1 => blocks[1] = blocks[2].clone(),
            2 | 4 => {
                let (header, _, signatures) = blocks[1].clone().into_parts();
                let injected = note(BurnNote::script(), NoteType::Public, 1, 30);
                let body = BlockBody::new_unchecked(
                    Vec::new(),
                    vec![vec![(0, injected.output)]],
                    Vec::new(),
                    OrderedTransactionHeaders::new_unchecked(Vec::new()),
                );
                blocks[1] = SignedBlock::new_unchecked(header, body, signatures);
            }
            3 => {
                let (header, body, _) = blocks[1].clone().into_parts();
                blocks[1] = SignedBlock::new_unchecked(
                    header,
                    body,
                    BlockSignatures::new(Vec::new()).unwrap(),
                );
            }
            _ => unreachable!(),
        }

        let tempdir = tempfile::tempdir().unwrap();
        let anchor = blocks[0].clone();
        let config = write_config(&tempdir, deployment_block, &anchor, 1);
        let (chain, _) = TestChain::new(blocks, scan_limits(3, 2));
        let chain = if missing { chain.missing_at(1) } else { chain };
        let mut attester = Attester::start(config, Box::new(chain), ready_circle())
            .await
            .unwrap();
        let error = attester
            .discover_burns()
            .await
            .expect_err("invalid chain must fail");
        match expected {
            Expected::ReadFailure => assert!(matches!(error, DiscoverError::Chain(_)), "{name}"),
            Expected::Divergence => {
                assert!(matches!(error, DiscoverError::ChainDiverged), "{name}")
            }
        }
        let state = attester.store.scan_state().unwrap();
        assert_eq!(
            state.cursor.next_block,
            BlockNumber::from(deployment_block),
            "{name}"
        );
        assert!(state.authenticated_parent.is_none(), "{name}");
        assert!(attester.store.candidates().unwrap().is_empty(), "{name}");
        assert!(
            attester.store.discovered_burns().unwrap().is_empty(),
            "{name}"
        );
    }

    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());
    let saved_note = note(BurnNote::script(), NoteType::Public, 1, 31);
    let saved_block = factory.push(vec![saved_note.output.clone()], Vec::new());
    factory.push(Vec::new(), Vec::new());
    let mut blocks = factory.blocks();
    let (header, body, _) = blocks[2].clone().into_parts();
    blocks[2] = SignedBlock::new_unchecked(header, body, BlockSignatures::new(Vec::new()).unwrap());
    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, _) = start(&tempdir, 1, blocks, scan_limits(3, 2)).await;
    assert!(matches!(
        attester.discover_burns().await,
        Err(DiscoverError::ChainDiverged)
    ));
    assert_eq!(
        attester.store.scan_state().unwrap(),
        ScanState {
            cursor: ScanCursor {
                next_block: BlockNumber::from(2u32),
            },
            authenticated_parent: Some(saved_block.header().clone()),
        }
    );
    assert_eq!(
        attester.store.candidates().unwrap()[0].note(),
        &saved_note.public_note.unwrap()
    );

    // Reporting block 12 is not evidence of ten descendants after the burn in block 2.
    for bad_signature in [false, true] {
        let mut factory = BlockFactory::new();
        factory.push(Vec::new(), Vec::new());
        let burn = note(BurnNote::script(), NoteType::Public, 1, 32);
        factory.push(vec![burn.output], Vec::new());
        let consumed = factory.push(
            Vec::new(),
            vec![transaction(faucet_account_id(), &[burn.nullifier])],
        );
        let mut blocks = factory.blocks();
        if bad_signature {
            let (header, body, _) = factory.push(Vec::new(), Vec::new()).into_parts();
            blocks.push(SignedBlock::new_unchecked(
                header,
                body,
                BlockSignatures::new(Vec::new()).unwrap(),
            ));
        }
        let tempdir = tempfile::tempdir().unwrap();
        let config = write_config(&tempdir, 1, &blocks[0], 10);
        let (chain, _) = TestChain::new(blocks, scan_limits(12, 12));
        let mut attester = Attester::start(config, Box::new(chain), ready_circle())
            .await
            .unwrap();
        let error = attester
            .discover_burns()
            .await
            .expect_err("descendant must authenticate");
        if bad_signature {
            assert!(matches!(error, DiscoverError::ChainDiverged));
        } else {
            assert!(matches!(error, DiscoverError::Chain(_)));
        }
        assert_eq!(
            attester.store.scan_state().unwrap(),
            ScanState {
                cursor: ScanCursor {
                    next_block: 3u32.into()
                },
                authenticated_parent: Some(consumed.header().clone()),
            }
        );
        assert_eq!(
            attester.store.discovered_burns().unwrap()[0].note_id(),
            burn.id
        );
        assert!(attester
            .store
            .burns_ready_for_withdrawal(12u32.into(), 10)
            .unwrap()
            .is_empty());
    }

    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());
    factory.push(Vec::new(), Vec::new());
    factory.push(Vec::new(), Vec::new());
    factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, controls) = start(&tempdir, 1, factory.blocks(), scan_limits(0, 0)).await;
    let request_count = controls.requests.lock().unwrap().len();
    attester.discover_burns().await.unwrap();
    assert_eq!(controls.requests.lock().unwrap().len(), request_count);
    assert_eq!(
        attester.store.scan_state().unwrap(),
        ScanState {
            cursor: ScanCursor {
                next_block: BlockNumber::from(1u32),
            },
            authenticated_parent: None,
        }
    );

    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, controls) = start(&tempdir, 1, factory.blocks(), scan_limits(3, 3)).await;
    attester.discover_burns().await.unwrap();
    controls.requests.lock().unwrap().clear();
    *controls.scan_limits.lock().unwrap() = scan_limits(3, 0);
    attester.discover_burns().await.unwrap();
    assert!(controls.requests.lock().unwrap().is_empty());
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(4u32)
    );

    *controls.scan_limits.lock().unwrap() = scan_limits(2, 1);
    assert!(matches!(
        attester.discover_burns().await,
        Err(DiscoverError::ChainDiverged)
    ));
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(4u32)
    );
}

/// A note published again with the same id, before or after the faucet consumed it, is the same
/// note and is skipped instead of halting discovery.
#[tokio::test]
async fn repeated_note_is_skipped() {
    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());
    let burn = note(BurnNote::script(), NoteType::Public, 1, 40);
    factory.push(vec![burn.output.clone()], Vec::new());
    factory.push(vec![burn.output.clone()], Vec::new());
    factory.push(
        Vec::new(),
        vec![transaction(faucet_account_id(), &[burn.nullifier])],
    );
    factory.push(vec![burn.output], Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, _) = start(&tempdir, 1, factory.blocks(), scan_limits(4, 4)).await;

    attester.discover_burns().await.unwrap();

    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(5u32)
    );
    assert!(attester.store.candidates().unwrap().is_empty());
    assert_eq!(
        attester
            .store
            .discovered_burns()
            .unwrap()
            .iter()
            .map(DiscoveredBurn::note_id)
            .collect::<Vec<_>>(),
        [burn.id]
    );
}

/// Before any block is authenticated, a node still short of the anchor is not a divergence.
#[tokio::test]
async fn node_behind_the_anchor_waits_on_a_fresh_store() {
    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());
    factory.push(Vec::new(), Vec::new());
    let anchor = factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let config = write_config(&tempdir, 2, &anchor, 1);
    let (chain, controls) = TestChain::new(factory.blocks(), scan_limits(1, 1));
    let mut attester = Attester::start(config, Box::new(chain), ready_circle())
        .await
        .unwrap();

    attester.discover_burns().await.unwrap();

    assert_eq!(
        *controls.requests.lock().unwrap(),
        [BlockNumber::from(2u32)]
    );
    assert!(attester
        .store
        .scan_state()
        .unwrap()
        .authenticated_parent
        .is_none());
}

/// A token cancelled before the first cycle returns before any stage runs or any sleep starts.
#[tokio::test]
async fn run_stops_when_shutdown_is_set() {
    let mut factory = BlockFactory::new();
    factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, controls) = start(&tempdir, 1, factory.blocks(), scan_limits(0, 0)).await;

    let shutdown = CancellationToken::new();
    shutdown.cancel();
    attester.run(shutdown).await.unwrap();

    assert_eq!(*controls.scan_limit_requests.lock().unwrap(), 0);
    assert_eq!(*controls.requests.lock().unwrap(), [BlockNumber::GENESIS]);
}
