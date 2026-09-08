//! Authenticated sequential discovery and loop-boundary tests.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockBody, BlockHeader, BlockNumber, BlockSignatures, ProvenBlock};
use miden_protocol::note::NoteType;
use miden_protocol::transaction::OrderedTransactionHeaders;
use miden_protocol::{Word, MAX_BATCHES_PER_BLOCK, MAX_OUTPUT_NOTES_PER_BATCH};
use miden_standards::note::{BurnNote, P2idNote};

use crate::attester::{Attester, DiscoverError, StartError};
use crate::chain::ScanLimits;
use crate::config::Config;
use crate::store::{
    BurnCandidate, DiscoveredBurn, ScanCursor, ScanState, Store, StoreError, TrustedAnchor,
};

use super::support::{
    faucet_account_id, note, ready_circle, replace_note_batches, scan_limits, transaction,
    BlockFactory, ChainControls, TestChain,
};

const OTHER_ACCOUNT_ID: &str = "0x9b405fd9fe431bd1135a292de098cb";
const SIGNING_KEY_ONE: &str =
    "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SIGNING_KEY_TWO: &str =
    "0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

fn write_config(
    tempdir: &tempfile::TempDir,
    deployment_block: u32,
    anchor: &ProvenBlock,
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

async fn start(
    tempdir: &tempfile::TempDir,
    deployment_block: u32,
    blocks: Vec<ProvenBlock>,
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

/// Scans every height through the conservative finality bound, selects public notes by the stock
/// burn script root, and promotes only faucet transactions that consume known candidates.
#[tokio::test]
async fn burns_are_discovered_safely() {
    let mut factory = BlockFactory::new(faucet_account_id());
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
    factory.push(
        vec![
            burn_one.output.clone(),
            burn_two.output.clone(),
            private_burn.output,
            spoofed_tag.output,
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

    let unconsumed = note(BurnNote::script(), NoteType::Public, 10, 6);
    let erased = note(BurnNote::script(), NoteType::Public, 11, 7);
    let consuming_tx = transaction(
        faucet_account_id(),
        &[burn_one.nullifier, burn_two.nullifier, erased.nullifier],
    );
    let consuming_tx_id = consuming_tx.id();
    factory.push(vec![unconsumed.output], vec![consuming_tx]);
    factory.push(
        Vec::new(),
        vec![transaction(faucet_account_id(), &[unconsumed.nullifier])],
    );

    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, controls) = start(&tempdir, 2, factory.blocks(), scan_limits(6, 4)).await;
    attester.discover_burns().await.unwrap();

    assert_eq!(
        *controls.requests.lock().unwrap(),
        (0u32..=4).map(BlockNumber::from).collect::<Vec<_>>()
    );
    assert_eq!(
        *controls.scan_limit_requests.lock().unwrap(),
        [BlockNumber::GENESIS]
    );
    let state = attester.store.scan_state().unwrap();
    assert_eq!(state.cursor.next_block, BlockNumber::from(5u32));
    assert_eq!(
        state.authenticated_parent.unwrap().block_num(),
        BlockNumber::from(4u32)
    );

    let candidates = attester.store.candidates().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].note_id(), unconsumed.id);
    assert_eq!(candidates[0].note, unconsumed.public_note.clone().unwrap());

    let mut burns = attester.store.discovered_burns().unwrap();
    burns.sort_by_key(DiscoveredBurn::note_id);
    assert_eq!(burns.len(), 2);
    assert_eq!(burns[0].burn_tx_id, consuming_tx_id);
    assert_eq!(burns[1].burn_tx_id, consuming_tx_id);
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
    assert_eq!(burns[0].note.id(), burns[0].note_id());
    assert_eq!(burns[1].note.id(), burns[1].note_id());

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
        [BlockNumber::GENESIS, BlockNumber::from(5u32)]
    );
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(6u32)
    );
    assert!(attester.store.candidates().unwrap().is_empty());
    let burns = attester.store.discovered_burns().unwrap();
    assert_eq!(burns.len(), 3);
    assert!(burns.iter().any(|burn| burn.note_id() == unconsumed.id));

    let burn_at_anchor = note(BurnNote::script(), NoteType::Public, 12, 8);
    let mut factory = BlockFactory::new(faucet_account_id());
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
}

/// Proves candidate insertion, burn promotion, cursor movement, and authenticated-parent updates
/// share one transaction; skipped blocks, wrong parents, and repeated evidence change nothing.
#[test]
fn burns_and_scan_position_are_saved_together() {
    let mut factory = BlockFactory::new(faucet_account_id());
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
    let candidate = BurnCandidate {
        note: burn_note.public_note.clone().unwrap(),
        creation_block: BlockNumber::GENESIS,
    };
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
    assert_eq!(
        store.save_scan_progress(
            &[],
            &[],
            &ScanState {
                cursor: after_anchor.cursor,
                authenticated_parent: None,
            }
        ),
        Err(StoreError::Invalid),
        "moving the cursor requires the authenticated block header"
    );
    // Even the first saved block must not skip a height. No stored parent can mask this check.
    assert_eq!(
        store.save_scan_progress(std::slice::from_ref(&candidate), &[], &after_child),
        Err(StoreError::Conflict)
    );
    assert_eq!(store.scan_state(), Ok(initial_state));
    assert!(store.candidates().unwrap().is_empty());
    assert!(store.discovered_burns().unwrap().is_empty());
    store
        .save_scan_progress(std::slice::from_ref(&candidate), &[], &after_anchor)
        .unwrap();
    for next_state in [&after_anchor, &after_child] {
        assert_eq!(
            store.save_scan_progress(std::slice::from_ref(&candidate), &[], next_state),
            Err(StoreError::Conflict)
        );
        assert_eq!(store.scan_state(), Ok(after_anchor.clone()));
        assert_eq!(store.candidates(), Ok(vec![candidate.clone()]));
        assert!(store.discovered_burns().unwrap().is_empty());
    }

    let second_note = note(BurnNote::script(), NoteType::Public, 2, 21);
    let second_candidate = BurnCandidate {
        note: second_note.public_note.unwrap(),
        creation_block: BlockNumber::from(1u32),
    };
    let tx = transaction(faucet_account_id(), &[candidate.nullifier()]);
    let burn = DiscoveredBurn {
        note: candidate.note.clone(),
        creation_block: candidate.creation_block,
        consumption_block: BlockNumber::from(1u32),
        burn_tx_id: tx.id(),
    };
    let header = child.header();
    let wrong_parent = ScanState {
        authenticated_parent: Some(BlockHeader::new(
            header.version(),
            Word::empty(),
            header.block_num(),
            header.chain_commitment(),
            header.account_root(),
            header.nullifier_root(),
            header.note_root(),
            header.tx_commitment(),
            header.tx_kernel_commitment(),
            header.validator_keys().clone(),
            header.fee_parameters().clone(),
            header.timestamp(),
        )),
        ..after_child.clone()
    };
    // The height is correct, but the new header must also link to the saved block.
    assert_eq!(
        store.save_scan_progress(
            std::slice::from_ref(&second_candidate),
            std::slice::from_ref(&burn),
            &wrong_parent,
        ),
        Err(StoreError::Conflict)
    );
    assert_eq!(store.scan_state(), Ok(after_anchor.clone()));
    assert_eq!(store.candidates(), Ok(vec![candidate.clone()]));
    assert!(store.discovered_burns().unwrap().is_empty());

    // Both heights pass the temporal bounds, but promotion must retain the candidate's height.
    let mismatched_promotion = DiscoveredBurn {
        note: second_candidate.note.clone(),
        burn_tx_id: transaction(faucet_account_id(), &[second_candidate.nullifier()]).id(),
        ..burn.clone()
    };
    assert_eq!(
        store.save_scan_progress(
            std::slice::from_ref(&second_candidate),
            std::slice::from_ref(&mismatched_promotion),
            &after_child,
        ),
        Err(StoreError::Conflict)
    );
    assert_eq!(store.scan_state(), Ok(after_anchor.clone()));
    assert_eq!(store.candidates(), Ok(vec![candidate.clone()]));
    assert!(store.discovered_burns().unwrap().is_empty());

    store
        .save_scan_progress(&[], std::slice::from_ref(&burn), &after_child)
        .unwrap();
    assert_eq!(
        store.save_scan_progress(
            std::slice::from_ref(&candidate),
            std::slice::from_ref(&burn),
            &after_child,
        ),
        Err(StoreError::Conflict)
    );
    assert_eq!(store.scan_state(), Ok(after_child.clone()));
    assert!(store.candidates().unwrap().is_empty());
    assert_eq!(store.discovered_burns(), Ok(vec![burn.clone()]));
    assert_eq!(
        store.save_scan_progress(&[], &[], &after_anchor),
        Err(StoreError::Conflict)
    );

    let conflicting_burn = DiscoveredBurn {
        burn_tx_id: transaction(
            faucet_account_id(),
            &[candidate.nullifier(), second_candidate.nullifier()],
        )
        .id(),
        ..burn.clone()
    };
    let after_grandchild = ScanState {
        cursor: ScanCursor {
            next_block: BlockNumber::from(3u32),
        },
        authenticated_parent: Some(grandchild.header().clone()),
    };
    assert_eq!(
        store.save_scan_progress(std::slice::from_ref(&candidate), &[], &after_grandchild),
        Err(StoreError::Conflict)
    );
    assert_eq!(store.scan_state(), Ok(after_child.clone()));
    assert!(store.candidates().unwrap().is_empty());
    assert_eq!(store.discovered_burns(), Ok(vec![burn.clone()]));
    for duplicate in [&burn, &conflicting_burn] {
        assert_eq!(
            store.save_scan_progress(
                std::slice::from_ref(&second_candidate),
                std::slice::from_ref(duplicate),
                &after_grandchild,
            ),
            Err(StoreError::Conflict)
        );
        assert_eq!(store.scan_state(), Ok(after_child.clone()));
        assert!(store.candidates().unwrap().is_empty());
        assert_eq!(store.discovered_burns(), Ok(vec![burn.clone()]));
    }
    let invalid_parent = ScanState {
        cursor: ScanCursor {
            next_block: BlockNumber::from(3u32),
        },
        authenticated_parent: after_child.authenticated_parent.clone(),
    };
    assert_eq!(
        store.save_scan_progress(&[], &[], &invalid_parent),
        Err(StoreError::Invalid)
    );
    assert_eq!(store.scan_state(), Ok(after_child.clone()));

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
    assert_eq!(store.discovered_burns(), Ok(vec![burn]));
    drop(store);

    let changed_anchor = TrustedAnchor {
        commitment: Word::empty(),
        ..trusted_anchor
    };
    assert!(matches!(
        Store::open_or_create(
            &path,
            faucet_account_id(),
            ScanCursor {
                next_block: BlockNumber::GENESIS,
            },
            changed_anchor,
        ),
        Err(StoreError::AnchorChanged)
    ));

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE burns SET note = x'00'", [])
        .unwrap();
    drop(connection);
    assert!(matches!(
        Store::open_or_create(
            &path,
            faucet_account_id(),
            ScanCursor {
                next_block: BlockNumber::GENESIS,
            },
            trusted_anchor,
        ),
        Err(StoreError::Invalid)
    ));

    let predeployment_path = tempdir.path().join("predeployment.sqlite3");
    let mut store = Store::open_or_create(
        &predeployment_path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::from(2u32),
        },
        TrustedAnchor {
            block_num: child.header().block_num(),
            commitment: child.header().commitment(),
        },
    )
    .unwrap();
    assert_eq!(
        store.save_scan_progress(
            &[BurnCandidate {
                creation_block: BlockNumber::GENESIS,
                ..candidate.clone()
            }],
            &[],
            &ScanState {
                cursor: ScanCursor {
                    next_block: BlockNumber::from(3u32),
                },
                authenticated_parent: Some(
                    BlockHeader::mock(2u32, None, None, &[], Word::empty(),)
                ),
            },
        ),
        Err(StoreError::Conflict)
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

    let mut configured_factory = BlockFactory::new(faucet_account_id());
    let configured_anchor = configured_factory.push(Vec::new(), Vec::new());
    let mut served_factory = BlockFactory::new(faucet_account_id());
    let served_anchor = served_factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let config = write_config(&tempdir, 0, &configured_anchor, 1);
    let (chain, _) = TestChain::new(vec![served_anchor], scan_limits(1, 0));
    assert!(matches!(
        Attester::start(config, Box::new(chain), ready_circle()).await,
        Err(StartError::TrustedAnchorInvalid)
    ));

    let (header, _, signatures, proof) = configured_anchor.clone().into_parts();
    let injected = note(BurnNote::script(), NoteType::Public, 1, 29);
    let tampered_body = BlockBody::new_unchecked(
        Vec::new(),
        vec![vec![(0, injected.output)]],
        Vec::new(),
        OrderedTransactionHeaders::new_unchecked(Vec::new()),
    );
    let tampered_anchor = ProvenBlock::new_unchecked(header, tampered_body, signatures, proof);
    let tempdir = tempfile::tempdir().unwrap();
    let config = write_config(&tempdir, 0, &configured_anchor, 1);
    let (chain, _) = TestChain::new(vec![tampered_anchor], scan_limits(1, 0));
    assert!(matches!(
        Attester::start(config, Box::new(chain), ready_circle()).await,
        Err(StartError::TrustedAnchorInvalid)
    ));

    let first = note(BurnNote::script(), NoteType::Public, 1, 40);
    let second = note(BurnNote::script(), NoteType::Public, 1, 41);
    let malformed_batches = [
        (
            "too many batches",
            vec![Vec::new(); MAX_BATCHES_PER_BLOCK + 1],
        ),
        (
            "note position outside batch",
            vec![vec![(MAX_OUTPUT_NOTES_PER_BATCH, first.output.clone())]],
        ),
        (
            "duplicate position",
            vec![vec![(0, first.output.clone()), (0, second.output.clone())]],
        ),
    ];
    for (name, batches) in malformed_batches {
        let mut factory = BlockFactory::new(faucet_account_id());
        let anchor = factory.push(Vec::new(), Vec::new());
        let child = factory.push(Vec::new(), Vec::new());
        let tempdir = tempfile::tempdir().unwrap();
        let config = write_config(&tempdir, 1, &anchor, 1);
        let malformed_anchor = replace_note_batches(anchor.clone(), batches.clone());
        let (chain, _) = TestChain::new(vec![malformed_anchor], scan_limits(2, 1));
        assert!(
            matches!(
                Attester::start(config, Box::new(chain), ready_circle()).await,
                Err(StartError::TrustedAnchorInvalid)
            ),
            "{name}: startup must return an error, not panic"
        );
        assert!(!tempdir.path().join("state.sqlite3").exists(), "{name}");

        let malformed_child = replace_note_batches(child, batches);
        let (mut attester, _) = start(
            &tempdir,
            1,
            vec![anchor, malformed_child],
            scan_limits(2, 1),
        )
        .await;
        assert!(
            matches!(
                attester.discover_burns().await,
                Err(DiscoverError::ChainDiverged)
            ),
            "{name}"
        );
        assert_eq!(
            attester.store.scan_state().unwrap().cursor.next_block,
            BlockNumber::from(1u32),
            "{name}"
        );
        assert!(attester.store.candidates().unwrap().is_empty(), "{name}");
    }

    // Maximum legal positions, unsorted entries, and index 0 in separate batches are all valid.
    let mut batches = vec![Vec::new(); MAX_BATCHES_PER_BLOCK];
    batches[0] = vec![
        (MAX_OUTPUT_NOTES_PER_BATCH - 1, first.output),
        (0, second.output),
    ];
    batches[MAX_BATCHES_PER_BLOCK - 1] =
        vec![(0, note(BurnNote::script(), NoteType::Public, 1, 42).output)];
    let mut factory = BlockFactory::new(faucet_account_id());
    factory.push_note_batches(batches.clone(), Vec::new());
    factory.push_note_batches(batches, Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, _) = start(&tempdir, 1, factory.blocks(), scan_limits(2, 1)).await;
    attester.discover_burns().await.unwrap();
    assert_eq!(attester.store.candidates().unwrap().len(), 3);

    let cases = [
        ("missing", 0u8, 1u32, Expected::ReadFailure),
        ("skipped", 1u8, 1u32, Expected::Divergence),
        ("bad body", 2u8, 1u32, Expected::Divergence),
        ("bad signature", 3u8, 1u32, Expected::Divergence),
        ("bad bootstrap body", 4u8, 2u32, Expected::Divergence),
    ];
    for (name, mutation, deployment_block, expected) in cases {
        let mut factory = BlockFactory::new(faucet_account_id());
        factory.push(Vec::new(), Vec::new());
        factory.push(Vec::new(), Vec::new());
        factory.push(Vec::new(), Vec::new());
        let mut blocks = factory.blocks();
        let mut missing = false;
        match mutation {
            0 => missing = true,
            1 => blocks[1] = blocks[2].clone(),
            2 | 4 => {
                let (header, _, signatures, proof) = blocks[1].clone().into_parts();
                let injected = note(BurnNote::script(), NoteType::Public, 1, 30);
                let body = BlockBody::new_unchecked(
                    Vec::new(),
                    vec![vec![(0, injected.output)]],
                    Vec::new(),
                    OrderedTransactionHeaders::new_unchecked(Vec::new()),
                );
                blocks[1] = ProvenBlock::new_unchecked(header, body, signatures, proof);
            }
            3 => {
                let (header, body, _, proof) = blocks[1].clone().into_parts();
                blocks[1] = ProvenBlock::new_unchecked(
                    header,
                    body,
                    BlockSignatures::new(Vec::new()).unwrap(),
                    proof,
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

    let mut factory = BlockFactory::new(faucet_account_id());
    factory.push(Vec::new(), Vec::new());
    let saved_note = note(BurnNote::script(), NoteType::Public, 1, 31);
    let saved_block = factory.push(vec![saved_note.output.clone()], Vec::new());
    factory.push(Vec::new(), Vec::new());
    let mut blocks = factory.blocks();
    let (header, body, _, proof) = blocks[2].clone().into_parts();
    blocks[2] = ProvenBlock::new_unchecked(
        header,
        body,
        BlockSignatures::new(Vec::new()).unwrap(),
        proof,
    );
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
        attester.store.candidates().unwrap()[0].note,
        saved_note.public_note.unwrap()
    );

    let mut factory = BlockFactory::new(faucet_account_id());
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
    *controls.scan_limits.lock().unwrap() = scan_limits(3, 2);
    attester.discover_burns().await.unwrap();
    assert!(controls.requests.lock().unwrap().is_empty());
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(3u32)
    );

    *controls.scan_limits.lock().unwrap() = scan_limits(2, 1);
    assert!(matches!(
        attester.discover_burns().await,
        Err(DiscoverError::ChainDiverged)
    ));
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(3u32)
    );
}

/// A pre-set shutdown flag returns before the first cycle, so no stage runs and no sleep occurs.
#[tokio::test]
async fn run_stops_when_shutdown_is_set() {
    let mut factory = BlockFactory::new(faucet_account_id());
    factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let (mut attester, controls) = start(&tempdir, 1, factory.blocks(), scan_limits(0, 0)).await;

    attester.run(Arc::new(AtomicBool::new(true))).await.unwrap();

    assert!(controls.scan_limit_requests.lock().unwrap().is_empty());
    assert_eq!(*controls.requests.lock().unwrap(), [BlockNumber::GENESIS]);
}
