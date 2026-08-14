//! Executable snapshots for the xUSDC note-consumption cost table.

mod support;

use std::sync::Arc;

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::{AssetAmount, AssetId, FungibleAsset};
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Word};
use miden_testing::{Auth, MockChain};
use support::mint_transport::{
    administrator, bring_up, consume_note, honest_note, note_rng, payload_for,
};
use support::*;
use xusdc_encoding::note::costs::{
    XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES, XRESERVE_SET_MIN_BURN_SIZE_CONSUMPTION_CYCLES,
    XUSDC_BURN_CONSUMPTION_CYCLES, XUSDC_MINT_CONSUMPTION_CYCLES,
};
use xusdc_encoding::note::xreserve_admin::{XReserveSetAttesterNote, XReserveSetMinBurnSizeNote};
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::xreserve::encoding::{
    DepositIntentField, ForeignChainAddress, HookData, XReserveBurnItems,
};

const MAX_SUPPLY: u64 = 1_000_000_000_000;
const BURN_AMOUNT: u64 = 5_000;
const DRIFT_TOLERANCE_PERCENT: u64 = 5;
const VERIFICATION_BASE_FEE: u32 = 500;
const FEE_BALANCE: u64 = 1_000_000;

fn fee_faucet_id() -> AccountId {
    ACCOUNT_ID_FEE_FAUCET
        .try_into()
        .expect("the protocol test fee-faucet id is valid")
}

fn fee_funding_asset() -> Result<FungibleAsset> {
    Ok(FungibleAsset::new(fee_faucet_id(), FEE_BALANCE)?)
}

fn total_cycles(executed: &ExecutedTransaction) -> Result<u32> {
    u32::try_from(executed.measurements().total_cycles())
        .context("the measured cycle count must fit in u32")
}

fn assert_cost(label: &str, measured: u32, committed: u32) {
    let measured_scaled = u64::from(measured) * 100;
    let committed = u64::from(committed);
    assert!(
        measured_scaled <= committed * (100 + DRIFT_TOLERANCE_PERCENT)
            && measured_scaled >= committed * (100 - DRIFT_TOLERANCE_PERCENT),
        "cost table stale for {label}: measured {measured} cycles vs checked-in {committed} \
         (more than {DRIFT_TOLERANCE_PERCENT}% apart)",
    );
}

fn with_hook_data(mut payload: Vec<u8>, hook_data_len: usize) -> Vec<u8> {
    let len_offset = DepositIntentField::HookDataLen.offset();
    payload.truncate(DepositIntentField::HookData.offset());
    payload[len_offset..len_offset + 4].copy_from_slice(
        &u32::try_from(hook_data_len)
            .expect("the hook-data limit fits u32")
            .to_be_bytes(),
    );
    payload.extend((0..hook_data_len).map(|index| index as u8));
    payload
}

fn priced_fixture_with(
    extra_notes: impl FnOnce(AccountId, AccountId) -> Vec<miden_protocol::note::Note>,
) -> Result<ProductionFaucet> {
    let mut builder = MockChain::builder()
        .fee_faucet_id(fee_faucet_id())
        .verification_base_fee(VERIFICATION_BASE_FEE);
    let recipient = builder.add_existing_wallet(Auth::IncrNonce)?;
    let producer = add_emitting_wallet(&mut builder, Auth::IncrNonce, [])?;
    let components = production_builder(MAX_SUPPLY, 0, TEST_DOMAIN)?.build_components()?;
    let faucet = build_network_faucet_account_with_fee_policy_and_assets(
        components,
        fee_faucet_id(),
        test_fee_policy(),
        [fee_funding_asset()?.into()],
    )?;
    builder.add_account(faucet.clone())?;

    let payload = payload_for(
        recipient.id(),
        faucet.id(),
        support::mint_transport::MINT_AMOUNT,
        0,
    );
    let mut notes = vec![XReserveSetAttesterNote::create(
        administrator(),
        faucet.id(),
        gen_attester(1, &payload).commitment,
        1,
        &mut note_rng(2_000),
    )?];
    notes.extend(extra_notes(recipient.id(), faucet.id()));
    for note in &notes {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    Ok(ProductionFaucet {
        mock_chain: builder.build()?,
        faucet_id: faucet.id(),
        recipient_id: recipient.id(),
        producer_id: producer.id(),
        seeded_notes: notes,
    })
}

fn minted_asset_witness(faucet: &Account) -> AdviceInputs {
    let witness = faucet.vault().open(AssetId::new_fungible(faucet.id()));
    let mut advice = AdviceInputs::default();
    advice.store.extend(witness.authenticated_nodes());
    let smt_proof = SmtProof::from(witness);
    advice.map.extend([(
        smt_proof.leaf().hash(),
        smt_proof.leaf().to_elements().collect::<Arc<[Felt]>>(),
    )]);
    advice
}

async fn mint_cycles(hook_data_len: usize, nonce_variant: u8) -> Result<u32> {
    let mut faucet = priced_fixture_with(|_, _| vec![])?;
    bring_up(&mut faucet, 1).await?;
    let payload = with_hook_data(
        payload_for(
            faucet.recipient_id,
            faucet.faucet_id,
            support::mint_transport::MINT_AMOUNT,
            nonce_variant,
        ),
        hook_data_len,
    );
    let note = honest_note(&faucet, &payload, u64::from(nonce_variant) + 1_000)?;
    emit_note_with_attachments(&mut faucet.mock_chain, faucet.producer_id, &note).await?;
    let faucet_account = faucet.mock_chain.committed_account(faucet.faucet_id)?;
    let executed = faucet
        .mock_chain
        .build_transaction(faucet.faucet_id)
        .authenticated_input_note(note.id())
        .extend_advice_inputs(minted_asset_witness(faucet_account))
        .build()?
        .execute()
        .await
        .map_err(|err| anyhow::anyhow!("the benchmark mint must execute: {err}"))?;
    total_cycles(&executed)
}

async fn set_attester_cycles(enabled: u8) -> Result<u32> {
    let mut faucet = priced_fixture_with(|_, faucet_id| {
        vec![XReserveSetAttesterNote::create(
            administrator(),
            faucet_id,
            Word::from([21u32, 22, 23, 24]),
            enabled,
            &mut note_rng(2_001 + u64::from(enabled)),
        )
        .expect("building the benchmark set-attester note")]
    })?;
    bring_up(&mut faucet, 1).await?;
    let note = faucet.seeded_notes[1].clone();
    let executed = consume_note(&faucet.mock_chain, faucet.faucet_id, note.id())
        .await
        .map_err(|err| anyhow::anyhow!("the benchmark set-attester note must execute: {err}"))?;
    total_cycles(&executed)
}

async fn set_min_burn_size_cycles() -> Result<u32> {
    let faucet = priced_fixture_with(|_, faucet_id| {
        vec![XReserveSetMinBurnSizeNote::create(
            administrator(),
            faucet_id,
            BURN_AMOUNT,
            &mut note_rng(2_100),
        )
        .expect("building the benchmark minimum-burn-size note")]
    })?;
    let note = faucet.seeded_notes[1].clone();
    let executed = consume_note(&faucet.mock_chain, faucet.faucet_id, note.id())
        .await
        .map_err(|err| {
            anyhow::anyhow!("the benchmark minimum-burn-size note must execute: {err}")
        })?;
    total_cycles(&executed)
}

async fn burn_cycles() -> Result<u32> {
    let mut builder = MockChain::builder()
        .fee_faucet_id(fee_faucet_id())
        .verification_base_fee(VERIFICATION_BASE_FEE);
    let components =
        production_builder(MAX_SUPPLY, BURN_AMOUNT, TEST_DOMAIN)?.build_components()?;
    let faucet = build_network_faucet_account_with_fee_policy_and_assets(
        components,
        fee_faucet_id(),
        test_fee_policy(),
        [fee_funding_asset()?.into()],
    )?;
    builder.add_account(faucet.clone())?;
    let asset = FungibleAsset::new(faucet.id(), BURN_AMOUNT)?;
    let user = add_emitting_wallet(&mut builder, miden_testing::Auth::IncrNonce, [asset.into()])?;
    let note = XReserveBurnNote::create(
        user.id(),
        faucet.id(),
        XReserveBurnItems {
            amount: AssetAmount::new(BURN_AMOUNT)?,
            dest_domain: 9,
            dest_recipient: ForeignChainAddress::new([0xAB; 32]),
            salt: [0xCD; 32],
        },
        builder.rng_mut(),
    )?;
    let mut chain = builder.build()?;
    let executed = run_burn_consume(&mut chain, &note, &asset, faucet.id(), user.id())
        .await
        .map_err(|err| anyhow::anyhow!("the benchmark burn must execute: {err}"))?;
    total_cycles(&executed)
}

#[tokio::test]
async fn checked_in_costs_match_benchmarked_transactions() -> Result<()> {
    let mint_empty = mint_cycles(0, 1).await?;
    let mint_max_hook_data = mint_cycles(HookData::MAX_LEN, 2).await?;
    let mint = mint_empty.max(mint_max_hook_data);
    let burn = burn_cycles().await?;
    let set_attester_enabled = set_attester_cycles(1).await?;
    let set_attester_disabled = set_attester_cycles(0).await?;
    let set_attester = set_attester_enabled.max(set_attester_disabled);
    let set_min_burn_size = set_min_burn_size_cycles().await?;

    eprintln!(
        "xUSDC note costs: mint empty={mint_empty}, mint max-hook-data={mint_max_hook_data}, \
         burn={burn}, set-attester enabled={set_attester_enabled}, set-attester \
         disabled={set_attester_disabled}, set-min-burn-size={set_min_burn_size}",
    );

    assert_cost("xUSDC MINT", mint, XUSDC_MINT_CONSUMPTION_CYCLES);
    assert_cost("xUSDC BURN", burn, XUSDC_BURN_CONSUMPTION_CYCLES);
    assert_cost(
        "xUSDC set-attester",
        set_attester,
        XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES,
    );
    assert_cost(
        "xUSDC set-minimum-burn-size",
        set_min_burn_size,
        XRESERVE_SET_MIN_BURN_SIZE_CONSUMPTION_CYCLES,
    );
    Ok(())
}
