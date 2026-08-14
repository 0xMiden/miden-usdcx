//! USDCx fee-policy composition and administration.
//!
//! Deployment supplies a fee faucet and `BasicConstantFeePolicy`. The builder installs the fee
//! manager and `ConstantFeeManager`, and the `ADMIN` role can reprice scheduled note roots through
//! `ConstantFeePolicyConfigNote`.

mod support;

use std::collections::BTreeSet;

use anyhow::Result;
use miden_protocol::account::{
    Account, AccountComponent, AccountId, AccountType, StorageMapKey, StorageSlotContent,
};
use miden_protocol::asset::{AssetAmount, AssetId, FungibleAsset};
use miden_protocol::block::FeeParameters;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::SponsorshipPolicy;
use miden_standards::account::fees::{
    BasicConstantFeePolicy, ConstantFeeManager, FeePolicyManager,
};
use miden_standards::errors::standards::ERR_CONSTANT_FEE_POLICY_CONFIG_ACCOUNT_MISMATCH;
use miden_standards::note::{
    ConstantFeePolicyConfigNote, FeeSponsorshipNote, MintNote, NetworkAccountConfigNote,
};
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::NetworkNotePricer;
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveAdminAuthority, XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};
use xusdc_encoding::xreserve::encoding::EthBytes32;

const MAX_SUPPLY: u64 = 1_000_000;
const NEW_FEE: u64 = 73;
const VERIFICATION_BASE_FEE: u32 = 500;

fn fee_faucet_id() -> AccountId {
    ACCOUNT_ID_FEE_FAUCET
        .try_into()
        .expect("the protocol test fee-faucet id is valid")
}

fn fee_entry(amount: u64) -> Word {
    Word::from([
        Felt::new(amount).expect("the test fee fits in a felt"),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ONE,
    ])
}

fn note_pricer() -> NetworkNotePricer {
    NetworkNotePricer::builder()
        .fee_parameters(FeeParameters::new(fee_faucet_id(), VERIFICATION_BASE_FEE))
        .build()
}

/// Returns a complete fee policy for fee-execution tests.
fn priced_fee_policy() -> Result<BasicConstantFeePolicy> {
    let fee = note_pricer().price(ConstantFeePolicyConfigNote::script_root())?;
    assert!(
        fee.as_u64() > 0,
        "the verification base fee must produce a note price"
    );
    Ok(BasicConstantFeePolicy::new().with_fees(
        XReserveStablecoinBuilder::allowed_note_scripts()
            .into_iter()
            .map(|root| (root, fee)),
    ))
}

fn build_with_fee_policy(
    policy: BasicConstantFeePolicy,
) -> Result<XReserveStablecoinBuilder, XReserveStablecoinBuilderError> {
    XReserveStablecoinBuilder::new(
        AssetAmount::new(MAX_SUPPLY).expect("the test max supply is valid"),
        AssetAmount::ZERO,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
        fee_faucet_id(),
        policy,
        TEST_DOMAIN,
        TEST_SOURCE_DOMAIN,
        EthBytes32::new(test_xreserve_contract()),
    )
}

fn scheduled_fee(account: &Account, note_root: NoteScriptRoot) -> Result<Word> {
    account
        .storage()
        .get_map_item(
            BasicConstantFeePolicy::fee_schedule_slot_name(),
            StorageMapKey::new(note_root.as_word()),
        )
        .map_err(|err| anyhow::anyhow!("reading the fee schedule: {err}"))
}

fn repricing_note(
    sender: AccountId,
    target: AccountId,
    fee_issuer: AccountId,
    note_root: NoteScriptRoot,
    amount: u64,
    serial_seed: u32,
) -> Result<Note> {
    let note = ConstantFeePolicyConfigNote::builder()
        .sender(sender)
        .target(target)
        .note_script_root(note_root)
        .fee_asset(FungibleAsset::new(fee_issuer, amount)?)
        .serial_number(Word::from([serial_seed, 0, 0, 0]))
        .build()?;
    Ok(Note::from(note))
}

fn priced_components(policy: BasicConstantFeePolicy) -> Result<Vec<AccountComponent>> {
    Ok(build_with_fee_policy(policy)?.build_components()?)
}

struct SponsoredConfigFixture {
    mock_chain: MockChain,
    faucet_id: AccountId,
    feature_note: Note,
    sponsorship_note: Note,
    deployed_fee: AssetAmount,
}

fn assert_mint_fee_unchanged(fixture: &SponsoredConfigFixture) -> Result<()> {
    let account = fixture.mock_chain.committed_account(fixture.faucet_id)?;
    assert_eq!(
        scheduled_fee(account, MintNote::script_root())?,
        fee_entry(fixture.deployed_fee.as_u64()),
        "a rejected config note must leave the schedule unchanged",
    );
    Ok(())
}

fn setup_sponsored_config_note(
    build_note: impl FnOnce(AccountId) -> Result<Note>,
) -> Result<SponsoredConfigFixture> {
    let policy = priced_fee_policy()?;
    let deployed_fee = *policy
        .fee_schedule()
        .get(&ConstantFeePolicyConfigNote::script_root())
        .expect("the priced fixture schedules the config note");
    let components = priced_components(policy.clone())?;
    let account =
        build_network_faucet_account_with_fee_policy(components, fee_faucet_id(), policy)?;
    let mut builder = MockChain::builder()
        .fee_faucet_id(fee_faucet_id())
        .verification_base_fee(VERIFICATION_BASE_FEE);
    builder.add_account(account.clone())?;
    let feature_note = build_note(account.id())?;
    let sponsorship_note: Note = FeeSponsorshipNote::builder()
        .sender(feature_note.metadata().sender())
        .target_account(account.id())
        .feature_note_id(feature_note.id())
        .asset(FungibleAsset::new(fee_faucet_id(), deployed_fee.as_u64())?)
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(feature_note.clone()));
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    Ok(SponsoredConfigFixture {
        mock_chain,
        faucet_id: account.id(),
        feature_note,
        sponsorship_note,
        deployed_fee,
    })
}

#[test]
fn production_installs_one_mutable_basic_constant_fee_policy() -> Result<()> {
    let policy = priced_fee_policy()?;
    let config_note_fee = policy
        .fee_schedule()
        .get(&ConstantFeePolicyConfigNote::script_root())
        .expect("the config note is scheduled");
    assert!(
        config_note_fee.as_u64() > 0,
        "the config note must be priced",
    );
    assert!(
        policy
            .fee_schedule()
            .get(&FeeSponsorshipNote::script_root())
            .expect("the sponsorship note is scheduled")
            .as_u64()
            > 0,
        "the fee-enabled policy must price the sponsorship note",
    );
    assert_eq!(
        policy
            .fee_schedule()
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        XReserveStablecoinBuilder::allowed_note_scripts(),
        "the policy schedule and note allowlist must have exactly the same roots",
    );
    let components = priced_components(policy.clone())?;
    assert!(
        components
            .iter()
            .any(|component| component.has_procedure(ConstantFeeManager::set_note_fee_root())),
        "the production component set must install ConstantFeeManager::set_note_fee",
    );

    let auth_components: Vec<AccountComponent> =
        XReserveStablecoinBuilder::auth_component(fee_faucet_id(), policy)?
            .into_iter()
            .collect();
    assert_eq!(
        auth_components
            .iter()
            .filter(|component| component.has_procedure(BasicConstantFeePolicy::root()))
            .count(),
        1,
        "the auth composition must install exactly one BasicConstantFeePolicy component",
    );

    let manager_slots = auth_components[0].storage_slots();
    assert_eq!(
        manager_slots
            .iter()
            .find(|slot| slot.name() == FeePolicyManager::active_fee_policy_slot())
            .expect("the auth component carries the active fee-policy slot")
            .value(),
        BasicConstantFeePolicy::root().as_word(),
    );
    assert_eq!(
        manager_slots
            .iter()
            .find(|slot| slot.name() == FeePolicyManager::fee_asset_id_slot())
            .expect("the auth component carries the fee-asset slot")
            .value(),
        AssetId::new_fungible(fee_faucet_id()).to_word(),
        "the fee manager must store the explicitly supplied fee faucet's fungible asset id",
    );
    let allowed_slot = manager_slots
        .iter()
        .find(|slot| slot.name() == FeePolicyManager::allowed_fee_policies_slot())
        .expect("the auth component carries the allowed fee-policies slot");
    let StorageSlotContent::Map(allowed_policies) = allowed_slot.content() else {
        anyhow::bail!("the allowed fee-policies slot must be a map");
    };
    assert_eq!(
        allowed_policies.num_entries(),
        1,
        "the internally built manager must not register a reserved alternate policy",
    );
    assert_eq!(
        allowed_policies.get(&StorageMapKey::new(
            BasicConstantFeePolicy::root().as_word()
        )),
        Word::from([1u32, 0, 0, 0]),
    );

    assert!(
        !XReserveAdminAuthority::new()
            .procedure_roles()
            .contains_key(&ConstantFeeManager::set_note_fee_root()),
        "set_note_fee must be unmapped so Authority::RbacControlled falls back to ADMIN",
    );
    Ok(())
}

#[test]
fn builder_rejects_a_missing_fee_sponsorship_note() -> Result<()> {
    let missing_root = FeeSponsorshipNote::script_root();
    let policy = BasicConstantFeePolicy::new().with_fees(
        test_fee_policy()
            .fee_schedule()
            .iter()
            .filter(|(root, _fee)| **root != missing_root)
            .map(|(root, fee)| (*root, *fee)),
    );

    let result = build_with_fee_policy(policy);
    assert!(matches!(
        result,
        Err(XReserveStablecoinBuilderError::MissingFeeScheduleEntry(root))
            if root == missing_root
    ));
    Ok(())
}

#[test]
fn builder_rejects_a_non_allowlisted_schedule_entry() -> Result<()> {
    let unexpected_root = NetworkAccountConfigNote::script_root();
    assert!(
        !XReserveStablecoinBuilder::allowed_note_scripts().contains(&unexpected_root),
        "the general network-account config note must remain outside the allowlist",
    );
    let policy = test_fee_policy().with_fee(unexpected_root, AssetAmount::ZERO);

    let result = build_with_fee_policy(policy);
    assert!(matches!(
        result,
        Err(XReserveStablecoinBuilderError::UnexpectedFeeScheduleEntry(root))
            if root == unexpected_root
    ));
    Ok(())
}

#[test]
fn builder_rejects_a_free_constant_fee_config_note() -> Result<()> {
    let policy = test_fee_policy().with_fee(
        ConstantFeePolicyConfigNote::script_root(),
        AssetAmount::ZERO,
    );

    let result = build_with_fee_policy(policy);
    assert!(matches!(
        result,
        Err(XReserveStablecoinBuilderError::ZeroConstantFeePolicyConfigFee)
    ));
    Ok(())
}

#[tokio::test]
async fn administrator_reprices_a_priced_config_note_under_collected_fees_bound() -> Result<()> {
    let fixture = setup_sponsored_config_note(|faucet_id| {
        repricing_note(
            test_account_id(1),
            faucet_id,
            fee_faucet_id(),
            MintNote::script_root(),
            NEW_FEE,
            1,
        )
    })?;
    let account = fixture
        .mock_chain
        .committed_account(fixture.faucet_id)?
        .clone();
    assert_eq!(
        SponsorshipPolicy::try_from(account.storage())?,
        SponsorshipPolicy::AtMostCollectedFees,
    );
    assert_eq!(
        scheduled_fee(&account, ConstantFeePolicyConfigNote::script_root())?,
        fee_entry(fixture.deployed_fee.as_u64()),
        "the config note must retain its deployment fee",
    );

    let executed = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.feature_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await?;
    assert!(
        executed.compute_fee().as_u64() > 0,
        "the fee-enabled transaction must pay a fee"
    );
    let mut evolved = account;
    evolved.apply_patch(executed.account_patch())?;
    assert_eq!(
        scheduled_fee(&evolved, MintNote::script_root())?,
        fee_entry(NEW_FEE)
    );
    Ok(())
}

#[tokio::test]
async fn config_note_for_another_account_cannot_reprice_the_faucet() -> Result<()> {
    let other_account = AccountId::builder()
        .account_type(AccountType::Public)
        .build_with_seed([98; 32]);
    let fixture = setup_sponsored_config_note(|_faucet_id| {
        repricing_note(
            test_account_id(1),
            other_account,
            fee_faucet_id(),
            MintNote::script_root(),
            NEW_FEE,
            4,
        )
    })?;
    let result = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.feature_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_CONSTANT_FEE_POLICY_CONFIG_ACCOUNT_MISMATCH);
    assert_mint_fee_unchanged(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn non_administrator_cannot_reprice_the_fee_schedule() -> Result<()> {
    let fixture = setup_sponsored_config_note(|faucet_id| {
        repricing_note(
            test_account_id(99),
            faucet_id,
            fee_faucet_id(),
            MintNote::script_root(),
            NEW_FEE,
            2,
        )
    })?;
    let result = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.feature_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_mint_fee_unchanged(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn configured_fee_asset_cannot_be_changed_by_a_config_note() -> Result<()> {
    let fixture = setup_sponsored_config_note(|faucet_id| {
        repricing_note(
            test_account_id(1),
            faucet_id,
            test_faucet_id(249),
            MintNote::script_root(),
            NEW_FEE,
            3,
        )
    })?;
    let result = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.feature_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        MasmError::from_static_str(
            "provided fee asset ID does not match the fee manager's configured fee asset ID",
        )
    );
    assert_mint_fee_unchanged(&fixture)?;
    Ok(())
}
