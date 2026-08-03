//! The faucet derives its own identifier instead of reading a stored one — proven byte for byte
//! against the Rust encoding.
//!
//! The mint path compares every deposit intent's `remoteToken` against the faucet's identifier.
//! That identifier is the faucet's own account id in the frozen bytes32 packaging, and the faucet
//! now computes it on chain from `native_account::get_id` rather than reading a slot somebody had
//! to seed. The whole design rests on one claim: the MASM packaging is the same packaging
//! `account_id_to_bytes32` produces, for every account id, not just the one a fixture happened to
//! pick. If the two ever disagreed, the faucet would reject deposits Circle addressed to it, or —
//! worse — accept deposits addressed elsewhere.
//!
//! So every assertion here is made on the result of EXECUTING the MASM inside a transaction, with
//! the expected value computed on the Rust side and pushed across the `call` boundary. The
//! comparison itself happens in MASM (`assert_eqw`), so a disagreement traps and the test fails
//! with the driver's own error message; nothing is ever compared against itself.
//!
//! The spread is deliberate. One account id proves little about the byte swapping: an id whose
//! limbs happened to be palindromic, or whose prefix and suffix happened to coincide, would pass a
//! broken implementation. The suite therefore runs the derivation over a dozen freshly generated
//! ids spanning both account types, and then over the account id of a faucet composed by the
//! production builder — the id that actually ships.
//!
//! Two controls keep the assertions honest: the same driver run against a DIFFERENT account's
//! expected key must trap (so the driver really compares), and two accounts must derive different
//! keys (so the derivation really reads the id).

mod support;

use anyhow::{Context, Result};
use miden_processor::advice::AdviceInputs;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{Account, AccountComponent, AccountId, AccountType};
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{
    assert_transaction_executor_error, AccountState, Auth, MockChain, MockTransactionInput,
};
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, account_id_to_felts, bytes32_to_packed_felts, bytes32_to_storage_map_key,
};

/// How many generated account ids the parity spread covers, over and above the production faucet.
/// The floor this suite has to clear is eight; twelve costs little and spans both account types
/// evenly.
const SPREAD_SIZE: usize = 12;

/// Module path the standalone derive driver component is compiled under (the production leg reuses
/// the guarded fixture's own driver path).
const DERIVE_DRIVER_PATH: &str = "xusdc::test_fixtures::own_id_derive_driver";

const MAX_SUPPLY: u64 = 1_000_000;

/// The driver component: three `call`-invoked procedures that run the faucet's own-id derivation
/// and compare it against values the caller pushes across the `call` boundary.
///
/// The expected values arrive through the advice provider rather than being compiled into the
/// source, and that is not a style choice. An account id is a hash over the account's own code and
/// storage commitments, so a driver that embedded the expected id would change the very id it is
/// trying to predict. Taking them as transaction inputs keeps the component's code — and therefore
/// every account id derived from it — independent of what is being asserted.
///
/// Reading them from advice does not weaken anything: advice is host-controlled, so a hostile host
/// could only make an assertion FAIL, never pass a wrong derivation. Each procedure is stack-neutral
/// across its `call` window, the shape the production note scripts use.
const DERIVE_DRIVER_SRC: &str = r#"use xreserve::deposit_intent_parser
use miden::protocol::native_account

#! Asserts the native account id's two felts equal the pair the caller staged in advice.
#!
#! Inputs:  [pad(16)]
#! Outputs: [pad(16)]
#!
#! Advice stack: [expected_suffix, expected_prefix].
#!
#! Panics if:
#! - either felt differs from what the kernel reports for the native account.
#!
#! Invocation: call
@account_procedure
pub proc assert_native_id
    exec.native_account::get_id
    # => [suffix, prefix, pad(16)]

    adv_push
    # => [expected_suffix, suffix, prefix, pad(16)]

    assert_eq.err="canary: native account id suffix mismatch"
    # => [prefix, pad(16)]

    adv_push
    # => [expected_prefix, prefix, pad(16)]

    assert_eq.err="canary: native account id prefix mismatch"
    # => [pad(16)]
end

#! Asserts the on-chain bytes32 packaging of the native account id equals the caller's limbs.
#!
#! Inputs:  [pad(16)]
#! Outputs: [pad(16)]
#!
#! Advice stack: [B_UPPER_EXPECTED, B_LOWER_EXPECTED] — the packed-felt limbs of the Rust
#! `account_id_to_bytes32` form, upper word first, in the orientation `bytes32_to_key` consumes.
#!
#! Panics if:
#! - either limb word differs from the one the derivation produces.
#!
#! Invocation: call
@account_procedure
pub proc assert_own_id_bytes32
    exec.deposit_intent_parser::compute_own_id_bytes32
    # => [B_UPPER, B_LOWER, pad(16)]

    padw adv_loadw
    # => [B_UPPER_EXPECTED, B_UPPER, B_LOWER, pad(16)]

    assert_eqw.err="parity: own-id bytes32 upper limbs mismatch"
    # => [B_LOWER, pad(16)]

    padw adv_loadw
    # => [B_LOWER_EXPECTED, B_LOWER, pad(16)]

    assert_eqw.err="parity: own-id bytes32 lower limbs mismatch"
    # => [pad(16)]
end

#! Asserts the derived own-id identifier key equals the key the caller staged in advice.
#!
#! Inputs:  [pad(16)]
#! Outputs: [pad(16)]
#!
#! Advice stack: [KEY_EXPECTED] — the Rust
#! `bytes32_to_storage_map_key(account_id_to_bytes32(id))` Word.
#!
#! Panics if:
#! - the derived key differs from the expected key.
#!
#! Invocation: call
@account_procedure
pub proc assert_own_id_key
    exec.deposit_intent_parser::compute_own_identifier_key
    # => [KEY, pad(16)]

    padw adv_loadw
    # => [KEY_EXPECTED, KEY, pad(16)]

    assert_eqw.err="parity: derived own-id identifier key mismatch"
    # => [pad(16)]
end
"#;

// HARNESS
// ================================================================================================

/// One account carrying the xreserve library plus the derive driver, and the chain it lives on.
struct DeriveHarness {
    mock_chain: MockChain,
    account_id: AccountId,
    /// How the transaction names the account. Private accounts are not committed to the chain in
    /// full, so they have to be passed by value rather than by id.
    tx_input: MockTransactionInput,
    driver_code: AccountComponentCode,
    driver_path: &'static str,
}

/// Builds one account of the requested type carrying the xreserve library + the derive driver. The
/// account seed is random per call, so successive calls produce genuinely different account ids.
fn setup_derive_account(account_type: AccountType) -> Result<DeriveHarness> {
    let library = assemble_xreserve_lib()?;
    let driver_code = CodeBuilder::new()
        .with_dynamically_linked_package(&library)
        .context("linking the xreserve library into the derive driver")?
        .compile_component_code(DERIVE_DRIVER_PATH, DERIVE_DRIVER_SRC)
        .context("the derive driver component failed to compile")?;

    let xreserve_component = AccountComponent::new(
        library,
        vec![],
        AccountComponentMetadata::new("xusdc-own-id-derive-harness"),
    )
    .context("binding the xreserve library as a component")?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-own-id-derive-driver"),
    )
    .context("binding the derive driver component")?;

    let account_builder = Account::builder(rand::random())
        .account_type(account_type)
        .with_component(xreserve_component)
        .with_component(driver_component);

    let mut builder = MockChain::builder();
    let account = builder
        .add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
        .context("adding the derive harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(DeriveHarness {
        mock_chain,
        account_id: account.id(),
        tx_input: MockTransactionInput::Account(account),
        driver_code,
        driver_path: DERIVE_DRIVER_PATH,
    })
}

/// The production-composed faucet, carrying the same derive driver as its fixture driver so the
/// derivation can be executed inside the real component set.
fn setup_production_derive_faucet() -> Result<DeriveHarness> {
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        MAX_SUPPLY,
        0,
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        Word::empty(),
        None,
        None,
        DERIVE_DRIVER_SRC,
        &composition_supply_probe_src(0),
        true,
    )?;
    Ok(DeriveHarness {
        mock_chain: gm.harness.mock_chain,
        account_id: gm.harness.account_id,
        tx_input: MockTransactionInput::AccountId(gm.harness.account_id),
        driver_code: gm.harness.driver_code,
        driver_path: GUARDED_DRIVER_PATH,
    })
}

/// Calls `proc_name` on the harness account with `advice` staged as the transaction's advice stack
/// — the values the driver compares its derivation against.
async fn call_driver(
    h: &DeriveHarness,
    proc_name: &str,
    advice: Vec<Felt>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!(
        "use {path} as driver\n\
         @transaction_script\n\
         pub proc main\n\
             call.driver::{proc_name}\n\
         end\n",
        path = h.driver_path
    );
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(&h.driver_code)
        .expect("linking the driver component into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| {
            panic!("driver call script failed to compile: {e}\n--- src ---\n{src}")
        });
    h.mock_chain
        .build_transaction(h.tx_input.clone())
        .tx_script(tx_script)
        .extend_advice_inputs(AdviceInputs::default().with_stack(advice))
        .build()
        .expect("building the transaction")
        .execute()
        .await
}

/// The advice stack carrying one Word: `adv_loadw` reads a word in canonical order, so the felts go
/// in as they are.
fn advice_word(w: Word) -> Vec<Felt> {
    w.as_elements().to_vec()
}

/// The Rust side of the packaging: the bytes32 form of `id`, split into the two limb words in the
/// orientation the MASM leaves them on the stack (upper first).
fn expected_bytes32_words(id: AccountId) -> (Word, Word) {
    let limbs = bytes32_to_packed_felts(&account_id_to_bytes32(id));
    let lower = Word::new([limbs[0], limbs[1], limbs[2], limbs[3]]);
    let upper = Word::new([limbs[4], limbs[5], limbs[6], limbs[7]]);
    (upper, lower)
}

/// The Rust side of the identifier key: the canonical key of the bytes32 form of `id`.
fn expected_key(id: AccountId) -> Word {
    bytes32_to_storage_map_key(&account_id_to_bytes32(id)).into()
}

/// The account ids the parity spread covers: `SPREAD_SIZE` freshly generated accounts, alternating
/// account type, each carrying the real xreserve library.
fn spread() -> Result<Vec<DeriveHarness>> {
    (0..SPREAD_SIZE)
        .map(|i| {
            setup_derive_account(if i % 2 == 0 {
                AccountType::Public
            } else {
                AccountType::Private
            })
        })
        .collect()
}

// THE CANARY — the kernel really hands the faucet its own id in account context
// ================================================================================================

/// `native_account::get_id`, read from inside a `call`-invoked account procedure, reports exactly
/// the felts Rust reads off the same `AccountId`.
///
/// Everything downstream is arithmetic on those two felts, so this pins the single value the whole
/// derivation is a function of, independently of the packaging that consumes it.
#[tokio::test]
async fn native_account_id_matches_the_rust_felts_in_account_context() -> Result<()> {
    let mut harnesses = spread()?;
    harnesses.push(setup_production_derive_faucet()?);
    for h in &harnesses {
        let [prefix, suffix] = account_id_to_felts(h.account_id);
        call_driver(h, "assert_native_id", vec![suffix, prefix])
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "account {}: get_id must report the Rust felts: {e}",
                    h.account_id
                )
            });
    }
    Ok(())
}

// PARITY — the packaging and the key, over the whole spread
// ================================================================================================

/// The on-chain bytes32 packaging of the account's own id equals `account_id_to_bytes32`, limb for
/// limb, for every id in the spread and for the production faucet.
///
/// This is the layer Circle's wire format actually fixes: sixteen zero bytes, then the prefix as a
/// u64 big endian, then the suffix as a u64 big endian. Asserting it separately from the hashed key
/// means a packaging bug surfaces as a packaging failure rather than as an opaque hash mismatch.
#[tokio::test]
async fn own_id_bytes32_packaging_matches_the_rust_encoding() -> Result<()> {
    let mut harnesses = spread()?;
    harnesses.push(setup_production_derive_faucet()?);
    for h in &harnesses {
        let (upper, lower) = expected_bytes32_words(h.account_id);
        let advice = [advice_word(upper), advice_word(lower)].concat();
        call_driver(h, "assert_own_id_bytes32", advice)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "account {}: the on-chain packaging must match account_id_to_bytes32: {e}",
                    h.account_id
                )
            });
    }
    Ok(())
}

/// The derived identifier key equals `bytes32_to_storage_map_key(account_id_to_bytes32(id))` for
/// every id in the spread and for the production faucet — the exact Word the mint path's
/// `assert_eqw` compares a deposit intent's hashed `remoteToken` against.
#[tokio::test]
async fn own_id_identifier_key_matches_the_rust_key() -> Result<()> {
    let mut harnesses = spread()?;
    harnesses.push(setup_production_derive_faucet()?);
    for h in &harnesses {
        let key = expected_key(h.account_id);
        call_driver(h, "assert_own_id_key", advice_word(key))
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "account {}: the derived identifier key must match the Rust key: {e}",
                    h.account_id
                )
            });
    }
    Ok(())
}

// CONTROLS — the assertions above cannot pass vacuously
// ================================================================================================

/// Feeding one account the OTHER account's expected key traps.
///
/// Without this, an `assert_eqw` that had been dropped — or a derivation that simply returned the
/// caller's own input — would sail through every parity test above.
#[tokio::test]
async fn a_foreign_expected_key_traps() -> Result<()> {
    let a = setup_derive_account(AccountType::Public)?;
    let b = setup_derive_account(AccountType::Public)?;
    assert_ne!(
        a.account_id, b.account_id,
        "the two harness accounts must have different ids"
    );

    let foreign = expected_key(b.account_id);
    let result = call_driver(&a, "assert_own_id_key", advice_word(foreign)).await;
    assert_transaction_executor_error!(
        result,
        &MasmError::from_static_str("parity: derived own-id identifier key mismatch")
    );
    Ok(())
}

/// Feeding one account the OTHER account's expected bytes32 limbs traps — the packaging leg's own
/// non-vacuity control.
#[tokio::test]
async fn foreign_expected_bytes32_limbs_trap() -> Result<()> {
    let a = setup_derive_account(AccountType::Public)?;
    let b = setup_derive_account(AccountType::Private)?;
    let (upper, lower) = expected_bytes32_words(b.account_id);
    let advice = [advice_word(upper), advice_word(lower)].concat();
    let result = call_driver(&a, "assert_own_id_bytes32", advice).await;
    assert_transaction_executor_error!(
        result,
        &MasmError::from_static_str("parity: own-id bytes32 upper limbs mismatch")
    );
    Ok(())
}

/// Two accounts derive DIFFERENT identifier keys — the derivation reads the id rather than
/// returning a constant, which is what makes the mint compare an identity check at all.
#[test]
fn distinct_accounts_derive_distinct_keys() -> Result<()> {
    let a = setup_derive_account(AccountType::Public)?;
    let b = setup_derive_account(AccountType::Private)?;
    assert_ne!(a.account_id, b.account_id, "distinct harness accounts");
    assert_ne!(
        expected_key(a.account_id),
        expected_key(b.account_id),
        "distinct accounts must derive distinct identifier keys"
    );
    Ok(())
}
