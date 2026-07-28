//! F5 — production transaction auth: the faucet is a Miden NETWORK ACCOUNT.
//!
//! Human decision (2026-07-08, RATIFIED): the xUSDC/xReserve faucet ships composing the stock
//! `AuthNetworkAccount` as its ONE production auth component — keyless, a frozen note-script
//! allowlist, and a tx-script allowlist of EXACTLY the one canonical `ExpirationTransactionScript`
//! (S12, RATIFIED 2026-07-20).
//!
//! The production faucet (`support::setup_production_faucet`) is finalized under
//! `Auth::NetworkAccount` fed `builder.allowed_note_scripts()`, and the mint + burn notes carry the
//! scheme-2 `NetworkAccountTarget` routing attachment.
//!
//! COVERAGE (this file):
//! - proof #6: the production faucet IS a network account AND its auth component is the stock
//!   `AuthNetworkAccount` (its auth procedure root is present in the account code).
//! - proof #5: the note-script allowlist equals EXACTLY the 14 ratified roots (2 supply + 12 admin
//!   — NO `set_role_admin` note: removed by the S21 disposition flip, human-ratified 2026-07-14);
//!   the tx-script allowlist is present AND equals EXACTLY the one canonical
//!   `ExpirationTransactionScript::script_root()` (S12, RATIFIED 2026-07-20).
//! - proof #1: a non-allowlisted note is rejected by auth; any tx script OTHER than the canonical
//!   expiration script is rejected, and that expiration script is admitted.
//! - proof #2/#3: exact routing-attachment wire form + semantics — the mint (a STOCK `MintNote`
//!   since the Wave-1 S1 recomposition) carries the three xUSDC attachments (scheme-4
//!   DepositIntent + scheme-5 attestation + scheme-2 `NetworkAccountTarget` to the faucet with
//!   `NoteExecutionHint::Always`); the burn carries the scheme-2 target to the faucet with `Always`.
//!
//! Related coverage lives in sibling suites: the admin layered-auth E2E per op (owner/role-gated
//! writes + wrong-sender traps + NOTE_ARGS-inert) in `f5_admin_notes.rs`, and the scheme-aware mint
//! transport negatives (missing scheme-4/5/2 attachments / wrong count / tampered attestation,
//! through the attestation mint policy) in `mint_policy_e2e.rs`.

mod support;

use core::num::NonZeroU16;
use core::slice;
use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountComponent};
use miden_protocol::note::{NoteAttachmentScheme, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{
    AuthNetworkAccount, NetworkAccount, NetworkAccountNoteAllowlist,
    NetworkAccountTxScriptAllowlist,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::note::{BurnNote, MintNote, NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_admin::{
    XReserveAcceptOwnershipNote, XReserveBlockAccountNote, XReserveGrantRoleNote,
    XReserveIdentifierInitNote, XReservePauseNote, XReserveRevokeRoleNote, XReserveSetAttesterNote,
    XReserveSetMaxSupplyNote, XReserveSetMinBurnSizeNote, XReserveTransferOwnershipNote,
    XReserveUnblockAccountNote, XReserveUnpauseNote,
};
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::note::xreserve_mint::{
    MintAttestation, XUsdcMintNote, XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME,
    XUSDC_MINT_ATTESTATION_NUM_WORDS, XUSDC_MINT_INTENT_ATTACHMENT_SCHEME,
};
use xusdc_encoding::xreserve::encoding::{account_id_to_bytes32, XReserveBurnItems};

const MAX_SUPPLY: u64 = 1_000_000;

// HELPERS
// ================================================================================================

/// A deterministic standalone note rng (only the serial number depends on it, never the gate).
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A sample DC-7 burn payload (round-trippable; only the amount is material here).
fn sample_burn_items(amount: u64) -> XReserveBurnItems {
    XReserveBurnItems {
        amount: miden_protocol::asset::AssetAmount::new(amount).expect("amount within bounds"),
        dest_domain: 9,
        dest_recipient: [0xABu8; 32],
        salt: [0xCDu8; 32],
    }
}

/// First byte of the 32-byte `remoteRecipient` field (felt 19 x 4 bytes; DC-1).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;

/// The attested wire amount spliced into the payload (any in-range value; the factory re-derives
/// the note storage from it).
const MINT_AMOUNT: u64 = 5_000;

/// A valid attested deposit-intent payload: the canonical accept vector with an in-range
/// amount/maxFee and a factory-decodable `remoteRecipient` (the DEV-10 bytes32 form of
/// `recipient`) spliced in — `XUsdcMintNote::create` re-derives the stock mint storage from
/// these fields, so they must be valid (the mint_policy_e2e.rs payload construction).
fn attested_deposit_intent_payload(recipient: miden_protocol::account::AccountId) -> Vec<u8> {
    let v = xusdc_encoding::vectors::load();
    let mut payload = v
        .families
        .di
        .iter()
        .find(|d| d.kind == "accept")
        .expect("at least one accepted deposit-intent vector")
        .bytes();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(MINT_AMOUNT));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(1));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&account_id_to_bytes32(recipient));
    payload
}

/// Builds the current PRODUCTION faucet and returns its MockChain + committed faucet account object.
/// The faucet id (`account.id()`) is PUBLIC — usable as a `NetworkAccountTarget` target.
fn production_faucet() -> Result<(MockChain, Account)> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_, _faucet_id| Vec::new())
        .context("building the production faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("fetching the committed faucet account")?
        .clone();
    Ok((pf.mock_chain, account))
}

/// The auth-procedure MAST root of the stock `AuthNetworkAccount` component (independent of the
/// allowlist storage contents; a dummy non-empty allowlist is used only to construct it).
fn stock_network_auth_proc_root() -> Word {
    let component: AccountComponent =
        AuthNetworkAccount::with_allowed_notes(BTreeSet::from_iter([MintNote::script_root()]))
            .expect("non-empty allowlist constructs")
            .into();
    let (root, _is_auth) = component
        .procedures()
        .find(|(_, is_auth)| *is_auth)
        .expect("AuthNetworkAccount exposes an auth procedure");
    Word::from(root)
}

// PROOF #6 — the production faucet is a network account, authed by the stock AuthNetworkAccount
// ================================================================================================

/// The production faucet must be a network account (public + the standardized note-script allowlist
/// slot).
#[test]
fn production_faucet_is_a_network_account() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let result = NetworkAccount::new(account);
    assert!(
        result.is_ok(),
        "the production faucet is not a network account (no AuthNetworkAccount / no allowlist \
         slot); F5 must compose AuthNetworkAccount as the sole auth component. Got: {:?}",
        result.err()
    );
    Ok(())
}

/// The production faucet's dedicated auth component must be the STOCK `AuthNetworkAccount` (not a
/// custom / mutable-allowlist component): its auth-procedure MAST root must appear in the account
/// code.
#[test]
fn production_faucet_auth_component_is_stock_network_account() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let auth_root = stock_network_auth_proc_root();
    let account_roots: BTreeSet<Word> = account.code().procedure_roots().collect();
    assert!(
        account_roots.contains(&auth_root),
        "the production faucet does not carry the stock AuthNetworkAccount auth procedure — the \
         auth component is not AuthNetworkAccount (F5 must compose the stock component, not a \
         custom auth)",
    );
    Ok(())
}

// PROOF #5 — the frozen note-script allowlist + a tx-script allowlist of EXACTLY the expiration root
// ================================================================================================

/// The note-script allowlist must equal EXACTLY the 14 ratified roots (2 supply + 12 admin) — an
/// extra OR a missing root is RED (the allowlist is IMMUTABLE post-deploy). Asserted at BOTH layers:
/// the builder's single-source `allowed_note_scripts()` and the built account's on-chain allowlist
/// map. The 12 roots come from the shipped note factories (pinned + parity-tested individually).
/// `set_role_admin` is deliberately ABSENT (S21 disposition flip, human-ratified 2026-07-14): the
/// role-admin graph is build-seeded and frozen; rotation is `grant_role`/`revoke_role`
/// (CIR-ADMIN-3) — the same removal disposition as `renounce_role` and `freeze`/`unfreeze`.
#[test]
fn production_faucet_note_allowlist_is_exactly_the_14_ratified_roots() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let expected: BTreeSet<_> = BTreeSet::from([
        // rows 1-2: the supply-side notes (row 1 = the STOCK MintNote since Wave-1 S1).
        MintNote::script_root(),
        BurnNote::script_root(),
        // rows 3-12: the 10 admin note scripts (NO set_role_admin — S21).
        XReserveSetAttesterNote::script_root(),
        XReserveSetMinBurnSizeNote::script_root(),
        XReserveSetMaxSupplyNote::script_root(),
        XReservePauseNote::script_root(),
        XReserveUnpauseNote::script_root(),
        XReserveGrantRoleNote::script_root(),
        XReserveRevokeRoleNote::script_root(),
        XReserveTransferOwnershipNote::script_root(),
        XReserveAcceptOwnershipNote::script_root(),
        XReserveIdentifierInitNote::script_root(),
        // rows 13-14: the F4-reversal transfer-blocklist admin notes (BLK_MANAGER-gated).
        XReserveBlockAccountNote::script_root(),
        XReserveUnblockAccountNote::script_root(),
    ]);
    assert_eq!(
        expected.len(),
        14,
        "the ratified allowlist is exactly 14 distinct roots"
    );

    // Source layer: the builder's single-source allowlist == the 14 ratified roots.
    assert_eq!(
        XReserveStablecoinBuilder::allowed_note_scripts(),
        expected,
        "allowed_note_scripts() must equal EXACTLY the 14 ratified roots (extra/missing = RED)",
    );

    // On-chain layer: the built faucet's allowlist storage map == the 14 ratified roots.
    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry a note-script allowlist slot: {e}"))?;
    assert_eq!(
        allowlist.allowed_script_roots(),
        &expected,
        "the built faucet's on-chain allowlist map must equal EXACTLY the 14 ratified roots",
    );
    Ok(())
}

/// The tx-script allowlist must exist and equal EXACTLY the one canonical
/// `ExpirationTransactionScript::script_root()` (S12, RATIFIED 2026-07-20) — the sole-mint-surface
/// posture (F1), now expressed as a ONE-root allowlist that admits only the protocol-standard
/// expiration bounder rather than an empty set. Extra/missing = RED.
#[test]
fn production_faucet_tx_script_allowlist_is_exactly_the_expiration_root() -> Result<()> {
    let (_chain, account) = production_faucet()?;
    let tx_allowlist = NetworkAccountTxScriptAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry a tx-script allowlist slot: {e}"))?;
    let expected = BTreeSet::from([ExpirationTransactionScript::script_root()]);
    assert_eq!(
        tx_allowlist.allowed_script_roots(),
        &expected,
        "the tx-script allowlist must equal EXACTLY {{ ExpirationTransactionScript::script_root() }} \
         (S12 sole-mint-surface); found {} root(s)",
        tx_allowlist.allowed_script_roots().len(),
    );
    Ok(())
}

// PROOF #1 — the auth boundary is real (non-allowlisted note + any tx script rejected)
// ================================================================================================

/// Consuming a note whose script root is NOT in the allowlist must be rejected by the network-auth
/// component with the exact allowlist error.
#[tokio::test]
async fn non_allowlisted_note_is_rejected_by_auth() -> Result<()> {
    let (chain, account) = production_faucet()?;
    let bogus_script = CodeBuilder::new()
        .compile_note_script("@note_script\npub proc main\n    dropw\nend")
        .context("compiling the non-allowlisted probe note script")?;
    let bogus = NoteBuilder::new(test_account_id(9), &mut note_rng(99))
        .note_type(NoteType::Public)
        .script(bogus_script)
        .build()
        .context("building the non-allowlisted probe note")?;

    let result = chain
        .build_tx_context(account.id(), &[], slice::from_ref(&bogus))
        .context("building the consume tx context")?
        .build()
        .context("building the consume tx")?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);
    Ok(())
}

/// Any transaction script OTHER than the canonical `ExpirationTransactionScript` must be rejected
/// by the one-root tx-script allowlist, AND that canonical expiration script must be ADMITTED
/// (S12): the `nop` probe still trips `ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED`, while the
/// expiration script clears the allowlist gate and executes.
#[tokio::test]
async fn non_expiration_tx_script_is_rejected_and_expiration_is_admitted() -> Result<()> {
    let (chain, account) = production_faucet()?;

    // NEGATIVE — an arbitrary (nop) tx script is NOT the expiration root, so the allowlist rejects it.
    let bogus = CodeBuilder::new()
        .compile_tx_script("@transaction_script\npub proc main\n    nop\nend\n")
        .context("compiling the probe tx script")?;
    let rejected = chain
        .build_tx_context(account.id(), &[], &[])
        .context("building the tx-script tx context")?
        .tx_script(bogus)
        .build()
        .context("building the tx-script tx")?
        .execute()
        .await;
    assert_transaction_executor_error!(rejected, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    // POSITIVE — the canonical expiration script IS allowlisted, so it CLEARS the allowlist gate.
    // An expiration-only tx changes no account state and consumes no notes, so the kernel rejects it
    // with the empty-tx epilogue assertion — downstream of, and orthogonal to, the allowlist gate.
    // The precise S12 invariant: the expiration script is NOT rejected by the tx-script allowlist (a
    // mutation dropping the expiration root flips this back to the allowlist error — RED — caught here).
    let expiration = ExpirationTransactionScript::new(NonZeroU16::new(64).expect("64 is non-zero"));
    let admitted = chain
        .build_tx_context(account.id(), &[], &[])
        .context("building the expiration tx-script tx context")?
        .tx_script(expiration.into())
        .tx_script_args(expiration.tx_script_args())
        .build()
        .context("building the expiration tx-script tx")?
        .execute()
        .await;
    match admitted {
        Ok(_) => {}
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(actual)) => assert!(
            !ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED.matches_execution_error(&actual),
            "the canonical ExpirationTransactionScript must be ADMITTED by the S12 allowlist, but \
             it was rejected by the tx-script allowlist: {actual}",
        ),
        Err(other) => {
            panic!("the expiration tx failed with an unexpected non-execution error: {other}")
        }
    }
    Ok(())
}

// PROOF #2 / #3 — exact routing-attachment wire form + NetworkAccountTarget semantics
// ================================================================================================

/// The mint note (the STOCK `MintNote` built by `XUsdcMintNote::create`) must carry EXACTLY the
/// three xUSDC attachments — the scheme-4 DepositIntent preimage, the scheme-5 attestation
/// (11 words: `[feeAmount(8), pubkey(16), signature(17), pad(3)]`), and the scheme-2
/// `NetworkAccountTarget` routing attachment addressed to the faucet with
/// `NoteExecutionHint::Always`.
#[test]
fn mint_note_carries_the_three_xusdc_attachments() -> Result<()> {
    let (_chain, faucet) = production_faucet()?;
    let faucet_id = faucet.id();
    let payload = attested_deposit_intent_payload(test_account_id(3));
    let att = gen_attester(1, &payload);
    let note = XUsdcMintNote::create(
        test_account_id(3),
        faucet_id,
        &payload,
        &MintAttestation::new(att.sig_bytes, att.pubkey_bytes),
        &mut note_rng(1),
    )
    .map_err(|e| anyhow::anyhow!("constructing the mint note: {e}"))?;

    assert_eq!(
        note.attachments().num_attachments(),
        3,
        "the mint note must carry exactly three attachments: the intent + the attestation + the \
         routing target",
    );
    let scheme_four = NoteAttachmentScheme::new(XUSDC_MINT_INTENT_ATTACHMENT_SCHEME)
        .expect("scheme 4 is a valid attachment scheme");
    let scheme_five = NoteAttachmentScheme::new(XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME)
        .expect("scheme 5 is a valid attachment scheme");
    let count_of = |scheme: NoteAttachmentScheme| {
        note.attachments()
            .iter()
            .filter(|a| a.attachment_scheme() == scheme)
            .count()
    };
    assert_eq!(
        count_of(scheme_four),
        1,
        "exactly one scheme-4 DepositIntent attachment"
    );
    assert_eq!(
        count_of(scheme_five),
        1,
        "exactly one scheme-5 attestation attachment"
    );
    assert_eq!(
        count_of(NetworkAccountTarget::ATTACHMENT_SCHEME),
        1,
        "exactly one scheme-2 routing attachment"
    );

    let attestation = note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == scheme_five)
        .context("the scheme-5 attestation attachment is present")?;
    assert_eq!(
        usize::from(attestation.num_words()),
        XUSDC_MINT_ATTESTATION_NUM_WORDS,
        "the attestation attachment is [feeAmount(8), pubkey(16), signature(17), pad(3)] = 11 words",
    );

    let target = NetworkAccountTarget::try_from(note.attachments())
        .map_err(|e| anyhow::anyhow!("the mint note must carry a scheme-2 routing target: {e}"))?;
    assert_eq!(
        target.target_id(),
        faucet_id,
        "the routing target must be the faucet account"
    );
    assert_eq!(
        target.execution_hint(),
        NoteExecutionHint::Always,
        "the routing target's execution hint must be Always",
    );
    Ok(())
}

/// The burn note must carry the scheme-2 `NetworkAccountTarget` routing attachment addressed to the
/// faucet with `NoteExecutionHint::Always` (and nothing else).
#[test]
fn burn_note_carries_scheme2_target_to_faucet() -> Result<()> {
    let (_chain, faucet) = production_faucet()?;
    let faucet_id = faucet.id();
    let note = XReserveBurnNote::create(
        test_account_id(3),
        faucet_id,
        sample_burn_items(5_000),
        &mut note_rng(2),
    )
    .map_err(|e| anyhow::anyhow!("constructing the burn note: {e}"))?;

    assert_eq!(
        note.attachments().num_attachments(),
        1,
        "the burn note must carry exactly one attachment: the scheme-2 routing target",
    );
    let target = NetworkAccountTarget::try_from(note.attachments())
        .map_err(|e| anyhow::anyhow!("the burn note must carry a scheme-2 routing target: {e}"))?;
    assert_eq!(
        target.target_id(),
        faucet_id,
        "the routing target must be the faucet account"
    );
    assert_eq!(
        target.execution_hint(),
        NoteExecutionHint::Always,
        "the routing target's execution hint must be Always",
    );
    Ok(())
}
