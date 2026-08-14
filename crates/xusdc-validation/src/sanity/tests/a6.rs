//! A6 offline tests — the `--faucet-id` (existing-faucet) mint must carry the DEPLOYED faucet's domain
//! config, not the fixed BASE_VECTOR's. The mint gate (structural validation `deposit_intent_parser::validate`)
//! compares a mint's `remoteDomain` against the faucet's stored `domain`, and `bytes32_to_storage_map_key(remoteToken)`
//! against the stored identifier key. A production faucet was deployed with domain 10007 and an
//! identifier = EthEmbeddedAccountId::from_account_id(faucet.id()).to_bytes32(); the fixed BASE_VECTOR carries domain 7, so structural validation
//! rejected every mint (the A6 300s path-N timeout). These node-free tests inject a synthetic deployed
//! config (a domain D != 7 and a faucet id F) and prove the produced payload carries D + the F-derived
//! identifier. sourceDomain is NOT asserted on the payload: it is NOT a DepositIntent field and the
//! mint proc never reads one — the mint gate compares ONLY remoteDomain + remoteToken (verified against
//! `asm/standards/xreserve/deposit_intent_parser.masm::validate`).
//!
//! Split out of `sanity/tests.rs` (BUILDER-GATES G3 file-size ceiling) into this `tests::a6` submodule;
//! the shared offline fixtures (`dummy_id`, `faucet_id`, `rng`) are reused from the parent `tests`
//! module.

use miden_standards::interop::eth::EthEmbeddedAccountId;
use xusdc_encoding::xreserve::encoding::{
    deposit_intent_field_offset, parse_deposit_intent_header, DepositIntentField,
};

use super::super::checks::mint_note_for;
use super::super::{MINT_NONROUND_UNITS, MINT_ROUND_UNITS};
use super::{dummy_id, faucet_id, rng};
use crate::mintburn;

/// THE A6 core proof: a `--faucet-id` mint payload built for a DEPLOYED faucet config (domain
/// D != 7, faucet id F) decodes to `remoteDomain == D` and `remoteToken == EthEmbeddedAccountId::from_account_id(F).to_bytes32()`
/// — NOT the BASE_VECTOR's domain 7 / token. Reverting EITHER splice (the audit mutation) makes this
/// test RED.
#[test]
fn faucet_id_mint_payload_carries_deployed_domain_and_identifier() {
    // A synthetic deployed faucet: the production domain from the A6 failure (10007 != MINT_DOMAIN 7)
    // and a real production faucet id F.
    const DEPLOYED_DOMAIN: u32 = 10007;
    let f = faucet_id(0x5A);
    assert_ne!(
        DEPLOYED_DOMAIN,
        mintburn::MINT_DOMAIN,
        "the test domain must differ from the BASE_VECTOR's 7 for this to prove anything"
    );

    let config = mintburn::MintDomainConfig::for_deployed_faucet(DEPLOYED_DOMAIN, f);
    // The identifier the mint gate compares is EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32(), recomputed from F.
    assert_eq!(
        config.remote_token,
        EthEmbeddedAccountId::from_account_id(f).to_bytes32(),
        "the resolved config's remote_token must be EthEmbeddedAccountId::from_account_id(F).to_bytes32()"
    );

    let recipient = dummy_id(0x33);
    let amount = MINT_NONROUND_UNITS; // a non-round amount also exercises the amount splice
    let max_fee = 0u64;
    let salt = 0x77u8;

    let payload = mintburn::mint_payload_for(&config, recipient, amount, max_fee, salt);
    let h = parse_deposit_intent_header(&payload)
        .expect("the spliced --faucet-id payload must still be a well-formed DepositIntent");

    // THE two gated fields carry the DEPLOYED faucet's config, not the fixed vector's.
    assert_eq!(
        h.remote_domain, DEPLOYED_DOMAIN,
        "remoteDomain must be the DEPLOYED faucet's domain D, not the BASE_VECTOR's 7"
    );
    assert_ne!(
        h.remote_domain,
        mintburn::MINT_DOMAIN,
        "remoteDomain must NOT be the BASE_VECTOR's MINT_DOMAIN (7)"
    );
    assert_eq!(
        h.remote_token,
        EthEmbeddedAccountId::from_account_id(f).to_bytes32(),
        "remoteToken must be EthEmbeddedAccountId::from_account_id(F).to_bytes32() (matches the deployed identifier)"
    );

    // Both fields ACTUALLY changed vs the BASE_VECTOR (proving a real splice, not a coincidence).
    let base =
        parse_deposit_intent_header(&mintburn::mint_payload(recipient, amount, max_fee, salt))
            .expect("the BASE_VECTOR payload parses");
    assert_ne!(
        h.remote_token, base.remote_token,
        "the spliced remoteToken must differ from the BASE_VECTOR's token"
    );
    assert_ne!(
        h.remote_domain, base.remote_domain,
        "the spliced remoteDomain must differ from the BASE_VECTOR's domain"
    );
}

/// No regression: the amount / maxFee / recipient / nonce still splice correctly in `--faucet-id`
/// mode — the A6 fix adds the domain/identifier splice ON TOP of the existing header splice, without
/// disturbing it.
#[test]
fn faucet_id_mint_payload_preserves_amount_recipient_and_nonce_splices() {
    let config = mintburn::MintDomainConfig::for_deployed_faucet(10007, faucet_id(0x11));
    let recipient = dummy_id(0x44);
    let amount = 123_456_789u64;
    let max_fee = 7u64;
    let salt = 0x99u8;

    let payload = mintburn::mint_payload_for(&config, recipient, amount, max_fee, salt);
    let h = parse_deposit_intent_header(&payload).expect("must parse");

    // amount: uint256 big-endian, value in the low 8 bytes, high 24 zero.
    assert_eq!(
        &h.amount[..24],
        &[0u8; 24],
        "amount high 24 bytes must be zero"
    );
    assert_eq!(
        u64::from_be_bytes(h.amount[24..].try_into().unwrap()),
        amount,
        "amount low 8 bytes must decode to the raw amount"
    );
    // maxFee likewise.
    assert_eq!(
        u64::from_be_bytes(h.max_fee[24..].try_into().unwrap()),
        max_fee,
        "maxFee low 8 bytes must decode to the raw max fee"
    );
    // recipient P2ID target.
    assert_eq!(
        h.remote_recipient,
        EthEmbeddedAccountId::from_account_id(recipient).to_bytes32(),
        "remoteRecipient must be EthEmbeddedAccountId::from_account_id(recipient).to_bytes32()"
    );
    // nonce salt: byte 0 flips by the salt vs an unsalted build; the rest is unchanged.
    let unsalted = parse_deposit_intent_header(&mintburn::mint_payload_for(
        &config, recipient, amount, max_fee, 0,
    ))
    .expect("must parse");
    assert_eq!(
        h.nonce[0],
        unsalted.nonce[0] ^ salt,
        "nonce byte 0 must XOR the salt"
    );
    assert_eq!(
        &h.nonce[1..],
        &unsalted.nonce[1..],
        "the rest of the nonce is unchanged by the salt"
    );
}

/// The fresh-LOCAL byte-for-byte invariant: splicing the LOCAL-VECTOR config reproduces the untouched
/// BASE_VECTOR payload exactly, and `mint_payload_opt(None)` is the BASE_VECTOR path — so routing every
/// mint through the config seam never alters the fresh-local vectors (the scope's guarantee).
#[test]
fn local_vector_config_reproduces_base_vector_payload_byte_for_byte() {
    let recipient = dummy_id(0x55);
    let local = mintburn::MintDomainConfig::local_vector();
    assert_eq!(
        local.domain,
        mintburn::MINT_DOMAIN,
        "local_vector's domain is the BASE_VECTOR's MINT_DOMAIN (7)"
    );
    for (amount, max_fee, salt) in [
        (MINT_ROUND_UNITS, 0u64, 0x11u8),
        (MINT_NONROUND_UNITS, 5, 0x22),
        (1, 0, 0),
    ] {
        let base = mintburn::mint_payload(recipient, amount, max_fee, salt);
        // Splicing the local vector's OWN domain/token is a no-op on the BASE_VECTOR payload.
        assert_eq!(
            mintburn::mint_payload_for(&local, recipient, amount, max_fee, salt),
            base,
            "local_vector splice must be byte-identical to BASE_VECTOR (amount {amount}, salt {salt})"
        );
        // The Option seam: None == BASE_VECTOR; Some(local) == BASE_VECTOR too.
        assert_eq!(
            mintburn::mint_payload_opt(None, recipient, amount, max_fee, salt),
            base,
            "mint_payload_opt(None) must be the BASE_VECTOR path"
        );
        assert_eq!(
            mintburn::mint_payload_opt(Some(&local), recipient, amount, max_fee, salt),
            base,
            "mint_payload_opt(Some(local_vector)) must be byte-identical to BASE_VECTOR"
        );
    }
}

/// The deployed-config seam actually CHANGES the payload vs the fresh-local path, and ONLY in the two
/// gated fields: a deployed config (domain != 7) makes `opt(Some(deployed))` differ from `opt(None)`
/// EXACTLY in the remoteDomain and remoteToken windows — nothing else. The windows are derived from the
/// DepositIntent layout owner (`deposit_intent_field_offset`), never restated literals, so an owner-side
/// layout change moves this test in lockstep with production instead of drifting.
#[test]
fn deployed_config_diverges_from_local_only_in_domain_and_token() {
    let recipient = dummy_id(0x66);
    let f = faucet_id(0x77);
    let deployed = mintburn::MintDomainConfig::for_deployed_faucet(10007, f);
    let (amount, max_fee, salt) = (MINT_ROUND_UNITS, 0u64, 0x33u8);

    let local_payload = mintburn::mint_payload_opt(None, recipient, amount, max_fee, salt);
    let deployed_payload =
        mintburn::mint_payload_opt(Some(&deployed), recipient, amount, max_fee, salt);
    assert_ne!(
        local_payload, deployed_payload,
        "a deployed config with a different domain/identifier MUST change the payload"
    );
    assert_eq!(
        local_payload.len(),
        deployed_payload.len(),
        "the splice must not change the payload length"
    );

    // The two gated fields' wire windows come from the layout owner, NOT restated literals:
    // remoteDomain = [dom_off, dom_off+4) (a u32), remoteToken = [tok_off, tok_off+32) (a bytes32).
    let dom_off = deposit_intent_field_offset(DepositIntentField::RemoteDomain);
    let tok_off = deposit_intent_field_offset(DepositIntentField::RemoteToken);
    let domain_window = dom_off..dom_off + 4;
    let token_window = tok_off..tok_off + 32;
    let gated_window = dom_off..tok_off + 32; // remoteDomain immediately precedes remoteToken
    let diff: Vec<usize> = (0..local_payload.len())
        .filter(|&i| local_payload[i] != deployed_payload[i])
        .collect();
    assert!(
        diff.iter().all(|i| gated_window.contains(i)),
        "only remoteDomain+remoteToken bytes ({gated_window:?}) may differ, got {diff:?}"
    );
    assert!(
        diff.iter().any(|i| domain_window.contains(i)),
        "the remoteDomain bytes ({domain_window:?}) must change (domain 7 -> 10007)"
    );
    assert!(
        diff.iter().any(|i| token_window.contains(i)),
        "the remoteToken bytes ({token_window:?}) must change (BASE_VECTOR token -> EthEmbeddedAccountId::from_account_id(F).to_bytes32())"
    );
}

/// THE A6 production-seam proof: `sanity_e2e` builds mint notes through `checks::mint_note_for`, so
/// this test drives THAT seam (not `mint_payload_for` directly) and asserts the note it returns
/// carries the resolved deployed config. It is the regression for the round-2 finding that the direct
/// tests bypass the production call site: if `mint_note_for` were reverted to ignore its `config` and
/// call the hardcoded `mint_payload`, the `Some(config)` assertions below go RED. Node-free: the
/// attester is reconstructed from a fixed scalar with `persist=false` (no disk), and note assembly is
/// pure (no RPC).
#[test]
fn mint_note_for_seam_threads_the_resolved_deployed_config() {
    // A test attester built entirely offline (persist=false ⇒ nothing is written under the dir).
    let dir = tempfile::tempdir().expect("temp dir");
    let attester = crate::actors::AttesterKey::from_secret_scalar(&[0x42; 32], dir.path(), "seam")
        .expect("reconstruct a test attester from a fixed scalar");

    let relayer = dummy_id(0x01);
    let recipient = dummy_id(0x33);
    let f = faucet_id(0x5A);
    const DEPLOYED_DOMAIN: u32 = 10007;
    let config = mintburn::MintDomainConfig::for_deployed_faucet(DEPLOYED_DOMAIN, f);
    let amount = MINT_ROUND_UNITS;
    let salt = 0x77u8;

    // Some(config): the PRODUCTION seam must thread the deployed domain + identifier into the note's
    // DepositIntent (mint_note_for returns the payload it embedded in the note).
    let (_note, payload) = mint_note_for(
        relayer,
        f,
        &attester,
        recipient,
        amount,
        salt,
        Some(config),
        &mut rng(9),
    )
    .expect("mint_note_for builds a production mint note for the deployed config");
    let h =
        parse_deposit_intent_header(&payload).expect("the note's embedded DepositIntent parses");
    assert_eq!(
        h.remote_domain, DEPLOYED_DOMAIN,
        "the mint_note_for seam must carry the DEPLOYED faucet's domain, not the BASE_VECTOR's 7"
    );
    assert_eq!(
        h.remote_token,
        EthEmbeddedAccountId::from_account_id(f).to_bytes32(),
        "the mint_note_for seam must carry EthEmbeddedAccountId::from_account_id(F).to_bytes32() as remoteToken"
    );
    // The recipient is still correct through the seam (no regression in the pre-existing splice).
    assert_eq!(
        h.remote_recipient,
        EthEmbeddedAccountId::from_account_id(recipient).to_bytes32(),
        "the seam still points remoteRecipient at the recipient"
    );

    // None (fresh-LOCAL): the SAME seam leaves the BASE_VECTOR header (domain 7 / vector token), so the
    // fresh-local mints are unchanged — and the two modes DEMONSTRABLY differ in the gated fields.
    let (_base_note, base_payload) = mint_note_for(
        relayer,
        f,
        &attester,
        recipient,
        amount,
        salt,
        None,
        &mut rng(9),
    )
    .expect("mint_note_for builds a fresh-local mint note");
    let bh = parse_deposit_intent_header(&base_payload).expect("parses");
    assert_eq!(
        bh.remote_domain,
        mintburn::MINT_DOMAIN,
        "None ⇒ the BASE_VECTOR's MINT_DOMAIN (7) through the seam"
    );
    assert_ne!(
        bh.remote_domain, h.remote_domain,
        "the two seam modes must carry different domains (7 vs the deployed 10007)"
    );
    assert_ne!(
        bh.remote_token, h.remote_token,
        "the two seam modes must carry different remoteTokens (vector token vs the F identifier)"
    );
}
