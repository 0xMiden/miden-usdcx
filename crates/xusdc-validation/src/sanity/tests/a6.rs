//! A6 offline tests — the `--faucet-id` (existing-faucet) mint must carry the DEPLOYED faucet's domain
//! config, not the fixed BASE_VECTOR's. The faucet writes its configured `remoteDomain` and its own id
//! as `remoteToken` into the message it rebuilds, so a mint naming different ones rebuilds a different
//! digest and dies on chain as an invalid signature; the note factory refuses such an intent up front.
//! A production faucet was deployed with domain 10007 while the fixed BASE_VECTOR carries domain 7, so
//! every mint was rejected (the A6 300s path-N timeout). These node-free tests inject a synthetic
//! deployed config (a domain D != 7 and a faucet id F) and prove the produced payload carries D + F.
//! sourceDomain is NOT asserted on the payload: it is NOT a DepositIntent field and the mint path never
//! reads one — only remoteDomain + remoteToken bind a mint to its faucet.
//!
//! Split out of `sanity/tests.rs` (BUILDER-GATES G3 file-size ceiling) into this `tests::a6` submodule;
//! the shared offline fixtures (`dummy_id`, `faucet_id`, `rng`) are reused from the parent `tests`
//! module.

use miden_protocol::utils::serde::Deserializable;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use xusdc_encoding::xreserve::encoding::{DepositIntent, DepositIntentField};

use super::super::checks::mint_note_for;
use super::super::{MINT_NONROUND_UNITS, MINT_ROUND_UNITS};
use super::{dummy_id, faucet_id, rng};
use crate::mintburn;

/// The `field`'s bytes32 window read straight off the wire, so the assertions below stay byte-level.
/// The window comes from the DepositIntent layout owner, never a restated literal.
fn field_bytes32(payload: &[u8], field: DepositIntentField) -> [u8; 32] {
    let off = field.offset();
    payload[off..off + 32]
        .try_into()
        .expect("a bytes32 field window")
}

/// The `field`'s big-endian u32 read straight off the wire.
fn field_u32(payload: &[u8], field: DepositIntentField) -> u32 {
    let off = field.offset();
    u32::from_be_bytes(
        payload[off..off + 4]
            .try_into()
            .expect("a u32 field window"),
    )
}

/// Asserts the payload is a well-formed DepositIntent (the same structural decode the faucet's note
/// factory runs) and returns it.
fn decoded(payload: &[u8]) -> DepositIntent {
    DepositIntent::read_from_bytes(payload).expect("a well-formed DepositIntent")
}

/// THE A6 core proof: a `--faucet-id` mint payload built for a DEPLOYED faucet config (domain
/// D != 7, faucet id F) decodes to `remoteDomain == D` and `remoteToken == F` — NOT the BASE_VECTOR's
/// domain 7 / token. Reverting EITHER splice (the audit mutation) makes this test RED.
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
    // The remoteToken the faucet writes into the message it rebuilds is its own id, recomputed from F.
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
    let intent = decoded(&payload);

    // THE two gated fields carry the DEPLOYED faucet's config, not the fixed vector's.
    assert_eq!(
        intent.header().remote_domain(),
        DEPLOYED_DOMAIN,
        "remoteDomain must be the DEPLOYED faucet's domain D, not the BASE_VECTOR's 7"
    );
    assert_ne!(
        intent.header().remote_domain(),
        mintburn::MINT_DOMAIN,
        "remoteDomain must NOT be the BASE_VECTOR's MINT_DOMAIN (7)"
    );
    assert_eq!(
        intent.header().remote_token(),
        f,
        "remoteToken must be F itself (the id the faucet writes into the message it rebuilds)"
    );
    assert_eq!(
        field_bytes32(&payload, DepositIntentField::RemoteToken),
        EthEmbeddedAccountId::from_account_id(f).to_bytes32(),
        "the remoteToken wire bytes must be EthEmbeddedAccountId::from_account_id(F).to_bytes32()"
    );

    // Both fields ACTUALLY changed vs the BASE_VECTOR (proving a real splice, not a coincidence).
    let base = mintburn::mint_payload(recipient, amount, max_fee, salt);
    assert_ne!(
        field_bytes32(&payload, DepositIntentField::RemoteToken),
        field_bytes32(&base, DepositIntentField::RemoteToken),
        "the spliced remoteToken must differ from the BASE_VECTOR's token"
    );
    assert_ne!(
        field_u32(&payload, DepositIntentField::RemoteDomain),
        field_u32(&base, DepositIntentField::RemoteDomain),
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
    decoded(&payload);

    // amount: uint256 big-endian, value in the low 8 bytes, high 24 zero.
    let amount_bytes = field_bytes32(&payload, DepositIntentField::Amount);
    assert_eq!(
        &amount_bytes[..24],
        &[0u8; 24],
        "amount high 24 bytes must be zero"
    );
    assert_eq!(
        u64::from_be_bytes(amount_bytes[24..].try_into().unwrap()),
        amount,
        "amount low 8 bytes must decode to the raw amount"
    );
    // maxFee likewise.
    let max_fee_bytes = field_bytes32(&payload, DepositIntentField::MaxFee);
    assert_eq!(
        u64::from_be_bytes(max_fee_bytes[24..].try_into().unwrap()),
        max_fee,
        "maxFee low 8 bytes must decode to the raw max fee"
    );
    // recipient P2ID target.
    assert_eq!(
        field_bytes32(&payload, DepositIntentField::RemoteRecipient),
        EthEmbeddedAccountId::from_account_id(recipient).to_bytes32(),
        "remoteRecipient must be EthEmbeddedAccountId::from_account_id(recipient).to_bytes32()"
    );
    // nonce salt: byte 0 flips by the salt vs an unsalted build; the rest is unchanged.
    let unsalted = mintburn::mint_payload_for(&config, recipient, amount, max_fee, 0);
    let nonce = field_bytes32(&payload, DepositIntentField::Nonce);
    let unsalted_nonce = field_bytes32(&unsalted, DepositIntentField::Nonce);
    assert_eq!(
        nonce[0],
        unsalted_nonce[0] ^ salt,
        "nonce byte 0 must XOR the salt"
    );
    assert_eq!(
        &nonce[1..],
        &unsalted_nonce[1..],
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
    let dom_off = DepositIntentField::RemoteDomain.offset();
    let tok_off = DepositIntentField::RemoteToken.offset();
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
/// call the hardcoded `mint_payload`, the `Some(config)` assertions below go RED — and the `None` leg
/// pins the factory's refusal of an intent addressed to another faucet. Node-free: the attester is
/// reconstructed from a fixed scalar with `persist=false` (no disk), and note assembly is pure (no
/// RPC).
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
    let intent = decoded(&payload);
    assert_eq!(
        intent.header().remote_domain(),
        DEPLOYED_DOMAIN,
        "the mint_note_for seam must carry the DEPLOYED faucet's domain, not the BASE_VECTOR's 7"
    );
    assert_eq!(
        intent.header().remote_token(),
        f,
        "the mint_note_for seam must carry F as remoteToken"
    );
    // The recipient is still correct through the seam (no regression in the pre-existing splice).
    assert_eq!(
        intent.header().remote_recipient(),
        recipient,
        "the seam still points remoteRecipient at the recipient"
    );

    // None (the BASE_VECTOR path): the SAME seam leaves the vector's header (domain 7 / vector
    // token), which names ANOTHER faucet — so the factory refuses to build a note for F from it.
    let base_payload = mintburn::mint_payload_opt(None, recipient, amount, 0, salt);
    assert_eq!(
        field_u32(&base_payload, DepositIntentField::RemoteDomain),
        mintburn::MINT_DOMAIN,
        "None ⇒ the BASE_VECTOR's MINT_DOMAIN (7) through the seam"
    );
    assert_ne!(
        field_bytes32(&base_payload, DepositIntentField::RemoteToken),
        field_bytes32(&payload, DepositIntentField::RemoteToken),
        "the two seam modes must carry different remoteTokens (vector token vs F)"
    );
    let refused = mint_note_for(
        relayer,
        f,
        &attester,
        recipient,
        amount,
        salt,
        None,
        &mut rng(9),
    );
    assert!(
        refused.is_err(),
        "an intent addressed to another faucet must be refused before the note exists"
    );
}
