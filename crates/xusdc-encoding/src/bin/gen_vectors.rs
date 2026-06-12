//! Committed generator of the ONE canonical golden-vector artifact
//! (`tests/vectors/xreserve-encoding-vectors.json`).
//!
//! Provenance engine per the approved plan §8: arithmetic/layout expectations are derived
//! here with exact integer math (formulas recorded per entry); hash/protocol-derived
//! expectations (Poseidon2 Words, AccountIds) are computed ONCE against the pinned
//! `protocol v0.15.3` crates (`Hasher::hash_elements`, `bytes_to_packed_u32_elements`,
//! `AccountIdBuilder::build_with_seed`). This binary never calls the crate's mirror
//! routines (derivation independence); it is derivation code, not routine logic.
//! Regeneration is an explicit, reviewed act: `cargo run --bin gen_vectors`.
//!
//! DC-1 byte offsets used below trace to the frozen 04 COMPONENT-SPEC DC-1 table
//! (CIRCLE-DATA-SCHEMAS.md:21-32): magic@0, version@4, amount@8, remoteDomain@40,
//! remoteToken@44, remoteRecipient@76, localToken@108, localDepositor@140, maxFee@172,
//! nonce@204, hookDataLen@236, hookData@240; header = 240 bytes = 60 u32-LE felts (C-10).

use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Hasher, Word};
use serde_json::{Value, json};

const ASSET_AMOUNT_MAX: u128 = (1u128 << 63) - (1u128 << 31); // E-7: 2^63 - 2^31

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn felt_hex(f: Felt) -> String {
    format!("0x{:x}", f.as_canonical_u64())
}

fn felts_hex(felts: &[Felt]) -> Vec<String> {
    felts.iter().copied().map(felt_hex).collect()
}

fn word_hex(w: Word) -> Vec<String> {
    felts_hex(w.as_elements())
}

/// 32-byte big-endian wire encoding of a u128-sized uint256 value.
fn u256_be_from_u128(x: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&x.to_be_bytes());
    out
}

/// The wire's 8 u32-LE limbs of a 32-byte region (limb i = LE u32 of bytes 4i..4i+4).
fn le_limbs(b: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap()))
}

fn packed(bytes: &[u8]) -> Vec<Felt> {
    bytes_to_packed_u32_elements(bytes)
}

fn poseidon2_key(bytes32: &[u8; 32]) -> Word {
    Word::from(Hasher::hash_elements(&packed(bytes32)))
}

// uint256 → AssetAmount reducer entries
// ================================================================================================

#[allow(clippy::too_many_arguments)]
fn amt_accept(id: &str, tv: &[&str], x: u128, scale_exp: u32, derivation: &str) -> Value {
    let b = u256_be_from_u128(x);
    let y = x / 10u128.pow(scale_exp);
    assert!(y <= ASSET_AMOUNT_MAX, "{id}: accept vector must be within the cap");
    json!({
        "id": id, "tv": tv, "kind": "accept",
        "uint256_be": hex_bytes(&b), "le_limbs": le_limbs(&b), "scale_exp": scale_exp,
        "expected_y": y.to_string(),
        "cite": "EL E-16 (:91), E-7 (:82); CIR-FEE-3 (:116)",
        "derivation": derivation,
    })
}

fn amt_reject(
    id: &str,
    tv: &[&str],
    b: [u8; 32],
    scale_exp: u32,
    variant: &str,
    masm_err: &str,
    cite: &str,
    derivation: &str,
) -> Value {
    json!({
        "id": id, "tv": tv, "kind": "reject",
        "uint256_be": hex_bytes(&b), "le_limbs": le_limbs(&b), "scale_exp": scale_exp,
        "expected_variant": variant, "masm_err": masm_err,
        "cite": cite, "derivation": derivation,
    })
}

// DepositIntent entries
// ================================================================================================

struct IntentSpec {
    magic: u32,
    version: u32,
    amount: [u8; 32],
    remote_domain: u32,
    remote_token: [u8; 32],
    remote_recipient: [u8; 32],
    local_token: [u8; 32],
    local_depositor: [u8; 32],
    max_fee: [u8; 32],
    nonce: [u8; 32],
    hook_data: Vec<u8>,
    /// When set, the encoded hookDataLen field diverges from `hook_data.len()`
    /// (the TV-DI-6 length-mismatch construction).
    hook_data_len_override: Option<u32>,
}

fn pattern32(base: u8) -> [u8; 32] {
    core::array::from_fn(|i| base.wrapping_add(i as u8))
}

impl IntentSpec {
    fn base(remote_recipient: [u8; 32]) -> Self {
        Self {
            magic: 0x5a2e_0acd, // CIRCLE-DATA-SCHEMAS.md:21
            version: 1,         // :22
            amount: u256_be_from_u128(1_000_000),
            remote_domain: 7,
            remote_token: pattern32(0xa0),
            remote_recipient,
            local_token: pattern32(0xb0),
            local_depositor: pattern32(0xc0),
            max_fee: u256_be_from_u128(2_000_000),
            nonce: pattern32(0xd0),
            hook_data: Vec::new(),
            hook_data_len_override: None,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(240 + self.hook_data.len());
        out.extend_from_slice(&self.magic.to_be_bytes()); // @0
        out.extend_from_slice(&self.version.to_be_bytes()); // @4
        out.extend_from_slice(&self.amount); // @8
        out.extend_from_slice(&self.remote_domain.to_be_bytes()); // @40
        out.extend_from_slice(&self.remote_token); // @44
        out.extend_from_slice(&self.remote_recipient); // @76
        out.extend_from_slice(&self.local_token); // @108
        out.extend_from_slice(&self.local_depositor); // @140
        out.extend_from_slice(&self.max_fee); // @172
        out.extend_from_slice(&self.nonce); // @204
        let hdl = self.hook_data_len_override.unwrap_or(self.hook_data.len() as u32);
        out.extend_from_slice(&hdl.to_be_bytes()); // @236
        out.extend_from_slice(&self.hook_data); // @240
        assert_eq!(out.len(), 240 + self.hook_data.len());
        out
    }
}

/// Per-field felt offsets within the packed preimage (byte offset / 4; C-10 packing).
const FIELD_FELT_OFFS: [(&str, usize, usize); 12] = [
    ("magic", 0, 1),
    ("version", 1, 1),
    ("amount", 2, 8),
    ("remote_domain", 10, 1),
    ("remote_token", 11, 8),
    ("remote_recipient", 19, 8),
    ("local_token", 27, 8),
    ("local_depositor", 35, 8),
    ("max_fee", 43, 8),
    ("nonce", 51, 8),
    ("hook_data_len", 59, 1),
    ("hook_data", 60, 0), // length = ceil(hookDataLen/4), variable
];

fn di_accept(id: &str, tv: &[&str], spec: &IntentSpec, derivation: &str) -> Value {
    let bytes = spec.encode();
    let preimage = packed(&bytes);
    let hook_felts = preimage.len() - 60;
    let packed_fields: Vec<Value> = FIELD_FELT_OFFS
        .iter()
        .map(|(name, off, len)| {
            let len = if *name == "hook_data" { hook_felts } else { *len };
            json!({
                "name": name, "felt_off": off,
                "felts": felts_hex(&preimage[*off..*off + len]),
            })
        })
        .collect();
    json!({
        "id": id, "tv": tv, "kind": "accept",
        "bytes_hex": hex_bytes(&bytes),
        "preimage_felts": felts_hex(&preimage),
        "len_felts": preimage.len(),
        "fields": {
            "magic": spec.magic, "version": spec.version,
            "remote_domain": spec.remote_domain,
            "hook_data_len": spec.hook_data.len() as u32,
            "amount_hex": hex_bytes(&spec.amount),
            "remote_token_hex": hex_bytes(&spec.remote_token),
            "remote_recipient_hex": hex_bytes(&spec.remote_recipient),
            "local_token_hex": hex_bytes(&spec.local_token),
            "local_depositor_hex": hex_bytes(&spec.local_depositor),
            "max_fee_hex": hex_bytes(&spec.max_fee),
            "nonce_hex": hex_bytes(&spec.nonce),
            "packed": packed_fields,
            "remote_token_felts": felts_hex(&preimage[11..19]),
        },
        "cite": "DC-1 (CIRCLE-DATA-SCHEMAS.md:21-35); C-10 (:85)",
        "derivation": derivation,
    })
}

fn di_reject(
    id: &str,
    tv: &[&str],
    bytes: &[u8],
    variant: &str,
    masm_err: Option<&str>,
    cite: &str,
    derivation: &str,
) -> Value {
    let preimage = packed(bytes);
    json!({
        "id": id, "tv": tv, "kind": "reject",
        "bytes_hex": hex_bytes(bytes),
        "preimage_felts": felts_hex(&preimage),
        "len_felts": preimage.len(),
        "expected_variant": variant, "masm_err": masm_err,
        "cite": cite, "derivation": derivation,
    })
}

fn main() {
    // ---- b32 family -------------------------------------------------------------------
    let b32_inputs: [(&str, [u8; 32], &str); 3] = [
        ("b32-pos-1", [0u8; 32], "all-zero bytes32"),
        ("b32-pos-2", [0xffu8; 32], "all-0xff bytes32"),
        ("b32-pos-3", core::array::from_fn(|i| i as u8), "bytes 0x00..0x1f"),
    ];
    let mut b32: Vec<Value> = b32_inputs
        .iter()
        .map(|(id, b, what)| {
            json!({
                "id": id, "tv": ["TV-B32-1", "TV-B32-3", "TV-B32-4", "TV-DUAL-1"],
                "bytes32": hex_bytes(b),
                "packed_felts": felts_hex(&packed(b)),
                "expected_key": word_hex(poseidon2_key(b)),
                "cite": "EL E-4 (:79), E-6 (:81), E-12 (:87), E-13 (:88)",
                "derivation": format!(
                    "{what}; key = Hasher::hash_elements(bytes_to_packed_u32_elements(b)) @ protocol v0.15.3 (gen_vectors)"
                ),
            })
        })
        .collect();
    // limb >= p: the first 8-byte LE limb is u64::MAX (> p = 2^64 - 2^32 + 1).
    let mut ge_p = [0u8; 32];
    ge_p[..8].copy_from_slice(&[0xff; 8]);
    for (i, byte) in ge_p[8..].iter_mut().enumerate() {
        *byte = i as u8;
    }
    b32.push(json!({
        "id": "b32-rej-limb-ge-p", "tv": ["TV-B32-2", "TV-DUAL-1"],
        "bytes32": hex_bytes(&ge_p),
        "packed_felts": felts_hex(&packed(&ge_p)),
        "expected_key": word_hex(poseidon2_key(&ge_p)),
        "lossless_error": "LimbOutOfField",
        "cite": "EL E-3 (:78); C-5 (ARCHITECTURE-DECISIONS-AND-CAVEATS.md:58-61)",
        "derivation": "first 8-byte LE limb = u64::MAX >= p, so the fallible native path must reject while Option B hashes; key computed @ v0.15.3",
    }));

    // ---- amt family -------------------------------------------------------------------
    let max = ASSET_AMOUNT_MAX;
    let mut amt = vec![
        amt_accept("amt-pos-1", &["TV-AMT-1", "TV-DUAL-2"], 1_000_000, 6, "x = 10^6, y = 1"),
        amt_accept(
            "amt-pos-2",
            &["TV-AMT-1", "TV-DUAL-2"],
            123_456_789_012 * 1_000_000,
            6,
            "x = 123456789012 * 10^6, y = 123456789012",
        ),
        amt_accept("amt-pos-3", &["TV-AMT-1", "TV-DUAL-2"], 42, 0, "scale 0: y = x = 42"),
        amt_accept(
            "amt-pos-4",
            &["TV-AMT-1", "TV-DUAL-2"],
            5 * 10u128.pow(18),
            18,
            "scale 18: x = 5 * 10^18, y = 5",
        ),
        amt_accept(
            "amt-cap-accept",
            &["TV-AMT-2", "TV-DUAL-2"],
            max * 1_000_000,
            6,
            "cap boundary: x = (2^63 - 2^31) * 10^6, y = AssetAmount::MAX exactly (E-7)",
        ),
        amt_reject(
            "amt-rej-cap",
            &["TV-AMT-3", "TV-DUAL-2"],
            u256_be_from_u128((max + 1) * 1_000_000),
            6,
            "AmountOverCap",
            "ERR_AMOUNT_OVER_CAP",
            "EL E-7 (:82); 04 COMPONENT-SPEC :313",
            "x = (2^63 - 2^31 + 1) * 10^6, post-scale y = MAX + 1 must reject (no saturation)",
        ),
        {
            // bit 130 set => high four limbs nonzero (> 2^128). BE byte 15, bit 2.
            let mut b = [0u8; 32];
            b[15] = 0x04;
            amt_reject(
                "amt-rej-limb-overflow",
                &["TV-AMT-4", "TV-DUAL-2"],
                b,
                6,
                "AmountTooLarge",
                "ERR_X_TOO_LARGE",
                "EL E-16 (:91)",
                "x = 2^130: high-4 limbs nonzero must reject (limb-overflow edge)",
            )
        },
        amt_reject(
            "amt-rej-scale-overflow",
            &["TV-AMT-7", "TV-DUAL-2"],
            u256_be_from_u128(1_000_000),
            20,
            "ScaleExpTooLarge",
            "ERR_SCALE_EXP_TOO_LARGE",
            "C-6 (:63-66); MIDEN-CRYPTO-AND-ENCODING.md:133; 04 :294 (scale 0..=18)",
            "scale_exp = 20 exceeds the 0..=18 bound / overflows 10^scale in u64",
        ),
    ];
    // reduced-ge pairs (TV-AMT-5).
    for (id, a, b, result, note) in [
        ("amt-ge-lt", 1_000_000u128, 2_000_000u128, false, "1 < 2 after reduction"),
        ("amt-ge-eq", 3_000_000, 3_000_000, true, "3 == 3 after reduction"),
        ("amt-ge-gt", 5_000_000, 2_000_000, true, "5 > 2 after reduction"),
    ] {
        let ab = u256_be_from_u128(a);
        let bb = u256_be_from_u128(b);
        amt.push(json!({
            "id": id, "tv": ["TV-AMT-5"], "kind": "ge",
            "uint256_be": hex_bytes(&ab), "le_limbs": le_limbs(&ab),
            "b_uint256_be": hex_bytes(&bb), "b_le_limbs": le_limbs(&bb),
            "scale_exp": 6, "ge_result": result,
            "cite": "CIR-MINT-PRE-8/9 (:47-48); D5b (ARCHITECTURE-FLOWS.md:50)",
            "derivation": note,
        }));
    }
    // dust (TV-AMT-6).
    let dust_b = u256_be_from_u128(1_500_123);
    amt.push(json!({
        "id": "amt-dust", "tv": ["TV-AMT-6"], "kind": "dust",
        "uint256_be": hex_bytes(&dust_b), "le_limbs": le_limbs(&dust_b), "scale_exp": 6,
        "expected_y": "1", "expected_dust": "500123",
        "cite": "EL E-16 (:91); DEV-5 (CIRCLE-MIDEN-DEVIATIONS-AND-QUESTIONS.md:44-49)",
        "derivation": "x = 1500123, y = floor(x/10^6) = 1, z = 500123; dust POLICY is REQUIRES CIRCLE CONFIRMATION (DEV-5)",
    }));
    // masm-only u32 guard staging (additive; G-MASM N11 — not a TV coverage claim).
    amt.push(json!({
        "id": "amt-guard-limb-not-u32", "tv": [], "kind": "guard", "mode": "masm-only",
        "scale_exp": 6,
        "staging_felts": ["0x1", "0x0", "0x0", "0x0", "0x0", "0x100000000", "0x0", "0x0"],
        "masm_err": "ERR_FELT_OUT_OF_FIELD",
        "cite": "BUILDER-GATES G-MASM (:28, u32-assert-before-u32-ops); 04 :237 (E-14 intent)",
        "derivation": "staged 'limb' felt = 2^32 is not a valid u32; the reducer's input guard must trap (unrepresentable in the Rust [u32;8] API)",
    }));

    // ---- aid family -------------------------------------------------------------------
    let ids: Vec<miden_protocol::account::AccountId> = (1u8..=3)
        .map(|seed| AccountIdBuilder::new().build_with_seed([seed; 32]))
        .collect();
    let mut aid: Vec<Value> = Vec::new();
    for (n, id) in ids.iter().enumerate() {
        let ser = id.to_bytes();
        assert_eq!(ser.len(), 15, "AccountId::SERIALIZED_SIZE");
        let mut b32_bytes = [0u8; 32];
        b32_bytes[..15].copy_from_slice(&ser);
        let prefix: Felt = id.prefix().as_felt();
        let suffix: Felt = id.suffix();
        aid.push(json!({
            "id": format!("aid-rt-{}", n + 1),
            "tv": ["TV-AID-1", "TV-AID-4"],
            "bytes32": hex_bytes(&b32_bytes),
            "prefix_felt": felt_hex(prefix), "suffix_felt": felt_hex(suffix),
            "cite": "EL E-9 (:84), E-10 (:85); MIDEN-CRYPTO-AND-ENCODING.md:148-157; DEV-10 + IMPL-ACCOUNTID-LAYOUT (draft layout, REQUIRES CIRCLE CONFIRMATION)",
            "derivation": format!(
                "AccountIdBuilder::new().build_with_seed([{}; 32]) @ v0.15.3; bytes32[..15] = canonical 15-byte serialization, rest zero (draft layout)",
                n + 1
            ),
        }));
    }
    // out-of-range: valid id bytes with padding violated at byte 20.
    {
        let ser = ids[0].to_bytes();
        let mut bad = [0u8; 32];
        bad[..15].copy_from_slice(&ser);
        bad[20] = 0x01;
        aid.push(json!({
            "id": "aid-rej-out-of-range", "tv": ["TV-AID-2"],
            "bytes32": hex_bytes(&bad),
            "expected_variant": "AccountIdOutOfRange",
            "cite": "EL E-9 (:84), E-10 (:85)",
            "derivation": "aid-rt-1 bytes32 with byte[20] = 0x01 (outside the 15-byte region)",
        }));
    }
    // non-canonical: in-region bytes that do not deserialize to an AccountId.
    {
        use miden_protocol::utils::serde::Deserializable;
        let candidate = [0xffu8; 15];
        assert!(
            miden_protocol::account::AccountId::read_from_bytes(&candidate).is_err(),
            "generator invariant: candidate must NOT deserialize to a canonical AccountId"
        );
        let mut bad = [0u8; 32];
        bad[..15].copy_from_slice(&candidate);
        aid.push(json!({
            "id": "aid-rej-non-canonical", "tv": ["TV-AID-2"],
            "bytes32": hex_bytes(&bad),
            "expected_variant": "NonCanonicalAccountId",
            "cite": "EL E-9 (:84)",
            "derivation": "15 bytes of 0xff inside the region; verified rejected by AccountId::read_from_bytes @ v0.15.3",
        }));
    }
    let recipient_b32: [u8; 32] = {
        let ser = ids[0].to_bytes();
        let mut b = [0u8; 32];
        b[..15].copy_from_slice(&ser);
        b
    };

    // ---- di family --------------------------------------------------------------------
    let mut di: Vec<Value> = Vec::new();
    {
        let mut spec = IntentSpec::base(recipient_b32);
        spec.hook_data = (0..10u8).map(|i| 0xe0 + i).collect();
        di.push(di_accept(
            "di-pos-hookdata",
            &["TV-DI-1", "TV-DI-7", "TV-DI-8", "TV-DUAL-3"],
            &spec,
            "valid intent, hookDataLen = 10 (3 hookData felts; total 63 felts)",
        ));
    }
    {
        let spec = IntentSpec::base(recipient_b32);
        di.push(di_accept(
            "di-pos-empty-hookdata",
            &["TV-DI-1", "TV-DI-7", "TV-DUAL-3"],
            &spec,
            "valid intent, hookDataLen = 0 (exactly the 60-felt header)",
        ));
    }
    let base_bytes = IntentSpec::base(recipient_b32).encode();
    {
        let mut spec = IntentSpec::base(recipient_b32);
        spec.magic = 0xdead_beef;
        di.push(di_reject(
            "di-rej-bad-magic",
            &["TV-DI-2", "TV-DUAL-3"],
            &spec.encode(),
            "BadMagic",
            Some("ERR_DI_BAD_MAGIC"),
            "CIR-MINT-PRE-2 (:41); 04 :238",
            "magic = 0xdeadbeef != 0x5a2e0acd",
        ));
    }
    {
        let mut spec = IntentSpec::base(recipient_b32);
        spec.version = 2;
        di.push(di_reject(
            "di-rej-bad-version",
            &["TV-DI-3", "TV-DUAL-3"],
            &spec.encode(),
            "BadVersion",
            Some("ERR_DI_BAD_VERSION"),
            "CIR-MINT-PRE-3 (:42); 04 :239",
            "version = 2 != 1",
        ));
    }
    for (id, tv, field, variant) in [
        ("di-rej-zero-amount", "TV-DI-4", "amount", "ZeroField:Amount"),
        ("di-rej-zero-local-token", "TV-DI-5", "local_token", "ZeroField:LocalToken"),
        ("di-rej-zero-local-depositor", "TV-DI-5", "local_depositor", "ZeroField:LocalDepositor"),
    ] {
        let mut spec = IntentSpec::base(recipient_b32);
        match field {
            "amount" => spec.amount = [0u8; 32],
            "local_token" => spec.local_token = [0u8; 32],
            "local_depositor" => spec.local_depositor = [0u8; 32],
            _ => unreachable!(),
        }
        di.push(di_reject(
            id,
            &[tv, "TV-DUAL-3"],
            &spec.encode(),
            variant,
            Some("ERR_DI_ZERO_FIELD"),
            "CIR-MINT-PRE-4/5 (:43-44); 04 :240",
            &format!("{field} = 0 must reject"),
        ));
    }
    {
        let mut spec = IntentSpec::base(recipient_b32);
        spec.hook_data = vec![0xee; 4];
        spec.hook_data_len_override = Some(10);
        di.push(di_reject(
            "di-rej-length-mismatch",
            &["TV-DI-6", "TV-DUAL-3"],
            &spec.encode(),
            "LengthMismatch",
            Some("ERR_DI_LENGTH"),
            "CIR-MINT-PRE-11 (:50); 04 :241",
            "hookDataLen field = 10 but only 4 hookData bytes appended (total 244 != 250)",
        ));
    }
    di.push(di_reject(
        "di-rej-truncated",
        &["TV-DI-6", "TV-DUAL-3"],
        &base_bytes[..100],
        "TruncatedHeader",
        Some("ERR_DI_LENGTH"),
        "CIRCLE-DATA-SCHEMAS.md:35; 04 :241 (MASM folds both length violations into ERR_DI_LENGTH)",
        "first 100 bytes only (< 240-byte header; 25 staged felts < 60)",
    ));
    {
        let mut spec = IntentSpec::base(recipient_b32);
        let hook_len = (1024 - 60) * 4 + 4; // 3860 bytes => 965 felts => 1025 > 1024
        spec.hook_data = vec![0xab; hook_len];
        di.push(di_reject(
            "di-rej-hookdata-overflow",
            &["TV-DI-7"],
            &spec.encode(),
            "HookDataTooLarge",
            None, // Rust-only: the 1024-felt bound lives in the Rust packer (04:344)
            "C-10 (:85); N-4 (EL:100); DEV-6 (REQUIRES CIRCLE CONFIRMATION)",
            "hookDataLen = 3860 => 60 + 965 = 1025 felts > 1024 NoteStorage bound",
        ));
    }
    {
        // masm-only: wrong len_felts parameter (unrepresentable in the Rust byte API).
        let preimage = packed(&base_bytes);
        di.push(json!({
            "id": "di-rej-felt-len", "tv": ["TV-DUAL-3"], "kind": "reject",
            "mode": "masm-only",
            "preimage_felts": felts_hex(&preimage),
            "len_felts": preimage.len(),
            "staging_len_felts": 59,
            "expected_variant": "LengthMismatch", "masm_err": "ERR_DI_LENGTH",
            "cite": "04 :348 (parser input contract)",
            "derivation": "valid 60-felt preimage staged with len_felts = 59; the felt-length relation must trap",
        }));
    }

    let file = json!({ "version": 1, "families": { "b32": b32, "amt": amt, "aid": aid, "di": di } });
    let path = xusdc_encoding::vectors_path();
    std::fs::create_dir_all(path.parent().unwrap()).expect("create vectors dir");
    std::fs::write(&path, serde_json::to_string_pretty(&file).expect("serialize") + "\n")
        .expect("write artifact");
    println!("wrote {} ({} bytes)", path.display(), std::fs::metadata(&path).unwrap().len());
}
