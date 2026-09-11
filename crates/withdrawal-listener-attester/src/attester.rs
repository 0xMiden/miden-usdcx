//! Signs Circle's 32-byte digest and assembles a verified signer quorum.
//! Signatures use secp256k1 with Ethereum recovery bytes 27 or 28. [`assemble_quorum`] checks
//! recovered addresses, threshold, strict ordering, and uniqueness.
//!
//! The supplied digest is signed without rehashing. Its exact derivation remains OPEN with Circle.

use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
pub use k256::SecretKey;
use sha3::{Digest, Keccak256};

use crate::error::{QuorumError, SignError, SignatureError};

/// Required signing-digest length in bytes.
pub const DIGEST_LEN: usize = 32;

/// Signature length: 32-byte r, 32-byte s, and one recovery byte.
pub const SIGNATURE_LEN: usize = 65;

/// Ethereum signer-address length in bytes.
pub const ADDRESS_LEN: usize = 20;

/// Offset converting recovery IDs 0 and 1 to Ethereum values 27 and 28.
pub const EVM_V_OFFSET: u8 = 27;

/// The ONLY two `v` bytes OpenZeppelin `ECDSA.recover` on the source chain accepts. The x-reduced
/// recovery ids `2`/`3` (wire `v = 29`/`30`) are deliberately NOT here — they recover locally but
/// the source-chain verifier rejects them, so a bundle counting one would fail at the fund-release
/// boundary. [`recover_address`] gates on exactly these values.
pub const EVM_V_VALUES: [u8; 2] = [EVM_V_OFFSET, EVM_V_OFFSET + 1];

/// Encodes a k256 recovery id as the Ethereum `v` byte, or `None` when it has no EVM
/// representation.
///
/// `Some(27 + b)` for a non-x-reduced recovery id `b ∈ {0, 1}`; `None` for an x-reduced id `{2,
/// 3}`, which OpenZeppelin `ECDSA.recover` cannot accept. This is the single source of truth for
/// the `v` range: [`sign`] uses it to REFUSE emitting a `v = 29`/`30` signature, and
/// [`recover_address`] enforces the same range on the way back in.
pub fn evm_v_from_recovery_id(recovery_id: RecoveryId) -> Option<u8> {
    match recovery_id.to_byte() {
        b @ (0 | 1) => Some(EVM_V_OFFSET + b),
        _ => None, // x-reduced (2/3): no 27/28 representation
    }
}

/// Circle's `MIN_SIGNATURE_THRESHOLD` (`CIRCLE-DATA-SCHEMAS.md:196`; `CIRCLE-API-SURFACE.md:184`
/// `minItems 2`). Circle's source-chain verifier is **exactly-threshold** — a `/v1/withdraw` batch
/// carries exactly this many `burnSignatures`, no fewer and no more (`Attestable.sol:75,333-381`);
/// [`assemble_quorum`] enforces that exact count. A single-key set is a non-gating local primitive
/// that is never submitted.
pub const MIN_SIGNATURE_THRESHOLD: usize = 2;

/// A 65-byte `r‖s‖v` burn signature — the exact wire form `burnSignatures[]` carries.
///
/// A newtype, not a bare `[u8; 65]`, so the shape is guaranteed by construction: [`from_bytes`] is
/// the only fallible entry point and it rejects anything that is not exactly 65 bytes (a DER blob,
/// a 64-byte `r‖s` with the recovery id dropped). Length is a wire-shape concern only — whether the
/// signature is VALID (verifies to its claimed signer) is established by [`assemble_quorum`], which
/// has the digest; a `Signature65` on its own asserts nothing about who signed what.
///
/// [`from_bytes`]: Signature65::from_bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature65([u8; SIGNATURE_LEN]);

impl Signature65 {
    /// Wraps an already-correctly-sized array (the [`sign`] output path, where the 65 bytes are
    /// assembled in-crate and cannot be the wrong length).
    pub fn from_array(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// Builds a signature from raw wire bytes, rejecting any length other than 65
    /// ([`SignatureError::Length`]). This is the boundary a signature coming OFF the wire (or out
    /// of a fixture) must pass through — a non-65-byte or DER-encoded blob never becomes a
    /// `Signature65`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array: [u8; SIGNATURE_LEN] = bytes.try_into().map_err(|_| SignatureError::Length {
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// The 65 raw bytes `r‖s‖v`.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// `r` — bytes 0..32.
    pub fn r(&self) -> [u8; 32] {
        self.0[..32].try_into().expect("32 bytes")
    }

    /// `s` — bytes 32..64.
    pub fn s(&self) -> [u8; 32] {
        self.0[32..64].try_into().expect("32 bytes")
    }

    /// `v` — the EVM recovery id, byte 64 (`27`/`28`).
    pub fn v(&self) -> u8 {
        self.0[SIGNATURE_LEN - 1]
    }

    /// The `0x`-prefixed lower-case hex the `burnSignatures[]` wire carries (matches the OpenAPI
    /// `^0x[a-fA-F0-9]*$` pattern).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// A 20-byte Ethereum-style signer address — the value `ECDSA.recover(digest, signature)` yields on
/// the source chain (`CIRCLE-DATA-SCHEMAS.md:46`,`:193`), and the key the quorum bundle is ordered
/// by.
///
/// `Ord` is the plain big-endian byte order — the same total order Circle's ascending-address check
/// uses. A caller pairs each signature with the address it EXPECTS signed it (the registered
/// attester); [`assemble_quorum`] then proves that expectation by recovering the real signer from
/// the signature and the digest, so a freely-constructed [`Address::new`] can never smuggle an
/// unauthorized signature into a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// Wraps 20 raw address bytes.
    pub fn new(bytes: [u8; ADDRESS_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses a `0x`-prefixed 20-byte hex address — the form an operator writes a registered
    /// attester as in the config allowlist.
    ///
    /// # Errors
    /// [`AddressParseError`] — a missing `0x` prefix, a non-hex digit, or a length other than 20
    /// bytes.
    pub fn from_hex(s: &str) -> Result<Self, AddressParseError> {
        let body = s.strip_prefix("0x").ok_or(AddressParseError)?;
        let bytes = hex::decode(body).map_err(|_| AddressParseError)?;
        let array: [u8; ADDRESS_LEN] =
            bytes.as_slice().try_into().map_err(|_| AddressParseError)?;
        Ok(Self(array))
    }

    /// The 20 raw address bytes.
    pub fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }

    /// The `0x`-prefixed lower-case hex rendering (the same form [`Self::from_hex`] parses).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// A string that is not a `0x`-prefixed 20-byte hex Ethereum-style address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressParseError;

impl core::fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not a 0x-prefixed 20-byte hex address")
    }
}

impl core::error::Error for AddressParseError {}

/// The configured set of **registered attester addresses** — the off-chain mirror of Circle's
/// on-chain `attesters[addr]` registry, and the allowlist the pre-submit fund-safety gate
/// ([`authorize_submission`](crate::withdrawal_api::authorize_submission)) checks every recovered
/// signer against.
///
/// It is a SET (deduplicated, ordered by address), because membership — not order or multiplicity
/// is the only question the gate asks it. An EMPTY allowlist is a legal value that means exactly
/// what it says: no attester is registered, so the gate must fail closed rather than authorize an
/// unbounded signer set.
///
/// serde renders it as a sequence of `0x`-hex address strings (the form an operator writes), so a
/// config file can carry the registry directly; a malformed address fails the load rather than
/// silently dropping an attester.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttesterAllowlist {
    addresses: std::collections::BTreeSet<Address>,
}

impl AttesterAllowlist {
    /// The allowlist of the given addresses (deduplicated).
    pub fn new(addresses: impl IntoIterator<Item = Address>) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
        }
    }

    /// Whether `address` is a registered attester.
    pub fn contains(&self, address: &Address) -> bool {
        self.addresses.contains(address)
    }

    /// Whether NO attester is registered — the fail-closed condition the gate refuses on.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// How many attesters are registered.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// The registered addresses, in ascending order.
    pub fn addresses(&self) -> impl Iterator<Item = &Address> {
        self.addresses.iter()
    }
}

impl serde::Serialize for AttesterAllowlist {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(self.addresses.len()))?;
        for address in &self.addresses {
            seq.serialize_element(&address.to_hex())?;
        }
        seq.end()
    }
}

impl<'de> serde::Deserialize<'de> for AttesterAllowlist {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hexes = Vec::<String>::deserialize(d)?;
        let mut addresses = std::collections::BTreeSet::new();
        for hex in hexes {
            addresses.insert(Address::from_hex(&hex).map_err(serde::de::Error::custom)?);
        }
        Ok(Self { addresses })
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Signs Circle's opaque `messageHashToSign` with `key`, producing the 65-byte `r‖s‖v` burn
/// signature — burn signing happens off-chain over Circle's opaque digest.
///
/// `msg_hash_to_sign` is the digest Circle returned, treated as **opaque** (its exact derivation is
/// still OPEN with Circle): it is signed AS-IS via `sign_prehash` — no local re-hashing, no EIP-712
/// re-derivation, no domain separator. The 65 bytes are `r‖s‖v` with `v` the **EVM** recovery id
/// `27`/`28` ([`EVM_V_OFFSET`]), the form Circle's source-chain `ECDSA.recover` requires. k256
/// signing is low-`s`-normalized, so the EVM malleability check passes too. secp256k1 ECDSA here is
/// RFC 6979 deterministic, so a given `(digest, key)` always yields the same signature.
///
/// # Errors
///
/// * [`SignError::DigestLength`] — `msg_hash_to_sign` is not exactly 32 bytes. The digest is
///   opaque; `sign` will not hash or pad it into shape.
/// * [`SignError::Ecdsa`] — `k256` refused to sign (not reachable with a valid key and a 32-byte
///   prehash; surfaced as a typed error rather than a `panic`).
///
/// Single-key signing is a non-gating local primitive and is NEVER submitted to Circle on its own;
/// see [`assemble_quorum`].
pub fn sign(msg_hash_to_sign: &[u8], key: &SecretKey) -> Result<Signature65, SignError> {
    if msg_hash_to_sign.len() != DIGEST_LEN {
        return Err(SignError::DigestLength {
            actual: msg_hash_to_sign.len(),
        });
    }

    let signing_key = SigningKey::from(key.clone());
    let (signature, recovery_id): (K256Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(msg_hash_to_sign)
        .map_err(|e| SignError::Ecdsa {
            source: crate::error::Cause::new(e),
        })?;

    // Refuse to emit a signature whose recovery id has no EVM `v` — an x-reduced `2`/`3` would become
    // wire `v = 29`/`30`, which the source-chain `ECDSA.recover` rejects. (Unreachable for real
    // inputs: k256 low-`s`-normalizes and an x-reduced `r` has probability ≈ 2^-128.)
    let v = evm_v_from_recovery_id(recovery_id).ok_or(SignError::UnrepresentableRecoveryId {
        recovery_id: recovery_id.to_byte(),
    })?;

    let mut out = [0u8; SIGNATURE_LEN];
    out[..64].copy_from_slice(signature.to_bytes().as_ref()); // r‖s, 64 big-endian bytes
    out[SIGNATURE_LEN - 1] = v; // EVM v ∈ {27, 28}
    Ok(Signature65::from_array(out))
}

/// The 20-byte Ethereum-style address of `key`'s public key — the address
/// [`recover_address`] yields for every signature `key` produces over any digest.
///
/// It exists so a caller that HOLDS the key does not have to sign-then-recover to learn which
/// signer its signature will be attributed to. That matters at exactly one place: the
/// orchestration's signing step pairs each signature with the address it claims signed it, and
/// [`assemble_quorum`] then proves the claim by recovery. Deriving the claim from the key rather
/// than from the signature keeps the two sides of that proof independent — a bug in one cannot
/// cancel out a bug in the other — and it is total, so the signing path has no "the key I just
/// signed with does not recover" branch to invent an error for.
///
/// The derivation is `keccak256(uncompressed pubkey X‖Y)[12..]`, shared with [`recover_address`] so
/// the two cannot drift onto different address rules.
pub fn address_of(key: &SecretKey) -> Address {
    address_from_verifying_key(SigningKey::from(key.clone()).verifying_key())
}

/// `keccak256(uncompressed pubkey X‖Y)[12..]` — the ONE place a secp256k1 public key becomes an
/// Ethereum-style address, so recovery and key-side derivation cannot disagree.
fn address_from_verifying_key(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false); // 0x04 ‖ X(32) ‖ Y(32)
    let hash: [u8; 32] = Keccak256::digest(&point.as_bytes()[1..]).into();
    let mut addr = [0u8; ADDRESS_LEN];
    addr.copy_from_slice(&hash[12..]);
    Address::new(addr)
}

/// Recovers the 20-byte Ethereum signer address from `digest` + a 65-byte `r‖s‖v` signature — the
/// exact `ECDSA.recover(digest, signature)` Circle runs on the source chain: decode `r‖s`, read the
/// EVM `v` (`27`/`28`) back to a k256 recovery id, recover the secp256k1 pubkey over `digest`, then
/// take `keccak256(uncompressed pubkey X‖Y)[12..]`.
///
/// Returns `None` for anything that does not recover — a `v` outside `27`/`28` (a raw `0`/`1`, an
/// x-reduced `29`/`30`, or garbage), an `r`/`s` that is not a valid signature, or a digest the
/// signature does not cover. The `v` range is enforced STRUCTURALLY against [`EVM_V_VALUES`] before
/// any recovery is attempted, so a `v = 29`/`30` (recovery id `2`/`3`) can never verify here even
/// though k256 could recover it — it is exactly the value Circle's source-chain verifier rejects. A
/// `None` here is "this signature does not verify", which [`assemble_quorum`] turns into
/// [`QuorumError::SignatureDoesNotVerify`].
pub fn recover_address(digest: &[u8; DIGEST_LEN], sig: &Signature65) -> Option<Address> {
    // Only the EVM `v` bytes 27/28 are accepted — NOT the full k256 recovery-id range 0..=3. This is
    // the fix's core: `v - 27` on a 29/30 wire byte would otherwise be a valid x-reduced recovery id
    // (2/3) that recovers locally but is rejected on the source chain.
    let recovery_id_byte = match sig.v() {
        v if v == EVM_V_VALUES[0] => 0,
        v if v == EVM_V_VALUES[1] => 1,
        _ => return None,
    };
    let signature = K256Signature::from_slice(&sig.as_bytes()[..64]).ok()?;
    let recovery_id = RecoveryId::from_byte(recovery_id_byte)?;
    let verifying_key = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id).ok()?;

    Some(address_from_verifying_key(&verifying_key))
}

/// The `burnSignatures[]` bundle **in the exact shape Circle's source-chain verifier requires**
/// exactly [`MIN_SIGNATURE_THRESHOLD`] signatures, strictly ascending by signer address, no
/// duplicate signer, each proven to recover to its claimed signer over the batch digest.
///
/// # Why the shape is a TYPE and not a check someone remembers to run
///
/// The shape is Circle's on-chain rule (`Attestable.sol:75,333-381`), and this crate mirrors it
/// OFF-chain so a bundle Circle would reject fails here rather than at the fund-release boundary.
/// But the wire type that carries the bundle
/// [`WithdrawBatch`](crate::circle::schema::WithdrawBatch) — cannot enforce it: `burnSignatures` is
/// a JSON array, its schema says only `minItems: 2`, and the type must stay able to DECODE whatever
/// Circle sends. So `WithdrawBatch::new` accepts three signatures, or two in descending order, or
/// the same signer twice. Every one of those is a submission Circle rejects, and none of them is a
/// shape the wire type can refuse.
///
/// The pre-submit allowlist gate
/// ([`authorize_submission`](crate::withdrawal_api::authorize_submission)) does not close that gap
/// either, and the distinction is worth naming precisely: it checks **membership** — is every
/// recovered signer a registered attester — and membership is not shape. Two signatures from the
/// same registered attester pass membership and fail Circle's verifier.
///
/// This newtype is the seam that binds the two. [`assemble_quorum`]'s full-pass path is its only
/// constructor, and [`build_withdraw_batch`](crate::withdrawal_api::build_withdraw_batch) — the
/// crate's assembly step from signatures to a submittable batch — takes one BY REFERENCE and
/// renders it. So a batch built through the orchestration carries `assemble_quorum`'s shape by
/// construction, rather than by a reviewer noticing that the call happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumBundle {
    signatures: Vec<Signature65>,
}

impl QuorumBundle {
    /// The signatures, in the ascending signer-address order Circle expects.
    pub fn signatures(&self) -> &[Signature65] {
        &self.signatures
    }

    /// How many signatures the bundle carries — always [`MIN_SIGNATURE_THRESHOLD`], since that is
    /// the only count [`assemble_quorum`] mints one for.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Always `false`: an empty bundle is not a shape [`assemble_quorum`] can produce. The accessor
    /// exists because clippy pairs it with [`Self::len`], and it is written out rather than derived
    /// so the guarantee is stated instead of implied.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

/// Assembles the `burnSignatures[]` bundle Circle verifies on the source chain: **exactly
/// [`MIN_SIGNATURE_THRESHOLD`] signatures, each verifying to its claimed signer, ascending
/// signer-address order, no duplicates** (`CIRCLE-DATA-SCHEMAS.md:196`).
///
/// `msg_hash_to_sign` is the same opaque digest [`sign`] signed. Each input pair is a signature and
/// the 20-byte address the caller EXPECTS signed it (the registered attester). On success the
/// addresses are stripped and the signatures are carried, in the SAME order — which, having been
/// validated ascending, is the ascending-address order Circle expects — inside a [`QuorumBundle`],
/// this function's exclusive output type. That bundle is what
/// [`build_withdraw_batch`](crate::withdrawal_api::build_withdraw_batch) requires, so the shape
/// checked here is the shape submitted: a `Vec<Signature65>` assembled some other way has nowhere
/// to go.
///
/// Checks, in order:
///
/// 1. **Exactly-threshold** — `len == MIN_SIGNATURE_THRESHOLD`. Circle's verifier is
///    exactly-threshold (`Attestable.sol:75,333-381`); a single-key set is never submitted, and an
///    over-threshold bundle Circle would reject is caught here rather than at the fund-release
///    boundary.
/// 2. **Each signature verifies to its claimed signer** — [`recover_address`] must yield the
///    claimed address. This is the `ECDSA.recover`-then-authorize step; a signature paired with the
///    wrong address (or one that does not recover at all) is refused.
/// 3. **No duplicate signer** — refused, never de-duplicated.
/// 4. **Strictly ascending by address**.
///
/// # Errors
///
/// * [`QuorumError::BelowThreshold`] / [`QuorumError::AboveThreshold`] — the count is not exactly
///   the threshold.
/// * [`QuorumError::SignatureDoesNotVerify`] — a signature does not recover to its claimed signer.
/// * [`QuorumError::DuplicateSigner`] — an address appears more than once.
/// * [`QuorumError::NotAscending`] — the addresses are not in strictly ascending order.
///
/// Ordering and uniqueness are over the signer ADDRESS, never the pubkey or signature bytes.
pub fn assemble_quorum(
    msg_hash_to_sign: &[u8; DIGEST_LEN],
    sigs: Vec<(Address, Signature65)>,
) -> Result<QuorumBundle, QuorumError> {
    if sigs.len() < MIN_SIGNATURE_THRESHOLD {
        return Err(QuorumError::BelowThreshold {
            have: sigs.len(),
            need: MIN_SIGNATURE_THRESHOLD,
        });
    }
    if sigs.len() > MIN_SIGNATURE_THRESHOLD {
        return Err(QuorumError::AboveThreshold {
            have: sigs.len(),
            need: MIN_SIGNATURE_THRESHOLD,
        });
    }

    // Each signature must recover to its CLAIMED signer over the digest — the `ECDSA.recover`-then-
    // authorize step. A pair the caller mis-attributed (or a signature that does not recover at all)
    // is refused before it can be counted toward the quorum.
    for (i, (claimed, sig)) in sigs.iter().enumerate() {
        match recover_address(msg_hash_to_sign, sig) {
            Some(recovered) if recovered == *claimed => {}
            _ => return Err(QuorumError::SignatureDoesNotVerify { at: i }),
        }
    }

    // Duplicate scan over the FULL set (not just adjacent pairs): a duplicate must be caught wherever
    // it sits, and reported as DuplicateSigner rather than masquerading as an ordering error.
    for i in 0..sigs.len() {
        for j in (i + 1)..sigs.len() {
            if sigs[i].0 == sigs[j].0 {
                return Err(QuorumError::DuplicateSigner { address: sigs[i].0 });
            }
        }
    }

    // Strictly ascending by address. Duplicates are already excluded, so any non-increase here is a
    // genuine ordering violation (descending or otherwise unsorted).
    for i in 1..sigs.len() {
        if sigs[i].0 <= sigs[i - 1].0 {
            return Err(QuorumError::NotAscending { at: i });
        }
    }

    Ok(QuorumBundle {
        signatures: sigs.into_iter().map(|(_, sig)| sig).collect(),
    })
}
