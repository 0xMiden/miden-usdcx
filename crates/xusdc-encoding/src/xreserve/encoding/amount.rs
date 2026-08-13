//! Reducing a deposit's uint256 amount to a Miden asset amount.
//!
//! Circle states deposit amounts as 256-bit values in the source token's smallest units; a Miden
//! fungible asset amount is a `u64` bounded by `AssetAmount::MAX`. Every mint therefore has to
//! cross that gap, and this is the only place it happens: on-chain the faucet does NOT divide,
//! because under `DC-14` the uint256 never reaches the chain at all.
//!
//! The arithmetic is the protocol standards' [`EthAmount::scale_to_asset_amount`], so this crate
//! carries no second implementation of it. What lives here is its adaptation to this crate's error
//! type and the golden vectors that pin the behaviour Circle's numbers depend on. Nothing
//! saturates and nothing truncates silently: every path out is either an exact value or an error.
//!
//! The exact cap, the scale factor, and how much dust rounding may discard are still Circle's to
//! decide. The mechanism is implemented; the numbers it is parameterized with remain open, and
//! nothing here should be read as settling them.

use miden_protocol::asset::AssetAmount;
use miden_standards::interop::eth::EthAmount;
#[cfg(test)]
use primitive_types::U256;

use super::error::EncodingError;

/// uint256 → AssetAmount: `y = floor(x / 10^scale_exp)`, rejecting a scale exponent past 18
/// (`ScaleExpTooLarge`), a quotient wider than a `u64` (`AmountTooLarge`), and a quotient past
/// `AssetAmount::MAX` (`AmountOverCap`). No saturation or clamping.
pub fn uint256_to_asset_amount(
    amount: EthAmount,
    scale_exp: u32,
) -> Result<AssetAmount, EncodingError> {
    let y = amount.scale_to_asset_amount(scale_exp)?;
    // the standards routine bounds the quotient by the maximum fungible amount, which is
    // AssetAmount::MAX, so this conversion only re-states that bound in the type
    AssetAmount::try_from(y).map_err(|_| EncodingError::AmountOverCap)
}

/// The reduced-compare: reduce both operands, then compare (the mint's `amount >= maxFee` check).
///
/// Test-only: it exercises the reduction over the TV-AMT-5 golden-vector rows, which are
/// Rust-fn-only by design; no production path calls it (the on-chain compare is the MASM's).
#[cfg(test)]
pub fn reduced_ge(a: EthAmount, b: EthAmount, scale_exp: u32) -> Result<bool, EncodingError> {
    Ok(uint256_to_asset_amount(a, scale_exp)? >= uint256_to_asset_amount(b, scale_exp)?)
}

/// The non-zero division remainder (dust), surfaced so the caller can apply the
/// dust policy, which `REQUIRES CIRCLE CONFIRMATION`.
///
/// Test-only: it drives the TV-AMT-6 dust golden-vector row (Rust-fn-only by design); the dust
/// policy is unsettled, so no production path consumes the remainder yet.
#[cfg(test)]
pub fn uint256_to_asset_amount_with_dust(
    amount: EthAmount,
    scale_exp: u32,
) -> Result<(AssetAmount, u128), EncodingError> {
    let y = uint256_to_asset_amount(amount, scale_exp)?;
    // the reduction above accepted, so the scale exponent is within 0..=18 and the remainder is
    // strictly below 10^18 — both the divisor and the dust stay far inside their target types
    let divisor = U256::from(10u64.pow(scale_exp));
    let dust = amount.to_u256() % divisor;
    Ok((y, dust.as_u128()))
}

// TESTS — TV-AMT-1..7
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    /// TV-AMT-1 (happy path, written first): in-bound amounts scale correctly
    /// (6-dp primary plus the scale-0 and scale-18 representatives).
    #[test]
    fn tv_amt_1_in_bound_scale6() {
        let v = load();
        for vec in v
            .families
            .amt
            .iter()
            .filter(|v| v.kind == "accept" && v.id != "amt-cap-accept")
        {
            let y = uint256_to_asset_amount(vec.amount(), vec.scale_exp)
                .unwrap_or_else(|e| panic!("vector {}: must accept, got {e}", vec.id));
            assert_eq!(
                y,
                vec.expected_amount(),
                "vector {}: reduced amount",
                vec.id
            );
        }
    }

    /// TV-AMT-2 (boundary): exactly `AssetAmount::MAX = 2^63 − 2^31` post-scale is
    /// accepted at the cap (required cap-boundary edge).
    #[test]
    fn tv_amt_2_cap_boundary_accept() {
        let v = load();
        let vec = v
            .families
            .amt
            .iter()
            .find(|v| v.id == "amt-cap-accept")
            .expect("vector");
        let y = uint256_to_asset_amount(vec.amount(), vec.scale_exp)
            .unwrap_or_else(|e| panic!("vector {}: must accept at cap, got {e}", vec.id));
        assert_eq!(y, vec.expected_amount(), "vector {}: cap boundary", vec.id);
        assert_eq!(
            y,
            AssetAmount::MAX,
            "cap boundary must equal AssetAmount::MAX"
        );
    }

    /// TV-AMT-3/4/7 (negative, parametrized): rejects pin their SPECIFIC variants —
    /// cap exceeded / limb overflow (required edge) / scale overflow.
    #[rstest]
    #[case::tv_amt_3_cap_reject("amt-rej-cap")]
    #[case::tv_amt_3_cap_reject_scale0("amt-rej-cap-scale0")]
    #[case::tv_amt_4_limb_overflow("amt-rej-limb-overflow")]
    #[case::tv_amt_7_scale_overflow("amt-rej-scale-overflow")]
    fn tv_amt_rejects(#[case] id: &str) {
        let v = load();
        let vec = v
            .families
            .amt
            .iter()
            .find(|v| v.id == id)
            .expect("vector present");
        let result = uint256_to_asset_amount(vec.amount(), vec.scale_exp);
        match vec.expected_variant.as_deref() {
            Some("AmountOverCap") => {
                assert_matches!(result, Err(EncodingError::AmountOverCap), "vector {id}")
            }
            Some("AmountTooLarge") => {
                assert_matches!(result, Err(EncodingError::AmountTooLarge), "vector {id}")
            }
            Some("ScaleExpTooLarge") => {
                assert_matches!(result, Err(EncodingError::ScaleExpTooLarge), "vector {id}")
            }
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }

    /// TV-AMT-5 (comparator, both directions): reduced_ge is false when a < b after
    /// reduction and true on >= (the caller's `amount >= maxFee` assert input).
    #[test]
    fn tv_amt_5_reduced_ge() {
        let v = load();
        for vec in v.families.amt.iter().filter(|v| v.kind == "ge") {
            let got = reduced_ge(vec.amount(), vec.b_amount(), vec.scale_exp)
                .unwrap_or_else(|e| panic!("vector {}: must compare, got {e}", vec.id));
            assert_eq!(got, vec.ge_result.expect("ge vector"), "vector {}", vec.id);
        }
    }

    /// TV-AMT-6 (boundary/dust): the remainder is surfaced, 0 <= z < 10^scale. The dust
    /// POLICY is `REQUIRES CIRCLE CONFIRMATION` — this test surfaces z only.
    #[test]
    fn tv_amt_6_dust_surfaced_rcc() {
        let v = load();
        let vec = v
            .families
            .amt
            .iter()
            .find(|v| v.kind == "dust")
            .expect("dust vector");
        let (y, z) = uint256_to_asset_amount_with_dust(vec.amount(), vec.scale_exp)
            .unwrap_or_else(|e| panic!("vector {}: must accept, got {e}", vec.id));
        assert_eq!(y, vec.expected_amount(), "vector {}: quotient", vec.id);
        assert_eq!(z, vec.expected_dust(), "vector {}: remainder", vec.id);
        assert!(
            z < 10u128.pow(vec.scale_exp),
            "vector {}: 0 <= z < 10^scale",
            vec.id
        );
    }
}
