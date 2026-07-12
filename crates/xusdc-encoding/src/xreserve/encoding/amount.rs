//! uint256 → AssetAmount family, frozen signatures per the shared-encoding spec
//! (INV-UINT256-TO-ASSETAMOUNT). Implemented per the frozen reduction order, with checked
//! arithmetic on every external-derived value. Cap/scale/dust values are
//! `REQUIRES CIRCLE CONFIRMATION` (DEV-5) — the mechanic is implemented per the frozen spec, the
//! policy stays OPEN.

use miden_protocol::asset::AssetAmount;

use super::error::EncodingError;

/// The scale exponent bound (scale_exp = EVM decimals − Miden decimals, 0..=18; mirrored in
/// MASM as `SCALE_EXP_MAX` — `pub` so the constant-parity suite pins the cross-language pair).
pub const MAX_SCALE_EXP: u32 = 18;

/// The single reduction core shared by all three public routines (≤ 1 implementation of
/// the owned mechanic): byte-swap → high-4-zero → low-4 u128 → floor-divide by 10^scale_exp →
/// (y, z). The AssetAmount cap is applied by the callers via [`AssetAmount::new`].
fn reduce(le_limbs: [u32; 8], scale_exp: u32) -> Result<(u64, u128), EncodingError> {
    // steps 1–2: the high four limbs (wire bytes 0..16) must be zero; a limb byte-swaps
    // to zero iff it is zero, so the raw LE-packed limbs are checked directly
    if le_limbs[..4].iter().any(|&limb| limb != 0) {
        return Err(EncodingError::AmountTooLarge);
    }

    // steps 1 + 3: byte-swap the low four limbs to numeric order and compose x
    // (limb 4 holds wire bytes 16..20 — the most significant of the low half)
    let mut x: u128 = 0;
    for &limb in &le_limbs[4..8] {
        x = (x << 32) | u128::from(limb.swap_bytes());
    }

    // step 4: y = floor(x / 10^scale_exp); the divisor is bounded first (TV-AMT-7)
    if scale_exp > MAX_SCALE_EXP {
        return Err(EncodingError::ScaleExpTooLarge);
    }
    let divisor = 10u128
        .checked_pow(scale_exp)
        .ok_or(EncodingError::ScaleExpTooLarge)?;
    // the divisor is at least 1 by construction, so checked division cannot fail
    let y = x.checked_div(divisor).expect("divisor is at least 1");
    let z = x.checked_rem(divisor).expect("divisor is at least 1");

    // the quotient must fit a u64 before the cap compare (x may be up to 2^128 − 1)
    let y = u64::try_from(y).map_err(|_| EncodingError::AmountOverCap)?;
    Ok((y, z))
}

/// uint256 (8 LE u32 limbs) → AssetAmount: byte-swap → assert high 4 limbs zero (else
/// `AmountTooLarge`) → low 4 as u128 x → y = floor(x / 10^scale_exp) → reject if y
/// exceeds `AssetAmount::MAX` (`AmountOverCap`). No saturation or clamping.
pub fn uint256_to_asset_amount(
    le_limbs: [u32; 8],
    scale_exp: u32,
) -> Result<AssetAmount, EncodingError> {
    let (y, _z) = reduce(le_limbs, scale_exp)?;
    AssetAmount::new(y).map_err(|_| EncodingError::AmountOverCap)
}

/// The reduced-compare: reduce both operands, then compare as u64 (the mint's `amount >= maxFee`
/// and `feeAmount <= maxFee` checks).
pub fn reduced_ge(a: [u32; 8], b: [u32; 8], scale_exp: u32) -> Result<bool, EncodingError> {
    let (ya, _) = reduce(a, scale_exp)?;
    let (yb, _) = reduce(b, scale_exp)?;
    Ok(ya >= yb)
}

/// The non-zero division remainder (dust), surfaced so the caller can apply the DEV-5
/// dust policy (`REQUIRES CIRCLE CONFIRMATION` — not resolved here).
pub fn uint256_to_asset_amount_with_dust(
    le_limbs: [u32; 8],
    scale_exp: u32,
) -> Result<(AssetAmount, u128), EncodingError> {
    let (y, z) = reduce(le_limbs, scale_exp)?;
    let amount = AssetAmount::new(y).map_err(|_| EncodingError::AmountOverCap)?;
    Ok((amount, z))
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
            let y = uint256_to_asset_amount(vec.le_limbs(), vec.scale_exp)
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
        let y = uint256_to_asset_amount(vec.le_limbs(), vec.scale_exp)
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
        let result = uint256_to_asset_amount(vec.le_limbs(), vec.scale_exp);
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
            let got = reduced_ge(vec.le_limbs(), vec.b_le_limbs(), vec.scale_exp)
                .unwrap_or_else(|e| panic!("vector {}: must compare, got {e}", vec.id));
            assert_eq!(got, vec.ge_result.expect("ge vector"), "vector {}", vec.id);
        }
    }

    /// TV-AMT-6 (boundary/dust): the remainder is surfaced, 0 <= z < 10^scale. The dust
    /// POLICY is `REQUIRES CIRCLE CONFIRMATION` (DEV-5) — this test surfaces z only.
    #[test]
    fn tv_amt_6_dust_surfaced_rcc() {
        let v = load();
        let vec = v
            .families
            .amt
            .iter()
            .find(|v| v.kind == "dust")
            .expect("dust vector");
        let (y, z) = uint256_to_asset_amount_with_dust(vec.le_limbs(), vec.scale_exp)
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
