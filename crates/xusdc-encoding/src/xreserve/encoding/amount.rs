//! Converts deposit amounts from uint256 to [`AssetAmount`] in the same smallest units.
//!
//! Circle's final cap and scaling decision remains OPEN.

use miden_protocol::asset::AssetAmount;
use miden_standards::interop::eth::EthAmount;

use super::error::EncodingError;

/// Zero scaling preserves the signed amount when the faucet zero-extends [`AssetAmount`] to uint256.
pub(super) const DEPOSIT_SCALE_EXP: u32 = 0;

/// Converts an amount at [`DEPOSIT_SCALE_EXP`], rejecting values above [`AssetAmount::MAX`].
pub(super) fn uint256_to_asset_amount(amount: EthAmount) -> Result<AssetAmount, EncodingError> {
    let y = amount.scale_to_asset_amount(DEPOSIT_SCALE_EXP)?;
    AssetAmount::try_from(y).map_err(|_| EncodingError::AmountOverCap)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    #[test]
    fn tv_amt_1_in_bound() {
        let v = load();
        for vec in v
            .families
            .amt
            .iter()
            .filter(|v| v.kind == "accept" && v.id != "amt-cap-accept")
        {
            let y = uint256_to_asset_amount(vec.amount())
                .unwrap_or_else(|e| panic!("vector {}: must accept, got {e}", vec.id));
            assert_eq!(
                y,
                vec.expected_amount(),
                "vector {}: reduced amount",
                vec.id
            );
        }
    }

    #[test]
    fn tv_amt_2_cap_boundary_accept() {
        let v = load();
        let vec = v
            .families
            .amt
            .iter()
            .find(|v| v.id == "amt-cap-accept")
            .expect("vector");
        let y = uint256_to_asset_amount(vec.amount())
            .unwrap_or_else(|e| panic!("vector {}: must accept at cap, got {e}", vec.id));
        assert_eq!(y, vec.expected_amount(), "vector {}: cap boundary", vec.id);
        assert_eq!(
            y,
            AssetAmount::MAX,
            "cap boundary must equal AssetAmount::MAX"
        );
    }

    #[rstest]
    #[case::tv_amt_3_cap_reject("amt-rej-cap")]
    #[case::tv_amt_4_limb_overflow("amt-rej-limb-overflow")]
    fn tv_amt_rejects(#[case] id: &str) {
        let v = load();
        let vec = v
            .families
            .amt
            .iter()
            .find(|v| v.id == id)
            .expect("vector present");
        let result = uint256_to_asset_amount(vec.amount());
        match vec.expected_variant.as_deref() {
            Some("AmountOverCap") => {
                assert_matches!(result, Err(EncodingError::AmountOverCap), "vector {id}")
            }
            Some("AmountTooLarge") => {
                assert_matches!(result, Err(EncodingError::AmountTooLarge), "vector {id}")
            }
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }
}
