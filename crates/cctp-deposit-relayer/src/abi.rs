use alloy_sol_types::sol;

sol!("../../contracts/cctp-deposit-helper/interfaces/IMidenCctpDepositHelper.sol");
pub use IMidenCctpDepositHelper as Helper;

sol! {
    interface Transmitter {
        event MessageSent(bytes message);
        function usedNonces(bytes32 nonce) external view returns (uint256);
    }
}
