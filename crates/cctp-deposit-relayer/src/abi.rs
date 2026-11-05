use alloy_sol_types::sol;
sol! {
    interface Helper {
        function receiveAndDeposit(bytes message, bytes attestation) external;
        function messageTransmitter() external view returns (address);
        function tokenMessenger() external view returns (address);
    }
    interface Transmitter {
        event MessageSent(bytes message);
        function usedNonces(bytes32 nonce) external view returns (uint256);
    }
}
