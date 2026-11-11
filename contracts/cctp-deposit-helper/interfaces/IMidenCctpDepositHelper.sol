// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/// @notice Worker-facing calls; the release gate checks them against the helper's full ABI.
interface IMidenCctpDepositHelper {
    function receiveAndDeposit(bytes calldata message, bytes calldata attestation) external;
    function messageTransmitter() external view returns (address);
    function tokenMessenger() external view returns (address);
}
