// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/// @dev Narrow ABI boundary; genuine Circle implementations compile in separate reference roots.
interface IMessageTransmitter {
    function receiveMessage(bytes calldata message, bytes calldata attestation) external returns (bool);
}

interface IXReserve {
    function getRemoteToken(uint32 remoteDomain, address localToken) external view returns (bytes32);
    function depositToRemote(
        uint256 value,
        uint32 remoteDomain,
        bytes32 remoteRecipient,
        address localToken,
        uint256 maxFee,
        bytes calldata hookData
    ) external;
}
