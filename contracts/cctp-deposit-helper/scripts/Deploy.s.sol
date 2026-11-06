// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import { MidenCctpDepositHelper } from "../contracts/MidenCctpDepositHelper.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { IXReserve } from "../contracts/interfaces/ICircleDeposit.sol";

interface IDeploymentTransmitter {
    function localDomain() external view returns (uint32);
    function version() external view returns (uint32);
}

interface IDeploymentMessenger {
    function localMessageTransmitter() external view returns (address);
    function messageBodyVersion() external view returns (uint32);
}

interface IDeploymentReserve {
    function domain() external view returns (uint32);
    function isRemoteDomainRegistered(uint32) external view returns (bool);
    function domainDepositsPaused(uint32) external view returns (bool);
    function paused() external view returns (bool);
}

/// @notice Simulation only: no broadcast calls, key handling or inferred production addresses.
/// @dev This verifies observable onchain prerequisites. External policy and deployed provenance remain separate gates.
contract Deploy {
    struct Config {
        uint256 chainId;
        address messageTransmitter;
        address tokenMessenger;
        address usdc;
        address xReserve;
        uint32 midenDomain;
        bytes32 expectedMidenFaucet;
    }
    error UnqualifiedConfiguration();

    function run(Config calldata c) external returns (MidenCctpDepositHelper helper) {
        if (block.chainid != c.chainId || c.midenDomain != 10007) revert UnqualifiedConfiguration();
        if (
            IDeploymentTransmitter(c.messageTransmitter).localDomain() != 26
                || IDeploymentTransmitter(c.messageTransmitter).version() != 1
                || IDeploymentMessenger(c.tokenMessenger).localMessageTransmitter() != c.messageTransmitter
                || IDeploymentMessenger(c.tokenMessenger).messageBodyVersion() != 1
                || IERC20Metadata(c.usdc).decimals() != 6 || IDeploymentReserve(c.xReserve).domain() != 26
                || !IDeploymentReserve(c.xReserve).isRemoteDomainRegistered(c.midenDomain)
                || IDeploymentReserve(c.xReserve).paused()
                || IDeploymentReserve(c.xReserve).domainDepositsPaused(c.midenDomain)
                || IXReserve(c.xReserve).getRemoteToken(c.midenDomain, c.usdc) != c.expectedMidenFaucet
        ) revert UnqualifiedConfiguration();
        return new MidenCctpDepositHelper(
            c.messageTransmitter, c.tokenMessenger, c.usdc, c.xReserve, c.midenDomain, c.expectedMidenFaucet
        );
    }
}
