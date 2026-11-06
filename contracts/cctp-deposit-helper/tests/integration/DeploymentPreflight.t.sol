// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import { CircleFixture } from "./CircleFixture.sol";
import { Deploy } from "../../scripts/Deploy.s.sol";
import { MidenCctpDepositHelper } from "../../contracts/MidenCctpDepositHelper.sol";

/// @dev S01 local dry-run behavior; deliberately not S14 live provenance qualification.
contract DeploymentPreflightTest is CircleFixture {
    function test_LocalDryRunBindsConfiguration() external {
        Deploy script = new Deploy();
        MidenCctpDepositHelper candidate = script.run(_config());
        assertEq(candidate.messageTransmitter(), address(transmitter));
        assertEq(candidate.tokenMessenger(), messenger);
        assertEq(candidate.usdc(), address(token));
        assertEq(candidate.xReserve(), address(xreserve));
        assertEq(candidate.midenDomain(), 10007);
        assertEq(candidate.expectedMidenFaucet(), FAUCET);
    }

    function test_DryRunRejectsUnqualifiedDomainChainPauseAndMapping() external {
        Deploy script = new Deploy();
        Deploy.Config memory config = _config();
        config.midenDomain = 10008;
        vm.expectRevert(Deploy.UnqualifiedConfiguration.selector);
        script.run(config);
        config = _config();
        config.chainId++;
        vm.expectRevert(Deploy.UnqualifiedConfiguration.selector);
        script.run(config);
        config = _config();
        xreserve.pause();
        vm.expectRevert(Deploy.UnqualifiedConfiguration.selector);
        script.run(config);
        xreserve.unpause();
        xreserve.deregisterRemoteToken(10007, FAUCET);
        vm.expectRevert(Deploy.UnqualifiedConfiguration.selector);
        script.run(config);
    }

    function _config() private view returns (Deploy.Config memory) {
        return Deploy.Config(
            block.chainid, address(transmitter), messenger, address(token), address(xreserve), 10007, FAUCET
        );
    }
}
