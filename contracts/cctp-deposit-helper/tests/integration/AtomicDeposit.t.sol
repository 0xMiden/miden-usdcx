// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { CircleFixture, IRealMessenger } from "./CircleFixture.sol";
import { MidenCctpDepositHelper } from "../../contracts/MidenCctpDepositHelper.sol";
import { GatewayPullStub, DomainHook } from "../mocks/FaultDependencies.sol";
import { Vm } from "forge-std/Vm.sol";

contract AtomicDepositTest is CircleFixture {
    bytes32 internal constant RESERVE_EVENT =
        keccak256("DepositedToRemote(address,uint256,address,bytes32,uint32,bytes32,uint256,bytes)");
    bytes32 internal constant HELPER_EVENT = keccak256("DepositedToMiden(uint32,bytes32,bytes32,uint256)");

    function test_ActualEvmAndNonEvmReceiveWithZeroBelowAndEqualCapFees() external {
        uint256 total;
        token.mint(address(helper), 41);
        for (uint256 i; i < 6; i++) {
            uint32 domain = i < 3 ? 0 : 5;
            uint256 fee = (i % 3) * 25;
            bytes memory message = _message(i + 1, domain, 100, fee);
            vm.recordLogs();
            vm.prank(relayer);
            helper.receiveAndDeposit(message, _sign(message));
            _assertPairs(vm.getRecordedLogs(), i + 1, domain, 100 - fee, 1);
            total += 100 - fee;
            assertEq(transmitter.usedNonces(bytes32(i + 1)), 1);
            assertEq(gateway.total(), total);
            assertEq(token.balanceOf(address(gateway)), total);
            assertEq(gateway.beneficiary(), remoteDepositor);
            assertEq(token.balanceOf(address(helper)), 41);
            assertEq(token.allowance(address(helper), address(xreserve)), 0);
        }
    }

    function test_ActualInvalidSignatureAndChangedValidRecipientReject() external {
        bytes memory message = _message(1, 0, 100, 3);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(99, keccak256(message));
        _rejectCircle(message, abi.encodePacked(r, s, v), bytes("Invalid signature: not attester"));
        bytes memory oldSignature = _sign(message);
        _setWord(message, 408, FAUCET);
        _rejectCircle(message, oldSignature, bytes("Invalid signature: not attester"));
    }

    function test_ActualWrongDestinationDomainRejects() external {
        bytes memory message = _message(1, 0, 100, 3);
        _setU32(message, 8, 27);
        _rejectCircle(message, _sign(message), bytes("Invalid destination domain"));
    }

    function test_ActualUnknownRemoteMessengerAndTokenReject() external {
        bytes memory message = _message(1, 0, 100, 3);
        _setWord(message, 44, bytes32(uint256(0x9999)));
        _rejectCircle(message, _sign(message), bytes("Remote TokenMessenger unsupported"));
        message = _message(1, 0, 100, 3);
        _setWord(message, 152, bytes32(uint256(0x9999)));
        _rejectCircle(message, _sign(message), bytes("Mint token not supported"));
    }

    function test_DirectBypassAndGlobalNonceReplay() external {
        bytes memory message = _message(1, 0, 100, 3);
        bytes memory signature = _sign(message);
        vm.expectRevert(bytes("Invalid caller for message"));
        transmitter.receiveMessage(message, signature);
        _assertRolledBack(bytes32(uint256(1)), 0, 0);
        vm.prank(address(0xbeef));
        helper.receiveAndDeposit(message, signature);
        vm.expectRevert(bytes("Nonce already used"));
        helper.receiveAndDeposit(message, signature);
        bytes memory otherDomain = _message(1, 5, 100, 3);
        bytes memory otherSignature = _sign(otherDomain);
        vm.expectRevert(bytes("Nonce already used"));
        helper.receiveAndDeposit(otherDomain, otherSignature);
        assertEq(gateway.total(), 97);
        assertEq(token.balanceOf(address(helper)), 0);
        assertEq(token.allowance(address(helper), address(xreserve)), 0);
    }

    function test_ActualFeeCapAndExpiryBoundariesAndSyntheticRefresh() external {
        bytes memory message = _message(1, 0, 100, 51);
        _rejectCircle(message, _sign(message), bytes("Fee exceeds max fee"));
        message = _message(1, 0, 100, 3);
        _setWord(message, 344, bytes32(block.number));
        _rejectCircle(message, _sign(message), bytes("Message expired and must be re-signed"));
        // Synthetic refresh preserves source intent and nonce; Circle did not issue these signatures.
        _setWord(message, 344, bytes32(block.number + 1));
        helper.receiveAndDeposit(message, _sign(message));
        _setWord(message, 344, bytes32(block.number + 100));
        bytes memory signature = _sign(message);
        vm.expectRevert(bytes("Nonce already used"));
        helper.receiveAndDeposit(message, signature);
        assertEq(gateway.total(), 97);
    }

    function test_CircleExecutedFinalityIsNotAnExtraHelperStandardGuard() external {
        bytes memory message = _message(1, 0, 100, 3);
        _setU32(message, 144, 500);
        helper.receiveAndDeposit(message, _sign(message));
        assertEq(gateway.total(), 97);
    }

    function test_ActualFeeRecipientEqualsHelperRejectsExcessDelta() external {
        IRealMessenger(messenger).setFeeRecipient(address(helper));
        bytes memory message = _message(1, 0, 100, 3);
        _rejectCircle(
            message, _sign(message), abi.encodeWithSelector(MidenCctpDepositHelper.UnexpectedReceivedAmount.selector)
        );
    }

    function test_RollsBackActualMintForGatewayFailureThenRetriesSameBytes() external {
        bytes memory message = _message(1, 0, 100, 3);
        bytes memory signature = _sign(message);
        token.mint(address(helper), 41);
        gateway.setFail(true);
        // Exact call expectation proves the genuine minter was reached before the downstream failure.
        vm.expectCall(address(token), abi.encodeWithSelector(token.mint.selector, address(helper), 97));
        vm.expectCall(
            address(gateway), abi.encodeWithSelector(gateway.depositFor.selector, address(token), remoteDepositor, 97)
        );
        vm.expectRevert(GatewayPullStub.GatewayFault.selector);
        helper.receiveAndDeposit(message, signature);
        _assertRolledBack(bytes32(uint256(1)), 41, 0);
        gateway.setFail(false);
        helper.receiveAndDeposit(message, signature);
        assertEq(gateway.total(), 97);
        assertEq(token.balanceOf(address(helper)), 41);
        assertEq(transmitter.usedNonces(bytes32(uint256(1))), 1);
    }

    function test_ActualGlobalAndDomainPauseAndBlocklistRollbackAndRetry() external {
        for (uint256 i; i < 3; i++) {
            uint256 snapshot = vm.snapshotState();
            bytes memory message = _message(1, 0, 100, 3);
            bytes memory signature = _sign(message);
            if (i == 0) xreserve.pause();
            else if (i == 1) xreserve.setDomainPauseState(10007, true, false);
            else xreserve.blocklist(10007, RECIPIENT);
            vm.expectCall(address(token), abi.encodeWithSelector(token.mint.selector, address(helper), 97));
            if (i == 0) {
                vm.expectRevert(bytes4(keccak256("EnforcedPause()")));
            } else if (i == 1) {
                vm.expectRevert(abi.encodeWithSignature("DomainDepositsPaused(uint32)", uint32(10007)));
            } else {
                vm.expectRevert(abi.encodeWithSignature("AccountBlocklisted(uint32,bytes32)", uint32(10007), RECIPIENT));
            }
            helper.receiveAndDeposit(message, signature);
            _assertRolledBack(bytes32(uint256(1)), 0, 0);
            if (i == 0) xreserve.unpause();
            else if (i == 1) xreserve.setDomainPauseState(10007, false, false);
            else xreserve.unblocklist(10007, RECIPIENT);
            helper.receiveAndDeposit(message, signature);
            assertEq(gateway.total(), 97);
            assertTrue(vm.revertToStateAndDelete(snapshot));
        }
    }

    function test_RemovedOrChangedTokenMappingRejectsBeforeMintAndCanRetry() external {
        bytes memory message = _message(1, 0, 100, 3);
        bytes memory signature = _sign(message);
        xreserve.deregisterRemoteToken(10007, FAUCET);
        vm.expectRevert(MidenCctpDepositHelper.UnexpectedRemoteToken.selector);
        helper.receiveAndDeposit(message, signature);
        _assertRolledBack(bytes32(uint256(1)), 0, 0);
        xreserve.registerRemoteToken(address(token), 10007, RECIPIENT);
        vm.expectRevert(MidenCctpDepositHelper.UnexpectedRemoteToken.selector);
        helper.receiveAndDeposit(message, signature);
        _assertRolledBack(bytes32(uint256(1)), 0, 0);
        xreserve.deregisterRemoteToken(10007, RECIPIENT);
        xreserve.registerRemoteToken(address(token), 10007, FAUCET);
        helper.receiveAndDeposit(message, signature);
        assertEq(gateway.total(), 97);
    }

    function test_ActualDomainHookFailureAndCaughtOrUncaughtReentry() external {
        bytes memory message = _message(1, 0, 100, 3);
        bytes memory signature = _sign(message);
        bytes memory nested = _message(2, 0, 100, 3);
        xreserve.setRemoteDomainHookExecutor(10007, address(hook));
        hook.configure(true, 0, address(helper), nested, _sign(nested));
        vm.expectRevert(DomainHook.HookFault.selector);
        helper.receiveAndDeposit(message, signature);
        _assertRolledBack(bytes32(uint256(1)), 0, 0);
        hook.configure(false, 1, address(helper), nested, _sign(nested));
        vm.expectRevert(bytes4(keccak256("ReentrancyGuardReentrantCall()")));
        helper.receiveAndDeposit(message, signature);
        _assertRolledBack(bytes32(uint256(1)), 0, 0);
        hook.configure(false, 2, address(helper), nested, _sign(nested));
        helper.receiveAndDeposit(message, signature);
        assertTrue(hook.caught());
        assertEq(gateway.total(), 97);
        assertEq(transmitter.usedNonces(bytes32(uint256(2))), 0);
    }

    function test_OrderedPairsForTwoSameRecipientAmountCalls() external {
        bytes memory first = _message(1, 0, 100, 3);
        bytes memory second = _message(2, 0, 100, 3);
        vm.recordLogs();
        helper.receiveAndDeposit(first, _sign(first));
        helper.receiveAndDeposit(second, _sign(second));
        _assertPairs(vm.getRecordedLogs(), 1, 0, 97, 2);
        assertEq(gateway.total(), 194);
    }

    function testFuzz_ChangedSignedHookReachesActualAuthentication(uint64 suffix) external {
        bytes memory message = _message(1, 0, 100, 3);
        bytes memory signature = _sign(message);
        suffix = (suffix & 0x7fff_ffff_ffff_ff00);
        if (suffix == uint64(uint256(RECIPIENT))) suffix ^= 0x100;
        bytes32 changed = bytes32((uint256(RECIPIENT) & ~uint256(type(uint64).max)) | suffix);
        _setWord(message, 408, changed);
        _rejectCircle(message, signature, bytes("Invalid signature: not attester"));
    }

    function _assertPairs(Vm.Log[] memory logs, uint256 firstNonce, uint32 domain, uint256 net, uint256 expected)
        internal
        view
    {
        uint256 pairs;
        bool pending;
        for (uint256 i; i < logs.length; i++) {
            Vm.Log memory entry = logs[i];
            if (entry.emitter == address(xreserve) && entry.topics[0] == RESERVE_EVENT) {
                assertFalse(pending, "ambiguous reserve event interval");
                assertEq(entry.topics.length, 4);
                assertEq(entry.topics[1], _word(address(token)));
                assertEq(entry.topics[2], _word(address(helper)));
                assertEq(entry.topics[3], RECIPIENT);
                (uint256 value, uint32 destination, bytes32 faucet, uint256 fee, bytes memory hookData) =
                    abi.decode(entry.data, (uint256, uint32, bytes32, uint256, bytes));
                assertEq(value, net);
                assertEq(destination, 10007);
                assertEq(faucet, FAUCET);
                assertEq(fee, 0);
                assertEq(hookData.length, 0);
                pending = true;
            }
            if (entry.emitter == address(helper) && entry.topics[0] == HELPER_EVENT) {
                assertTrue(pending, "helper without preceding reserve");
                assertEq(entry.topics[1], bytes32(uint256(domain)));
                assertEq(entry.topics[2], bytes32(firstNonce + pairs));
                assertEq(entry.topics[3], RECIPIENT);
                assertEq(abi.decode(entry.data, (uint256)), net);
                pairs++;
                pending = false;
            }
        }
        assertFalse(pending);
        assertEq(pairs, expected);
    }
}
