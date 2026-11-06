// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { BaseTest } from "../../../Base.t.sol";
import { MidenCctpDepositHelper } from "../../../../contracts/MidenCctpDepositHelper.sol";
import { TestToken, FaultReceiver, FaultReserve } from "../../../mocks/FaultDependencies.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { RecipientVectors } from "../../../../fixtures/RecipientVectors.sol";

contract ReceiveAndDepositConcreteTest is BaseTest {
    function test_ConfigurationGettersAndNoAssumedTokenCode() external {
        assertEq(helper.messageTransmitter(), address(receiver));
        assertEq(helper.tokenMessenger(), messenger);
        assertEq(helper.usdc(), address(token));
        assertEq(helper.xReserve(), address(reserve));
        assertEq(helper.midenDomain(), 10007);
        assertEq(helper.expectedMidenFaucet(), FAUCET);
        MidenCctpDepositHelper h =
            new MidenCctpDepositHelper(address(1), address(2), address(3), address(4), 10007, FAUCET);
        assertEq(h.usdc(), address(3));
    }

    function test_RejectsZeroRequiredAddresses() external {
        for (uint256 i; i < 4; i++) {
            address[4] memory addresses = [address(receiver), messenger, address(token), address(reserve)];
            addresses[i] = address(0);
            vm.expectRevert(MidenCctpDepositHelper.InvalidConfiguration.selector);
            new MidenCctpDepositHelper(addresses[0], addresses[1], addresses[2], addresses[3], 10007, FAUCET);
        }
    }

    function test_RejectsInvalidConfiguredFaucet() external {
        vm.expectRevert(MidenCctpDepositHelper.InvalidMidenRecipient.selector);
        new MidenCctpDepositHelper(address(receiver), messenger, address(token), address(reserve), 10007, bytes32(0));
    }

    function test_RejectsNativeValue() external {
        vm.deal(address(this), 1);
        (bool ok,) = address(helper).call{ value: 1 }(
            abi.encodeCall(helper.receiveAndDeposit, (_message(1, 0, 10, 0), bytes("")))
        );
        assertFalse(ok);
        _assertUnitUnchanged(bytes32(uint256(1)), 0);
    }

    function test_RejectsEveryEnvelopeBoundaryAndTrailingData() external {
        uint256[16] memory lengths = [uint256(0), 3, 4, 147, 148, 151, 152, 215, 216, 375, 376, 407, 408, 439, 441, 472];
        for (uint256 i; i < lengths.length; i++) {
            _rejectEarly(new bytes(lengths[i]), MidenCctpDepositHelper.InvalidMessage.selector);
        }
    }

    function test_RejectsHeaderBodyHookVersionsAndDirtyUint32Padding() external {
        uint256[4] memory offsets = [uint256(0), 148, 376, 404];
        for (uint256 i; i < offsets.length; i++) {
            bytes memory message = _message(1, 0, 10, 0);
            _setU32(message, offsets[i], 2);
            _rejectEarly(message, MidenCctpDepositHelper.InvalidMessage.selector);
        }
    }

    function test_RejectsFullWordBindingsIncludingHighPadding() external {
        uint256[3] memory offsets = [uint256(76), 108, 184];
        for (uint256 i; i < offsets.length; i++) {
            for (uint256 j; j < 3; j++) {
                bytes memory message = _message(1, 0, 10, 0);
                bytes32 value = j == 0
                    ? bytes32(0)
                    : j == 1
                        ? bytes32(uint256(0xdead))
                        : bytes32((uint256(1) << 255) | uint256(i == 0 ? _word(messenger) : _word(address(helper))));
                _setWord(message, offsets[i], value);
                _rejectEarly(message, MidenCctpDepositHelper.InvalidMessage.selector);
            }
        }
    }

    function test_MatchesActualRustDecoderBoundaryVectors() external {
        (bytes32[] memory ids, bool[] memory accepted) = RecipientVectors.cases();
        for (uint256 i; i < ids.length; i++) {
            uint256 snapshot = vm.snapshotState();
            bytes memory message = _message(1, 0, 10, 0);
            _setWord(message, 408, ids[i]);
            if (accepted[i]) {
                helper.receiveAndDeposit(message, "");
                assertEq(reserve.lastRecipient(), ids[i]);
                assertEq(reserve.total(), 10);
            } else {
                _rejectEarly(message, MidenCctpDepositHelper.InvalidMidenRecipient.selector);
            }
            assertTrue(vm.revertToStateAndDelete(snapshot));
        }
    }

    function test_RejectsEveryHighRecipientPaddingByte() external {
        for (uint256 i; i < 16; i++) {
            bytes memory message = _message(1, 0, 10, 0);
            message[408 + i] = 0x01;
            _rejectEarly(message, MidenCctpDepositHelper.InvalidMidenRecipient.selector);
        }
    }

    function test_RejectsNonpositivePrincipalBeforeReceive() external {
        for (uint256 i; i < 3; i++) {
            bytes memory message = _message(1, 0, i == 0 ? 0 : 10, i == 0 ? 0 : i == 1 ? 10 : 11);
            _rejectEarly(message, MidenCctpDepositHelper.InvalidMessage.selector);
        }
    }

    function test_RejectsWrongRemoteTokenBeforeReceive() external {
        bytes memory message = _message(1, 0, 10, 0);
        reserve.setRemoteToken(bytes32(0));
        vm.mockCallRevert(address(receiver), bytes(""), abi.encodeWithSelector(FaultReceiver.ReceiverFault.selector));
        vm.expectRevert(MidenCctpDepositHelper.UnexpectedRemoteToken.selector);
        helper.receiveAndDeposit(message, "");
        vm.clearMockedCalls();
        _assertUnitUnchanged(bytes32(uint256(1)), 0);
    }

    function test_RejectsZeroNegativeWrongAndExcessFeeDelta() external {
        bytes memory message = _message(1, 0, 10, 1);
        token.mint(address(helper), 41);
        for (uint256 i; i < 4; i++) {
            receiver.configure(i == 0 || i == 1 ? 0 : i == 2 ? 8 : 10, i == 1 ? 1 : 0, false);
            vm.expectRevert(MidenCctpDepositHelper.UnexpectedReceivedAmount.selector);
            helper.receiveAndDeposit(message, "");
            _assertUnitUnchanged(bytes32(uint256(1)), 41);
        }
    }

    function test_UnexpectedLocalTokenCannotProduceUsdcDelta() external {
        TestToken other = new TestToken();
        FaultReceiver wrongReceiver = new FaultReceiver(other);
        MidenCctpDepositHelper h = new MidenCctpDepositHelper(
            address(wrongReceiver), messenger, address(token), address(reserve), 10007, FAUCET
        );
        helper = h;
        bytes memory message = _message(1, 0, 10, 0);
        vm.expectRevert(MidenCctpDepositHelper.UnexpectedReceivedAmount.selector);
        h.receiveAndDeposit(message, "");
        assertEq(other.totalSupply(), 0);
        assertFalse(wrongReceiver.used(bytes32(uint256(1))));
    }

    function test_AmountBoundAndBoundPlusOne() external {
        bytes memory tooMuch = _message(1, 0, MAX + 1, 0);
        vm.expectRevert(MidenCctpDepositHelper.UnexpectedReceivedAmount.selector);
        helper.receiveAndDeposit(tooMuch, "");
        _assertUnitUnchanged(bytes32(uint256(1)), 0);
        helper.receiveAndDeposit(_message(1, 0, MAX, 0), "");
        assertEq(reserve.total(), MAX);
    }

    function test_DepositsOnlyNetPreservesDonationAndEmitsExactCompletion() external {
        token.mint(address(helper), 41);
        bytes memory message = _message(1, 5, 100, 3);
        vm.expectCall(
            address(reserve),
            abi.encodeWithSelector(
                reserve.depositToRemote.selector, 97, uint32(10007), RECIPIENT, address(token), 0, bytes("")
            ),
            1
        );
        vm.expectEmit(true, true, true, true, address(helper));
        emit DepositedToMiden(5, bytes32(uint256(1)), RECIPIENT, 97);
        vm.prank(relayer);
        helper.receiveAndDeposit(message, "");
        assertEq(token.balanceOf(address(helper)), 41);
        assertEq(token.balanceOf(address(reserve)), 97);
        assertEq(token.allowance(address(helper), address(reserve)), 0);
        assertEq(reserve.observedAllowance(), 97);
        assertEq(reserve.count(), 1);
    }

    function test_ReturnFalseReceiverRollsBackMintAndNonce() external {
        bytes memory message = _message(1, 0, 10, 0);
        receiver.configure(type(uint256).max, 0, true);
        vm.expectRevert(MidenCctpDepositHelper.ReceiveFailed.selector);
        helper.receiveAndDeposit(message, "");
        _assertUnitUnchanged(bytes32(uint256(1)), 0);
    }

    function test_ApprovalFalseAndRevertBubbleAndRollBack() external {
        bytes memory message = _message(1, 0, 10, 0);
        for (uint8 mode = 1; mode <= 2; mode++) {
            token.setApprovalMode(mode, false);
            if (mode == 1) {
                vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
            } else {
                vm.expectRevert(TestToken.TokenFault.selector);
            }
            helper.receiveAndDeposit(message, "");
            _assertUnitUnchanged(bytes32(uint256(1)), 0);
        }
    }

    function test_UnderconsumptionAndNoConsumptionRevert() external {
        bytes memory message = _message(1, 0, 10, 0);
        for (uint256 i = 1; i <= 2; i++) {
            reserve.configure(i * 5, false, 0, "");
            vm.expectRevert(MidenCctpDepositHelper.UnexpectedResidualBalance.selector);
            helper.receiveAndDeposit(message, "");
            _assertUnitUnchanged(bytes32(uint256(1)), 0);
        }
    }

    function test_ResidualAllowanceAfterLyingResetReverts() external {
        bytes memory message = _message(1, 0, 10, 0);
        token.setApprovalMode(3, true);
        vm.expectRevert(MidenCctpDepositHelper.UnexpectedResidualBalance.selector);
        helper.receiveAndDeposit(message, "");
        _assertUnitUnchanged(bytes32(uint256(1)), 0);
    }

    function test_UncaughtReserveFailureRevertsAndSameMessageRetries() external {
        bytes memory message = _message(1, 0, 10, 0);
        reserve.configure(0, true, 0, "");
        vm.expectRevert(FaultReserve.ReserveFault.selector);
        helper.receiveAndDeposit(message, "");
        _assertUnitUnchanged(bytes32(uint256(1)), 0);
        reserve.configure(0, false, 0, "");
        helper.receiveAndDeposit(message, "");
        assertEq(reserve.total(), 10);
        assertEq(reserve.count(), 1);
    }

    function test_UncaughtReentryRevertsAndCaughtReentryAllowsOnlyOuter() external {
        bytes memory message = _message(1, 0, 10, 0);
        reserve.configure(0, false, 1, _message(2, 0, 10, 0));
        vm.expectRevert(bytes4(keccak256("ReentrancyGuardReentrantCall()")));
        helper.receiveAndDeposit(message, "");
        _assertUnitUnchanged(bytes32(uint256(1)), 0);
        reserve.configure(0, false, 2, _message(2, 0, 10, 0));
        helper.receiveAndDeposit(message, "");
        assertTrue(reserve.caught());
        assertEq(reserve.count(), 1);
        assertEq(reserve.total(), 10);
        assertFalse(receiver.used(bytes32(uint256(2))));
    }
}
