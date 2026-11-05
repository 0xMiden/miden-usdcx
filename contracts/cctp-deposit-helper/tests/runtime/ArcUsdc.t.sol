// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import { BaseTest } from "../Base.t.sol";
import { MidenCctpDepositHelper } from "../../contracts/MidenCctpDepositHelper.sol";
import { FaultReserve } from "../mocks/FaultDependencies.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface INativeUsdc is IERC20 {
    function decimals() external view returns (uint8);
    function blacklister() external view returns (address);
    function blacklist(address) external;
    function unBlacklist(address) external;
    function isBlacklisted(address) external view returns (bool);
}

/// @dev Funding stub for isolated Arc native-token testing, not a CCTP authenticator.
contract NativeReceiptStub {
    using SafeERC20 for IERC20;
    IERC20 public immutable token;
    uint256 public received;

    constructor(IERC20 token_) {
        token = token_;
    }

    function receiveMessage(bytes calldata message, bytes calldata) external returns (bool) {
        uint256 net = uint256(bytes32(message[216:248])) - uint256(bytes32(message[312:344]));
        received++;
        token.safeTransfer(msg.sender, net);
        return true;
    }
}

/// @notice Must run with Arc execution backend and local Arc fork; no public RPC is used.
contract ArcUsdcTest is BaseTest {
    INativeUsdc internal nativeUsdc = INativeUsdc(0x3600000000000000000000000000000000000000);
    uint256 internal constant SCALE = 1e12;
    uint256 internal constant DUST = 123_456_789;
    NativeReceiptStub internal nativeReceiver;

    function setUp() public override {
        _setUpCodec();
        assertEq(nativeUsdc.decimals(), 6, "Arc runtime unavailable");
        nativeReceiver = new NativeReceiptStub(nativeUsdc);
        reserve = new FaultReserve(FAUCET);
        helper = new MidenCctpDepositHelper(
            address(nativeReceiver), messenger, address(nativeUsdc), address(reserve), 10007, FAUCET
        );
        vm.deal(address(nativeReceiver), 100 * SCALE);
        vm.deal(address(helper), 41 * SCALE + DUST);
    }

    function test_ArcNativeSafeApprovePullResetAndDustPreservation() external {
        bytes memory message = _message(1, 0, 100, 3);
        vm.expectCall(address(nativeUsdc), abi.encodeCall(nativeUsdc.approve, (address(reserve), 97)), 1);
        vm.expectCall(address(nativeUsdc), abi.encodeCall(nativeUsdc.approve, (address(reserve), 0)), 1);
        vm.prank(relayer);
        helper.receiveAndDeposit(message, "");
        assertEq(address(helper).balance, 41 * SCALE + DUST);
        assertEq(nativeUsdc.balanceOf(address(helper)), 41);
        assertEq(address(reserve).balance, 97 * SCALE);
        assertEq(nativeUsdc.balanceOf(address(reserve)), 97);
        assertEq(address(nativeReceiver).balance, 3 * SCALE);
        assertEq(nativeUsdc.allowance(address(helper), address(reserve)), 0);
        assertEq(reserve.observedAllowance(), 97);
        assertEq(nativeReceiver.received(), 1);
    }

    function test_ArcRealTokenBlocklistRollsBackAndCanRetry() external {
        address authority = nativeUsdc.blacklister();
        vm.prank(authority);
        nativeUsdc.blacklist(address(reserve));
        assertTrue(nativeUsdc.isBlacklisted(address(reserve)));
        bytes memory message = _message(1, 0, 100, 3);
        (bool ok, bytes memory reason) =
            address(helper).call(abi.encodeCall(helper.receiveAndDeposit, (message, bytes(""))));
        assertFalse(ok, "blocklisted native-token transfer committed");
        assertEq(reason, abi.encodeWithSignature("Error(string)", "Blacklistable: account is blacklisted"));
        assertEq(address(helper).balance, 41 * SCALE + DUST);
        assertEq(address(nativeReceiver).balance, 100 * SCALE);
        assertEq(address(reserve).balance, 0);
        assertEq(nativeReceiver.received(), 0);
        assertEq(nativeUsdc.allowance(address(helper), address(reserve)), 0);
        vm.prank(authority);
        nativeUsdc.unBlacklist(address(reserve));
        helper.receiveAndDeposit(message, "");
        assertEq(address(helper).balance, 41 * SCALE + DUST);
        assertEq(address(reserve).balance, 97 * SCALE);
    }
}
