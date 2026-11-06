// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import { BaseTest, ICircleCodec } from "../../Base.t.sol";
import { MidenCctpDepositHelper } from "../../../contracts/MidenCctpDepositHelper.sol";
import { TestToken, FaultReceiver, FaultReserve } from "../../mocks/FaultDependencies.sol";
import { Vm } from "forge-std/Vm.sol";

/// @dev Ghost totals derive from generated intentions and successful outcomes, never reserve totals.
contract HelperHandler is BaseTest {
    uint256 public donated;
    uint256 public deposited;
    uint256 public successes;
    uint256 public failures;
    uint256 private nextNonce = 1;
    mapping(bytes32 => uint256) public successCount;
    bytes[] private completed;

    constructor(MidenCctpDepositHelper h, TestToken t, FaultReceiver r, FaultReserve x, ICircleCodec c) {
        helper = h;
        token = t;
        receiver = r;
        reserve = x;
        codec = c;
        messenger = h.tokenMessenger();
    }

    function donate(uint64 seed) external {
        uint256 value = bound(seed, 0, 1e15);
        token.mint(address(helper), value);
        donated += value;
    }

    function complete(uint64 grossSeed, uint64 feeSeed, uint32 source) external {
        uint256 gross = bound(grossSeed, 1, MAX);
        uint256 fee = bound(feeSeed, 0, gross / 2);
        bytes32 nonce = bytes32(nextNonce++);
        bytes memory message = _message(uint256(nonce), source, gross, fee);
        vm.recordLogs();
        helper.receiveAndDeposit(message, "");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 events;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter == address(helper)) {
                assertEq(logs[i].topics[0], keccak256("DepositedToMiden(uint32,bytes32,bytes32,uint256)"));
                assertEq(logs[i].topics[1], bytes32(uint256(source)));
                assertEq(logs[i].topics[2], nonce);
                assertEq(logs[i].topics[3], RECIPIENT);
                assertEq(abi.decode(logs[i].data, (uint256)), gross - fee);
                events++;
            }
        }
        assertEq(events, 1);
        successCount[nonce]++;
        assertEq(successCount[nonce], 1);
        deposited += gross - fee;
        successes++;
        completed.push(message);
        _assertAccounting();
    }

    function duplicate(uint256 index) external {
        if (completed.length == 0) return;
        bytes memory message = completed[index % completed.length];
        bytes32 nonce;
        assembly { nonce := mload(add(message, 44)) }
        uint256 supply = token.totalSupply();
        (bool ok, bytes memory reason) =
            address(helper).call(abi.encodeCall(helper.receiveAndDeposit, (message, bytes(""))));
        assertFalse(ok);
        assertEq(reason, abi.encodeWithSignature("Error(string)", "fixture replay"));
        assertTrue(receiver.used(nonce));
        assertEq(successCount[nonce], 1);
        assertEq(token.totalSupply(), supply);
        failures++;
        _assertAccounting();
    }

    function downstreamFailure(uint64 grossSeed) external {
        uint256 gross = bound(grossSeed, 1, MAX);
        bytes32 nonce = bytes32(nextNonce++);
        bytes memory message = _message(uint256(nonce), 5, gross, 0);
        uint256 supply = token.totalSupply();
        reserve.configure(0, true, 0, "");
        (bool ok, bytes memory reason) =
            address(helper).call(abi.encodeCall(helper.receiveAndDeposit, (message, bytes(""))));
        assertFalse(ok);
        assertEq(reason, abi.encodeWithSelector(FaultReserve.ReserveFault.selector));
        assertFalse(receiver.used(nonce));
        assertEq(token.totalSupply(), supply);
        assertEq(successCount[nonce], 0);
        reserve.configure(0, false, 0, "");
        failures++;
        _assertAccounting();
    }

    function assertAccounting() external view {
        _assertAccounting();
    }

    function _assertAccounting() private view {
        assertEq(token.balanceOf(address(helper)), donated);
        assertEq(token.balanceOf(address(reserve)), deposited);
        assertEq(reserve.total(), deposited);
        assertEq(reserve.count(), successes);
        assertEq(token.allowance(address(helper), address(reserve)), 0);
        assertEq(token.totalSupply(), donated + deposited);
    }
}
