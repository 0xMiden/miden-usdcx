// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { Test } from "forge-std/Test.sol";
import { MidenCctpDepositHelper } from "../contracts/MidenCctpDepositHelper.sol";
import { TestToken, FaultReceiver, FaultReserve } from "./mocks/FaultDependencies.sol";

interface ICircleCodec {
    function body(uint32, bytes32, bytes32, uint256, bytes32, uint256, bytes calldata)
        external
        pure
        returns (bytes memory);
    function message(uint32, uint32, uint32, bytes32, bytes32, bytes32, uint32, bytes calldata)
        external
        pure
        returns (bytes memory);
    function decode(bytes calldata) external view returns (uint32, bytes32, bytes32, bytes32, bytes memory);
    function decodeBody(bytes calldata) external view returns (uint256, uint256, uint256, uint256, bytes memory);
}

/// @notice Shared fixture and actual Circle formatter, following HiFi's shared base pattern.
abstract contract BaseTest is Test {
    uint256 internal constant MAX = 9_223_372_034_707_292_160;
    bytes32 internal constant RECIPIENT = 0x000000000000000000000000000000008110548cc41852010140bd1325ff0800;
    bytes32 internal constant FAUCET = 0x000000000000000000000000000000008110548cc41852110140bd1325ff0800;
    bytes32 internal constant SOURCE_MESSENGER = bytes32(uint256(0x1234));
    bytes32 internal constant SOURCE_TOKEN = bytes32(uint256(0xabcd));
    uint256 internal constant TEST_ATTESTER_KEY = 1; // Public deterministic test-only authority.
    address internal messenger = address(0x2222);
    address internal relayer = address(0x9876);
    address internal feeRecipient = address(0xfeee);
    ICircleCodec internal codec;
    MidenCctpDepositHelper internal helper;
    TestToken internal token;
    FaultReceiver internal receiver;
    FaultReserve internal reserve;

    event DepositedToMiden(
        uint32 indexed sourceDomain, bytes32 indexed cctpNonce, bytes32 indexed midenRecipient, uint256 amount
    );

    function setUp() public virtual {
        _setUpCodec();
        token = new TestToken();
        receiver = new FaultReceiver(token);
        reserve = new FaultReserve(FAUCET);
        helper =
            new MidenCctpDepositHelper(address(receiver), messenger, address(token), address(reserve), 10007, FAUCET);
    }

    function _setUpCodec() internal {
        codec = ICircleCodec(_deploy("reference/cctp/artifacts/CodecProbe.sol/CodecProbe.json", ""));
    }

    function _deploy(string memory artifact, bytes memory arguments) internal returns (address deployed) {
        bytes memory creation = bytes.concat(vm.getCode(artifact), arguments);
        assembly { deployed := create(0, add(creation, 32), mload(creation)) }
        require(deployed != address(0), artifact);
    }

    function _word(address account) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(account)));
    }

    function _setWord(bytes memory data, uint256 offset, bytes32 value) internal pure {
        require(offset + 32 <= data.length);
        assembly { mstore(add(add(data, 32), offset), value) }
    }

    function _setU32(bytes memory data, uint256 offset, uint32 value) internal pure {
        for (uint256 i; i < 4; i++) {
            data[offset + i] = bytes1(uint8(value >> (24 - 8 * i)));
        }
    }

    function _source(uint32 domain, uint256 gross, uint256 cap, bytes32 recipient)
        internal
        view
        returns (bytes memory)
    {
        bytes32 sender = domain == 5 ? bytes32(type(uint256).max - 10) : bytes32(uint256(0x3333));
        bytes memory body =
            codec.body(1, SOURCE_TOKEN, _word(address(helper)), gross, sender, cap, abi.encode(uint32(1), recipient));
        return codec.message(1, domain, 26, SOURCE_MESSENGER, _word(messenger), _word(address(helper)), 2000, body);
    }

    /// @dev Synthetic attestation changes only the four mutable Circle fields from actual formatter output.
    function _message(uint256 nonce, uint32 domain, uint256 gross, uint256 fee)
        internal
        view
        returns (bytes memory message)
    {
        message = _source(domain, gross, gross / 2, RECIPIENT);
        _setWord(message, 12, bytes32(nonce));
        _setU32(message, 144, 2000);
        _setWord(message, 312, bytes32(fee));
    }

    function _sign(bytes memory message) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TEST_ATTESTER_KEY, keccak256(message));
        return abi.encodePacked(r, s, v);
    }

    function _assertUnitUnchanged(bytes32 nonce, uint256 donation) internal view {
        assertFalse(receiver.used(nonce));
        assertEq(token.balanceOf(address(helper)), donation);
        assertEq(token.balanceOf(address(reserve)), 0);
        assertEq(token.allowance(address(helper), address(reserve)), 0);
        assertEq(reserve.count(), 0);
    }

    function _rejectEarly(bytes memory message, bytes4 error_) internal {
        // Specific dependency poison proves parsing stops before *any* receive/reserve call.
        vm.mockCallRevert(address(receiver), bytes(""), abi.encodeWithSelector(FaultReceiver.ReceiverFault.selector));
        vm.mockCallRevert(address(reserve), bytes(""), abi.encodeWithSelector(FaultReserve.ReserveFault.selector));
        vm.expectRevert(error_);
        helper.receiveAndDeposit(message, "");
        vm.clearMockedCalls();
        _assertUnitUnchanged(bytes32(uint256(1)), 0);
    }
}
