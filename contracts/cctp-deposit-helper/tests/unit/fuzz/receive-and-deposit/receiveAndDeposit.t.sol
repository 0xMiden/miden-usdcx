// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import { BaseTest } from "../../../Base.t.sol";
import { MidenCctpDepositHelper } from "../../../../contracts/MidenCctpDepositHelper.sol";

contract ReceiveAndDepositFuzzTest is BaseTest {
    function testFuzz_PreservesDonationAndDepositsExactlySignedNet(uint64 donation, uint64 grossSeed, uint64 feeSeed)
        external
    {
        uint256 gross = bound(grossSeed, 1, MAX);
        uint256 fee = bound(feeSeed, 0, gross / 2);
        token.mint(address(helper), donation);
        helper.receiveAndDeposit(_message(1, 0, gross, fee), "");
        assertEq(token.balanceOf(address(helper)), donation);
        assertEq(token.balanceOf(address(reserve)), gross - fee);
        assertEq(reserve.total(), gross - fee);
        assertEq(reserve.observedAllowance(), gross - fee);
        assertEq(token.allowance(address(helper), address(reserve)), 0);
        assertTrue(receiver.used(bytes32(uint256(1))));
    }

    function testFuzz_MalformedLengthNeverReachesDependencies(uint16 lengthSeed) external {
        uint256 length = bound(lengthSeed, 0, 1024);
        if (length == 440) length++;
        _rejectEarly(new bytes(length), MidenCctpDepositHelper.InvalidMessage.selector);
    }

    function testFuzz_DirtyFullWordAddressPaddingNeverTruncates(uint8 fieldSeed, uint8 byteSeed, uint8 dirty) external {
        uint256[3] memory offsets = [uint256(76), 108, 184];
        bytes memory message = _message(1, 0, 10, 0);
        message[offsets[fieldSeed % 3] + (byteSeed % 12)] = bytes1(uint8(bound(dirty, 1, 255)));
        _rejectEarly(message, MidenCctpDepositHelper.InvalidMessage.selector);
    }

    function testFuzz_FieldExtractionMatchesActualCircleFormatter(uint32 domain, bytes32 nonce, uint64 amountSeed)
        external
    {
        uint256 amount = bound(amountSeed, 1, MAX);
        bytes memory message = _message(uint256(nonce), domain, amount, 0);
        _assertCodec(message, domain, nonce, amount);
        vm.expectEmit(true, true, true, true, address(helper));
        emit DepositedToMiden(domain, nonce, RECIPIENT, amount);
        helper.receiveAndDeposit(message, "");
        assertEq(reserve.total(), amount);
        assertEq(reserve.lastRecipient(), RECIPIENT);
    }

    function _assertCodec(bytes memory message, uint32 domain, bytes32 nonce, uint256 amount) private view {
        bytes memory body;
        {
            (uint32 source, bytes32 decodedNonce, bytes32 to, bytes32 caller, bytes memory decodedBody) =
                codec.decode(message);
            assertEq(source, domain);
            assertEq(decodedNonce, nonce);
            assertEq(to, _word(messenger));
            assertEq(caller, _word(address(helper)));
            body = decodedBody;
        }
        (uint256 gross, uint256 cap, uint256 fee, uint256 expiry, bytes memory hook) = codec.decodeBody(body);
        assertEq(gross, amount);
        assertEq(cap, amount / 2);
        assertEq(fee, 0);
        assertEq(expiry, 0);
        assertEq(hook, abi.encode(uint32(1), RECIPIENT));
    }
}
