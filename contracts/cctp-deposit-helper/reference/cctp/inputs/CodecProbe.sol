// Research only: exposes the pinned Circle libraries; this is not a deposit helper.
pragma solidity 0.7.6;
pragma experimental ABIEncoderV2;
import {MessageV2} from "src/messages/v2/MessageV2.sol";
import {BurnMessageV2} from "src/messages/v2/BurnMessageV2.sol";
import {TypedMemView} from "@memview-sol/contracts/TypedMemView.sol";
contract CodecProbe {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;
    using MessageV2 for bytes29;
    function hook(bytes32 recipient) external pure returns (bytes memory) {
        return abi.encode(uint32(1), recipient);
    }
    function body(uint32 version, bytes32 token, bytes32 recipient, uint256 amount, bytes32 sender, uint256 maxFee, bytes calldata data) external pure returns(bytes memory) {
        return BurnMessageV2._formatMessageForRelay(version, token, recipient, amount, sender, maxFee, data);
    }
    function message(uint32 version, uint32 sourceDomain, uint32 destinationDomain, bytes32 sender, bytes32 recipient, bytes32 caller, uint32 minFinality, bytes calldata data) external pure returns(bytes memory) {
        return MessageV2._formatMessageForRelay(version, sourceDomain, destinationDomain, sender, recipient, caller, minFinality, data);
    }
    function decode(bytes memory data) external view returns (uint32 sourceDomain, bytes32 nonce, bytes32 recipient, bytes32 caller, bytes memory bodyData) {
        bytes29 ref = data.ref(0);
        ref._validateMessageFormat();
        return (ref._getSourceDomain(), ref._getNonce(), ref._getRecipient(), ref._getDestinationCaller(), ref._getMessageBody().clone());
    }
    function decodeBody(bytes memory data) external view returns(uint256 amount,uint256 maxFee,uint256 fee,uint256 expiry,bytes memory dataHook) {
        bytes29 ref=data.ref(0);
        BurnMessageV2._validateBurnMessageFormat(ref);
        return (BurnMessageV2._getAmount(ref),BurnMessageV2._getMaxFee(ref),BurnMessageV2._getFeeExecuted(ref),BurnMessageV2._getExpirationBlock(ref),BurnMessageV2._getHookData(ref).clone());
    }
}
