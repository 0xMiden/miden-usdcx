// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {
    DepositIntent,
    DEPOSIT_INTENT_MAGIC,
    DEPOSIT_INTENT_VERSION,
    DEPOSIT_INTENT_MAGIC_OFFSET,
    DEPOSIT_INTENT_VERSION_OFFSET,
    DEPOSIT_INTENT_AMOUNT_OFFSET,
    DEPOSIT_INTENT_REMOTE_DOMAIN_OFFSET,
    DEPOSIT_INTENT_REMOTE_TOKEN_OFFSET,
    DEPOSIT_INTENT_REMOTE_RECIPIENT_OFFSET,
    DEPOSIT_INTENT_LOCAL_TOKEN_OFFSET,
    DEPOSIT_INTENT_LOCAL_DEPOSITOR_OFFSET,
    DEPOSIT_INTENT_MAX_FEE_OFFSET,
    DEPOSIT_INTENT_NONCE_OFFSET,
    DEPOSIT_INTENT_HOOK_DATA_LENGTH_OFFSET,
    DEPOSIT_INTENT_HOOK_DATA_OFFSET
} from "src/lib/DepositIntent.sol";
import {DepositIntentLib} from "src/lib/DepositIntentLib.sol";

/// @notice Emits ground-truth encoded DepositIntent bytes via Circle's OWN encoder
///         (`DepositIntentLib.encodeDepositIntent`) for two fully-known intents and asserts every
///         DC-1 byte offset. cctp-free, so it compiles on macOS arm64 with `--skip 'test/**'`.
contract ExtractDepositIntentGroundTruth is Script {
    uint32 internal constant VERSION = DEPOSIT_INTENT_VERSION; // 1
    uint256 internal constant AMOUNT = 1_000_000;
    uint32 internal constant REMOTE_DOMAIN = 0xCAFE; // 51966
    bytes32 internal constant REMOTE_TOKEN = 0x52e1ee52e1ee52e1ee52e1ee52e1ee52e1ee52e1ee52e1ee52e1ee52e1ee52e1;
    bytes32 internal constant REMOTE_RECIPIENT = 0x5243aa5243aa5243aa5243aa5243aa5243aa5243aa5243aa5243aa5243aa5243;
    bytes32 internal constant LOCAL_TOKEN = bytes32(uint256(uint160(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)));
    bytes32 internal constant LOCAL_DEPOSITOR = bytes32(uint256(uint160(0x1111111111111111111111111111111111111111)));
    uint256 internal constant MAX_FEE = 5_000;
    bytes32 internal constant NONCE = 0x4e4f4e4345000000000000000000000000000000000000000000000000000001;
    bytes internal constant HOOK_DATA = hex"deadbeefcafe"; // 6 bytes

    function _intent(bytes memory hookData) internal pure returns (DepositIntent memory) {
        return DepositIntent({
            version: VERSION,
            amount: AMOUNT,
            remoteDomain: REMOTE_DOMAIN,
            remoteToken: REMOTE_TOKEN,
            remoteRecipient: REMOTE_RECIPIENT,
            localToken: LOCAL_TOKEN,
            localDepositor: LOCAL_DEPOSITOR,
            maxFee: MAX_FEE,
            nonce: NONCE,
            hookData: hookData
        });
    }

    function _bytes4At(bytes memory d, uint256 o) internal pure returns (bytes4 v) {
        for (uint256 i = 0; i < 4; i++) v |= bytes4(d[o + i]) >> (8 * i);
    }

    function _bytes32At(bytes memory d, uint256 o) internal pure returns (bytes32 v) {
        for (uint256 i = 0; i < 32; i++) v |= bytes32(d[o + i]) >> (8 * i);
    }

    function _u32BeAt(bytes memory d, uint256 o) internal pure returns (uint32 v) {
        for (uint256 i = 0; i < 4; i++) v = (v << 8) | uint8(d[o + i]);
    }

    function _slice(bytes memory d, uint256 s, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i = 0; i < n; i++) out[i] = d[s + i];
    }

    function _verify(bytes memory e, DepositIntent memory it) internal view {
        require(_bytes4At(e, DEPOSIT_INTENT_MAGIC_OFFSET) == DEPOSIT_INTENT_MAGIC, "magic");
        require(DEPOSIT_INTENT_MAGIC_OFFSET == 0, "magic@0");
        require(_u32BeAt(e, DEPOSIT_INTENT_VERSION_OFFSET) == it.version, "version");
        require(DEPOSIT_INTENT_VERSION_OFFSET == 4, "version@4");
        require(uint256(_bytes32At(e, DEPOSIT_INTENT_AMOUNT_OFFSET)) == it.amount, "amount");
        require(DEPOSIT_INTENT_AMOUNT_OFFSET == 8, "amount@8");
        require(_u32BeAt(e, DEPOSIT_INTENT_REMOTE_DOMAIN_OFFSET) == it.remoteDomain, "remoteDomain");
        require(DEPOSIT_INTENT_REMOTE_DOMAIN_OFFSET == 40, "remoteDomain@40");
        require(_bytes32At(e, DEPOSIT_INTENT_REMOTE_TOKEN_OFFSET) == it.remoteToken, "remoteToken");
        require(DEPOSIT_INTENT_REMOTE_TOKEN_OFFSET == 44, "remoteToken@44");
        require(_bytes32At(e, DEPOSIT_INTENT_REMOTE_RECIPIENT_OFFSET) == it.remoteRecipient, "remoteRecipient");
        require(DEPOSIT_INTENT_REMOTE_RECIPIENT_OFFSET == 76, "remoteRecipient@76");
        require(_bytes32At(e, DEPOSIT_INTENT_LOCAL_TOKEN_OFFSET) == it.localToken, "localToken");
        require(DEPOSIT_INTENT_LOCAL_TOKEN_OFFSET == 108, "localToken@108");
        require(_bytes32At(e, DEPOSIT_INTENT_LOCAL_DEPOSITOR_OFFSET) == it.localDepositor, "localDepositor");
        require(DEPOSIT_INTENT_LOCAL_DEPOSITOR_OFFSET == 140, "localDepositor@140");
        require(uint256(_bytes32At(e, DEPOSIT_INTENT_MAX_FEE_OFFSET)) == it.maxFee, "maxFee");
        require(DEPOSIT_INTENT_MAX_FEE_OFFSET == 172, "maxFee@172");
        require(_bytes32At(e, DEPOSIT_INTENT_NONCE_OFFSET) == it.nonce, "nonce");
        require(DEPOSIT_INTENT_NONCE_OFFSET == 204, "nonce@204");
        require(_u32BeAt(e, DEPOSIT_INTENT_HOOK_DATA_LENGTH_OFFSET) == uint32(it.hookData.length), "hookDataLength");
        require(DEPOSIT_INTENT_HOOK_DATA_LENGTH_OFFSET == 236, "hookDataLength@236");
        require(DEPOSIT_INTENT_HOOK_DATA_OFFSET == 240, "hookData@240");
        require(e.length == 240 + it.hookData.length, "total length");
        if (it.hookData.length > 0) {
            require(
                keccak256(_slice(e, DEPOSIT_INTENT_HOOK_DATA_OFFSET, it.hookData.length)) == keccak256(it.hookData),
                "hookData bytes"
            );
        }
        // round-trip through Circle's own decoder/validator
        DepositIntent memory dec = DepositIntentLib.decodeDepositIntent(e);
        require(dec.amount == it.amount && dec.nonce == it.nonce, "roundtrip");
        require(keccak256(dec.hookData) == keccak256(it.hookData), "roundtrip hookData");
    }

    function run() external view {
        // ---- Vector di-circle-1 : non-empty hookData ----
        DepositIntent memory i1 = _intent(HOOK_DATA);
        bytes memory e1 = DepositIntentLib.encodeDepositIntent(i1);
        _verify(e1, i1);
        console.log("=== di-circle-1 (non-empty hookData) length=%d ===", e1.length);
        console.logBytes(e1);
        console.log("messageHash (keccak256 of encoded):");
        console.logBytes32(keccak256(e1));

        // ---- Vector di-circle-2 : empty hookData ----
        DepositIntent memory i2 = _intent("");
        bytes memory e2 = DepositIntentLib.encodeDepositIntent(i2);
        _verify(e2, i2);
        console.log("=== di-circle-2 (empty hookData) length=%d ===", e2.length);
        console.logBytes(e2);
        console.log("messageHash (keccak256 of encoded):");
        console.logBytes32(keccak256(e2));

        console.log("ALL ENVELOPE SELF-CHECKS PASSED");
    }
}
