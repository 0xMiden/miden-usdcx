// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IMessageTransmitter, IXReserve } from "./interfaces/ICircleDeposit.sol";

/// @notice Atomically receives authenticated CCTP USDC and deposits its net principal for Miden.
/// @dev Immutable v1: no cancellation, retargeting, refund or rescue, including accidental donations.
/// Recipient checks establish Miden AccountId v1 syntax only, not ownership or usability.
contract MidenCctpDepositHelper is ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public immutable messageTransmitter;
    address public immutable tokenMessenger;
    address public immutable usdc;
    address public immutable xReserve;
    uint32 public immutable midenDomain;
    bytes32 public immutable expectedMidenFaucet;

    uint256 internal constant MAX_AMOUNT = 9_223_372_034_707_292_160;
    uint64 internal constant GOLDILOCKS_MODULUS = 0xffff_ffff_0000_0001;

    struct Transfer {
        uint32 sourceDomain;
        bytes32 cctpNonce;
        bytes32 midenRecipient;
        uint256 expectedNetAmount;
    }

    error InvalidConfiguration();
    error InvalidMessage();
    error InvalidMidenRecipient();
    error UnexpectedRemoteToken();
    error ReceiveFailed();
    error UnexpectedReceivedAmount();
    error UnexpectedResidualBalance();

    event DepositedToMiden(
        uint32 indexed sourceDomain, bytes32 indexed cctpNonce, bytes32 indexed midenRecipient, uint256 amount
    );

    constructor(
        address messageTransmitter_,
        address tokenMessenger_,
        address usdc_,
        address xReserve_,
        uint32 midenDomain_,
        bytes32 expectedMidenFaucet_
    ) {
        if (
            messageTransmitter_ == address(0) || tokenMessenger_ == address(0) || usdc_ == address(0)
                || xReserve_ == address(0)
        ) revert InvalidConfiguration();
        _validateMidenRecipient(expectedMidenFaucet_);
        messageTransmitter = messageTransmitter_;
        tokenMessenger = tokenMessenger_;
        usdc = usdc_;
        xReserve = xReserve_;
        midenDomain = midenDomain_;
        expectedMidenFaucet = expectedMidenFaucet_;
    }

    /// @notice Anyone may complete a transfer, but only for its authenticated destination and amount.
    /// @dev A revert rolls back Arc nonce/mint/deposit effects. It never reverses the source burn.
    function receiveAndDeposit(bytes calldata message, bytes calldata attestation) external nonReentrant {
        Transfer memory transfer = _decodeAndValidate(message);
        if (IXReserve(xReserve).getRemoteToken(midenDomain, usdc) != expectedMidenFaucet) {
            revert UnexpectedRemoteToken();
        }

        IERC20 token = IERC20(usdc);
        uint256 balanceBefore = token.balanceOf(address(this));
        if (!IMessageTransmitter(messageTransmitter).receiveMessage(message, attestation)) revert ReceiveFailed();
        uint256 balanceAfter = token.balanceOf(address(this));
        if (balanceAfter <= balanceBefore) revert UnexpectedReceivedAmount();
        uint256 received = balanceAfter - balanceBefore;
        if (received != transfer.expectedNetAmount || received > MAX_AMOUNT) revert UnexpectedReceivedAmount();

        token.forceApprove(xReserve, received);
        IXReserve(xReserve).depositToRemote(received, midenDomain, transfer.midenRecipient, usdc, 0, "");
        token.forceApprove(xReserve, 0);
        if (token.balanceOf(address(this)) != balanceBefore || token.allowance(address(this), xReserve) != 0) {
            revert UnexpectedResidualBalance();
        }
        emit DepositedToMiden(transfer.sourceDomain, transfer.cctpNonce, transfer.midenRecipient, received);
    }

    /// @dev Frozen CCTP v2 layout: 148-byte header, 228-byte burn body, 64-byte application hook.
    /// Circle owns signatures, domain/token/messenger authentication, replay, expiry and fee cap.
    /// Standard executed-finality admission is an offchain policy, not another helper guard.
    function _decodeAndValidate(bytes calldata message) internal view returns (Transfer memory transfer) {
        if (message.length != 440) revert InvalidMessage();
        if (uint32(bytes4(message[0:4])) != 1 || uint32(bytes4(message[148:152])) != 1) {
            revert InvalidMessage();
        }
        bytes32 self = bytes32(uint256(uint160(address(this))));
        if (
            bytes32(message[76:108]) != bytes32(uint256(uint160(tokenMessenger))) || bytes32(message[108:140]) != self
                || bytes32(message[184:216]) != self || bytes32(message[376:408]) != bytes32(uint256(1))
        ) revert InvalidMessage();
        (, bytes32 recipient) = abi.decode(message[376:440], (uint32, bytes32));
        _validateMidenRecipient(recipient);
        uint256 gross = uint256(bytes32(message[216:248]));
        uint256 fee = uint256(bytes32(message[312:344]));
        if (gross == 0 || fee >= gross) revert InvalidMessage();
        transfer = Transfer({
            sourceDomain: uint32(bytes4(message[4:8])),
            cctpNonce: bytes32(message[12:44]),
            midenRecipient: recipient,
            expectedNetAmount: gross - fee
        });
    }

    /// @dev Miden protocol/standards/USDCx 0.17.1 EthEmbeddedAccountId decoding predicates.
    function _validateMidenRecipient(bytes32 recipient) internal pure {
        uint256 encoded = uint256(recipient);
        uint64 prefix = uint64(encoded >> 64);
        uint64 suffix = uint64(encoded);
        if (
            encoded >> 128 != 0 || prefix >= GOLDILOCKS_MODULUS || prefix & 0xf != 1 || suffix >> 63 != 0
                || suffix & 0xff != 0
        ) revert InvalidMidenRecipient();
    }
}
