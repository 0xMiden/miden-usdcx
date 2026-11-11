// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { MidenCctpDepositHelper } from "../../contracts/MidenCctpDepositHelper.sol";

/// @dev Test-only mint/burn token. These switches are fault injection, not Circle token behavior.
contract TestToken is ERC20 {
    error TokenFault();
    uint8 public approvalMode;
    bool public stickyAllowance;
    bool public blocked;

    constructor() ERC20("Local test USDC", "tUSDC") { }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address recipient, uint256 value) external returns (bool) {
        _mint(recipient, value);
        return true;
    }

    function burn(uint256 value) external {
        _burn(msg.sender, value);
    }

    function burnFrom(address account, uint256 value) external {
        _burn(account, value);
    }

    function setApprovalMode(uint8 mode, bool sticky) external {
        approvalMode = mode;
        stickyAllowance = sticky;
    }

    function setBlocked(bool value) external {
        blocked = value;
    }

    function approve(address spender, uint256 value) public override returns (bool) {
        if (approvalMode == 1) return false;
        if (approvalMode == 2) revert TokenFault();
        if (approvalMode == 3 && value == 0) return true;
        return super.approve(spender, value);
    }

    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        if (blocked) revert TokenFault();
        if (stickyAllowance) {
            require(allowance(from, msg.sender) >= value);
            _transfer(from, to, value);
            return true;
        }
        return super.transferFrom(from, to, value);
    }
}

contract FaultReceiver {
    error ReceiverFault();
    TestToken public token;
    mapping(bytes32 => bool) public used;
    uint256 public deltaOverride = type(uint256).max;
    uint256 public burnAmount;
    bool public returnFalse;

    constructor(TestToken token_) {
        token = token_;
    }

    function configure(uint256 delta, uint256 burnValue, bool falseResult) external {
        deltaOverride = delta;
        burnAmount = burnValue;
        returnFalse = falseResult;
    }

    function receiveMessage(bytes calldata message, bytes calldata) external returns (bool) {
        bytes32 nonce = bytes32(message[12:44]);
        require(!used[nonce], "fixture replay");
        used[nonce] = true;
        if (burnAmount != 0) token.burnFrom(msg.sender, burnAmount);
        uint256 value = deltaOverride == type(uint256).max
            ? uint256(bytes32(message[216:248])) - uint256(bytes32(message[312:344]))
            : deltaOverride;
        token.mint(msg.sender, value);
        return !returnFalse;
    }
}

contract FaultReserve {
    error ReserveFault();
    bytes32 public remoteToken;
    uint256 public shortfall;
    bool public fails;
    uint8 public reentryMode;
    bool public caught;
    uint256 public count;
    uint256 public total;
    uint256 public observedAllowance;
    bytes32 public lastRecipient;
    bytes public nestedMessage;

    constructor(bytes32 faucet) {
        remoteToken = faucet;
    }

    function getRemoteToken(uint32, address) external view returns (bytes32) {
        return remoteToken;
    }

    function setRemoteToken(bytes32 value) external {
        remoteToken = value;
    }

    function configure(uint256 shortfall_, bool fails_, uint8 mode, bytes calldata message) external {
        shortfall = shortfall_;
        fails = fails_;
        reentryMode = mode;
        nestedMessage = message;
    }

    function depositToRemote(
        uint256 value,
        uint32 domain,
        bytes32 recipient,
        address token,
        uint256 fee,
        bytes calldata hook
    ) external {
        require(domain == 10007 && fee == 0 && hook.length == 0, "fixture arguments");
        if (fails) revert ReserveFault();
        observedAllowance = IERC20(token).allowance(msg.sender, address(this));
        IERC20(token).transferFrom(msg.sender, address(this), value - shortfall);
        count++;
        total += value;
        lastRecipient = recipient;
        if (reentryMode != 0) {
            (bool ok, bytes memory reason) =
                msg.sender.call(abi.encodeCall(MidenCctpDepositHelper.receiveAndDeposit, (nestedMessage, bytes(""))));
            require(!ok, "nested execution succeeded");
            require(bytes4(reason) == bytes4(keccak256("ReentrancyGuardReentrantCall()")), "unexpected reentry failure");
            if (reentryMode == 1) assembly { revert(add(reason, 32), mload(reason)) }
            caught = true;
        }
    }
}

/// @dev GatewayWallet STUB. It actually pulls all principal and records the genuine reserve beneficiary.
contract GatewayPullStub {
    error GatewayFault();
    bool public fails;
    uint256 public total;
    address public beneficiary;

    function setFail(bool value) external {
        fails = value;
    }

    function depositFor(address token, address beneficiary_, uint256 value) external {
        if (fails) revert GatewayFault();
        require(IERC20(token).transferFrom(msg.sender, address(this), value));
        total += value;
        beneficiary = beneficiary_;
    }
}

/// @dev Same ABI tuple as Circle IRemoteDomainHookExecutor; no imported alternate compiler graph.
contract DomainHook {
    struct DepositParams {
        uint256 value;
        uint32 remoteDomain;
        bytes32 remoteRecipient;
        address localToken;
        uint256 maxFee;
        bytes hookData;
    }
    error HookFault();
    bool public fails;
    uint8 public reentryMode;
    bool public caught;
    address public helper;
    bytes public message;
    bytes public attestation;

    function configure(bool fails_, uint8 mode, address helper_, bytes calldata message_, bytes calldata attestation_)
        external
    {
        fails = fails_;
        reentryMode = mode;
        helper = helper_;
        message = message_;
        attestation = attestation_;
    }

    function executeHook(DepositParams calldata) external {
        if (fails) revert HookFault();
        if (reentryMode != 0) {
            (bool ok, bytes memory reason) =
                helper.call(abi.encodeCall(MidenCctpDepositHelper.receiveAndDeposit, (message, attestation)));
            require(!ok && bytes4(reason) == bytes4(keccak256("ReentrancyGuardReentrantCall()")), "bad nested result");
            if (reentryMode == 1) assembly { revert(add(reason, 32), mload(reason)) }
            caught = true;
        }
    }
}

interface IBurnMessenger {
    function depositForBurnWithHook(uint256, uint32, bytes32, address, bytes32, uint256, uint32, bytes calldata)
        external;
}

/// @dev Two identical original burns in one source transaction; attestations later assign distinct nonces.
contract LocalBatch {
    function burnTwice(address token, address messenger, bytes32 helper, bytes calldata hook) external {
        require(IERC20(token).approve(messenger, 2_000_000));
        IBurnMessenger(messenger).depositForBurnWithHook(1_000_000, 26, helper, token, helper, 0, 2000, hook);
        IBurnMessenger(messenger).depositForBurnWithHook(1_000_000, 26, helper, token, helper, 0, 2000, hook);
    }
}
