// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { BaseTest } from "../Base.t.sol";
import { MidenCctpDepositHelper } from "../../contracts/MidenCctpDepositHelper.sol";
import { TestToken, GatewayPullStub, DomainHook } from "../mocks/FaultDependencies.sol";

interface IRealTransmitter {
    function receiveMessage(bytes calldata, bytes calldata) external returns (bool);
    function usedNonces(bytes32) external view returns (uint256);
    function localDomain() external view returns (uint32);
    function version() external view returns (uint32);
    function signatureThreshold() external view returns (uint256);
}

interface IRealMessenger {
    function addRemoteTokenMessenger(uint32, bytes32) external;
    function setFeeRecipient(address) external;
}

interface IRealMinter {
    function addLocalTokenMessenger(address) external;
    function linkTokenPair(address, uint32, bytes32) external;
}

interface IRealReserve {
    function registerRemoteDomain(uint32, address, address, address[] calldata, uint256, uint256, address)
        external
        returns (address);
    function registerRemoteToken(address, uint32, bytes32) external;
    function deregisterRemoteToken(uint32, bytes32) external;
    function setRemoteDomainHookExecutor(uint32, address) external;
    function setDomainPauseState(uint32, bool, bool) external;
    function pause() external;
    function unpause() external;
    function blocklist(uint32, bytes32) external;
    function unblocklist(uint32, bytes32) external;
    function getRemoteToken(uint32, address) external view returns (bytes32);
    function getRemoteDomainDepositor(uint32) external view returns (address);
    function owner() external view returns (address);
}

interface IRealDomain {
    function signatureThreshold() external view returns (uint256);
    function persistentSignatureBufferDelayBlocks() external view returns (uint256);
    function numPersistentEnabledAttesters() external view returns (uint256);
}

/// @notice Genuine Circle proxies, implementations and formatter, separately compiled without pragma rewrites.
abstract contract CircleFixture is BaseTest {
    IRealTransmitter internal transmitter;
    IRealMinter internal minter;
    IRealReserve internal xreserve;
    GatewayPullStub internal gateway;
    DomainHook internal hook;
    address internal remoteDepositor;

    function setUp() public virtual override {
        _setUpCodec();
        token = new TestToken();
        gateway = new GatewayPullStub();
        hook = new DomainHook();
        _setUpCctp();
        _setUpReserve();
        helper = new MidenCctpDepositHelper(
            address(transmitter), messenger, address(token), address(xreserve), 10007, FAUCET
        );
    }

    function _cctp(string memory name, bytes memory args) internal returns (address) {
        return _deploy(string.concat("reference/cctp/artifacts/", name, ".sol/", name, ".json"), args);
    }

    function _xr(string memory name, bytes memory args) internal returns (address) {
        return _deploy(string.concat("reference/xreserve/artifacts/", name, ".sol/", name, ".json"), args);
    }

    function _setUpCctp() private {
        minter = IRealMinter(_cctp("TokenMinterV2", abi.encode(address(this))));
        address mtImpl = _cctp("MessageTransmitterV2", abi.encode(uint32(26), uint32(1)));
        address[] memory attesters = new address[](1);
        attesters[0] = vm.addr(TEST_ATTESTER_KEY);
        bytes memory init = abi.encodeWithSignature(
            "initialize(address,address,address,address,address[],uint256,uint256)",
            address(this),
            address(this),
            address(this),
            address(this),
            attesters,
            1,
            8192
        );
        transmitter = IRealTransmitter(_cctp("AdminUpgradableProxy", abi.encode(mtImpl, address(this), init)));
        assertEq(transmitter.localDomain(), 26);
        assertEq(transmitter.version(), 1);
        assertEq(transmitter.signatureThreshold(), 1);
        address tmImpl = _cctp("TokenMessengerV2", abi.encode(address(transmitter), uint32(1)));
        address[6] memory roles =
            [address(this), address(this), feeRecipient, address(this), address(minter), address(this)];
        init = abi.encodeWithSignature(
            "initialize((address,address,address,address,address,address),uint256,uint32[],bytes32[])",
            roles,
            0,
            new uint32[](0),
            new bytes32[](0)
        );
        messenger = _cctp("AdminUpgradableProxy", abi.encode(tmImpl, address(this), init));
        minter.addLocalTokenMessenger(messenger);
        for (uint32 domain; domain <= 5; domain += 5) {
            IRealMessenger(messenger).addRemoteTokenMessenger(domain, SOURCE_MESSENGER);
            minter.linkTokenPair(address(token), domain, SOURCE_TOKEN);
        }
    }

    function _setUpReserve() private {
        address placeholder = _xr("UpgradeablePlaceholder", "");
        address proxy =
            _xr("ERC1967Proxy", abi.encode(placeholder, abi.encodeWithSignature("initialize(address)", address(this))));
        address domainImpl = _xr("RemoteDomainDepositor", "");
        address implementation = _xr("xReserve", abi.encode(address(gateway), address(gateway), messenger, messenger));
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        bytes memory init = abi.encodeWithSignature(
            "initialize(uint32,address,address,address,address[],address)",
            uint32(26),
            address(this),
            address(this),
            address(this),
            tokens,
            domainImpl
        );
        (bool ok, bytes memory reason) =
            proxy.call(abi.encodeWithSignature("upgradeToAndCall(address,bytes)", implementation, init));
        if (!ok) assembly { revert(add(reason, 32), mload(reason)) }
        xreserve = IRealReserve(proxy);
        assertEq(xreserve.owner(), address(this));
        address[] memory attesters = new address[](2);
        attesters[0] = vm.addr(2);
        attesters[1] = vm.addr(3);
        remoteDepositor =
            xreserve.registerRemoteDomain(10007, address(this), address(this), attesters, 2, 1, address(0));
        assertEq(IRealDomain(remoteDepositor).signatureThreshold(), 2);
        assertEq(IRealDomain(remoteDepositor).numPersistentEnabledAttesters(), 2);
        assertEq(IRealDomain(remoteDepositor).persistentSignatureBufferDelayBlocks(), 1);
        xreserve.registerRemoteToken(address(token), 10007, FAUCET);
        assertEq(xreserve.getRemoteToken(10007, address(token)), FAUCET);
    }

    function _assertRolledBack(bytes32 nonce, uint256 donation, uint256 priorTotal) internal view {
        assertEq(transmitter.usedNonces(nonce), 0);
        assertEq(token.balanceOf(address(helper)), donation);
        assertEq(token.balanceOf(address(xreserve)), 0);
        assertEq(token.balanceOf(address(gateway)), priorTotal);
        assertEq(gateway.total(), priorTotal);
        assertEq(token.balanceOf(feeRecipient), 0);
        assertEq(token.totalSupply(), donation + priorTotal);
        assertEq(token.allowance(address(helper), address(xreserve)), 0);
    }

    function _rejectCircle(bytes memory message, bytes memory signature, bytes memory reason) internal {
        vm.expectCall(address(transmitter), abi.encodeCall(transmitter.receiveMessage, (message, signature)), 1);
        vm.expectRevert(reason);
        helper.receiveAndDeposit(message, signature);
        _assertRolledBack(bytes32(uint256(1)), 0, 0);
    }
}
