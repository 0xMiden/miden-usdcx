pragma solidity 0.7.6;

// Compile the exact Circle contracts used by the local fixture.
import {MessageTransmitterV2} from "src/v2/MessageTransmitterV2.sol";
import {TokenMessengerV2} from "src/v2/TokenMessengerV2.sol";
import {TokenMinterV2} from "src/v2/TokenMinterV2.sol";
import {AdminUpgradableProxy} from "src/proxy/AdminUpgradableProxy.sol";
