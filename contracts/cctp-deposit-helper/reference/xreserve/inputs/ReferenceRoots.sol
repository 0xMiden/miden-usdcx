pragma solidity 0.8.29;

// Keep the fixture closure separate from upstream tests and scripts.
import {xReserve} from "src/xReserve.sol";
import {RemoteDomainDepositor} from "src/RemoteDomainDepositor.sol";
import {UpgradeablePlaceholder} from "src/UpgradeablePlaceholder.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
