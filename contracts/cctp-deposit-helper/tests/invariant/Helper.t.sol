// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import { BaseTest } from "../Base.t.sol";
import { HelperHandler } from "./handlers/HelperHandler.sol";

contract HelperInvariantTest is BaseTest {
    HelperHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new HelperHandler(helper, token, receiver, reserve, codec);
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = handler.donate.selector;
        selectors[1] = handler.complete.selector;
        selectors[2] = handler.duplicate.selector;
        selectors[3] = handler.downstreamFailure.selector;
        targetSelector(FuzzSelector({ addr: address(handler), selectors: selectors }));
        targetContract(address(handler));
    }

    function invariant_PrincipalDonationsAllowanceAndUniqueNonceAccounting() external view {
        handler.assertAccounting();
    }
}
