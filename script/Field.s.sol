// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

contract FieldScript is Script {
    function setUp() public {}

    function run() public {
        vm.broadcast();
    }
}
