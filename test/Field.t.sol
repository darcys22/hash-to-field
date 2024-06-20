// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {HashToField} from "../src/Field.sol";

import "forge-std/console.sol";

contract FieldTest is Test {
    HashToField public hash_to_field;

    function setUp() public {
        hash_to_field = new HashToField();
    }

    function test_byteSwap() public view {
        uint256 new_field = hash_to_field.byteSwap(5);
        assertEq(new_field, 2261564242916331941866620800950935700259179388000792266395655937654553313280);
    }

    function testStrxorWithEqualLengthStrings() public {
        bytes memory str1 = bytes("abc");
        bytes memory str2 = bytes("XYZ");
        bytes memory expected = hex"393b39"; // Result of XOR between "abc" and "XYZ"

        bytes memory result = hash_to_field.strxor(str1, str2);
        assertEq(result, expected, "XOR of 'abc' and 'XYZ' should match expected result");
    }

    function testStrxorRevertsOnUnequalLength() public {
        bytes memory str1 = bytes("short");
        bytes memory str2 = bytes("longer");

        try hash_to_field.strxor(str1, str2) {
            assertEq(false, true, "Function did not revert with unequal length strings");
        } catch Error(string memory reason) {
            assertEq(reason, "Strings must be of equal length", "Unexpected revert reason");
        }
    }

    function testI2OSPSuccess() public {
        uint x = 12345;
        uint xLen = 3;
        string memory expected = "003039"; // Correct representation of 12345 in 3 bytes

        string memory result = hash_to_field.I2OSP(x, xLen);
        assertEq(result, expected, "I2OSP should correctly convert integer to bytes");
    }

    function testI2OSPFail() public {
        uint x = 12345;
        uint xLen = 1; // Not enough bytes to represent 12345

        try hash_to_field.I2OSP(x, xLen) {
            assertEq(false, true, "I2OSP did not revert with 'integer too large'");
        } catch Error(string memory reason) {
            assertEq(reason, "integer too large", "I2OSP failed with incorrect reason");
        }
    }

    function testOS2IP() public {
        bytes memory X = hex"3039";
        uint expected = 12345;

        uint result = hash_to_field.OS2IP(X);
        assertEq(result, expected, "OS2IP should correctly convert bytes to integer");
    }

    function testI2OSPAsPadding() public {
        uint x = 0;
        uint xLen = 10;
        string memory expected = "00000000000000000000";

        string memory result = hash_to_field.I2OSP(x, xLen);
        assertEq(result, expected, "I2OSP should correctly pad 0 integer to 0 bytes");
    }

    function testI2OSPAsPadding64() public {
        uint x = 0;
        uint xLen = 64;

        string memory result = hash_to_field.I2OSP(x, xLen);
        assertEq(bytes(result).length, xLen * 2, "I2OSP should correctly pad 0 integer to 64 bytes");
    }

    function testExpandMessage() public {
        uint len = 48 + 128;
        bytes memory result = hash_to_field.expand_message_xmd("hello", hash_to_field.hash_to_field_tag(), len);
        assertEq(result.length, len, "returned bytes incorrect length");
    }

    function testHashToField() public {
        (uint256 u0, uint256 u1) = hash_to_field.hash_to_field(abi.encodePacked("Hello"), hash_to_field.bytes32_to_bytes(hash_to_field.hash_to_field_tag()));
        console.log(u0);
        console.log(u1);
    }
}
