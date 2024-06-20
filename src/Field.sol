// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;


import "forge-std/console.sol";


contract HashToField {

    uint256 b_in_bytes = 32;
    uint256 s_in_bytes = 32;
bytes32 public hash_to_field_tag;

    //The characteristic of a finite field F
    uint256 internal constant FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // The lenth that the extended hash needs to be
    // ceil((ceil(log2(p)) + k) / 8) = 48 bytes where k is the security paramter = 128
    uint256 L = 48;


    constructor() {
        hash_to_field_tag = buildTag("BLS_SIG_HASH_TO_FIELD");
    }

    function buildTag(string memory baseTag) private view returns (bytes32) {
        return keccak256(bytes(abi.encodePacked(baseTag, block.chainid, address(this))));
    }

    function byteSwap(uint256 value) public pure returns (uint256) {
        uint256 swapped = 0;
        for (uint256 i = 0; i < 32; i++) {
            uint256 byteValue = (value >> (i * 8)) & 0xFF;
            swapped |= byteValue << (256 - 8 - (i * 8));
        }
        return swapped;
    }

    // Function to perform XOR on two equal-length strings
    function strxor(bytes memory str1, bytes memory str2) public pure returns (bytes memory) {
        require(str1.length == str2.length, "Strings must be of equal length");

        bytes memory result = new bytes(str1.length);

        for (uint i = 0; i < str1.length; i++) {
            result[i] = bytes1(uint8(str1[i]) ^ uint8(str2[i]));
        }

        return result;
    }
    
    // Integer-to-Octet String Primitive (I2OSP)
    function I2OSP(uint x, uint xLen) public pure returns (string memory) {
        if (xLen < 32 && x >= 256**xLen) {
            revert("integer too large");
        }

        bytes memory digits = new bytes(xLen);
        uint index = xLen - 1;

        while (x != 0) {
            digits[index] = bytes1(uint8(x % 256));
            x /= 256;
            if (index > 0) {
                index--;
            }
        }

        return bytes_to_hex_string(digits);
    }

    // Octet String-to-Integer Primitive (OS2IP)
    function OS2IP(bytes memory X) public pure returns (uint) {
        uint x = 0;
        for (uint i = 0; i < X.length; i++) {
            uint byteValue = uint8(X[X.length - i - 1]);
            x += byteValue * (256 ** i);
        }
        return x;
    }

    function OS2IPModulus(bytes memory X, uint modulus) public pure returns (uint) {
        require(modulus > 0, "Modulus must be greater than zero");
        
        uint x = 0;
        for (uint i = 0; i < X.length; i++) {
            uint byteValue = uint8(X[X.length - i - 1]);
            // Compute each term and immediately take modulus to prevent overflow
            x = (x + (byteValue * (256 ** i) % modulus)) % modulus;
        }
        return x;
    }

    // Function to convert bytes to a hex string
    function bytes_to_hex_string(bytes memory data) public pure returns (string memory) {
        bytes16 hexAlphabet = "0123456789abcdef";
        bytes memory hexString = new bytes(2 * data.length);
        for (uint i = 0; i < data.length; i++) {
            bytes2 hexPair = bytes2(hexAlphabet[uint8(data[i]) >> 4]) | (bytes2(hexAlphabet[uint8(data[i]) & 0xf]) >> 8);
            hexString[2 * i] = hexPair[0];
            hexString[2 * i + 1] = hexPair[1];
        }
        return string(hexString);
    }

    // Function to concatenate an array of bytes32 into a single bytes array
    function concatenate_bytes32_array(bytes32[] memory b) public pure returns (bytes memory) {
        // Calculate the total length of the resulting bytes array
        uint totalLength = b.length * 32;
        bytes memory concatenatedBytes = new bytes(totalLength);

        // Position marker for the resulting bytes array
        uint currentLength = 0;

        // Iterate over the input array and copy each bytes32 to the correct position in bytes
        for (uint i = 0; i < b.length; i++) {
            bytes32 currentBytes32 = b[i];
            for (uint j = 0; j < 32; j++) {
                concatenatedBytes[currentLength++] = currentBytes32[j];
            }
        }

        return concatenatedBytes;
    }

    function bytes32_to_bytes(bytes32 data) public pure returns (bytes memory) {
        bytes memory byteArray = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            byteArray[i] = data[i];
        }
        return byteArray;
    }

    // Function to return a substring of a bytes memory array up to a specified length
    function get_substring(bytes memory uniform_bytes, uint length) public pure returns (bytes memory) {
        require(length <= uniform_bytes.length, "Substring length exceeds the size of the original bytes array");

        bytes memory result = new bytes(length);
        for (uint i = 0; i < length; i++) {
            result[i] = uniform_bytes[i];
        }

        return result;
    }

    function expand_message_xmd(string memory message, bytes32 DST, uint256 len_in_bytes) public view returns (bytes memory) {
        uint256 ell = ceil_div(len_in_bytes, b_in_bytes);
        require(ell < 255, "ell too long");
        require(len_in_bytes < 65535, "len in bytes too long");
        bytes memory DST_prime = abi.encodePacked(DST, I2OSP(32, 1));
        string memory Z_pad = I2OSP(0, s_in_bytes);
        string memory l_i_b_str = I2OSP(len_in_bytes, 2);
        bytes memory msg_prime = abi.encodePacked(Z_pad, message, l_i_b_str, I2OSP(0,1), DST_prime);
        bytes32[] memory b = new bytes32[](ell);
        b[0] = keccak256(msg_prime);
        b[1] = keccak256(abi.encodePacked(b[0], I2OSP(1,1), DST_prime));
        for (uint i = 2; i < ell; i++) {
            b[i] = keccak256(abi.encodePacked(strxor(bytes32_to_bytes(b[0]), bytes32_to_bytes(b[i])), I2OSP(i,1), DST_prime));
        }
        bytes memory uniform_bytes = concatenate_bytes32_array(b);
        return get_substring(uniform_bytes, len_in_bytes);
    }

    function hash_to_field(string memory message) public view returns (uint256) {
        bytes memory tv = expand_message_xmd(message, hash_to_field_tag, L);
        return OS2IPModulus(tv, FIELD_MODULUS);
    }
}
