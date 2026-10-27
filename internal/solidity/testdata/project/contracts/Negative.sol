// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// ecrecover(h, v, r, s) in a line comment is not a finding.
/*
   Nor is ecrecover( in a block comment,
   or address(0x0A01).staticcall(x).
*/
contract Negative {
    string public constant NOTE = "ecrecover(h, v, r, s) and keccak256(x) inside a string";

    function myecrecover(uint256 x) external pure returns (uint256) {
        return x;
    }

    function sentinel() external pure returns (address) {
        return address(1);
    }
}
