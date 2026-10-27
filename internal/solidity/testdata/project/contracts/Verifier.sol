// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IQorePQC} from "./IQorePQC.sol";

contract Verifier {
    using ECDSA for bytes32;

    IQorePQC constant PQC = IQorePQC(address(0x0A01));

    function classic(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);
    }

    function viaLibrary(bytes32 h, bytes calldata sig) external pure returns (address) {
        return ECDSA.recover(h, sig);
    }

    function quantum(bytes calldata pk, bytes calldata sig, bytes calldata m) external view returns (bool) {
        return PQC.pqcVerify(pk, sig, m);
    }

    function rawPqc(bytes calldata input) external view returns (bool ok, bytes memory out) {
        (ok, out) = address(0x0A01).staticcall(input);
    }

    function rawEcrecover(bytes memory input) external view returns (bytes32 out) {
        assembly {
            let ok := staticcall(gas(), 0x01, add(input, 0x20), 0x80, out, 0x20)
        }
    }

    function p256(bytes calldata input) external view returns (bool ok, bytes memory out) {
        (ok, out) = address(0x100).staticcall(input);
    }

    function hashes(bytes calldata d) external pure returns (bytes32, bytes32, bytes20) {
        return (keccak256(d), sha256(d), ripemd160(d));
    }
}
