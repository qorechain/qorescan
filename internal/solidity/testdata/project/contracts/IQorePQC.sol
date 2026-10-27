// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

interface IQorePQC {
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message) external view returns (bool);
    function pqcKeyStatus(address account) external view returns (bool, uint8, bytes memory, bool);
}
