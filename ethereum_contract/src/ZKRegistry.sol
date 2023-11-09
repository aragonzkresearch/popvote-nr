// SPDX-License-Identifier: GNU GPLv3
pragma solidity ^0.8.13;

/// Rudimentary ZKRegistry contract
contract ZKRegistry
{
    // The registry is a mapping of the form `address -> uint256 -> bytes32`,
    // where `Type` is an integer representing the curve type of the key
    // and `bytes32` is an appropriate 32-byte compressed representation
    // of the key (e.g. one of the standard compression schemes or a
    // 32-byte hash).

    mapping(address => mapping(uint256 => uint256)) public pk;

    /// Function for key registration
    function register(uint256 curve, uint256 _pk) public
    {
	pk[msg.sender][curve] = _pk;
    }
}
