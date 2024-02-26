// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";


/// @title MerkleToken: ERC20 token with vesting and cross-chain functionality.

contract MerkleToken is ERC20, AccessControl {
   
    // Role for operator
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Role for burner
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
  

    constructor(
        address operator,
        address burner,
        address MERKLEFOUNDATION
    ) ERC20("MerkleToken", "MERK")  {
        _setupRole(DEFAULT_ADMIN_ROLE, MERKLEFOUNDATION);
        _setupRole(BURNER_ROLE, burner);
        _setupRole(OPERATOR_ROLE, operator);
       // Mint 1 billion MERK tokens (with 18 decimal places) to the MERKLEFOUNDATION
        _mint(MERKLEFOUNDATION, 1e27);
    }


     /**
     * @notice Burns a specified amount of tokens from an account.
     * @dev Only callable by accounts with the BURNER_ROLE.
     * @param account The account from which tokens will be burned.
     * @param amount The amount of tokens to burn.
     */
    function Burn(address account, uint256 amount) external onlyRole(BURNER_ROLE){
        _burn(account, amount);
    }


    function Mint(address account, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE){
        _mint(account, amount);
    }

}