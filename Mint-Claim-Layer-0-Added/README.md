# MerkleToken

# Overview

MerkleToken is an ERC20 token that incorporates vesting and cross-chain functionality through the use of Merkle proofs, offering a unique approach to token distribution and cross-chain interactions. This smart contract integrates the OpenZeppelin library for ERC20 token and AccessControl functionalities, alongside custom implementations for Merkle proof verification and the LayerZero protocol for cross-chain operations.

### Key Features

* ERC20 Standard: Implements all standard functionalities of an ERC20 token.
* Access Control: Utilizes OpenZeppelin's AccessControl for role-based permissions.
* Merkle Proof Verification: Supports token claims for both NFT holders and specific addresses through Merkle proof verification, ensuring secure and decentralized verification of eligibility.
* Cross-Chain Functionality: Built on the LayerZero protocol, enabling seamless token operations across different blockchains.
* Vesting: Allows NFT holders and addresses to claim tokens based on predefined criteria.
* Role-Based Permissions: Defines roles for operators, burners, and the default admin, enabling a flexible management system.

# Roles and Permissions
* DEFAULT_ADMIN_ROLE: Has the permissions to manage other roles and execute administrative functions.
* OPERATOR_ROLE: Authorized to update Merkle roots and manage contract parameters.
* BURNER_ROLE: Granted permissions to burn tokens from addresses.
