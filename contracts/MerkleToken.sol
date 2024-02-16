// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "./layer0/BaseOFTV2.sol";
import "./layer0/OFTCoreV2.sol";

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address owner);

}


/// @title MerkleToken: ERC20 token with vesting and cross-chain functionality.

contract MerkleToken is BaseOFTV2, ERC20, AccessControl {
   
    // Role for operator
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Role for burner
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    // rate between layer 0
    uint internal immutable ld2sdRate;

    // Storage for amount of tokens per NFT
    uint public amountOfTokensPerNFT;

    // Storage for NFTContract
    address public NFTContract;

    // Merkle Root for NFTs
    bytes32 public merkleRoot;

    // Merkle Root for Earnings
    bytes32 public merkleRootForEarnings;

    // token => vesting schedules
    mapping(uint256 => bool) public hasTheNFTClaimedTheMerkleToken;
    mapping(address => bool) public hasClaimedEarnedTokens;

    // Errors
    error CallerIsNotOwner();
    error RewardAlreadyClaimed();


    // Events
    event NFTHasClaimed(address indexed holder, uint256 indexed tokenId, uint256 indexed amount);
    event AddressClaimedEarnedTokens(address indexed earner, uint256 indexed amount);

    constructor(
        address operator,
        address burner,
        address _NFTContract,
        uint8 _sharedDecimals,
        address _lzEndpoint,
        bytes32 _merkleRoot,
        bytes32 _merkleRootForEarnings
    ) ERC20("MerkleToken", "KTS") BaseOFTV2(_sharedDecimals, _lzEndpoint) {
        uint8 decimals = decimals();
        merkleRoot = _merkleRoot;
        NFTContract = _NFTContract;
        merkleRootForEarnings = _merkleRootForEarnings;
        require(_sharedDecimals <= decimals, "OFT: sharedDecimals must be <= decimals");
        ld2sdRate = 10**(decimals - _sharedDecimals);
        amountOfTokensPerNFT = 2250;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(BURNER_ROLE, burner);
        _setupRole(OPERATOR_ROLE,operator);
        _mint(msg.sender, 0);
    }

     /**
     * @notice Claims tokens for an NFT holder based on a Merkle proof.
     * @dev Verifies the ownership and claim status of the NFT, then mints tokens to the caller.
     * @param tokenId The ID of the NFT.
     * @param amount The amount of tokens to claim.
     * @param merkleProof A Merkle proof proving the claim is valid.
     */
    function claimNFTMerkleToken(uint256 tokenId, uint256 amount, bytes32[] calldata merkleProof) external {
            if(IERC721(NFTContract).ownerOf(tokenId) != msg.sender){
                revert CallerIsNotOwner();

            }
            if(hasTheNFTClaimedTheMerkleToken[tokenId] == true){
                revert RewardAlreadyClaimed();
            }
            // Verify the Merkle proof
            bytes32 leaf = keccak256(abi.encode(tokenId, amount));
            require(MerkleProof.verify(merkleProof, merkleRoot, leaf), "Invalid Merkle proof");

            // Mark as claimed and transfer the ERC-20 tokens
            hasTheNFTClaimedTheMerkleToken[tokenId] = true;
            amount += amountOfTokensPerNFT;
            _mint(msg.sender, amount);

        emit NFTHasClaimed(msg.sender, tokenId, amount);
    }

    /**
     * @notice Claims tokens based on an address and amount with a Merkle proof verification.
     * @dev Verifies the claim hasn't been made yet and the proof is valid before minting tokens to the caller.
     * @param amount The amount of tokens to claim.
     * @param merkleProof A Merkle proof that validates the claim.
     */
    function claimForAddress(uint256 amount, bytes32[] calldata merkleProof) external {
        if(hasClaimedEarnedTokens[msg.sender] == true){
            revert RewardAlreadyClaimed();
        }

        bytes32 leaf = keccak256(abi.encode(msg.sender, amount));
        require(MerkleProof.verify(merkleProof, merkleRootForEarnings, leaf), "Invalid Merkle proof for address");

        hasClaimedEarnedTokens[msg.sender] = true;
        _mint(msg.sender, amount);

        emit AddressClaimedEarnedTokens(msg.sender, amount);
    }

     /**
     * @notice Sets the Merkle root for NFT-based token claims.
     * @dev Only callable by accounts with the OPERATOR_ROLE.
     * @param _merkleRoot The new Merkle root.
     */
    function setMerkleRoot(bytes32 _merkleRoot) external onlyRole(OPERATOR_ROLE){
        merkleRoot = _merkleRoot;
    }

    /**
     * @notice Sets the Merkle root for address-based token claims.
     * @dev Assumes the same role-based access control for consistency.
     * @param _merkleRootForEarnings The new Merkle root for address-based claims.
     */
    function setMerkleRootForEarnings(bytes32 _merkleRootForEarnings) external onlyRole(OPERATOR_ROLE){
        merkleRootForEarnings = _merkleRootForEarnings;
    }

    function setNFTAddress(address _NFTContract) external onlyRole(OPERATOR_ROLE){
        NFTContract = _NFTContract;

    }

    function setTokensPerNFT(uint _amountOfTokensPerNFT) external onlyRole(OPERATOR_ROLE){
        amountOfTokensPerNFT = _amountOfTokensPerNFT;

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

    // layer 0 functions
    /************************************************************************
     * public functions
     ************************************************************************/
    function circulatingSupply() public view virtual override returns (uint) {
        return totalSupply();
    }

    function token() public view virtual override returns (address) {
        return address(this);
    }

    /************************************************************************
     * internal functions
     ************************************************************************/
    function _debitFrom(
        address _from,
        uint16,
        bytes32,
        uint _amount
    ) internal virtual override returns (uint) {
        address spender = _msgSender();
        if (_from != spender) _spendAllowance(_from, spender, _amount);
        _burn(_from, _amount);
        return _amount;
    }

    function _creditTo(
        uint16,
        address _toAddress,
        uint _amount
    ) internal virtual override returns (uint) {
        _mint(_toAddress, _amount);
        return _amount;
    }

    function _transferFrom(
        address _from,
        address _to,
        uint _amount
    ) internal virtual override returns (uint) {
        address spender = _msgSender();
        // if transfer from this contract, no need to check allowance
        if (_from != address(this) && _from != spender) _spendAllowance(_from, spender, _amount);
        _transfer(_from, _to, _amount);
        return _amount;
    }

    function _ld2sdRate() internal view virtual override returns (uint) {
        return ld2sdRate;
    }

    // Required override for LayerZero + AccessControl
      function supportsInterface(bytes4 interfaceId) public view virtual override(BaseOFTV2, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}