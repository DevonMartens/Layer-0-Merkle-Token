// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;


import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address owner);

}


/// @title MerkleToken: ERC20 token with vesting and cross-chain functionality.

contract MerkleClaims is AccessControl {
    using SafeERC20 for IERC20;
   
    // Role for operator
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Role for burner
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    // Storage for amount of tokens per NFT
    uint public amountOfTokensPerNFT;

    // Storage for NFTContract
    address public NFTContract;

    // Merkle Root for NFTs
    bytes32 public merkleRoot;

    // Merkle Root for Earnings
    bytes32 public merkleRootForEarnings;

    // Merkle Root For Vesting
    bytes32 public merkleRootForVesting;

    // Storage for the Merkle Foundation
    address private merkleFoundation;

    // Storage for the Merkle Token
    address public merkleToken;

    // Storage for Deploy TimeStamp
    uint public deployTimeStamp;

    // Address is Presale Buyer
    mapping(address => bool) private approvedAddress;

    // Address is Presale Buyer
    mapping(address => bool) private remainderGiven;

    // beneficiary => reccuring vesting schedules
    mapping(address => ReccuringVesting) public reccuringVestingSchedules;

    // multiple vesting schedules per beneficiary
    struct ReccuringVesting {
        uint256 startTimestamp;
        uint256 amountPerWithdrawal;
        uint256 withdrawalInterval;
        uint256 totalTokens;
        uint8 numberOfWithdrawalsExecuted;
        uint8 numberOfTotalWithdrawals;  
    }


    // token => vesting schedules
    mapping(uint256 => bool) public hasTheNFTClaimedTheMerkleToken;
    mapping(address => bool) public hasClaimedEarnedTokens;
    mapping(address => uint) public totalClaimsForAddress;

    // Errors
    error CallerIsNotOwner();
    error RewardAlreadyClaimed();
    error TokensStillLocked();
    error TokensAlreadyClaimed();
    error NotTimeYetOrDuplicateClaim();
    error NotApprovedAddress();


    // Events
    event NFTHasClaimed(address indexed holder, uint256 indexed tokenId, uint256 indexed amount);
    event AddressClaimedEarnedTokens(address indexed earner, uint256 indexed amount);
    event TokensSetToVest(address indexed beneficiary, uint256 indexed totalTokensVesting);


    modifier isApprovedAddress() {
        if(!approvedAddress[msg.sender]){
            revert NotApprovedAddress();
        }
        
        _;
    }


    constructor(
        
        address _merkleToken,
        address _NFTContract,
        address MERKLEFOUNDATION,
        bytes32 _merkleRoot,
        bytes32 _merkleRootForEarnings,
        bytes32 _merkleRootForVesting,
        address operator
    ) {
        deployTimeStamp = block.timestamp;
        merkleToken = _merkleToken;
        merkleFoundation = MERKLEFOUNDATION;
        merkleRoot = _merkleRoot;
        merkleRootForEarnings = _merkleRootForEarnings;
        merkleRootForVesting = _merkleRootForVesting;
        NFTContract = _NFTContract;
        amountOfTokensPerNFT = 2250;
        _setupRole(DEFAULT_ADMIN_ROLE, MERKLEFOUNDATION);
        _setupRole(OPERATOR_ROLE,operator);
    }

     /**
     * @notice Claims tokens for an NFT holder based on a Merkle proof.
     * @dev Verifies the ownership and claim status of the NFT, then mints tokens to the caller.
     * @param tokenId The ID of the NFT.
     * @param amount The amount of tokens to claim.
     * @param merkleProof A Merkle proof proving the claim is valid.
     */
    function claimNFTRelatedTokens(uint256 tokenId, uint256 amount, bytes32[] calldata merkleProof) external {
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
            SafeERC20.safeTransferFrom(IERC20(merkleToken), merkleFoundation, msg.sender, amount);

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
        SafeERC20.safeTransferFrom(IERC20(merkleToken), merkleFoundation, msg.sender, amount);
        emit AddressClaimedEarnedTokens(msg.sender, amount);
    }

    /**
     * @notice Claims tokens based on a vesting schedule with a Merkle proof verification.
     * @dev Verifies the claim hasn't been made yet and the proof is valid before minting tokens to the caller.
     * @param amountOfTotalTokens The total amount of tokens to claim.
     * @param holdPeriod The time to hold the tokens before claiming.
     * @param deliveryPeriod The time to deliver the tokens after the hold period.
     * @param totalMonths The total number of months for the vesting schedule.
     * @param merkleProof A Merkle proof that validates the claim.
     */
    function claimVestingSchedule(
        uint amountOfTotalTokens, 
        uint holdPeriod, 
        uint deliveryPeriod, 
        uint8 totalMonths, 
        bytes32[] calldata merkleProof
        ) external {

        bytes32 leaf = keccak256(abi.encode(msg.sender, amountOfTotalTokens, holdPeriod, deliveryPeriod, totalMonths));
        require(MerkleProof.verify(merkleProof, merkleRootForVesting, leaf), "Invalid Merkle proof for address");

        if (!approvedAddress[msg.sender] && block.timestamp > holdPeriod + deployTimeStamp){
            uint startTime = deployTimeStamp + holdPeriod;
            uint tokensPerWithdraw = amountOfTotalTokens / totalMonths;
            _setUpVesting(startTime, tokensPerWithdraw, amountOfTotalTokens, totalMonths);

        } else {
            revert NotTimeYetOrDuplicateClaim();
        }
        }

        /** 
        * @notice Claims vested tokens based on a vesting schedule.
        * @dev Verifies the claim hasn't been made yet and the proof is valid before minting tokens to the caller.
        * @param claimsPending The number of claims to make.
        */

        function claimVestedTokens(uint8 claimsPending) external isApprovedAddress(){

            ReccuringVesting storage vesting = reccuringVestingSchedules[msg.sender];

            if (vesting.numberOfWithdrawalsExecuted == vesting.numberOfTotalWithdrawals) {
                if(!remainderGiven[msg.sender]) {
                    uint remainder = vesting.totalTokens % vesting.numberOfTotalWithdrawals;
                    remainderGiven[msg.sender] = true;
                    SafeERC20.safeTransferFrom(IERC20(merkleToken), merkleFoundation, msg.sender, remainder);
                } else {
                revert TokensAlreadyClaimed();
                }
        }

        uint month = 30 days; 

        uint months = vesting.numberOfWithdrawalsExecuted * month; // 0

        uint monthsBeingClaimed = claimsPending * month; // 1 month

        if(block.timestamp < vesting.startTimestamp + months + monthsBeingClaimed) {
            revert TokensStillLocked();
        }
         uint256 amount = vesting.amountPerWithdrawal * claimsPending;

        vesting.numberOfWithdrawalsExecuted += claimsPending;
       
     
        SafeERC20.safeTransferFrom(IERC20(merkleToken), merkleFoundation, msg.sender, amount);
    }

    /**
     * @notice Sets the Merkle Token address.
     * @dev Only callable by accounts with the DEFAULT_ADMIN_ROLE.
     * @param _merkleToken The new Merkle Token address.
     */

    function setMerkleToken(address _merkleToken) external onlyRole(DEFAULT_ADMIN_ROLE){
        merkleToken = _merkleToken;
    }

    /**
     * @notice Sets the Merkle Foundation address.
     * @dev Only callable by accounts with the DEFAULT_ADMIN_ROLE.
     * @param _merkleFoundation The new Merkle Foundation address.
     */

    function setMerkleFoundation(address _merkleFoundation) external onlyRole(DEFAULT_ADMIN_ROLE){
        merkleFoundation = _merkleFoundation;
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

    /**
     * @notice Sets the Merkle root for vesting-based token claims.
     * @dev Assumes the same role-based access control for consistency.
     * @param _merkleRootForVesting The new Merkle root for vesting-based claims.
     */
    function setMerkleRootForVesting(bytes32 _merkleRootForVesting) external onlyRole(OPERATOR_ROLE){
        merkleRootForVesting = _merkleRootForVesting;
    }

    /**
     * @notice Sets the NFT contract address.
     * @dev Only callable by accounts with the OPERATOR_ROLE.
     * @param _NFTContract The new NFT contract address.
     */
    function setNFTAddress(address _NFTContract) external onlyRole(OPERATOR_ROLE){
        NFTContract = _NFTContract;

    }

    /**
     * @notice Sets the amount of tokens per NFT.
     * @dev Only callable by accounts with the OPERATOR_ROLE.
     * @param _amountOfTokensPerNFT The new amount of tokens per NFT.
     */
    function setTokensPerNFT(uint _amountOfTokensPerNFT) external onlyRole(OPERATOR_ROLE){
        amountOfTokensPerNFT = _amountOfTokensPerNFT;

    }

    /**
     * @notice Sets the approved address for claiming tokens.
     * @dev Only callable by accounts with the OPERATOR_ROLE.
     * @param _address The new approved address.
     */
    function _setUpVesting(       
        uint256 startTimestamp,
      uint256 amountPerWithdrawal,
        uint256 totalTokens,
        uint8 numberOfWithdrawals
        ) internal
        { 

        reccuringVestingSchedules[msg.sender] = (ReccuringVesting(
            startTimestamp,
            amountPerWithdrawal, 
            30 days, 
            totalTokens,
            0,
            numberOfWithdrawals
        ));
        approvedAddress[msg.sender] = true;
        emit TokensSetToVest(
            msg.sender, 
            totalTokens
            );
        
    }
}