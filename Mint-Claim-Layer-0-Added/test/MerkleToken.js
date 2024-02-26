const { expect } = require("chai");
const { ethers } = require("hardhat");
const {time } = require("@nomicfoundation/hardhat-network-helpers");
const { keccak256 } = ethers.utils;
const { MerkleTree } = require("merkletreejs");

const { expectRevert } = require('@openzeppelin/test-helpers');


function hashTokenIdAmountPair(tokenId, amount) {
  return keccak256(ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [tokenId, amount]));
}

function hashAddressAmountPair(address, amount) {
  return keccak256(ethers.utils.defaultAbiCoder.encode(['address', 'uint256'], [address, amount]));
}

describe("merkleToken Contract", function () {
  let merkleToken;
  let owner;
  let addr1;
  let addr2;
  let addrs;
  let merkleTreeAddressAmount;
  let nft;
  let merkleTreeTokenIdAmount;
  let rootTokenIdAmount;
  let rootAddressAmount;


  // This is a global setup function that runs before all tests
  beforeEach(async function () {
    const MerkleToken = await ethers.getContractFactory("MerkleToken");
    const NFT = await ethers.getContractFactory("NFT");
    [owner, addr1, addr2, ...addrs] = await ethers.getSigners();
    console.log("OWNER", + " ",  owner.address)

    const addressAmountPairs = [
      { address: owner.address.toString(), amount: '300' },
      { address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', amount: '400' },
    ];

    const tokenIdAmountPairs = [
      { tokenId: '0', amount: '50' },
      { tokenId: '1', amount: '100' },
      { tokenId: '2', amount: '200' },
    ];

    function hashTokenIdAmountPair(tokenId, amount) {
      return keccak256(ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [tokenId, amount]));
    }

    function hashAddressAmountPair(address, amount) {
      return keccak256(ethers.utils.defaultAbiCoder.encode(['address', 'uint256'], [address, amount]));
    }

    const leafNodesTokenIdAmount = tokenIdAmountPairs.map(pair => hashTokenIdAmountPair(pair.tokenId, pair.amount));
    merkleTreeTokenIdAmount = new MerkleTree(leafNodesTokenIdAmount, keccak256, { sortPairs: true });

    const leafNodesAddressAmount = addressAmountPairs.map(pair => hashAddressAmountPair(pair.address, pair.amount));
    merkleTreeAddressAmount = new MerkleTree(leafNodesAddressAmount, keccak256, { sortPairs: true });

    rootTokenIdAmount = "0x" + merkleTreeTokenIdAmount.getRoot().toString('hex');
    rootAddressAmount = "0x" + merkleTreeAddressAmount.getRoot().toString('hex');

    console.log("Merkle Root (Token ID to Amount):", rootTokenIdAmount);
    console.log("Merkle Root (Address to Amount):", rootAddressAmount);

    // Deploy Dummy NFT
    nft = await NFT.deploy();

    // Deploy the merkleToken contract with corrected root formats
    merkleToken = await MerkleToken.deploy(owner.address, owner.address, nft.address, 18, owner.address, rootTokenIdAmount, rootAddressAmount);
    await merkleToken.deployed();
  });


  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      expect(await merkleToken.owner()).to.equal(owner.address);
    });

    it("Should assign the total supply of tokens to the owner", async function () {


      const ownerBalance = await merkleToken.balanceOf(owner.address);
      expect(await merkleToken.totalSupply()).to.equal(ownerBalance);
    });
  });
  describe("Claimes", function () {
    it("Address can claim earned tokens", async function () {
      // Use BigNumber for the amount to ensure consistency with uint256 in Solidity
      const claimAmount = "300"; // Adjust based on your token's decimals
  
      // Generate the leaf node using the adjusted claim amount
      const leaf = hashAddressAmountPair(owner.address, claimAmount.toString());
  
      // Generate the proof
      const proof = merkleTreeAddressAmount.getHexProof(leaf);
  
      // Verify the proof as a sanity check (optional)
      const isValidProof = merkleTreeAddressAmount.verify(proof, leaf, merkleTreeAddressAmount.getHexRoot());
      console.log("Is the proof valid?", isValidProof);
      console.log(claimAmount.toString())
      
      // Attempt to claim tokens
      await expect(merkleToken.connect(owner).claimForAddress(claimAmount, proof))
          .to.emit(merkleToken, "AddressClaimedEarnedTokens")
          .withArgs(owner.address, claimAmount.toString());
  
      // Verify the claim was successful
      const hasClaimed = await merkleToken.hasClaimedEarnedTokens(owner.address);
      expect(hasClaimed).to.be.true;
  });
  it("Address cant calim if its for the wrong amount", async function () {
    // Use BigNumber for the amount to ensure consistency with uint256 in Solidity
    const claimAmount = "400"; // Adjust based on your token's decimals

    // Generate the leaf node using the adjusted claim amount
    const leaf = hashAddressAmountPair(owner.address, claimAmount.toString());

    // Generate the proof
    const proof = merkleTreeAddressAmount.getHexProof(leaf);

    // Verify the proof as a sanity check (optional)
    const isValidProof = merkleTreeAddressAmount.verify(proof, leaf, merkleTreeAddressAmount.getHexRoot());
    console.log("Is the proof valid?", isValidProof);
    console.log(claimAmount.toString())
    
    // Attempt to claim tokens
    await expectRevert(merkleToken.connect(owner).claimForAddress(claimAmount, proof), "Invalid Merkle proof for address");
});
  it("Address cant claim earned tokens twice", async function () {
    // Use BigNumber for the amount to ensure consistency with uint256 in Solidity
    const claimAmount = "300"; // Adjust based on your token's decimals

    // Generate the leaf node using the adjusted claim amount
    const leaf = hashAddressAmountPair(owner.address, claimAmount.toString());

    // Generate the proof
    const proof = merkleTreeAddressAmount.getHexProof(leaf);

    // Verify the proof as a sanity check (optional)
    const isValidProof = merkleTreeAddressAmount.verify(proof, leaf, merkleTreeAddressAmount.getHexRoot());
    console.log("Is the proof valid?", isValidProof);
    console.log(claimAmount.toString())
    
    // Attempt to claim tokens
    await expect(merkleToken.connect(owner).claimForAddress(claimAmount, proof))
        .to.emit(merkleToken, "AddressClaimedEarnedTokens")
        .withArgs(owner.address, claimAmount.toString());

    // Verify the claim was successful
    const hasClaimed = await merkleToken.hasClaimedEarnedTokens(owner.address);
    expect(hasClaimed).to.be.true;
    await expectRevert(
      merkleToken.connect(owner).claimForAddress(claimAmount, proof), 
      "RewardAlreadyClaimed()"

    )
});
  it("NFT Owner can claim tokens", async function () {
 
      await nft.mint(1);
      const owner = await nft.ownerOf(0);

      console.log(`Owner of token 0 is ${owner}`);
  
   //  console.log(check);
      const token = 0;
      const amount = 50; 
      const leaf = hashTokenIdAmountPair(token, amount);
      const proof = merkleTreeTokenIdAmount.getHexProof(leaf);

      await merkleToken.claimNFTMerkleToken(token, amount, proof);
      const hey = await merkleToken.balanceOf(owner);
      console.log(hey);


  });
  it("If a user is not the owner of a NFT then they cant claim tokens", async function () {
 
    await nft.mint(1);
    const owner = await nft.ownerOf(0);

    console.log(`Owner of token 0 is ${owner}`);

 //  console.log(check);
    const token = 0;
    const amount = 50; 
    const leaf = hashTokenIdAmountPair(token, amount);
    const proof = merkleTreeTokenIdAmount.getHexProof(leaf);

    await expectRevert(
      merkleToken.connect(addr1).claimNFTMerkleToken(token, amount, proof), "CallerIsNotOwner()"
      );

});
it("If NFT token id has claimed then the cant claim tokens", async function () {
 
  await nft.mint(1);
  const owner = await nft.ownerOf(0);

  console.log(`Owner of token 0 is ${owner}`);

//  console.log(check);
  const token = 0;
  const amount = 50; 
  const leaf = hashTokenIdAmountPair(token, amount);
  const proof = merkleTreeTokenIdAmount.getHexProof(leaf);
  await merkleToken.claimNFTMerkleToken(token, amount, proof);

  await expectRevert(
    merkleToken.claimNFTMerkleToken(token, amount, proof), "RewardAlreadyClaimed()"
    );

});
it("a user can only claim the tokens they own", async function () {
 
  await nft.mint(1);
  const owner = await nft.ownerOf(0);

  console.log(`Owner of token 0 is ${owner}`);

//  console.log(check);
  const token = 0;
  const amount = 1000; 
  const leaf = hashTokenIdAmountPair(token, amount);
  const proof = merkleTreeTokenIdAmount.getHexProof(leaf);

  await expectRevert(
    merkleToken.claimNFTMerkleToken(token, amount, proof), "Invalid Merkle proof"
    );

});
  
  });
  describe("Mint and Burn function", function () {
    it("mint function should mint", async function () {
      await merkleToken.Mint(addr1.address, 10);
      expect(await merkleToken.balanceOf(addr1.address)).to.equal(10);
    });
      it("burn function should burn", async function () {
        await merkleToken.Mint(addr1.address, 10);
        expect(await merkleToken.balanceOf(addr1.address)).to.equal(10);
        await merkleToken.Burn(addr1.address, 10);
        expect(await merkleToken.balanceOf(addr1.address)).to.equal(0);
      });
  });
  describe("Setters", function () {
    it("setMerkleRoot should change the value of the merklerot", async function () {
      const root = await merkleToken.merkleRoot();
     await merkleToken.setMerkleRoot(rootAddressAmount);
      const earningsRoot = await merkleToken.merkleRoot();
      expect(root).not.to.equal(earningsRoot);
    });
    it("setMerkleRootForEarnings should change the value of the earningsmerkleroot", async function () {
      const earningsRoot = await merkleToken.merkleRootForEarnings();
     await merkleToken.setMerkleRootForEarnings(rootTokenIdAmount);
      const root = await merkleToken.merkleRootForEarnings();
      expect(root).not.to.equal(earningsRoot);
    });
    it("setNFTAddress should change the value of the addr for the contract for NFTs", async function () {
      const properAddr = await merkleToken.NFTContract();
     await merkleToken.setNFTAddress(owner.address);
      const wrongAddr = await merkleToken.NFTContract();
      expect(properAddr).not.to.equal(wrongAddr);
    });
    //
    it("setTokensPerNFT should change the amount of tokens a token holder gets", async function () {
      const originalNum = await merkleToken.amountOfTokensPerNFT();
     await merkleToken.setTokensPerNFT(15);
      const newNum = await merkleToken.amountOfTokensPerNFT();
      expect(newNum).not.to.equal(originalNum);
    });    
  });
  describe("access control", function () {
      let OPERATOR_ROLE;
      let DEFAULT_ADMIN_ROLE;
      let BURNER_ROLE;
      let addr1Lower;
    beforeEach(async function () {
      OPERATOR_ROLE = await merkleToken.OPERATOR_ROLE();
      DEFAULT_ADMIN_ROLE = await merkleToken.DEFAULT_ADMIN_ROLE();
      BURNER_ROLE = await merkleToken.BURNER_ROLE();
      addr1Lower = addr1.address.toLowerCase();

    });
    it("mint function only callable by admin", async function () {
      await expectRevert(merkleToken.connect(addr1).Mint(addr1.address, 10), `AccessControl: account ${addr1Lower} is missing role ${DEFAULT_ADMIN_ROLE}`);

    });
     
      it("burn function should only be called by burner role", async function () {
        await merkleToken.Mint(addr1.address, 10);
        await expectRevert(merkleToken.connect(addr1).Burn(addr1.address, 10), `AccessControl: account ${addr1Lower} is missing role ${BURNER_ROLE}`);
      });
    it("setMerkleRoot should change the value of the merklerot", async function () {
      await expectRevert(merkleToken.connect(addr1).setMerkleRoot(rootAddressAmount),`AccessControl: account ${addr1Lower} is missing role ${OPERATOR_ROLE}`);
    });
    it("setMerkleRootForEarnings should change the value of the earningsmerkleroot", async function () {
      
      await expectRevert(merkleToken.connect(addr1).setMerkleRootForEarnings(rootTokenIdAmount),`AccessControl: account ${addr1Lower} is missing role ${OPERATOR_ROLE}`);
    
    });
    it("setNFTAddress should change the value of the addr for the contract for NFTs", async function () {
 
      await expectRevert(merkleToken.connect(addr1).setNFTAddress(owner.address),`AccessControl: account ${addr1Lower} is missing role ${OPERATOR_ROLE}`);
    
    });
    
    it("setTokensPerNFT should change the amount of tokens a token holder gets", async function () {
 
      await expectRevert(merkleToken.connect(addr1).setTokensPerNFT(15),`AccessControl: account ${addr1Lower} is missing role ${OPERATOR_ROLE}`);
 
    });    
  });
});





