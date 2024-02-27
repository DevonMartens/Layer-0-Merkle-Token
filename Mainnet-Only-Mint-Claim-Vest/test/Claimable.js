const { expect } = require("chai");
const { ethers } = require("hardhat");
const {time } = require("@nomicfoundation/hardhat-network-helpers");
const { keccak256 } = ethers.utils;
const { MerkleTree } = require("merkletreejs");

const { expectRevert } = require('@openzeppelin/test-helpers');

const DeployTime = time.latest();
const SIXmo_YEAR_IN_SECS = 365 * 24 * 60 * 30;
const ONE_YEAR_IN_SECS = 365 * 24 * 60 * 60;
const TWO_YEAR_IN_SECS = 365 * 24 * 60 * 120;
const THREE_YEAR_IN_SECS = 365 * 24 * 60 * 120;


function hashTokenIdAmountPair(tokenId, amount) {
  return keccak256(ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [tokenId, amount]));
}

function hashAddressAmountPair(address, amount) {
  return keccak256(ethers.utils.defaultAbiCoder.encode(['address', 'uint256'], [address, amount]));
}

function hashVestingList(address, amountOfTokens, holdPeriod, deliveryPeriod, months) {
  return keccak256(ethers.utils.defaultAbiCoder.encode([
    'address', 
    'uint256', 
    'uint256', 
    'uint256', 
    'uint8',
    ], [address, amountOfTokens, holdPeriod, deliveryPeriod, months]));
}


describe("MerkleClaims Contract", function () {
  let MerkleClaims;
  let owner;
  let addr1;
  let addr2;
  let addrs;
  let merkleTreeAddressAmount;
  let nft;
  let merkleTreeTokenIdAmount;
  let rootTokenIdAmount;
  let rootAddressAmount;
  let token;
  let merkleTreeVesting;


  // This is a global setup function that runs before all tests
  beforeEach(async function () {
    const MerkleToken = await ethers.getContractFactory("MerkleToken");
    const MerkleClaims = await ethers.getContractFactory("MerkleClaims");
    const NFT = await ethers.getContractFactory("NFT");
    [owner, addr1, addr2, ...addrs] = await ethers.getSigners();

    const addressAmountPairs = [
      { address: owner.address.toString(), amount: '300' },
      { address: addr1.address.toString(), amount: '400' },
    ];

    const tokenIdAmountPairs = [
      { tokenId: '0', amount: '50' },
      { tokenId: '1', amount: '100' },
      { tokenId: '2', amount: '200' },
    ];

    const vestingList = [  
      // six months in seconds // 24 months delivery 
      { address: owner.address.toString(), amountOfTokens: '50', holdPeriod: SIXmo_YEAR_IN_SECS.toString(), deliveryPeriod: '63072000', months: '24'},
      // 12 months in seconds // 24 months delivery
      { address: addr1.address.toString(), amountOfTokens: '100', holdPeriod: ONE_YEAR_IN_SECS.toString(), deliveryPeriod: '63072000', months: '24'},
      // 12 months in seconds // 36 months delivery
      { address: addr2.address.toString(), amountOfTokens: '200', holdPeriod: ONE_YEAR_IN_SECS.toString(), deliveryPeriod: '94608000', months: '36'},
    ];


    function hashTokenIdAmountPair(tokenId, amount) {
      return keccak256(ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [tokenId, amount]));
    }

    function hashAddressAmountPair(address, amount) {
      return keccak256(ethers.utils.defaultAbiCoder.encode(['address', 'uint256'], [address, amount]));
    }

    function hashVestingList(address, amountOfTokens, holdPeriod, deliveryPeriod, months) {
      return keccak256(ethers.utils.defaultAbiCoder.encode([
        'address', 
        'uint256', 
        'uint256', 
        'uint256', 
        'uint8',
        ], [address, amountOfTokens, holdPeriod, deliveryPeriod, months]));
    }

    const leafNodesTokenIdAmount = tokenIdAmountPairs.map(pair => hashTokenIdAmountPair(pair.tokenId, pair.amount));
    merkleTreeTokenIdAmount = new MerkleTree(leafNodesTokenIdAmount, keccak256, { sortPairs: true });

    const leafNodesAddressAmount = addressAmountPairs.map(pair => hashAddressAmountPair(pair.address, pair.amount));
    merkleTreeAddressAmount = new MerkleTree(leafNodesAddressAmount, keccak256, { sortPairs: true });

    // for Vesting
    const leafNodesVesting = vestingList.map(pair => hashVestingList(pair.address, pair.amountOfTokens, pair.holdPeriod, pair.deliveryPeriod, pair.months));
    merkleTreeVesting = new MerkleTree(leafNodesVesting, keccak256, { sortPairs: true });

    rootTokenIdAmount = "0x" + merkleTreeTokenIdAmount.getRoot().toString('hex');
    rootAddressAmount = "0x" + merkleTreeAddressAmount.getRoot().toString('hex');
    rootVesting = "0x" + merkleTreeVesting.getRoot().toString('hex');



    // Deploy Token
    token = await MerkleToken.deploy(owner.address, owner.address, owner.address);

    // Deploy Dummy NFT
    nft = await NFT.deploy();

    // Deploy the merkleClaims contract with corrected root formats
    merkleClaims = await MerkleClaims.deploy(
      token.address, 
      nft.address, 
      owner.address, 
      rootTokenIdAmount, 
      rootAddressAmount,
      rootVesting,
      owner.address,
      );

    await merkleClaims.deployed();
    await token.approve(merkleClaims.address, 9000000000000);
  
  });


  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      const balance = await token.balanceOf(owner.address);
      const Sbalance = balance.toString();
      expect(Sbalance).to.equal("1000000000000000000000000000");
    });

    it("Should assign the total supply of tokens to the owner", async function () {


      const ownerBalance = await token.balanceOf(owner.address);
      expect(await token.totalSupply()).to.equal(ownerBalance);
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
      
      // Attempt to claim tokens
      await expect(merkleClaims.connect(owner).claimForAddress(claimAmount, proof))
          .to.emit(merkleClaims, "AddressClaimedEarnedTokens")
          .withArgs(owner.address, claimAmount.toString());
  
      // Verify the claim was successful
      const hasClaimed = await merkleClaims.hasClaimedEarnedTokens(owner.address);
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

    
    // Attempt to claim tokens
    await expectRevert(merkleClaims.connect(owner).claimForAddress(claimAmount, proof), "Invalid Merkle proof for address");
});
  it("Address cant claim earned tokens twice", async function () {
    // Use BigNumber for the amount to ensure consistency with uint256 in Solidity
    const claimAmount = "300"; // Adjust based on your token's decimals

    // Generate the leaf node using the adjusted claim amount
    const leaf = hashAddressAmountPair(owner.address, claimAmount.toString());

    // Generate the proof
    const proof = merkleTreeAddressAmount.getHexProof(leaf);
    
    // Attempt to claim tokens
    await expect(merkleClaims.connect(owner).claimForAddress(claimAmount, proof))
        .to.emit(merkleClaims, "AddressClaimedEarnedTokens")
        .withArgs(owner.address, claimAmount.toString());

    // Verify the claim was successful
    const hasClaimed = await merkleClaims.hasClaimedEarnedTokens(owner.address);
    expect(hasClaimed).to.be.true;
    await expectRevert(
      merkleClaims.connect(owner).claimForAddress(claimAmount, proof), 
      "RewardAlreadyClaimed()"

    )
});
  it("NFT Owner can claim tokens", async function () {
 
      await nft.connect(addr1).mint(1);
      const owner = await nft.ownerOf(0);

      const tokenId = 0;
      const amount = 50; 
      const leaf = hashTokenIdAmountPair(tokenId, amount);
      const proof = merkleTreeTokenIdAmount.getHexProof(leaf);

      await merkleClaims.connect(addr1).claimNFTRelatedTokens(tokenId, amount, proof);
      expect(await token.balanceOf(addr1.address)).to.equal(2300);



  });
  it("If a user is not the owner of a NFT then they cant claim tokens", async function () {
 
    await nft.mint(1);
    const owner = await nft.ownerOf(0);


    const token = 0;
    const amount = 50; 
    const leaf = hashTokenIdAmountPair(token, amount);
    const proof = merkleTreeTokenIdAmount.getHexProof(leaf);

    await expectRevert(
      merkleClaims.connect(addr1).claimNFTRelatedTokens(token, amount, proof), "CallerIsNotOwner()"
      );

});
it("If NFT token id has claimed then the cant claim tokens", async function () {
 
  await nft.mint(1);
  const owner = await nft.ownerOf(0);

  const token = 0;
  const amount = 50; 
  const leaf = hashTokenIdAmountPair(token, amount);
  const proof = merkleTreeTokenIdAmount.getHexProof(leaf);
  await merkleClaims.claimNFTRelatedTokens(token, amount, proof);

  await expectRevert(
    merkleClaims.claimNFTRelatedTokens(token, amount, proof), "RewardAlreadyClaimed()"
    );

});
it("a user can only claim the tokens they own", async function () {
 
  await nft.mint(1);
  const owner = await nft.ownerOf(0);

  const token = 0;
  const amount = 1000; 
  const leaf = hashTokenIdAmountPair(token, amount);
  const proof = merkleTreeTokenIdAmount.getHexProof(leaf);

  await expectRevert(
    merkleClaims.claimNFTRelatedTokens(token, amount, proof), "Invalid Merkle proof"
    );

});
  
  });
  describe("Mint and Burn function", function () {
    it("mint function should mint", async function () {
      await token.Mint (addr1.address, 10);
      expect(await token.balanceOf(addr1.address)).to.equal(10);
    });
      it("burn function should burn", async function () {
        await token.Mint (addr1.address, 10);
        expect(await token.balanceOf(addr1.address)).to.equal(10);
        await token.Burn(addr1.address, 10);
        expect(await token.balanceOf(addr1.address)).to.equal(0);
      });
  });
  describe("Setters", function () {
    it("setMerkleRoot should change the value of the merklerot", async function () {
      const root = await merkleClaims.merkleRoot();
     await merkleClaims.setMerkleRoot(rootAddressAmount);
      const earningsRoot = await merkleClaims.merkleRoot();
      expect(root).not.to.equal(earningsRoot);
    });
    it("setMerkleRootForEarnings should change the value of the earningsmerkleroot", async function () {
      const earningsRoot = await merkleClaims.merkleRootForEarnings();
     await merkleClaims.setMerkleRootForEarnings(rootTokenIdAmount);
      const root = await merkleClaims.merkleRootForEarnings();
      expect(root).not.to.equal(earningsRoot);
    });
    it("setNFTAddress should change the value of the addr for the contract for NFTs", async function () {
      const properAddr = await merkleClaims.NFTContract();
     await merkleClaims.setNFTAddress(owner.address);
      const wrongAddr = await merkleClaims.NFTContract();
      expect(properAddr).not.to.equal(wrongAddr);
    });
    //
    it("setTokensPerNFT should change the amount of tokens a token holder gets", async function () {
      const originalNum = await merkleClaims.amountOfTokensPerNFT();
     await merkleClaims.setTokensPerNFT(15);
      const newNum = await merkleClaims.amountOfTokensPerNFT();
      expect(newNum).not.to.equal(originalNum);
    });    
  });
  describe("access control", function () {
      let OPERATOR_ROLE;
      let DEFAULT_ADMIN_ROLE;
      let BURNER_ROLE;
      let addr1Lower;
    beforeEach(async function () {
      OPERATOR_ROLE = await merkleClaims.OPERATOR_ROLE();
      DEFAULT_ADMIN_ROLE = await merkleClaims.DEFAULT_ADMIN_ROLE();
      BURNER_ROLE = await merkleClaims.BURNER_ROLE();
      addr1Lower = addr1.address.toLowerCase();

    });
    it("mint function only callable by admin", async function () {
      await expectRevert(token.connect(addr1).Mint(addr1.address, 10), `AccessControl: account ${addr1Lower} is missing role ${DEFAULT_ADMIN_ROLE}`);

    });
     
      it("burn function should only be called by burner role", async function () {
        await token.Mint (addr1.address, 10);
        await expectRevert(token.connect(addr1).Burn(addr1.address, 10), `AccessControl: account ${addr1Lower} is missing role ${BURNER_ROLE}`);
      });
    it("setMerkleRoot should change the value of the merklerot", async function () {
      await expectRevert(merkleClaims.connect(addr1).setMerkleRoot(rootAddressAmount),`AccessControl: account ${addr1Lower} is missing role ${OPERATOR_ROLE}`);
    });
    it("setMerkleRootForEarnings should change the value of the earningsmerkleroot", async function () {
      
      await expectRevert(merkleClaims.connect(addr1).setMerkleRootForEarnings(rootTokenIdAmount),`AccessControl: account ${addr1Lower} is missing role ${OPERATOR_ROLE}`);
    
    });
    it("setNFTAddress should change the value of the addr for the contract for NFTs", async function () {
 
      await expectRevert(merkleClaims.connect(addr1).setNFTAddress(owner.address),`AccessControl: account ${addr1Lower} is missing role ${OPERATOR_ROLE}`);
    
    });
    
    it("setTokensPerNFT should change the amount of tokens a token holder gets", async function () {
 
      await expectRevert(merkleClaims.connect(addr1).setTokensPerNFT(15),`AccessControl: account ${addr1Lower} is missing role ${OPERATOR_ROLE}`);
 
    });    
  });
  describe("access control", function () {
    

    it("It should set a struct once the six month hold is done", async function () {

      // address: addr1.address.toString(), amountOfTokens: '100', holdPeriod: '31536000', deliveryPeriod: '63072000', months: '24'},

      const amountOfTokens = 100; 
      const holdPeriod = 31536000;
      const  deliveryPeriod = 63072000; 
      const months = 24;
    
      const leaf = hashVestingList(addr1.address, amountOfTokens, holdPeriod, deliveryPeriod, months);
     // console.log(leaf);
     const proof =  merkleTreeVesting.getHexProof(leaf);

      const unlockTime = ONE_YEAR_IN_SECS + 1;
      await time.increase(unlockTime);


  await expect(merkleClaims.connect(addr1).claimVestingSchedule(amountOfTokens, holdPeriod, deliveryPeriod, months, proof))
      .to.emit(merkleClaims, "TokensSetToVest")
      .withArgs(addr1.address, amountOfTokens.toString());

  //    
    });
  });

});





