// Import necessary components from the libraries
const { MerkleTree } = require('merkletreejs');
const { keccak256 } = require('ethers/lib/utils');
const { ethers } = require('hardhat');

async function main() {
  // Sample data
  const addressAmountPairs = [
    { address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', amount: '300' },
    { address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', amount: '400' },
  ];

  const tokenIdAmountPairs = [
    { tokenId: '1', amount: '100' },
    { tokenId: '2', amount: '200' },
  ];

  // Helper functions to hash pairs
  function hashTokenIdAmountPair(tokenId, amount) {
    return keccak256(ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [tokenId, amount]));
  }

  function hashAddressAmountPair(address, amount) {
    return keccak256(ethers.utils.defaultAbiCoder.encode(['address', 'uint256'], [address, amount]));
  }

  // Generate leaf nodes for both trees
  const leafNodesTokenIdAmount = tokenIdAmountPairs.map(pair => hashTokenIdAmountPair(pair.tokenId, pair.amount));
  const leafNodesAddressAmount = addressAmountPairs.map(pair => hashAddressAmountPair(pair.address, pair.amount));

  // Create Merkle trees
  const merkleTreeTokenIdAmount = new MerkleTree(leafNodesTokenIdAmount, keccak256, { sortPairs: true });
  const merkleTreeAddressAmount = new MerkleTree(leafNodesAddressAmount, keccak256, { sortPairs: true });

  // Get the roots
  const rootTokenIdAmount = merkleTreeTokenIdAmount.getHexRoot();
  const rootAddressAmount = merkleTreeAddressAmount.getHexRoot();

  // Log the roots
  console.log("Merkle Root (Token ID to Amount):", rootTokenIdAmount);
  console.log("Merkle Root (Address to Amount):", rootAddressAmount);
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
