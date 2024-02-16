const hre = require("hardhat");

async function main() {
  // Fetch contract to deploy
  const MerkleToken = await hre.ethers.getContractFactory("MerkleToken");
  const merkleToken = await MerkleToken.deploy(
    "operator_address_here", // Operator address
    "burner_address_here", // Burner address
    "NFT_contract_address_here", // NFT contract address
    18, // Shared decimals
    "layerzero_endpoint_here", // LayerZero Endpoint
    "merkle_root_here", // Merkle root for NFTs
    "merkle_root_for_earnings_here" // Merkle root for earnings
  );

  await merkleToken.deployed();

  console.log("MerkleToken deployed to:", merkleToken.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
