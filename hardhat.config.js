require("@nomiclabs/hardhat-waffle");
require("@nomiclabs/hardhat-ethers");
require("@openzeppelin/hardhat-upgrades");
require("@nomiclabs/hardhat-etherscan");
require("hardhat-gas-reporter");
require("solidity-coverage");
require("@nomiclabs/hardhat-solhint");
require("hardhat-contract-sizer");
require("solidity-docgen");
require("dotenv").config();

const { DEPLOYER_PRIVATE_KEY, TESTNET_RPC_URL } = process.env;

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  docgen: {},
  networks: {
    hardhat: {
      mining: {
        blockGasLimit: 100000000, 
      },
       testnet: {
        url: TESTNET_RPC_URL,
        accounts: [`0x${DEPLOYER_PRIVATE_KEY}`],
      },
    },
  },
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000,
      },
    },
  }
};