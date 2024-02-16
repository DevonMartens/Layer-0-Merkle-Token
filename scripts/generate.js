
function generateMerkleTree(leaves) {
    const hashedLeaves = leaves.map(x => keccak256(x));
    const merkleTree = new MerkleTree(hashedLeaves, keccak256, { sortPairs: true });
    return merkleTree;
}

const testData = ["0x123...", "0x456..."]; // Replace with actual test data
const merkleTree = generateMerkleTree(testData);
const root = merkleTree.getHexRoot();