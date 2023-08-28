//! Data structure for representing Merkle proofs.
//!
//! A `MerkleProof` provides evidence for the inclusion of a specific leaf in the Merkle tree. It includes
//! the leaf's index, the hash of the leaf, and the authentication path necessary for verification.

pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: [u8; 32],
    pub authentication_path: Vec<[u8; 32]>,
}
