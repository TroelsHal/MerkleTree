//! Enables verification of the generated Merkle proofs against the Merkle tree.
//!
//! The `Verifier` provides a method for checking the validity of a `MerkleProof` against a known Merkle tree root hash.
//! This ensures data integrity and correctness.

use crate::hasher::hash_data_sequences;
use crate::merkle_proof::MerkleProof;

/// Represents a verifier for Merkle proofs.
///
/// The primary responsibility of the `Verifier` is to ensure that a given `MerkleProof`
/// matches a known Merkle tree root hash, thereby ensuring the integrity and correctness of the data.
pub struct Verifier {
    /// The root hash of the Merkle tree against which proofs will be verified.
    root_hash: [u8; 32],
}

impl Verifier {
    pub fn new(root_hash: [u8; 32]) -> Self {
        Verifier { root_hash }
    }
    /// Verifies the validity of a given Merkle proof against the stored root hash.
    ///
    /// This method computes the Merkle tree root hash using the provided `proof` and checks
    /// if it matches the `Verifier`'s known root hash.
    ///
    /// # Arguments
    ///
    /// * `proof` - The `MerkleProof` to be verified.
    ///
    /// # Returns
    ///
    /// Returns `true` if the proof is valid, otherwise returns `false`.
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        let mut height: usize = 0;
        let mut current_hash = proof.leaf_hash.clone();

        for hash in proof.authentication_path.iter().rev() {
            let direction = (1 << height) & proof.leaf_index;

            let combined_hash = if direction != 0 {
                hash_data_sequences(&[hash, &current_hash])
            } else {
                hash_data_sequences(&[&current_hash, hash])
            };
            current_hash = combined_hash;
            height += 1;
        }

        current_hash == self.root_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_new() {
        // Create valid root hash
        let valid_root_hash = [1u8; 32]; // Mock 32 bytes filled with the value 1
        let verifier = Verifier::new(valid_root_hash);
        assert_eq!(verifier.root_hash, valid_root_hash);
    }
}
