//! Provides functionality for generating Merkle proofs.
//!
//! The `Prover` is a core component of the library, responsible for constructing the Merkle tree and
//! generating proofs for given leaf indices. This implementation supports multithreading for efficient tree
//! construction.

use crate::hash_data_sequences;
use crate::MerkleProof;

extern crate rayon;
use rayon::prelude::*;

const MAX_DATA_SIZE: usize = 1 << 20;

/// Represents a node in the Merkle tree.
///
/// Each node contains a hash representing either a data point (in the case of leaves) or
/// a combination of child hashes (for internal nodes). Non-leaf nodes have references
/// to their left and right children.
struct Node {
    hash: [u8; 32],
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

/// `Prover` is responsible for constructing a Merkle tree from provided data
/// and generating proofs for specified leaf indices.
///
/// It leverages multithreading capabilities for efficient tree construction and
/// contains the root node of the tree once it's built. Additionally, it keeps track
/// of the number of data points it was built from.
pub struct Prover {
    root: Option<Box<Node>>,
    data_length: usize,
}

impl Prover {
    /// Creates a new Prover instance by building a Merkle tree from the provided data.
    ///
    /// This method utilizes a specified number of threads for parallel construction.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of string data to construct the Merkle tree.
    /// * `num_threads` - The number of threads to be used in the parallel construction.
    ///
    /// # Returns
    ///
    /// A Result containing the created Prover instance, or an error string if any issues arise.
    pub fn new(data: &[&str], num_threads: usize) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("Data cannot be empty");
        }
        if data.len() > MAX_DATA_SIZE {
            return Err("Data size exceeds the maximum allowed size");
        }
        if num_threads == 0 {
            return Err("Number of threads cannot be zero");
        }
        Ok(Prover {
            root: Self::build_tree(data, num_threads),
            data_length: data.len(),
        })
    }

    /// Retrieves the hash of the root node of the Merkle tree.
    ///
    /// # Returns
    ///
    /// A Result containing the root hash, or an error string if the root is missing.
    pub fn get_root_hash(&self) -> Result<[u8; 32], &'static str> {
        self.root
            .as_ref()
            .map(|node| node.hash)
            .ok_or("Root node is missing")
    }

    /// Generates a Merkle proof for the specified leaf index.
    ///
    /// # Arguments
    ///
    /// * `leaf_index` - The index of the leaf for which the proof should be generated.
    ///
    /// # Returns
    ///
    /// A Result containing the generated MerkleProof, or an error string if any issues arise.
    pub fn get_proof(&self, leaf_index: usize) -> Result<MerkleProof, &'static str> {
        if leaf_index >= self.data_length {
            return Err("Leaf index is out of bounds.");
        }

        let mut authentication_path = Vec::new();
        let mut height: usize = (self.data_length as f64).log2().ceil() as usize;
        let mut current_node = self.root.as_ref().unwrap(); // Assuming root is always present

        while height > 0 {
            // Take hash of left sibling and go to right subtree
            if ((1 << (height - 1)) & leaf_index) != 0 {
                authentication_path.push(current_node.left.as_ref().unwrap().hash);
                current_node = current_node.right.as_ref().unwrap();
            }
            // Take hash of right sibling and go to left subtree
            else {
                authentication_path.push(current_node.right.as_ref().unwrap().hash);
                current_node = current_node.left.as_ref().unwrap();
            }
            height -= 1;
        }

        Ok(MerkleProof {
            leaf_index: leaf_index,
            leaf_hash: current_node.hash,
            authentication_path,
        })
    }

    /// Constructs the Merkle tree from the provided data.
    ///
    /// This internal method is used during the creation of the Prover instance.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of string data from which to construct the tree.
    /// * `_num_threads` - The number of threads to be used for parallel construction.
    ///
    /// # Returns
    ///
    /// An Option containing the root node of the constructed tree.
    fn build_tree(data: &[&str], _num_threads: usize) -> Option<Box<Node>> {
        // Use the input data to create the leaf nodes
        // Convert the input string slice to a byte slice
        let mut current_level: Vec<Option<Box<Node>>> = data
            .iter()
            .map(|d| {
                Some(Box::new(Node {
                    hash: hash_data_sequences(&[d.as_bytes()]), // Make to bytes and wrap in slice
                    left: None,
                    right: None,
                }))
            })
            .collect();

        // While a level has more than one node, create the parent level
        while current_level.len() > 1 {
            if current_level.len() % 2 == 1 {
                // If there is a uneven number of nodes in current level,
                // create a new node with the same hash value
                let new_node = Box::new(Node {
                    hash: current_level.last().unwrap().as_ref().unwrap().hash.clone(),
                    left: None,
                    right: None,
                });
                current_level.push(Some(new_node));
            }

            // The size of the next (upper) level will be half the size
            let next_size = current_level.len() / 2;

            // Fill the vector with 'None' so we can index into it.
            // All None values will be overwritten.
            let mut next_level: Vec<Option<Box<Node>>> = (0..next_size).map(|_| None).collect();

            // Collect the result as a vector of (index, Option<Box<Node>>)
            let parents: Vec<(usize, Option<Box<Node>>)> = current_level
                .par_chunks_exact_mut(2)
                .enumerate()
                .map(|(chunk_number, chunk)| {
                    let combined_hash = hash_data_sequences(&[
                        &chunk[0].as_ref().unwrap().hash,
                        &chunk[1].as_ref().unwrap().hash,
                    ]);

                    let parent = Box::new(Node {
                        hash: combined_hash,
                        left: chunk[0].take(),
                        right: chunk[1].take(),
                    });

                    (chunk_number, Some(parent))
                })
                .collect();

            for (idx, parent) in parents.into_iter() {
                next_level[idx] = parent;
            }

            current_level = next_level;
        }

        // Return the root node
        current_level.pop().unwrap()
    }

    pub fn generate_proof(_target: &str) -> MerkleProof {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::hash_data_sequences;
    use std::fs;

    #[test]
    fn test_construct_and_get_root_hash() {
        let data = vec!["data1", "data2", "data3", "data4", "data5"];
        let num_threads = 1;
        let root_hash;

        // Construct the initial prover and get its root hash
        match Prover::new(&data, num_threads) {
            Ok(prover) => {
                match prover.get_root_hash() {
                    Ok(hash) => {
                        assert!(!hash.is_empty(), "Root hash should not be empty");
                        root_hash = hash; // Assigning the hash to root_hash for use later
                    }
                    Err(e) => {
                        panic!("Failed to get root hash: {}", e);
                    }
                }
            }
            Err(e) => {
                panic!("Failed to create Prover instance: {}", e);
            }
        }

        // Construct a second prover and compare its root hash to the first
        match Prover::new(&data, num_threads) {
            Ok(prover2) => match prover2.get_root_hash() {
                Ok(hash2) => {
                    assert_eq!(
                        root_hash, hash2,
                        "Root hashes should match for the same data"
                    );
                }
                Err(e) => {
                    panic!("Failed to get root hash from prover2: {}", e);
                }
            },
            Err(e) => {
                panic!("Failed to create Prover2 instance: {}", e);
            }
        }

        // Construct a prover with modified data and ensure its root hash is different
        let mut modified_data = data.clone();
        modified_data[0] = "modified_data";

        match Prover::new(&modified_data, num_threads) {
            Ok(prover_modified) => match prover_modified.get_root_hash() {
                Ok(modified_hash) => {
                    assert_ne!(
                        root_hash, modified_hash,
                        "Root hash should change when data is modified"
                    );
                }
                Err(e) => {
                    panic!("Failed to get root hash from modified prover: {}", e);
                }
            },
            Err(e) => {
                panic!("Failed to create Prover with modified data instance: {}", e);
            }
        }
    }

    #[test]
    fn test_construct_and_get_root_hash_parallel() {
        // Read data from file
        let content =
            fs::read_to_string("tests/data/data1000.txt").expect("Failed to read the file");
        let data: Vec<&str> = content.lines().collect();

        let mut reference_root_hash: Option<[u8; 32]> = None;

        // Testing num_threads from 1 to 8
        for num_threads in 1..=8 {
            match Prover::new(&data, num_threads) {
                Ok(prover) => match prover.get_root_hash() {
                    Ok(hash) => {
                        assert!(
                            !hash.is_empty(),
                            "Root hash should not be empty with {} threads",
                            num_threads
                        );

                        if let Some(ref root) = reference_root_hash {
                            assert_eq!(
                                &hash, root,
                                "Root hash mismatch at {} threads!",
                                num_threads
                            );
                        } else {
                            reference_root_hash = Some(hash);
                        }
                    }
                    Err(e) => {
                        panic!(
                            "Failed to get root hash with {} threads: {}",
                            num_threads, e
                        );
                    }
                },
                Err(e) => {
                    panic!(
                        "Failed to create Prover instance with {} threads: {}",
                        num_threads, e
                    );
                }
            }
        }
    }

    #[test]
    fn test_get_proof_complete_tree() {
        let data = vec!["data1", "data2", "data3", "data4"];
        let num_threads = 1;
        let prover = Prover::new(&data, num_threads).expect("Failed to create prover");

        for leaf_index in 0..data.len() {
            let proof = prover.get_proof(leaf_index).unwrap();

            assert_eq!(proof.leaf_index, leaf_index);

            assert_eq!(
                proof.leaf_hash,
                hash_data_sequences(&[data[leaf_index].as_bytes()])
            );

            // The height of the tree should be ceil(log2(4)) = 2
            assert_eq!(
                proof.authentication_path.len(),
                2,
                "Failed at leaf_index: {}",
                leaf_index
            );
        }
    }

    #[test]
    fn test_get_proof_non_complete_tree() {
        let data = vec!["data1", "data2", "data3", "data4", "data5"];
        let num_threads = 1;
        let prover = Prover::new(&data, num_threads).expect("Failed to create prover");

        for leaf_index in 0..data.len() {
            let proof = prover.get_proof(leaf_index).unwrap();

            assert_eq!(proof.leaf_index, leaf_index);

            assert_eq!(
                proof.leaf_hash,
                hash_data_sequences(&[data[leaf_index].as_bytes()])
            );

            // The height of the tree should be ceil(log2(5)) = 3
            assert_eq!(
                proof.authentication_path.len(),
                3,
                "Failed at leaf_index: {}",
                leaf_index
            );
        }
    }

    #[test]
    fn test_get_proof_out_of_bounds() {
        let data = vec!["data1", "data2", "data3", "data4"];
        let num_threads = 1;
        let prover = Prover::new(&data, num_threads).expect("Failed to create prover");

        // Attempt to get a proof for an out-of-bounds leaf_index
        let result = prover.get_proof(data.len());

        // Validate the result is an error
        assert!(
            result.is_err(),
            "Expected an error for out-of-bounds leaf_index"
        );
    }

    #[test]
    fn test_larger_than_max_data_size() {
        let large_data: Vec<String> = (0..MAX_DATA_SIZE).map(|i| i.to_string()).collect();
        let data_refs: Vec<&str> = large_data.iter().map(AsRef::as_ref).collect();

        let result = Prover::new(&data_refs, 1);
        assert!(
            result.is_err(),
            "Data size exceeds the maximum allowed size"
        );
    }

    #[test]
    fn test_max_data_size() {
        let large_data: Vec<String> = (0..MAX_DATA_SIZE - 1).map(|i| i.to_string()).collect();
        let data_refs: Vec<&str> = large_data.iter().map(AsRef::as_ref).collect();

        let result = Prover::new(&data_refs, 1);
        assert!(
            result.is_ok(),
            "Data size should be within the allowable limit"
        );
    }
}
