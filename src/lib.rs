//! # MerkleTree Library
//!
//! This library provides a robust implementation of a Merkle tree, a fundamental data structure
//! used in cryptography and various distributed systems.
//!
//! ## Primary Components:
//!
//! - `hasher`: Utility functions for hashing data.
//! - `merkle_proof`: Data structure for representing Merkle proofs.
//! - `prover`: Functionality for bulding Merkle tree and generating Merkle proofs from a given tree.
//! - `verifier`: Functionality for verification of Merkle proofs.
//!
//! ## Features:
//!
//! - Efficient SHA256 hashing.
//! - Multithreading support in tree construction.
//! - Comprehensive verification methods.

//! # Examples
//!
//! Below is a simple usage example that demonstrates how to utilize the Prover and Verifier components
//! to construct a Merkle tree, generate a Merkle proof, and verify the proof.
//!
//! ```
//! # use merkletree::{Prover, Verifier};
//! let data = vec![
//!     "integration00",
//!     "integration01",
//!     "integration02",
//!     "integration03",
//! ];
//!
//! // Chose a number of threads for parallelization
//! let num_threads = 4;
//!
//! // Create a Prover instance
//! let prover = Prover::new(&data, num_threads).expect("Failed to create Prover instance");
//!
//! // Get the root hash from the Prover
//! let root_hash = prover.get_root_hash().expect("Failed to get root hash");
//!
//! // Choose a leaf_index
//! let leaf_index = 3;
//!
//! // Get the proof for the specified leaf index from the Prover
//! let proof = prover.get_proof(leaf_index).expect("Failed to get proof for leaf");
//!
//! // Create a Verifier instance with the root hash
//! let verifier = Verifier::new(root_hash);
//!
//! // Check the proof using the Verifier
//! assert!(verifier.verify_proof(&proof));
//! ```
//!

mod hasher;
mod merkle_proof;
mod prover;
mod verifier;

pub use hasher::hash_data_sequences;
pub use merkle_proof::MerkleProof;
pub use prover::Prover;
pub use verifier::Verifier;
