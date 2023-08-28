//! Utility functions for hashing data.
//!
//! This module provides the basic hashing functionality utilized throughout the library,
//!  that computes the SHA256 hash of given data sequences.

use sha2::{Digest, Sha256};

/// Computes the SHA256 hash of the given data and returns the result as raw bytes.
pub fn hash_data_sequences(datas: &[&[u8]]) -> [u8; 32] {
    let mut sha256 = Sha256::new();
    for data in datas.iter() {
        sha256.update(data);
    }
    sha256.finalize().into()
}
