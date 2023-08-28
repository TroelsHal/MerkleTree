# MerkleTree Library

An implementation of a Merkle tree, a fundamental data structure used in cryptography and various distributed systems.

## Features

- Building merkle tree. Constructing proof. Verifying proof
- Efficient SHA256 hashing.
- Multithreading support in tree construction.

## Primary Components

- `prover`: Functionality for bulding Merkle tree and generating Merkle proofs from a given tree.
- `verifier`: Functionality for verification of Merkle proofs.
- `hasher`: Utility functions for hashing data.
- `merkle_proof`: Data structure for representing Merkle proofs.

## Prerequisites

Ensure you have Rust and Cargo installed. If not, install them from [rust-lang.org](https://www.rust-lang.org/tools/install).

## Building and running test

Navigate to the project directory and run:

```bash
cargo test
```
## Runing benchmark

The building of the merkle tree is parallelized with Rayon.
Benchmark the runtime with 1-8 threads.
 
Navigate to the project directory and run:

```bash
cargo bench
```
## Author

Code written by Troels Halgreen

