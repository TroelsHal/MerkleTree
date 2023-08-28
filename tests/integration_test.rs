use merkletree::Prover;
use merkletree::Verifier;
use std::fs;

#[test]
fn simple_protocol() {
    let data = vec![
        "integration00",
        "integration01",
        "integration02",
        "integration03",
    ];

    let num_threads = 1;

    // Create a Prover instance
    let prover = match Prover::new(&data, num_threads) {
        Ok(p) => p,
        Err(e) => panic!("Failed to create Prover instance: {}", e),
    };

    // Get the root hash from the Prover
    let root_hash = match prover.get_root_hash() {
        Ok(hash) => hash,
        Err(e) => panic!("Failed to get root hash: {}", e),
    };

    let leaf_index = 3;

    // Get the proof for the specified leaf index from the Prover
    let proof = match prover.get_proof(leaf_index) {
        Ok(p) => p,
        Err(e) => panic!("Failed to get proof for leaf index {}: {}", leaf_index, e),
    };

    // Create a Verifier instance with the root hash
    let verifier = Verifier::new(root_hash);

    // Check the proof using the Verifier
    assert!(verifier.verify_proof(&proof));
}

#[test]
fn thread_numbers_and_leaf_indices_systematically() {
    // Read data from file
    let content = fs::read_to_string("tests/data/data1000.txt").expect("Failed to read the file");
    let data: Vec<&str> = content.lines().collect();

    // Testing num_threads from 1 to 16
    for num_threads in 1..=16 {
        // Create a Prover instance
        let prover = match Prover::new(&data, num_threads) {
            Ok(p) => p,
            Err(e) => panic!("Failed to create Prover instance: {}", e),
        };

        // Get the root hash from the Prover
        let root_hash = match prover.get_root_hash() {
            Ok(hash) => hash,
            Err(e) => panic!("Failed to get root hash: {}", e),
        };

        // Create a Verifier instance with the root hash
        let verifier = Verifier::new(root_hash);

        for leaf_index in 0..=999 {
            // Get the proof for the specified leaf index from the Prover
            let proof = match prover.get_proof(leaf_index) {
                Ok(p) => p,
                Err(e) => panic!("Failed to get proof for leaf index {}: {}", leaf_index, e),
            };

            // Check the proof using the Verifier
            assert!(verifier.verify_proof(&proof));
        }
    }
}

#[test]
fn wrong_proof() {
    let data1 = vec![
        "integration00",
        "integration01",
        "integration02",
        "integration03",
    ];

    let data2 = vec![
        "integration00",
        "integration01",
        "integration02",
        "modified",
    ];

    let num_threads = 1;

    // Create two Prover instances
    let prover1 = match Prover::new(&data1, num_threads) {
        Ok(p) => p,
        Err(e) => panic!("Failed to create Prover instance: {}", e),
    };

    let prover2 = match Prover::new(&data2, num_threads) {
        Ok(p) => p,
        Err(e) => panic!("Failed to create Prover instance: {}", e),
    };

    // Get the root hash from prover1
    let root_hash1 = match prover1.get_root_hash() {
        Ok(hash) => hash,
        Err(e) => panic!("Failed to get root hash: {}", e),
    };

    // Get a proof from prover2
    let leaf_index = 3;
    let proof2 = match prover2.get_proof(leaf_index) {
        Ok(p) => p,
        Err(e) => panic!("Failed to get proof for leaf index {}: {}", leaf_index, e),
    };

    // Create a Verifier instance with root hash from prover1
    let verifier = Verifier::new(root_hash1);

    // Check proof from prover2 using the Verifier.
    // Should not be valid.
    assert!(!verifier.verify_proof(&proof2));
}
