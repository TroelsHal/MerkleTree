use criterion::{criterion_group, criterion_main, Criterion};
use merkletree::Prover;
use std::fs;

fn bench_prover_new(c: &mut Criterion) {
    let content = fs::read_to_string("tests/data/data10000.txt").expect("Failed to read the file");
    let data: Vec<&str> = content.lines().collect();

    let mut group = c.benchmark_group("Prover::new");
    group.sample_size(10); // Reducing the sample size can help with really slow benchmarks
    group.measurement_time(std::time::Duration::new(10, 0));

    for threads in 1..=8 {
        group.bench_function(format!("num_threads_{}", threads), |b| {
            b.iter(|| {
                let _ = Prover::new(&data, threads).unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_prover_new);
criterion_main!(benches);
