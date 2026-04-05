use std::time::Instant;
use zk_pqc_hash_layer::constants::{FELT, T};
use zk_pqc_hash_layer::hybrid::HybridHash;
use zk_pqc_hash_layer::poseidon::Poseidon;
use zk_pqc_hash_layer::sponge::PoseidonSponge;

fn main() {
    let iterations = 1000;

    // 1. Poseidon Permutation Benchmark
    let poseidon = Poseidon::new();
    let mut state = [FELT::zero(); T];
    let start = Instant::now();
    for _ in 0..iterations {
        poseidon.permute(&mut state);
    }
    let duration = start.elapsed();
    println!(
        "Poseidon Permutation (t=6, 91 rounds): {:?} avg",
        duration / iterations
    );

    // 2. Sponge Hash Benchmark (Small input)
    let input = vec![FELT::from(1), FELT::from(2), FELT::from(3), FELT::from(4)];
    let start = Instant::now();
    for _ in 0..iterations {
        PoseidonSponge::hash(&input);
    }
    let duration = start.elapsed();
    println!(
        "Poseidon Sponge Hash (len=4): {:?} avg",
        duration / iterations
    );

    // 3. Hybrid Hash Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        HybridHash::hash(&input);
    }
    let duration = start.elapsed();
    println!("Hybrid Hash (len=4): {:?} avg", duration / iterations);
}
