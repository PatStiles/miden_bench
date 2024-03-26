use std::hint::black_box;

use miden::{prove, verify, Assembler, DefaultHost, Kernel, ProgramInfo, ProvingOptions, StackInputs};
use miden_stdlib::StdLibrary;
use criterion::{criterion_group, criterion_main, Criterion};

/// Initial value loaded onto the Miden Stack
const SHA256_INITIAL_HASH_VALUE: [u32; 8] = [u32::MAX; 8];

pub fn sha256_prove_benchmark(c: &mut Criterion) {
    let n = 2;
    let program_script = format!(
        "
        use.std::crypto::hashes::sha256
        
        begin
            repeat.{}
                exec.sha256::hash_1to1
            end
        end",
        n
    );

    let program = Assembler::default().with_library(&StdLibrary::default()).unwrap().compile(program_script).unwrap();
    let mut group = c.benchmark_group("Sha256");

    // use an empty list as initial stack
    let stack_inputs = StackInputs::try_from_values(SHA256_INITIAL_HASH_VALUE.iter().map(|&v| v as u64)).unwrap();

    // prove the program
    group.bench_function(format!("Prove Sha256 Miden-VM"), |bench| {
        bench.iter(|| {
            black_box(prove(
                &program,
                stack_inputs.clone(),
                DefaultHost::default(),
                ProvingOptions::default(), // use default proving options
            ))
        });
    });
}

pub fn sha256_verify_benchmark(c: &mut Criterion) {
    // n: number of 
    let n = 2;
    let program_script = format!(
        "
        use.std::crypto::hashes::keccak256
        
        begin
            repeat.{}
                exec.keccak256::hash
            end
        end",
        n
    );

    let program = Assembler::default().with_library(&StdLibrary::default()).unwrap().compile(program_script).unwrap();
    let mut group = c.benchmark_group("Sha256");

    // use an empty list as initial stack
    let stack_inputs = StackInputs::try_from_values(SHA256_INITIAL_HASH_VALUE.iter().map(|&v| v as u64)).unwrap();

    // prove the program
    let (outputs, proof) = prove(
        &program,
        stack_inputs.clone(),
        DefaultHost::default(),
        ProvingOptions::default(), // use default proving options
    )
    .unwrap();

    let kernel = Kernel::default();
    let program_info = ProgramInfo::new(program.hash(), kernel);

    group.bench_function(format!("Verify Sha256 Miden-VM"), |bench| {
        bench.iter(|| {
            let _ = black_box(verify(program_info.clone(), stack_inputs.clone(), outputs.clone(), proof.clone()));
        });
    });
}


criterion_group!(benches, sha256_verify_benchmark, sha256_prove_benchmark);
criterion_main!(benches);
