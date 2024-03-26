use std::hint::black_box;

use miden::{prove, verify, Assembler, DefaultHost, Kernel, ProgramInfo, ProvingOptions, StackInputs};
use miden_stdlib::StdLibrary;
use criterion::{criterion_group, criterion_main, Criterion};

/// Initial value loaded onto the Miden Stack
const KECCAK256_INITIAL_HASH_VALUE: [u32; 16] = [u32::MAX; 16];

pub fn keccak_prove_benchmark(c: &mut Criterion) {
    // n: number of 512 bytes hashed in a chain. 
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
    let mut group = c.benchmark_group("Keccak256");

    // use an empty list as initial stack
    let stack_inputs = StackInputs::try_from_values(KECCAK256_INITIAL_HASH_VALUE.iter().map(|&v| v as u64)).unwrap();

    // prove the program
    group.bench_function(format!("Prove Keccak256 Miden-VM"), |bench| {
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

pub fn keccak_verify_benchmark(c: &mut Criterion) {
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
    let mut group = c.benchmark_group("Keccak256");

    // use an empty list as initial stack
    let stack_inputs = StackInputs::try_from_values(KECCAK256_INITIAL_HASH_VALUE.iter().map(|&v| v as u64)).unwrap();

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

    group.bench_function(format!("Verify Keccak256 Miden-VM"), |bench| {
        bench.iter(|| {
            let _ = black_box(verify(program_info.clone(), stack_inputs.clone(), outputs.clone(), proof.clone()));
        });
    });
}


criterion_group!(benches, keccak_verify_benchmark, keccak_prove_benchmark);
criterion_main!(benches);
