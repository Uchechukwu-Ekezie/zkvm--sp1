//! ZK Password Verifier — host script
//!
//! Run with --execute to simulate (fast, no proof).
//! Run with --prove to generate and verify a real ZK proof.
//!
//! Usage:
//!   cargo run --release -- --execute --password "mysecret"
//!   cargo run --release -- --prove   --password "mysecret"

use clap::Parser;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const ELF: Elf = include_elf!("zkpassword-program");

#[derive(Parser, Debug)]
#[command(about = "ZK Password Verifier — prove you know a password without revealing it")]
struct Args {
    /// Run in execute mode (fast, no proof generated)
    #[arg(long)]
    execute: bool,

    /// Run in prove mode (generates and verifies a real ZK proof)
    #[arg(long)]
    prove: bool,

    /// The secret password to prove knowledge of
    #[arg(long, default_value = "zk-masterclass-2024")]
    password: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: specify exactly one of --execute or --prove");
        std::process::exit(1);
    }

    // Feed the secret password as private input to the zkVM.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.password);

    // The password is NEVER logged or printed — zero knowledge.
    println!("Password:  [HIDDEN — known only to the prover]");

    let client = ProverClient::from_env();

    if args.execute {
        // Execute inside the zkVM without generating a proof (instant).
        let (output, report) = client.execute(ELF, stdin).run().unwrap();

        let hash_bytes: &[u8; 32] = output.as_slice().try_into().unwrap();
        println!("SHA-256 hash (public): 0x{}", hex::encode(hash_bytes));
        println!("Execution cycles:       {}", report.total_instruction_count());
        println!();
        println!("The zkVM confirms: SHA256(password) = 0x{}", hex::encode(hash_bytes));
    } else {
        println!("Generating ZK proof...");

        let pk = client.setup(ELF).expect("failed to setup ELF");
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Proof generated!");

        // The verifier only sees the public output — the hash.
        // The password is cryptographically hidden inside the proof.
        let hash_bytes: &[u8; 32] = proof.public_values.as_slice().try_into().unwrap();
        println!("Public output (hash):  0x{}", hex::encode(hash_bytes));
        println!();

        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("proof verification failed");

        println!("Proof verified!");
        println!();
        println!("The verifier is convinced:");
        println!("  - The prover knows a password whose SHA-256 is 0x{}", hex::encode(hash_bytes));
        println!("  - The verifier learned NOTHING about the password itself.");
        println!("  - This is zero-knowledge.");
    }
}
