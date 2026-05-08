//! ZK Age Verifier — host script
//!
//! Usage:
//!   cargo run --release -- --execute --birth-year 1995
//!   cargo run --release -- --prove   --birth-year 1995

use clap::Parser;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const ELF: Elf = include_elf!("zkage-program");

const CURRENT_YEAR: u32 = 2026;
const MINIMUM_AGE:  u32 = 18;

#[derive(Parser, Debug)]
#[command(about = "ZK Age Verifier — prove you meet an age requirement without revealing your age")]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// Your birth year (private — never revealed to verifier)
    #[arg(long, default_value = "1995")]
    birth_year: u32,
}

fn banner(title: &str) {
    let line = "═".repeat(50);
    println!("\n{}", line);
    println!("  {}", title);
    println!("{}\n", line);
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: specify exactly one of --execute or --prove");
        std::process::exit(1);
    }

    banner("ZK Age Verifier  —  Powered by SP1 zkVM");

    println!("  [PRIVATE]  Birth year   : ████  ← hidden from verifier");
    println!("  [PUBLIC]   Current year : {}", CURRENT_YEAR);
    println!("  [PUBLIC]   Minimum age  : {}+\n", MINIMUM_AGE);

    // Feed inputs to the zkVM
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.birth_year);   // private
    stdin.write(&CURRENT_YEAR);      // public
    stdin.write(&MINIMUM_AGE);       // public

    let client = ProverClient::from_env();

    if args.execute {
        println!("  Running inside zkVM (execute mode — no proof)...");

        let (mut output, report) = client.execute(ELF, stdin).run().unwrap();

        let is_eligible: bool = output.read::<bool>();
        let min_age: u32      = output.read::<u32>();
        let year: u32         = output.read::<u32>();

        banner("EXECUTION RESULT");

        if is_eligible {
            println!("  RESULT      : ✅  ELIGIBLE");
        } else {
            println!("  RESULT      : ❌  NOT ELIGIBLE");
        }
        println!("  Claim       : Person is {}+ years old as of {}", min_age, year);
        println!("  Cycles used : {}", report.total_instruction_count());

        println!("\n  Birth year stays hidden. Only the eligibility result is public.");

    } else {
        println!("  Generating ZK proof inside SP1 zkVM...\n");

        let pk = client.setup(ELF).expect("setup failed");
        let proof = client.prove(&pk, stdin).run().expect("proving failed");

        let mut public = proof.public_values.clone();
        let is_eligible: bool = public.read::<bool>();
        let min_age: u32      = public.read::<u32>();
        let year: u32         = public.read::<u32>();

        banner("PROOF RESULT");

        if is_eligible {
            println!("  RESULT      : ✅  ELIGIBLE");
        } else {
            println!("  RESULT      : ❌  NOT ELIGIBLE");
        }
        println!("  Claim       : Person is {}+ years old as of {}", min_age, year);
        println!("  Birth year  : ████  (cryptographically hidden)");

        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("verification failed");

        banner("VERIFICATION PASSED ✅");

        println!("  The verifier is now convinced:");
        println!("  → This person is {min_age}+ years old as of {year}");
        println!("  → Their actual birth year is NEVER revealed");
        println!("  → This is Zero-Knowledge Proof in action\n");
    }
}
