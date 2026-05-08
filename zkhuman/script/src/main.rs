//! ZK Human Verifier — host script
//!
//! Usage:
//!   cargo run --release -- --subject alice
//!   cargo run --release -- --subject bob
//!   cargo run --release -- --all
//!   cargo run --release -- --all --prove

use clap::Parser;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const ELF: Elf = include_elf!("zkhuman-program");

// ── Public rules (verifier knows these) ──────────────────────────────────────
const MIN_AGE:    u32      = 18;
const MIN_CREDIT: u32      = 600;
const WHITELIST:  [u32; 5] = [1001, 1002, 1003, 1004, 1005];

// ── Test subjects (private data — only the prover knows) ─────────────────────
#[derive(Clone)]
struct Subject {
    name:         &'static str,
    age:          u32,
    credit_score: u32,
    citizen_id:   u32,
}

fn all_subjects() -> Vec<Subject> {
    vec![
        Subject { name: "Alice",   age: 28, credit_score: 750, citizen_id: 1001 }, // ✅ all pass
        Subject { name: "Bob",     age: 16, credit_score: 720, citizen_id: 1002 }, // ❌ underage
        Subject { name: "Charlie", age: 35, credit_score: 450, citizen_id: 1003 }, // ❌ low credit
        Subject { name: "Diana",   age: 22, credit_score: 680, citizen_id: 9999 }, // ❌ not citizen
        Subject { name: "Eve",     age: 19, credit_score: 390, citizen_id: 8888 }, // ❌ credit + citizen
    ]
}

#[derive(Parser, Debug)]
#[command(about = "ZK Human Verifier — prove eligibility without revealing personal data")]
struct Args {
    /// Subject name: alice, bob, charlie, diana, eve
    #[arg(long)]
    subject: Option<String>,

    /// Run all subjects in sequence
    #[arg(long)]
    all: bool,

    /// Generate a real ZK proof (slower). Default is execute mode (fast).
    #[arg(long)]
    prove: bool,
}

fn divider() { println!("{}", "─".repeat(56)); }

fn banner(text: &str) {
    println!("\n{}", "═".repeat(56));
    println!("  {text}");
    println!("{}", "═".repeat(56));
}

fn check(label: &str, passed: bool) {
    let icon = if passed { "✅" } else { "❌" };
    println!("    {icon}  {label}");
}

fn build_stdin(s: &Subject) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&s.age);
    stdin.write(&s.credit_score);
    stdin.write(&s.citizen_id);
    stdin.write(&MIN_AGE);
    stdin.write(&MIN_CREDIT);
    stdin.write(&WHITELIST);
    stdin
}

fn print_subject_header(s: &Subject) {
    banner(&format!("SUBJECT: {}", s.name.to_uppercase()));
    println!("  [PRIVATE — hidden from verifier]");
    println!("    Age          : ████");
    println!("    Credit Score : ████");
    println!("    Citizen ID   : ████");
    println!();
    println!("  [PUBLIC — verifier knows]");
    println!("    Minimum age    : {MIN_AGE}");
    println!("    Minimum credit : {MIN_CREDIT}");
    println!("    Whitelist size : {} registered citizens", WHITELIST.len());
    divider();
}

fn print_result(name: &str, age_ok: bool, credit_ok: bool, citizen_ok: bool, all_passed: bool, proved: bool) {
    println!();
    println!("  VERIFICATION CHECKS:");
    check(&format!("Age meets minimum ({MIN_AGE}+)"), age_ok);
    check(&format!("Credit score meets minimum ({MIN_CREDIT}+)"), credit_ok);
    check("Registered citizen (on whitelist)", citizen_ok);
    divider();

    if all_passed {
        println!("  RESULT: ✅  VERIFIED — {name} is cleared");
    } else {
        println!("  RESULT: ❌  REJECTED — {name} did not pass all checks");
    }
    if proved {
        println!("  ZK proof verified ✅  (actual values never revealed)");
    } else {
        println!("  Executed in zkVM  (actual values never revealed)");
    }
    println!();
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    let subjects = all_subjects();

    banner("ZK HUMAN VERIFIER  —  Powered by SP1 zkVM");
    println!("  Proves eligibility without revealing personal data.");
    println!("  Mode : {}", if args.prove { "ZK Proof (cryptographic)" } else { "Execute (fast demo)" });
    println!("  Rules: Age {}+,  Credit {}+,  Registered citizen", MIN_AGE, MIN_CREDIT);

    let client = ProverClient::from_env();
    let pk = client.setup(ELF).expect("setup failed");

    let to_run: Vec<Subject> = if args.all {
        subjects
    } else {
        let name = args.subject.as_deref().unwrap_or("alice").to_lowercase();
        match subjects.into_iter().find(|s| s.name.to_lowercase() == name) {
            Some(s) => vec![s],
            None => {
                eprintln!("Unknown subject '{name}'. Choose: alice, bob, charlie, diana, eve");
                std::process::exit(1);
            }
        }
    };

    for s in &to_run {
        print_subject_header(s);
        let stdin = build_stdin(s);

        let (age_ok, credit_ok, citizen_ok, all_passed) = if args.prove {
            println!("  Generating ZK proof...");
            let proof = client.prove(&pk, stdin).run().expect("proving failed");
            let mut pv = proof.public_values.clone();
            let r = (pv.read::<bool>(), pv.read::<bool>(), pv.read::<bool>(), pv.read::<bool>());
            client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
            r
        } else {
            let (mut out, _) = client.execute(ELF, stdin).run().unwrap();
            (out.read::<bool>(), out.read::<bool>(), out.read::<bool>(), out.read::<bool>())
        };

        print_result(s.name, age_ok, credit_ok, citizen_ok, all_passed, args.prove);
    }

    if to_run.len() > 1 {
        banner("ALL SUBJECTS PROCESSED");
    }
}
