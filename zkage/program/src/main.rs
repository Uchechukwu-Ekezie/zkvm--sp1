//! ZK Age Verifier — guest program (runs inside SP1 zkVM)
//!
//! Proves a person meets a minimum age requirement
//! WITHOUT revealing their actual birth year or age.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // PRIVATE: only the prover knows this — never committed to the proof
    let birth_year = sp1_zkvm::io::read::<u32>();

    // PUBLIC: both prover and verifier agree on these
    let current_year  = sp1_zkvm::io::read::<u32>();
    let minimum_age   = sp1_zkvm::io::read::<u32>();

    // Compute inside the zkVM — this is what gets proven
    let age        = current_year.saturating_sub(birth_year);
    let is_eligible = age >= minimum_age;

    // Commit only the result — NOT the birth year or actual age
    sp1_zkvm::io::commit(&is_eligible);
    sp1_zkvm::io::commit(&minimum_age);
    sp1_zkvm::io::commit(&current_year);
}
