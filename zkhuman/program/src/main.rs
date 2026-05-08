//! ZK Human Verifier — guest program (runs inside SP1 zkVM)
//!
//! Verifies 3 criteria about a person WITHOUT revealing their actual values:
//!   1. Age >= minimum age
//!   2. Credit score >= minimum credit score
//!   3. Citizen ID is on the registered whitelist
//!
//! Private: age, credit_score, citizen_id   ← never in the proof
//! Public:  which checks passed/failed       ← committed to proof

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // ── PRIVATE inputs (prover only) ──────────────────────────────────────
    let age: u32          = sp1_zkvm::io::read::<u32>();
    let credit_score: u32 = sp1_zkvm::io::read::<u32>();
    let citizen_id: u32   = sp1_zkvm::io::read::<u32>();

    // ── PUBLIC inputs (verifier can see) ─────────────────────────────────
    let min_age: u32          = sp1_zkvm::io::read::<u32>();
    let min_credit: u32       = sp1_zkvm::io::read::<u32>();
    let whitelist: [u32; 5]   = sp1_zkvm::io::read::<[u32; 5]>();

    // ── Verification logic (proven inside zkVM) ───────────────────────────
    let age_ok      = age >= min_age;
    let credit_ok   = credit_score >= min_credit;
    let citizen_ok  = whitelist.contains(&citizen_id);
    let all_passed  = age_ok && credit_ok && citizen_ok;

    // ── PUBLIC outputs (committed to proof — actual values stay hidden) ───
    sp1_zkvm::io::commit(&age_ok);
    sp1_zkvm::io::commit(&credit_ok);
    sp1_zkvm::io::commit(&citizen_ok);
    sp1_zkvm::io::commit(&all_passed);
}
