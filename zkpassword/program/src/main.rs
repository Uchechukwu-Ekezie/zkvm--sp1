//! ZK Password Verifier — guest program (runs inside the SP1 zkVM)
//!
//! Proves knowledge of a secret password by committing only its SHA-256 hash.
//! The password itself is NEVER revealed in the proof.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn main() {
    // Read the secret password — this is a PRIVATE input.
    // It goes into the zkVM but is never committed to the proof.
    let password = sp1_zkvm::io::read::<String>();

    // Hash the password with SHA-256 inside the zkVM.
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();

    // Commit the hash as a PUBLIC output.
    // The verifier will only ever see this hash — not the original password.
    sp1_zkvm::io::commit_slice(&hash);
}
