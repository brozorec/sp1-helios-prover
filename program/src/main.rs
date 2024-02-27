//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod helpers;

use helios_prover_primitives::types::{Bytes32, Header, SyncCommittee};
use helpers::utils::is_proof_valid;

fn main() {
    let attested_header = sp1_zkvm::io::read::<Header>();
    let finality_branch = sp1_zkvm::io::read::<Vec<Bytes32>>();
    let mut finalized_header = sp1_zkvm::io::read::<Header>();
    let mut next_committee = sp1_zkvm::io::read::<SyncCommittee>();
    let next_sync_committee_branch = sp1_zkvm::io::read::<Vec<Bytes32>>();

    let mut valid = is_proof_valid(
        &attested_header,
        &mut finalized_header,
        &finality_branch,
        6,
        41,
    );

    valid = valid
        && is_proof_valid(
            &attested_header,
            &mut next_committee,
            &next_sync_committee_branch,
            5,
            23,
        );

    sp1_zkvm::io::write(&valid);
}
