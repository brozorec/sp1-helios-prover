//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod helpers;

use helios_prover_primitives::types::{Bytes32, Header, SyncAggregate, SyncCommittee, BLSPubKeyUncompressed};
use helpers::utils::*;
use milagro_bls::PublicKey;
use ssz_rs::{Merkleized, Node};

fn main() {
    let attested_header = sp1_zkvm::io::read::<Header>();
    let finality_branch = sp1_zkvm::io::read::<Vec<Bytes32>>();
    let mut finalized_header = sp1_zkvm::io::read::<Header>();
    let current_sync_committee = sp1_zkvm::io::read::<SyncCommittee>();
    let _current_sync_committee_branch = sp1_zkvm::io::read::<Vec<Bytes32>>();
    let mut next_committee = sp1_zkvm::io::read::<SyncCommittee>();
    let next_sync_committee_branch = sp1_zkvm::io::read::<Vec<Bytes32>>();
    let sync_aggregate = sp1_zkvm::io::read::<SyncAggregate>();

    let hash_tree_root: Node = attested_header.clone().hash_tree_root().unwrap();
    let header_root = Bytes32::try_from(hash_tree_root.as_ref()).unwrap();
    let signing_root = get_committee_sign_root(header_root).unwrap();

    //sp1_zkvm::precompiles::unconstrained! {
        let pks = get_participating_keys(&current_sync_committee, &sync_aggregate.sync_committee_bits)
            .unwrap();
        //sp1_zkvm::io::hint(&pks);
    //};
    //let pks = sp1_zkvm::io::read::<Vec<BLSPubKeyUncompressed>>();

    let signature = sync_aggregate.sync_committee_signature;

    //let valid = true;
    let mut valid = is_aggregate_valid(
        &signature,
        signing_root.as_ref(),
        &pks.iter().collect::<Vec<&PublicKey>>(),
    );

    //println!("cycle-tracker-start: finalized_header");
    //valid = valid
        //&& is_proof_valid(
            //&attested_header,
            //&mut finalized_header,
            //&finality_branch,
            //6,
            //41,
        //);
    //println!("cycle-tracker-end: finalized_header");

    // TODO: curent committee

    //valid = valid
        //&& is_proof_valid(
            //&attested_header,
            //&mut next_committee,
            //&next_sync_committee_branch,
            //5,
            //23,
        //);

    sp1_zkvm::io::write(&valid);
}
