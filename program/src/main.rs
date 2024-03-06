//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod helpers;

use bls12_381_bls::Signature;
use dusk_bytes::Serializable;
use eyre::Result;
use helios_prover_primitives::types::{Bytes32, Header, SyncAggregate, SyncCommittee, SigningData};
use helpers::utils::is_proof_valid;

use bls12_381_bls::{PublicKey, APK};
use ssz_rs::{Bitvector, Merkleized, Node};

fn get_participating_keys(
    committee: &SyncCommittee,
    bitfield: &Bitvector<512>,
) -> Result<Vec<PublicKey>> {
    let mut pks: Vec<PublicKey> = Vec::new();
    bitfield.iter().enumerate().for_each(|(i, bit)| {
        if bit == true {
            let pk = &committee.pubkeys[i];
            unsafe {
                let pk = PublicKey::from_slice_unchecked(pk.as_slice());
                pks.push(pk);
            }
        }
    });

    Ok(pks)
}

fn get_committee_sign_root(header: Bytes32) -> Result<Node> {
    //let genesis_root: [u8; 32] = [
        //75, 54, 61, 185, 78, 40, 97, 32, 215, 110, 185, 5, 52, 15, 221, 78, 84, 191, 233, 240, 107,
        //243, 63, 246, 207, 90, 210, 127, 81, 27, 254, 149,
    //];
    //let fork_version: [u8; 4] = [3, 0, 0, 0];
    let domain: &[u8] = &[
        7, 0, 0, 0, 187, 164, 218, 150, 53, 76, 159, 37, 71, 108, 241, 188, 105, 191, 88, 58, 127,
        158, 10, 240, 73, 48, 91, 98, 222, 103, 102, 64,
    ];
    let mut data = SigningData {
        object_root: header,
        domain: Bytes32::try_from(domain).unwrap(),
    };
    Ok(data.hash_tree_root()?)
}

fn main() {
    let attested_header = sp1_zkvm::io::read::<Header>();
    let finality_branch = sp1_zkvm::io::read::<Vec<Bytes32>>();
    let mut finalized_header = sp1_zkvm::io::read::<Header>();
    let mut current_sync_committee = sp1_zkvm::io::read::<SyncCommittee>();
    let current_sync_committee_branch = sp1_zkvm::io::read::<Vec<Bytes32>>();
    let mut next_committee = sp1_zkvm::io::read::<SyncCommittee>();
    let next_sync_committee_branch = sp1_zkvm::io::read::<Vec<Bytes32>>();
    let sync_aggregate = sp1_zkvm::io::read::<SyncAggregate>();

    let hash_tree_root: Node = attested_header.clone().hash_tree_root().unwrap();
    let header_root = Bytes32::try_from(hash_tree_root.as_ref()).unwrap();
    let signing_root = get_committee_sign_root(header_root).unwrap();
    let pks = get_participating_keys(&current_sync_committee, &sync_aggregate.sync_committee_bits).unwrap();
    let signature = sync_aggregate.sync_committee_signature;

    let mut apk = APK::from(&pks[0]);
    apk.aggregate(&pks[1..]);
    let s: &[u8; 48] = signature.as_slice().try_into().unwrap();
    let sig = Signature::from_bytes(s).unwrap();
    let valid = apk.verify(&sig, &signing_root.as_ref()).is_ok();

    //let is_valid_sig = self.verify_sync_committee_signture(
    //&pks,
    //&update.attested_header,
    //&update.sync_aggregate.sync_committee_signature,
    //update.signature_slot,
    //);

    //let mut valid = is_proof_valid(
        //&attested_header,
        //&mut finalized_header,
        //&finality_branch,
        //6,
        //41,
    //);

    //// TODO: curent committee

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
