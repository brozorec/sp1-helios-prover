use std::hint::black_box;
use eyre::Result;
use ssz_rs::prelude::*;

use helios_prover_primitives::types::{
    Bytes32, Header, SignatureBytes, SigningData, SyncCommittee, ByteVector, BLSPubKeyUncompressed
};
use milagro_bls::{AggregateSignature, PublicKey};

pub fn is_proof_valid<L: Merkleized>(
    attested_header: &Header,
    leaf_object: &mut L,
    branch: &[Bytes32],
    depth: usize,
    index: usize,
) -> bool {
    let res: Result<bool> = (move || {
        let leaf_hash = leaf_object.hash_tree_root()?;
        let state_root = bytes32_to_node(&attested_header.state_root)?;
        let branch = branch_to_nodes(branch.to_vec())?;

        let is_valid = is_valid_merkle_branch(&leaf_hash, branch.iter(), depth, index, &state_root);
        Ok(is_valid)
    })();

    if let Ok(is_valid) = res {
        is_valid
    } else {
        false
    }
}

pub fn branch_to_nodes(branch: Vec<Bytes32>) -> Result<Vec<Node>> {
    branch
        .iter()
        .map(bytes32_to_node)
        .collect::<Result<Vec<Node>>>()
}

pub fn bytes32_to_node(bytes: &Bytes32) -> Result<Node> {
    Ok(Node::try_from(bytes.as_slice())?)
}

//pub fn get_participating_keys(
    //committee: &SyncCommittee,
    //bitfield: &Bitvector<512>,
//) -> Result<Vec<BLSPubKeyUncompressed>> {
    //let mut pks: Vec<ByteVector<96>> = Vec::new();
    //bitfield.iter().enumerate().for_each(|(i, bit)| {
        //if bit == true && i < 5 {
            ////println!("cycle-tracker-start: init_keys");
            //let pk = &committee.pubkeys[i];
            //let pk = PublicKey::from_bytes_unchecked(pk).unwrap().as_uncompressed_bytes();
            //pks.push(BLSPubKeyUncompressed::try_from(pk.as_slice()).unwrap());
            ////println!("cycle-tracker-end: init_keys");
        //}
    //});

    //Ok(pks)
//}

pub fn get_participating_keys(
    committee: &SyncCommittee,
    bitfield: &Bitvector<512>,
) -> Result<Vec<PublicKey>> {
    let mut pks: Vec<PublicKey> = Vec::new();
    println!("cycle-tracker-start: utils:init_keys");
    bitfield.iter().enumerate().for_each(|(i, bit)| {
        if bit == true && i < 5 {
            let pk = &committee.pubkeys[i];
            let pk = PublicKey::from_bytes_unchecked(pk).unwrap();
            pks.push(pk);
        }
    });

    println!("cycle-tracker-end: utils:init_keys");
    Ok(pks)
}

pub fn get_committee_sign_root(header: Bytes32) -> Result<Node> {
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

pub fn is_aggregate_valid(sig_bytes: &SignatureBytes, msg: &[u8], pks: &[&PublicKey]) -> bool {
    println!("cycle-tracker-start: utils:aggregate_sig_init");
    let sig_res = AggregateSignature::from_bytes(sig_bytes);
    println!("cycle-tracker-end: utils:aggregate_sig_init");
    match sig_res {
        Ok(sig) => sig.fast_aggregate_verify(msg, pks),
        Err(_) => false,
    }
}
