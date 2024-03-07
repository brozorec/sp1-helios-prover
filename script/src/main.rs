//! A simple script to generate and verify the proof of a given program.

use ethers::types::H256;
use eyre::Result;
use helios::{
    consensus::{
        self, constants,
        rpc::{nimbus_rpc::NimbusRpc, ConsensusRpc},
        types::{Bootstrap, Update},
        utils, Inner,
    },
    prelude::*,
};
use helios_prover_primitives::types::{
    BLSPubKey, Bytes32, Header, SignatureBytes, SyncAggregate, SyncCommittee, Vector, U64,
};
use sp1_core::{utils::setup_tracer, SP1Prover, SP1Stdin, SP1Verifier};
use std::sync::Arc;
use tokio::sync::{mpsc::channel, watch};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

async fn get_latest_checkpoint() -> H256 {
    let cf = checkpoints::CheckpointFallback::new()
        .build()
        .await
        .unwrap();

    // Fetch the latest mainnet checkpoint
    let mainnet_checkpoint = cf
        .fetch_latest_checkpoint(&networks::Network::MAINNET)
        .await
        .unwrap();
    println!(
        "Fetched latest mainnet checkpoint: {:?}",
        mainnet_checkpoint
    );

    mainnet_checkpoint
}

async fn get_client(checkpoint: Vec<u8>) -> Inner<NimbusRpc> {
    let consensus_rpc = "https://www.lightclientdata.org";

    let base_config = networks::mainnet();
    let config = Config {
        consensus_rpc: consensus_rpc.to_string(),
        //consensus_rpc: String::new(),
        //execution_rpc: untrusted_rpc_url.to_string(),
        execution_rpc: String::new(),
        chain: base_config.chain,
        forks: base_config.forks,
        strict_checkpoint_age: false,
        ..Default::default()
    };

    //let check = get_latest_checkpoint().await;
    //let checkpoint = check.as_bytes().to_vec();
    //let checkpoint =
    //hex::decode("60b0473910c8236cdd467f5115ea612f65dd71e052533a60f3864eee0702aaf0").unwrap();

    let (block_send, _) = channel(256);
    let (finalized_block_send, _) = watch::channel(None);
    let (channel_send, _) = watch::channel(None);

    let mut client = Inner::<NimbusRpc>::new(
        //"testdata/",
        consensus_rpc,
        block_send,
        finalized_block_send,
        channel_send,
        Arc::new(config),
    );

    //only sync when verifying finallity
    //client.sync(&checkpoint).await.unwrap();
    client.bootstrap(&checkpoint).await.unwrap();
    client
}

async fn get_bootstrap(client: &Inner<NimbusRpc>, checkpoint: &[u8]) -> Bootstrap {
    client.rpc.get_bootstrap(checkpoint).await.unwrap()
}

async fn get_update(client: &Inner<NimbusRpc>) -> Update {
    let period = utils::calc_sync_period(client.store.finalized_header.slot.into());
    let updates = client
        .rpc
        .get_updates(period, constants::MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await
        .unwrap();

    /*let update = updates[0].clone();*/
    //client.verify_update(&update).unwrap();
    //update
    updates[0].clone()
}

fn to_header(h: consensus::types::Header) -> Header {
    Header {
        slot: U64::from(h.slot.as_u64()),
        proposer_index: U64::from(h.proposer_index.as_u64()),
        parent_root: Bytes32::try_from(h.parent_root.as_slice()).unwrap(),
        state_root: Bytes32::try_from(h.state_root.as_slice()).unwrap(),
        body_root: Bytes32::try_from(h.body_root.as_slice()).unwrap(),
    }
}

fn to_committee(c: consensus::types::SyncCommittee) -> SyncCommittee {
    let pubkeys: Vec<BLSPubKey> = c
        .pubkeys
        .to_vec()
        .iter()
        .map(|k| BLSPubKey::try_from(k.as_slice()).unwrap())
        .collect();

    let aggregate_pubkey: BLSPubKey = BLSPubKey::try_from(c.aggregate_pubkey.as_slice()).unwrap();
    SyncCommittee {
        pubkeys: Vector::try_from(pubkeys).unwrap(),
        aggregate_pubkey,
    }
}

fn to_branch(v: Vec<consensus::types::Bytes32>) -> Vec<Bytes32> {
    v.iter()
        .map(|v| Bytes32::try_from(v.as_slice()).unwrap())
        .collect()
}

fn to_sync_agg(sa: consensus::types::SyncAggregate) -> SyncAggregate {
    SyncAggregate {
        sync_committee_bits: sa.sync_committee_bits,
        sync_committee_signature: SignatureBytes::try_from(sa.sync_committee_signature.as_slice())
            .unwrap(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracer();

    // Generate proof.
    let mut stdin = SP1Stdin::new();

    let checkpoint = get_latest_checkpoint().await;
    let client = get_client(checkpoint.as_bytes().to_vec()).await;
    let bootstrap = get_bootstrap(&client, checkpoint.as_bytes()).await;
    let update = get_update(&client).await;

    let attested_header = to_header(update.attested_header.clone());

    let finality_branch = to_branch(update.finality_branch);

    let finalized_header = to_header(update.finalized_header);
    let current_sync_committee = to_committee(bootstrap.current_sync_committee);
    let current_sync_committee_branch = to_branch(bootstrap.current_sync_committee_branch);
    let next_committee = to_committee(update.next_sync_committee);
    let next_sync_committee_branch = to_branch(update.next_sync_committee_branch);
    let sync_aggregate = to_sync_agg(update.sync_aggregate);

    stdin.write(&attested_header);
    stdin.write(&finality_branch);
    stdin.write(&finalized_header);
    stdin.write(&current_sync_committee);
    stdin.write(&current_sync_committee_branch);
    stdin.write(&next_committee);
    stdin.write(&next_sync_committee_branch);
    stdin.write(&sync_aggregate);

    //let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");
    let mut out = SP1Prover::execute(ELF, stdin).expect("execute failed");
    let valid = out.read::<bool>();
    println!("valid: {}", valid);

    // Read output.
    //let valid = proof.stdout.read::<bool>();
    //println!("valid: {}", valid);

    // Verify proof.
    //SP1Verifier::verify(ELF, &proof).expect("verification failed");

    //// Save proof.
    //proof
    //.save("proof-with-io.json")
    //.expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!");
    Ok(())
}
