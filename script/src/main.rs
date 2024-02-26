//! A simple script to generate and verify the proof of a given program.

use ethers::types::H256;
use eyre::Result;
use helios::{
    //config::networks::Network,
    consensus::{
        self, constants,
        rpc::{nimbus_rpc::NimbusRpc, ConsensusRpc},
        types::Update,
        utils, Inner,
    },
    prelude::*,
};
use helios_prover_primitives::types::{Bytes32, Header, U64};
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

async fn get_update() -> Update {
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

    let check = get_latest_checkpoint().await;
    let checkpoint = check.as_bytes().to_vec();
    //let checkpoint =
    //hex::decode("60b0473910c8236cdd467f5115ea612f65dd71e052533a60f3864eee0702aaf0").unwrap();

    let (block_send, _) = channel(256);
    let (finalized_block_send, _) = watch::channel(None);
    let (channel_send, _) = watch::channel(None);

    let mut inner = Inner::<NimbusRpc>::new(
        //"testdata/",
        consensus_rpc,
        block_send,
        finalized_block_send,
        channel_send,
        Arc::new(config),
    );

    //only sync when verifying finallity
    //inner.sync(&checkpoint).await.unwrap();
    inner.bootstrap(&checkpoint).await.unwrap();

    let period = utils::calc_sync_period(inner.store.finalized_header.slot.into());
    let updates = inner
        .rpc
        .get_updates(period, constants::MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await
        .unwrap();

    //let update = updates[0].clone();
    //inner.verify_update(&update).unwrap();
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

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracer();

    // Generate proof.
    let mut stdin = SP1Stdin::new();

    let update = get_update().await;

    let attested_header = to_header(update.attested_header);

    let finality_branch: Vec<Bytes32> = update
        .finality_branch
        .iter()
        .map(|v| Bytes32::try_from(v.as_slice()).unwrap())
        .collect();

    let finalized_header = to_header(update.finalized_header);

    stdin.write(&attested_header);
    stdin.write(&finality_branch);
    stdin.write(&finalized_header);

    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");
    //SP1Prover::execute(ELF, stdin).expect("execute failed");

    // Read output.
    let valid = proof.stdout.read::<bool>();
    println!("valid: {}", valid);

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    //// Save proof.
    //proof
    //.save("proof-with-io.json")
    //.expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!");
    Ok(())
}
