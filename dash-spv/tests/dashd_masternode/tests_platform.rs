//! Masternode lookups made the way Dash Platform's `rs-platform-wallet` makes
//! them against a `DashSpvClient`: quorum public keys for proof verification at
//! the proof's core chain locked height, and reads of the tip masternode list
//! from blocking FFI threads.

use std::collections::HashMap;
use std::sync::Arc;

use dashcore::address::NetworkUnchecked;
use dashcore::hashes::Hash;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::{Address, Network, PubkeyHash, QuorumHash};

use super::helpers::{
    mine_dkg_cycle_and_wait, mine_past_the_pruning_floor, wait_for_masternode_sync,
};
use super::setup::{
    create_and_start_client, create_client, create_dummy_wallet, create_mn_test_config, TestClient,
    TestContext, SYNC_TIMEOUT,
};

/// `SpvRuntime::get_quorum_public_key`. The proof carries the quorum hash in
/// display order, which Platform reverses before asking the client.
async fn platform_quorum_public_key(
    client: &TestClient,
    quorum_type: u32,
    quorum_hash: [u8; 32],
    height: u32,
) -> Result<[u8; 48], String> {
    let llmq_type = LLMQType::from(quorum_type as u8);
    let qh = QuorumHash::from_byte_array(quorum_hash).reverse();

    let quorum =
        client.get_quorum_at_height(height, llmq_type, qh).await.map_err(|e| e.to_string())?;

    Ok(*quorum.quorum_entry.quorum_public_key.as_ref())
}

/// `SpvRuntime::masternode_validity_snapshot_blocking`, on a blocking thread
/// the way the FFI runs it.
async fn platform_validity_snapshot(client: &TestClient) -> Option<HashMap<[u8; 32], bool>> {
    let client = client.clone();
    tokio::task::spawn_blocking(move || {
        let engine = client.masternode_list_engine().ok()?;
        let engine_guard = engine.blocking_read();
        let list = engine_guard.latest_masternode_list()?;
        Some(
            list.masternodes
                .values()
                .map(|qualified| {
                    let entry = &qualified.masternode_list_entry;
                    let mut pro_tx = [0u8; 32];
                    pro_tx.copy_from_slice(entry.pro_reg_tx_hash.as_ref());
                    (pro_tx, entry.is_valid)
                })
                .collect(),
        )
    })
    .await
    .expect("blocking snapshot panicked")
}

/// `SpvRuntime::masternodes_by_voting_key_blocking`.
async fn platform_masternodes_by_voting_key(
    client: &TestClient,
    voting_key_id: PubkeyHash,
) -> Vec<[u8; 32]> {
    let client = client.clone();
    tokio::task::spawn_blocking(move || {
        let Ok(engine) = client.masternode_list_engine() else {
            return Vec::new();
        };
        let engine_guard = engine.blocking_read();
        let Some(list) = engine_guard.latest_masternode_list() else {
            return Vec::new();
        };
        list.masternodes
            .values()
            .filter(|qualified| qualified.masternode_list_entry.key_id_voting == voting_key_id)
            .map(|qualified| {
                let mut pro_tx = [0u8; 32];
                pro_tx.copy_from_slice(qualified.masternode_list_entry.pro_reg_tx_hash.as_ref());
                pro_tx
            })
            .collect()
    })
    .await
    .expect("blocking voting key lookup panicked")
}

/// A quorum as a Platform proof names it.
#[derive(Clone, Copy, Debug)]
struct ProofQuorum {
    quorum_type: u32,
    quorum_hash: [u8; 32],
    public_key: [u8; 48],
    /// Height of the block whose hash is the quorum hash: no list below it can
    /// hold the quorum.
    block_height: u32,
}

impl ProofQuorum {
    fn llmq_type(&self) -> LLMQType {
        LLMQType::from(self.quorum_type as u8)
    }

    fn hash(&self) -> QuorumHash {
        QuorumHash::from_byte_array(self.quorum_hash).reverse()
    }
}

fn block_height_of(ctx: &TestContext, hash: &QuorumHash) -> u32 {
    let header = ctx
        .mn_ctx
        .controller
        .try_rpc_call("getblockheader", &[serde_json::json!(hash.to_string())])
        .expect("dashd knows the quorum's block");
    header["height"].as_u64().expect("header height") as u32
}

/// Dashd's own public key for the quorum, independent of the SPV.
fn dashd_public_key(ctx: &TestContext, llmq_type: LLMQType, hash: &QuorumHash) -> [u8; 48] {
    let info = ctx
        .mn_ctx
        .controller
        .try_rpc_call(
            "quorum",
            &[
                serde_json::json!("info"),
                serde_json::json!(llmq_type as u8),
                serde_json::json!(hash.to_string()),
            ],
        )
        .expect("dashd knows the quorum");
    let bytes = hex::decode(info["quorumPublicKey"].as_str().expect("quorumPublicKey"))
        .expect("public key hex");
    bytes.try_into().expect("48-byte public key")
}

/// The non-rotating quorums of `list`, the kind Platform signs proofs with,
/// platform type first.
fn proof_quorums(ctx: &TestContext, list: &MasternodeList) -> Vec<ProofQuorum> {
    let platform = Network::Regtest.platform_type();
    let mut quorums: Vec<ProofQuorum> = list
        .quorums
        .iter()
        .filter(|(llmq_type, _)| !llmq_type.is_rotating_quorum_type())
        .flat_map(|(llmq_type, quorums)| quorums.keys().map(move |hash| (*llmq_type, *hash)))
        .map(|(llmq_type, hash)| ProofQuorum {
            quorum_type: llmq_type as u8 as u32,
            quorum_hash: hash.reverse().to_byte_array(),
            public_key: dashd_public_key(ctx, llmq_type, &hash),
            block_height: block_height_of(ctx, &hash),
        })
        .collect();
    quorums.sort_by_key(|quorum| (quorum.llmq_type() != platform, quorum.block_height));
    quorums
}

async fn assert_found(client: &TestClient, quorum: &ProofQuorum, height: u32, case: &str) {
    let key = platform_quorum_public_key(client, quorum.quorum_type, quorum.quorum_hash, height)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{case}: quorum {} type {} at height {height} must resolve: {e}",
                quorum.hash(),
                quorum.llmq_type()
            )
        });
    assert_eq!(key, quorum.public_key, "{case}: SPV and dashd disagree on the public key");
}

async fn assert_not_found(
    client: &TestClient,
    quorum_type: u32,
    hash: [u8; 32],
    height: u32,
    case: &str,
) {
    let result = platform_quorum_public_key(client, quorum_type, hash, height).await;
    assert!(
        result.as_ref().is_err_and(|e| e.contains("Quorum not found")),
        "{case}: expected a not-found error at height {height}, got {result:?}"
    );
}

/// Every masternode the network registered is in the tip list Platform reads,
/// valid, and found by its voting key.
async fn assert_tip_list_reads(ctx: &TestContext, client: &TestClient, case: &str) {
    let snapshot = platform_validity_snapshot(client)
        .await
        .unwrap_or_else(|| panic!("{case}: Platform must see a tip masternode list"));

    for masternode in &ctx.mn_ctx.metadata.masternodes {
        // Internal order, as a registration txid is stored: the RPC hex reversed.
        let mut pro_tx_bytes: [u8; 32] =
            hex::decode(&masternode.pro_tx_hash).expect("proTxHash hex").try_into().unwrap();
        pro_tx_bytes.reverse();

        assert_eq!(
            snapshot.get(&pro_tx_bytes),
            Some(&true),
            "{case}: masternode {} must be listed as valid, snapshot holds {} entries",
            masternode.pro_tx_hash,
            snapshot.len()
        );

        let voting_key_id = masternode
            .voting_address
            .parse::<Address<NetworkUnchecked>>()
            .expect("voting address")
            .assume_checked()
            .payload()
            .as_pubkey_hash()
            .copied()
            .expect("voting address is P2PKH");
        let by_voting_key = platform_masternodes_by_voting_key(client, voting_key_id).await;
        assert!(
            by_voting_key.contains(&pro_tx_bytes),
            "{case}: voting key of {} must map back to it, got {} masternode(s)",
            masternode.pro_tx_hash,
            by_voting_key.len()
        );
    }
}

/// Every height a proof can carry, while the client runs, after the lists the
/// quorum sits in have been pruned from memory, and after a restart before and
/// after the client is back on the network.
#[tokio::test]
async fn test_platform_quorum_lookups_across_heights_and_restart() {
    let Some(ctx) = TestContext::new(true).await else {
        return;
    };

    let wallet = create_dummy_wallet();
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);

    let mut client_handle = create_and_start_client(&config, Arc::clone(&wallet)).await;
    let progress =
        wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;
    let synced_height = progress.current_height();

    let quorums = {
        let engine = client_handle.engine.read().await;
        let tip_list = engine.latest_masternode_list().expect("synced list");
        proof_quorums(&ctx, tip_list)
    };
    tracing::info!(
        "Proof quorums at {synced_height}: {:?}",
        quorums.iter().map(|q| (q.llmq_type(), q.block_height)).collect::<Vec<_>>()
    );
    let quorum = *quorums.first().expect("the synced list holds a non-rotating quorum");
    let other_type = quorums
        .iter()
        .map(|q| q.quorum_type)
        .find(|t| *t != quorum.quorum_type)
        .unwrap_or(Network::Regtest.isd_llmq_type() as u8 as u32);
    let client = client_handle.client.clone();

    assert_found(&client, &quorum, synced_height, "fresh proof at the synced tip").await;
    assert_found(&client, &quorum, synced_height + 100, "Platform ahead of the SPV tip").await;
    for other in &quorums {
        assert_found(&client, other, synced_height, "every quorum in the tip list").await;
    }
    assert_tip_list_reads(&ctx, &client, "after the initial sync").await;

    let tip = mine_past_the_pruning_floor(&ctx, &mut client_handle, synced_height).await;
    let lowest_in_memory =
        *client_handle.engine.read().await.masternode_lists.keys().next().expect("lists");
    assert!(
        lowest_in_memory > synced_height,
        "the live engine must have pruned the synced tip's list for the old cases to mean anything"
    );

    assert_found(&client, &quorum, tip, "fresh proof at the new tip").await;
    for height in (lowest_in_memory..=tip).step_by(7) {
        assert_found(&client, &quorum, height, "height inside the retained window").await;
    }
    assert_found(&client, &quorum, synced_height, "old proof, list pruned from memory").await;
    assert_found(
        &client,
        &quorum,
        quorum.block_height.max(synced_height - 1),
        "old proof just below the synced tip",
    )
    .await;
    assert_not_found(
        &client,
        quorum.quorum_type,
        quorum.quorum_hash,
        quorum.block_height - 1,
        "height before the quorum's block",
    )
    .await;
    assert_not_found(&client, quorum.quorum_type, [0x42; 32], tip, "unknown quorum hash").await;
    assert_not_found(&client, other_type, quorum.quorum_hash, tip, "right hash, wrong type").await;
    assert_tip_list_reads(&ctx, &client, "after pruning").await;

    client_handle.stop().await;
    drop(client);
    drop(client_handle);

    let mut client_handle = create_client(&config, Arc::clone(&wallet)).await;
    let client = client_handle.client.clone();

    assert_found(&client, &quorum, tip, "tip proof, restarted, before the network").await;
    assert_found(&client, &quorum, synced_height, "old proof, restarted, before the network").await;
    assert_not_found(
        &client,
        quorum.quorum_type,
        quorum.quorum_hash,
        quorum.block_height - 1,
        "height before the quorum's block, restarted",
    )
    .await;
    assert_tip_list_reads(&ctx, &client, "restarted, before the network").await;

    client_handle.start();
    wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;

    assert_found(&client, &quorum, tip, "tip proof, restarted and synced").await;
    assert_found(&client, &quorum, synced_height, "old proof, restarted and synced").await;
    assert_tip_list_reads(&ctx, &client, "restarted and synced").await;

    client_handle.stop().await;
}

/// A proof signed by a quorum that has since left the active set. The tip list
/// no longer holds it, so the lookup has to walk back to a list that does.
#[tokio::test]
async fn test_platform_quorum_lookup_after_the_quorum_retires() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };

    let wallet = create_dummy_wallet();
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);

    let mut client_handle = create_and_start_client(&config, Arc::clone(&wallet)).await;
    let progress =
        wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;
    let mut height = progress.current_height();

    let (oldest, signed_at) = {
        let engine = client_handle.engine.read().await;
        let tip_list = engine.latest_masternode_list().expect("synced list");
        let quorums = proof_quorums(&ctx, tip_list);
        let rotating_out = quorums
            .iter()
            .filter(|q| q.quorum_type == Network::Regtest.chain_locks_type() as u8 as u32)
            .min_by_key(|q| q.block_height)
            .copied()
            .expect("the tip list holds a chainlock-type quorum, which DKG cycles replace");
        (rotating_out, tip_list.known_height)
    };

    let mut retired = false;
    for _ in 0..4 {
        height =
            mine_dkg_cycle_and_wait(&mut ctx, &mut client_handle.sync_event_receiver, height).await;
        let engine = client_handle.engine.read().await;
        let tip_list = engine.latest_masternode_list().expect("list");
        if tip_list
            .quorum_entry_of_type_for_quorum_hash(oldest.llmq_type(), oldest.hash())
            .is_none()
        {
            retired = true;
            break;
        }
    }
    assert!(retired, "quorum {} never left the active set in 4 DKG cycles", oldest.hash());

    let client = client_handle.client.clone();
    assert_found(&client, &oldest, signed_at, "proof signed while the quorum was active").await;
    assert_found(&client, &oldest, height, "proof checked after the quorum retired").await;

    client_handle.stop().await;
}
