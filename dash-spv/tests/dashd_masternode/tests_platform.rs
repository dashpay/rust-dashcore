//! Masternode lookups made the way Dash Platform makes them against a
//! `DashSpvClient`, checked against dashd: quorum public keys for proof
//! verification (dash-evo-tool, through `rs-platform-wallet`'s `SpvRuntime`)
//! and reads of the tip masternode list from blocking FFI threads (Swift SDK).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use dashcore::address::NetworkUnchecked;
use dashcore::hashes::Hash;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_entry::{EntryMasternodeType, MasternodeListEntry};
use dashcore::{Address, Network, PubkeyHash, QuorumHash};
use serde_json::{json, Value};

use super::helpers::{follow_tip, mine_and_follow, wait_for_masternode_sync};
use super::setup::{
    create_client, create_dummy_wallet, create_mn_test_config, ClientHandle, TestClient,
    TestContext, SYNC_TIMEOUT,
};

/// Active windows below the lookup height the quorum walk-back searches.
const WALK_BACK_ACTIVE_WINDOWS: u32 = 4;

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

/// A tip list read the way every `SpvRuntime` masternode accessor makes it: on
/// a blocking thread, `None` until the SPV holds a list.
async fn platform_tip_read<T: Send + 'static>(
    client: &TestClient,
    read: impl FnOnce(&MasternodeList) -> T + Send + 'static,
) -> Option<T> {
    let client = client.clone();
    tokio::task::spawn_blocking(move || {
        let engine = client.masternode_list_engine().ok()?;
        let engine_guard = engine.blocking_read();
        engine_guard.latest_masternode_list().map(read)
    })
    .await
    .expect("blocking tip list read panicked")
}

/// `SpvRuntime::masternode_validity_snapshot_blocking`.
async fn platform_validity_snapshot(client: &TestClient) -> Option<HashMap<[u8; 32], bool>> {
    platform_tip_read(client, |list| {
        list.masternodes
            .values()
            .map(|qualified| {
                let entry = &qualified.masternode_list_entry;
                (entry.pro_reg_tx_hash.to_byte_array(), entry.is_valid)
            })
            .collect()
    })
    .await
}

/// `SpvRuntime::masternodes_by_voting_key_blocking`.
async fn platform_masternodes_by_voting_key(
    client: &TestClient,
    voting_key_id: PubkeyHash,
) -> BTreeSet<[u8; 32]> {
    platform_tip_read(client, move |list| {
        list.masternodes
            .values()
            .map(|qualified| &qualified.masternode_list_entry)
            .filter(|entry| entry.key_id_voting == voting_key_id)
            .map(|entry| entry.pro_reg_tx_hash.to_byte_array())
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// The entries `SpvRuntime::masternode_list_summaries_blocking` lifts into
/// summaries, with the height of their list.
async fn platform_list_entries(client: &TestClient) -> Option<(u32, Vec<MasternodeListEntry>)> {
    platform_tip_read(client, |list| {
        let entries = list.masternodes.values().map(|q| q.masternode_list_entry.clone()).collect();
        (list.known_height, entries)
    })
    .await
}

fn rpc(ctx: &TestContext, method: &str, params: &[Value]) -> Value {
    ctx.mn_ctx
        .controller
        .try_rpc_call(method, params)
        .unwrap_or_else(|| panic!("dashd {method} {params:?} failed"))
}

/// Internal order, as a registration txid is stored: the RPC hex reversed.
fn pro_tx_bytes(hex: &str) -> [u8; 32] {
    let mut bytes: [u8; 32] =
        hex::decode(hex).expect("proTxHash hex").try_into().expect("32 bytes");
    bytes.reverse();
    bytes
}

fn voting_key_id(address: &str) -> PubkeyHash {
    *address
        .parse::<Address<NetworkUnchecked>>()
        .expect("voting address")
        .assume_checked()
        .payload()
        .as_pubkey_hash()
        .expect("P2PKH voting address")
}

/// The quorums dashd has active at `height`, of every type.
fn dashd_active_quorums(ctx: &TestContext, height: u32) -> BTreeSet<(LLMQType, QuorumHash)> {
    let active = rpc(ctx, "quorum", &[json!("listextended"), json!(height)]);
    let mut quorums = BTreeSet::new();
    for (name, list) in active.as_object().expect("quorums by type") {
        let llmq_type = (1..=u8::MAX)
            .map(LLMQType::from)
            .find(|t| *t != LLMQType::LlmqtypeUnknown && t.params().name == name)
            .unwrap_or_else(|| panic!("unknown quorum type {name}"));
        for quorum in list.as_array().expect("quorums") {
            for hash in quorum.as_object().expect("quorum").keys() {
                quorums.insert((llmq_type, hash.parse().expect("quorum hash")));
            }
        }
    }
    quorums
}

/// The height of the block dashd mined the quorum in, and its public key.
fn dashd_quorum(ctx: &TestContext, llmq_type: LLMQType, hash: QuorumHash) -> (u32, [u8; 48]) {
    let info =
        rpc(ctx, "quorum", &[json!("info"), json!(llmq_type as u8), json!(hash.to_string())]);
    let mined = rpc(ctx, "getblockheader", &[info["minedBlock"].clone()])["height"]
        .as_u64()
        .expect("mined height");
    let key = hex::decode(info["quorumPublicKey"].as_str().expect("quorumPublicKey"))
        .expect("public key hex");
    (mined as u32, key.try_into().expect("48-byte public key"))
}

async fn sync(ctx: &TestContext, client_handle: &mut ClientHandle) {
    client_handle.start();
    wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;
    follow_tip(ctx, client_handle).await;
}

/// Asks for every quorum type with every quorum hash the SPV holds, and one no
/// quorum has, at every height from genesis to one past the walk-back reach of
/// the tip. A lookup resolves, with dashd's key, exactly from the first list
/// holding the quorum to the walk-back reach of the last one. Returns the tip
/// and, per quorum, the first and last list holding it.
async fn assert_lookups_at_every_height(
    ctx: &TestContext,
    client_handle: &ClientHandle,
) -> (u32, BTreeMap<(LLMQType, QuorumHash), (u32, u32)>) {
    let (lowest, tip, reach) = {
        let engine = client_handle.engine.read().await;
        let lowest = *engine.masternode_lists.keys().next().expect("a list");
        let mut reach = BTreeMap::new();
        for (height, list) in &engine.masternode_lists {
            for (llmq_type, quorums) in &list.quorums {
                for hash in quorums.keys() {
                    reach.entry((*llmq_type, *hash)).or_insert((*height, *height)).1 = *height;
                }
            }
        }
        (lowest, engine.latest_masternode_list().expect("a tip list").known_height, reach)
    };

    let at_tip: BTreeSet<_> =
        reach.iter().filter(|(_, &(_, last))| last == tip).map(|(quorum, _)| *quorum).collect();
    assert_eq!(at_tip, dashd_active_quorums(ctx, tip), "quorums active at the tip {tip}");

    let dashd: BTreeMap<_, _> =
        reach.keys().map(|&(t, hash)| ((t, hash), dashd_quorum(ctx, t, hash))).collect();
    let cycle = Network::Regtest.isd_llmq_type().params().dkg_params.interval;
    let recent = lowest.max(tip.saturating_sub(cycle));
    for (&(llmq_type, hash), &(first, _)) in &reach {
        let mined = dashd[&(llmq_type, hash)].0;
        if first > recent {
            assert_eq!(first, mined, "{llmq_type} {hash}: first list holding it, mined block");
        } else {
            assert!(first >= mined, "{llmq_type} {hash} is in a list at {first}, mined at {mined}");
        }
    }

    let mut hashes: BTreeSet<QuorumHash> = reach.keys().map(|(_, hash)| *hash).collect();
    hashes.insert(QuorumHash::from_byte_array([0x42; 32]));

    let mut llmq_types: BTreeSet<LLMQType> = reach.keys().map(|(t, _)| *t).collect();
    llmq_types.extend(Network::Regtest.enabled_llmq_types());
    llmq_types.insert(Network::Regtest.platform_type());

    for llmq_type in llmq_types {
        let params = llmq_type.params();
        let walk_back = WALK_BACK_ACTIVE_WINDOWS
            * params.signing_active_quorum_count
            * params.dkg_params.interval;
        for hash in &hashes {
            let expected = reach
                .get(&(llmq_type, *hash))
                .map(|&(first, last)| (first..=last + walk_back, dashd[&(llmq_type, *hash)].1));
            for height in 0..=tip + walk_back + 1 {
                let result = platform_quorum_public_key(
                    &client_handle.client,
                    llmq_type as u8 as u32,
                    hash.reverse().to_byte_array(),
                    height,
                )
                .await;
                match &expected {
                    Some((found, key)) if found.contains(&height) => assert_eq!(
                        result.as_ref(),
                        Ok(key),
                        "{llmq_type} {hash} at {height}, found from lists at {found:?}"
                    ),
                    _ => assert!(
                        result.as_ref().is_err_and(|e| e.contains("Quorum not found")),
                        "{llmq_type} {hash} at {height} must miss, got {result:?}"
                    ),
                }
            }
        }
    }

    (tip, reach)
}

/// Platform's reads of the tip list agree with dashd's registered masternodes
/// at the same height: status, voting keys and every field a summary lifts.
async fn assert_tip_list_matches_dashd(ctx: &TestContext, client: &TestClient) {
    let (height, entries) = platform_list_entries(client).await.expect("a tip list");
    let validity = platform_validity_snapshot(client).await.expect("a tip list");
    let registered =
        rpc(ctx, "protx", &[json!("list"), json!("registered"), json!(true), json!(height)]);
    let registered = registered.as_array().expect("registered masternodes");
    assert_eq!(entries.len(), registered.len(), "masternodes listed at {height}");
    assert_eq!(validity.len(), registered.len(), "validity snapshot at {height}");

    let mut by_voting_key: BTreeMap<PubkeyHash, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for masternode in registered {
        let pro_tx_hash = pro_tx_bytes(masternode["proTxHash"].as_str().expect("proTxHash"));
        let case = format!("{} at {height}", masternode["proTxHash"]);
        let state = &masternode["state"];
        let entry = entries
            .iter()
            .find(|entry| entry.pro_reg_tx_hash.to_byte_array() == pro_tx_hash)
            .unwrap_or_else(|| panic!("{case}: missing from the SPV list"));

        assert_eq!(validity[&pro_tx_hash], state["PoSeBanHeight"] == -1, "{case}: validity");
        assert_eq!(
            entry.service_address.primary_service_address().map(|addr| addr.to_string()),
            state["service"].as_str().map(String::from),
            "{case}: service"
        );
        assert_eq!(
            hex::encode(entry.operator_public_key.to_bytes()),
            state["pubKeyOperator"],
            "{case}: operator key"
        );
        let voting = voting_key_id(state["votingAddress"].as_str().expect("votingAddress"));
        assert_eq!(entry.key_id_voting, voting, "{case}: voting key");
        match (&entry.mn_type, masternode["type"].as_str()) {
            (EntryMasternodeType::Regular, Some("Regular")) => {}
            (
                EntryMasternodeType::HighPerformance {
                    platform_http_port,
                    platform_node_id,
                },
                Some("Evo"),
            ) => {
                assert_eq!(json!(platform_http_port), state["platformHTTPPort"], "{case}: port");
                assert_eq!(
                    hex::encode(platform_node_id.to_byte_array()),
                    state["platformNodeID"],
                    "{case}: platform node id"
                );
            }
            (mn_type, dashd_type) => panic!("{case}: {mn_type:?}, dashd says {dashd_type:?}"),
        }
        by_voting_key.entry(voting).or_default().insert(pro_tx_hash);
    }

    for (voting_key_id, pro_tx_hashes) in by_voting_key {
        assert_eq!(
            platform_masternodes_by_voting_key(client, voting_key_id).await,
            pro_tx_hashes,
            "masternodes of voting key {voting_key_id} at {height}"
        );
    }
}

/// Registers an evonode whose voting key is `voting_address`. Returns its
/// proTxHash in internal order.
fn register_evonode(ctx: &TestContext, voting_address: &str) -> [u8; 32] {
    let new_address = || json!(ctx.mn_ctx.controller.get_new_address().to_string());
    let payout = new_address();
    rpc(ctx, "sendtoaddress", &[payout.clone(), json!(4001)]);
    let operator = rpc(ctx, "bls", &[json!("generate")]);
    let pro_tx_hash = rpc(
        ctx,
        "protx",
        &[
            json!("register_fund_evo"),
            new_address(),
            json!(["127.0.0.1:29990"]),
            new_address(),
            operator["public"].clone(),
            json!(voting_address),
            json!("0"),
            payout,
            json!("00112233445566778899aabbccddeeff00112233"),
            json!(29991),
            json!(29992),
        ],
    );
    pro_tx_bytes(pro_tx_hash.as_str().expect("proTxHash"))
}

/// Spends the collateral of `pro_tx_hash`, which drops it from the list.
fn spend_collateral(ctx: &TestContext, pro_tx_hash: &str) {
    let info = rpc(ctx, "protx", &[json!("info"), json!(pro_tx_hash)]);
    let collateral = json!([{"txid": info["collateralHash"], "vout": info["collateralIndex"]}]);
    rpc(ctx, "lockunspent", &[json!(true), collateral.clone()]);
    let mut outputs = serde_json::Map::new();
    outputs.insert(ctx.mn_ctx.controller.get_new_address().to_string(), json!(999.999));
    let raw = rpc(ctx, "createrawtransaction", &[collateral, Value::Object(outputs)]);
    let signed = rpc(ctx, "signrawtransactionwithwallet", &[raw]);
    rpc(ctx, "sendrawtransaction", &[signed["hex"].clone()]);
}

/// Every height a proof can carry relative to the SPV tip, for every quorum
/// the SPV holds: before the first list holding it, in lists that hold it, past
/// its retirement, and with Platform ahead of the SPV, up to and past the
/// walk-back reach. Once after the sync, and once the chain has moved on past
/// the reach of every list the sync fetched.
#[tokio::test]
async fn test_platform_quorum_lookups_at_every_height() {
    let Some(ctx) = TestContext::new(true).await else {
        return;
    };
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);
    let mut client_handle = create_client(&config, create_dummy_wallet()).await;
    sync(&ctx, &mut client_handle).await;

    let (tip, reach) = assert_lookups_at_every_height(&ctx, &client_handle).await;
    assert!(reach.values().any(|&(_, last)| last < tip), "a quorum retired before the tip");
    assert!(
        reach.keys().any(|(t, h)| reach.keys().any(|(other, hash)| hash == h && other != t)),
        "a quorum hash shared by two quorum types"
    );

    mine_and_follow(&ctx, &mut client_handle, 250).await;
    assert_lookups_at_every_height(&ctx, &client_handle).await;

    client_handle.stop().await;
}

/// Lookups at every height across three DKG cycles: quorums active at the sync
/// retire, and quorums mined after it retire in turn, still found through the
/// walk-back past the lists that dropped them.
#[tokio::test]
async fn test_platform_quorum_lookups_across_rotations() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);
    let mut client_handle = create_client(&config, create_dummy_wallet()).await;
    sync(&ctx, &mut client_handle).await;

    let (synced, at_sync) = assert_lookups_at_every_height(&ctx, &client_handle).await;

    for _ in 0..3 {
        ctx.mn_ctx.mine_dkg_cycle().expect("DKG cycle should succeed");
        follow_tip(&ctx, &mut client_handle).await;
    }
    let (tip, reach) = assert_lookups_at_every_height(&ctx, &client_handle).await;
    let retired = |quorum: &(LLMQType, QuorumHash)| reach[quorum].1 < tip;
    assert!(
        at_sync.iter().any(|(quorum, &(_, last))| last == synced && retired(quorum)),
        "a quorum active at the sync retired"
    );
    assert!(
        reach.keys().any(|quorum| !at_sync.contains_key(quorum) && retired(quorum)),
        "a quorum mined after the sync retired"
    );

    client_handle.stop().await;
}

/// A proof can carry any height its quorum is active at. In the last rotation
/// cycle below the SPV tip, where Platform's core heights fall, every quorum
/// dashd has active resolves to dashd's key.
async fn assert_active_quorums_resolve(ctx: &TestContext, client_handle: &ClientHandle) {
    let heights = {
        let engine = client_handle.engine.read().await;
        let first = *engine.masternode_lists.keys().next().expect("a list");
        let tip = engine.latest_masternode_list().expect("a tip list").known_height;
        let cycle = Network::Regtest.isd_llmq_type().params().dkg_params.interval;
        first.max(tip.saturating_sub(cycle) + 1)..=tip
    };
    let mut keys = BTreeMap::new();
    let mut misses: BTreeMap<_, Vec<u32>> = BTreeMap::new();
    for height in heights {
        for (llmq_type, hash) in dashd_active_quorums(ctx, height) {
            let (_, key) = *keys
                .entry((llmq_type, hash))
                .or_insert_with(|| dashd_quorum(ctx, llmq_type, hash));
            let result = platform_quorum_public_key(
                &client_handle.client,
                llmq_type as u8 as u32,
                hash.reverse().to_byte_array(),
                height,
            )
            .await;
            if result != Ok(key) {
                misses.entry((llmq_type, hash)).or_default().push(height);
            }
        }
    }
    assert!(misses.is_empty(), "quorums dashd has active, missed at these heights: {misses:?}");
}

/// Right after the sync, and after three DKG cycles followed by the SPV.
#[tokio::test]
async fn test_platform_quorum_lookups_wherever_dashd_has_the_quorum_active() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);
    let mut client_handle = create_client(&config, create_dummy_wallet()).await;
    sync(&ctx, &mut client_handle).await;
    assert_active_quorums_resolve(&ctx, &client_handle).await;

    for _ in 0..3 {
        ctx.mn_ctx.mine_dkg_cycle().expect("DKG cycle should succeed");
        follow_tip(&ctx, &mut client_handle).await;
    }
    assert_active_quorums_resolve(&ctx, &client_handle).await;

    client_handle.stop().await;
}

/// Platform's reads of the tip list against dashd: Unknown before any list,
/// then Active, Inactive and Retired masternodes, an evonode, a voting key
/// shared by two masternodes, service and voting key updates, and a restart.
#[tokio::test]
async fn test_platform_masternode_list_reads() {
    let Some(ctx) = TestContext::new(true).await else {
        return;
    };
    let [revoked, spent, moved, revoted] = &ctx.mn_ctx.metadata.masternodes[..] else {
        panic!("the regtest network has four masternodes");
    };
    let wallet = create_dummy_wallet();
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);
    let mut client_handle = create_client(&config, Arc::clone(&wallet)).await;
    let client = client_handle.client.clone();

    let chain_locks = Network::Regtest.chain_locks_type();
    let quorum: QuorumHash = rpc(&ctx, "quorum", &[json!("list")])[chain_locks.params().name][0]
        .as_str()
        .expect("a quorum")
        .parse()
        .expect("quorum hash");
    let dashd_tip = ctx.mn_ctx.controller.get_block_count();
    let lookup = platform_quorum_public_key(
        &client,
        chain_locks as u8 as u32,
        quorum.reverse().to_byte_array(),
        dashd_tip,
    )
    .await;
    assert!(lookup.is_err_and(|e| e.contains("Quorum not found")), "no key before any list");
    assert_eq!(platform_validity_snapshot(&client).await, None, "Unknown before any list");
    assert!(platform_list_entries(&client).await.is_none());
    assert!(platform_masternodes_by_voting_key(&client, voting_key_id(&revoked.voting_address))
        .await
        .is_empty());

    sync(&ctx, &mut client_handle).await;
    assert_tip_list_matches_dashd(&ctx, &client).await;

    let evonode = register_evonode(&ctx, &revoked.voting_address);
    mine_and_follow(&ctx, &mut client_handle, 1).await;
    assert_tip_list_matches_dashd(&ctx, &client).await;

    rpc(
        &ctx,
        "protx",
        &[json!("revoke"), json!(revoked.pro_tx_hash), json!(revoked.bls_private_key)],
    );
    spend_collateral(&ctx, &spent.pro_tx_hash);
    rpc(
        &ctx,
        "protx",
        &[
            json!("update_service"),
            json!(moved.pro_tx_hash),
            json!("127.0.0.1:29995"),
            json!(moved.bls_private_key),
        ],
    );
    let new_voting_address = ctx.mn_ctx.controller.get_new_address().to_string();
    rpc(
        &ctx,
        "protx",
        &[
            json!("update_registrar"),
            json!(revoted.pro_tx_hash),
            json!(""),
            json!(new_voting_address),
            json!(""),
        ],
    );
    mine_and_follow(&ctx, &mut client_handle, 1).await;
    assert_tip_list_matches_dashd(&ctx, &client).await;

    let validity = platform_validity_snapshot(&client).await.expect("a tip list");
    assert_eq!(validity.get(&pro_tx_bytes(&revoked.pro_tx_hash)), Some(&false), "Inactive");
    assert_eq!(validity.get(&pro_tx_bytes(&spent.pro_tx_hash)), None, "Retired");
    assert_eq!(validity.get(&evonode), Some(&true), "Active evonode");
    let shared_voting_key = voting_key_id(&revoked.voting_address);
    let shared = platform_masternodes_by_voting_key(&client, shared_voting_key).await;
    assert_eq!(shared.len(), 2, "a voting key shared by two masternodes");
    let old_voting_key = voting_key_id(&revoted.voting_address);
    assert!(platform_masternodes_by_voting_key(&client, old_voting_key).await.is_empty());

    client_handle.stop().await;
    drop((client, client_handle));

    let mut client_handle = create_client(&config, wallet).await;
    sync(&ctx, &mut client_handle).await;
    assert_tip_list_matches_dashd(&ctx, &client_handle.client).await;

    client_handle.stop().await;
}
