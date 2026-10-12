//! Transactions and blocks produced by Dash Core v24.
//!
//! The vectors in `data/core_v24_devnet/` were mined on a devnet where every node runs
//! Dash Core v24.0.0-rc.3 and V24 activated at height 15000, and fetched through DAPI
//! (`Core/getTransaction` and `Core/getBlock`). Each transaction file hashes (sha256d,
//! reversed) to the txid asserted below, so the bytes are exactly what Core relayed.

use std::net::SocketAddr;
use std::str::FromStr;

use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
use dashcore::blockdata::transaction::special_transaction::provider_registration::{
    MasternodePayoutShare, ProviderMasternodeType, ProviderRegistrationPayload, SharedCollateral,
};
use dashcore::consensus::{deserialize, serialize};
use dashcore::hash_types::MerkleRootAssetUnlocks;
use dashcore::hashes::Hash;
use dashcore::sml::masternode_list_entry::MasternodeNetInfo;
use dashcore::sml::masternode_list_entry::net_info::{ExtNetInfo, NetInfoEntry, NetInfoPurpose};
use dashcore::{Address, Block, Network, PlatformNodeId, ScriptBuf, Transaction, Txid, VarInt};
use test_case::test_case;

const PRO_REG_TX_ONE_PAYOUT: &str =
    include_str!("data/core_v24_devnet/pro_reg_tx_v3_one_payout.hex");
const PRO_REG_TX_TWO_PAYOUTS: &str =
    include_str!("data/core_v24_devnet/pro_reg_tx_v3_two_payouts.hex");
const PRO_REG_TX_P2SH_PAYOUT: &str =
    include_str!("data/core_v24_devnet/pro_reg_tx_v3_p2sh_payout.hex");
const EVO_PRO_UP_SERV_TX: &str = include_str!("data/core_v24_devnet/evo_pro_up_serv_tx_v3.hex");
const PRO_UP_REG_TX: &str = include_str!("data/core_v24_devnet/pro_up_reg_tx_v3.hex");

const PRO_REG_TX_ONE_PAYOUT_TXID: &str =
    "20814c480e94dce7f3fe3f3370ec6bacd1fdc4f446f17aa7de7886be0b5d07c2";
const PRO_REG_TX_TWO_PAYOUTS_TXID: &str =
    "f7e6fad0084ae34e410a8b710e5d74c0af1b95a29c1f3ae5507bed8e08b38adb";
const PRO_REG_TX_P2SH_PAYOUT_TXID: &str =
    "1bff9d395c2647e370202e87c80fa3942930567d217238392363cd2542fb496f";
const EVO_PRO_UP_SERV_TX_TXID: &str =
    "7c58d9776ef31869b8cae3f94366e9fedb914e41a5b4c26d048c12f30f5e51ac";
const PRO_UP_REG_TX_TXID: &str = "16b69f49a4aba21954e199efe7209478763133f7c473fab6668d5d2b79e55775";

/// Payout shares are in basis points: a single payee receives the whole owner reward.
const WHOLE_OWNER_REWARD: u16 = 10_000;

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex_conservative::decode_to_vec(hex.trim()).expect("vector is hex")
}

/// Decodes a transaction Core produced and checks that nothing is lost on the way back: it
/// re-encodes to the same bytes and hashes to the txid Core reported. The payload's `size()`
/// must also match its encoding, since fees are estimated from it.
fn decode_core_tx(hex: &str, txid: &str) -> TransactionPayload {
    let bytes = hex_bytes(hex);
    let tx: Transaction = deserialize(&bytes).expect("Core v24 transaction decodes");
    assert_eq!(serialize(&tx), bytes, "re-encoding changes the transaction bytes");
    assert_eq!(tx.txid(), Txid::from_str(txid).unwrap(), "txid differs from Core's");
    let payload = tx.special_transaction_payload.clone().expect("special transaction payload");
    assert_eq!(payload.size(), serialize(&payload).len(), "payload size() is off");
    payload
}

fn decode_pro_reg_tx(hex: &str, txid: &str) -> ProviderRegistrationPayload {
    let payload = decode_core_tx(hex, txid);
    let payload =
        payload.to_provider_registration_payload().expect("payload decodes as a typed ProRegTx");
    assert_eq!(payload.version, 3);
    assert_eq!(payload.masternode_type, ProviderMasternodeType::Regular);
    // From version 3 the payees live in `payouts` and the legacy payout script stays empty.
    assert!(payload.script_payout.is_empty());
    assert_eq!(payload.platform_node_id, None);
    // These masternodes register without announcing an address and do not share their
    // collateral, so both fields are present but empty.
    assert_eq!(
        payload.service_address,
        MasternodeNetInfo::Extended(ExtNetInfo {
            version: 1,
            purposes: vec![],
        })
    );
    assert_eq!(payload.shared_collateral, Some(SharedCollateral::default()));
    payload
}

fn p2pkh_payout(payout: &MasternodePayoutShare) -> &ScriptBuf {
    assert!(payout.script_payout.is_p2pkh(), "not P2PKH: {:?}", payout.script_payout);
    &payout.script_payout
}

fn devnet_address(script: &ScriptBuf) -> String {
    Address::from_script(script, Network::Devnet).expect("standard script").to_string()
}

#[test]
fn a_pro_reg_tx_v3_pays_the_whole_owner_reward_to_one_payout() {
    let payload = decode_pro_reg_tx(PRO_REG_TX_ONE_PAYOUT, PRO_REG_TX_ONE_PAYOUT_TXID);

    let payouts = payload.payouts.expect("version 3 has payouts");
    assert_eq!(payouts.len(), 1);
    assert_eq!(devnet_address(p2pkh_payout(&payouts[0])), "yQohnoFhM5avKnzVzAX79xT8uCKviaPxj4");
    assert_eq!(payouts[0].reward, WHOLE_OWNER_REWARD);
}

#[test]
fn a_pro_reg_tx_v3_splits_the_owner_reward_between_two_payouts() {
    let payload = decode_pro_reg_tx(PRO_REG_TX_TWO_PAYOUTS, PRO_REG_TX_TWO_PAYOUTS_TXID);

    let payouts = payload.payouts.expect("version 3 has payouts");
    let rewards: Vec<u16> = payouts.iter().map(|payout| payout.reward).collect();
    assert_eq!(rewards, [6000, 4000]);
    assert_ne!(p2pkh_payout(&payouts[0]), p2pkh_payout(&payouts[1]));
}

#[test]
fn a_pro_reg_tx_v3_pays_the_owner_reward_to_a_p2sh_script() {
    let payload = decode_pro_reg_tx(PRO_REG_TX_P2SH_PAYOUT, PRO_REG_TX_P2SH_PAYOUT_TXID);

    let payouts = payload.payouts.expect("version 3 has payouts");
    assert_eq!(payouts.len(), 1);
    assert_eq!(payouts[0].reward, WHOLE_OWNER_REWARD);
    let script = &payouts[0].script_payout;
    assert!(script.is_p2sh(), "not P2SH: {script:?}");
    assert_eq!(devnet_address(script), "8yyRcXHGCXypDWTCNZMHUYZJJEC87GqLfK");
}

#[test]
fn an_evo_pro_up_serv_tx_v3_keeps_its_platform_node_id_and_carries_platform_ports_in_net_info() {
    let payload = decode_core_tx(EVO_PRO_UP_SERV_TX, EVO_PRO_UP_SERV_TX_TXID);
    let payload =
        payload.to_update_service_payload().expect("payload decodes as a typed ProUpServTx");

    assert_eq!(payload.version, 3);
    assert_eq!(payload.mn_type, Some(ProviderMasternodeType::HighPerformance as u16));
    assert_eq!(
        payload.platform_node_id,
        Some(PlatformNodeId::from_str("f958365178aaf234a101db3a34025bdf5f6ed315").unwrap())
    );
    // From version 3 the platform ports are entries of the extended addresses, not fields.
    assert_eq!(payload.platform_p2p_port, None);
    assert_eq!(payload.platform_http_port, None);

    let MasternodeNetInfo::Extended(net_info) = &payload.service_address else {
        panic!("version 3 carries extended addresses, got {:?}", payload.service_address);
    };
    assert_eq!(
        purpose_ports(net_info),
        [
            (NetInfoPurpose::CoreP2P, 20001),
            (NetInfoPurpose::PlatformP2P, 26656),
            (NetInfoPurpose::PlatformHttps, 1443),
        ]
    );
    assert_eq!(
        payload.service_address.primary_service_address(),
        Some(SocketAddr::from(([68, 67, 122, 237], 20001)))
    );
    assert_eq!(net_info.platform_https_port(), Some(1443));
}

/// The port of every service entry in `net_info` with its purpose, in wire order.
fn purpose_ports(net_info: &ExtNetInfo) -> Vec<(NetInfoPurpose, u16)> {
    net_info
        .purposes
        .iter()
        .flat_map(|(purpose, entries)| {
            entries.iter().map(move |entry| match entry {
                NetInfoEntry::Service {
                    port,
                    ..
                } => (*purpose, *port),
                other => panic!("expected a service entry, got {other:?}"),
            })
        })
        .collect()
}

#[test]
fn a_pro_up_reg_tx_v3_replaces_a_masternode_payout_through_the_payouts_list() {
    let payload = decode_core_tx(PRO_UP_REG_TX, PRO_UP_REG_TX_TXID);
    let payload =
        payload.to_update_registrar_payload().expect("payload decodes as a typed ProUpRegTx");

    assert_eq!(payload.version, 3);
    assert!(payload.script_payout.is_empty());
    // It updates the masternode the one-payout ProRegTx vector registered.
    assert_eq!(payload.pro_tx_hash, Txid::from_str(PRO_REG_TX_ONE_PAYOUT_TXID).unwrap());

    // The registration paid yQohnoFhM5avKnzVzAX79xT8uCKviaPxj4; the update moves the whole owner
    // reward to another payee.
    let payouts = payload.payouts.expect("version 3 has payouts");
    assert_eq!(payouts.len(), 1);
    assert_eq!(devnet_address(p2pkh_payout(&payouts[0])), "yT7ShTqEqPBskpTAiHzWaAggFmD4j1MCT3");
    assert_eq!(payouts[0].reward, WHOLE_OWNER_REWARD);
}

/// Every block decodes with no special payload left raw, and re-encodes transaction by
/// transaction to the bytes Core mined, so the merkle root built from the decoded txids matches
/// the header. Its coinbase carries a version 4 CbTx at the block's height, and every block
/// but the activation block carries the transaction vector mined in it, byte for byte.
#[test_case(include_str!("data/core_v24_devnet/block_15000.hex"), 15000, None; "the V24 activation block")]
#[test_case(include_str!("data/core_v24_devnet/block_15146.hex"), 15146, Some(PRO_REG_TX_ONE_PAYOUT); "the block with the one-payout ProRegTx")]
#[test_case(include_str!("data/core_v24_devnet/block_15153.hex"), 15153, Some(PRO_REG_TX_TWO_PAYOUTS); "the block with the two-payout ProRegTx")]
#[test_case(include_str!("data/core_v24_devnet/block_15166.hex"), 15166, Some(PRO_REG_TX_P2SH_PAYOUT); "the block with the P2SH-payout ProRegTx")]
#[test_case(include_str!("data/core_v24_devnet/block_15182.hex"), 15182, Some(EVO_PRO_UP_SERV_TX); "the block with the Evo ProUpServTx")]
#[test_case(include_str!("data/core_v24_devnet/block_15190.hex"), 15190, Some(PRO_UP_REG_TX); "the block with the ProUpRegTx")]
fn a_core_v24_block_decodes_with_every_transaction_byte_identical(
    block_hex: &str,
    height: u32,
    mined_tx_hex: Option<&str>,
) {
    let bytes = hex_bytes(block_hex);
    let block: Block = deserialize(&bytes).expect("Core v24 block decodes");

    let mut offset = serialize(&block.header).len() + VarInt(block.txdata.len() as u64).len();
    for tx in &block.txdata {
        let encoded = serialize(tx);
        assert_eq!(
            bytes.get(offset..offset + encoded.len()),
            Some(encoded.as_slice()),
            "transaction {} re-encodes differently",
            tx.txid()
        );
        offset += encoded.len();
        if let Some(TransactionPayload::RawPayloadType(tx_type, _)) =
            &tx.special_transaction_payload
        {
            panic!("transaction {} kept its type {tx_type} payload raw", tx.txid());
        }
    }
    assert_eq!(offset, bytes.len(), "transactions do not cover the whole block");
    assert_eq!(serialize(&block), bytes);
    assert!(block.check_merkle_root(), "merkle root does not match the decoded txids");

    let coinbase: CoinbasePayload = block
        .coinbase()
        .and_then(|coinbase| coinbase.special_transaction_payload.clone())
        .expect("coinbase has a CbTx payload")
        .to_coinbase_payload()
        .expect("payload decodes as a typed CbTx");
    assert_eq!(coinbase.version, 4);
    assert_eq!(coinbase.height, height);
    // None of these blocks carries an asset unlock, so the root over them is all-zero.
    assert_eq!(coinbase.merkle_root_asset_unlocks, Some(MerkleRootAssetUnlocks::all_zeros()));

    if let Some(mined_tx_hex) = mined_tx_hex {
        let mined_tx = hex_bytes(mined_tx_hex);
        assert!(
            block.txdata.iter().any(|tx| serialize(tx) == mined_tx),
            "block {height} does not carry the transaction vector mined in it"
        );
    }
}
