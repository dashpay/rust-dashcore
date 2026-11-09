//! `gettxoutsetinfo` results recorded from Dash Core v24.0.0 and from a Dash Core with
//! `hash_serialized_3`, on the same regtest chain (`tests/data/gettxoutsetinfo/README.md`).

use dashcore_rpc_json::GetTxOutSetInfoResult;
use dashcore_rpc_json::dashcore::hashes::Hash;
use serde_json::Value;

macro_rules! fixture {
    ($version:literal, $name:literal) => {
        include_str!(concat!("data/gettxoutsetinfo/", $version, "/", $name, ".json"))
    };
}

fn parse(json: &str) -> GetTxOutSetInfoResult {
    serde_json::from_str(json).expect("a recorded gettxoutsetinfo result parses")
}

/// The hex string `field` holds in the recorded `json`.
fn recorded_hex(json: &str, field: &str) -> String {
    let value: Value = serde_json::from_str(json).unwrap();
    value[field].as_str().unwrap().to_owned()
}

/// Dash Core prints a hash as its `uint256` with the bytes reversed (`GetHex`), so the hash
/// holds the recorded bytes in reverse and prints back the recorded hex.
fn assert_core_order<H: Hash<Bytes = [u8; 32]> + std::fmt::Display>(hash: H, hex: &str) {
    assert_eq!(hash.to_string(), hex);
    let mut bytes: [u8; 32] = hex_conservative::decode_to_array(hex).unwrap();
    bytes.reverse();
    assert_eq!(hash.to_byte_array(), bytes);
}

#[test]
fn v24_default_reports_hash_serialized_2() {
    let json = fixture!("v24.0.0", "default");
    let info = parse(json);
    let hash = info.hash_serialized_2.expect("v24.0.0 defaults to hash_serialized_2");
    assert_core_order(hash, &recorded_hex(json, "hash_serialized_2"));
    assert_eq!(info.hash_serialized_3, None);
    assert_eq!(info.muhash, None);
    assert_eq!(info.transactions, Some(110));
    assert_eq!(info.disk_size, Some(0));
}

#[test]
fn hash_serialized_3_default_reports_hash_serialized_3() {
    let json = fixture!("pr8067", "default");
    let info = parse(json);
    let hash = info.hash_serialized_3.expect("the default is hash_serialized_3");
    assert_core_order(hash, &recorded_hex(json, "hash_serialized_3"));
    assert_eq!(info.hash_serialized_2, None);
    assert_eq!(info.muhash, None);
    assert_eq!(info.transactions, Some(110));
    assert_eq!(info.disk_size, Some(0));
}

#[test]
fn hash_serialized_2_and_3_differ_for_the_same_set() {
    let v2 = parse(fixture!("v24.0.0", "default"));
    let v3 = parse(fixture!("pr8067", "default"));
    assert_eq!((v2.height, v2.best_block), (v3.height, v3.best_block));
    assert_eq!((v2.tx_outs, v2.total_amount), (v3.tx_outs, v3.total_amount));
    assert_ne!(
        v2.hash_serialized_2.unwrap().to_byte_array(),
        v3.hash_serialized_3.unwrap().to_byte_array()
    );
}

#[test]
fn muhash_is_the_same_on_both_versions() {
    let jsons = [fixture!("v24.0.0", "muhash"), fixture!("pr8067", "muhash")];
    let [v24, v3] = jsons.map(|json| {
        let info = parse(json);
        let muhash = info.muhash.expect("muhash was asked for");
        assert_core_order(muhash, &recorded_hex(json, "muhash"));
        assert_eq!(info.hash_serialized_2, None);
        assert_eq!(info.hash_serialized_3, None);
        // Answered from the coinstatsindex.
        assert_eq!((info.transactions, info.disk_size), (None, None));
        info
    });
    assert_eq!(v24, v3);
}

#[test]
fn hash_type_none_reports_no_hash() {
    for json in [fixture!("v24.0.0", "none"), fixture!("pr8067", "none")] {
        let info = parse(json);
        assert_eq!(info.hash_serialized_2, None);
        assert_eq!(info.hash_serialized_3, None);
        assert_eq!(info.muhash, None);
    }
}
