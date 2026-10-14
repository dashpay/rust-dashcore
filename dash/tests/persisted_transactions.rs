//! Hosts persist `Transaction` with `bincode::serde` and `bincode` (Dash Platform's wallet store
//! does), and both encode `TransactionPayload` by the index of its variant. A variant inserted
//! before an existing one shifts that variant's index, and everything stored with it stops
//! decoding.
//!
//! `data/persisted_transactions.txt` holds transactions encoded before rust-dashcore#1156, one or
//! more per payload variant that existed then. They must keep decoding to the transaction their
//! consensus bytes hold, and re-encode to the same bytes.
#![cfg(all(feature = "serde", feature = "bincode"))]

use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::special_transaction::provider_dissolve::ProviderDissolvePayload;
use dashcore::blockdata::transaction::special_transaction::provider_registration::CompactSignature;
use dashcore::blockdata::transaction::special_transaction::provider_update_share::ProviderUpdateSharePayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_shared_registrar::ProviderUpdateSharedRegistrarPayload;
use dashcore::bls_sig_utils::BLSPublicKey;
use dashcore::consensus::deserialize;
use dashcore::hash_types::InputsHash;
use dashcore::hashes::Hash;
use dashcore::{PubkeyHash, ScriptBuf, Transaction, Txid};

const CONFIG: bincode::config::Configuration = bincode::config::standard();

const ROWS: &str = include_str!("data/persisted_transactions.txt");

struct Row {
    name: &'static str,
    variant: &'static str,
    consensus: Vec<u8>,
    serde: Vec<u8>,
    bincode: Vec<u8>,
}

fn rows() -> Vec<Row> {
    ROWS.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let columns: Vec<&str> = line.split(' ').collect();
            let [name, variant, consensus, serde, bincode] = columns[..] else {
                panic!("five columns: {line}");
            };
            let hex = |s: &str| hex_conservative::decode_to_vec(s).expect("hex");
            Row {
                name,
                variant,
                consensus: hex(consensus),
                serde: hex(serde),
                bincode: hex(bincode),
            }
        })
        .collect()
}

/// The variant index each payload is stored under. New variants go at the end; an existing
/// index never changes.
fn stored_index(payload: &TransactionPayload) -> u8 {
    match payload {
        TransactionPayload::ProviderRegistrationPayloadType(_) => 0,
        TransactionPayload::ProviderUpdateServicePayloadType(_) => 1,
        TransactionPayload::ProviderUpdateRegistrarPayloadType(_) => 2,
        TransactionPayload::ProviderUpdateRevocationPayloadType(_) => 3,
        TransactionPayload::CoinbasePayloadType(_) => 4,
        TransactionPayload::QuorumCommitmentPayloadType(_) => 5,
        TransactionPayload::MnhfSignalPayloadType(_) => 6,
        TransactionPayload::AssetLockPayloadType(_) => 7,
        TransactionPayload::AssetUnlockPayloadType(_) => 8,
        TransactionPayload::ClassicalWithNonStandardVersionTypeBytesPayloadType(_) => 9,
        TransactionPayload::RawPayloadType(..) => 10,
        TransactionPayload::ProviderDissolvePayloadType(_) => 11,
        TransactionPayload::ProviderUpdateSharePayloadType(_) => 12,
        TransactionPayload::ProviderUpdateSharedRegistrarPayloadType(_) => 13,
    }
}

fn variant_name(payload: &TransactionPayload) -> String {
    let debug = format!("{payload:?}");
    debug.split('(').next().expect("a variant name").to_string()
}

/// One payload of every variant: the stored ones, then those added by rust-dashcore#1156.
fn one_payload_per_variant() -> Vec<TransactionPayload> {
    let mut payloads: Vec<TransactionPayload> = Vec::new();
    for row in rows() {
        let tx: Transaction = deserialize(&row.consensus).expect("consensus bytes");
        let payload = tx.special_transaction_payload.expect("a payload");
        if !payloads.iter().any(|p| stored_index(p) == stored_index(&payload)) {
            payloads.push(payload);
        }
    }
    let signatures = vec![CompactSignature::from([1; 65])];
    payloads.push(TransactionPayload::ProviderDissolvePayloadType(ProviderDissolvePayload {
        version: 1,
        pro_tx_hash: Txid::all_zeros(),
        actor_index: 0,
        signatures: signatures.clone(),
    }));
    payloads.push(TransactionPayload::ProviderUpdateSharePayloadType(ProviderUpdateSharePayload {
        version: 1,
        pro_tx_hash: Txid::all_zeros(),
        share_index: 0,
        script_reward: ScriptBuf::new(),
        inputs_hash: InputsHash::all_zeros(),
        payload_sig: vec![1; 65],
    }));
    payloads.push(TransactionPayload::ProviderUpdateSharedRegistrarPayloadType(
        ProviderUpdateSharedRegistrarPayload {
            version: 1,
            pro_tx_hash: Txid::all_zeros(),
            operator_public_key: BLSPublicKey::from([1; 48]),
            voting_key_hash: PubkeyHash::all_zeros(),
            inputs_hash: InputsHash::all_zeros(),
            signatures,
        },
    ));
    payloads
}

#[test]
fn should_encode_every_payload_variant_under_its_stored_index() {
    let payloads = one_payload_per_variant();
    let mut indexes: Vec<u8> = payloads.iter().map(stored_index).collect();
    indexes.sort_unstable();
    assert_eq!(indexes, (0..=13).collect::<Vec<u8>>(), "one payload per variant");

    for payload in &payloads {
        let name = variant_name(payload);
        // bincode's standard configuration writes a variant index below 251 as one byte.
        let serde = bincode::serde::encode_to_vec(payload, CONFIG).expect("serde encoding");
        assert_eq!(serde[0], stored_index(payload), "{name} under bincode::serde");
        let native = bincode::encode_to_vec(payload, CONFIG).expect("bincode encoding");
        assert_eq!(native[0], stored_index(payload), "{name} under bincode");
    }
}

#[test]
fn should_decode_and_re_encode_transactions_stored_before_new_payload_types_unchanged() {
    let rows = rows();
    assert!(!rows.is_empty());
    for row in rows {
        let name = row.name;
        let expected: Transaction = deserialize(&row.consensus).expect("consensus bytes");
        let payload = expected.special_transaction_payload.as_ref().expect("a payload");
        assert_eq!(variant_name(payload), row.variant, "{name}");

        let (from_serde, read): (Transaction, usize) =
            bincode::serde::decode_from_slice(&row.serde, CONFIG)
                .unwrap_or_else(|e| panic!("{name}: bincode::serde: {e}"));
        assert_eq!(read, row.serde.len(), "{name}: bincode::serde reads every byte");
        assert_eq!(from_serde, expected, "{name}: bincode::serde");
        assert_eq!(
            bincode::serde::encode_to_vec(&from_serde, CONFIG).unwrap(),
            row.serde,
            "{name}: bincode::serde re-encodes differently"
        );

        let (from_bincode, read): (Transaction, usize) =
            bincode::decode_from_slice(&row.bincode, CONFIG)
                .unwrap_or_else(|e| panic!("{name}: bincode: {e}"));
        assert_eq!(read, row.bincode.len(), "{name}: bincode reads every byte");
        assert_eq!(from_bincode, expected, "{name}: bincode");
        assert_eq!(
            bincode::encode_to_vec(&from_bincode, CONFIG).unwrap(),
            row.bincode,
            "{name}: bincode re-encodes differently"
        );
    }
}
