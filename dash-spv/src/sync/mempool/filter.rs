//! Bloom filter builder for wallet addresses and outpoints.
//!
//! Builds BIP37 bloom filters from wallet data for peer-side transaction filtering.

use dashcore::address::Payload;
use dashcore::bloom::BloomFilter;
use dashcore::consensus::Encodable;
use dashcore::network::message_bloom::{BloomFlags, FilterLoad};
use dashcore::{Address, OutPoint};

use crate::error::{SyncError, SyncResult};

/// Extract the raw hash payload bytes from an address for bloom filter insertion.
fn address_payload_bytes(addr: &Address) -> Option<Vec<u8>> {
    match addr.payload() {
        Payload::PubkeyHash(hash) => Some(<[u8; 20]>::from(*hash).to_vec()),
        Payload::ScriptHash(hash) => Some(<[u8; 20]>::from(*hash).to_vec()),
        _ => {
            tracing::warn!("skipping unknown address type for bloom filter: {:?}", addr);
            None
        }
    }
}

/// Build a bloom filter from wallet addresses and outpoints.
///
/// Addresses are inserted as their raw hash payload bytes (20-byte hash160
/// for P2PKH/P2SH). This matches what Dash Core's `CheckScript` extracts as
/// data pushes from scriptPubKeys.
///
/// Outpoints are inserted as consensus-serialized bytes (`txid || vout_le`)
/// to detect transactions spending our UTXOs.
pub(super) fn build_wallet_bloom_filter(
    addresses: &[Address],
    outpoints: &[OutPoint],
    false_positive_rate: f64,
    tweak: u32,
) -> SyncResult<FilterLoad> {
    let element_count = addresses.len() + outpoints.len();
    if element_count == 0 {
        let filter = BloomFilter::new(1, false_positive_rate, tweak, BloomFlags::All)
            .map_err(|e| SyncError::Validation(e.to_string()))?;
        return Ok(FilterLoad::from_bloom_filter(&filter));
    }

    let mut filter =
        BloomFilter::new(element_count as u32, false_positive_rate, tweak, BloomFlags::All)
            .map_err(|e| SyncError::Validation(e.to_string()))?;

    for addr in addresses {
        if let Some(payload) = address_payload_bytes(addr) {
            filter.insert(&payload);
        }
    }

    for outpoint in outpoints {
        let mut buf = Vec::new();
        outpoint.consensus_encode(&mut buf).map_err(|e| SyncError::Validation(e.to_string()))?;
        filter.insert(&buf);
    }

    Ok(FilterLoad::from_bloom_filter(&filter))
}

#[cfg(test)]
mod tests {
    use std::slice;

    use super::*;
    use crate::sync::mempool::BLOOM_FALSE_POSITIVE_RATE;
    use dashcore::hashes::Hash;
    use dashcore::{Network, Txid};

    fn test_addr(seed: usize) -> Address {
        Address::dummy(Network::Testnet, seed)
    }

    fn test_outpoint(seed: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([seed; 32]),
            vout,
        }
    }

    fn outpoint_bytes(outpoint: &OutPoint) -> Vec<u8> {
        let mut buf = Vec::new();
        outpoint.consensus_encode(&mut buf).unwrap();
        buf
    }

    fn build_filter(addrs: &[Address], outpoints: &[OutPoint]) -> FilterLoad {
        build_wallet_bloom_filter(addrs, outpoints, BLOOM_FALSE_POSITIVE_RATE, 0).unwrap()
    }

    #[test]
    fn test_address_membership() {
        let addr = test_addr(0);
        let other = test_addr(1);
        let filter = build_filter(slice::from_ref(&addr), &[]).to_bloom_filter().unwrap();

        assert!(filter.contains(&address_payload_bytes(&addr).unwrap()));
        assert!(!filter.contains(&address_payload_bytes(&other).unwrap()));
    }

    #[test]
    fn test_outpoint_membership() {
        let outpoint = test_outpoint(1, 0);
        let filter = build_filter(&[], &[outpoint]).to_bloom_filter().unwrap();

        assert!(filter.contains(&outpoint_bytes(&outpoint)));
    }

    #[test]
    fn test_empty_inputs() {
        let filter = build_filter(&[], &[]).to_bloom_filter().unwrap();
        assert!(!filter.contains(&[1, 2, 3]));
    }

    fn test_p2sh_addr(seed: u8) -> Address {
        // Build OP_HASH160 <20-byte-hash> OP_EQUAL script, then wrap as P2SH
        let redeem_script = dashcore::ScriptBuf::from(vec![seed; 20]);
        Address::p2sh(&redeem_script, Network::Testnet).unwrap()
    }

    #[test]
    fn test_p2sh_address_membership() {
        let addr = test_p2sh_addr(0x42);
        let other = test_p2sh_addr(0x43);
        let filter = build_filter(slice::from_ref(&addr), &[]).to_bloom_filter().unwrap();

        assert!(filter.contains(&address_payload_bytes(&addr).unwrap()));
        assert!(!filter.contains(&address_payload_bytes(&other).unwrap()));
    }

    #[test]
    fn test_combined_addresses_and_outpoints() {
        let addr1 = test_addr(0);
        let addr2 = test_p2sh_addr(0x10);
        let op1 = test_outpoint(1, 0);
        let op2 = test_outpoint(2, 1);

        let filter =
            build_filter(&[addr1.clone(), addr2.clone()], &[op1, op2]).to_bloom_filter().unwrap();

        assert!(filter.contains(&address_payload_bytes(&addr1).unwrap()));
        assert!(filter.contains(&address_payload_bytes(&addr2).unwrap()));
        assert!(filter.contains(&outpoint_bytes(&op1)));
        assert!(filter.contains(&outpoint_bytes(&op2)));

        // Random data should not match
        assert!(!filter.contains(&[0xff; 20]));
    }

    #[test]
    fn test_rejects_invalid_fp_rates() {
        let addr = test_addr(0);
        let addrs = slice::from_ref(&addr);

        for rate in [0.0, -0.5, 1.0, 1.5] {
            assert!(build_wallet_bloom_filter(addrs, &[], rate, 0).is_err());
        }
    }
}
