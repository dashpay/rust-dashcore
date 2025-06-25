//! Shared utility functions for bloom filter operations

use dashcore::OutPoint;
use dashcore::Script;

/// Extract pubkey hash from P2PKH script
pub fn extract_pubkey_hash(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if bytes.len() == 25 
        && bytes[0] == 0x76  // OP_DUP
        && bytes[1] == 0xa9  // OP_HASH160
        && bytes[2] == 0x14  // Push 20 bytes
        && bytes[23] == 0x88 // OP_EQUALVERIFY
        && bytes[24] == 0xac // OP_CHECKSIG
    {
        Some(bytes[3..23].to_vec())
    } else {
        None
    }
}

/// Convert outpoint to bytes for bloom filter
pub fn outpoint_to_bytes(outpoint: &OutPoint) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&outpoint.txid[..]);
    bytes.extend_from_slice(&outpoint.vout.to_le_bytes());
    bytes
}