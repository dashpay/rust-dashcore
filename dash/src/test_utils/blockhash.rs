use crate::BlockHash;
use dashcore_hashes::Hash;

impl BlockHash {
    /// Create a deterministic test block hash from a u32 identifier
    pub fn dummy(id: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&id.to_le_bytes());
        BlockHash::from_byte_array(bytes)
    }
}
