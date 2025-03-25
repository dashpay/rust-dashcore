use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;

use hashes::Hash;

use crate::bls_sig_utils::BLSSignature;
use crate::consensus::encode::VarInt;
use crate::consensus::Encodable;
use crate::hash_types::QuorumModifierHash;
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_type::LLMQType;
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::{BlockHash, Network};

pub enum LLMQModifierType {
    PreCoreV20(LLMQType, BlockHash),
    CoreV20(LLMQType, CoreBlockHeight, BLSSignature),
}

impl fmt::Display for LLMQModifierType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LLMQModifierType::PreCoreV20(llmq_type, block_hash) => {
                write!(f, "PreCoreV20: Type: {}, BlockHash: {}", llmq_type, block_hash)
            }
            LLMQModifierType::CoreV20(llmq_type, height, signature) => {
                write!(
                    f,
                    "CoreV20: Type: {}, Height: {}, Signature: {}",
                    llmq_type, height, signature
                )
            }
        }
    }
}

impl LLMQModifierType {
    /// Constructs a unique quorum modifier hash.
    ///
    /// This function builds a hash that uniquely identifies a quorum based on its type and relevant
    /// contextual information (block hash or height and chain lock signature).
    ///
    /// # Returns
    ///
    /// * `QuorumModifierHash` - The computed hash representing the quorum modifier.
    ///
    /// # Notes
    ///
    /// * For pre-Core v20 quorums, the hash consists of:
    ///   - LLMQ type (encoded as a `VarInt`).
    ///   - Block hash (as raw bytes).
    /// * For Core v20+ quorums, the hash consists of:
    ///   - LLMQ type (encoded as a `VarInt`).
    ///   - Block height.
    ///   - Chain lock signature (as raw bytes).
    pub fn build_llmq_hash(&self) -> QuorumModifierHash {
        let mut writer = vec![];

        match self {
            LLMQModifierType::PreCoreV20(llmq_type, block_hash) => {
                // Encode LLMQ type as VarInt
                VarInt(*llmq_type as u64).consensus_encode(&mut writer).unwrap();
                // Encode block hash as raw bytes
                writer.write_all(&block_hash.to_byte_array()).unwrap();
            }
            LLMQModifierType::CoreV20(llmq_type, block_height, cl_signature) => {
                // Encode LLMQ type as VarInt
                VarInt(*llmq_type as u64).consensus_encode(&mut writer).unwrap();
                // Encode block height
                block_height.consensus_encode(&mut writer).unwrap();
                // Encode the signature
                writer.write_all(cl_signature.as_bytes()).unwrap();
            }
        }
        QuorumModifierHash::hash(&writer)
    }

    /// Creates a new `LLMQModifierType` based on the network activation rules.
    ///
    /// This function determines whether the quorum modifier should be based on a block hash (pre-Core v20)
    /// or a chain lock signature (Core v20+), depending on the network state at a given block height.
    ///
    /// # Arguments
    ///
    /// * `llmq_type` - The type of LLMQ being processed.
    /// * `work_block_hash` - The block hash of the work block.
    /// * `work_block_height` - The height of the work block.
    /// * `known_chain_locks` - A map of known chain lock signatures indexed by block hash.
    /// * `network` - The current network configuration.
    ///
    /// # Returns
    ///
    /// * `Ok(LLMQModifierType::CoreV20)` - If Core v20 is active at the given height, using a chain lock signature.
    /// * `Ok(LLMQModifierType::PreCoreV20)` - If Core v20 is not active, using a block hash.
    /// * `Err(QuorumValidationError::RequiredChainLockNotPresent)` - If Core v20 is active but no chain lock signature is found.
    ///
    /// # Notes
    ///
    /// * Core v20 introduces the use of chain lock signatures instead of block hashes for quorum modifiers.
    /// * This function checks if Core v20 is active at the given block height before selecting the appropriate modifier type.
    pub fn new_quorum_modifier_type(
        llmq_type: LLMQType,
        work_block_hash: BlockHash,
        work_block_height: CoreBlockHeight,
        best_cl_signature: BLSSignature,
        network: Network,
    ) -> Result<LLMQModifierType, QuorumValidationError> {
        if network.core_v20_is_active_at(work_block_height) {
            Ok(LLMQModifierType::CoreV20(llmq_type, work_block_height, best_cl_signature))
        } else {
            Ok(LLMQModifierType::PreCoreV20(llmq_type, work_block_hash))
        }
    }
}
