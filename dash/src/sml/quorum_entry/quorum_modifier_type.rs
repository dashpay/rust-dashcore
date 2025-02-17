use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use hashes::Hash;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::hash_types::QuorumModifierHash;
use crate::{BlockHash, Network};
use crate::bls_sig_utils::BLSSignature;
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_type::LLMQType;
use crate::sml::quorum_validation_error::QuorumValidationError;

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
                write!(f, "CoreV20: Type: {}, Height: {}, Signature: {}", llmq_type, height, signature)
            }
        }
    }
}

impl LLMQModifierType {
    pub fn build_llmq_hash(&self) -> QuorumModifierHash {
        let mut writer = vec![];

        match self {
            LLMQModifierType::PreCoreV20(llmq_type, block_hash) => {
                // Encode LLMQ type as VarInt
                VarInt(*llmq_type as u64).consensus_encode(&mut writer).unwrap();
                // Encode block hash as raw bytes
                writer.write_all(&block_hash.to_byte_array()).unwrap();
            },
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

    pub fn new_quorum_modifier_type(llmq_type: LLMQType, work_block_hash: BlockHash, work_block_height: CoreBlockHeight, known_chain_locks: &BTreeMap<BlockHash, BLSSignature>, network: Network) -> Result<LLMQModifierType, QuorumValidationError> {
        if network.core_v20_is_active_at(work_block_height) {
            let best_cl_signature = known_chain_locks.get(&work_block_hash).ok_or(QuorumValidationError::RequiredChainLockNotPresent(work_block_height, work_block_hash))?;
            Ok(LLMQModifierType::CoreV20(llmq_type, work_block_height, *best_cl_signature))
        } else {
            Ok(LLMQModifierType::PreCoreV20(llmq_type, work_block_hash))
        }
    }
}
