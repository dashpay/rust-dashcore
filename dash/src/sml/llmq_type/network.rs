use crate::Network;
use crate::sml::llmq_type::{
    LLMQType, devnet_chain_locks_type_override, devnet_isd_type_override,
    devnet_platform_type_override,
};

/// Extension trait for Network to add LLMQ-specific methods
pub trait NetworkLLMQExt {
    fn isd_llmq_type(&self) -> LLMQType;
    fn chain_locks_type(&self) -> LLMQType;
    fn platform_type(&self) -> LLMQType;
    fn enabled_llmq_types(&self) -> Vec<LLMQType>;
    fn should_skip_quorum_type(&self, llmq_type: &LLMQType, height: u32) -> bool;
}

impl NetworkLLMQExt for Network {
    fn isd_llmq_type(&self) -> LLMQType {
        match self {
            Network::Mainnet => LLMQType::Llmqtype60_75,
            Network::Testnet => LLMQType::Llmqtype60_75,
            Network::Devnet => {
                devnet_isd_type_override().unwrap_or(LLMQType::LlmqtypeDevnetDIP0024)
            }
            Network::Regtest => LLMQType::LlmqtypeTestDIP0024,
        }
    }

    fn chain_locks_type(&self) -> LLMQType {
        match self {
            Network::Mainnet => LLMQType::Llmqtype400_60,
            Network::Testnet => LLMQType::Llmqtype50_60,
            Network::Devnet => {
                devnet_chain_locks_type_override().unwrap_or(LLMQType::LlmqtypeDevnet)
            }
            Network::Regtest => LLMQType::LlmqtypeTest,
        }
    }

    fn platform_type(&self) -> LLMQType {
        match self {
            Network::Mainnet => LLMQType::Llmqtype100_67,
            Network::Testnet => LLMQType::Llmqtype25_67,
            Network::Devnet => {
                devnet_platform_type_override().unwrap_or(LLMQType::LlmqtypeDevnetPlatform)
            }
            Network::Regtest => LLMQType::LlmqtypeTestnetPlatform,
        }
    }

    /// Get all enabled LLMQ types for this network
    fn enabled_llmq_types(&self) -> Vec<LLMQType> {
        match self {
            Network::Mainnet => vec![
                LLMQType::Llmqtype50_60,  // InstantSend
                LLMQType::Llmqtype60_75,  // InstantSend DIP24 (rotating)
                LLMQType::Llmqtype400_60, // ChainLocks
                LLMQType::Llmqtype400_85, // Platform/Evolution
                LLMQType::Llmqtype100_67, // Platform consensus
            ],
            Network::Testnet => vec![
                LLMQType::Llmqtype50_60, // InstantSend & ChainLocks on testnet
                LLMQType::Llmqtype60_75, // InstantSend DIP24 (rotating)
                // Note: 400_60 and 400_85 are included but may not mine on testnet
                LLMQType::Llmqtype25_67, // Platform consensus (smaller for testnet)
            ],
            Network::Devnet => vec![
                LLMQType::Llmqtype50_60,
                LLMQType::Llmqtype60_75,
                LLMQType::Llmqtype400_60,
                LLMQType::Llmqtype400_85,
                LLMQType::Llmqtype100_67,
                LLMQType::LlmqtypeDevnet,
                LLMQType::LlmqtypeDevnetDIP0024,
                LLMQType::LlmqtypeDevnetPlatform,
            ],
            Network::Regtest => vec![
                LLMQType::LlmqtypeTest,
                LLMQType::LlmqtypeTestDIP0024,
                LLMQType::LlmqtypeTestInstantSend,
            ],
        }
    }

    /// Check if a quorum type should be skipped at the given height
    fn should_skip_quorum_type(&self, llmq_type: &LLMQType, height: u32) -> bool {
        match (self, llmq_type) {
            (Network::Mainnet, LLMQType::Llmqtype100_67) => height < 1_888_888, // Platform activation on mainnet
            (Network::Testnet, LLMQType::Llmqtype25_67) => height < 1_289_520, // Platform activation on testnet
            // Retired once DIP24 quorums took over InstantSend (Core's
            // `DIP0024QuorumsHeight`); its last quorums stay in the list.
            (Network::Mainnet, LLMQType::Llmqtype50_60) => height >= 1_738_698,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enabled_llmq_types_mainnet() {
        let network = Network::Mainnet;
        let types = network.enabled_llmq_types();

        assert!(types.contains(&LLMQType::Llmqtype50_60));
        assert!(types.contains(&LLMQType::Llmqtype60_75));
        assert!(types.contains(&LLMQType::Llmqtype400_60));
        assert!(types.contains(&LLMQType::Llmqtype400_85));
        assert!(types.contains(&LLMQType::Llmqtype100_67));
        assert_eq!(types.len(), 5);
    }

    #[test]
    fn test_should_skip_platform_quorum() {
        let network = Network::Mainnet;

        // Platform quorum should be skipped before activation height
        assert!(network.should_skip_quorum_type(&LLMQType::Llmqtype100_67, 1_888_887));
        assert!(!network.should_skip_quorum_type(&LLMQType::Llmqtype100_67, 1_888_888));
        assert!(!network.should_skip_quorum_type(&LLMQType::Llmqtype100_67, 1_888_889));

        // Other quorums should not be skipped
        assert!(!network.should_skip_quorum_type(&LLMQType::Llmqtype400_60, 1_888_887));
    }

    #[test]
    fn test_should_skip_the_retired_instant_send_quorum() {
        assert!(!Network::Mainnet.should_skip_quorum_type(&LLMQType::Llmqtype50_60, 1_738_697));
        assert!(Network::Mainnet.should_skip_quorum_type(&LLMQType::Llmqtype50_60, 1_738_698));
        // Testnet keeps it for ChainLocks.
        assert!(!Network::Testnet.should_skip_quorum_type(&LLMQType::Llmqtype50_60, 1_738_698));
    }
}
