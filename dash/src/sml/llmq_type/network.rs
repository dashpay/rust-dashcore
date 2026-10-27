use crate::Network;
use crate::sml::llmq_type::{
    DEVNET_REGISTERED_LLMQ_TYPES, LLMQType, devnet_chain_locks_type_override,
    devnet_isd_type_override, devnet_platform_type_override,
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
        match self.chain_params() {
            Some(chain) => chain.consensus.llmq_type_dip0024_instant_send.into(),
            None => devnet_isd_type_override().unwrap_or(LLMQType::LlmqtypeDevnetDIP0024),
        }
    }

    fn chain_locks_type(&self) -> LLMQType {
        match self.chain_params() {
            Some(chain) => chain.consensus.llmq_type_chain_locks.into(),
            None => devnet_chain_locks_type_override().unwrap_or(LLMQType::LlmqtypeDevnet),
        }
    }

    fn platform_type(&self) -> LLMQType {
        match self.chain_params() {
            Some(chain) => chain.consensus.llmq_type_platform.into(),
            None => devnet_platform_type_override().unwrap_or(LLMQType::LlmqtypeDevnetPlatform),
        }
    }

    /// Get all enabled LLMQ types for this network
    fn enabled_llmq_types(&self) -> Vec<LLMQType> {
        match self.chain_params() {
            Some(chain) => chain.consensus.llmqs.iter().copied().map(LLMQType::from).collect(),
            None => DEVNET_REGISTERED_LLMQ_TYPES.to_vec(),
        }
    }

    /// Check if a quorum type should be skipped at the given height
    fn should_skip_quorum_type(&self, llmq_type: &LLMQType, height: u32) -> bool {
        match (self, llmq_type) {
            (Network::Mainnet, LLMQType::Llmqtype100_67) => height < 1_888_888, // Platform activation on mainnet
            (Network::Testnet, LLMQType::Llmqtype25_67) => height < 1_289_520, // Platform activation on testnet
            // DIP24 retires the old InstantSend type unless ChainLocks use it.
            _ => self.chain_params().is_some_and(|chain| {
                let instant_send = match self {
                    Network::Regtest => LLMQType::LlmqtypeTestInstantSend,
                    _ => LLMQType::Llmqtype50_60,
                };
                *llmq_type == instant_send
                    && *llmq_type != self.chain_locks_type()
                    && height >= chain.consensus.dip0024_quorums_height.to_u32()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let quorums_height = |network: Network| {
            network.chain_params().unwrap().consensus.dip0024_quorums_height.to_u32()
        };
        let mainnet = quorums_height(Network::Mainnet);
        assert!(!Network::Mainnet.should_skip_quorum_type(&LLMQType::Llmqtype50_60, mainnet - 1));
        assert!(Network::Mainnet.should_skip_quorum_type(&LLMQType::Llmqtype50_60, mainnet));
        assert!(Network::Regtest.should_skip_quorum_type(
            &LLMQType::LlmqtypeTestInstantSend,
            quorums_height(Network::Regtest)
        ));
        // Testnet keeps it for ChainLocks.
        assert!(
            !Network::Testnet.should_skip_quorum_type(
                &LLMQType::Llmqtype50_60,
                quorums_height(Network::Testnet)
            )
        );
        assert!(!Network::Devnet.should_skip_quorum_type(&LLMQType::Llmqtype50_60, u32::MAX));
    }
}
