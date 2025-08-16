use crate::sml::llmq_type::{DKGWindow, LLMQType};
use dash_network::Network;
use std::collections::BTreeMap;

/// Extension trait for Network to add LLMQ-specific methods
pub trait NetworkLLMQExt {
    fn is_llmq_type(&self) -> LLMQType;
    fn isd_llmq_type(&self) -> LLMQType;
    fn chain_locks_type(&self) -> LLMQType;
    fn platform_type(&self) -> LLMQType;
    fn enabled_llmq_types(&self) -> Vec<LLMQType>;
    fn get_all_dkg_windows(&self, start: u32, end: u32) -> BTreeMap<u32, Vec<DKGWindow>>;
    fn should_skip_quorum_type(&self, llmq_type: &LLMQType, height: u32) -> bool;
}

impl NetworkLLMQExt for Network {
    fn is_llmq_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype50_60,
            Network::Testnet => LLMQType::Llmqtype50_60,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTestInstantSend,
            other => unreachable!("Unsupported network variant {other:?}"),
        }
    }

    fn isd_llmq_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype60_75,
            Network::Testnet => LLMQType::Llmqtype60_75,
            Network::Devnet => LLMQType::LlmqtypeDevnetDIP0024,
            Network::Regtest => LLMQType::LlmqtypeTestDIP0024,
            other => unreachable!("Unsupported network variant {other:?}"),
        }
    }

    fn chain_locks_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype400_60,
            Network::Testnet => LLMQType::Llmqtype50_60,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTest,
            other => unreachable!("Unsupported network variant {other:?}"),
        }
    }

    fn platform_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype100_67,
            Network::Testnet => LLMQType::Llmqtype25_67,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTest,
            other => unreachable!("Unsupported network variant {other:?}"),
        }
    }

    /// Get all enabled LLMQ types for this network
    fn enabled_llmq_types(&self) -> Vec<LLMQType> {
        match self {
            Network::Dash => vec![
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
                LLMQType::LlmqtypeDevnet,
                LLMQType::LlmqtypeDevnetDIP0024,
                LLMQType::LlmqtypeDevnetPlatform,
            ],
            Network::Regtest => vec![
                LLMQType::LlmqtypeTest,
                LLMQType::LlmqtypeTestDIP0024,
                LLMQType::LlmqtypeTestInstantSend,
            ],
            other => unreachable!("Unsupported network variant {other:?}"),
        }
    }

    /// Get all DKG windows in the given range for all active quorum types
    fn get_all_dkg_windows(&self, start: u32, end: u32) -> BTreeMap<u32, Vec<DKGWindow>> {
        let mut windows_by_height: BTreeMap<u32, Vec<DKGWindow>> = BTreeMap::new();

        log::debug!(
            "get_all_dkg_windows: Calculating DKG windows for range {}-{} on network {:?}",
            start,
            end,
            self
        );

        for llmq_type in self.enabled_llmq_types() {
            let type_windows = llmq_type.get_dkg_windows_in_range(start, end);
            log::debug!(
                "LLMQ type {:?}: found {} DKG windows in range {}-{}",
                llmq_type,
                type_windows.len(),
                start,
                end
            );

            for window in type_windows {
                // Skip platform quorums before activation if needed
                if self.should_skip_quorum_type(&llmq_type, window.mining_start) {
                    log::trace!(
                        "Skipping {:?} for height {} (activation threshold not met)",
                        llmq_type,
                        window.mining_start
                    );
                    continue;
                }

                // Group windows by their mining start for efficient fetching
                windows_by_height.entry(window.mining_start).or_insert_with(Vec::new).push(window);
            }
        }

        log::info!(
            "get_all_dkg_windows: Total {} unique mining heights with DKG windows for range {}-{}",
            windows_by_height.len(),
            start,
            end
        );

        windows_by_height
    }

    /// Check if a quorum type should be skipped at the given height
    fn should_skip_quorum_type(&self, llmq_type: &LLMQType, height: u32) -> bool {
        match (self, llmq_type) {
            (Network::Dash, LLMQType::Llmqtype100_67) => height < 1_888_888, // Platform activation on mainnet
            (Network::Testnet, LLMQType::Llmqtype25_67) => height < 1_289_520, // Platform activation on testnet
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enabled_llmq_types_mainnet() {
        let network = Network::Dash;
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
        let network = Network::Dash;

        // Platform quorum should be skipped before activation height
        assert!(network.should_skip_quorum_type(&LLMQType::Llmqtype100_67, 1_888_887));
        assert!(!network.should_skip_quorum_type(&LLMQType::Llmqtype100_67, 1_888_888));
        assert!(!network.should_skip_quorum_type(&LLMQType::Llmqtype100_67, 1_888_889));

        // Other quorums should not be skipped
        assert!(!network.should_skip_quorum_type(&LLMQType::Llmqtype50_60, 1_888_887));
    }

    #[test]
    fn test_get_all_dkg_windows() {
        let network = Network::Testnet;
        let windows = network.get_all_dkg_windows(100, 200);

        // Should have windows for multiple quorum types
        assert!(!windows.is_empty());

        // Check that windows are grouped by mining start
        for (height, window_list) in &windows {
            assert!(*height >= 100 || window_list.iter().any(|w| w.mining_end >= 100));
            assert!(*height <= 200);
        }
    }
}
