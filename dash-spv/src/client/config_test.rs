//! Unit tests for client configuration

#[cfg(test)]
mod tests {
    use crate::client::config::{ClientConfig, MempoolStrategy};
    use crate::client::devnet::DevnetConfig;
    use crate::types::ValidationMode;
    use dashcore::sml::llmq_type::{
        devnet_chain_locks_type_override, devnet_isd_type_override, devnet_platform_type_override,
        llmq_devnet_params, LLMQType, LlmqDevnetParams,
    };
    use dashcore::Network;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();

        assert_eq!(config.network, Network::Mainnet);
        assert!(config.peers.is_empty());
        assert_eq!(config.validation_mode, ValidationMode::Full);
        assert!(config.enable_filters);
        assert!(config.enable_masternodes);
        assert_eq!(config.max_peers, 8);

        // Mempool defaults
        assert!(config.enable_mempool_tracking);
        assert_eq!(config.mempool_strategy, MempoolStrategy::FetchAll);
        assert_eq!(config.max_mempool_transactions, 1000);
        assert!(config.fetch_mempool_transactions);

        assert!(config.devnet.is_none());
    }

    #[test]
    fn test_network_specific_configs() {
        let mainnet = ClientConfig::mainnet();
        assert_eq!(mainnet.network, Network::Mainnet);
        assert!(mainnet.peers.is_empty()); // Should use DNS discovery
        assert!(mainnet.devnet.is_none());

        let testnet = ClientConfig::testnet();
        assert_eq!(testnet.network, Network::Testnet);
        assert!(testnet.peers.is_empty()); // Should use DNS discovery
        assert!(testnet.devnet.is_none());

        let regtest = ClientConfig::regtest();
        assert_eq!(regtest.network, Network::Regtest);
        assert!(regtest.peers.is_empty());
        assert!(regtest.devnet.is_none());
    }

    #[test]
    fn test_builder_pattern() {
        let path = PathBuf::from("/test/storage");

        let config = ClientConfig::mainnet()
            .with_storage_path(path.clone())
            .with_validation_mode(ValidationMode::Basic)
            .with_mempool_tracking(MempoolStrategy::BloomFilter)
            .with_max_mempool_transactions(500)
            .with_start_height(100000);

        assert_eq!(config.storage_path, path);
        assert_eq!(config.validation_mode, ValidationMode::Basic);

        // Mempool settings
        assert!(config.enable_mempool_tracking);
        assert_eq!(config.mempool_strategy, MempoolStrategy::BloomFilter);
        assert_eq!(config.max_mempool_transactions, 500);
        assert_eq!(config.start_from_height, Some(100000));
        assert!(config.devnet.is_none());
    }

    #[test]
    fn test_with_devnet_round_trip() {
        let devnet = DevnetConfig::new("alpha")
            .with_llmq_params(LlmqDevnetParams {
                size: 6,
                threshold: 4,
            })
            .with_chainlocks_type(LLMQType::Llmqtype50_60)
            .with_instantsend_dip0024_type(LLMQType::LlmqtypeDevnetDIP0024)
            .with_platform_type(LLMQType::LlmqtypeDevnetPlatform);

        let config = ClientConfig::new(Network::Devnet).with_devnet(devnet);

        let devnet = config.devnet.as_ref().expect("devnet must be set");
        assert_eq!(devnet.name, "alpha");
        assert_eq!(
            devnet.llmq_params,
            Some(LlmqDevnetParams {
                size: 6,
                threshold: 4
            })
        );
        assert_eq!(devnet.llmq_chainlocks_type, Some(LLMQType::Llmqtype50_60));
        assert_eq!(devnet.llmq_instantsend_dip0024_type, Some(LLMQType::LlmqtypeDevnetDIP0024));
        assert_eq!(devnet.llmq_platform_type, Some(LLMQType::LlmqtypeDevnetPlatform));
    }

    #[test]
    fn test_user_agent_format_matches_dash_core() {
        let devnet = DevnetConfig::new("alpha");
        assert_eq!(devnet.user_agent("0.43.0"), "/rust-dash-spv:0.43.0(devnet.devnet-alpha)/");
    }

    #[test]
    fn test_validate_devnet_matrix() {
        let tmp = TempDir::new().unwrap();
        let networks = [Network::Mainnet, Network::Testnet, Network::Regtest, Network::Devnet];
        for network in networks {
            let want_devnet = network == Network::Devnet;
            for has_devnet in [false, true] {
                let mut config =
                    ClientConfig::new(network).with_storage_path(tmp.path().join("storage"));
                if has_devnet {
                    config = config.with_devnet(DevnetConfig::new("alpha"));
                }
                let result = config.validate();
                if has_devnet == want_devnet {
                    assert!(
                        result.is_ok(),
                        "network={:?} has_devnet={} should be OK, got {:?}",
                        network,
                        has_devnet,
                        result
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "network={:?} has_devnet={} must error",
                        network,
                        has_devnet
                    );
                }
            }
        }
    }

    #[test]
    fn test_validate_rejects_empty_devnet_name() {
        let tmp = TempDir::new().unwrap();
        let config = ClientConfig::new(Network::Devnet)
            .with_storage_path(tmp.path().join("storage"))
            .with_devnet(DevnetConfig::new(""));
        let err = config.validate().expect_err("empty name must be rejected");
        assert!(err.contains("must not be empty"), "got: {}", err);
    }

    #[test]
    fn test_add_peer() {
        let mut config = ClientConfig::default();
        let addr1: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:9999".parse().unwrap();

        config.add_peer(addr1);
        config.add_peer(addr2);

        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.peers[0], addr1);
        assert_eq!(config.peers[1], addr2);
    }

    #[test]
    fn test_disable_features() {
        let config = ClientConfig::default().without_filters().without_masternodes();

        assert!(!config.enable_filters);
        assert!(!config.enable_masternodes);
    }

    #[test]
    fn test_validation_invalid_max_peers() {
        let config = ClientConfig {
            max_peers: 0,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "max_peers must be > 0");
    }

    #[test]
    fn test_validation_invalid_mempool_config() {
        let config = ClientConfig {
            enable_mempool_tracking: true,
            max_mempool_transactions: 0,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_mempool_transactions must be > 0"));
    }

    #[test]
    fn test_apply_global_overrides_no_devnet_is_noop() {
        let tmp = TempDir::new().unwrap();
        let config = ClientConfig::new(Network::Mainnet).with_storage_path(tmp.path());
        assert!(config.apply_global_overrides().is_ok());
    }

    // Each `dashcore` `OnceLock` accepts only one value per process; all four
    // slots are exercised here in one shot.
    #[test]
    fn test_apply_global_overrides_forwards_all_slots() {
        let tmp = TempDir::new().unwrap();
        let devnet = DevnetConfig::new("alpha")
            .with_llmq_params(LlmqDevnetParams {
                size: 11,
                threshold: 7,
            })
            .with_chainlocks_type(LLMQType::Llmqtype100_67)
            .with_instantsend_dip0024_type(LLMQType::Llmqtype60_75)
            .with_platform_type(LLMQType::LlmqtypeDevnet);
        let config =
            ClientConfig::new(Network::Devnet).with_storage_path(tmp.path()).with_devnet(devnet);

        config.apply_global_overrides().expect("forwarding all four overrides must succeed");

        let params = llmq_devnet_params();
        assert_eq!(params.size, 11);
        assert_eq!(params.threshold, 7);
        assert_eq!(devnet_chain_locks_type_override(), Some(LLMQType::Llmqtype100_67));
        assert_eq!(devnet_isd_type_override(), Some(LLMQType::Llmqtype60_75));
        assert_eq!(devnet_platform_type_override(), Some(LLMQType::LlmqtypeDevnet));

        // Re-applying the same config must be idempotent.
        config.apply_global_overrides().expect("idempotent re-apply");
    }
}
