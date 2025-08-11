//! Wallet configuration
//!
//! This module defines the configuration options for wallets.

use serde::{Deserialize, Serialize};

/// Wallet configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct WalletConfig {
    /// Default external gap limit
    pub external_gap_limit: u32,
    /// Default internal gap limit
    pub internal_gap_limit: u32,
    /// Enable CoinJoin by default
    pub enable_coinjoin: bool,
    /// CoinJoin gap limit
    pub coinjoin_gap_limit: u32,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            external_gap_limit: 20,
            internal_gap_limit: 10,
            enable_coinjoin: false,
            coinjoin_gap_limit: 10,
        }
    }
}

impl WalletConfig {
    /// Create a new wallet configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the external gap limit
    pub fn with_external_gap_limit(mut self, limit: u32) -> Self {
        self.external_gap_limit = limit;
        self
    }

    /// Set the internal gap limit
    pub fn with_internal_gap_limit(mut self, limit: u32) -> Self {
        self.internal_gap_limit = limit;
        self
    }

    /// Set both gap limits
    pub fn with_gap_limits(mut self, external: u32, internal: u32) -> Self {
        self.external_gap_limit = external;
        self.internal_gap_limit = internal;
        self
    }

    /// Enable CoinJoin with specified gap limit
    pub fn with_coinjoin(mut self, gap_limit: u32) -> Self {
        self.enable_coinjoin = true;
        self.coinjoin_gap_limit = gap_limit;
        self
    }

    /// Disable CoinJoin
    pub fn without_coinjoin(mut self) -> Self {
        self.enable_coinjoin = false;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if self.external_gap_limit == 0 {
            return Err(crate::error::Error::InvalidParameter(
                "External gap limit must be at least 1".into(),
            ));
        }
        if self.internal_gap_limit == 0 {
            return Err(crate::error::Error::InvalidParameter(
                "Internal gap limit must be at least 1".into(),
            ));
        }
        if self.enable_coinjoin && self.coinjoin_gap_limit == 0 {
            return Err(crate::error::Error::InvalidParameter(
                "CoinJoin gap limit must be at least 1 when CoinJoin is enabled".into(),
            ));
        }
        Ok(())
    }

    /// Ensure minimum gap limits (used internally)
    pub(crate) fn ensure_minimum_limits(&mut self) {
        if self.external_gap_limit == 0 {
            self.external_gap_limit = 1;
        }
        if self.internal_gap_limit == 0 {
            self.internal_gap_limit = 1;
        }
        if self.coinjoin_gap_limit == 0 {
            self.coinjoin_gap_limit = 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WalletConfig::default();
        assert_eq!(config.external_gap_limit, 20);
        assert_eq!(config.internal_gap_limit, 10);
        assert!(!config.enable_coinjoin);
        assert_eq!(config.coinjoin_gap_limit, 10);
    }

    #[test]
    fn test_config_builder() {
        let config = WalletConfig::new().with_gap_limits(30, 15).with_coinjoin(5);

        assert_eq!(config.external_gap_limit, 30);
        assert_eq!(config.internal_gap_limit, 15);
        assert!(config.enable_coinjoin);
        assert_eq!(config.coinjoin_gap_limit, 5);
    }

    #[test]
    fn test_config_validation() {
        let mut config = WalletConfig::default();
        assert!(config.validate().is_ok());

        config.external_gap_limit = 0;
        assert!(config.validate().is_err());

        config.external_gap_limit = 20;
        config.internal_gap_limit = 0;
        assert!(config.validate().is_err());

        config.internal_gap_limit = 10;
        config.enable_coinjoin = true;
        config.coinjoin_gap_limit = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ensure_minimum_limits() {
        let mut config = WalletConfig {
            external_gap_limit: 0,
            internal_gap_limit: 0,
            enable_coinjoin: true,
            coinjoin_gap_limit: 0,
        };

        config.ensure_minimum_limits();

        assert_eq!(config.external_gap_limit, 1);
        assert_eq!(config.internal_gap_limit, 1);
        assert_eq!(config.coinjoin_gap_limit, 1);
    }
}
