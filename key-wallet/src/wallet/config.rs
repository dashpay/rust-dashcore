//! Wallet configuration
//!
//! This module defines the configuration options for wallets.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet configuration
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct WalletConfig {
    /// Default external gap limit for accounts
    pub account_default_external_gap_limit: u32,
    /// Default external amount of addresses generated when hitting gap limit
    /// This is the amount of addresses past the gap limit
    pub account_default_external_address_generation_count: u32,
    /// Default internal gap limit for accounts
    pub account_default_internal_gap_limit: u32,
    /// Default internal amount of addresses generated when hitting gap limit
    /// This is the amount of addresses past the gap limit
    pub account_default_internal_address_generation_count: u32,
    /// Enable CoinJoin by default
    pub enable_coinjoin: bool,
    /// CoinJoin default gap limit
    pub coinjoin_default_gap_limit: u32,
    /// Default coinjoin amount of addresses generated when hitting gap limit
    /// This is the amount of addresses past the gap limit
    pub coinjoin_default_address_generation_count: u32,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            account_default_external_gap_limit: 20,
            account_default_external_address_generation_count: 20,
            account_default_internal_gap_limit: 10,
            account_default_internal_address_generation_count: 10,
            enable_coinjoin: false,
            coinjoin_default_gap_limit: 10,
            coinjoin_default_address_generation_count: 10,
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
        self.account_default_external_gap_limit = limit;
        self
    }

    /// Set the internal gap limit
    pub fn with_internal_gap_limit(mut self, limit: u32) -> Self {
        self.account_default_internal_gap_limit = limit;
        self
    }

    /// Set both gap limits
    pub fn with_gap_limits(mut self, external: u32, internal: u32) -> Self {
        self.account_default_external_gap_limit = external;
        self.account_default_internal_gap_limit = internal;
        self
    }

    /// Set the external address generation count
    pub fn with_external_address_generation_count(mut self, count: u32) -> Self {
        self.account_default_external_address_generation_count = count;
        self
    }

    /// Set the internal address generation count
    pub fn with_internal_address_generation_count(mut self, count: u32) -> Self {
        self.account_default_internal_address_generation_count = count;
        self
    }

    /// Set both address generation counts
    pub fn with_address_generation_counts(mut self, external: u32, internal: u32) -> Self {
        self.account_default_external_address_generation_count = external;
        self.account_default_internal_address_generation_count = internal;
        self
    }

    /// Enable CoinJoin with specified gap limit
    pub fn with_coinjoin(mut self, gap_limit: u32) -> Self {
        self.enable_coinjoin = true;
        self.coinjoin_default_gap_limit = gap_limit;
        self
    }

    /// Set the CoinJoin address generation count
    pub fn with_coinjoin_address_generation_count(mut self, count: u32) -> Self {
        self.coinjoin_default_address_generation_count = count;
        self
    }

    /// Disable CoinJoin
    pub fn without_coinjoin(mut self) -> Self {
        self.enable_coinjoin = false;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if self.account_default_external_gap_limit == 0 {
            return Err(crate::error::Error::InvalidParameter(
                "External gap limit must be at least 1".into(),
            ));
        }
        if self.account_default_internal_gap_limit == 0 {
            return Err(crate::error::Error::InvalidParameter(
                "Internal gap limit must be at least 1".into(),
            ));
        }
        if self.enable_coinjoin && self.coinjoin_default_gap_limit == 0 {
            return Err(crate::error::Error::InvalidParameter(
                "CoinJoin gap limit must be at least 1 when CoinJoin is enabled".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WalletConfig::default();
        assert_eq!(config.account_default_external_gap_limit, 20);
        assert_eq!(config.account_default_external_address_generation_count, 20);
        assert_eq!(config.account_default_internal_gap_limit, 10);
        assert_eq!(config.account_default_internal_address_generation_count, 10);
        assert!(!config.enable_coinjoin);
        assert_eq!(config.coinjoin_default_gap_limit, 10);
        assert_eq!(config.coinjoin_default_address_generation_count, 10);
    }

    #[test]
    fn test_config_builder() {
        let config = WalletConfig::new().with_gap_limits(30, 15).with_coinjoin(5);

        assert_eq!(config.account_default_external_gap_limit, 30);
        assert_eq!(config.account_default_internal_gap_limit, 15);
        assert!(config.enable_coinjoin);
        assert_eq!(config.coinjoin_default_gap_limit, 5);
    }

    #[test]
    fn test_config_validation() {
        let mut config = WalletConfig::default();
        assert!(config.validate().is_ok());

        config.account_default_external_gap_limit = 0;
        assert!(config.validate().is_err());

        config.account_default_external_gap_limit = 20;
        config.account_default_internal_gap_limit = 0;
        assert!(config.validate().is_err());

        config.account_default_internal_gap_limit = 10;
        config.enable_coinjoin = true;
        config.coinjoin_default_gap_limit = 0;
        assert!(config.validate().is_err());
    }
}
