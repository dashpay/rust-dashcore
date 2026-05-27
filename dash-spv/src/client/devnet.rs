//! Devnet-only configuration knobs that mirror Dash Core's `-devnet=<name>`,
//! `-llmqdevnetparams`, and the three `-llmq{chainlocks,instantsenddip0024,platform}`
//! routing flags. Grouped into a single struct so the cross-field invariant
//! "presence iff `Network::Devnet`" is expressible at the `ClientConfig` level.

use dashcore::sml::llmq_type::{
    set_devnet_chain_locks_type, set_devnet_isd_type, set_devnet_platform_type,
    set_llmq_devnet_params, LLMQType, LlmqDevnetParams,
};

/// Configuration values that only apply on `Network::Devnet`.
///
/// The `name` field is required because Dash Core embeds the devnet name into
/// both the genesis-block discovery and the peer-handshake user agent. Without
/// a name the SPV client cannot complete a devnet handshake against `dashd`.
/// Dash Core itself technically accepts `-devnet` with no name (defaulting the
/// network name to `"devnet"`), but every real devnet is launched with one.
#[derive(Debug, Clone)]
pub struct DevnetConfig {
    /// Devnet name. Embedded in the user agent suffix
    /// (`devnet.devnet-<name>`) so peers gating on the name accept us.
    pub name: String,
    /// Override for `LLMQ_DEVNET` quorum size and threshold.
    /// Mirrors Dash Core's `-llmqdevnetparams=<size>:<threshold>`.
    pub llmq_params: Option<LlmqDevnetParams>,
    /// Reroute ChainLocks onto a different devnet LLMQ type.
    /// Mirrors Dash Core's `-llmqchainlocks=<quorum name>`.
    pub llmq_chainlocks_type: Option<LLMQType>,
    /// Reroute InstantSend DIP24 locks onto a different devnet LLMQ type.
    /// Mirrors Dash Core's `-llmqinstantsenddip0024=<quorum name>`.
    pub llmq_instantsend_dip0024_type: Option<LLMQType>,
    /// Reroute Platform quorums onto a different devnet LLMQ type.
    /// Mirrors Dash Core's `-llmqplatform=<quorum name>`.
    pub llmq_platform_type: Option<LLMQType>,
}

impl DevnetConfig {
    /// Create a new devnet config with no overrides.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            llmq_params: None,
            llmq_chainlocks_type: None,
            llmq_instantsend_dip0024_type: None,
            llmq_platform_type: None,
        }
    }

    /// Set `LLMQ_DEVNET` size and threshold override.
    pub fn with_llmq_params(mut self, params: LlmqDevnetParams) -> Self {
        self.llmq_params = Some(params);
        self
    }

    /// Set the ChainLocks LLMQ routing override.
    pub fn with_chainlocks_type(mut self, llmq_type: LLMQType) -> Self {
        self.llmq_chainlocks_type = Some(llmq_type);
        self
    }

    /// Set the InstantSend DIP24 LLMQ routing override.
    pub fn with_instantsend_dip0024_type(mut self, llmq_type: LLMQType) -> Self {
        self.llmq_instantsend_dip0024_type = Some(llmq_type);
        self
    }

    /// Set the Platform LLMQ routing override.
    pub fn with_platform_type(mut self, llmq_type: LLMQType) -> Self {
        self.llmq_platform_type = Some(llmq_type);
        self
    }

    /// Render the user agent suffix that signals devnet identity to peers,
    /// matching the format `dashd` itself uses: `/<base>(devnet.devnet-<name>)/`.
    pub fn user_agent(&self, crate_version: &str) -> String {
        format!("/rust-dash-spv:{}(devnet.devnet-{})/", crate_version, self.name)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("devnet name must not be empty".to_string());
        }
        if self.name.contains('/') {
            return Err("devnet name must not contain '/'".to_string());
        }
        Ok(())
    }

    /// Apply the four `dashcore` process-global overrides. Idempotent for
    /// identical values, errors on conflicting re-set or invalid type.
    pub(crate) fn apply_global_overrides(&self) -> Result<(), String> {
        if let Some(params) = self.llmq_params {
            set_llmq_devnet_params(params).map_err(|e| e.to_string())?;
        }
        if let Some(t) = self.llmq_chainlocks_type {
            set_devnet_chain_locks_type(t)?;
        }
        if let Some(t) = self.llmq_instantsend_dip0024_type {
            set_devnet_isd_type(t)?;
        }
        if let Some(t) = self.llmq_platform_type {
            set_devnet_platform_type(t)?;
        }
        Ok(())
    }
}
