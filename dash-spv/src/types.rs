//! Common type definitions for the Dash SPV client.

use std::time::SystemTime;

use dashcore::{
    block::Header as BlockHeader,
    hash_types::FilterHeader,
    sml::masternode_list_engine::MasternodeListEngine,
    BlockHash, Network,
};
use serde::{Deserialize, Serialize};

/// Sync progress information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncProgress {
    /// Current height of synchronized headers.
    pub header_height: u32,
    
    /// Current height of synchronized filter headers.
    pub filter_header_height: u32,
    
    /// Current height of synchronized masternode list.
    pub masternode_height: u32,
    
    /// Total number of peers connected.
    pub peer_count: u32,
    
    /// Whether header sync is complete.
    pub headers_synced: bool,
    
    /// Whether filter headers sync is complete.
    pub filter_headers_synced: bool,
    
    /// Whether masternode list is synced.
    pub masternodes_synced: bool,
    
    /// Number of compact filters downloaded.
    pub filters_downloaded: u64,
    
    /// Last height where filters were synced/verified.
    pub last_synced_filter_height: Option<u32>,
    
    /// Sync start time.
    pub sync_start: SystemTime,
    
    /// Last update time.
    pub last_update: SystemTime,
}

impl Default for SyncProgress {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            header_height: 0,
            filter_header_height: 0,
            masternode_height: 0,
            peer_count: 0,
            headers_synced: false,
            filter_headers_synced: false,
            masternodes_synced: false,
            filters_downloaded: 0,
            last_synced_filter_height: None,
            sync_start: now,
            last_update: now,
        }
    }
}

/// Chain state maintained by the SPV client.
#[derive(Clone)]
pub struct ChainState {
    /// Block headers indexed by height.
    pub headers: Vec<BlockHeader>,
    
    /// Filter headers indexed by height.
    pub filter_headers: Vec<FilterHeader>,
    
    /// Last ChainLock height.
    pub last_chainlock_height: Option<u32>,
    
    /// Last ChainLock hash.
    pub last_chainlock_hash: Option<BlockHash>,
    
    /// Current filter tip.
    pub current_filter_tip: Option<FilterHeader>,
    
    /// Masternode list engine.
    pub masternode_engine: Option<MasternodeListEngine>,
    
    /// Last masternode diff height processed.
    pub last_masternode_diff_height: Option<u32>,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            filter_headers: Vec::new(),
            last_chainlock_height: None,
            last_chainlock_hash: None,
            current_filter_tip: None,
            masternode_engine: None,
            last_masternode_diff_height: None,
        }
    }
}

impl ChainState {
    /// Create a new chain state for the given network.
    pub fn new_for_network(network: Network) -> Self {
        let mut state = Self::default();
        
        // Initialize masternode engine for the network
        let mut engine = MasternodeListEngine::default_for_network(network);
        if let Some(genesis_hash) = network.known_genesis_block_hash() {
            engine.feed_block_height(0, genesis_hash);
        }
        state.masternode_engine = Some(engine);
        
        state
    }
    
    /// Get the current tip height.
    pub fn tip_height(&self) -> u32 {
        self.headers.len().saturating_sub(1) as u32
    }
    
    /// Get the current tip hash.
    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.headers.last().map(|h| h.block_hash())
    }
    
    /// Get header at the given height.
    pub fn header_at_height(&self, height: u32) -> Option<&BlockHeader> {
        self.headers.get(height as usize)
    }
    
    /// Get filter header at the given height.
    pub fn filter_header_at_height(&self, height: u32) -> Option<&FilterHeader> {
        self.filter_headers.get(height as usize)
    }
    
    /// Add headers to the chain.
    pub fn add_headers(&mut self, headers: Vec<BlockHeader>) {
        self.headers.extend(headers);
    }
    
    /// Add filter headers to the chain.
    pub fn add_filter_headers(&mut self, filter_headers: Vec<FilterHeader>) {
        if let Some(last) = filter_headers.last() {
            self.current_filter_tip = Some(*last);
        }
        self.filter_headers.extend(filter_headers);
    }
}

impl std::fmt::Debug for ChainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainState")
            .field("headers", &format!("{} headers", self.headers.len()))
            .field("filter_headers", &format!("{} filter headers", self.filter_headers.len()))
            .field("last_chainlock_height", &self.last_chainlock_height)
            .field("last_chainlock_hash", &self.last_chainlock_hash)
            .field("current_filter_tip", &self.current_filter_tip)
            .field("last_masternode_diff_height", &self.last_masternode_diff_height)
            .finish()
    }
}

/// Validation mode for the SPV client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationMode {
    /// Validate only basic structure and signatures.
    Basic,
    
    /// Validate proof of work and chain rules.
    Full,
    
    /// Skip most validation (useful for testing).
    None,
}

impl Default for ValidationMode {
    fn default() -> Self {
        Self::Full
    }
}

/// Peer information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer address.
    pub address: std::net::SocketAddr,
    
    /// Connection state.
    pub connected: bool,
    
    /// Last seen time.
    pub last_seen: SystemTime,
    
    /// Peer version.
    pub version: Option<u32>,
    
    /// Peer services.
    pub services: Option<u64>,
    
    /// User agent.
    pub user_agent: Option<String>,
    
    /// Best height reported by peer.
    pub best_height: Option<i32>,
}

/// Filter match result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterMatch {
    /// Block hash where match was found.
    pub block_hash: BlockHash,
    
    /// Block height.
    pub height: u32,
    
    /// Whether we requested the full block.
    pub block_requested: bool,
}

/// Watch item for monitoring the blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WatchItem {
    /// Watch an address with optional earliest height.
    Address {
        address: dashcore::Address,
        earliest_height: Option<u32>,
    },
    
    /// Watch a script.
    Script(dashcore::ScriptBuf),
    
    /// Watch an outpoint.
    Outpoint(dashcore::OutPoint),
}

impl WatchItem {
    /// Create a new address watch item without earliest height restriction.
    pub fn address(address: dashcore::Address) -> Self {
        Self::Address {
            address,
            earliest_height: None,
        }
    }
    
    /// Create a new address watch item with earliest height restriction.
    pub fn address_from_height(address: dashcore::Address, earliest_height: u32) -> Self {
        Self::Address {
            address,
            earliest_height: Some(earliest_height),
        }
    }
    
    /// Get the earliest height for this watch item.
    pub fn earliest_height(&self) -> Option<u32> {
        match self {
            WatchItem::Address { earliest_height, .. } => *earliest_height,
            _ => None,
        }
    }
}

// Custom serialization for WatchItem to handle Address serialization issues
impl Serialize for WatchItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        match self {
            WatchItem::Address { address, earliest_height } => {
                let mut state = serializer.serialize_struct("WatchItem", 3)?;
                state.serialize_field("type", "Address")?;
                state.serialize_field("value", &address.to_string())?;
                state.serialize_field("earliest_height", earliest_height)?;
                state.end()
            }
            WatchItem::Script(script) => {
                let mut state = serializer.serialize_struct("WatchItem", 2)?;
                state.serialize_field("type", "Script")?;
                state.serialize_field("value", &script.to_hex_string())?;
                state.end()
            }
            WatchItem::Outpoint(outpoint) => {
                let mut state = serializer.serialize_struct("WatchItem", 2)?;
                state.serialize_field("type", "Outpoint")?;
                state.serialize_field("value", &format!("{}:{}", outpoint.txid, outpoint.vout))?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for WatchItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;
        
        struct WatchItemVisitor;
        
        impl<'de> Visitor<'de> for WatchItemVisitor {
            type Value = WatchItem;
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a WatchItem struct")
            }
            
            fn visit_map<M>(self, mut map: M) -> Result<WatchItem, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut item_type: Option<String> = None;
                let mut value: Option<String> = None;
                let mut earliest_height: Option<u32> = None;
                
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            if item_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("type"));
                            }
                            item_type = Some(map.next_value()?);
                        }
                        "value" => {
                            if value.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value = Some(map.next_value()?);
                        }
                        "earliest_height" => {
                            if earliest_height.is_some() {
                                return Err(serde::de::Error::duplicate_field("earliest_height"));
                            }
                            earliest_height = map.next_value()?;
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                
                let item_type = item_type.ok_or_else(|| serde::de::Error::missing_field("type"))?;
                let value = value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                
                match item_type.as_str() {
                    "Address" => {
                        let addr = value.parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>()
                            .map_err(|e| serde::de::Error::custom(format!("Invalid address: {}", e)))?
                            .assume_checked();
                        Ok(WatchItem::Address {
                            address: addr,
                            earliest_height,
                        })
                    }
                    "Script" => {
                        let script = dashcore::ScriptBuf::from_hex(&value)
                            .map_err(|e| serde::de::Error::custom(format!("Invalid script: {}", e)))?;
                        Ok(WatchItem::Script(script))
                    }
                    "Outpoint" => {
                        let parts: Vec<&str> = value.split(':').collect();
                        if parts.len() != 2 {
                            return Err(serde::de::Error::custom("Invalid outpoint format"));
                        }
                        let txid = parts[0].parse()
                            .map_err(|e| serde::de::Error::custom(format!("Invalid txid: {}", e)))?;
                        let vout = parts[1].parse()
                            .map_err(|e| serde::de::Error::custom(format!("Invalid vout: {}", e)))?;
                        Ok(WatchItem::Outpoint(dashcore::OutPoint { txid, vout }))
                    }
                    _ => Err(serde::de::Error::custom(format!("Unknown WatchItem type: {}", item_type)))
                }
            }
        }
        
        deserializer.deserialize_struct("WatchItem", &["type", "value", "earliest_height"], WatchItemVisitor)
    }
}

/// Statistics about the SPV client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpvStats {
    /// Number of headers downloaded.
    pub headers_downloaded: u64,
    
    /// Number of filter headers downloaded.
    pub filter_headers_downloaded: u64,
    
    /// Number of filters downloaded.
    pub filters_downloaded: u64,
    
    /// Number of compact filters that matched watch items.
    pub filters_matched: u64,
    
    /// Number of blocks with relevant transactions (after full block processing).
    pub blocks_with_relevant_transactions: u64,
    
    /// Number of full blocks requested.
    pub blocks_requested: u64,
    
    /// Number of full blocks processed.
    pub blocks_processed: u64,
    
    /// Number of masternode diffs processed.
    pub masternode_diffs_processed: u64,
    
    /// Total bytes received.
    pub bytes_received: u64,
    
    /// Total bytes sent.
    pub bytes_sent: u64,
    
    /// Connection uptime.
    pub uptime: std::time::Duration,
    
    /// Number of filters requested during sync.
    pub filters_requested: u64,
    
    /// Number of filters received during sync.
    pub filters_received: u64,
    
    /// Filter sync start time.
    #[serde(skip)]
    pub filter_sync_start_time: Option<std::time::Instant>,
    
    /// Last time a filter was received.
    #[serde(skip)]
    pub last_filter_received_time: Option<std::time::Instant>,
    
    /// Received filter heights for gap tracking (shared with FilterSyncManager).
    #[serde(skip)]
    pub received_filter_heights: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    
    /// Number of filter requests currently active.
    pub active_filter_requests: u32,
    
    /// Number of filter requests currently queued.
    pub pending_filter_requests: u32,
    
    /// Number of filter request timeouts.
    pub filter_request_timeouts: u64,
    
    /// Number of filter requests retried.
    pub filter_requests_retried: u64,
}

impl Default for SpvStats {
    fn default() -> Self {
        Self {
            headers_downloaded: 0,
            filter_headers_downloaded: 0,
            filters_downloaded: 0,
            filters_matched: 0,
            blocks_with_relevant_transactions: 0,
            blocks_requested: 0,
            blocks_processed: 0,
            masternode_diffs_processed: 0,
            bytes_received: 0,
            bytes_sent: 0,
            uptime: std::time::Duration::default(),
            filters_requested: 0,
            filters_received: 0,
            filter_sync_start_time: None,
            last_filter_received_time: None,
            received_filter_heights: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            active_filter_requests: 0,
            pending_filter_requests: 0,
            filter_request_timeouts: 0,
            filter_requests_retried: 0,
        }
    }
}

/// Balance information for an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBalance {
    /// Confirmed balance (6+ confirmations or InstantLocked).
    pub confirmed: dashcore::Amount,
    
    /// Unconfirmed balance (less than 6 confirmations).
    pub unconfirmed: dashcore::Amount,
}

impl AddressBalance {
    /// Get the total balance (confirmed + unconfirmed).
    pub fn total(&self) -> dashcore::Amount {
        self.confirmed + self.unconfirmed
    }
}

// Custom serialization for AddressBalance to handle Amount serialization
impl Serialize for AddressBalance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("AddressBalance", 2)?;
        state.serialize_field("confirmed", &self.confirmed.to_sat())?;
        state.serialize_field("unconfirmed", &self.unconfirmed.to_sat())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AddressBalance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;
        
        struct AddressBalanceVisitor;
        
        impl<'de> Visitor<'de> for AddressBalanceVisitor {
            type Value = AddressBalance;
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an AddressBalance struct")
            }
            
            fn visit_map<M>(self, mut map: M) -> Result<AddressBalance, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut confirmed: Option<u64> = None;
                let mut unconfirmed: Option<u64> = None;
                
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "confirmed" => {
                            if confirmed.is_some() {
                                return Err(serde::de::Error::duplicate_field("confirmed"));
                            }
                            confirmed = Some(map.next_value()?);
                        }
                        "unconfirmed" => {
                            if unconfirmed.is_some() {
                                return Err(serde::de::Error::duplicate_field("unconfirmed"));
                            }
                            unconfirmed = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                
                let confirmed = confirmed.ok_or_else(|| serde::de::Error::missing_field("confirmed"))?;
                let unconfirmed = unconfirmed.ok_or_else(|| serde::de::Error::missing_field("unconfirmed"))?;
                
                Ok(AddressBalance {
                    confirmed: dashcore::Amount::from_sat(confirmed),
                    unconfirmed: dashcore::Amount::from_sat(unconfirmed),
                })
            }
        }
        
        deserializer.deserialize_struct("AddressBalance", &["confirmed", "unconfirmed"], AddressBalanceVisitor)
    }
}