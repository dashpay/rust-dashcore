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
    
    /// Current ChainLock tip.
    pub chainlock_tip: Option<BlockHash>,
    
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
            chainlock_tip: None,
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
            .field("chainlock_tip", &self.chainlock_tip)
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
    /// Watch an address.
    Address(dashcore::Address),
    
    /// Watch a script.
    Script(dashcore::ScriptBuf),
    
    /// Watch an outpoint.
    Outpoint(dashcore::OutPoint),
}

// Custom serialization for WatchItem to handle Address serialization issues
impl Serialize for WatchItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        match self {
            WatchItem::Address(addr) => {
                let mut state = serializer.serialize_struct("WatchItem", 2)?;
                state.serialize_field("type", "Address")?;
                state.serialize_field("value", &addr.to_string())?;
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
                        Ok(WatchItem::Address(addr))
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
        
        deserializer.deserialize_struct("WatchItem", &["type", "value"], WatchItemVisitor)
    }
}

/// Statistics about the SPV client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpvStats {
    /// Number of headers downloaded.
    pub headers_downloaded: u64,
    
    /// Number of filter headers downloaded.
    pub filter_headers_downloaded: u64,
    
    /// Number of filters downloaded.
    pub filters_downloaded: u64,
    
    /// Number of filter matches found.
    pub filter_matches: u64,
    
    /// Number of full blocks requested.
    pub blocks_requested: u64,
    
    /// Number of masternode diffs processed.
    pub masternode_diffs_processed: u64,
    
    /// Total bytes received.
    pub bytes_received: u64,
    
    /// Total bytes sent.
    pub bytes_sent: u64,
    
    /// Connection uptime.
    pub uptime: std::time::Duration,
}