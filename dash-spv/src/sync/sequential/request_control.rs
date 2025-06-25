//! Request control and phase validation for sequential sync

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use dashcore::network::constants::NetworkExt;
use dashcore::network::message::NetworkMessage;
use dashcore::BlockHash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;

use super::phases::SyncPhase;

// Phase name constants - must match the phase names from SyncPhase::name()
pub const PHASE_DOWNLOADING_HEADERS: &str = "Downloading Headers";
pub const PHASE_DOWNLOADING_MNLIST: &str = "Downloading Masternode Lists";
pub const PHASE_DOWNLOADING_CFHEADERS: &str = "Downloading Filter Headers";
pub const PHASE_DOWNLOADING_FILTERS: &str = "Downloading Filters";
pub const PHASE_DOWNLOADING_BLOCKS: &str = "Downloading Blocks";

/// Types of sync requests
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestType {
    GetHeaders(Option<BlockHash>),
    GetMnListDiff(u32),
    GetCFHeaders(u32, BlockHash),
    GetCFilters(u32, BlockHash),
    GetBlock(BlockHash),
}

/// A network request with metadata
#[derive(Debug, Clone)]
pub struct NetworkRequest {
    pub request_type: RequestType,
    pub queued_at: Instant,
    pub retry_count: u32,
}

/// Active request tracking
#[derive(Debug)]
pub struct ActiveRequest {
    pub request: NetworkRequest,
    pub sent_at: Instant,
}

/// Controls request sending based on current phase
pub struct RequestController {
    /// Configuration
    config: ClientConfig,

    /// Queue of pending requests
    pending_requests: VecDeque<NetworkRequest>,

    /// Currently active requests
    active_requests: HashMap<RequestType, ActiveRequest>,

    /// Maximum concurrent requests per phase
    max_concurrent_requests: HashMap<String, usize>,

    /// Request rate limits (requests per second)
    rate_limits: HashMap<String, f64>,

    /// Last request times for rate limiting
    last_request_times: HashMap<String, Instant>,
}

impl RequestController {
    /// Create a new request controller
    pub fn new(config: &ClientConfig) -> Self {
        let mut max_concurrent_requests = HashMap::new();
        max_concurrent_requests.insert(PHASE_DOWNLOADING_HEADERS.to_string(), config.max_concurrent_headers_requests.unwrap_or(1));
        max_concurrent_requests.insert(PHASE_DOWNLOADING_MNLIST.to_string(), config.max_concurrent_mnlist_requests.unwrap_or(1));
        max_concurrent_requests.insert(PHASE_DOWNLOADING_CFHEADERS.to_string(), config.max_concurrent_cfheaders_requests.unwrap_or(1));
        max_concurrent_requests.insert(PHASE_DOWNLOADING_FILTERS.to_string(), config.max_concurrent_filter_requests);
        max_concurrent_requests.insert(PHASE_DOWNLOADING_BLOCKS.to_string(), config.max_concurrent_block_requests.unwrap_or(5));

        let mut rate_limits = HashMap::new();
        rate_limits.insert(PHASE_DOWNLOADING_HEADERS.to_string(), config.headers_request_rate_limit.unwrap_or(10.0));
        rate_limits.insert(PHASE_DOWNLOADING_MNLIST.to_string(), config.mnlist_request_rate_limit.unwrap_or(5.0));
        rate_limits.insert(PHASE_DOWNLOADING_CFHEADERS.to_string(), config.cfheaders_request_rate_limit.unwrap_or(10.0));
        rate_limits.insert(PHASE_DOWNLOADING_FILTERS.to_string(), config.filters_request_rate_limit.unwrap_or(50.0));
        rate_limits.insert(PHASE_DOWNLOADING_BLOCKS.to_string(), config.blocks_request_rate_limit.unwrap_or(10.0));

        Self {
            config: config.clone(),
            pending_requests: VecDeque::new(),
            active_requests: HashMap::new(),
            max_concurrent_requests,
            rate_limits,
            last_request_times: HashMap::new(),
        }
    }

    /// Check if a request type is allowed in the current phase
    pub fn is_request_allowed(&self, phase: &SyncPhase, request_type: &RequestType) -> bool {
        match (phase, request_type) {
            (SyncPhase::DownloadingHeaders { .. }, RequestType::GetHeaders(_)) => true,
            (SyncPhase::DownloadingMnList { .. }, RequestType::GetMnListDiff(_)) => true,
            (SyncPhase::DownloadingCFHeaders { .. }, RequestType::GetCFHeaders(_, _)) => true,
            (SyncPhase::DownloadingFilters { .. }, RequestType::GetCFilters(_, _)) => true,
            (SyncPhase::DownloadingBlocks { .. }, RequestType::GetBlock(_)) => true,
            _ => false,
        }
    }

    /// Queue a request for sending
    pub fn queue_request(
        &mut self,
        phase: &SyncPhase,
        request_type: RequestType,
    ) -> SyncResult<()> {
        if !self.is_request_allowed(phase, &request_type) {
            return Err(SyncError::SyncFailed(format!(
                "Request type {:?} not allowed in phase {}",
                request_type,
                phase.name()
            )));
        }

        self.pending_requests.push_back(NetworkRequest {
            request_type,
            queued_at: Instant::now(),
            retry_count: 0,
        });

        Ok(())
    }

    /// Process pending requests based on rate limits and concurrency
    pub async fn process_pending_requests(
        &mut self,
        phase: &SyncPhase,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
    ) -> SyncResult<()> {
        let phase_name = phase.name().to_string();
        let max_concurrent = self
            .max_concurrent_requests
            .get(&phase_name)
            .copied()
            .unwrap_or(1);

        // Count active requests for this phase
        let active_count = self
            .active_requests
            .values()
            .filter(|ar| self.request_phase(&ar.request.request_type) == phase_name)
            .count();

        // Process pending requests up to the limit
        while active_count < max_concurrent && !self.pending_requests.is_empty() {
            // Check rate limit
            if !self.check_rate_limit(&phase_name) {
                break;
            }

            // Get next request
            if let Some(request) = self.pending_requests.pop_front() {
                // Validate it's still allowed
                if !self.is_request_allowed(phase, &request.request_type) {
                    continue;
                }

                // Send the request
                self.send_request(request, network, storage).await?;
            }
        }

        Ok(())
    }

    /// Send a request to the network
    async fn send_request(
        &mut self,
        request: NetworkRequest,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
    ) -> SyncResult<()> {
        let message = match &request.request_type {
            RequestType::GetHeaders(locator) => {
                let getheaders = dashcore::network::message_blockdata::GetHeadersMessage {
                    version: 70214,
                    locator_hashes: locator.map(|h| vec![h]).unwrap_or_default(),
                    stop_hash: BlockHash::from([0; 32]),
                };
                NetworkMessage::GetHeaders(getheaders)
            }

            RequestType::GetMnListDiff(height) => {
                // Get the base block hash - either genesis or from a terminal block
                let base_block_hash = if *height == 0 {
                    // Genesis block
                    self.config
                        .network
                        .known_genesis_block_hash()
                        .ok_or_else(|| SyncError::Network("No genesis hash for network".to_string()))?
                } else {
                    // For non-genesis, we need to determine the base height
                    // This logic should match what the masternode sync manager does
                    let base_height = 0; // For now, always use genesis as base
                    if base_height == 0 {
                        self.config
                            .network
                            .known_genesis_block_hash()
                            .ok_or_else(|| SyncError::Network("No genesis hash for network".to_string()))?
                    } else {
                        storage
                            .get_header(base_height)
                            .await
                            .map_err(|e| SyncError::SyncFailed(format!("Failed to get base header: {}", e)))?
                            .ok_or_else(|| SyncError::SyncFailed("Base header not found".to_string()))?
                            .block_hash()
                    }
                };

                // Get the target block hash at the requested height
                let block_hash = storage
                    .get_header(*height)
                    .await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get header at height {}: {}", height, e)))?
                    .ok_or_else(|| SyncError::SyncFailed(format!("Header not found at height {}", height)))?
                    .block_hash();

                let getmnlistdiff = dashcore::network::message_sml::GetMnListDiff {
                    base_block_hash,
                    block_hash,
                };
                NetworkMessage::GetMnListD(getmnlistdiff)
            }

            RequestType::GetCFHeaders(start_height, stop_hash) => {
                let getcfheaders = dashcore::network::message_filter::GetCFHeaders {
                    filter_type: 0, // Basic filter
                    start_height: *start_height,
                    stop_hash: *stop_hash,
                };
                NetworkMessage::GetCFHeaders(getcfheaders)
            }

            RequestType::GetCFilters(start_height, stop_hash) => {
                let getcfilters = dashcore::network::message_filter::GetCFilters {
                    filter_type: 0, // Basic filter
                    start_height: *start_height,
                    stop_hash: *stop_hash,
                };
                NetworkMessage::GetCFilters(getcfilters)
            }

            RequestType::GetBlock(hash) => {
                let inv = dashcore::network::message_blockdata::Inventory::Block(*hash);
                let getdata = dashcore::network::message::NetworkMessage::GetData(vec![inv]);
                getdata
            }
        };

        // Send to network
        network
            .send_message(message)
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send request: {}", e)))?;

        // Track as active
        let request_type = request.request_type.clone();
        self.active_requests.insert(
            request_type.clone(),
            ActiveRequest {
                request,
                sent_at: Instant::now(),
            },
        );

        // Update rate limit tracking
        let phase_name = self.request_phase(&request_type);
        self.last_request_times
            .insert(phase_name.clone(), Instant::now());

        Ok(())
    }

    /// Check if we can send a request based on rate limits
    fn check_rate_limit(&self, phase_name: &str) -> bool {
        if let Some(rate_limit) = self.rate_limits.get(phase_name) {
            if let Some(last_time) = self.last_request_times.get(phase_name) {
                let elapsed = last_time.elapsed().as_secs_f64();
                let min_interval = 1.0 / rate_limit;
                return elapsed >= min_interval;
            }
        }
        true
    }

    /// Get the phase name for a request type
    fn request_phase(&self, request_type: &RequestType) -> String {
        match request_type {
            RequestType::GetHeaders(_) => PHASE_DOWNLOADING_HEADERS,
            RequestType::GetMnListDiff(_) => PHASE_DOWNLOADING_MNLIST,
            RequestType::GetCFHeaders(_, _) => PHASE_DOWNLOADING_CFHEADERS,
            RequestType::GetCFilters(_, _) => PHASE_DOWNLOADING_FILTERS,
            RequestType::GetBlock(_) => PHASE_DOWNLOADING_BLOCKS,
        }
        .to_string()
    }

    /// Mark a request as completed
    pub fn complete_request(&mut self, request_type: &RequestType) {
        self.active_requests.remove(request_type);
    }

    /// Get statistics about pending and active requests
    pub fn get_stats(&self) -> RequestStats {
        let mut stats = RequestStats::default();
        stats.pending_count = self.pending_requests.len();
        stats.active_count = self.active_requests.len();

        // Count by type
        for request in &self.pending_requests {
            match &request.request_type {
                RequestType::GetHeaders(_) => stats.pending_headers += 1,
                RequestType::GetMnListDiff(_) => stats.pending_mnlist += 1,
                RequestType::GetCFHeaders(_, _) => stats.pending_cfheaders += 1,
                RequestType::GetCFilters(_, _) => stats.pending_filters += 1,
                RequestType::GetBlock(_) => stats.pending_blocks += 1,
            }
        }

        for (_, active) in &self.active_requests {
            match &active.request.request_type {
                RequestType::GetHeaders(_) => stats.active_headers += 1,
                RequestType::GetMnListDiff(_) => stats.active_mnlist += 1,
                RequestType::GetCFHeaders(_, _) => stats.active_cfheaders += 1,
                RequestType::GetCFilters(_, _) => stats.active_filters += 1,
                RequestType::GetBlock(_) => stats.active_blocks += 1,
            }
        }

        stats
    }

    /// Clear all pending requests (used on phase transition)
    pub fn clear_pending_requests(&mut self) {
        self.pending_requests.clear();
    }

    /// Check for timed out requests
    pub fn check_timeouts(&mut self, timeout_duration: std::time::Duration) -> Vec<RequestType> {
        let mut timed_out = Vec::new();
        let now = Instant::now();

        self.active_requests.retain(|request_type, active| {
            if now.duration_since(active.sent_at) > timeout_duration {
                timed_out.push(request_type.clone());
                false
            } else {
                true
            }
        });

        timed_out
    }
}

/// Statistics about request queues
#[derive(Debug, Default)]
pub struct RequestStats {
    pub pending_count: usize,
    pub active_count: usize,
    pub pending_headers: usize,
    pub pending_mnlist: usize,
    pub pending_cfheaders: usize,
    pub pending_filters: usize,
    pub pending_blocks: usize,
    pub active_headers: usize,
    pub active_mnlist: usize,
    pub active_cfheaders: usize,
    pub active_filters: usize,
    pub active_blocks: usize,
}