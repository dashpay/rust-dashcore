⏺ Plan: Engine-Driven Hybrid QRInfo + MnListDiff Integration

  Executive Summary

  This plan integrates the modern engine-driven sync system that strategically uses both QRInfo and MnListDiff based on the masternode list engine's intelligent decision-making. QRInfo handles bulk sync efficiently, while MnListDiff
  fills gaps, handles peer compatibility, and provides fallback capabilities.

  Architecture Understanding

  Hybrid Sync Strategy:

  - Primary: QRInfo for bulk synchronization (5-10x performance gains)
  - Strategic: MnListDiff for gap filling, peer compatibility, and error recovery
  - Engine-Driven: Masternode list engine decides optimal request strategy
  - Intelligent: Request type chosen based on gap size, network conditions, peer capabilities

  ---
  Revised Implementation Plan

  Phase 1: Legacy Code Analysis and Selective Removal

  Duration: 2 days

  1.1 KEEP Strategic MnListDiff Methods

  File: dash-spv/src/sync/masternodes.rs

  ✅ PRESERVE these methods (needed for hybrid approach):
  // Core MnListDiff functionality - needed for fallback/gaps
  ✅ async fn request_masternode_diff()  // Individual diff requests
  ✅ async fn handle_mnlistdiff_message() // Process MnListDiff responses  
  ✅ async fn process_masternode_diff()  // Engine integration
  ✅ NetworkMessage::MnListDiff handling in message routing

  1.2 REMOVE Obsolete Sequential Logic

  File: dash-spv/src/sync/masternodes.rs

  ❌ DELETE these methods (replaced by engine-driven approach):
  // Manual height tracking and sequential logic
  ❌ start_sync_with_height() // Replace with engine-driven entry point
  ❌ request_masternode_diffs_smart() // Replace with engine planning
  ❌ request_masternode_diffs_for_chainlock_validation_with_base() // Replace with discovery
  ❌ All DKG window calculation logic // Engine handles this
  ❌ Terminal block optimization code // Engine discovery supersedes this
  ❌ Manual bulk/smart fetch state management // Engine plans requests
  ❌ All hardcoded height progression logic // Engine discovery driven

  1.3 Clean Configuration

  File: dash-spv/src/client/config.rs

  impl ClientConfig {
      // REMOVE QRInfo enable/disable flags (always enabled when masternodes enabled)
      ❌ pub enable_qr_info: bool,
      ❌ pub qr_info_fallback: bool,  // Always available as strategic fallback

      // KEEP essential tuning parameters
      ✅ pub qr_info_extra_share: bool,     // Performance/validation option
      ✅ pub qr_info_timeout: Duration,     // Network reliability

      // ADD hybrid sync tuning
      ✅ pub qr_info_max_parallel: usize,   // Concurrent QRInfo requests
      ✅ pub mnlist_diff_timeout: Duration, // MnListDiff fallback timeout
  }

  impl Default for ClientConfig {
      fn default() -> Self {
          Self {
              // ... existing fields ...
              qr_info_extra_share: true,
              qr_info_timeout: Duration::from_secs(30),
              qr_info_max_parallel: 3,  // Conservative concurrent requests
              mnlist_diff_timeout: Duration::from_secs(15), // Faster individual requests
          }
      }
  }

  Phase 2: Engine-Driven Sync Integration

  Duration: 3 days

  2.1 Modern Engine-Driven Entry Point

  File: dash-spv/src/sync/masternodes.rs

  impl MasternodeSyncManager {
      /// Modern engine-driven sync that uses both QRInfo and MnListDiff strategically
      pub async fn start_engine_driven_sync(
          &mut self,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
          target_height: u32,
          sync_base_height: u32,
      ) -> SyncResult<bool> {
          if self.sync_in_progress {
              return Err(SyncError::SyncInProgress);
          }

          // Skip if masternodes are disabled
          if !self.config.enable_masternodes || self.engine.is_none() {
              return Ok(false);
          }

          tracing::info!("Starting engine-driven masternode sync to height {} (base: {})",
                        target_height, sync_base_height);

          // Store sync parameters
          self.sync_base_height = sync_base_height;
          self.sync_in_progress = true;
          self.last_sync_progress = std::time::Instant::now();

          // Execute hybrid sync strategy
          self.execute_hybrid_sync_strategy(network, storage, target_height).await
      }

      /// Execute hybrid QRInfo + MnListDiff sync strategy
      async fn execute_hybrid_sync_strategy(
          &mut self,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
          target_height: u32,
      ) -> SyncResult<bool> {
          // Phase 1: Engine-driven discovery
          let sync_plan = self.discover_sync_needs().await
              .map_err(|e| SyncError::Validation(format!("Sync discovery failed: {}", e)))?;

          if sync_plan.qr_info_requests.is_empty() && sync_plan.mn_diff_requests.is_empty() {
              tracing::info!("Masternode sync complete - engine has all required data");
              self.sync_in_progress = false;
              return Ok(true);
          }

          tracing::info!(
              "Executing hybrid sync plan: {} QRInfo requests, {} MnListDiff requests, fallback_enabled={}",
              sync_plan.qr_info_requests.len(),
              sync_plan.mn_diff_requests.len(),
              sync_plan.fallback_to_mn_diff
          );

          // Phase 2: Execute planned sync strategy using engine's native methods
          match self.execute_native_engine_sync(network, storage, sync_plan.clone()).await {
              Ok(()) => {
                  tracing::info!("Hybrid sync completed successfully");
                  self.sync_in_progress = false;
                  Ok(true)
              }
              Err(e) if sync_plan.fallback_to_mn_diff => {
                  tracing::warn!("QRInfo sync encountered issues: {}, using MnListDiff fallback", e);
                  self.execute_mn_diff_fallback_strategy(network, storage, &sync_plan).await
              }
              Err(e) => {
                  tracing::error!("Hybrid sync failed: {}", e);
                  self.sync_in_progress = false;
                  Err(e)
              }
          }
      }

      /// Execute sync using engine's native QRInfo and MnListDiff processing
      async fn execute_native_engine_sync(
          &mut self,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
          sync_plan: SyncPlan,
      ) -> SyncResult<()> {
          let engine = self.engine.as_mut().ok_or(SyncError::Configuration("Engine not initialized".to_string()))?;

          // CRITICAL: Create height resolution function
          let get_height_fn = {
              let block_height_cache = &self.block_height_cache;
              let storage_ref = storage as *const dyn StorageManager;
              
              move |block_hash: &BlockHash| -> Result<u32, String> {
                  // First check engine's block container
                  // Note: In actual implementation, use engine.block_container.get_height(block_hash)
                  if let Some(height) = block_height_cache.get(block_hash) {
                      return Ok(*height);
                  }
                  
                  // Fallback to storage lookup with proper error handling
                  unsafe {
                      (*storage_ref).get_block_height(block_hash)
                          .map_err(|e| format!("Height not found for block hash {}: {}", block_hash, e))
                  }
              }
          };

          // CRITICAL: Create chain lock signature resolution function
          let get_chain_lock_sig_fn = {
              let chain_lock_cache = &self.chain_lock_signature_cache;
              let storage_ref = storage as *const dyn StorageManager;
              
              move |block_hash: &BlockHash| -> Result<Option<ChainLockSignature>, String> {
                  // First check cache
                  if let Some(sig) = chain_lock_cache.get(block_hash) {
                      return Ok(Some(sig.clone()));
                  }
                  
                  // Fetch from storage/Core RPC if needed
                  unsafe {
                      match (*storage_ref).get_chain_lock_signature_by_hash(block_hash) {
                          Ok(Some(sig)) => Ok(Some(sig)),
                          Ok(None) => Ok(None), // Not all blocks have chain lock signatures
                          Err(e) => {
                              tracing::debug!("Chain lock signature fetch failed for {}: {}", block_hash, e);
                              Ok(None) // Graceful degradation - continue without signature
                          }
                      }
                  }
              }
          };

          // Process QRInfo requests using engine's native feed_qr_info() with height function
          for qr_info_request in &sync_plan.qr_info_requests {
              tracing::debug!("Requesting QRInfo for range {}-{}", 
                            qr_info_request.base_height, qr_info_request.tip_height);

              let qr_info = self.request_qr_info(
                  network, 
                  qr_info_request.base_hash, 
                  qr_info_request.tip_hash
              ).await?;

              // CRITICAL: Prepare block heights before feeding QRInfo
              self.feed_qr_info_block_heights(&qr_info).await?;
              
              // CRITICAL: Prepare chain lock signatures for rotating quorums
              if sync_plan.rotating_validation_needed {
                  self.feed_qr_info_chain_lock_signatures(&qr_info).await?;
              }

              // Use engine's native QRInfo processing with both resolution functions
              if let Err(e) = engine.feed_qr_info(qr_info, true, Some(get_height_fn), Some(get_chain_lock_sig_fn)) {
                  return Err(SyncError::Validation(format!("QRInfo processing failed: {}", e)));
              }

              tracing::debug!("QRInfo processed successfully for range {}-{}", 
                            qr_info_request.base_height, qr_info_request.tip_height);
          }

          // Process individual MnListDiff requests
          for mn_diff_request in &sync_plan.mn_diff_requests {
              tracing::debug!("Requesting MnListDiff for range {}-{}: {}", 
                            mn_diff_request.base_height, mn_diff_request.tip_height, mn_diff_request.reason);

              let mn_list_diff = self.request_masternode_diff(
                  network, 
                  storage, 
                  mn_diff_request.base_height, 
                  mn_diff_request.tip_height
              ).await?;

              // Use engine's native diff processing with proper signature
              if let Err(e) = engine.apply_diff(
                  mn_list_diff, 
                  Some(mn_diff_request.tip_height),  // Use Some(height) variant
                  false  // validate = false for individual diffs, QRInfo handles validation
              ) {
                  return Err(SyncError::Validation(format!("MnListDiff processing failed: {}", e)));
              }

              tracing::debug!("MnListDiff processed successfully for range {}-{}", 
                            mn_diff_request.base_height, mn_diff_request.tip_height);
          }

          // Perform final validation if rotating quorums were involved
          if sync_plan.rotating_validation_needed {
              self.validate_rotating_quorums(engine).await?;
          }

          Ok(())
      }

      /// Fallback strategy using MnListDiff when QRInfo fails
      async fn execute_mn_diff_fallback_strategy(
          &mut self,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
          failed_plan: &SyncPlan,
      ) -> SyncResult<bool> {
          tracing::info!("Executing MnListDiff fallback strategy for {} failed QRInfo ranges",
                        failed_plan.qr_info_requests.len());

          let engine = self.engine.as_mut().ok_or(SyncError::Configuration("Engine not initialized".to_string()))?;

          for qr_info_request in &failed_plan.qr_info_requests {
              // Convert failed QRInfo request to individual MnListDiff requests
              for height in qr_info_request.base_height..=qr_info_request.tip_height {
                  let base_height = height.saturating_sub(1);

                  let mn_list_diff = self.request_masternode_diff_by_height(
                      network, storage, base_height, height
                  ).await.map_err(|e| SyncError::Network(
                      format!("MnListDiff fallback failed at height {}: {}", height, e)
                  ))?;

                  // Use engine's native diff processing with proper signature
                  if let Err(e) = engine.apply_diff(mn_list_diff, Some(height), false) {
                      return Err(SyncError::Validation(
                          format!("Fallback MnListDiff processing failed at height {}: {}", height, e)
                      ));
                  }
              }
          }

          tracing::info!("MnListDiff fallback strategy completed successfully");
          self.sync_in_progress = false;
          Ok(true)
      }

      /// Request individual MnListDiff (refined existing method)
      async fn request_masternode_diff_by_height(
          &mut self,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
          base_height: u32,
          tip_height: u32,
      ) -> SyncResult<()> {
          // Use existing request_masternode_diff logic but with height-based interface
          // This preserves the working MnListDiff functionality
          self.request_masternode_diff(network, storage, base_height, tip_height).await
      }

      /// ENHANCED: Rotating quorum validation
      async fn validate_rotating_quorums(&mut self, engine: &mut MasternodeListEngine) -> SyncResult<()> {
          tracing::debug!("Starting comprehensive rotating quorum validation");
          
          // Verify rotating quorum hashes
          let rotating_hashes = engine.latest_masternode_list_rotating_quorum_hashes(&[]);
          tracing::debug!("Verifying {} rotating quorum hashes", rotating_hashes.len());

          for quorum_hash in rotating_hashes {
              if let Ok(height) = self.get_height_for_hash(&quorum_hash).await {
                  engine.feed_block_height(height, quorum_hash);
              }
          }

          // Verify non-rotating quorum hashes
          let non_rotating_hashes = engine.latest_masternode_list_non_rotating_quorum_hashes(
              &[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85]
          );
          tracing::debug!("Verifying {} non-rotating quorum hashes", non_rotating_hashes.len());
          
          for quorum_hash in non_rotating_hashes {
              if let Ok(height) = self.get_height_for_hash(&quorum_hash).await {
                  engine.feed_block_height(height, quorum_hash);
              }
          }
          
          // Final comprehensive quorum verification
          let tip_height = self.get_current_tip_height().await?;
          engine.verify_masternode_list_quorums(
              tip_height, 
              &[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85]
          ).map_err(|e| SyncError::Validation(format!("Quorum verification failed: {}", e)))?;

          tracing::debug!("Rotating quorum validation completed successfully");
          Ok(())
      }
      
      /// Helper: Get height for quorum hash
      async fn get_height_for_hash(&self, hash: &BlockHash) -> SyncResult<u32> {
          // This should be implemented to fetch from storage/chain
          self.get_height_for_block_hash(hash).await
      }
      
      /// Helper: Get current chain tip height
      async fn get_current_tip_height(&self) -> SyncResult<u32> {
          // This should be implemented to get current chain height
          Err(SyncError::Validation("Current tip height not available".to_string()))
      }

      /// Feed block heights to engine before QRInfo processing
      async fn feed_qr_info_block_heights(&mut self, qr_info: &QRInfo) -> SyncResult<()> {
          let engine = self.engine.as_mut().ok_or(SyncError::Configuration("Engine not initialized".to_string()))?;
          
          // Extract all MnListDiff block hashes from QRInfo
          let mn_list_diffs = [
              &qr_info.mn_list_diff_tip,
              &qr_info.mn_list_diff_h,
              &qr_info.mn_list_diff_at_h_minus_c,
              &qr_info.mn_list_diff_at_h_minus_2c,
              &qr_info.mn_list_diff_at_h_minus_3c,
          ];
          
          // Also handle optional h-4c diff
          let mut all_diffs = mn_list_diffs.to_vec();
          if let Some((_, mn_list_diff_h_minus_4c)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
              all_diffs.push(mn_list_diff_h_minus_4c);
          }
          
          // Feed both base and block hash heights
          for diff in all_diffs {
              // Feed base block hash height
              if let Ok(base_height) = self.get_height_for_block_hash(&diff.base_block_hash).await {
                  engine.feed_block_height(base_height, diff.base_block_hash);
                  tracing::trace!("Fed base height {} for hash {}", base_height, diff.base_block_hash);
              }
              
              // Feed block hash height
              if let Ok(block_height) = self.get_height_for_block_hash(&diff.block_hash).await {
                  engine.feed_block_height(block_height, diff.block_hash);
                  tracing::trace!("Fed block height {} for hash {}", block_height, diff.block_hash);
              }
          }
          
          // Feed heights for additional diffs in the list
          for diff in &qr_info.mn_list_diff_list {
              if let Ok(base_height) = self.get_height_for_block_hash(&diff.base_block_hash).await {
                  engine.feed_block_height(base_height, diff.base_block_hash);
              }
              if let Ok(block_height) = self.get_height_for_block_hash(&diff.block_hash).await {
                  engine.feed_block_height(block_height, diff.block_hash);
              }
          }
          
          // Feed quorum entry heights
          for quorum_entry in &qr_info.quorum_snapshot_list {
              if let Ok(height) = self.get_height_for_block_hash(&quorum_entry.quorum_hash).await {
                  engine.feed_block_height(height, quorum_entry.quorum_hash);
                  tracing::trace!("Fed quorum height {} for hash {}", height, quorum_entry.quorum_hash);
              }
          }
          
          Ok(())
      }
      
      /// Feed chain lock signatures for rotating quorum validation
      async fn feed_qr_info_chain_lock_signatures(&mut self, qr_info: &QRInfo) -> SyncResult<()> {
          let engine = self.engine.as_mut().ok_or(SyncError::Configuration("Engine not initialized".to_string()))?;
          
          // Get required chain lock hashes directly from quorum snapshots
          let mut chain_lock_hashes = Vec::new();
          
          // Collect chain lock validation hashes from all quorum snapshots
          for quorum_entry in &qr_info.quorum_snapshot_at_h_minus_c {
              if let Some(validation_hash) = &quorum_entry.maybe_chain_lock_signature_validation_hash {
                  chain_lock_hashes.push(BlockHash::from_byte_array(validation_hash.to_byte_array()));
              }
          }
          
          for quorum_entry in &qr_info.quorum_snapshot_at_h_minus_2c {
              if let Some(validation_hash) = &quorum_entry.maybe_chain_lock_signature_validation_hash {
                  chain_lock_hashes.push(BlockHash::from_byte_array(validation_hash.to_byte_array()));
              }
          }
          
          for quorum_entry in &qr_info.quorum_snapshot_at_h_minus_3c {
              if let Some(validation_hash) = &quorum_entry.maybe_chain_lock_signature_validation_hash {
                  chain_lock_hashes.push(BlockHash::from_byte_array(validation_hash.to_byte_array()));
              }
          }
          
          // Handle h-4c snapshots if present
          if let Some((quorum_snapshot, _)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
              for quorum_entry in quorum_snapshot {
                  if let Some(validation_hash) = &quorum_entry.maybe_chain_lock_signature_validation_hash {
                      chain_lock_hashes.push(BlockHash::from_byte_array(validation_hash.to_byte_array()));
                  }
              }
          }
              
          tracing::debug!("Feeding {} chain lock signatures for QRInfo validation", chain_lock_hashes.len());
          
          // Feed chain lock signatures for validation hashes
          for block_hash in chain_lock_hashes {
              if let Ok(Some(chain_lock_sig)) = self.fetch_chain_lock_signature_by_hash(&block_hash).await {
                  engine.feed_chain_lock_sig(block_hash, chain_lock_sig);
                  tracing::trace!("Fed chain lock signature for hash {}", block_hash);
              } else {
                  tracing::debug!("No chain lock signature available for hash {}", block_hash);
              }
          }
          
          Ok(())
      }

      /// Request QRInfo using known block hashes
      async fn request_qr_info(
          &mut self,
          network: &mut dyn NetworkManager,
          base_block_hash: BlockHash,
          tip_block_hash: BlockHash,
      ) -> SyncResult<QRInfo> {
          // Collect known block hashes from engine for efficiency
          let engine = self.engine.as_ref().ok_or(SyncError::Configuration("Engine not initialized".to_string()))?;
          let known_block_hashes: Vec<BlockHash> = engine.block_hashes.keys().cloned().collect();

          let qr_info_request = GetQRInfo {
              base_block_hashes: known_block_hashes,
              block_request_hash: tip_block_hash,
              extra_share: self.config.qr_info_extra_share,
          };

          network.send_message(NetworkMessage::GetQRInfo(qr_info_request)).await
              .map_err(|e| SyncError::Network(format!("QRInfo request failed: {}", e)))?;

          // Wait for QRInfo response
          self.wait_for_qr_info_response_with_timeout(self.config.qr_info_timeout).await
      }
      
      /// Helper: Get height for block hash with caching
      async fn get_height_for_block_hash(&self, block_hash: &BlockHash) -> SyncResult<u32> {
          if let Some(height) = self.block_height_cache.get(block_hash) {
              return Ok(*height);
          }
          
          // This should be implemented to fetch from storage/network
          Err(SyncError::Validation(format!("Height not found for block hash: {}", block_hash)))
      }
      
      /// Helper: Get block hash for height
      async fn get_block_hash_for_height(&self, height: u32) -> SyncResult<BlockHash> {
          // This should be implemented to fetch from storage/chain
          Err(SyncError::Validation(format!("Block hash not found for height: {}", height)))
      }
      
      /// Fetch chain lock signature by hash with Core RPC integration
      async fn fetch_chain_lock_signature_by_hash(&self, block_hash: &BlockHash) -> SyncResult<Option<ChainLockSignature>> {
          // First check cache
          if let Some(sig) = self.chain_lock_signature_cache.get(block_hash) {
              return Ok(Some(sig.clone()));
          }
          
          // Get height for this block hash
          let height = self.get_height_for_block_hash(block_hash).await
              .map_err(|e| SyncError::Validation(format!("Cannot get height for block hash {}: {}", block_hash, e)))?;
              
          // Check storage first
          if let Ok(Some(chain_lock)) = self.storage.get_chain_lock_signature_by_hash(block_hash).await {
              return Ok(Some(chain_lock));
          }
          
          // Fetch from Core RPC if not in storage
          match self.core_rpc_client.get_chain_lock_signature(height).await {
              Ok(Some(chain_lock_sig)) => {
                  // Cache the result for future use
                  self.chain_lock_signature_cache.insert(*block_hash, chain_lock_sig.clone());
                  Ok(Some(chain_lock_sig))
              }
              Ok(None) => {
                  tracing::debug!("No chain lock signature available for height {} hash {}", height, block_hash);
                  Ok(None) // Not all blocks have chain lock signatures
              }
              Err(e) => {
                  tracing::warn!("Failed to fetch chain lock signature for height {}: {}", height, e);
                  Ok(None) // Graceful degradation - continue without signature
              }
          }
      }
      
      /// Legacy method for height-based fetching
      async fn fetch_chain_lock_signature(&self, height: u32) -> SyncResult<Option<ChainLockSignature>> {
          let block_hash = self.get_block_hash_for_height(height).await?;
          self.fetch_chain_lock_signature_by_hash(&block_hash).await
      }
  }

  2.2 Enhanced Sync Plan Structure

  File: dash-spv/src/sync/masternodes.rs

  #[derive(Debug, Clone)]
  pub struct SyncPlan {
      /// Primary QRInfo requests for bulk sync
      pub qr_info_requests: Vec<QRInfoRequest>,

      /// Individual MnListDiff requests for gap filling
      pub mn_diff_requests: Vec<MnDiffRequest>,

      /// Whether to fallback to MnListDiff if QRInfo fails
      pub fallback_to_mn_diff: bool,

      /// Rotating quorum validation needed
      pub rotating_validation_needed: bool,

      /// Estimated completion time
      pub estimated_completion_time: Duration,

      /// Strategy rationale for debugging
      pub strategy_reason: String,
  }

  #[derive(Debug, Clone)]
  pub struct MnDiffRequest {
      pub base_height: u32,
      pub tip_height: u32,
      pub base_hash: BlockHash,
      pub tip_hash: BlockHash,
      pub priority: u32,
      pub reason: String, // Why MnListDiff instead of QRInfo
  }

  impl MasternodeDiscoveryService {
      /// Enhanced planning leveraging engine capabilities
      pub fn plan_hybrid_sync_requests(
          &self,
          discovery: &DiscoveryResult,
          max_qr_info_span: u32,
      ) -> SyncPlan {
          let mut qr_info_requests = Vec::new();
          let mut mn_diff_requests = Vec::new();
          let mut strategy_reasons = Vec::new();

          // Use engine intelligence for gap detection
          let height_groups = self.group_heights_by_engine_efficiency(&discovery.missing_by_height, max_qr_info_span);

          for group in height_groups {
              match group.request_type {
                  OptimalRequestType::QRInfo => {
                      qr_info_requests.push(QRInfoRequest {
                          base_height: group.start_height,
                          tip_height: group.end_height,
                          base_hash: group.base_hash,
                          tip_hash: group.tip_hash,
                          extra_share: true,
                          priority: group.priority,
                      });
                      strategy_reasons.push(format!("QRInfo bulk sync {}-{}: {} (engine will auto-extract MnListDiffs)",
                                                   group.start_height, group.end_height, group.reason));
                  }
                  OptimalRequestType::MnListDiff => {
                      mn_diff_requests.push(MnDiffRequest {
                          base_height: group.start_height,
                          tip_height: group.end_height,
                          base_hash: group.base_hash,
                          tip_hash: group.tip_hash,
                          priority: group.priority,
                          reason: group.reason.clone(),
                      });
                      strategy_reasons.push(format!("MnListDiff targeted sync {}-{}: {}",
                                                   group.start_height, group.end_height, group.reason));
                  }
              }
          }

          SyncPlan {
              qr_info_requests,
              mn_diff_requests,
              fallback_to_mn_diff: discovery.total_discovered > 500, // Fallback for large syncs
              rotating_validation_needed: self.detect_rotation_requirements(&discovery),
              estimated_completion_time: self.estimate_hybrid_sync_time(&qr_info_requests, &mn_diff_requests),
              strategy_reason: strategy_reasons.join("; "),
          }
      }

      /// ADDED: Detect if rotating quorum validation is needed
      fn detect_rotation_requirements(&self, discovery: &DiscoveryResult) -> bool {
          // Check if any missing heights fall on quorum rotation boundaries
          // This would require chain lock signature validation
          discovery.missing_by_height.keys().any(|&height| {
              height % 576 == 0 || // DKG window boundaries
              height % 288 == 0    // Half-window boundaries
          })
      }

      /// Group heights using engine intelligence
      fn group_heights_by_engine_efficiency(
          &self,
          missing_heights: &BTreeMap<u32, BlockHash>,
          max_qr_info_span: u32,
      ) -> Vec<HeightGroup> {
          // This replaces the complex manual grouping with engine-informed decisions
          self.group_heights_by_efficiency(missing_heights, max_qr_info_span)
      }

      /// Group heights by optimal request type
      fn group_heights_by_efficiency(
          &self,
          missing_heights: &BTreeMap<u32, BlockHash>,
          max_qr_info_span: u32,
      ) -> Vec<HeightGroup> {
          let mut groups = Vec::new();
          let heights: Vec<u32> = missing_heights.keys().cloned().collect();

          if heights.is_empty() {
              return groups;
          }

          let mut current_start = heights[0];
          let mut current_end = heights[0];

          for &height in &heights[1..] {
              let gap = height - current_end;
              let range_size = current_end - current_start + 1;

              if gap <= 3 && range_size < max_qr_info_span {
                  // Continue current group - small gap, efficient for QRInfo
                  current_end = height;
              } else {
                  // Finalize current group
                  groups.push(self.create_height_group(current_start, current_end, missing_heights, max_qr_info_span));
                  current_start = height;
                  current_end = height;
              }
          }

          // Add final group
          groups.push(self.create_height_group(current_start, current_end, missing_heights, max_qr_info_span));
          groups
      }

      fn create_height_group(
          &self,
          start: u32,
          end: u32,
          missing_heights: &BTreeMap<u32, BlockHash>,
          max_qr_info_span: u32,
      ) -> HeightGroup {
          let range_size = end - start + 1;

          let (request_type, reason) = if range_size == 1 {
              (OptimalRequestType::MnListDiff, "Single block - MnListDiff more efficient".to_string())
          } else if range_size > max_qr_info_span {
              (OptimalRequestType::MnListDiff, format!("Range too large ({} > {})", range_size, max_qr_info_span))
          } else if range_size >= 5 {
              (OptimalRequestType::QRInfo, format!("Range size {} efficient for QRInfo", range_size))
          } else {
              (OptimalRequestType::MnListDiff, format!("Small range ({}) - MnListDiff preferred", range_size))
          };

          HeightGroup {
              start_height: start,
              end_height: end,
              base_hash: missing_heights[&start],
              tip_hash: missing_heights[&end],
              request_type,
              priority: end, // More recent = higher priority
              reason,
          }
      }
  }

  #[derive(Debug)]
  enum OptimalRequestType {
      QRInfo,
      MnListDiff,
  }

  #[derive(Debug)]
  struct HeightGroup {
      start_height: u32,
      end_height: u32,
      base_hash: BlockHash,
      tip_hash: BlockHash,
      request_type: OptimalRequestType,
      priority: u32,
      reason: String,
  }

  Phase 3: Message Routing Enhancement

  Duration: 1 day

  3.1 Support Both Message Types

  File: dash-spv/src/sync/sequential/mod.rs

  impl SequentialSyncManager {
      async fn execute_current_phase(
          &mut self,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
      ) -> SyncResult<()> {
          match &self.current_phase {
              // ... existing cases ...

              SyncPhase::DownloadingMnList { .. } => {
                  tracing::info!("📥 Starting engine-driven hybrid masternode sync");

                  let effective_height = self.header_sync.get_chain_height();
                  let sync_base_height = self.header_sync.get_sync_base_height();

                  // Use modern engine-driven approach (supports both QRInfo + MnListDiff)
                  self.masternode_sync.start_engine_driven_sync(
                      network,
                      storage,
                      effective_height,
                      sync_base_height
                  ).await?;
              }

              // ... rest unchanged ...
          }
          Ok(())
      }

      pub async fn handle_network_message(
          &mut self,
          message: NetworkMessage,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
      ) -> SyncResult<()> {
          match (&mut self.current_phase, message) {
              // ... existing cases ...

              // Support both QRInfo and MnListDiff with complete engine integration
              (SyncPhase::DownloadingMnList { .. }, NetworkMessage::QRInfo(qr_info)) => {
                  // Use engine's native QRInfo processing
                  if let Some(engine) = &mut self.masternode_sync.engine {
                      // CRITICAL: Prepare block heights before processing
                      if let Err(e) = self.masternode_sync.feed_qr_info_block_heights(&qr_info).await {
                          tracing::error!("QRInfo block height preparation failed: {}", e);
                          return Err(e);
                      }
                      
                      // CRITICAL: Prepare chain lock signatures if needed
                      if self.masternode_sync.needs_chain_lock_validation(&qr_info) {
                          if let Err(e) = self.masternode_sync.feed_qr_info_chain_lock_signatures(&qr_info).await {
                              tracing::warn!("Chain lock signature preparation failed: {}", e);
                              // Continue without chain lock sigs - not always critical
                          }
                      }
                      
                      // Create height resolution function
                      let get_height_fn = {
                          let cache = &self.masternode_sync.block_height_cache;
                          move |block_hash: &BlockHash| -> Result<u32, String> {
                              cache.get(block_hash).copied()
                                  .ok_or_else(|| format!("Height not found for block hash: {}", block_hash))
                          }
                      };
                      
                      // Process QRInfo with height resolution function
                      if let Err(e) = engine.feed_qr_info(qr_info, true, Some(get_height_fn)) {
                          tracing::error!("QRInfo processing failed: {}", e);
                          return Err(SyncError::Validation(format!("QRInfo processing failed: {}", e)));
                      }
                      tracing::debug!("QRInfo processed successfully via engine with complete preparation");
                  } else {
                      return Err(SyncError::Configuration("Masternode engine not initialized".to_string()));
                  }
              }

              (SyncPhase::DownloadingMnList { .. }, NetworkMessage::MnListDiff(diff)) => {
                  // Use engine's native MnListDiff processing
                  if let Some(engine) = &mut self.masternode_sync.engine {
                      let height = self.get_height_for_diff(&diff).await?;
                      if let Err(e) = engine.apply_diff(diff, Some(height), false) {
                          tracing::error!("MnListDiff processing failed: {}", e);
                          return Err(SyncError::Validation(format!("MnListDiff processing failed: {}", e)));
                      }
                      tracing::debug!("MnListDiff processed successfully via engine at height {}", height);
                  } else {
                      return Err(SyncError::Configuration("Masternode engine not initialized".to_string()));
                  }
              }

              // ... rest unchanged ...
          }
          Ok(())
      }
  }

  Phase 4: Enhanced Progress Tracking

  Duration: 1 day

  4.1 Hybrid Progress Reporting

  File: dash-spv/src/sync/sequential/phases.rs

  #[derive(Debug, Clone, PartialEq)]
  pub enum SyncPhase {
      // ... existing phases ...

      /// Phase 2: Engine-driven hybrid masternode sync
      DownloadingMnList {
          start_time: Instant,
          start_height: u32,
          current_height: u32,
          target_height: u32,
          last_progress: Instant,

          // Hybrid tracking
          sync_strategy: HybridSyncStrategy,
          requests_completed: u32,
          requests_total: u32,

          // Backward compatibility
          diffs_processed: u32,
      },
  }

  #[derive(Debug, Clone, PartialEq)]
  pub enum HybridSyncStrategy {
      EngineDiscovery {
          qr_info_requests: u32,
          mn_diff_requests: u32,
          qr_info_completed: u32,
          mn_diff_completed: u32,
      },
      FallbackActive {
          original_qr_info_failed: u32,
          fallback_mn_diffs: u32,
          reason: String,
      },
  }

  impl SyncPhase {
      pub fn progress(&self) -> PhaseProgress {
          match self {
              SyncPhase::DownloadingMnList {
                  sync_strategy,
                  requests_completed,
                  requests_total,
                  start_time,
                  ..
              } => {
                  let (method_description, efficiency_note) = match sync_strategy {
                      HybridSyncStrategy::EngineDiscovery { qr_info_requests, mn_diff_requests, .. } => {
                          let total_requests = qr_info_requests + mn_diff_requests;
                          let qr_info_ratio = if total_requests > 0 {
                              (*qr_info_requests as f64 / total_requests as f64) * 100.0
                          } else { 0.0 };

                          (
                              format!("Hybrid Sync ({:.0}% QRInfo, {:.0}% MnListDiff)",
                                     qr_info_ratio, 100.0 - qr_info_ratio),
                              if qr_info_ratio > 70.0 { "High Efficiency" } else { "Standard Efficiency" }
                          )
                      }
                      HybridSyncStrategy::FallbackActive { reason, .. } => {
                          (format!("MnListDiff Fallback: {}", reason), "Recovery Mode")
                      }
                  };

                  let percentage = if *requests_total > 0 {
                      (*requests_completed as f64 / *requests_total as f64) * 100.0
                  } else {
                      0.0
                  };

                  PhaseProgress {
                      phase_name: format!("Masternode Sync - {} ({})", method_description, efficiency_note),
                      items_completed: *requests_completed,
                      items_total: Some(*requests_total),
                      percentage,
                      // ... rest of calculation unchanged
                  }
              }
              // ... other phases unchanged
          }
      }
  }

  Phase 5: Critical Helper Methods Implementation (NEW)

  Duration: 1 day

  5.1 Essential Support Methods

  File: dash-spv/src/sync/masternodes.rs

  impl MasternodeSyncManager {
      /// CRITICAL: Block height cache for efficient lookups
      pub struct BlockHeightCache {
          cache: HashMap<BlockHash, u32>,
          storage: Arc<dyn StorageManager>,
      }

      impl BlockHeightCache {
          pub fn get(&self, block_hash: &BlockHash) -> Option<u32> {
              // Check memory cache first
              if let Some(height) = self.cache.get(block_hash) {
                  return Some(*height);
              }
              
              // Fallback to storage lookup and cache result
              if let Ok(height) = self.storage.get_block_height(block_hash) {
                  self.cache.insert(*block_hash, height);
                  Some(height)
              } else {
                  None
              }
          }
          
          pub fn insert(&mut self, block_hash: BlockHash, height: u32) {
              self.cache.insert(block_hash, height);
          }
      }

      /// CRITICAL: Chain lock signature management
      pub async fn fetch_chain_lock_signature(&self, height: u32) -> SyncResult<ChainLockSignature> {
          // First check local storage
          if let Ok(chain_lock) = self.storage.get_chain_lock_signature(height).await {
              return Ok(chain_lock);
          }
          
          // Request from network if not available locally
          let block_hash = self.get_block_hash_for_height(height).await?;
          let request = GetChainLockSig { block_hash, height };
          
          self.network.send_message(NetworkMessage::GetChainLockSig(request)).await
              .map_err(|e| SyncError::Network(format!("Chain lock request failed: {}", e)))?;
              
          // Wait for response with timeout
          self.wait_for_chain_lock_response(height, Duration::from_secs(10)).await
      }

      /// CRITICAL: Check if QRInfo requires chain lock validation
      pub fn needs_chain_lock_validation(&self, qr_info: &QRInfo) -> bool {
          // Check if any quorum snapshots indicate rotating quorums
          !qr_info.quorum_snapshot_at_h_minus_c.is_empty() ||
          !qr_info.quorum_snapshot_at_h_minus_2c.is_empty() ||
          !qr_info.quorum_snapshot_at_h_minus_3c.is_empty() ||
          qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some()
      }

      /// CRITICAL: Response timeout handling for QRInfo
      pub async fn wait_for_qr_info_response_with_timeout(&mut self, timeout: Duration) -> SyncResult<QRInfo> {
          let start_time = std::time::Instant::now();
          
          while start_time.elapsed() < timeout {
              if let Some(qr_info) = self.pending_qr_info_responses.pop_front() {
                  return Ok(qr_info);
              }
              
              // Check for network messages
              if let Ok(message) = self.network.try_receive_message().await {
                  match message {
                      NetworkMessage::QRInfo(qr_info) => {
                          return Ok(qr_info);
                      }
                      _ => {
                          // Handle other messages or ignore
                      }
                  }
              }
              
              tokio::time::sleep(Duration::from_millis(10)).await;
          }
          
          Err(SyncError::Timeout(format!("QRInfo request timed out after {:?}", timeout)))
      }
  }

  5.2 Storage Interface Extensions

  File: dash-spv/src/storage/mod.rs

  /// Extended storage interface for QRInfo support
  pub trait StorageManager {
      // ... existing methods ...
      
      /// CRITICAL: Block height lookup for QRInfo processing
      async fn get_block_height(&self, block_hash: &BlockHash) -> Result<u32, StorageError>;
      
      /// CRITICAL: Block hash lookup for height
      async fn get_block_hash(&self, height: u32) -> Result<BlockHash, StorageError>;
      
      /// Chain lock signature storage/retrieval by hash
      async fn get_chain_lock_signature_by_hash(&self, block_hash: &BlockHash) -> Result<Option<ChainLockSignature>, StorageError>;
      async fn store_chain_lock_signature_by_hash(&mut self, block_hash: &BlockHash, signature: ChainLockSignature) -> Result<(), StorageError>;
      
      /// Legacy height-based chain lock signature methods
      async fn get_chain_lock_signature(&self, height: u32) -> Result<Option<ChainLockSignature>, StorageError>;
      async fn store_chain_lock_signature(&mut self, height: u32, signature: ChainLockSignature) -> Result<(), StorageError>;
      
      /// CRITICAL: Batch height lookups for efficiency
      async fn get_block_heights(&self, block_hashes: &[BlockHash]) -> Result<Vec<(BlockHash, u32)>, StorageError>;
      
      /// Cache management for efficient lookups
      async fn cache_block_height(&mut self, block_hash: &BlockHash, height: u32) -> Result<(), StorageError>;
      async fn cache_chain_lock_signature(&mut self, block_hash: &BlockHash, signature: ChainLockSignature) -> Result<(), StorageError>;
  }

  Phase 6: Testing Strategy

  Duration: 2 days

  5.1 Engine-Native Integration Tests

  File: dash-spv/tests/engine_native_sync_integration_test.rs

  #[tokio::test]
  async fn test_engine_native_qr_info_processing() {
      // Test engine's native feed_qr_info() method
      let config = ClientConfig::testnet();
      let mut client = DashSpvClient::new(config).await.unwrap();

      // Mock network to provide QRInfo with embedded MnListDiffs
      client.setup_qr_info_network_mock().await;

      client.start().await.unwrap();

      // Monitor engine state directly
      let engine_state = client.get_masternode_engine_state().await.unwrap();
      
      // Verify engine processed QRInfo correctly
      assert!(!engine_state.masternode_lists.is_empty(), "Engine should have processed masternode lists");
      assert!(!engine_state.block_hashes.is_empty(), "Engine should have tracked block hashes");
      
      // Verify all QRInfo embedded diffs were processed
      let processed_heights: Vec<u32> = engine_state.masternode_lists.keys().cloned().collect();
      assert!(processed_heights.len() >= 5, "QRInfo should populate multiple heights via embedded diffs");

      let final_progress = client.get_sync_progress().await.unwrap();
      assert!(final_progress.masternodes_synced);
  }

  #[tokio::test]
  async fn test_engine_native_hybrid_processing() {
      // Test both QRInfo and MnListDiff engine processing
      let config = ClientConfig::testnet();
      let mut client = DashSpvClient::new(config).await.unwrap();

      // Mock network providing strategic mix of QRInfo and individual MnListDiffs
      client.setup_hybrid_strategic_network_mock().await;

      client.start().await.unwrap();

      let engine_state = client.get_masternode_engine_state().await.unwrap();
      
      // Verify engine processed both message types
      assert!(!engine_state.masternode_lists.is_empty());
      
      // Check that quorum validation was performed if rotating quorums involved
      if engine_state.has_rotating_quorums {
          assert!(!engine_state.known_chain_locks.is_empty(), "Should have chain lock signatures for validation");
      }

      let final_progress = client.get_sync_progress().await.unwrap();
      assert!(final_progress.masternodes_synced);
  }

  #[tokio::test]
  async fn test_engine_native_fallback_processing() {
      // Test engine fallback with native apply_diff()
      let config = ClientConfig::testnet();
      let mut client = DashSpvClient::new(config).await.unwrap();

      // Mock network to fail QRInfo but support MnListDiff
      client.setup_qr_info_failing_network().await;

      client.start().await.unwrap();

      let engine_state = client.get_masternode_engine_state().await.unwrap();
      
      // Verify engine processed fallback MnListDiffs correctly
      assert!(!engine_state.masternode_lists.is_empty(), "Engine should have processed fallback diffs");
      
      // Verify all heights were covered by individual MnListDiffs
      let processed_heights: Vec<u32> = engine_state.masternode_lists.keys().cloned().collect();
      assert!(processed_heights.windows(2).all(|w| w[1] - w[0] <= 1), 
              "Fallback should process sequential heights");

      let final_progress = client.get_sync_progress().await.unwrap();
      assert!(final_progress.masternodes_synced);
  }

  #[tokio::test]
  async fn test_optimal_request_planning() {
      let discovery_service = MasternodeDiscoveryService::new();

      // Create various gap patterns
      let mut missing_heights = BTreeMap::new();
      missing_heights.insert(1000, test_block_hash(1000)); // Single block
      missing_heights.insert(1001, test_block_hash(1001)); // Adjacent
      missing_heights.insert(1002, test_block_hash(1002)); // Adjacent
      missing_heights.insert(1010, test_block_hash(1010)); // Gap
      missing_heights.insert(1020, test_block_hash(1020)); // Isolated

      let discovery = DiscoveryResult {
          missing_by_height: missing_heights,
          total_discovered: 5,
          requires_qr_info: true,
      };

      let plan = discovery_service.plan_hybrid_sync_requests(&discovery, 50);

      // Should create optimal mix: QRInfo for 1000-1002 range, MnListDiff for isolated blocks
      assert!(!plan.qr_info_requests.is_empty(), "Should have some QRInfo requests");
      assert!(!plan.mn_diff_requests.is_empty(), "Should have some MnListDiff requests");

      // Verify strategic decision making
      let qr_info_covers_range = plan.qr_info_requests.iter()
          .any(|req| req.base_height <= 1000 && req.tip_height >= 1002);
      assert!(qr_info_covers_range, "QRInfo should handle contiguous ranges");
  }

  ---
  Implementation Timeline

  | Day  | Phase                     | Deliverables                                      |
  |------|---------------------------|---------------------------------------------------|
  | 1-2  | Legacy Analysis           | Identify keep vs remove, preserve MnListDiff core |
  | 3-5  | Hybrid Integration        | Engine-driven entry point, strategic planning     |
  | 6    | Message Routing           | Support both QRInfo and MnListDiff                |
  | 7    | Progress Tracking         | Hybrid progress reporting                         |
  | 8    | Critical Helper Methods   | Height resolution, chain lock handling            |
  | 9-10 | Testing                   | Hybrid integration tests                          |

  Total Duration: 10 days



