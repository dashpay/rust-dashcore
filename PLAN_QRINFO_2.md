⏺ Plan: Engine-Driven QRInfo Integration (Following DMLviewer.patch Sync Pattern)

  Executive Summary

  This plan integrates QRInfo-driven masternode sync following the proven "Sync" implementation pattern from DMLviewer.patch. The approach is simple and engine-driven: always request QRInfo (which contains embedded MnListDiffs), then let the masternode list engine's `feed_qr_info()` method intelligently process what it needs.

  Key architectural improvements include:
  - Faithful implementation of DMLviewer.patch "Sync" button logic
  - Proper engine method signatures and parameter usage from reference implementation
  - Comprehensive error handling patterns after each engine operation
  - Engine-first height resolution with proper preparation
  - Chain lock signature discovery using engine's native methods
  - Simplified approach: engine decides everything, no manual gap analysis

  Architecture Understanding

  Engine-Driven Sync Strategy (from DMLviewer.patch):

  - Single Strategy: Always request QRInfo (contains embedded MnListDiffs for tip, h, h-c, h-2c, h-3c, optional h-4c)
  - Engine Intelligence: Let engine.feed_qr_info() decide what to process and apply
  - Proven Pattern: Follows exact "Sync" implementation from reference patch
  - No Complex Logic: Engine handles sequencing, validation, and application automatically

  ---
  Revised Implementation Plan

  Phase 1: Legacy Code Analysis and Selective Removal

  Duration: 2 days

  1.1 KEEP Essential MnListDiff Methods (Simplified)

  File: dash-spv/src/sync/masternodes.rs

  ✅ PRESERVE full MnListDiff methods (DMLviewer.patch shows both are needed):
  // Direct MnListDiff requests for individual/targeted updates
  ✅ async fn request_masternode_diff()  // For "Get single end DML diff" scenarios
  ✅ async fn handle_mnlistdiff_message() // Process MnListDiff responses
  ✅ async fn process_masternode_diff()  // Engine integration via apply_diff()
  ✅ NetworkMessage::MnListDiff handling in message routing // Full message support

  Note: DMLviewer.patch shows both get_dml_diff() AND get_qr_info() are used

  1.2 REMOVE Obsolete Sequential Logic

  File: dash-spv/src/sync/masternodes.rs

  ❌ DELETE these methods (replaced by simple QRInfo approach):
  // Manual height tracking and sequential logic
  ❌ start_sync_with_height() // Replace with simple sync() pattern
  ❌ request_masternode_diffs_smart() // QRInfo contains all needed diffs
  ❌ request_masternode_diffs_for_chainlock_validation_with_base() // Engine handles validation
  ❌ All DKG window calculation logic // Engine handles this internally
  ❌ Terminal block optimization code // Not needed with QRInfo
  ❌ Manual bulk/smart fetch state management // Engine decides everything
  ❌ All hardcoded height progression logic // Engine processes embedded diffs
  ❌ Complex gap analysis and request planning // Engine intelligence supersedes this

  1.3 Clean Configuration (Simplified)

  File: dash-spv/src/client/config.rs

  impl ClientConfig {
      // REMOVE QRInfo enable/disable flags (always enabled when masternodes enabled)
      ❌ pub enable_qr_info: bool,
      ❌ pub qr_info_fallback: bool,  // Removed - QRInfo is primary

      // KEEP essential QRInfo parameters (from DMLviewer.patch)
      ✅ pub qr_info_extra_share: bool,     // Matches DMLviewer.patch usage
      ✅ pub qr_info_timeout: Duration,     // Network reliability

      // REMOVE complex hybrid parameters (not needed)
      ❌ pub qr_info_max_parallel: usize,   // Single QRInfo request pattern
      ❌ pub mnlist_diff_timeout: Duration, // QRInfo handles embedded diffs
  }

  impl Default for ClientConfig {
      fn default() -> Self {
          Self {
              // ... existing fields ...
              qr_info_extra_share: false,  // Matches DMLviewer.patch default
              qr_info_timeout: Duration::from_secs(30),
          }
      }
  }

  Phase 2: Simple Engine-Driven Sync (Following DMLviewer.patch)

  Duration: 2 days

  2.1 Dual Sync Entry Points (DMLviewer.patch Patterns)

  File: dash-spv/src/sync/masternodes.rs

  impl MasternodeSyncManager {
      /// Engine-driven sync following DMLviewer.patch patterns 
      /// Supports both QRInfo (bulk) and MnListDiff (individual) requests like the reference
      pub async fn sync(
          &mut self,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
          base_block_hash: BlockHash,
          tip_block_hash: BlockHash,
      ) -> SyncResult<bool> {
          // Simple sync guard (from DMLviewer.patch)
          if self.sync_in_progress {
              return Err(SyncError::SyncInProgress);
          }

          // Skip if masternodes are disabled
          if !self.config.enable_masternodes || self.engine.is_none() {
              return Ok(false);
          }

          tracing::info!("Starting hybrid sync (DMLviewer.patch Sync pattern: QRInfo + individual MnListDiffs)");

          // Set sync state
          self.sync_in_progress = true;
          self.last_sync_progress = std::time::Instant::now();

          // Execute hybrid sync (DMLviewer.patch "Sync" button / fetch_end_qr_info_with_dmls pattern)
          // Step 1: QRInfo for bulk data, Step 2: Individual MnListDiffs for validation gaps
          self.fetch_qr_info_and_feed_engine_with_validation(network, storage, base_block_hash, tip_block_hash).await
      }

      /// Hybrid QRInfo + individual MnListDiff sync (DMLviewer.patch "Sync" pattern)
      async fn fetch_qr_info_and_feed_engine_with_validation(
          &mut self,
          network: &mut dyn NetworkManager,
          storage: &mut dyn StorageManager,
          base_block_hash: BlockHash,
          tip_block_hash: BlockHash,
      ) -> SyncResult<bool> {
          let engine = self.engine.as_mut().ok_or(SyncError::Configuration("Engine not initialized".to_string()))?;

          // Step 1: Get QRInfo (DMLviewer.patch get_qr_info pattern)
          let qr_info = self.request_qr_info(network, base_block_hash, tip_block_hash).await?;

          // Step 2: Feed block heights first (DMLviewer.patch preparation pattern)
          self.feed_qr_info_block_heights(&qr_info).await?;
          
          // Step 3: Feed chain lock signatures if needed (DMLviewer.patch validation pattern)
          if self.needs_chain_lock_validation(&qr_info) {
              self.feed_qr_info_chain_lock_signatures(&qr_info).await?;
          }

          // Step 4: Let engine process QRInfo (DMLviewer.patch feed_qr_info pattern)
          if let Err(e) = engine.feed_qr_info(qr_info, true, Some(self.get_height_fn()), Some(self.get_chain_lock_sig_fn())) {
              self.error = Some(e.to_string());
              self.sync_in_progress = false;
              return Err(SyncError::Validation(format!("QRInfo processing failed: {}", e)));
          }

          // Step 5: Fetch additional individual MnListDiffs for validation (DMLviewer.patch fetch_diffs_with_hashes pattern)
          self.fetch_validation_diffs(network, engine).await?;
          
          tracing::info!("Hybrid sync completed successfully (QRInfo + validation MnListDiffs)");
          self.sync_in_progress = false;
          Ok(true)
      }

      /// Individual MnListDiff request (DMLviewer.patch "Get single end DML diff" pattern)
      pub async fn fetch_individual_mn_diff(
          &mut self,
          network: &mut dyn NetworkManager,
          base_block_hash: BlockHash,
          tip_block_hash: BlockHash,
      ) -> SyncResult<bool> {
          let engine = self.engine.as_mut().ok_or(SyncError::Configuration("Engine not initialized".to_string()))?;

          // Direct MnListDiff request (like DMLviewer.patch get_dml_diff)
          let mn_diff = self.request_masternode_diff(network, base_block_hash, tip_block_hash).await?;

          // Use engine's apply_diff (DMLviewer.patch pattern)
          if let Err(e) = engine.apply_diff(mn_diff, None, false) {
              self.error = Some(e.to_string());
              return Err(SyncError::Validation(format!("MnListDiff processing failed: {}", e)));
          }

          tracing::info!("Individual MnListDiff processed successfully");
          Ok(true)
      }

      /// Fetch validation MnListDiffs (DMLviewer.patch fetch_diffs_with_hashes pattern)
      async fn fetch_validation_diffs(
          &mut self,
          network: &mut dyn NetworkManager,
          engine: &mut MasternodeListEngine,
      ) -> SyncResult<()> {
          // Get quorum hashes that need validation (DMLviewer.patch pattern)
          let non_rotating_hashes = engine.latest_masternode_list_non_rotating_quorum_hashes(
              &[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85], 
              true
          );
          
          // Calculate validation heights (height - 8 for each quorum)
          let mut validation_requests = Vec::new();
          for quorum_hash in non_rotating_hashes {
              if let Ok(quorum_height) = self.get_height_for_block_hash(&quorum_hash).await {
                  let validation_height = quorum_height.saturating_sub(8);
                  let validation_hash = self.get_block_hash_for_height(validation_height).await?;
                  validation_requests.push((validation_height, validation_hash));
              }
          }

          // Fetch individual MnListDiffs for validation gaps (DMLviewer.patch fetch_single_dml pattern)
          if let Some((first_engine_height, first_list)) = engine.masternode_lists.first_key_value() {
              let mut base_height = *first_engine_height;
              let mut base_hash = first_list.block_hash;
              
              for (validation_height, validation_hash) in validation_requests {
                  if validation_height > base_height {
                      // Request individual MnListDiff for validation
                      let mn_diff = self.request_masternode_diff(network, base_hash, validation_hash).await?;
                      
                      // Apply to engine
                      if let Err(e) = engine.apply_diff(mn_diff, Some(validation_height), false) {
                          self.error = Some(e.to_string());
                          return Err(SyncError::Validation(format!("Validation MnListDiff failed: {}", e)));
                      }
                      
                      // Update base for next request
                      base_height = validation_height;
                      base_hash = validation_hash;
                  }
              }
          }

          // Verify quorums after fetching validation diffs
          if let Some((tip_height, _)) = engine.masternode_lists.last_key_value() {
              engine.verify_non_rotating_masternode_list_quorums(
                  *tip_height, 
                  &[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85]
              ).map_err(|e| SyncError::Validation(format!("Quorum verification failed: {}", e)))?;
          }

          Ok(())
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
          // Create height resolution function with engine-first lookup
          let get_height_fn = {
              let engine_ref = engine as *const MasternodeListEngine;
              let block_height_cache = &self.block_height_cache;
              let storage_ref = storage as *const dyn StorageManager;
              
              move |block_hash: &BlockHash| -> Result<u32, String> {
                  // Check memory cache first for performance
                  if let Some(height) = block_height_cache.get(block_hash) {
                      return Ok(*height);
                  }
                  
                  // Check engine state first (most reliable)
                  unsafe {
                      if let Some(height) = (*engine_ref).block_heights.get(block_hash) {
                          return Ok(*height);
                      }
                  }
                  
                  // Fall back to storage lookup with proper error handling
                  unsafe {
                      (*storage_ref).get_block_height(block_hash)
                          .map_err(|e| format!("Height not found for block hash {}: {}", block_hash, e))
                  }
              }
          };

          // Create chain lock signature resolution function
          let get_chain_lock_sig_fn = {
              let chain_lock_cache = &self.chain_lock_signature_cache;
              let core_rpc_client = &self.core_rpc_client;
              
              move |block_hash: &BlockHash| -> Result<Option<ChainLockSignature>, String> {
                  // First check cache for performance
                  if let Some(sig) = chain_lock_cache.get(block_hash) {
                      return Ok(Some(sig.clone()));
                  }
                  
                  // Extract chain lock signature from coinbase
                  match core_rpc_client.get_block(block_hash) {
                      Ok(block) => {
                          let Some(coinbase) = block.coinbase()
                              .and_then(|coinbase| coinbase.special_transaction_payload.as_ref())
                              .and_then(|payload| payload.clone().to_coinbase_payload().ok()) else {
                              return Err(format!("Coinbase not found on block hash {}", block_hash));
                          };
                          
                          // Extract best_cl_signature from coinbase
                          Ok(coinbase.best_cl_signature.map(|sig| sig.to_bytes().into()))
                      }
                      Err(e) => {
                          tracing::debug!("Chain lock signature fetch failed for {}: {}", block_hash, e);
                          Ok(None) // Graceful degradation - continue without signature
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

              // Use engine's native QRInfo processing with controlled parameters
              // Note: apply_all_diffs = false for controlled processing
              if let Err(e) = engine.feed_qr_info(qr_info, false, Some(get_height_fn), Some(get_chain_lock_sig_fn)) {
                  self.error = Some(e.to_string());
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

              // Use engine's native diff processing with proper error handling
              if let Err(e) = engine.apply_diff(
                  mn_list_diff, 
                  Some(mn_diff_request.tip_height),  // Use Some(height) variant
                  false  // save_to_cache = false for controlled caching
              ) {
                  self.error = Some(e.to_string());
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
      
      /// Feed chain lock signatures using engine discovery
      async fn feed_qr_info_chain_lock_signatures(&mut self, qr_info: &QRInfo) -> SyncResult<()> {
          let engine = self.engine.as_mut().ok_or(SyncError::Configuration("Engine not initialized".to_string()))?;
          
          // Use engine's discovery method to determine required chain lock signatures
          let required_heights = match engine.required_cl_sig_heights(qr_info) {
              Ok(heights) => heights,
              Err(e) => {
                  self.error = Some(e.to_string());
                  return Err(SyncError::Validation(format!("Chain lock height discovery failed: {}", e)));
              }
          };
          
          tracing::debug!("Engine discovered {} required chain lock signature heights", required_heights.len());
          
          // Feed chain lock signatures for discovered heights
          for height in required_heights {
              let block_hash = self.get_block_hash_for_height(height).await?;
              if let Ok(Some(chain_lock_sig)) = self.fetch_chain_lock_signature_by_hash(&block_hash).await {
                  engine.feed_chain_lock_sig(block_hash, chain_lock_sig);
                  tracing::trace!("Fed chain lock signature for height {} hash {}", height, block_hash);
              } else {
                  tracing::debug!("No chain lock signature available for height {} hash {}", height, block_hash);
              }
          }
          
          // Fallback method: Get required chain lock hashes directly from quorum snapshots
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
      
      /// Get height for block hash with engine-first lookup
      async fn get_height_for_block_hash(&self, block_hash: &BlockHash) -> SyncResult<u32> {
          // Check memory cache first
          if let Some(height) = self.block_height_cache.get(block_hash) {
              return Ok(*height);
          }
          
          // Check engine state first (most efficient)
          if let Some(engine) = &self.engine {
              if let Some(height) = engine.block_heights.get(block_hash) {
                  // Cache the result for future use
                  self.block_height_cache.insert(*block_hash, *height);
                  return Ok(*height);
              }
          }
          
          // Fall back to storage lookup
          match self.storage.get_block_height(block_hash).await {
              Ok(height) => {
                  self.block_height_cache.insert(*block_hash, height);
                  Ok(height)
              }
              Err(e) => {
                  tracing::debug!("Height lookup failed for block hash {}: {}", block_hash, e);
                  Err(SyncError::Validation(format!("Height not found for block hash {}: {}", block_hash, e)))
              }
          }
      }
      
      /// Get block hash for height with engine-first lookup
      async fn get_block_hash_for_height(&self, height: u32) -> SyncResult<BlockHash> {
          // Check engine state first (most efficient)
          if let Some(engine) = &self.engine {
              if let Some(block_hash) = engine.block_hashes.get(&height) {
                  // Cache the result for future use
                  self.block_height_cache.insert(*block_hash, height);
                  return Ok(*block_hash);
              }
          }
          
          // Fall back to storage lookup
          match self.storage.get_block_hash(height).await {
              Ok(block_hash) => {
                  self.block_height_cache.insert(block_hash, height);
                  Ok(block_hash)
              }
              Err(e) => {
                  tracing::debug!("Block hash lookup failed for height {}: {}", height, e);
                  Err(SyncError::Validation(format!("Block hash not found for height {}: {}", height, e)))
              }
          }
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
      /// QRInfo requests for bulk sync ranges
      pub qr_info_requests: Vec<QRInfoRequest>,

      /// Individual MnListDiff requests for targeted updates
      pub mn_diff_requests: Vec<MnDiffRequest>,

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
      pub reason: String, // Request rationale for debugging
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
              rotating_validation_needed: self.detect_rotation_requirements(&discovery),
              estimated_completion_time: self.estimate_hybrid_sync_time(&qr_info_requests, &mn_diff_requests),
              strategy_reason: strategy_reasons.join("; "),
          }
      }

      /// Detect if rotating quorum validation is needed
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
                      
                      // Create height resolution function with engine-first lookup
                      let get_height_fn = {
                          let cache = &self.masternode_sync.block_height_cache;
                          let engine_ref = engine as *const MasternodeListEngine;
                          
                          move |block_hash: &BlockHash| -> Result<u32, String> {
                              // Check cache first
                              if let Some(height) = cache.get(block_hash).copied() {
                                  return Ok(height);
                              }
                              
                              // Check engine state first
                              unsafe {
                                  if let Some(height) = (*engine_ref).block_heights.get(block_hash) {
                                      return Ok(*height);
                                  }
                              }
                              
                              Err(format!("Height not found for block hash: {}", block_hash))
                          }
                      };
                      
                      // Process QRInfo with correct parameters
                      if let Err(e) = engine.feed_qr_info(qr_info, false, Some(get_height_fn), None) {
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

  5.1 Essential Support Methods (ENHANCED from DMLviewer.patch)

  File: dash-spv/src/sync/masternodes.rs

  impl MasternodeSyncManager {
      /// CRITICAL: Enhanced block height cache with engine integration (from DMLviewer.patch)
      pub struct BlockHeightCache {
          cache: HashMap<BlockHash, u32>,
          storage: Arc<dyn StorageManager>,
          engine_ref: Option<*const MasternodeListEngine>, // Direct reference to engine state
      }

      impl BlockHeightCache {
          pub fn get(&self, block_hash: &BlockHash) -> Option<u32> {
              // Check memory cache first
              if let Some(height) = self.cache.get(block_hash) {
                  return Some(*height);
              }
              
              // CRITICAL: Check engine state first (most reliable, from DMLviewer.patch)
              if let Some(engine_ref) = self.engine_ref {
                  unsafe {
                      if let Some(height) = (*engine_ref).block_heights.get(block_hash) {
                          // Cache the result for future use
                          self.cache.insert(*block_hash, *height);
                          return Some(*height);
                      }
                  }
              }
              
              // Fall back to storage lookup and cache result
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
          
          /// ADDED: Set engine reference for enhanced lookups
          pub fn set_engine_ref(&mut self, engine: &MasternodeListEngine) {
              self.engine_ref = Some(engine as *const MasternodeListEngine);
          }
      }

      /// ENHANCED: Chain lock signature management with coinbase extraction (from DMLviewer.patch)
      pub async fn fetch_chain_lock_signature(&self, height: u32) -> SyncResult<Option<ChainLockSignature>> {
          // Get block hash for this height
          let block_hash = self.get_block_hash_for_height(height).await?;
          
          // Check cache first
          if let Some(sig) = self.chain_lock_signature_cache.get(&block_hash) {
              return Ok(Some(sig.clone()));
          }
          
          // CRITICAL: Extract from coinbase using Core RPC (DMLviewer.patch pattern)
          match self.core_rpc_client.get_block(&block_hash).await {
              Ok(block) => {
                  let Some(coinbase) = block.coinbase()
                      .and_then(|coinbase| coinbase.special_transaction_payload.as_ref())
                      .and_then(|payload| payload.clone().to_coinbase_payload().ok()) else {
                      tracing::debug!("No coinbase found on block hash {} at height {}", block_hash, height);
                      return Ok(None);
                  };
                  
                  // Extract best_cl_signature from coinbase
                  let signature = coinbase.best_cl_signature.map(|sig| sig.to_bytes().into());
                  
                  // Cache the result (including None)
                  self.chain_lock_signature_cache.insert(block_hash, signature.clone());
                  
                  Ok(signature)
              }
              Err(e) => {
                  tracing::warn!("Failed to fetch block for chain lock signature at height {}: {}", height, e);
                  Ok(None) // Graceful degradation - not all blocks have chain lock signatures
              }
          }
      }

      /// CRITICAL: Check if QRInfo requires chain lock validation
      pub fn needs_chain_lock_validation(&self, qr_info: &QRInfo) -> bool {
          // Check if any quorum snapshots indicate rotating quorums
          !qr_info.quorum_snapshot_at_h_minus_c.is_empty() ||
          !qr_info.quorum_snapshot_at_h_minus_2c.is_empty() ||
          !qr_info.quorum_snapshot_at_h_minus_3c.is_empty() ||
          qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some()
      }

      /// ENHANCED: Response timeout handling with comprehensive error tracking (from DMLviewer.patch)
      pub async fn wait_for_qr_info_response_with_timeout(&mut self, timeout: Duration) -> SyncResult<QRInfo> {
          let start_time = std::time::Instant::now();
          
          while start_time.elapsed() < timeout {
              if let Some(qr_info) = self.pending_qr_info_responses.pop_front() {
                  return Ok(qr_info);
              }
              
              // Check for network messages with error handling
              match self.network.try_receive_message().await {
                  Ok(message) => {
                      match message {
                          NetworkMessage::QRInfo(qr_info) => {
                              return Ok(qr_info);
                          }
                          NetworkMessage::Reject(reject) => {
                              // CRITICAL: Handle rejection messages (from DMLviewer.patch)
                              return Err(SyncError::Network(format!("QRInfo request rejected: {:?}", reject)));
                          }
                          _ => {
                              // Handle other messages or queue them
                              self.handle_other_network_message(message).await?;
                          }
                      }
                  }
                  Err(e) => {
                      // Network error - continue waiting unless critical
                      tracing::debug!("Network receive error while waiting for QRInfo: {}", e);
                  }
              }
              
              tokio::time::sleep(Duration::from_millis(10)).await;
          }
          
          // CRITICAL: Set error state on timeout (DMLviewer.patch pattern)
          self.error = Some(format!("QRInfo request timed out after {:?}", timeout));
          Err(SyncError::Timeout(format!("QRInfo request timed out after {:?}", timeout)))
      }
      
      /// ADDED: Handle other network messages during QRInfo wait
      async fn handle_other_network_message(&mut self, message: NetworkMessage) -> SyncResult<()> {
          // Queue non-QRInfo messages for later processing or handle immediately
          match message {
              NetworkMessage::MnListDiff(diff) => {
                  self.pending_mn_diff_responses.push_back(diff);
              }
              _ => {
                  // Log unexpected messages during QRInfo wait
                  tracing::debug!("Received unexpected message during QRInfo wait: {:?}", message);
              }
          }
          Ok(())
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
      
      /// ENHANCED: Cache management with engine integration (from DMLviewer.patch)
      async fn cache_block_height(&mut self, block_hash: &BlockHash, height: u32) -> Result<(), StorageError>;
      async fn cache_chain_lock_signature(&mut self, block_hash: &BlockHash, signature: ChainLockSignature) -> Result<(), StorageError>;
      
      /// ADDED: Engine state inspection for debugging
      async fn get_engine_masternode_count(&self) -> Result<usize, StorageError>;
      async fn get_engine_block_hash_count(&self) -> Result<usize, StorageError>;
      async fn validate_engine_consistency(&self) -> Result<bool, StorageError>;
      
      /// ADDED: Engine cache clearing (equivalent to DMLviewer.patch clear_keep_base)
      async fn clear_engine_cache_keep_base(&mut self) -> Result<(), StorageError>;
  }

  Phase 6: CRITICAL Error Handling Integration (NEW from DMLviewer.patch)

  Duration: 1 day

  6.1 Comprehensive Error State Management

  File: dash-spv/src/sync/masternodes.rs

  impl MasternodeSyncManager {
      /// CRITICAL: Error state management (from DMLviewer.patch)
      pub error: Option<String>,
      
      /// Set error state and propagate (DMLviewer.patch pattern)
      fn set_error(&mut self, error: String) {
          self.error = Some(error.clone());
          tracing::error!("Masternode sync error: {}", error);
      }
      
      /// Check for errors before proceeding with operations
      fn check_error_state(&self) -> SyncResult<()> {
          if let Some(error) = &self.error {
              return Err(SyncError::Validation(error.clone()));
          }
          Ok(())
      }
      
      /// Clear error state for retry operations
      pub fn clear_error(&mut self) {
          self.error = None;
      }
  }

  6.2 Engine Operation Error Patterns

  ALL engine operations must follow this pattern:
  ```rust
  // Before any engine operation
  self.check_error_state()?;
  
  // Engine operation with immediate error checking
  if let Err(e) = engine.feed_qr_info(qr_info, false, Some(get_height_fn), Some(get_chain_lock_sig_fn)) {
      self.set_error(e.to_string());
      return Err(SyncError::Validation(format!("QRInfo processing failed: {}", e)));
  }
  
  // Continue only if no errors
  ```

  Phase 7: Testing Strategy (ENHANCED from DMLviewer.patch)

  Duration: 2 days

  7.1 Engine-Native Integration Tests

  File: dash-spv/tests/engine_native_sync_integration_test.rs

  #[tokio::test]
  async fn test_engine_native_qr_info_processing() {
      // Test engine's native feed_qr_info() method with proper error handling
      let config = ClientConfig::testnet();
      let mut client = DashSpvClient::new(config).await.unwrap();

      // Mock network to provide QRInfo with embedded MnListDiffs
      client.setup_qr_info_network_mock().await;

      client.start().await.unwrap();
      
      // Check for errors during processing
      if let Some(error) = client.get_sync_error().await {
          panic!("Sync failed with error: {}", error);
      }

      // Monitor engine state directly
      let engine_state = client.get_masternode_engine_state().await.unwrap();
      
      // Verify engine processed QRInfo correctly
      assert!(!engine_state.masternode_lists.is_empty(), "Engine should have processed masternode lists");
      assert!(!engine_state.block_hashes.is_empty(), "Engine should have tracked block hashes");
      
      // Verify engine-first height resolution works
      for (height, block_hash) in &engine_state.block_hashes {
          assert_eq!(engine_state.block_heights.get(block_hash), Some(height), 
                    "Bidirectional height-hash mapping should be consistent");
      }
      
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
  async fn test_engine_native_mn_diff_processing() {
      // Test engine's native apply_diff() for individual updates
      let config = ClientConfig::testnet();
      let mut client = DashSpvClient::new(config).await.unwrap();

      // Mock network to provide strategic mix requiring individual MnListDiffs
      client.setup_individual_mn_diff_network().await;

      client.start().await.unwrap();

      let engine_state = client.get_masternode_engine_state().await.unwrap();
      
      // Verify engine processed individual MnListDiffs correctly
      assert!(!engine_state.masternode_lists.is_empty(), "Engine should have processed individual diffs");
      
      // Verify all heights were covered by individual MnListDiffs
      let processed_heights: Vec<u32> = engine_state.masternode_lists.keys().cloned().collect();
      assert!(processed_heights.windows(2).all(|w| w[1] - w[0] <= 1), 
              "Individual MnListDiffs should process sequential heights");

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
  ## Implementation Timeline

  | Day  | Phase                     | Deliverables                                      |
  |------|---------------------------|---------------------------------------------------|
  | 1-2  | Legacy Analysis           | Identify keep vs remove, preserve MnListDiff core |
  | 3-5  | Enhanced Hybrid Integration | Engine-driven entry point with proper error handling |
  | 6    | Message Routing           | Support both QRInfo and MnListDiff with correct params |
  | 7    | Progress Tracking         | Hybrid progress reporting                         |
  | 8    | Critical Helper Methods   | Engine-first height resolution, coinbase chain lock extraction |
  | 9    | Error Handling Integration | Comprehensive error state management (DMLviewer.patch) |
  | 10-11| Enhanced Testing          | Engine-native tests with error handling validation |

  Total Duration: 11 days

  ## Critical Success Factors (From DMLviewer.patch Analysis)

  1. **Correct Engine Method Signatures**: 
     - `feed_qr_info(qr_info, false, Some(get_height_fn), Some(get_chain_lock_sig_fn))`
     - `apply_diff(diff, Some(height), false)` with save_to_cache = false

  2. **Engine-First Data Resolution**:
     - Always check `engine.block_heights` and `engine.block_hashes` before storage
     - Implement bidirectional caching with engine integration

  3. **Chain Lock Signature Discovery**:
     - Use `engine.required_cl_sig_heights(qr_info)` for discovery
     - Extract signatures from coinbase `best_cl_signature` field

  4. **Comprehensive Error Handling**:
     - Set `self.error = Some(e.to_string())` on every engine operation failure
     - Check error state before proceeding with operations
     - Implement graceful degradation for non-critical failures

  5. **Performance Optimizations**:
     - Cache frequently accessed data with engine integration
     - Use engine state as primary data source
     - Implement proper cache clearing with `clear_keep_base` equivalent

  ## Risk Mitigation

  - **Method Signature Mismatches**: Validate all engine method calls against DMLviewer.patch patterns
  - **Missing Error Handling**: Implement comprehensive error state management
  - **Performance Degradation**: Use engine-first lookups for all height/hash resolution
  - **Chain Lock Validation Failures**: Implement proper coinbase signature extraction
  - **Memory Leaks**: Implement proper cache clearing and engine state management



