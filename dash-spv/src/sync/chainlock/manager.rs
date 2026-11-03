//! ChainLock manager for parallel sync.
//!
//! Handles ChainLock messages (clsig) from the network. A ChainLock is accepted
//! once a quorum the masternode engine holds as anchored signed it, and then
//! raises the engine's anchor: the block every list and quorum below it is
//! trusted from. Since ChainLocks are cumulative (all blocks below the best
//! ChainLock are implicitly locked), only the best accepted ChainLock is kept.

use std::sync::Arc;

use crate::sml_engine::{AnchorRoot, ChainLockAnchor, ChainLockVerdict, MasternodeListEngine};
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::hash_types::ChainLockHash;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::sync::RwLock;

use crate::error::SyncResult;
use crate::storage::{BlockHeaderStorage, MetadataStorage};
use crate::sync::{ChainLockProgress, SyncEvent, CHAINLOCK_ANCHOR_METADATA_STORAGE_KEY};

/// The best accepted ChainLock as persisted, with the root its trust descends
/// from, so a restart only trusts it where that root is trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PersistedChainLockAnchor {
    pub(crate) chain_lock: ChainLock,
    pub(crate) root: AnchorRoot,
}

/// ChainLock manager for the parallel sync coordinator.
///
/// This manager:
/// - Subscribes to CLSig messages from the network
/// - Validates ChainLocks only after masternode sync is complete
/// - Tracks only the best (highest) accepted ChainLock
/// - Emits ChainLockReceived events
pub struct ChainLockManager<H: BlockHeaderStorage, M: MetadataStorage> {
    /// Current progress of the manager.
    pub(super) progress: ChainLockProgress,
    /// Block header storage for hash verification.
    header_storage: Arc<RwLock<H>>,
    /// Metadata storage for persisting the best chainlock.
    metadata_storage: Arc<RwLock<M>>,
    /// Masternode engine, which verifies ChainLocks and holds the anchor.
    masternode_engine: Arc<RwLock<MasternodeListEngine<H>>>,
    /// The best (highest height) accepted ChainLock.
    best_chainlock: Option<ChainLock>,
    /// ChainLock hashes that have been requested (to avoid duplicate requests).
    pub(super) requested_chainlocks: HashSet<ChainLockHash>,
    /// Whether masternode sync is complete and we can validate signatures.
    pub(super) masternode_ready: bool,
    /// Chainlock that could not be decided yet: one that arrived before
    /// `masternode_ready`, one the engine could not check yet because the
    /// lists around its signing height or an anchored signer are missing, or
    /// one whose header has not been stored yet. Re-validated on every
    /// masternode state update, every accepted ChainLock and every header
    /// batch (see [`Self::revalidate_pending`]).
    pending_validation: Option<ChainLock>,
    /// Whether the signature of `pending_validation` verified.
    pending_verified: bool,
}

/// How a ChainLock's block hash compares with the stored header at its height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderMatch {
    Matches,
    Mismatch,
    /// The header is not stored yet, or storage failed to return it.
    Unknown,
}

impl<H: BlockHeaderStorage, M: MetadataStorage> ChainLockManager<H, M> {
    /// Create a new ChainLock manager.
    pub(crate) async fn new(
        header_storage: Arc<RwLock<H>>,
        metadata_storage: Arc<RwLock<M>>,
        masternode_engine: Arc<RwLock<MasternodeListEngine<H>>>,
    ) -> Self {
        let mut manager = Self {
            progress: ChainLockProgress::default(),
            header_storage,
            metadata_storage,
            masternode_engine,
            best_chainlock: None,
            requested_chainlocks: HashSet::new(),
            masternode_ready: false,
            pending_validation: None,
            pending_verified: false,
        };

        // TODO: Move load_best_chainlock() and save_best_chainlock() to MetadataStorage trait.
        manager.load_best_chainlock().await;

        manager
    }

    /// Apply the masternode-ready transition.
    ///
    /// Validates any chainlock cached in `pending_validation` (i.e. a
    /// chainlock that arrived before masternode state was available)
    /// and promotes it to `best_chainlock` on success. Returns the
    /// chainlock that should be re-broadcast to downstream consumers,
    /// preferring a freshly-promoted one over the persisted-from-disk
    /// `best_chainlock`. Returns `None` if there's nothing to surface.
    ///
    /// Re-checks the pending chainlock against its header before
    /// validating the BLS signature: at the time the chainlock was
    /// cached the header for that height may still have been missing,
    /// but by the time masternode state is ready the header has
    /// usually arrived. If the resolved header's hash disagrees with
    /// the chainlock's claimed block hash, the chainlock is dropped
    /// instead of moving the finality boundary onto a block the local
    /// chain doesn't match. While the header is still missing it stays
    /// pending.
    pub(super) async fn on_masternode_ready(&mut self) -> Option<ChainLock> {
        self.masternode_ready = true;
        self.revalidate_pending().await;
        self.best_chainlock.clone()
    }

    /// Re-validates the chainlock cached in `pending_validation` against the
    /// current masternode state and stored headers. Returns it if it validated
    /// and became the best chainlock. It stays cached while it cannot be
    /// decided yet.
    pub(super) async fn revalidate_pending(&mut self) -> Option<ChainLock> {
        let pending = self.pending_validation.take()?;
        if self
            .best_chainlock
            .as_ref()
            .is_some_and(|best| best.block_height >= pending.block_height)
        {
            return None;
        }

        if self.match_header(&pending).await == HeaderMatch::Mismatch {
            self.progress.add_invalid(1);
            return None;
        }

        let verdict = self.masternode_engine.write().await.accept_chain_lock(&pending).await;
        match verdict {
            ChainLockVerdict::Accepted => {
                self.adopt(&pending).await;
                Some(pending)
            }
            ChainLockVerdict::AwaitingHeader => {
                self.defer(&pending, true);
                None
            }
            ChainLockVerdict::Deferred(_) => {
                self.defer(&pending, false);
                None
            }
            ChainLockVerdict::Rejected(_) => {
                self.progress.add_invalid(1);
                None
            }
        }
    }

    /// Caches `chainlock` for a later retry in place of a lower one. One whose signature
    /// verified always takes the place of one whose signature did not, and never the reverse,
    /// so an unverified ChainLock can't evict a genuine one waiting for its header.
    fn defer(&mut self, chainlock: &ChainLock, verified: bool) {
        let replace = match &self.pending_validation {
            None => true,
            Some(_) if verified != self.pending_verified => verified,
            Some(existing) => chainlock.block_height > existing.block_height,
        };
        if replace {
            self.pending_validation = Some(chainlock.clone());
            self.pending_verified = verified;
        }
    }

    /// Makes `chainlock`, which the engine accepted, the best one and persists
    /// it with the root of its trust.
    async fn adopt(&mut self, chainlock: &ChainLock) {
        self.progress.add_valid(1);
        self.progress.update_best_validated_height(chainlock.block_height);
        self.best_chainlock = Some(chainlock.clone());
        self.save_best_chainlock().await;
    }

    /// Adopts a ChainLock another manager had the engine accept, such as one
    /// from a coinbase on the way up from a checkpoint, if it is the best yet.
    /// The engine's anchor may already be above it, raised by the next one.
    pub(super) async fn on_chain_lock_accepted(&mut self, chainlock: &ChainLock) {
        if self
            .best_chainlock
            .as_ref()
            .is_some_and(|best| best.block_height >= chainlock.block_height)
        {
            return;
        }
        let covered = self
            .masternode_engine
            .read()
            .await
            .chain_lock_anchor()
            .is_some_and(|anchor| anchor.height >= chainlock.block_height);
        if covered && self.match_header(chainlock).await == HeaderMatch::Matches {
            self.adopt(chainlock).await;
        }
    }

    /// Process an incoming ChainLock message.
    pub(super) async fn process_chainlock(
        &mut self,
        chainlock: &ChainLock,
    ) -> SyncResult<Vec<SyncEvent>> {
        let height = chainlock.block_height;
        let block_hash = chainlock.block_hash;

        tracing::info!("Processing ChainLock for height {} hash {}", height, block_hash);

        // Skip if we already have a better or equal ChainLock
        if let Some(best) = &self.best_chainlock {
            if height <= best.block_height {
                tracing::debug!(
                    "Ignoring ChainLock at height {} (best is {})",
                    height,
                    best.block_height
                );
                return Ok(vec![]);
            }
        }

        // Verify block hash matches our chain (if we have the header)
        if self.match_header(chainlock).await == HeaderMatch::Mismatch {
            tracing::warn!("ChainLock hash mismatch at height {}, rejecting", height);
            return Ok(vec![]);
        }

        // Only validate once masternode sync is complete; until then the
        // chainlock is cached for the retry `on_masternode_ready` makes.
        if !self.masternode_ready {
            tracing::debug!(
                "Caching ChainLock at height {} for validation once masternode sync completes",
                height
            );
            self.defer(chainlock, false);
            return Ok(vec![SyncEvent::ChainLockReceived {
                chain_lock: chainlock.clone(),
                validated: false,
            }]);
        }

        let verdict = self.masternode_engine.write().await.accept_chain_lock(chainlock).await;
        let accepted = verdict == ChainLockVerdict::Accepted;
        match verdict {
            ChainLockVerdict::Accepted => {
                tracing::info!("ChainLock accepted for height {}", height);
                self.adopt(chainlock).await;
            }
            ChainLockVerdict::AwaitingHeader => {
                // A genuine signature does not make it ours: keep it pending until
                // the header arrives and its hash can be checked.
                tracing::debug!(
                    "Deferring ChainLock at height {} until its header is stored",
                    height
                );
                self.defer(chainlock, true);
            }
            ChainLockVerdict::Deferred(reason) => {
                tracing::debug!("Deferring ChainLock at height {}: {}", height, reason);
                self.defer(chainlock, false);
            }
            ChainLockVerdict::Rejected(reason) => {
                tracing::warn!("Rejecting ChainLock at height {}: {}", height, reason);
                self.progress.add_invalid(1);
            }
        }

        Ok(vec![SyncEvent::ChainLockReceived {
            chain_lock: chainlock.clone(),
            validated: accepted,
        }])
    }

    /// Persist the best chainlock to metadata storage, with the root the
    /// engine's anchor descends from.
    async fn save_best_chainlock(&self) {
        let Some(chainlock) = &self.best_chainlock else {
            return;
        };
        let Some(anchor) = self.masternode_engine.read().await.chain_lock_anchor() else {
            return;
        };
        let persisted = PersistedChainLockAnchor {
            chain_lock: chainlock.clone(),
            root: anchor.root,
        };
        match serde_json::to_vec(&persisted) {
            Ok(bytes) => {
                let mut storage = self.metadata_storage.write().await;
                if let Err(e) =
                    storage.store_metadata(CHAINLOCK_ANCHOR_METADATA_STORAGE_KEY, &bytes).await
                {
                    tracing::warn!("Failed to persist best chainlock: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize best chainlock: {}", e);
            }
        }
    }

    /// Load the best chainlock from metadata storage into the engine's anchor
    /// and restore progress. One the engine does not take as its anchor, such
    /// as one rooted in a first ChainLock on a network with checkpoints, is
    /// not restored.
    pub(super) async fn load_best_chainlock(&mut self) {
        let loaded = {
            let storage = self.metadata_storage.read().await;
            storage
                .load_metadata::<PersistedChainLockAnchor>(CHAINLOCK_ANCHOR_METADATA_STORAGE_KEY)
                .await
        };
        let persisted = match loaded {
            Ok(Some(persisted)) => persisted,
            Ok(None) => {
                tracing::debug!("No persisted chainlock found (fresh start)");
                return;
            }
            Err(e) => {
                tracing::warn!("Failed to load persisted chainlock: {}", e);
                return;
            }
        };
        let chain_lock = persisted.chain_lock;
        let anchor = ChainLockAnchor {
            height: chain_lock.block_height,
            block_hash: chain_lock.block_hash,
            root: persisted.root,
        };
        let mut engine = self.masternode_engine.write().await;
        engine.restore_chain_lock_anchor(anchor);
        if engine.chain_lock_anchor() == Some(anchor) {
            tracing::info!("Restored persisted ChainLock at height {}", anchor.height);
            self.progress.update_best_validated_height(anchor.height);
            self.best_chainlock = Some(chain_lock);
        }
    }

    /// Compares the ChainLock block hash with our stored header at its height.
    async fn match_header(&self, chainlock: &ChainLock) -> HeaderMatch {
        let storage = self.header_storage.read().await;
        match storage.get_header(chainlock.block_height).await {
            Ok(Some(header)) if *header.hash() == chainlock.block_hash => HeaderMatch::Matches,
            Ok(Some(_)) => HeaderMatch::Mismatch,
            Ok(None) => HeaderMatch::Unknown,
            Err(e) => {
                tracing::warn!(
                    "Storage error checking ChainLock header at height {}: {}",
                    chainlock.block_height,
                    e
                );
                HeaderMatch::Unknown
            }
        }
    }
}

impl<H: BlockHeaderStorage, M: MetadataStorage> std::fmt::Debug for ChainLockManager<H, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainLockManager")
            .field("progress", &self.progress)
            .field("best_height", &self.best_chainlock.as_ref().map(|cl| cl.block_height))
            .field("masternode_ready", &self.masternode_ready)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{MessageType, NetworkManager};
    use crate::sml_engine::anchor::test_support::{
        anchor_at_newest_list, checkpoint_root, forge_chain_lock_above_the_newest_list,
    };
    use crate::sml_engine::test_support::TestEngine;
    use crate::sml_engine::{AnchorRoot, ChainLockAnchor, ChainLockVerdict};
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentMetadataStorage, StorageManager,
    };
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress, SyncState};
    use crate::sync::{BEST_CHAINLOCK_METADATA_STORAGE_KEY, CHAINLOCK_ANCHOR_METADATA_STORAGE_KEY};
    use crate::test_utils::MockNetworkManager;
    use crate::Network;
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::hashes::Hash;
    use dashcore::sml::masternode_list::MasternodeList;
    use dashcore::BlockHash;
    use test_case::test_case;

    type TestChainLockManager =
        ChainLockManager<PersistentBlockHeaderStorage, PersistentMetadataStorage>;

    async fn create_test_manager() -> TestChainLockManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let engine = Arc::new(RwLock::new(MasternodeListEngine::new(
            Network::Testnet,
            storage.block_headers(),
        )));
        ChainLockManager::new(storage.block_headers(), storage.metadata(), engine).await
    }

    async fn create_test_manager_with_storage(
        storage: &DiskStorageManager,
    ) -> TestChainLockManager {
        let engine = Arc::new(RwLock::new(MasternodeListEngine::new(
            Network::Testnet,
            storage.block_headers(),
        )));
        ChainLockManager::new(storage.block_headers(), storage.metadata(), engine).await
    }

    fn create_test_chainlock(height: u32) -> ChainLock {
        ChainLock {
            block_height: height,
            block_hash: BlockHash::all_zeros(),
            signature: BLSSignature::from([0u8; 96]),
        }
    }

    #[tokio::test]
    async fn test_chainlock_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::ChainLock);
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert_eq!(manager.wanted_message_types(), [MessageType::ChainLock, MessageType::Inv]);
    }

    /// Buffered `MasternodeStateUpdated` events delivered during
    /// `WaitingForConnections` must not force a `Synced` transition.
    /// `MasternodesManager` re-emits the event once it completes its next
    /// sync cycle after reconnect, so dropping it here is safe.
    #[tokio::test]
    async fn test_handle_sync_event_drops_masternode_state_updated_in_waiting_for_connections() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::WaitingForConnections);

        let event = SyncEvent::MasternodeStateUpdated {
            height: 100,
            qr_info_result: None,
        };
        let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());
        let events = manager.handle_sync_event(&event, &network).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert!(!manager.masternode_ready);
    }

    #[tokio::test]
    async fn test_chainlock_skips_validation_before_masternode_ready() {
        let mut manager = create_test_manager().await;

        // Before masternode sync, ChainLocks should not be validated
        let chainlock = create_test_chainlock(100);
        let events = manager.process_chainlock(&chainlock).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(manager.progress.valid(), 0);
        assert_eq!(manager.progress.invalid(), 0);
        assert!(manager.best_chainlock.as_ref().is_none());
        // But the chainlock must be cached for retry once masternode
        // state arrives, rather than discarded.
        assert!(manager.pending_validation.is_some());
    }

    #[tokio::test]
    async fn test_pending_validation_keeps_highest() {
        let mut manager = create_test_manager().await;

        // Lower height first, then higher — pending_validation tracks
        // the highest seen pre-ready chainlock so the retry on
        // masternode-ready always validates the most recent.
        let _ = manager.process_chainlock(&create_test_chainlock(100)).await.unwrap();
        let _ = manager.process_chainlock(&create_test_chainlock(200)).await.unwrap();
        let _ = manager.process_chainlock(&create_test_chainlock(150)).await.unwrap();

        assert_eq!(manager.pending_validation.as_ref().map(|cl| cl.block_height), Some(200));
    }

    #[tokio::test]
    async fn test_on_masternode_ready_rejects_pending_chainlock_on_block_hash_mismatch() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let mut manager = create_test_manager_with_storage(&storage).await;

        // Cache a chainlock for height 100 BEFORE any header exists.
        // It can't be checked against a header yet, so it lands in
        // `pending_validation`.
        let _ = manager.process_chainlock(&create_test_chainlock(100)).await.unwrap();
        assert!(manager.pending_validation.is_some());

        // Header for height 100 resolves later with a hash that differs
        // from the cached chainlock's `BlockHash::all_zeros()`. The
        // readiness transition must re-check the header and
        // drop the chainlock instead of moving the finality boundary.
        let header = dashcore::block::Header::dummy(100);
        storage
            .block_headers()
            .write()
            .await
            .store_headers_at_height(&[crate::types::HashedBlockHeader::from(header)], 100)
            .await
            .expect("store header at 100");

        let rebroadcast = manager.on_masternode_ready().await;
        assert!(rebroadcast.is_none(), "mismatched chainlock must not be re-broadcast");
        assert!(
            manager.best_chainlock.as_ref().is_none(),
            "mismatched chainlock must not be persisted"
        );
        assert!(manager.pending_validation.is_none(), "pending_validation must be consumed");
        assert_eq!(manager.progress.invalid(), 1);
        assert_eq!(manager.progress.valid(), 0);
    }

    #[tokio::test]
    async fn test_on_masternode_ready_retries_pending_validation() {
        let mut manager = create_test_manager().await;
        let _ = manager.process_chainlock(&create_test_chainlock(100)).await.unwrap();
        assert!(manager.pending_validation.is_some());

        // With the default empty engine, validation fails — the
        // pending chainlock is consumed (cleared) and counted as
        // invalid; `best_chainlock` stays `None`.
        let rebroadcast = manager.on_masternode_ready().await;
        assert!(rebroadcast.is_none());
        assert!(manager.pending_validation.is_none());
        assert!(manager.best_chainlock.as_ref().is_none());
        assert_eq!(manager.progress.invalid(), 1);
        assert!(manager.masternode_ready);
    }

    #[tokio::test]
    async fn test_chainlock_validates_after_masternode_ready() {
        let mut manager = create_test_manager().await;
        let _ = manager.on_masternode_ready().await;

        // After masternode sync, ChainLocks should be validated (will fail with empty engine)
        let chainlock = create_test_chainlock(100);
        let _ = manager.process_chainlock(&chainlock).await.unwrap();

        assert_eq!(manager.progress.invalid(), 1);
        assert_eq!(manager.progress.valid(), 0);
    }

    #[tokio::test]
    async fn test_chainlock_signed_above_the_newest_list_is_not_accepted() {
        let mut manager = create_test_manager().await;
        manager
            .masternode_engine
            .write()
            .await
            .masternode_lists
            .insert(100, MasternodeList::empty(BlockHash::all_zeros(), 100));
        let _ = manager.on_masternode_ready().await;

        let events = manager.process_chainlock(&create_test_chainlock(1_000)).await.unwrap();

        assert!(matches!(
            events.as_slice(),
            [SyncEvent::ChainLockReceived {
                validated: false,
                ..
            }]
        ));
        assert!(manager.best_chainlock.as_ref().is_none());
        assert_eq!(manager.progress.invalid(), 0);
        assert_eq!(manager.pending_validation.as_ref().map(|cl| cl.block_height), Some(1_000));
    }

    #[tokio::test]
    async fn test_deferred_chainlock_is_rejected_once_lists_reach_it() {
        let mut manager = create_test_manager().await;
        manager
            .masternode_engine
            .write()
            .await
            .masternode_lists
            .insert(100, MasternodeList::empty(BlockHash::all_zeros(), 100));
        let _ = manager.on_masternode_ready().await;
        let _ = manager.process_chainlock(&create_test_chainlock(1_000)).await.unwrap();

        let event = SyncEvent::MasternodeStateUpdated {
            height: 500,
            qr_info_result: None,
        };
        let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());
        assert!(manager.handle_sync_event(&event, &network).await.unwrap().is_empty());
        assert_eq!(manager.progress.invalid(), 0);
        assert!(manager.pending_validation.is_some());

        manager
            .masternode_engine
            .write()
            .await
            .masternode_lists
            .insert(1_000, MasternodeList::empty(BlockHash::all_zeros(), 1_000));
        let event = SyncEvent::MasternodeStateUpdated {
            height: 1_000,
            qr_info_result: None,
        };
        assert!(manager.handle_sync_event(&event, &network).await.unwrap().is_empty());
        assert_eq!(manager.progress.invalid(), 1);
        assert!(manager.pending_validation.is_none());
        assert!(manager.best_chainlock.as_ref().is_none());
    }

    #[tokio::test]
    async fn test_chainlock_below_the_newest_list_is_rejected_immediately() {
        let mut manager = create_test_manager().await;
        manager
            .masternode_engine
            .write()
            .await
            .masternode_lists
            .insert(2_000, MasternodeList::empty(BlockHash::all_zeros(), 2_000));
        let _ = manager.on_masternode_ready().await;

        let _ = manager.process_chainlock(&create_test_chainlock(1_000)).await.unwrap();

        assert_eq!(manager.progress.invalid(), 1);
        assert!(manager.pending_validation.is_none());
    }

    /// A genuine ChainLock is only accepted once its header is stored and matches, and a
    /// forged one received meanwhile does not evict it.
    #[test_case(true, false; "header matches")]
    #[test_case(false, false; "header mismatches")]
    #[test_case(true, true; "forged chainlock in between")]
    #[tokio::test]
    async fn test_genuine_chainlock_waits_for_its_header(header_matches: bool, forged: bool) {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let headers = engine.headers();
        let engine = Arc::new(RwLock::new(engine));
        let mut manager = ChainLockManager::new(headers, storage.metadata(), engine.clone()).await;
        let _ = manager.on_masternode_ready().await;

        let [chain_lock, _] = ChainLock::mainnet_fixture_pair();
        let events = manager.process_chainlock(&chain_lock).await.unwrap();
        assert!(matches!(
            events.as_slice(),
            [SyncEvent::ChainLockReceived {
                validated: false,
                ..
            }]
        ));
        assert!(manager.best_chainlock.as_ref().is_none());
        assert!(manager.pending_validation.is_some());

        if forged {
            // Signed by no quorum, above the newest masternode list.
            let forged = create_test_chainlock(chain_lock.block_height + 10_000);
            let _ = manager.process_chainlock(&forged).await.unwrap();
            assert_eq!(manager.pending_validation, Some(chain_lock.clone()));
        }

        let block_hash = if header_matches {
            chain_lock.block_hash
        } else {
            BlockHash::all_zeros()
        };
        engine.write().await.feed_block_height(chain_lock.block_height, block_hash);
        let event = SyncEvent::BlockHeadersStored {
            tip_height: chain_lock.block_height,
        };
        let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());
        let events = manager.handle_sync_event(&event, &network).await.unwrap();

        assert!(manager.pending_validation.is_none());
        if header_matches {
            assert!(matches!(
                events.as_slice(),
                [SyncEvent::ChainLockReceived {
                    validated: true,
                    ..
                }]
            ));
            assert_eq!(manager.best_chainlock.as_ref(), Some(&chain_lock));
        } else {
            assert!(events.is_empty());
            assert!(manager.best_chainlock.as_ref().is_none());
            assert_eq!(manager.progress.invalid(), 1);
        }
    }

    /// A peer serving headers no ChainLock covers can put a ChainLock quorum of
    /// its own in a list on them, keyed by a secret it holds, with a hash ground
    /// so DIP-8 selection picks it. Its DIP-6 status vouches only for members
    /// taken from that same list, so even `Verified` it must not lock a block.
    #[tokio::test]
    async fn a_chain_lock_signed_by_a_quorum_minted_above_the_anchor_is_not_accepted() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let forged = forge_chain_lock_above_the_newest_list(&mut engine);
        let headers = engine.headers();
        let engine = Arc::new(RwLock::new(engine));
        let mut manager = ChainLockManager::new(headers, storage.metadata(), engine).await;
        let _ = manager.on_masternode_ready().await;

        let events = manager.process_chainlock(&forged).await.unwrap();

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::ChainLockReceived {
                    validated: false,
                    ..
                }]
            ),
            "{events:?}"
        );
        assert!(manager.best_chainlock.as_ref().is_none());
        // Its quorum is not anchored yet, which only a ChainLock it did not
        // sign can change, so it waits rather than counting as invalid.
        assert_eq!(manager.pending_validation, Some(forged));
        assert_eq!(manager.progress.invalid(), 0);
    }

    /// The catch-up walk has the engine accept coinbase ChainLocks and
    /// announces them. The ChainLock manager makes such a ChainLock its best,
    /// persists it, so a restart does not walk again, and retries the
    /// ChainLock it holds pending, whose signer the walk may have anchored.
    #[tokio::test]
    async fn a_chain_lock_the_walk_accepted_is_adopted_persisted_and_unblocks_pending() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let mut engine = TestEngine::mainnet_fixture();
        let [first, second] = ChainLock::mainnet_fixture_pair();
        for chain_lock in [&first, &second] {
            engine.feed_block_height(chain_lock.block_height, chain_lock.block_hash);
        }
        anchor_at_newest_list(&mut engine);
        let headers = engine.headers();
        let engine = Arc::new(RwLock::new(engine));
        let mut manager =
            ChainLockManager::new(headers.clone(), storage.metadata(), engine.clone()).await;
        let _ = manager.on_masternode_ready().await;
        let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());

        assert_eq!(
            engine.write().await.accept_chain_lock(&first).await,
            ChainLockVerdict::Accepted
        );
        let accepted = SyncEvent::ChainLockReceived {
            chain_lock: first.clone(),
            validated: true,
        };
        assert!(manager.handle_sync_event(&accepted, &network).await.unwrap().is_empty());
        assert_eq!(manager.best_chainlock.as_ref(), Some(&first));
        let restarted =
            ChainLockManager::new(headers.clone(), storage.metadata(), engine.clone()).await;
        assert_eq!(restarted.best_chainlock.as_ref(), Some(&first), "persisted");

        manager.defer(&second, false);
        let events = manager.handle_sync_event(&accepted, &network).await.unwrap();
        assert!(matches!(
            events.as_slice(),
            [SyncEvent::ChainLockReceived { chain_lock, validated: true }] if *chain_lock == second
        ));
        assert_eq!(manager.best_chainlock.as_ref(), Some(&second));
    }

    #[tokio::test]
    async fn test_chainlock_keeps_only_best() {
        let mut manager = create_test_manager().await;

        // Manually set a best chainlock
        manager.best_chainlock = Some(create_test_chainlock(200));

        // Lower height should be ignored
        let chainlock_lower = create_test_chainlock(150);
        let events = manager.process_chainlock(&chainlock_lower).await.unwrap();
        assert_eq!(events.len(), 0);

        // Equal height should also be ignored
        let chainlock_equal = create_test_chainlock(200);
        let events = manager.process_chainlock(&chainlock_equal).await.unwrap();
        assert_eq!(events.len(), 0);

        // Higher height should be processed
        let chainlock_higher = create_test_chainlock(300);
        let events = manager.process_chainlock(&chainlock_higher).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_chainlock_progress() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);
        manager.progress.update_best_validated_height(500);
        manager.progress.add_valid(8);
        manager.progress.add_invalid(2);

        let progress = manager.progress();
        if let SyncManagerProgress::ChainLock(cp) = progress {
            assert_eq!(cp.state(), SyncState::Syncing);
            assert_eq!(cp.best_validated_height(), 500);
            assert_eq!(cp.valid(), 8);
            assert_eq!(cp.invalid(), 2);
        } else {
            panic!("Expected SyncManagerProgress::ChainLock");
        }
    }

    #[tokio::test]
    async fn test_load_from_empty_storage_returns_none() {
        let mut manager = create_test_manager().await;

        manager.load_best_chainlock().await;

        assert!(manager.best_chainlock.as_ref().is_none());
        assert_eq!(manager.progress.best_validated_height(), 0);
    }

    /// Makes `chainlock` the best one, as accepted under a checkpoint root.
    async fn set_best(manager: &mut TestChainLockManager, chainlock: &ChainLock) {
        manager.masternode_engine.write().await.restore_chain_lock_anchor(ChainLockAnchor {
            height: chainlock.block_height,
            block_hash: chainlock.block_hash,
            root: checkpoint_root(Network::Testnet),
        });
        manager.best_chainlock = Some(chainlock.clone());
    }

    async fn persist(storage: &DiskStorageManager, key: &str, value: &impl serde::Serialize) {
        let bytes = serde_json::to_vec(value).unwrap();
        storage.metadata().write().await.store_metadata(key, &bytes).await.unwrap();
    }

    #[tokio::test]
    async fn test_save_and_load_chainlock_round_trip() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let chainlock = create_test_chainlock(42000);

        // Save a chainlock via the first manager
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            set_best(&mut manager, &chainlock).await;
            manager.save_best_chainlock().await;
        }

        // Fresh manager sharing the same storage should load the chainlock automatically
        {
            let manager = create_test_manager_with_storage(&storage).await;

            let restored = manager.best_chainlock.as_ref().expect("chainlock should be restored");
            assert_eq!(restored.block_height, 42000);
            assert_eq!(restored.block_hash, chainlock.block_hash);
            assert_eq!(restored.signature, chainlock.signature);
            assert_eq!(manager.progress.best_validated_height(), 42000);
            let anchor = manager.masternode_engine.read().await.chain_lock_anchor();
            assert_eq!(anchor.map(|anchor| anchor.root), Some(checkpoint_root(Network::Testnet)));
        }
    }

    #[tokio::test]
    async fn test_initialize_restores_persisted_chainlock() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let chainlock = create_test_chainlock(99999);
        let persisted = PersistedChainLockAnchor {
            chain_lock: chainlock.clone(),
            root: checkpoint_root(Network::Testnet),
        };
        persist(&storage, CHAINLOCK_ANCHOR_METADATA_STORAGE_KEY, &persisted).await;

        // Create a new manager and call initialize (the SyncManager trait method)
        let manager = create_test_manager_with_storage(&storage).await;

        let restored =
            manager.best_chainlock.as_ref().expect("chainlock should be restored after initialize");
        assert_eq!(restored.block_height, 99999);
        assert_eq!(manager.progress.best_validated_height(), 99999);
        assert_eq!(manager.state(), SyncState::WaitForEvents);
    }

    /// Trust on a network with checkpoints starts at one. A ChainLock persisted
    /// before quorums had to be anchored, or one rooted in a first ChainLock,
    /// was accepted without that, so a restart must not trust it.
    #[tokio::test]
    async fn a_chain_lock_not_rooted_in_a_checkpoint_is_not_restored_on_testnet() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        persist(&storage, BEST_CHAINLOCK_METADATA_STORAGE_KEY, &create_test_chainlock(500)).await;
        let manager = create_test_manager_with_storage(&storage).await;
        assert!(manager.best_chainlock.as_ref().is_none());

        let persisted = PersistedChainLockAnchor {
            chain_lock: create_test_chainlock(600),
            root: AnchorRoot::FirstChainLock,
        };
        persist(&storage, CHAINLOCK_ANCHOR_METADATA_STORAGE_KEY, &persisted).await;
        let manager = create_test_manager_with_storage(&storage).await;
        assert!(manager.best_chainlock.as_ref().is_none());
        assert!(manager.masternode_engine.read().await.chain_lock_anchor().is_none());
    }

    #[tokio::test]
    async fn test_process_chainlock_persists_on_validation() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let mut manager = create_test_manager_with_storage(&storage).await;

        // Without masternode ready, chainlocks are not validated and not persisted
        let chainlock = create_test_chainlock(500);
        manager.process_chainlock(&chainlock).await.unwrap();
        assert!(manager.best_chainlock.as_ref().is_none());

        // Verify nothing was persisted
        {
            let meta_storage = storage.metadata();
            let meta = meta_storage.read().await;
            let loaded = meta
                .load_metadata::<PersistedChainLockAnchor>(CHAINLOCK_ANCHOR_METADATA_STORAGE_KEY)
                .await
                .unwrap();
            assert!(loaded.is_none());
        }
    }

    #[tokio::test]
    async fn test_save_overwrites_previous_chainlock() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();

        // Save first chainlock
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            set_best(&mut manager, &create_test_chainlock(100)).await;
            manager.save_best_chainlock().await;
        }

        // Save a higher chainlock
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            set_best(&mut manager, &create_test_chainlock(200)).await;
            manager.save_best_chainlock().await;
        }

        // Load and verify only the latest is stored
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            manager.load_best_chainlock().await;

            let restored = manager.best_chainlock.as_ref().expect("chainlock should be restored");
            assert_eq!(restored.block_height, 200);
        }
    }

    #[tokio::test]
    async fn test_lower_chainlock_rejected_after_load() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();

        // Save chainlock at height 200
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            set_best(&mut manager, &create_test_chainlock(200)).await;
            manager.save_best_chainlock().await;
        }

        // Load and try to process a lower chainlock
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            manager.load_best_chainlock().await;

            // Try to process a lower chainlock
            let lower_chainlock = create_test_chainlock(100);
            let events = manager.process_chainlock(&lower_chainlock).await.unwrap();

            // Should be rejected (no events)
            assert_eq!(events.len(), 0);

            // Best should still be 200
            let best = manager.best_chainlock.as_ref().expect("should have best chainlock");
            assert_eq!(best.block_height, 200);
        }
    }
}
