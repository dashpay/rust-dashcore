//! Query methods for peers, masternodes, and balances.
//!
//! This module contains:
//! - Peer queries (count, info, disconnect)
//! - Masternode queries (engine, list, quorums)
//! - Balance queries
//! - Filter availability checks

use crate::error::{MasternodeListNotCurrent, Result, SpvError};
use crate::network::NetworkManager;
use crate::sml_engine::MasternodeListEngine;
use crate::storage::PersistentBlockHeaderStorage;
use crate::sync::{SyncProgress, SyncState};
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::transaction::special_transaction::coinbase::CoinbasePayload;
use dashcore::QuorumHash;
use key_wallet_manager::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::DashSpvClient;
use hex_conservative::DisplayHex;

impl<W: WalletInterface, N: NetworkManager> DashSpvClient<W, N> {
    // ============ Peer Queries ============

    /// Get the number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.network.connected_count().await as usize
    }

    // ============ Masternode Queries ============

    /// Get a reference to the masternode list engine.
    /// Returns an error if the masternode engine is not initialized.
    pub(crate) fn masternode_list_engine(
        &self,
    ) -> Result<Arc<RwLock<MasternodeListEngine<PersistentBlockHeaderStorage>>>> {
        match self.masternode_engine {
            Some(ref masternode_engine) => Ok(masternode_engine.clone()),
            None => Err(SpvError::Config("Masternode list engine not initialized".to_string())),
        }
    }

    /// The newest masternode list, `None` while masternode sync is off or has
    /// not built a list yet.
    pub async fn latest_masternode_list(&self) -> Option<MasternodeList> {
        let engine = self.masternode_engine.as_ref()?;
        engine.read().await.latest_masternode_list().cloned()
    }

    /// Blocking twin of [`Self::latest_masternode_list`] for threads outside the
    /// async runtime, such as FFI callers.
    ///
    /// # Panics
    ///
    /// Panics when called from an async execution context, like
    /// [`RwLock::blocking_read`].
    pub fn latest_masternode_list_blocking(&self) -> Option<MasternodeList> {
        let engine = self.masternode_engine.as_ref()?;
        engine.blocking_read().latest_masternode_list().cloned()
    }

    /// The newest masternode list while it follows the chain: masternode sync caught up since
    /// the client started, and the list's `known_height` is at most two blocks below the header
    /// tip. Otherwise returns why the list is not current. Use it over
    /// [`Self::latest_masternode_list`] to act on what the network holds now.
    pub async fn current_masternode_list(
        &self,
    ) -> std::result::Result<MasternodeList, MasternodeListNotCurrent> {
        let engine = self.masternode_engine.as_ref().ok_or(MasternodeListNotCurrent::Disabled)?;
        // Holding the coordinator keeps `run` and `stop` from replacing the progress meanwhile.
        let coordinator = self.sync_coordinator.lock().await;
        let engine = engine.read().await;
        current_list(self.is_running(), &coordinator.progress(), engine.latest_masternode_list())
    }

    /// Blocking twin of [`Self::current_masternode_list`] for threads outside the async
    /// runtime, such as FFI callers.
    ///
    /// # Panics
    ///
    /// Panics when called from an async execution context, like
    /// [`RwLock::blocking_read`].
    pub fn current_masternode_list_blocking(
        &self,
    ) -> std::result::Result<MasternodeList, MasternodeListNotCurrent> {
        let engine = self.masternode_engine.as_ref().ok_or(MasternodeListNotCurrent::Disabled)?;
        let coordinator = self.sync_coordinator.blocking_lock();
        let engine = engine.blocking_read();
        current_list(self.is_running(), &coordinator.progress(), engine.latest_masternode_list())
    }

    /// The coinbase payload of the newest block a masternode list diff proved it
    /// in, `None` while masternode sync is off, has validated none yet, or has
    /// rolled it back after following a fork.
    ///
    /// It is not checked against the tip: after a restart it is the one stored
    /// before, until sync proves a newer one. It is current once
    /// `progress().masternodes()` has `state() == SyncState::Synced` and
    /// `current_height() >= block_header_tip_height()`. Even then, on the last
    /// block before a fork activates, its version follows the tip's rules, not
    /// the next block's ones that Core checks mempool transactions against.
    pub async fn latest_coinbase(&self) -> Option<CoinbasePayload> {
        let engine = self.masternode_engine.as_ref()?;
        engine.read().await.latest_coinbase().cloned()
    }

    /// Get a quorum entry by type and hash at a specific block height.
    ///
    /// Only heights the engine holds lists for resolve. It keeps lists within
    /// its retention window below its newest list, a few days of blocks, and
    /// right after a restart only up to the newest list it stored, until sync
    /// catches up with the tip.
    ///
    /// Returns `SpvError::QuorumLookupError` if the quorum is not found.
    pub async fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Result<QualifiedQuorumEntry> {
        let engine = self.masternode_list_engine()?;
        let quorum = engine
            .read()
            .await
            .quorum_entry_for_hash_at_or_before_height(quorum_type, quorum_hash, height)
            .map(|(_, quorum)| quorum.clone());

        quorum.ok_or_else(|| {
            let message = format!(
                "Quorum not found: type {} at or before height {} with hash {}",
                quorum_type,
                height,
                quorum_hash.as_byte_array().to_lower_hex_string()
            );
            tracing::warn!("{}", message);
            SpvError::QuorumLookupError(message)
        })
    }
}

/// How many blocks the newest masternode list may trail the header tip and still be current.
/// The client requests a diff for every new tip, so the list trails only while one is in flight.
const MASTERNODE_LIST_TIP_TOLERANCE: u32 = 2;

/// Returns `list` if it is current for a client in `progress`, see
/// [`DashSpvClient::current_masternode_list`].
fn current_list(
    running: bool,
    progress: &SyncProgress,
    list: Option<&MasternodeList>,
) -> std::result::Result<MasternodeList, MasternodeListNotCurrent> {
    if !running {
        return Err(MasternodeListNotCurrent::NotRunning);
    }
    let headers_synced =
        progress.headers().is_ok_and(|headers| headers.state() == SyncState::Synced);
    let masternodes = progress
        .masternodes()
        .ok()
        .filter(|masternodes| headers_synced && masternodes.state() == SyncState::Synced);
    let (Some(masternodes), Some(list)) = (masternodes, list) else {
        return Err(MasternodeListNotCurrent::Syncing);
    };
    let tip = masternodes.block_header_tip_height();
    if list.known_height.saturating_add(MASTERNODE_LIST_TIP_TOLERANCE) < tip {
        return Err(MasternodeListNotCurrent::BehindTip {
            list_height: list.known_height,
            tip,
        });
    }
    Ok(list.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{BlockHeadersProgress, MasternodesProgress};
    use dashcore::BlockHash;

    const TIP: u32 = 1_000;

    fn progress(headers: SyncState, masternodes: SyncState) -> SyncProgress {
        let mut header_progress = BlockHeadersProgress::default();
        header_progress.set_state(headers);
        header_progress.update_tip_height(TIP);
        let mut masternode_progress = MasternodesProgress::default();
        masternode_progress.set_state(masternodes);
        masternode_progress.update_block_header_tip_height(TIP);
        let mut progress = SyncProgress::default();
        progress.update_headers(header_progress);
        progress.update_masternodes(masternode_progress);
        progress
    }

    fn list_at(height: u32) -> MasternodeList {
        MasternodeList::empty(BlockHash::all_zeros(), height)
    }

    #[test]
    fn a_list_within_two_blocks_of_the_tip_is_current() {
        let synced = progress(SyncState::Synced, SyncState::Synced);
        for height in [TIP - 2, TIP - 1, TIP] {
            let list = list_at(height);
            assert_eq!(current_list(true, &synced, Some(&list)), Ok(list));
        }
    }

    #[test]
    fn a_list_further_behind_the_tip_is_not_current() {
        let synced = progress(SyncState::Synced, SyncState::Synced);
        assert_eq!(
            current_list(true, &synced, Some(&list_at(TIP - 3))),
            Err(MasternodeListNotCurrent::BehindTip {
                list_height: TIP - 3,
                tip: TIP,
            })
        );
    }

    #[test]
    fn a_stored_list_is_not_current_before_sync_catches_up() {
        let list = list_at(TIP);
        for (headers, masternodes) in [
            (SyncState::Synced, SyncState::WaitingForConnections),
            (SyncState::Synced, SyncState::Syncing),
            (SyncState::Syncing, SyncState::Synced),
        ] {
            let progress = progress(headers, masternodes);
            assert_eq!(
                current_list(true, &progress, Some(&list)),
                Err(MasternodeListNotCurrent::Syncing)
            );
        }
        let synced = progress(SyncState::Synced, SyncState::Synced);
        assert_eq!(current_list(true, &synced, None), Err(MasternodeListNotCurrent::Syncing));
    }

    #[test]
    fn no_list_is_current_while_the_client_is_stopped() {
        let synced = progress(SyncState::Synced, SyncState::Synced);
        assert_eq!(
            current_list(false, &synced, Some(&list_at(TIP))),
            Err(MasternodeListNotCurrent::NotRunning)
        );
    }
}
