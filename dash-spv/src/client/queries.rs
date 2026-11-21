//! Query methods for peers, masternodes, and balances.
//!
//! This module contains:
//! - Peer queries (count, info, disconnect)
//! - Masternode queries (engine, list, quorums)
//! - Balance queries
//! - Filter availability checks

use crate::error::{MasternodeListNotCurrentError, Result, SpvError};
use crate::network::NetworkManager;
use crate::sml_engine::MasternodeListEngine;
use crate::storage::PersistentBlockHeaderStorage;
use crate::sync::{SyncProgress, SyncState};
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::transaction::special_transaction::coinbase::CoinbasePayload;
use dashcore::{Network, QuorumHash};
use key_wallet_manager::WalletInterface;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

    /// The newest masternode list while it follows the chain: header and masternode sync are
    /// caught up, the header tip is no older than [`MAINNET_MAX_TIP_AGE`] or
    /// [`TESTNET_MAX_TIP_AGE`], and the list's `known_height` is at most
    /// [`MASTERNODE_LIST_TIP_TOLERANCE`] blocks below the header tip. Otherwise returns why the
    /// list is not current. Use it over [`Self::latest_masternode_list`] to act on what the
    /// network holds now. The tip age is measured against the host clock: a clock running ahead
    /// reports `TipStale` early, and one running behind hides a stale tip. Regtest and devnets
    /// have no maximum tip age, so there a stalled header chain is not detected.
    pub async fn current_masternode_list(
        &self,
    ) -> std::result::Result<MasternodeList, MasternodeListNotCurrentError> {
        let engine =
            self.masternode_engine.as_ref().ok_or(MasternodeListNotCurrentError::Disabled)?;
        // Checked before the coordinator lock too, which `stop` holds until its tasks drain.
        if !self.is_running() {
            return Err(MasternodeListNotCurrentError::NotRunning);
        }
        let network = self.network().await;
        // Holding the coordinator keeps `run` and `stop` from replacing the progress meanwhile.
        let coordinator = self.sync_coordinator.lock().await;
        let engine = engine.read().await;
        current_list(
            self.is_running(),
            network,
            SystemTime::now(),
            &coordinator.progress(),
            engine.latest_masternode_list(),
        )
    }

    /// Blocking twin of [`Self::current_masternode_list`] for threads outside the async
    /// runtime, such as FFI callers. While the client stops, it can wait for the sync tasks to
    /// drain.
    ///
    /// # Panics
    ///
    /// Panics when called from an async execution context, like
    /// [`RwLock::blocking_read`].
    pub fn current_masternode_list_blocking(
        &self,
    ) -> std::result::Result<MasternodeList, MasternodeListNotCurrentError> {
        let engine =
            self.masternode_engine.as_ref().ok_or(MasternodeListNotCurrentError::Disabled)?;
        if !self.is_running() {
            return Err(MasternodeListNotCurrentError::NotRunning);
        }
        let network = self.config.blocking_read().network;
        let coordinator = self.sync_coordinator.blocking_lock();
        let engine = engine.blocking_read();
        current_list(
            self.is_running(),
            network,
            SystemTime::now(),
            &coordinator.progress(),
            engine.latest_masternode_list(),
        )
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

/// How many blocks the newest masternode list may trail the header tip and still be current,
/// see [`DashSpvClient::current_masternode_list`]. The client requests a diff for every new tip,
/// so the list trails only while one is in flight.
pub const MASTERNODE_LIST_TIP_TOLERANCE: u32 = 2;

/// How old the header tip may be on mainnet for its masternode list to be current. Blocks come
/// every 2.5 minutes, so a 30-minute gap means the client is not hearing of new blocks.
pub const MAINNET_MAX_TIP_AGE: Duration = Duration::from_secs(30 * 60);

/// How old the header tip may be on testnet for its masternode list to be current. Its low
/// hashrate leaves real gaps of over 30 minutes. Regtest and devnets mine on demand, so they
/// have no maximum tip age.
pub const TESTNET_MAX_TIP_AGE: Duration = Duration::from_secs(2 * 60 * 60);

/// Returns `list` if it is current for a client on `network` in `progress` at `now`, see
/// [`DashSpvClient::current_masternode_list`].
fn current_list(
    running: bool,
    network: Network,
    now: SystemTime,
    progress: &SyncProgress,
    list: Option<&MasternodeList>,
) -> std::result::Result<MasternodeList, MasternodeListNotCurrentError> {
    if !running {
        return Err(MasternodeListNotCurrentError::NotRunning);
    }
    let Ok(masternodes) = progress.masternodes() else {
        return Err(MasternodeListNotCurrentError::Disabled);
    };
    let headers = progress.headers().ok().filter(|headers| {
        headers.state() == SyncState::Synced && masternodes.state() == SyncState::Synced
    });
    let (Some(headers), Some(list)) = (headers, list) else {
        return Err(MasternodeListNotCurrentError::Syncing);
    };
    let max_tip_age = match network {
        Network::Mainnet => Some(MAINNET_MAX_TIP_AGE),
        Network::Testnet => Some(TESTNET_MAX_TIP_AGE),
        _ => None,
    };
    let tip_time = UNIX_EPOCH + Duration::from_secs(headers.tip_time().into());
    if max_tip_age.is_some_and(|max| now.duration_since(tip_time).is_ok_and(|age| age > max)) {
        return Err(MasternodeListNotCurrentError::TipStale {
            tip_time: headers.tip_time(),
        });
    }
    let tip = headers.tip_height().max(masternodes.block_header_tip_height());
    if list.known_height.saturating_add(MASTERNODE_LIST_TIP_TOLERANCE) < tip {
        return Err(MasternodeListNotCurrentError::BehindTip {
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
    const TIP_TIME: u32 = 1_800_000_000;

    fn at(tip_age: Duration) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(TIP_TIME.into()) + tip_age
    }

    fn current_list(
        running: bool,
        progress: &SyncProgress,
        list: Option<&MasternodeList>,
    ) -> std::result::Result<MasternodeList, MasternodeListNotCurrentError> {
        super::current_list(running, Network::Mainnet, at(Duration::ZERO), progress, list)
    }

    fn progress(headers: SyncState, masternodes: SyncState) -> SyncProgress {
        progress_with_header_tip(headers, masternodes, TIP)
    }

    fn progress_with_header_tip(
        headers: SyncState,
        masternodes: SyncState,
        header_tip: u32,
    ) -> SyncProgress {
        let mut header_progress = BlockHeadersProgress::default();
        header_progress.set_state(headers);
        header_progress.update_tip_height(header_tip);
        header_progress.update_tip_time(TIP_TIME);
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
        for height in [TIP - MASTERNODE_LIST_TIP_TOLERANCE, TIP - 1, TIP] {
            let list = list_at(height);
            assert_eq!(current_list(true, &synced, Some(&list)), Ok(list));
        }
    }

    #[test]
    fn a_list_further_behind_the_tip_is_not_current() {
        let synced = progress(SyncState::Synced, SyncState::Synced);
        assert_eq!(
            current_list(true, &synced, Some(&list_at(TIP - MASTERNODE_LIST_TIP_TOLERANCE - 1))),
            Err(MasternodeListNotCurrentError::BehindTip {
                list_height: TIP - MASTERNODE_LIST_TIP_TOLERANCE - 1,
                tip: TIP,
            })
        );
    }

    #[test]
    fn a_list_is_measured_against_the_header_manager_tip_when_it_is_ahead() {
        let header_tip = TIP + MASTERNODE_LIST_TIP_TOLERANCE + 1;
        let progress = progress_with_header_tip(SyncState::Synced, SyncState::Synced, header_tip);
        assert_eq!(
            current_list(true, &progress, Some(&list_at(TIP))),
            Err(MasternodeListNotCurrentError::BehindTip {
                list_height: TIP,
                tip: header_tip,
            })
        );
    }

    #[test]
    fn a_list_is_not_current_once_the_header_tip_is_too_old() {
        let synced = progress(SyncState::Synced, SyncState::Synced);
        let list = list_at(TIP);
        let stale = Err(MasternodeListNotCurrentError::TipStale {
            tip_time: TIP_TIME,
        });
        for (network, max_age) in
            [(Network::Mainnet, MAINNET_MAX_TIP_AGE), (Network::Testnet, TESTNET_MAX_TIP_AGE)]
        {
            let fresh = super::current_list(true, network, at(max_age), &synced, Some(&list));
            assert_eq!(fresh, Ok(list.clone()));
            let too_old = at(max_age + Duration::from_secs(1));
            assert_eq!(super::current_list(true, network, too_old, &synced, Some(&list)), stale);
        }
    }

    #[test]
    fn regtest_and_devnet_lists_do_not_age() {
        let synced = progress(SyncState::Synced, SyncState::Synced);
        let list = list_at(TIP);
        let years_later = at(Duration::from_secs(5 * 365 * 24 * 60 * 60));
        for network in [Network::Regtest, Network::Devnet] {
            let current = super::current_list(true, network, years_later, &synced, Some(&list));
            assert_eq!(current, Ok(list.clone()));
        }
    }

    #[test]
    fn a_running_client_without_masternode_sync_reports_it_disabled() {
        let mut progress = SyncProgress::default();
        progress.update_headers(BlockHeadersProgress::default());
        assert_eq!(
            current_list(true, &progress, Some(&list_at(TIP))),
            Err(MasternodeListNotCurrentError::Disabled)
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
                Err(MasternodeListNotCurrentError::Syncing)
            );
        }
        let synced = progress(SyncState::Synced, SyncState::Synced);
        assert_eq!(current_list(true, &synced, None), Err(MasternodeListNotCurrentError::Syncing));
    }

    #[test]
    fn no_list_is_current_while_the_client_is_stopped() {
        let synced = progress(SyncState::Synced, SyncState::Synced);
        assert_eq!(
            current_list(false, &synced, Some(&list_at(TIP))),
            Err(MasternodeListNotCurrentError::NotRunning)
        );
    }
}
