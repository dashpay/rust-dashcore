//! Mempool manager for monitoring unconfirmed transactions.
//!
//! Activates after initial sync is complete and uses either BIP37 bloom
//! filters or local address matching to identify wallet-relevant
//! transactions from the mempool.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::{Amount, Transaction, Txid};
use rand::seq::IteratorRandom;
use tokio::sync::RwLock;

use super::broadcast::{BroadcastConfig, BroadcastResult, BroadcastStatus, TxBroadcastState};
use super::filter::build_wallet_bloom_filter;
use super::BLOOM_FALSE_POSITIVE_RATE;
use crate::client::config::MempoolStrategy;
use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::sync::mempool::MempoolProgress;
use crate::sync::SyncEvent;
use crate::types::UnconfirmedTransaction;
use key_wallet_manager::WalletInterface;

/// Timeout for pruning expired mempool transactions (24 hours).
pub(super) const MEMPOOL_TX_EXPIRY: Duration = Duration::from_secs(24 * 3600);

/// Timeout for pending getdata requests that never received a response.
const PENDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum number of in-flight getdata requests.
const MAX_IN_FLIGHT: usize = 100;

/// Maximum number of pending IS locks awaiting their corresponding transaction.
const MAX_PENDING_IS_LOCKS: usize = 1000;

/// How long a downloaded txid stays in the dedup map.
/// Covers the window where multiple peers respond to the initial `mempool` request.
const SEEN_TXID_EXPIRY: Duration = Duration::from_secs(180);

/// Per-transaction interval between rebroadcast attempts (10 minutes).
const REBROADCAST_INTERVAL: Duration = Duration::from_secs(600);

/// Mempool manager that monitors unconfirmed transactions from the P2P network.
///
/// Tracks connected peers via a unified map where:
/// - `None` = peer is connected but not yet activated (before sync completes)
/// - `Some(VecDeque)` = peer is activated (relay enabled), queue holds pending getdata txids
pub(crate) struct MempoolManager<W: WalletInterface> {
    pub(super) progress: MempoolProgress,
    pub(super) wallet: Arc<RwLock<W>>,
    pub(super) transactions: HashMap<Txid, UnconfirmedTransaction>,
    /// Self-broadcast transactions and their network-acceptance state.
    pub(super) broadcasts: HashMap<Txid, TxBroadcastState>,
    broadcast_config: BroadcastConfig,
    strategy: MempoolStrategy,
    max_transactions: usize,
    /// Txids we have requested via getdata but not yet received, with request time.
    pending_requests: HashMap<Txid, Instant>,
    /// Connected peers and their activation state.
    pub(super) peers: HashMap<SocketAddr, Option<VecDeque<Txid>>>,
    /// IS locks that arrived before their corresponding transaction, with insertion time.
    pending_is_locks: HashMap<Txid, (InstantLock, Instant)>,
    /// Txids already downloaded, with download timestamp.
    /// Prevents duplicate downloads when multiple peers announce the same transactions.
    /// Entries expire after `SEEN_TXID_EXPIRY`.
    seen_txids: HashMap<Txid, Instant>,
    /// Wallet monitor revision at the time of the last filter build.
    /// Compared on each tick to detect when the wallet's monitored set has changed.
    pub(super) last_monitor_revision: u64,
}

impl<W: WalletInterface> MempoolManager<W> {
    /// Creates a new mempool manager with the given wallet,
    /// bloom filter strategy, and transaction capacity limit.
    pub(crate) fn new(
        wallet: Arc<RwLock<W>>,
        strategy: MempoolStrategy,
        max_transactions: usize,
        initial_monitor_revision: u64,
        broadcast_config: BroadcastConfig,
    ) -> Self {
        Self {
            progress: MempoolProgress::default(),
            wallet,
            transactions: HashMap::new(),
            broadcasts: HashMap::new(),
            broadcast_config,
            strategy,
            max_transactions,
            pending_requests: HashMap::new(),
            peers: HashMap::new(),
            pending_is_locks: HashMap::new(),
            seen_txids: HashMap::new(),
            last_monitor_revision: initial_monitor_revision,
        }
    }

    /// Activate mempool monitoring on a single peer.
    ///
    /// Since we connect with `relay=false`, peers won't send transaction INVs
    /// until we explicitly enable relay:
    /// - BloomFilter strategy: sends `filterload` (which enables filtered relay) + `mempool`
    /// - FetchAll strategy: sends `filterclear` (which enables unfiltered relay) + `mempool`
    pub(super) async fn activate_peer(
        &mut self,
        peer: SocketAddr,
        requests: &RequestSender,
    ) -> SyncResult<()> {
        tracing::info!("Activating mempool on peer {} (strategy: {:?})", peer, self.strategy);

        match self.strategy {
            MempoolStrategy::BloomFilter => {
                self.load_bloom_filter(peer, requests).await?;
            }
            MempoolStrategy::FetchAll => {
                requests.send_filter_clear(peer)?;
            }
        }
        requests.request_mempool(peer)?;

        self.peers.insert(peer, Some(VecDeque::new()));
        Ok(())
    }

    /// Activate mempool relay on all connected but not-yet-activated peers.
    pub(super) async fn activate_all_peers(&mut self, requests: &RequestSender) -> SyncResult<()> {
        let inactive: Vec<SocketAddr> =
            self.peers.iter().filter(|(_, v)| v.is_none()).map(|(k, _)| *k).collect();
        for peer in inactive {
            self.activate_peer(peer, requests).await?;
        }
        Ok(())
    }

    /// Build and send a bloom filter to the mempool peer.
    async fn load_bloom_filter(
        &mut self,
        peer: SocketAddr,
        requests: &RequestSender,
    ) -> SyncResult<()> {
        let wallet = self.wallet.read().await;
        let addresses = wallet.monitored_addresses();
        let outpoints = wallet.watched_outpoints();
        drop(wallet);

        if addresses.is_empty() && outpoints.is_empty() {
            tracing::debug!("No addresses or outpoints to build bloom filter from");
            return Ok(());
        }

        let filter_load = build_wallet_bloom_filter(
            &addresses,
            &outpoints,
            BLOOM_FALSE_POSITIVE_RATE,
            rand::random(),
        )?;

        tracing::info!(
            "Built bloom filter with {} addresses and {} outpoints (fp_rate={}, size={}B)",
            addresses.len(),
            outpoints.len(),
            BLOOM_FALSE_POSITIVE_RATE,
            filter_load.filter.len()
        );

        requests.send_filter_load(filter_load, peer)?;

        Ok(())
    }

    /// Rebuild the bloom filter on all activated peers.
    pub(super) async fn rebuild_filter(&mut self, requests: &RequestSender) -> SyncResult<()> {
        if self.strategy != MempoolStrategy::BloomFilter {
            return Ok(());
        }

        let activated: Vec<SocketAddr> =
            self.peers.iter().filter(|(_, v)| v.is_some()).map(|(k, _)| *k).collect();

        if activated.is_empty() {
            return Ok(());
        }

        for peer in activated {
            requests.send_filter_clear(peer)?;
            self.load_bloom_filter(peer, requests).await?;
            requests.request_mempool(peer)?;
        }

        Ok(())
    }

    /// Handle incoming inventory announcements.
    ///
    /// Filters for new transaction txids and enqueues them. The actual getdata
    /// requests are sent by `send_queued()`, respecting the in-flight limit.
    pub(super) async fn handle_inv(
        &mut self,
        inv: &[Inventory],
        peer: SocketAddr,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Acceptance detection must run before any early return: an inv for
        // one of our own broadcasts from a peer we did NOT send it to proves
        // the transaction relayed through the network.
        let events = self.record_broadcast_echoes(inv, peer);

        let mempool_full = self.transactions.len() >= self.max_transactions;
        if mempool_full {
            return Ok(events);
        }

        let total_queued: usize =
            self.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum();
        let mut enqueued = 0;
        for item in inv {
            let Inventory::Transaction(txid) = item else {
                continue;
            };

            if self.seen_txids.get(txid).is_some_and(|t| t.elapsed() < SEEN_TXID_EXPIRY)
                || self.pending_requests.contains_key(txid)
                || self.is_queued(txid)
                || self.transactions.contains_key(txid)
            {
                continue;
            }
            if self.pending_requests.len() + total_queued + enqueued >= self.max_transactions {
                break;
            }
            // Only queue on activated peers
            if let Some(Some(queue)) = self.peers.get_mut(&peer) {
                queue.push_back(*txid);
                enqueued += 1;
            }
        }

        if enqueued > 0 {
            tracing::debug!("Enqueued {} mempool txids for download", enqueued);
            self.send_queued(requests).await?;
        }

        Ok(events)
    }

    /// Record `inv` announcements of our own broadcast transactions and
    /// promote broadcasts to accepted once enough non-recipient peers have
    /// announced them back.
    fn record_broadcast_echoes(&mut self, inv: &[Inventory], peer: SocketAddr) -> Vec<SyncEvent> {
        let mut events = Vec::new();
        for item in inv {
            let Inventory::Transaction(txid) = item else {
                continue;
            };
            let Some(state) = self.broadcasts.get_mut(txid) else {
                continue;
            };
            // Announcements from direct recipients carry no information: a
            // peer only ever announces to peers it did not get the tx from,
            // so a recipient echoing back would just be a protocol quirk.
            if state.sent_to.contains(&peer) || !state.announced_by.insert(peer) {
                continue;
            }
            tracing::debug!(
                "Broadcast {} announced back by non-recipient peer {} ({}/{} needed)",
                txid,
                peer,
                state.announced_by.len(),
                self.broadcast_config.acceptance_threshold
            );
            if matches!(state.status, BroadcastStatus::Pending | BroadcastStatus::Uncertain)
                && state.announced_by.len() >= self.broadcast_config.acceptance_threshold
            {
                state.status = BroadcastStatus::Accepted;
                tracing::info!(
                    "Broadcast {} accepted by the network ({} peer(s) relayed it back)",
                    txid,
                    state.announced_by.len()
                );
                events.push(SyncEvent::TransactionBroadcastResult {
                    txid: *txid,
                    result: BroadcastResult::Accepted {
                        relayed_by: state.announced_by.len(),
                    },
                });
            }
        }
        events
    }

    /// Drain per-peer queues and send getdata for up to `MAX_IN_FLIGHT` items.
    ///
    /// Deduplicates at send time against `pending_requests` and `mempool_state`
    /// in case a transaction was received between enqueue and send.
    pub(super) async fn send_queued(&mut self, requests: &RequestSender) -> SyncResult<()> {
        let mut available = MAX_IN_FLIGHT.saturating_sub(self.pending_requests.len());
        let has_queued = self.peers.values().any(|v| v.as_ref().is_some_and(|q| !q.is_empty()));
        if available == 0 || !has_queued {
            return Ok(());
        }

        let now = Instant::now();
        let mut per_peer: HashMap<SocketAddr, Vec<Inventory>> = HashMap::new();

        let activated_peers: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, v)| v.as_ref().is_some_and(|q| !q.is_empty()))
            .map(|(k, _)| *k)
            .collect();
        for peer in activated_peers {
            if available == 0 {
                break;
            }
            let Some(Some(queue)) = self.peers.get_mut(&peer) else {
                continue;
            };
            while available > 0 {
                let Some(txid) = queue.pop_front() else {
                    break;
                };
                if self.pending_requests.contains_key(&txid)
                    || self.transactions.contains_key(&txid)
                {
                    continue;
                }
                self.pending_requests.insert(txid, now);
                per_peer.entry(peer).or_default().push(Inventory::Transaction(txid));
                available -= 1;
            }
        }

        let total_queued: usize =
            self.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum();
        for (peer, inventory) in per_peer {
            if inventory.is_empty() {
                continue;
            }
            tracing::debug!(
                "Requesting {} mempool transactions via getdata from {} ({} still queued)",
                inventory.len(),
                peer,
                total_queued,
            );
            requests.request_inventory(inventory, peer)?;
        }
        Ok(())
    }

    /// Handle a received transaction.
    ///
    /// When `peer` is the local sentinel address (`0.0.0.0:0`), the transaction
    /// is treated as self-originated: it is sent to a subset of connected peers
    /// (withholding a holdout set) and tracked in `broadcasts` for network
    /// acceptance detection.
    pub(super) async fn handle_tx(
        &mut self,
        tx: Transaction,
        peer: SocketAddr,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        let txid = tx.txid();
        self.pending_requests.remove(&txid);
        let is_local = peer.ip().is_unspecified();

        // Send self-originated transactions to the network regardless of
        // wallet relevance — the caller explicitly asked to broadcast.
        let mut events = Vec::new();
        if is_local {
            events.extend(self.start_broadcast(&tx, requests));
        }

        // Skip if already tracked (e.g., locally broadcast then received from a peer)
        if self.transactions.contains_key(&txid) {
            self.seen_txids.insert(txid, Instant::now());
            return Ok(events);
        }

        self.seen_txids.insert(txid, Instant::now());
        self.progress.add_received(1);

        // Check for a pre-arrived IS lock before wallet processing consumes it
        let pending_lock = self.pending_is_locks.remove(&txid).map(|(lock, _)| lock);
        let is_locked = pending_lock.is_some();

        let result = {
            let mut wallet = self.wallet.write().await;
            wallet.process_mempool_transaction(&tx, pending_lock).await
        };

        if !result.is_relevant {
            return Ok(events);
        }

        self.progress.add_relevant(1);
        tracing::info!("Wallet-relevant mempool transaction: {}", txid);

        // Build and store the unconfirmed transaction.
        // The wallet already confirmed relevance, so we store unconditionally.
        let unconfirmed_tx = UnconfirmedTransaction::new(
            tx,
            Amount::ZERO,
            is_locked,
            result.is_outgoing,
            result.addresses,
            result.net_amount,
        );
        self.transactions.insert(txid, unconfirmed_tx);
        self.progress.set_tracked(self.transactions.len() as u32);

        Ok(events)
    }

    /// Acceptance evidence gathered before this node broadcast the transaction
    /// itself, with the label to log it under.
    ///
    /// The echo heuristic can only observe signals that arrive *after* the
    /// broadcast is registered: a holdout peer announcing the txid back. When
    /// the very same signed transaction reached the network by another route
    /// first — a BIP70 merchant broadcasting the bytes it was just paid with,
    /// another copy of the wallet, a rebroadcast after a restart — its
    /// InstantSend lock or peer relay lands before `start_broadcast` runs and
    /// is then invisible to that heuristic. No peer re-announces a transaction
    /// it is only now being sent, so the broadcast would sit `Pending` until
    /// the timeout and be reported as `Uncertain` while the network had in
    /// fact accepted it seconds earlier.
    fn preexisting_acceptance(&self, txid: &Txid) -> Option<&'static str> {
        if self.pending_is_locks.contains_key(txid) {
            return Some("InstantSend lock arrived before the broadcast");
        }
        match self.transactions.get(txid) {
            Some(tx) if tx.is_instant_send => Some("mempool entry is already InstantSend-locked"),
            // Present in our mempool view without a local broadcast behind it means a peer
            // relayed it to us — the same proof of propagation the echo threshold waits for.
            Some(_) => Some("already relayed to us by a peer"),
            // `transactions` only keeps wallet-relevant entries, but relay is relay: a
            // transaction the wallet ignored still reached us from the network. `seen_txids`
            // records every download, and at this point it can only hold a txid some peer sent
            // us — our own copy is inserted after `start_broadcast` runs, and a second local
            // dispatch never reaches here (`broadcasts` short-circuits it).
            None => self
                .seen_txids
                .get(txid)
                .is_some_and(|seen| seen.elapsed() < SEEN_TXID_EXPIRY)
                .then_some("already received from a peer"),
        }
    }

    /// Begin tracking a self-originated transaction and send it to the
    /// network, withholding it from a holdout subset of peers.
    ///
    /// Idempotent per txid: repeated local dispatches of the same transaction
    /// do not resend (the rebroadcast timer handles resends).
    ///
    /// Returns the acceptance event when the network's verdict is already
    /// known (see [`Self::preexisting_acceptance`]); the transaction is still
    /// sent, since knowing one peer has it says nothing about the rest.
    pub(super) fn start_broadcast(
        &mut self,
        tx: &Transaction,
        requests: &RequestSender,
    ) -> Vec<SyncEvent> {
        let txid = tx.txid();
        if self.broadcasts.contains_key(&txid) {
            return Vec::new();
        }

        let known_acceptance = self.preexisting_acceptance(&txid);

        let mut state = TxBroadcastState::new(tx.clone(), Instant::now());
        let peers: Vec<SocketAddr> = self.peers.keys().copied().collect();
        let holdout_count = self.broadcast_config.holdout.count_for(peers.len());
        state.holdout = peers
            .iter()
            .copied()
            .choose_multiple(&mut rand::thread_rng(), holdout_count)
            .into_iter()
            .collect();

        for peer in &peers {
            if state.holdout.contains(peer) {
                continue;
            }
            if requests.send_transaction(tx.clone(), *peer).is_ok() {
                state.sent_to.insert(*peer);
            }
        }

        if peers.is_empty() {
            // No peers right now; the rebroadcast timer sends once one connects.
            tracing::warn!("Broadcast {} deferred: no connected peers", txid);
        } else {
            tracing::info!(
                "Broadcast {} to {}/{} peers ({} withheld for acceptance detection)",
                txid,
                state.sent_to.len(),
                peers.len(),
                state.holdout.len()
            );
        }
        if let Some(reason) = known_acceptance {
            tracing::info!("Broadcast {} accepted before dispatch ({})", txid, reason);
            state.status = BroadcastStatus::Accepted;
            self.broadcasts.insert(txid, state);
            return vec![SyncEvent::TransactionBroadcastResult {
                txid,
                result: BroadcastResult::Accepted {
                    relayed_by: 0,
                },
            }];
        }

        self.broadcasts.insert(txid, state);
        Vec::new()
    }

    /// Transition pending broadcasts that outlived the acceptance timeout to
    /// `Uncertain`, emitting one event per transition. A late echo, IS lock,
    /// or confirmation can still upgrade them to `Accepted`.
    pub(super) fn expire_broadcasts(&mut self) -> Vec<SyncEvent> {
        self.expire_broadcasts_at(Instant::now())
    }

    fn expire_broadcasts_at(&mut self, now: Instant) -> Vec<SyncEvent> {
        let timeout = self.broadcast_config.acceptance_timeout;
        let mut events = Vec::new();
        for (txid, state) in &mut self.broadcasts {
            if state.status == BroadcastStatus::Pending
                && now.saturating_duration_since(state.created_at) >= timeout
            {
                state.status = BroadcastStatus::Uncertain;
                tracing::info!(
                    "Broadcast {} outcome uncertain: no acceptance signal within {:?}",
                    txid,
                    timeout
                );
                events.push(SyncEvent::TransactionBroadcastResult {
                    txid: *txid,
                    result: BroadcastResult::Uncertain,
                });
            }
        }
        events
    }

    /// Remove transactions from the mempool that have been confirmed in a block.
    ///
    /// Confirmation is definitive acceptance: pending or uncertain broadcasts
    /// for confirmed txids are promoted to accepted and dropped from tracking.
    pub(super) fn remove_confirmed(&mut self, txids: &[Txid]) -> Vec<SyncEvent> {
        self.seen_txids.retain(|_, t| t.elapsed() < SEEN_TXID_EXPIRY);
        let mut events = Vec::new();
        let mut removed = Vec::new();
        for txid in txids {
            if let Some(state) = self.broadcasts.remove(txid) {
                if matches!(state.status, BroadcastStatus::Pending | BroadcastStatus::Uncertain) {
                    events.push(SyncEvent::TransactionBroadcastResult {
                        txid: *txid,
                        result: BroadcastResult::Accepted {
                            relayed_by: state.announced_by.len(),
                        },
                    });
                }
            }
            if self.transactions.remove(txid).is_some() {
                removed.push(*txid);
            }
        }
        if !removed.is_empty() {
            self.progress.add_removed(removed.len() as u32);
            self.progress.set_tracked(self.transactions.len() as u32);
            tracing::debug!("Removed {} confirmed transactions from mempool", removed.len());
        }
        events
    }

    /// Mark a mempool transaction as InstantSend-locked and notify the wallet.
    ///
    /// If the transaction hasn't arrived yet, remembers the lock so it
    /// can be applied when the transaction is later received via `handle_tx`.
    ///
    /// An InstantSend lock is definitive acceptance: any pending or uncertain
    /// broadcast for the txid is promoted to accepted and dropped from tracking.
    pub(super) async fn process_instant_send(
        &mut self,
        instant_lock: InstantLock,
    ) -> Vec<SyncEvent> {
        let txid = instant_lock.txid;
        let mut events = Vec::new();
        if let Some(state) = self.broadcasts.remove(&txid) {
            if matches!(state.status, BroadcastStatus::Pending | BroadcastStatus::Uncertain) {
                tracing::info!("Broadcast {} accepted (InstantSend lock received)", txid);
                events.push(SyncEvent::TransactionBroadcastResult {
                    txid,
                    result: BroadcastResult::Accepted {
                        relayed_by: state.announced_by.len(),
                    },
                });
            }
        }
        let instant_lock_opt = if let Some(tx) = self.transactions.get_mut(&txid) {
            tx.is_instant_send = true;
            tracing::debug!("Marked mempool tx {} as InstantSend-locked", txid);
            Some(instant_lock)
        } else if self.pending_is_locks.len() < MAX_PENDING_IS_LOCKS {
            self.pending_is_locks.insert(txid, (instant_lock, Instant::now()));
            tracing::debug!("IS lock arrived before tx {}, remembering for later", txid);
            None
        } else {
            tracing::warn!(
                "Pending IS locks at capacity ({}), dropping IS lock for {}",
                MAX_PENDING_IS_LOCKS,
                txid
            );
            None
        };
        if let Some(lock) = instant_lock_opt {
            let mut wallet = self.wallet.write().await;
            wallet.process_instant_send_lock(lock);
        }
        events
    }

    /// Prune transactions and pending IS locks older than `timeout`.
    pub(super) fn prune_expired(&mut self, timeout: Duration) {
        let mut expired_txids = Vec::new();
        self.transactions.retain(|txid, tx| {
            if tx.is_expired(timeout) {
                expired_txids.push(*txid);
                false
            } else {
                true
            }
        });

        // Prune old broadcast tracking states
        if let Some(cutoff) = Instant::now().checked_sub(timeout) {
            self.broadcasts.retain(|_, state| state.created_at > cutoff);
        }

        if !expired_txids.is_empty() {
            self.progress.add_removed(expired_txids.len() as u32);
            self.progress.set_tracked(self.transactions.len() as u32);
            tracing::debug!("Pruned {} expired mempool transactions", expired_txids.len());
            for txid in &expired_txids {
                self.pending_is_locks.remove(txid);
            }
        }

        // Prune pending IS locks whose transaction never arrived
        let before = self.pending_is_locks.len();
        self.pending_is_locks.retain(|_, (_, inserted_at)| inserted_at.elapsed() < timeout);
        let expired = before - self.pending_is_locks.len();
        if expired > 0 {
            tracing::debug!("Pruned {} expired pending IS locks", expired);
        }
    }

    /// Rebroadcast unconfirmed self-sent transactions.
    ///
    /// Each entry in `broadcasts` tracks when it was last sent. Entries whose
    /// last send was more than `REBROADCAST_INTERVAL` ago are resent:
    /// - `Pending`: targeted resend that keeps respecting the holdout set so
    ///   an acceptance echo remains possible. If every holdout peer has
    ///   disconnected, replacement holdouts are picked from peers that never
    ///   received the transaction.
    /// - `Accepted`/`Uncertain`: plain broadcast to all peers (the holdout no
    ///   longer matters; a late echo from a new peer can still upgrade
    ///   `Uncertain` to `Accepted`).
    pub(super) async fn rebroadcast_if_due(&mut self, requests: &RequestSender) {
        self.rebroadcast_if_due_at(requests, Instant::now()).await
    }

    /// `now`-injected variant of [`Self::rebroadcast_if_due`]. Tests project `now`
    /// forward instead of subtracting from `Instant::now()`, which underflows on
    /// Windows when the QPC-based monotonic clock has a small value at boot.
    async fn rebroadcast_if_due_at(&mut self, requests: &RequestSender, now: Instant) {
        let current_peers: Vec<SocketAddr> = self.peers.keys().copied().collect();
        let mut count: usize = 0;
        for (txid, state) in &mut self.broadcasts {
            if current_peers.is_empty() {
                continue;
            }
            // A pending broadcast that never reached any peer (no peers were
            // connected at send time) is due immediately.
            let never_sent = state.status == BroadcastStatus::Pending && state.sent_to.is_empty();
            if !never_sent
                && now.saturating_duration_since(state.last_broadcast) < REBROADCAST_INTERVAL
            {
                continue;
            }
            if state.status == BroadcastStatus::Pending {
                // Re-pick the holdout from never-sent peers if all holdouts left.
                let holdout_alive = current_peers.iter().any(|p| state.holdout.contains(p));
                if !holdout_alive {
                    let needed = self.broadcast_config.holdout.count_for(current_peers.len());
                    let candidates: Vec<SocketAddr> = current_peers
                        .iter()
                        .filter(|p| !state.sent_to.contains(*p))
                        .copied()
                        .collect();
                    state.holdout.extend(
                        candidates.into_iter().choose_multiple(&mut rand::thread_rng(), needed),
                    );
                }
                let targets: Vec<SocketAddr> =
                    current_peers.iter().filter(|p| !state.holdout.contains(*p)).copied().collect();
                if targets.is_empty() {
                    // Every connected peer is a holdout (all original
                    // recipients are gone); relay through everyone rather
                    // than letting the transaction stall.
                    if !current_peers.is_empty() {
                        let _ = requests.broadcast(NetworkMessage::Tx(state.transaction.clone()));
                        state.sent_to.extend(current_peers.iter().copied());
                    }
                } else {
                    for peer in targets {
                        if requests.send_transaction(state.transaction.clone(), peer).is_ok() {
                            state.sent_to.insert(peer);
                        }
                    }
                }
            } else {
                let _ = requests.broadcast(NetworkMessage::Tx(state.transaction.clone()));
            }
            tracing::debug!("Rebroadcast unconfirmed transaction {}", txid);
            state.last_broadcast = now;
            count += 1;
        }

        if count > 0 {
            tracing::info!("Rebroadcast {} unconfirmed transaction(s)", count);
        }
    }

    fn is_queued(&self, txid: &Txid) -> bool {
        self.peers.values().filter_map(|v| v.as_ref()).any(|q| q.contains(txid))
    }

    /// Register a newly connected peer (not yet activated).
    pub(super) fn handle_peer_connected(&mut self, peer: SocketAddr) {
        self.peers.entry(peer).or_insert(None);
    }

    /// Remove a disconnected peer, redistributing its queued txids to another activated peer.
    pub(super) fn handle_peer_disconnected(&mut self, peer: SocketAddr) {
        if let Some(Some(orphaned)) = self.peers.remove(&peer) {
            if !orphaned.is_empty() {
                let target = self
                    .peers
                    .iter_mut()
                    .filter(|(_, v)| v.is_some())
                    .map(|(_, v)| v)
                    .choose(&mut rand::thread_rng());
                if let Some(Some(queue)) = target {
                    queue.extend(orphaned);
                } else {
                    tracing::warn!(
                        "Dropped {} orphaned txids from disconnected peer {}: no activated peers available",
                        orphaned.len(),
                        peer
                    );
                }
            }
        }
    }

    /// Clear all peer state, pending requests, and pending IS locks.
    pub(super) fn clear_pending(&mut self) {
        self.pending_requests.clear();
        self.peers.clear();
        self.pending_is_locks.clear();
    }

    /// Remove pending requests that have timed out without receiving a response.
    /// Timed-out txids are re-queued to any connected peer for retry.
    pub(super) fn prune_pending_requests(&mut self) {
        let mut timed_out = Vec::new();
        self.pending_requests.retain(|txid, requested_at| {
            if requested_at.elapsed() >= PENDING_REQUEST_TIMEOUT {
                timed_out.push(*txid);
                false
            } else {
                true
            }
        });
        if timed_out.is_empty() {
            return;
        }
        tracing::debug!("Pruned {} timed-out pending requests, re-queuing", timed_out.len());
        let target =
            self.peers.values_mut().filter_map(|v| v.as_mut()).choose(&mut rand::thread_rng());
        if let Some(queue) = target {
            queue.extend(timed_out);
        } else {
            tracing::warn!(
                "Dropped {} timed-out txids: no activated peers available for re-queue",
                timed_out.len()
            );
        }
    }
}

impl<W: WalletInterface> fmt::Debug for MempoolManager<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let activated = self.peers.values().filter(|v| v.is_some()).count();
        f.debug_struct("MempoolManager")
            .field("progress", &self.progress)
            .field("strategy", &self.strategy)
            .field("broadcasts", &self.broadcasts.len())
            .field("pending_requests", &self.pending_requests.len())
            .field("peers", &self.peers.len())
            .field("activated_peers", &activated)
            .field(
                "queued",
                &self.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum::<usize>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkRequest;
    use dashcore::hashes::Hash;
    use dashcore::network::message::NetworkMessage;
    use dashcore::{Address, BlockHash, Network, ScriptBuf, Transaction};
    use key_wallet::transaction_checking::TransactionContext;
    use key_wallet_manager::test_utils::MockWallet;

    use crate::sync::SyncState;
    use crate::test_utils::test_socket_address;
    use tokio::sync::mpsc;

    fn dummy_instant_lock(txid: Txid) -> InstantLock {
        InstantLock {
            txid,
            ..InstantLock::default()
        }
    }

    fn rich_instant_lock(txid: Txid) -> InstantLock {
        InstantLock {
            txid,
            cyclehash: BlockHash::from_byte_array([0xab; 32]),
            ..InstantLock::default()
        }
    }

    fn create_test_manager(
    ) -> (MempoolManager<MockWallet>, RequestSender, mpsc::UnboundedReceiver<NetworkRequest>) {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx, rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(
            wallet,
            MempoolStrategy::FetchAll,
            1000,
            0,
            BroadcastConfig::default(),
        );
        manager.progress.set_state(SyncState::Synced);

        (manager, requests, rx)
    }

    fn create_bloom_manager(
    ) -> (MempoolManager<MockWallet>, RequestSender, mpsc::UnboundedReceiver<NetworkRequest>) {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx, rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let manager = MempoolManager::new(
            wallet,
            MempoolStrategy::BloomFilter,
            1000,
            0,
            BroadcastConfig::default(),
        );

        (manager, requests, rx)
    }

    #[tokio::test]
    async fn test_activation_fetch_all() {
        let peer = test_socket_address(1);
        let (mut manager, requests, mut rx) = create_test_manager();
        manager.activate_peer(peer, &requests).await.unwrap();

        // FetchAll activation sends filterclear then mempool to the chosen peer
        let msg1 = rx.recv().await.unwrap();
        assert!(
            matches!(msg1, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterClear, p) if p == peer)
        );
        let msg2 = rx.recv().await.unwrap();
        assert!(
            matches!(msg2, NetworkRequest::SendMessageToPeer(NetworkMessage::MemPool, p) if p == peer)
        );
        assert!(matches!(manager.peers.get(&peer), Some(Some(_))));
    }

    #[tokio::test]
    async fn test_activation_bloom_filter_skips_empty_wallet() {
        let (mut manager, requests, mut rx) = create_bloom_manager();
        manager.activate_peer(test_socket_address(1), &requests).await.unwrap();

        // No addresses in mock wallet, so only MemPool should be sent (no FilterLoad)
        let mut found_filter_load = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(msg, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _)) {
                found_filter_load = true;
            }
        }
        assert!(!found_filter_load, "should not send FilterLoad for empty wallet");
    }

    #[tokio::test]
    async fn test_handle_inv_deduplication() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        let txid = Txid::from_byte_array([1u8; 32]);
        let inv = vec![Inventory::Transaction(txid)];

        // First call should add to pending
        let events = manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert!(events.is_empty());
        assert!(manager.pending_requests.contains_key(&txid));

        // Second call with same txid should be filtered out
        let events = manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.pending_requests.len(), 1);
    }

    #[tokio::test]
    async fn test_handle_inv_capacity_limit() {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx, _rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(
            wallet,
            MempoolStrategy::FetchAll,
            2, // Very small capacity
            0,
            BroadcastConfig::default(),
        );
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        // Fill mempool to capacity
        for i in 0..2u32 {
            let tx = Transaction {
                version: 1,
                lock_time: i,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            };
            let txid = tx.txid();
            manager.transactions.insert(
                txid,
                UnconfirmedTransaction::new(tx, Amount::from_sat(0), false, false, Vec::new(), 0),
            );
        }

        // New transactions should be filtered out
        let new_txid = Txid::from_byte_array([99u8; 32]);
        let inv = vec![Inventory::Transaction(new_txid)];
        let events = manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert!(events.is_empty());
        assert!(!manager.pending_requests.contains_key(&new_txid));
    }

    #[tokio::test]
    async fn test_handle_inv_pending_requests_limit() {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx, _rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(
            wallet,
            MempoolStrategy::FetchAll,
            2,
            0,
            BroadcastConfig::default(),
        );
        manager.progress.set_state(SyncState::Synced);
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        // Fill pending requests to capacity
        let inv1: Vec<Inventory> =
            (0..2).map(|i| Inventory::Transaction(Txid::from_byte_array([i; 32]))).collect();
        manager.handle_inv(&inv1, peer, &requests).await.unwrap();
        assert_eq!(manager.pending_requests.len(), 2);

        // Additional requests should be rejected when pending is at capacity
        let extra_txid = Txid::from_byte_array([99; 32]);
        let inv2 = vec![Inventory::Transaction(extra_txid)];
        manager.handle_inv(&inv2, peer, &requests).await.unwrap();
        assert!(!manager.pending_requests.contains_key(&extra_txid));
    }

    #[test]
    fn test_prune_pending_requests_timeout() {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx, _rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let _requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(
            wallet,
            MempoolStrategy::FetchAll,
            1000,
            0,
            BroadcastConfig::default(),
        );

        let fresh_txid = Txid::from_byte_array([1; 32]);
        let stale_txid = Txid::from_byte_array([2; 32]);

        manager.pending_requests.insert(fresh_txid, Instant::now());
        manager
            .pending_requests
            .insert(stale_txid, Instant::now() - PENDING_REQUEST_TIMEOUT - Duration::from_secs(1));

        manager.prune_pending_requests();

        assert!(manager.pending_requests.contains_key(&fresh_txid));
        assert!(!manager.pending_requests.contains_key(&stale_txid));
    }

    #[tokio::test]
    async fn test_handle_tx_irrelevant() {
        let (mut manager, requests, _rx) = create_test_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        let events = manager.handle_tx(tx, test_socket_address(1), &requests).await.unwrap();
        // MockWallet returns is_relevant=false by default
        assert!(events.is_empty());
        assert_eq!(manager.progress.received(), 1);

        // Irrelevant tx should not be stored
        assert!(!manager.transactions.contains_key(&txid));
        assert_eq!(manager.progress.relevant(), 0);
    }

    #[tokio::test]
    async fn test_handle_inv_non_transaction_filtered() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        let inv = vec![
            Inventory::Block(BlockHash::all_zeros()),
            Inventory::Transaction(Txid::from_byte_array([1u8; 32])),
        ];

        let events = manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert!(events.is_empty());
        // Only the transaction should be tracked, not the block
        assert_eq!(manager.pending_requests.len(), 1);
    }

    #[test]
    fn test_prune_expired() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let fresh_tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let fresh_txid = fresh_tx.txid();

        let expired_tx = Transaction {
            version: 1,
            lock_time: 99,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let expired_txid = expired_tx.txid();
        let test_timeout = Duration::from_secs(2);

        manager.transactions.insert(
            fresh_txid,
            UnconfirmedTransaction::new(fresh_tx, Amount::from_sat(0), false, false, Vec::new(), 0),
        );
        let mut expired_utx = UnconfirmedTransaction::new(
            expired_tx,
            Amount::from_sat(0),
            false,
            false,
            Vec::new(),
            0,
        );
        expired_utx.first_seen = Instant::now() - test_timeout - Duration::from_secs(1);
        manager.transactions.insert(expired_txid, expired_utx);

        manager.prune_expired(test_timeout);

        assert_eq!(manager.transactions.len(), 1);
        assert!(manager.transactions.contains_key(&fresh_txid));
        assert!(!manager.transactions.contains_key(&expired_txid));
        assert_eq!(manager.progress.removed(), 1);
    }

    /// Create a manager with BloomFilter strategy where the wallet reports
    /// mempool transactions as relevant. BloomFilter strategy skips local
    /// address pre-filtering, relying on the wallet for definitive checks.
    fn create_relevant_manager(
    ) -> (MempoolManager<MockWallet>, RequestSender, Arc<RwLock<MockWallet>>) {
        let mut mock = MockWallet::new();
        mock.set_mempool_relevant(true);
        let wallet = Arc::new(RwLock::new(mock));
        let (tx, _rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::BloomFilter,
            1000,
            0,
            BroadcastConfig::default(),
        );

        (manager, requests, wallet)
    }

    #[tokio::test]
    async fn test_handle_tx_relevant_stores_transaction() {
        let (mut manager, requests, _wallet) = create_relevant_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        let events = manager.handle_tx(tx, test_socket_address(1), &requests).await.unwrap();
        assert!(events.is_empty());

        // Verify transaction was stored
        assert!(manager.transactions.contains_key(&txid));
        assert_eq!(manager.progress.received(), 1);
        assert_eq!(manager.progress.relevant(), 1);
        assert_eq!(manager.progress.tracked(), 1);

        // Processing the same transaction again should be a no-op (dedup guard)
        let tx2 = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let events = manager.handle_tx(tx2, test_socket_address(1), &requests).await.unwrap();
        assert!(events.is_empty());

        assert_eq!(manager.transactions.len(), 1);
        // Progress counters should not have incremented
        assert_eq!(manager.progress.received(), 1);
        assert_eq!(manager.progress.relevant(), 1);
    }

    #[tokio::test]
    async fn test_handle_tx_local_records_send() {
        let (mut manager, requests, _wallet) = create_relevant_manager();

        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        // Use the unspecified address to simulate a locally broadcast transaction
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        manager.handle_tx(tx, local_addr, &requests).await.unwrap();

        assert!(manager.transactions.contains_key(&txid));
        assert!(
            manager.broadcasts.contains_key(&txid),
            "locally dispatched transaction should be tracked as a broadcast"
        );
    }

    #[tokio::test]
    async fn test_handle_tx_remote_does_not_record_send() {
        let (mut manager, requests, _wallet) = create_relevant_manager();

        let tx = Transaction {
            version: 3,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        manager.handle_tx(tx, test_socket_address(1), &requests).await.unwrap();

        assert!(manager.transactions.contains_key(&txid));
        assert!(
            !manager.broadcasts.contains_key(&txid),
            "peer-received transaction should not be tracked as a broadcast"
        );
    }

    #[tokio::test]
    async fn test_handle_tx_clears_pending_request() {
        let (mut manager, requests, _wallet) = create_relevant_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        // Simulate that we requested this transaction
        manager.pending_requests.insert(txid, Instant::now());
        assert!(manager.pending_requests.contains_key(&txid));

        manager.handle_tx(tx, test_socket_address(1), &requests).await.unwrap();
        // Pending request should be cleared regardless of relevance
        assert!(!manager.pending_requests.contains_key(&txid));

        // Since the manager uses BloomFilter strategy (relevant mock), tx should be stored
        assert!(manager.transactions.contains_key(&txid));
    }

    fn create_bloom_manager_with_addresses(
        addresses: Vec<Address>,
    ) -> (MempoolManager<MockWallet>, RequestSender, mpsc::UnboundedReceiver<NetworkRequest>) {
        let mut mock = MockWallet::new();
        mock.set_addresses(addresses);
        let wallet = Arc::new(RwLock::new(mock));
        let (tx, rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let manager = MempoolManager::new(
            wallet,
            MempoolStrategy::BloomFilter,
            1000,
            0,
            BroadcastConfig::default(),
        );

        (manager, requests, rx)
    }

    /// Create a test P2PKH address from a byte pattern.
    fn test_address(byte: u8) -> Address {
        // Build OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut script_bytes = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20
        script_bytes.extend_from_slice(&[byte; 20]);
        script_bytes.push(0x88); // OP_EQUALVERIFY
        script_bytes.push(0xac); // OP_CHECKSIG
        let script = ScriptBuf::from(script_bytes);
        Address::from_script(&script, Network::Testnet).unwrap()
    }

    #[tokio::test]
    async fn test_bloom_filter_loaded_with_addresses() {
        let addr = test_address(0xab);

        let (mut manager, requests, mut rx) = create_bloom_manager_with_addresses(vec![addr]);
        manager.activate_peer(test_socket_address(1), &requests).await.unwrap();

        let mut found_filter_load = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(msg, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _)) {
                found_filter_load = true;
            }
        }
        assert!(found_filter_load, "expected FilterLoad for wallet with addresses");
    }

    #[tokio::test]
    async fn test_mark_instant_send_emits_status_change() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 42,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();
        manager.broadcasts.insert(txid, TxBroadcastState::new(tx.clone(), Instant::now()));
        manager.transactions.insert(
            txid,
            UnconfirmedTransaction::new(tx, Amount::from_sat(0), false, false, Vec::new(), 0),
        );

        let events = manager.process_instant_send(dummy_instant_lock(txid)).await;

        // Verify IS flag, broadcast promotion, and tracking cleanup
        assert!(manager.transactions.get(&txid).unwrap().is_instant_send);
        assert!(
            !manager.broadcasts.contains_key(&txid),
            "IS-locked transaction should no longer be tracked as a broadcast"
        );
        assert!(matches!(
            events.as_slice(),
            [SyncEvent::TransactionBroadcastResult {
                result: BroadcastResult::Accepted { .. },
                ..
            }]
        ));

        let wallet = manager.wallet.read().await;
        let status_changes = wallet.status_changes();
        let changes = status_changes.lock().await;
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].0, txid);
        assert!(matches!(changes[0].1, TransactionContext::InstantSend(_)));
    }

    #[tokio::test]
    async fn test_mark_instant_send_stores_pending_for_unknown() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let unknown_txid = Txid::from_byte_array([0xbb; 32]);
        manager.process_instant_send(dummy_instant_lock(unknown_txid)).await;

        // No immediate wallet notification
        let wallet = manager.wallet.read().await;
        let status_changes = wallet.status_changes();
        let changes = status_changes.lock().await;
        assert!(changes.is_empty());

        // But the txid is remembered for when the transaction arrives
        assert!(manager.pending_is_locks.contains_key(&unknown_txid));
    }

    #[tokio::test]
    async fn test_in_flight_limit() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        // Send 200 INVs — only MAX_IN_FLIGHT should go to pending, rest queued
        let inv: Vec<Inventory> = (0..200u16)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0..2].copy_from_slice(&i.to_le_bytes());
                Inventory::Transaction(Txid::from_byte_array(bytes))
            })
            .collect();

        manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert_eq!(manager.pending_requests.len(), MAX_IN_FLIGHT);
        assert_eq!(
            manager.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum::<usize>(),
            100
        );
    }

    #[tokio::test]
    async fn test_send_queued_drains_after_response() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        // Fill with 150 INVs
        let inv: Vec<Inventory> = (0..150u16)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0..2].copy_from_slice(&i.to_le_bytes());
                Inventory::Transaction(Txid::from_byte_array(bytes))
            })
            .collect();

        manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert_eq!(manager.pending_requests.len(), MAX_IN_FLIGHT);
        assert_eq!(
            manager.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum::<usize>(),
            50
        );

        // Simulate receiving 10 responses (freeing 10 slots)
        let pending_txids: Vec<Txid> = manager.pending_requests.keys().take(10).copied().collect();
        for txid in &pending_txids {
            manager.pending_requests.remove(txid);
        }
        assert_eq!(manager.pending_requests.len(), 90);

        // send_queued should fill the freed slots
        manager.send_queued(&requests).await.unwrap();
        assert_eq!(manager.pending_requests.len(), MAX_IN_FLIGHT);
        assert_eq!(
            manager.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum::<usize>(),
            40
        );
    }

    #[tokio::test]
    async fn test_send_queued_skips_already_received() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);

        // Create a real transaction and get its actual txid
        let tx = Transaction {
            version: 1,
            lock_time: 0xaa,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        // Enqueue the txid on an activated peer
        manager.peers.insert(peer, Some(VecDeque::from([txid])));

        // Simulate the transaction arriving before send
        manager.transactions.insert(
            txid,
            UnconfirmedTransaction::new(tx, Amount::from_sat(0), false, false, Vec::new(), 0),
        );

        manager.send_queued(&requests).await.unwrap();
        // Txid should have been skipped, not added to pending
        assert!(manager.pending_requests.is_empty());
        assert!(manager.peers.values().filter_map(|v| v.as_ref()).all(|q| q.is_empty()));
    }

    #[test]
    fn test_clear_pending_clears_queue() {
        let (mut manager, _requests, _rx) = create_test_manager();

        manager.pending_requests.insert(Txid::from_byte_array([1; 32]), Instant::now());
        manager
            .peers
            .insert(test_socket_address(1), Some(VecDeque::from([Txid::from_byte_array([2; 32])])));
        let txid3 = Txid::from_byte_array([3; 32]);
        manager.pending_is_locks.insert(txid3, (dummy_instant_lock(txid3), Instant::now()));

        manager.clear_pending();

        assert!(manager.pending_requests.is_empty());
        assert!(manager.peers.is_empty());
        assert!(manager.pending_is_locks.is_empty());
    }

    #[tokio::test]
    async fn test_send_queued_noop_at_capacity() {
        let (mut manager, requests, _rx) = create_test_manager();

        // Fill pending to MAX_IN_FLIGHT
        for i in 0..MAX_IN_FLIGHT as u16 {
            let mut bytes = [0u8; 32];
            bytes[0..2].copy_from_slice(&i.to_le_bytes());
            manager.pending_requests.insert(Txid::from_byte_array(bytes), Instant::now());
        }

        // Add something to the queue on an activated peer
        manager.peers.insert(
            test_socket_address(1),
            Some(VecDeque::from([Txid::from_byte_array([0xff; 32])])),
        );

        manager.send_queued(&requests).await.unwrap();
        // Queue should remain unchanged (one peer with one txid)
        assert_eq!(
            manager.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum::<usize>(),
            1
        );
        assert_eq!(manager.pending_requests.len(), MAX_IN_FLIGHT);
    }

    #[tokio::test]
    async fn test_instant_send_before_transaction() {
        let (mut manager, requests, wallet) = create_relevant_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 77,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        // IS lock arrives before the transaction (with a distinct cyclehash)
        manager.process_instant_send(rich_instant_lock(txid)).await;
        assert!(manager.pending_is_locks.contains_key(&txid));

        // Transaction arrives
        manager.handle_tx(tx, test_socket_address(1), &requests).await.unwrap();

        // Pending IS lock consumed
        assert!(manager.pending_is_locks.is_empty());

        // Transaction stored with IS flag set
        assert!(manager.transactions.get(&txid).unwrap().is_instant_send);

        // Wallet received the IS lock payload with the correct cyclehash
        let w = wallet.read().await;
        let locks = w.processed_instant_locks.lock().await;
        let received = locks.iter().find(|(id, lock)| {
            *id == txid
                && lock
                    .as_ref()
                    .is_some_and(|l| l.cyclehash == BlockHash::from_byte_array([0xab; 32]))
        });
        assert!(received.is_some(), "wallet should have received rich IS lock with cyclehash 0xab");
    }

    #[tokio::test]
    async fn test_instant_send_before_irrelevant_transaction() {
        let (mut manager, requests, _rx) = create_test_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 88,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        // IS lock arrives before the transaction
        manager.process_instant_send(dummy_instant_lock(txid)).await;
        assert!(manager.pending_is_locks.contains_key(&txid));

        // Transaction arrives but wallet says it's not relevant
        manager.handle_tx(tx, test_socket_address(1), &requests).await.unwrap();

        // Pending IS lock cleaned up (no leak)
        assert!(manager.pending_is_locks.is_empty());

        // Irrelevant tx should not be stored
        assert!(!manager.transactions.contains_key(&txid));
    }

    #[tokio::test]
    async fn test_pending_is_locks_capacity_limit() {
        let (mut manager, _requests, _rx) = create_test_manager();

        // Fill pending IS locks to capacity
        for i in 0..MAX_PENDING_IS_LOCKS {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let txid = Txid::from_byte_array(bytes);
            manager.pending_is_locks.insert(txid, (dummy_instant_lock(txid), Instant::now()));
        }
        assert_eq!(manager.pending_is_locks.len(), MAX_PENDING_IS_LOCKS);

        // Next IS lock should be dropped
        let overflow_txid = Txid::from_byte_array([0xff; 32]);
        manager.process_instant_send(dummy_instant_lock(overflow_txid)).await;
        assert!(!manager.pending_is_locks.contains_key(&overflow_txid));
        assert_eq!(manager.pending_is_locks.len(), MAX_PENDING_IS_LOCKS);
    }

    #[test]
    fn test_prune_expired_removes_is_lock_for_expired_tx() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        let test_timeout = Duration::from_secs(2);

        // Add the tx with a timestamp in the past so it expires
        let mut utx =
            UnconfirmedTransaction::new(tx, Amount::from_sat(0), false, false, Vec::new(), 0);
        utx.first_seen = Instant::now() - test_timeout - Duration::from_secs(1);
        manager.transactions.insert(txid, utx);

        // Also store a pending IS lock for this txid and an unrelated one
        let unrelated_txid = Txid::from_byte_array([0xdd; 32]);
        manager.pending_is_locks.insert(txid, (dummy_instant_lock(txid), Instant::now()));
        manager
            .pending_is_locks
            .insert(unrelated_txid, (dummy_instant_lock(unrelated_txid), Instant::now()));

        manager.prune_expired(test_timeout);

        // The expired tx's IS lock should be removed
        assert!(
            !manager.pending_is_locks.contains_key(&txid),
            "IS lock for expired tx should be removed"
        );
        // The unrelated IS lock should be preserved
        assert!(
            manager.pending_is_locks.contains_key(&unrelated_txid),
            "IS lock for non-expired tx should be preserved"
        );
    }

    #[test]
    fn test_prune_expired_removes_stale_pending_is_locks() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let test_timeout = Duration::from_secs(2);

        // Insert a pending IS lock that is older than the test timeout
        let stale_txid = Txid::from_byte_array([0xaa; 32]);
        manager.pending_is_locks.insert(
            stale_txid,
            (
                dummy_instant_lock(stale_txid),
                Instant::now() - test_timeout - Duration::from_secs(1),
            ),
        );

        // Insert a fresh pending IS lock
        let fresh_txid = Txid::from_byte_array([0xbb; 32]);
        manager
            .pending_is_locks
            .insert(fresh_txid, (dummy_instant_lock(fresh_txid), Instant::now()));

        manager.prune_expired(test_timeout);

        assert!(
            !manager.pending_is_locks.contains_key(&stale_txid),
            "stale pending IS lock should be pruned"
        );
        assert!(
            manager.pending_is_locks.contains_key(&fresh_txid),
            "fresh pending IS lock should be preserved"
        );
    }

    #[tokio::test]
    async fn test_handle_inv_dedup_against_queue() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        // Fill pending to capacity so items go to queue
        for i in 0..MAX_IN_FLIGHT as u16 {
            let mut bytes = [0u8; 32];
            bytes[0..2].copy_from_slice(&i.to_le_bytes());
            manager.pending_requests.insert(Txid::from_byte_array(bytes), Instant::now());
        }

        let txid = Txid::from_byte_array([0xff; 32]);
        let inv = vec![Inventory::Transaction(txid)];

        // First call enqueues
        manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert_eq!(
            manager.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum::<usize>(),
            1
        );

        // Second call with same txid should be deduped
        manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert_eq!(
            manager.peers.values().filter_map(|v| v.as_ref()).map(|q| q.len()).sum::<usize>(),
            1
        );
    }

    #[tokio::test]
    async fn test_bloom_filter_load_failure_propagates() {
        let addr = test_address(0xab);
        let mut mock = MockWallet::new();
        mock.set_addresses(vec![addr]);
        let wallet = Arc::new(RwLock::new(mock));
        let (tx, rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(
            wallet,
            MempoolStrategy::BloomFilter,
            1000,
            0,
            BroadcastConfig::default(),
        );

        // Drop receiver so send_filter_load fails
        drop(rx);

        // activate() should propagate the error
        let result = manager.activate_peer(test_socket_address(1), &requests).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_tx_relevant_populates_wallet_effect_fields() {
        let (mut manager, requests, wallet) = create_relevant_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        let addr: Address =
            "yWdXnYxGbouNoo8yMvcbZmZ3Gdp6BpySxL".parse::<Address<_>>().unwrap().assume_checked();
        {
            let mut w = wallet.write().await;
            w.set_mempool_net_amount(50000);
            w.set_mempool_addresses(vec![addr.clone()]);
        }

        manager.handle_tx(tx, test_socket_address(1), &requests).await.unwrap();

        let stored = manager.transactions.get(&txid).unwrap();
        assert_eq!(stored.net_amount, 50000);
        assert!(!stored.is_outgoing);
        assert!(!stored.is_instant_send);
        assert_eq!(stored.addresses.len(), 1);
        assert_eq!(stored.addresses[0].to_string(), "yWdXnYxGbouNoo8yMvcbZmZ3Gdp6BpySxL");
    }

    #[tokio::test]
    async fn test_handle_tx_outgoing_transaction() {
        let (mut manager, requests, wallet) = create_relevant_manager();

        let tx = Transaction {
            version: 1,
            lock_time: 123,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();

        {
            let mut w = wallet.write().await;
            w.set_mempool_net_amount(-30000);
        }

        manager.handle_tx(tx, test_socket_address(1), &requests).await.unwrap();

        let stored = manager.transactions.get(&txid).unwrap();
        assert_eq!(stored.net_amount, -30000);
        assert!(stored.is_outgoing);
        assert!(!stored.is_instant_send);
        assert!(stored.addresses.is_empty());
    }

    #[test]
    fn test_peer_connected_creates_entry() {
        let (mut manager, _requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);

        assert!(!manager.peers.contains_key(&peer));
        manager.handle_peer_connected(peer);
        assert!(manager.peers.contains_key(&peer));
        assert!(manager.peers[&peer].is_none());
    }

    #[test]
    fn test_peer_disconnected_redistributes_queue() {
        let (mut manager, _requests, _rx) = create_test_manager();
        let peer1 = test_socket_address(1);
        let peer2 = test_socket_address(2);

        // Both peers activated with queues
        let txid1 = Txid::from_byte_array([1; 32]);
        let txid2 = Txid::from_byte_array([2; 32]);
        manager.peers.insert(peer1, Some(VecDeque::from([txid1, txid2])));
        manager.peers.insert(peer2, Some(VecDeque::new()));

        manager.handle_peer_disconnected(peer1);

        assert!(!manager.peers.contains_key(&peer1));
        // Txids should have moved to peer2
        let peer2_queue = manager.peers[&peer2].as_ref().unwrap();
        assert!(peer2_queue.contains(&txid1));
        assert!(peer2_queue.contains(&txid2));
    }

    #[test]
    fn test_peer_disconnected_no_peers_drops_queue() {
        let (mut manager, _requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);

        manager.peers.insert(peer, Some(VecDeque::from([Txid::from_byte_array([1; 32])])));

        manager.handle_peer_disconnected(peer);

        assert!(manager.peers.is_empty());
    }

    #[test]
    fn test_prune_pending_requeues_to_activated_peer() {
        let (mut manager, _requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        let txid = Txid::from_byte_array([1; 32]);
        manager
            .pending_requests
            .insert(txid, Instant::now() - PENDING_REQUEST_TIMEOUT - Duration::from_secs(1));

        manager.prune_pending_requests();

        assert!(!manager.pending_requests.contains_key(&txid));
        assert!(manager.peers[&peer].as_ref().unwrap().contains(&txid));
    }

    #[test]
    fn test_prune_pending_drops_when_no_peers() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let txid = Txid::from_byte_array([1; 32]);
        manager
            .pending_requests
            .insert(txid, Instant::now() - PENDING_REQUEST_TIMEOUT - Duration::from_secs(1));

        manager.prune_pending_requests();

        assert!(!manager.pending_requests.contains_key(&txid));
        assert!(manager.peers.is_empty());
    }

    #[test]
    fn test_remove_confirmed_removes_txids() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let mut txids = Vec::new();
        for i in 0..3u32 {
            let tx = Transaction {
                version: 1,
                lock_time: i,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            };
            let txid = tx.txid();
            txids.push(txid);
            if i < 2 {
                // Mark the first two as self-broadcasts
                manager.broadcasts.insert(txid, TxBroadcastState::new(tx.clone(), Instant::now()));
            }
            manager.transactions.insert(
                txid,
                UnconfirmedTransaction::new(tx, Amount::from_sat(0), false, false, Vec::new(), 0),
            );
        }
        assert_eq!(manager.transactions.len(), 3);

        // Remove 2 of the 3 transactions
        let events = manager.remove_confirmed(&txids[..2]);

        assert_eq!(manager.transactions.len(), 1);
        assert!(manager.transactions.contains_key(&txids[2]));
        assert!(!manager.broadcasts.contains_key(&txids[0]));
        assert!(!manager.broadcasts.contains_key(&txids[1]));
        // Both pending broadcasts were confirmed => promoted to accepted
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| matches!(
            e,
            SyncEvent::TransactionBroadcastResult {
                result: BroadcastResult::Accepted {
                    relayed_by: 0
                },
                ..
            }
        )));

        assert_eq!(manager.progress.removed(), 2);
        assert_eq!(manager.progress.tracked(), 1);
    }

    #[test]
    fn test_remove_confirmed_unknown_txids_noop() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let unknown = vec![Txid::from_byte_array([0xaa; 32]), Txid::from_byte_array([0xbb; 32])];

        manager.remove_confirmed(&unknown);

        assert!(manager.transactions.is_empty());
        assert_eq!(manager.progress.removed(), 0);
    }

    #[tokio::test]
    async fn test_rebuild_filter_clears_and_reloads() {
        let addr = test_address(0xab);
        let (mut manager, requests, mut rx) = create_bloom_manager_with_addresses(vec![addr]);
        let peer = test_socket_address(1);

        manager.activate_peer(peer, &requests).await.unwrap();

        // Drain activation messages
        while rx.try_recv().is_ok() {}

        manager.rebuild_filter(&requests).await.unwrap();

        // Verify message sequence: FilterClear, FilterLoad, MemPool
        let msg1 = rx.try_recv().unwrap();
        assert!(matches!(msg1, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterClear, _)));
        let msg2 = rx.try_recv().unwrap();
        assert!(matches!(
            msg2,
            NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _)
        ));
        let msg3 = rx.try_recv().unwrap();
        assert!(matches!(msg3, NetworkRequest::SendMessageToPeer(NetworkMessage::MemPool, _)));
    }

    #[tokio::test]
    async fn test_rebuild_filter_no_activated_peers_noop() {
        let (mut manager, requests, mut rx) = create_bloom_manager();
        // No activation, so no activated peers
        assert!(manager.peers.values().all(|v| v.is_none()));

        manager.rebuild_filter(&requests).await.unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_seen_txids_deduplication_window() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        let txid = Txid::from_byte_array([1u8; 32]);
        let inv = vec![Inventory::Transaction(txid)];

        // A fresh seen_txids entry should cause handle_inv to skip the txid
        manager.seen_txids.insert(txid, Instant::now());
        manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert!(manager.pending_requests.is_empty(), "seen txid should be skipped");

        // An expired entry should allow the txid to be accepted again
        manager.seen_txids.insert(txid, Instant::now() - SEEN_TXID_EXPIRY - Duration::from_secs(1));
        manager.handle_inv(&inv, peer, &requests).await.unwrap();
        assert!(
            manager.pending_requests.contains_key(&txid),
            "expired seen txid should be accepted"
        );
    }

    #[tokio::test]
    async fn test_broadcast_seeds_acceptance_from_earlier_instant_lock() {
        let (mut manager, requests, _rx) = create_test_manager();
        let tx = test_transaction(40);
        let txid = tx.txid();

        // The same signed transaction reached the network by another route first (a BIP70
        // merchant broadcasting the bytes it was just paid with), so its InstantSend lock
        // arrives before this node dispatches its own copy.
        manager.process_instant_send(dummy_instant_lock(txid)).await;
        assert!(manager.pending_is_locks.contains_key(&txid));

        let events = manager.start_broadcast(&tx, &requests);

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::TransactionBroadcastResult {
                    txid: seen,
                    result: BroadcastResult::Accepted { relayed_by: 0 },
                }] if *seen == txid
            ),
            "a lock that preceded the broadcast still proves acceptance, got {:?}",
            events
        );
        assert_eq!(
            manager.broadcasts.get(&txid).map(|state| state.status),
            Some(BroadcastStatus::Accepted)
        );
    }

    #[tokio::test]
    async fn test_broadcast_seeds_acceptance_from_peer_relay() {
        let (mut manager, requests, _rx) = create_test_manager();
        let tx = test_transaction(41);
        let txid = tx.txid();

        // A peer relayed the transaction to us before we broadcast it — the same proof of
        // propagation the echo threshold waits for, and one no later echo can repeat.
        manager.transactions.insert(
            txid,
            UnconfirmedTransaction::new(tx.clone(), Amount::ZERO, false, false, vec![], 0),
        );

        let events = manager.start_broadcast(&tx, &requests);

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::TransactionBroadcastResult {
                    result: BroadcastResult::Accepted {
                        relayed_by: 0
                    },
                    ..
                }]
            ),
            "a peer relay that preceded the broadcast still proves acceptance, got {:?}",
            events
        );
    }

    #[tokio::test]
    async fn test_broadcast_seeds_acceptance_from_irrelevant_peer_relay() {
        let (mut manager, requests, _rx) = create_test_manager();
        let tx = test_transaction(44);
        let txid = tx.txid();

        // A peer relayed the transaction and the wallet found it irrelevant, so it never entered
        // `transactions` — but the network demonstrably has it.
        manager.handle_tx(tx.clone(), test_socket_address(1), &requests).await.unwrap();
        assert!(!manager.transactions.contains_key(&txid));
        assert!(manager.seen_txids.contains_key(&txid));

        let events = manager.start_broadcast(&tx, &requests);

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::TransactionBroadcastResult {
                    result: BroadcastResult::Accepted {
                        relayed_by: 0
                    },
                    ..
                }]
            ),
            "relay is relay even when the wallet ignored the transaction, got {:?}",
            events
        );
    }

    #[tokio::test]
    async fn test_broadcast_without_prior_evidence_stays_pending() {
        let (mut manager, requests, _rx) = create_test_manager();
        let tx = test_transaction(42);
        let txid = tx.txid();

        let events = manager.start_broadcast(&tx, &requests);

        assert!(events.is_empty(), "nothing is known yet, got {:?}", events);
        assert_eq!(
            manager.broadcasts.get(&txid).map(|state| state.status),
            Some(BroadcastStatus::Pending)
        );
    }

    #[tokio::test]
    async fn test_handle_tx_reports_acceptance_proven_before_dispatch() {
        let (mut manager, requests, _rx) = create_test_manager();
        let tx = test_transaction(43);
        let txid = tx.txid();

        manager.process_instant_send(dummy_instant_lock(txid)).await;

        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let events = manager.handle_tx(tx, local_addr, &requests).await.unwrap();

        assert!(
            events.iter().any(|event| matches!(
                event,
                SyncEvent::TransactionBroadcastResult {
                    txid: seen,
                    result: BroadcastResult::Accepted { .. },
                } if *seen == txid
            )),
            "handle_tx must forward the verdict, otherwise the waiter never sees it: {:?}",
            events
        );
    }

    fn test_transaction(version: u16) -> Transaction {
        Transaction {
            version,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        }
    }

    #[tokio::test]
    async fn test_rebroadcast_sends_old_pending_broadcasts() {
        let (mut manager, requests, mut rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        let tx = test_transaction(10);
        let txid = tx.txid();

        let t0 = Instant::now();
        let later = t0 + REBROADCAST_INTERVAL + Duration::from_secs(1);

        let mut state = TxBroadcastState::new(tx, t0);
        state.sent_to.insert(peer);
        manager.broadcasts.insert(txid, state);

        manager.rebroadcast_if_due_at(&requests, later).await;

        // Pending entries are resent via targeted sends (respecting the holdout)
        let msg = rx.try_recv().expect("expected a rebroadcast message");
        assert!(
            matches!(msg, NetworkRequest::SendMessageToPeer(NetworkMessage::Tx(_), p) if p == peer),
            "expected SendMessageToPeer(Tx), got {:?}",
            msg
        );

        // Timestamp should be reset to `later`, so a second call at the same instant
        // must not rebroadcast.
        manager.rebroadcast_if_due_at(&requests, later).await;
        assert!(rx.try_recv().is_err(), "should not rebroadcast immediately after reset");
    }

    #[tokio::test]
    async fn test_rebroadcast_uncertain_uses_full_broadcast() {
        let (mut manager, requests, mut rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        let tx = test_transaction(12);
        let txid = tx.txid();

        let t0 = Instant::now();
        let later = t0 + REBROADCAST_INTERVAL + Duration::from_secs(1);

        let mut state = TxBroadcastState::new(tx, t0);
        state.sent_to.insert(peer);
        state.status = BroadcastStatus::Uncertain;
        manager.broadcasts.insert(txid, state);

        manager.rebroadcast_if_due_at(&requests, later).await;

        let msg = rx.try_recv().expect("expected a rebroadcast message");
        assert!(
            matches!(msg, NetworkRequest::BroadcastMessage(NetworkMessage::Tx(_))),
            "expected BroadcastMessage(Tx), got {:?}",
            msg
        );
    }

    #[tokio::test]
    async fn test_rebroadcast_skips_recent_transactions() {
        let (mut manager, requests, mut rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, Some(VecDeque::new()));

        let tx = test_transaction(11);
        let txid = tx.txid();

        // Add a broadcast that was just sent (within the rebroadcast interval)
        let mut state = TxBroadcastState::new(tx, Instant::now());
        state.sent_to.insert(peer);
        manager.broadcasts.insert(txid, state);

        manager.rebroadcast_if_due(&requests).await;

        assert!(rx.try_recv().is_err(), "recently sent transactions should not be rebroadcast");
    }

    #[test]
    fn test_peer_disconnect_keeps_other_peers_intact() {
        let (mut manager, _requests, _rx) = create_test_manager();
        let peer1 = test_socket_address(1);
        let peer2 = test_socket_address(2);

        // Both activated
        manager.peers.insert(peer1, Some(VecDeque::new()));
        manager.peers.insert(peer2, Some(VecDeque::from([Txid::from_byte_array([1; 32])])));

        manager.handle_peer_disconnected(peer1);

        assert!(!manager.peers.contains_key(&peer1));
        // peer2 should still be present and activated
        assert!(manager.peers.contains_key(&peer2));
        assert!(manager.peers[&peer2].is_some());
    }

    // ---- Broadcast acceptance tracking ----

    const LOCAL_SENTINEL: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

    fn drain_tx_sends(rx: &mut mpsc::UnboundedReceiver<NetworkRequest>) -> Vec<SocketAddr> {
        let mut sends = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let NetworkRequest::SendMessageToPeer(NetworkMessage::Tx(_), peer) = msg {
                sends.push(peer);
            }
        }
        sends
    }

    fn accepted_event_count(events: &[SyncEvent]) -> usize {
        events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    SyncEvent::TransactionBroadcastResult {
                        result: BroadcastResult::Accepted { .. },
                        ..
                    }
                )
            })
            .count()
    }

    #[tokio::test]
    async fn test_local_tx_sends_to_half_of_peers() {
        let (mut manager, requests, mut rx) = create_test_manager();
        for i in 1..=4 {
            manager.peers.insert(test_socket_address(i), None);
        }

        let tx = test_transaction(20);
        let txid = tx.txid();
        manager.handle_tx(tx, LOCAL_SENTINEL, &requests).await.unwrap();

        let sends = drain_tx_sends(&mut rx);
        assert_eq!(sends.len(), 2, "should send to half of 4 peers");

        let state = manager.broadcasts.get(&txid).expect("broadcast tracked");
        assert_eq!(state.sent_to.len(), 2);
        assert_eq!(state.holdout.len(), 2);
        assert!(state.sent_to.is_disjoint(&state.holdout));
        assert_eq!(state.status, BroadcastStatus::Pending);

        // A second local dispatch of the same tx must not resend
        let tx = test_transaction(20);
        manager.handle_tx(tx, LOCAL_SENTINEL, &requests).await.unwrap();
        assert!(drain_tx_sends(&mut rx).is_empty(), "idempotent per txid");
    }

    #[tokio::test]
    async fn test_local_tx_single_peer_no_holdout() {
        let (mut manager, requests, mut rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.peers.insert(peer, None);

        let tx = test_transaction(21);
        let txid = tx.txid();
        manager.handle_tx(tx, LOCAL_SENTINEL, &requests).await.unwrap();

        assert_eq!(drain_tx_sends(&mut rx), vec![peer]);
        let state = manager.broadcasts.get(&txid).unwrap();
        assert!(state.holdout.is_empty(), "single peer leaves nobody to hold out");
    }

    #[tokio::test]
    async fn test_echo_from_holdout_peer_accepts_once() {
        let (mut manager, requests, mut rx) = create_test_manager();
        let recipient = test_socket_address(1);
        let holdout = test_socket_address(2);
        manager.peers.insert(recipient, None);
        manager.peers.insert(holdout, None);

        let tx = test_transaction(22);
        let txid = tx.txid();
        let mut state = TxBroadcastState::new(tx, Instant::now());
        state.sent_to.insert(recipient);
        state.holdout.insert(holdout);
        manager.broadcasts.insert(txid, state);
        drain_tx_sends(&mut rx);

        let inv = vec![Inventory::Transaction(txid)];

        // Echo from the recipient peer carries no information
        let events = manager.handle_inv(&inv, recipient, &requests).await.unwrap();
        assert_eq!(accepted_event_count(&events), 0);
        assert_eq!(manager.broadcasts[&txid].status, BroadcastStatus::Pending);

        // Echo from the holdout peer proves propagation
        let events = manager.handle_inv(&inv, holdout, &requests).await.unwrap();
        assert_eq!(accepted_event_count(&events), 1);
        assert_eq!(manager.broadcasts[&txid].status, BroadcastStatus::Accepted);

        // A repeat announcement must not emit a second event
        let events = manager.handle_inv(&inv, holdout, &requests).await.unwrap();
        assert_eq!(accepted_event_count(&events), 0);
    }

    #[tokio::test]
    async fn test_echo_detected_when_mempool_full() {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx_chan, _rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx_chan);
        let mut manager = MempoolManager::new(
            wallet,
            MempoolStrategy::FetchAll,
            1, // capacity of one
            0,
            BroadcastConfig::default(),
        );

        // Fill the mempool to capacity with an unrelated transaction
        let filler = test_transaction(23);
        manager.transactions.insert(
            filler.txid(),
            UnconfirmedTransaction::new(filler, Amount::from_sat(0), false, false, Vec::new(), 0),
        );

        let holdout = test_socket_address(2);
        let tx = test_transaction(24);
        let txid = tx.txid();
        let mut state = TxBroadcastState::new(tx, Instant::now());
        state.sent_to.insert(test_socket_address(1));
        state.holdout.insert(holdout);
        manager.broadcasts.insert(txid, state);

        // The mempool-full early return must not swallow the acceptance echo
        let inv = vec![Inventory::Transaction(txid)];
        let events = manager.handle_inv(&inv, holdout, &requests).await.unwrap();
        assert_eq!(accepted_event_count(&events), 1);
    }

    #[tokio::test]
    async fn test_timeout_uncertain_then_late_echo_upgrades() {
        let (mut manager, requests, _rx) = create_test_manager();
        let holdout = test_socket_address(2);

        let tx = test_transaction(28);
        let txid = tx.txid();
        let t0 = Instant::now();
        let mut state = TxBroadcastState::new(tx, t0);
        state.sent_to.insert(test_socket_address(1));
        state.holdout.insert(holdout);
        manager.broadcasts.insert(txid, state);

        // Before the timeout nothing expires
        let events = manager.expire_broadcasts_at(t0 + Duration::from_secs(1));
        assert!(events.is_empty());

        // At the timeout the broadcast becomes uncertain, exactly once
        let deadline = t0 + BroadcastConfig::default().acceptance_timeout;
        let events = manager.expire_broadcasts_at(deadline);
        assert!(matches!(
            events.as_slice(),
            [SyncEvent::TransactionBroadcastResult {
                result: BroadcastResult::Uncertain,
                ..
            }]
        ));
        assert!(manager.expire_broadcasts_at(deadline + Duration::from_secs(9)).is_empty());
        assert_eq!(manager.broadcasts[&txid].status, BroadcastStatus::Uncertain);

        // A late echo still upgrades the outcome to accepted
        let inv = vec![Inventory::Transaction(txid)];
        let events = manager.handle_inv(&inv, holdout, &requests).await.unwrap();
        assert_eq!(accepted_event_count(&events), 1);
        assert_eq!(manager.broadcasts[&txid].status, BroadcastStatus::Accepted);
    }

    #[tokio::test]
    async fn test_zero_peers_at_broadcast_sends_on_next_tick() {
        let (mut manager, requests, mut rx) = create_test_manager();

        // No peers connected at broadcast time
        let tx = test_transaction(29);
        let txid = tx.txid();
        manager.handle_tx(tx, LOCAL_SENTINEL, &requests).await.unwrap();
        assert!(drain_tx_sends(&mut rx).is_empty());
        assert!(manager.broadcasts[&txid].sent_to.is_empty());

        // A peer connects; the never-sent broadcast is due immediately
        let peer = test_socket_address(1);
        manager.peers.insert(peer, None);
        manager.rebroadcast_if_due(&requests).await;
        assert_eq!(drain_tx_sends(&mut rx), vec![peer]);
        assert!(manager.broadcasts[&txid].sent_to.contains(&peer));
    }

    #[tokio::test]
    async fn test_holdout_sticky_across_rebroadcasts() {
        let (mut manager, requests, mut rx) = create_test_manager();
        let recipient = test_socket_address(1);
        let holdout = test_socket_address(2);
        manager.peers.insert(recipient, None);
        manager.peers.insert(holdout, None);

        let tx = test_transaction(30);
        let txid = tx.txid();
        let t0 = Instant::now();
        let mut state = TxBroadcastState::new(tx, t0);
        state.sent_to.insert(recipient);
        state.holdout.insert(holdout);
        manager.broadcasts.insert(txid, state);

        let later = t0 + REBROADCAST_INTERVAL + Duration::from_secs(1);
        manager.rebroadcast_if_due_at(&requests, later).await;

        // Only the original recipient is resent to; the holdout stays withheld
        assert_eq!(drain_tx_sends(&mut rx), vec![recipient]);
        assert_eq!(manager.broadcasts[&txid].holdout, [holdout].into_iter().collect());
    }

    #[tokio::test]
    async fn test_holdout_repicked_when_all_holdouts_disconnect() {
        let (mut manager, requests, mut rx) = create_test_manager();
        let recipient = test_socket_address(1);
        let new_peer = test_socket_address(3);
        manager.peers.insert(recipient, None);
        manager.peers.insert(new_peer, None);

        let tx = test_transaction(31);
        let txid = tx.txid();
        let t0 = Instant::now();
        let mut state = TxBroadcastState::new(tx, t0);
        state.sent_to.insert(recipient);
        // Original holdout peer already disconnected (not in manager.peers)
        state.holdout.insert(test_socket_address(2));
        manager.broadcasts.insert(txid, state);

        let later = t0 + REBROADCAST_INTERVAL + Duration::from_secs(1);
        manager.rebroadcast_if_due_at(&requests, later).await;

        // The never-sent connected peer becomes the replacement holdout,
        // so the resend goes only to the original recipient.
        assert_eq!(drain_tx_sends(&mut rx), vec![recipient]);
        assert!(manager.broadcasts[&txid].holdout.contains(&new_peer));
        assert!(!manager.broadcasts[&txid].sent_to.contains(&new_peer));
    }

    #[tokio::test]
    async fn test_acceptance_threshold_two_requires_two_peers() {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx_chan, _rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx_chan);
        let mut manager = MempoolManager::new(
            wallet,
            MempoolStrategy::FetchAll,
            1000,
            0,
            BroadcastConfig {
                acceptance_threshold: 2,
                ..BroadcastConfig::default()
            },
        );

        let holdout1 = test_socket_address(2);
        let holdout2 = test_socket_address(3);
        let tx = test_transaction(32);
        let txid = tx.txid();
        let mut state = TxBroadcastState::new(tx, Instant::now());
        state.sent_to.insert(test_socket_address(1));
        state.holdout.extend([holdout1, holdout2]);
        manager.broadcasts.insert(txid, state);

        let inv = vec![Inventory::Transaction(txid)];
        let events = manager.handle_inv(&inv, holdout1, &requests).await.unwrap();
        assert_eq!(accepted_event_count(&events), 0, "one echo below threshold");

        let events = manager.handle_inv(&inv, holdout2, &requests).await.unwrap();
        assert_eq!(accepted_event_count(&events), 1, "second distinct peer meets threshold");
        assert!(matches!(
            events.as_slice(),
            [SyncEvent::TransactionBroadcastResult {
                result: BroadcastResult::Accepted {
                    relayed_by: 2
                },
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn test_clear_pending_preserves_broadcasts() {
        let (mut manager, _requests, _rx) = create_test_manager();

        let tx = test_transaction(33);
        let txid = tx.txid();
        manager.broadcasts.insert(txid, TxBroadcastState::new(tx, Instant::now()));

        manager.clear_pending();

        assert!(
            manager.broadcasts.contains_key(&txid),
            "broadcast tracking must survive disconnects"
        );
    }

    #[test]
    fn test_prune_expired_removes_old_broadcasts() {
        let (mut manager, _requests, _rx) = create_test_manager();
        let timeout = Duration::from_secs(2);

        let fresh = test_transaction(34);
        let fresh_txid = fresh.txid();
        manager.broadcasts.insert(fresh_txid, TxBroadcastState::new(fresh, Instant::now()));

        let stale = test_transaction(35);
        let stale_txid = stale.txid();
        let mut stale_state =
            TxBroadcastState::new(stale, Instant::now() - timeout - Duration::from_secs(1));
        stale_state.status = BroadcastStatus::Uncertain;
        manager.broadcasts.insert(stale_txid, stale_state);

        manager.prune_expired(timeout);

        assert!(manager.broadcasts.contains_key(&fresh_txid));
        assert!(!manager.broadcasts.contains_key(&stale_txid));
    }
}
