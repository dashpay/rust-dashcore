//! Walking ChainLock trust up from an old anchor towards the tip.
//!
//! A ChainLock quorum signs for a limited number of blocks, so once the anchor
//! lags the tip by more than that, no quorum signing at the tip is anchored,
//! and peers serve no ChainLocks of past heights. Every coinbase carries a
//! ChainLock for an ancestor just below it (DIP-29), though. Each step fetches
//! the list a few ChainLock mining windows above the anchor, then the
//! coinbases of the blocks just above that list, until a quorum the anchor
//! vouches for signed one of their ChainLocks: that anchors the list, and with
//! it the quorums mined in the windows it crossed.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::pipeline::MNLISTDIFF_DEADLINE;
use crate::chain::CheckpointManager;
use crate::error::SyncResult;
use crate::network::{NetworkManager, RequestKey, SendRequest};
use crate::sml_engine::{
    may_root_at_checkpoint, trusts_first_chain_lock, AnchorRoot, ChainLockAnchor, ChainLockVerdict,
    FeedError,
};
use crate::storage::BlockHeaderStorage;
use crate::sync::{MasternodesManager, SyncEvent, SyncManager, SyncState};
use dashcore::hashes::Hash;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_sml::{GetMnListDiff, MnListDiff};
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::error::SmlError;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::{BlockHash, Network};

/// Coinbase ChainLocks tried per planned step.
const CARRIERS_PER_STEP: u32 = 7;
/// Steps tried on one list before the next one past one more window.
const STEPS_PER_LIST: u32 = 2;
/// The wait after a first failed step, doubling with each one after it.
const MIN_BACKOFF: Duration = Duration::from_secs(30);
/// The longest wait between failed steps.
const MAX_BACKOFF: Duration = Duration::from_secs(600);
/// How long the first QRInfo of a sync waits for the walk. Running the walk
/// first only spares the QRInfo the diffs from genesis, so a long walk must
/// not keep the tip lists from wallets.
const QRINFO_WAIT: Duration = Duration::from_secs(30);

/// Whether the engine did not take a diff the walk asked for because of our
/// own state: a header storage that cannot be read, or a base or block our
/// header chain or lists no longer hold as they did when the walk asked.
/// Every peer's answer would fail the same way, so the walk plans again.
fn is_our_gap(error: &FeedError<SmlError>) -> bool {
    matches!(
        error,
        FeedError::HeaderStorage(_)
            | FeedError::Refused(
                SmlError::BlockHashLookupFailed(_)
                    | SmlError::MissingStartMasternodeList(_)
                    | SmlError::BaseBlockHashMismatch { .. }
                    | SmlError::BaseBlockNotGenesis(_)
            )
    )
}

/// A step of the walk: the list a ChainLock at or above it anchors, and the
/// blocks whose coinbase ChainLocks are tried, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    list_height: CoreBlockHeight,
    carriers: Vec<CoreBlockHeight>,
}

/// The windows of `chain_locks_type` a step crosses at most: about half the
/// active quorums, so each ChainLock of the step is signed by an anchored
/// quorum at least half the time, and at least one, so each step brings the
/// quorum of a window it crosses.
fn windows_per_step(chain_locks_type: LLMQType) -> u32 {
    (chain_locks_type.active_quorum_count().saturating_sub(1) / 2).max(1)
}

/// The `nth` (from 1) mining window of `chain_locks_type` that ends above
/// `anchor`, as its start and end heights.
fn window_ending_above(
    chain_locks_type: LLMQType,
    anchor: CoreBlockHeight,
    nth: u32,
) -> Option<(CoreBlockHeight, CoreBlockHeight)> {
    let interval = chain_locks_type.dkg_interval();
    if interval == 0 {
        return None;
    }
    let window = chain_locks_type.dkg_window_at_cycle(0);
    let mut cycle = anchor - anchor % interval;
    let mut found = 0;
    loop {
        let end = cycle.checked_add(window.mining_end)?;
        if end > anchor {
            found += 1;
            if found == nth {
                return Some((cycle.checked_add(window.mining_start)?, end));
            }
        }
        cycle = cycle.checked_add(interval)?;
    }
}

/// The end of the last mining window of `chain_locks_type` at or below
/// `height`. An anchored list from there up to `height` holds every quorum
/// whose mining window ended by `height`.
fn last_window_end_at_or_below(
    chain_locks_type: LLMQType,
    height: CoreBlockHeight,
) -> CoreBlockHeight {
    let interval = chain_locks_type.dkg_interval();
    if interval == 0 {
        return height;
    }
    let window_end = chain_locks_type.dkg_window_at_cycle(0).mining_end;
    let cycle = height - height % interval;
    match cycle.checked_add(window_end) {
        Some(end) if end <= height => end,
        _ => cycle.checked_sub(interval).map_or(0, |previous| previous + window_end),
    }
}

/// The list height and carrier heights of the step that crosses `crossed`
/// windows above `anchor`, if its list sits below `tip`. The list sits 8 blocks
/// past the end of the last window crossed, so no window has a block in the 8
/// blocks up to it and its ChainLock quorums are those active at the signing
/// height of every ChainLock the carriers bring. Carriers go on until a
/// ChainLock's signing height would reach the next window.
fn gap(
    chain_locks_type: LLMQType,
    anchor: CoreBlockHeight,
    tip: CoreBlockHeight,
    crossed: u32,
) -> Option<(CoreBlockHeight, Vec<CoreBlockHeight>)> {
    let (_, last_end) = window_ending_above(chain_locks_type, anchor, crossed)?;
    let (next_start, _) = window_ending_above(chain_locks_type, anchor, crossed + 1)?;
    let list_height = last_end.checked_add(8)?;
    if list_height >= tip {
        return None;
    }
    let last_carrier = next_start.saturating_add(8).min(tip);
    Some((list_height, (list_height + 1..=last_carrier).collect()))
}

/// The step to try on `attempt` (from 0) from `anchor`, with the header chain
/// at `tip`. The first attempts jump as far as [`windows_per_step`] allows,
/// or less near the tip. Later ones try further carriers of the same list,
/// then the list past one more window, so a retry never asks the same
/// quorums the same question, until a step would cross as many windows as
/// there are active quorums: past that, every quorum the anchor vouches for
/// may have retired. `None` once the attempts run out: on attempt 0, the
/// anchor is as close to the tip as a step can bring it.
fn plan_step(
    chain_locks_type: LLMQType,
    anchor: CoreBlockHeight,
    tip: CoreBlockHeight,
    attempt: u32,
) -> Option<Step> {
    let active = chain_locks_type.active_quorum_count();
    let mut crossed = (1..=windows_per_step(chain_locks_type))
        .rev()
        .find(|&crossed| gap(chain_locks_type, anchor, tip, crossed).is_some())?;
    let mut skip = attempt.saturating_mul(CARRIERS_PER_STEP) as usize;
    while crossed < active.max(2) {
        let (list_height, carriers) = gap(chain_locks_type, anchor, tip, crossed)?;
        // Whole steps of carriers, so every attempt starts a fresh one.
        let steps =
            carriers.len().div_ceil(CARRIERS_PER_STEP as usize).min(STEPS_PER_LIST as usize);
        let tried = steps * CARRIERS_PER_STEP as usize;
        if skip < tried {
            let carriers =
                carriers.into_iter().skip(skip).take(CARRIERS_PER_STEP as usize).collect();
            return Some(Step {
                list_height,
                carriers,
            });
        }
        skip -= tried;
        crossed += 1;
    }
    None
}

/// The newest compiled-in checkpoint at or below `tip` that trust can start
/// from, see [`may_root_at_checkpoint`], with its block stored in the header
/// chain.
async fn root_checkpoint<H: BlockHeaderStorage>(
    network: Network,
    headers: &H,
    tip: CoreBlockHeight,
) -> Option<ChainLockAnchor> {
    let eligible: Vec<_> = CheckpointManager::for_network(network)
        .checkpoints()
        .filter(|checkpoint| {
            checkpoint.height() <= tip && may_root_at_checkpoint(network, checkpoint.height())
        })
        .collect();
    for checkpoint in eligible.into_iter().rev() {
        let stored = headers.get_header(checkpoint.height()).await.ok().flatten();
        if stored.is_some_and(|header| header.hash() == checkpoint.hash()) {
            return Some(ChainLockAnchor {
                height: checkpoint.height(),
                block_hash: *checkpoint.hash(),
                root: AnchorRoot::Checkpoint(checkpoint.height()),
            });
        }
    }
    None
}

/// What a catch-up request fetches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fetch {
    /// The list at the anchor, which the anchor vouches for by itself.
    AnchorList,
    /// The list of the planned step.
    StepList,
    /// The coinbase of a block above the step's list.
    Carrier,
}

/// The diff the walk waits for. The broker sends the request, and re-sends it
/// to another peer when one stalls or is gone, until it is released.
#[derive(Debug, Clone, Copy)]
pub(super) struct Wanted {
    base: BlockHash,
    target: BlockHash,
    fetch: Fetch,
    /// When the walk started waiting, for [`MNLISTDIFF_DEADLINE`].
    since: Instant,
}

/// Where the walk is.
#[derive(Debug, Default)]
pub(super) struct CatchUp {
    /// Whether the walk runs: started once the anchor lags the tip, until it
    /// is as close as a step brings it.
    active: bool,
    /// When the walk started.
    started_at: Option<Instant>,
    /// Whether the first QRInfo of a sync waits for the walk.
    qrinfo_after: bool,
    pub(super) wanted: Option<Wanted>,
    /// The anchor height the attempts were last planned from.
    planned_from: Option<CoreBlockHeight>,
    /// Which planned step the walk is on, see [`plan_step`].
    attempt: u32,
    /// The next carrier of the step to try.
    carrier: usize,
    /// The header tip the anchor was last checked against while synced.
    checked_tip: Option<CoreBlockHeight>,
    /// Steps that failed in a row from the same anchor.
    failures: u32,
    /// No step is planned before then.
    retry_at: Option<Instant>,
    /// Whether a missing checkpoint to start trust from was reported.
    reported_no_root: bool,
    /// Whether the wanted diff of this step was planned again after a gap of
    /// ours. A second gap in the same step fails it.
    replanned: bool,
    /// Peers whose answer for a `(base, target)` the engine refused. Their
    /// later answers for it are ignored, so one peer cannot answer for it again
    /// and again: the broker sends the request to another peer once it waited
    /// for the refused one. A request planned again from another base asks
    /// every peer afresh. Forgotten when the anchor moves or the peers change.
    refusers: HashMap<(BlockHash, BlockHash), Vec<SocketAddr>>,
    /// Heights of the lists the walk built.
    built: BTreeSet<CoreBlockHeight>,
}

impl CatchUp {
    /// Plans from `anchor` from now on, from the first attempt and without a
    /// backoff if it moved.
    fn plan_from(&mut self, anchor: CoreBlockHeight) {
        if self.planned_from != Some(anchor) {
            self.planned_from = Some(anchor);
            self.failures = 0;
            self.attempt = 0;
            self.carrier = 0;
            self.replanned = false;
            self.refusers.clear();
        }
    }

    /// Moves on to the next attempt once a step's carriers are used up.
    fn next_attempt(&mut self) {
        self.attempt += 1;
        self.carrier = 0;
        self.replanned = false;
    }

    /// Gives up on the planned steps until a backoff passes, which doubles
    /// with every failure from the same anchor. The wanted diff, if any, must
    /// have been released.
    fn fail(&mut self, now: Instant) {
        self.wanted = None;
        self.attempt = 0;
        self.carrier = 0;
        self.replanned = false;
        self.failures = self.failures.saturating_add(1);
        let backoff = MIN_BACKOFF
            .saturating_mul(1u32 << self.failures.saturating_sub(1).min(16))
            .min(MAX_BACKOFF);
        self.retry_at = Some(now + backoff);
    }

    fn backing_off(&self, now: Instant) -> bool {
        self.retry_at.is_some_and(|retry_at| now < retry_at)
    }

    /// Drops the backoff earned with peers that are gone, and what they
    /// refused, so the walk resumes at once with the next ones. The wanted
    /// diff stays wanted: the broker sends it to the next peers.
    pub(super) fn reconnected(&mut self) {
        self.retry_at = None;
        self.refusers.clear();
    }

    fn has_refused(&self, diff: &MnListDiff, peer: SocketAddr) -> bool {
        self.refusers
            .get(&(diff.base_block_hash, diff.block_hash))
            .is_some_and(|peers| peers.contains(&peer))
    }

    /// How many peers refused their answer for `wanted`.
    fn refusals(&self, wanted: &Wanted) -> usize {
        self.refusers.get(&(wanted.base, wanted.target)).map_or(0, Vec::len)
    }

    fn refused_by(&mut self, wanted: &Wanted, peer: SocketAddr) {
        let peers = self.refusers.entry((wanted.base, wanted.target)).or_default();
        if !peers.contains(&peer) {
            peers.push(peer);
        }
    }

    /// Lets a QRInfo sent for any reason stand for the one the walk held.
    pub(super) fn qrinfo_sent(&mut self) {
        self.qrinfo_after = false;
    }

    /// Whether the walk built the list at `height`. Lists of its own lie far
    /// below the tip, so they alone do not end an initial sync.
    pub(super) fn built(&self, height: CoreBlockHeight) -> bool {
        self.built.contains(&height)
    }

    /// Ends the walk. Where its attempts were, and how often they failed from
    /// the same anchor, stays for the next walk.
    fn finish(&mut self) {
        self.active = false;
        self.started_at = None;
        self.retry_at = None;
    }
}

/// What the walk does next.
enum Next {
    Request(BlockHash, BlockHash, Fetch),
    /// Caught up as far as a step brings it, or nothing to walk from.
    Done,
    /// Every planned step was tried without a ChainLock anchoring one.
    Failed,
}

impl<H: BlockHeaderStorage> MasternodesManager<H> {
    /// Starts the walk if the anchor lags the tip by more than a step, and
    /// moves it on. On an initial sync the first QRInfo waits for it, for up
    /// to [`QRINFO_WAIT`], and then diffs from where it got to rather than
    /// from genesis.
    pub(super) async fn begin_catch_up(
        &mut self,
        network: &Arc<dyn NetworkManager>,
        qrinfo_after: bool,
    ) -> SyncResult<Vec<SyncEvent>> {
        self.sync_state.catch_up.qrinfo_after |= qrinfo_after;
        let now = Instant::now();
        if qrinfo_after {
            // An initial sync is under way from here, whether the walk or its
            // QRInfo goes first, so `tick` moves it on.
            if self.state() != SyncState::Synced {
                self.set_state(SyncState::Syncing);
            }
            // Masternode sync starts here, at a start or once peers are back,
            // so the walk's request and its hold on the QRInfo wait anew.
            self.sync_state.catch_up.started_at = Some(now);
            if let Some(wanted) = &mut self.sync_state.catch_up.wanted {
                wanted.since = now;
            }
        }
        if !self.sync_state.catch_up.active {
            self.sync_state.catch_up.active = true;
            self.sync_state.catch_up.started_at = Some(now);
            self.root_trust().await;
        }
        self.advance_catch_up(now, network).await
    }

    /// Sets the checkpoint trust starts from on a network that has them,
    /// once the header chain reaches one.
    async fn root_trust(&mut self) {
        let network = self.engine.read().await.network();
        if trusts_first_chain_lock(network) {
            return;
        }
        let root = {
            let headers = self.header_storage.read().await;
            match headers.get_tip_height().await {
                Some(tip) => root_checkpoint(network, &*headers, tip).await,
                None => None,
            }
        };
        match root {
            Some(root) => self.engine.write().await.set_root_anchor(root),
            None if !self.sync_state.catch_up.reported_no_root => {
                self.sync_state.catch_up.reported_no_root = true;
                tracing::error!(
                    "No checkpoint to start ChainLock trust from is stored on {network}: \
                     no quorum will be reported verified"
                );
            }
            None => {}
        }
    }

    /// Whether `diff` answers the walk's request.
    pub(super) fn expects_catch_up_diff(&self, diff: &MnListDiff) -> bool {
        self.sync_state.catch_up.wanted.is_some_and(|wanted| {
            wanted.target == diff.block_hash && wanted.base == diff.base_block_hash
        })
    }

    /// Applies a list the walk fetched, or tries the ChainLock a carrier's
    /// coinbase brings, then moves the walk on. A ChainLock that raises the
    /// anchor is announced as validated, so the ChainLock manager persists it.
    ///
    /// A coinbase the stored header proves is the block's own, so whatever its
    /// ChainLock, the walk goes on to the next block. An answer the engine
    /// refuses keeps the request wanted, and `peer`'s later answers for it are
    /// ignored: the broker sends the request to another peer once it waited
    /// for this one, and a refusal that blames `peer` bans it at once. Once
    /// two peers, or every peer there is, sent answers refused without blame,
    /// the walk backs off instead. A gap of ours, see [`is_our_gap`], releases
    /// the request and plans it again, once per step; a second one, or a
    /// header storage that cannot be read, backs the walk off.
    pub(super) async fn handle_catch_up_diff(
        &mut self,
        diff: &MnListDiff,
        peer: SocketAddr,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        if self.sync_state.catch_up.has_refused(diff, peer) {
            tracing::debug!(
                "Ignoring another catch-up answer for {} from {peer}, whose last was refused",
                diff.block_hash
            );
            return Ok(vec![]);
        }
        let Some(wanted) = self.sync_state.catch_up.wanted.take() else {
            return Ok(vec![]);
        };
        self.progress.bump_last_activity();
        let now = Instant::now();
        let mut events = Vec::new();
        let refused = match wanted.fetch {
            Fetch::AnchorList | Fetch::StepList => {
                let applied = self.engine.write().await.apply_diff(diff.clone()).await;
                match applied {
                    Ok(()) => {
                        let height =
                            self.engine.read().await.height_if_known(&diff.block_hash).await;
                        if let Some(height) = height {
                            self.sync_state.catch_up.built.insert(height);
                        }
                        None
                    }
                    Err(e) => Some(e),
                }
            }
            Fetch::Carrier => {
                let mut engine = self.engine.write().await;
                match engine.proven_coinbase_chain_lock(diff).await {
                    Ok(carried) => {
                        if let Some(chain_lock) = carried {
                            let before = engine.usable_anchor().await.map(|anchor| anchor.height);
                            let verdict = engine.accept_chain_lock(&chain_lock).await;
                            let after = engine.usable_anchor().await.map(|anchor| anchor.height);
                            match verdict {
                                ChainLockVerdict::Accepted if after > before => {
                                    tracing::info!(
                                        "Catch-up anchored the chain at {} from a coinbase ChainLock",
                                        chain_lock.block_height
                                    );
                                    events.push(SyncEvent::ChainLockReceived {
                                        chain_lock,
                                        validated: true,
                                    });
                                }
                                verdict => tracing::debug!(
                                    "Coinbase ChainLock at {} did not raise the anchor: {:?}",
                                    chain_lock.block_height,
                                    verdict
                                ),
                            }
                        }
                        self.sync_state.catch_up.carrier += 1;
                        None
                    }
                    Err(e) => Some(e),
                }
            }
        };
        match refused {
            None => {
                self.sync_state.catch_up.replanned = false;
                Self::release_catch_up_request(&wanted, network).await;
            }
            Some(FeedError::HeaderStorage(e)) => {
                tracing::warn!("Catch-up could not read the header chain, backing off: {}", e);
                Self::release_catch_up_request(&wanted, network).await;
                self.sync_state.catch_up.fail(now);
            }
            Some(e) if is_our_gap(&e) => {
                Self::release_catch_up_request(&wanted, network).await;
                if std::mem::replace(&mut self.sync_state.catch_up.replanned, true) {
                    tracing::warn!(
                        "Catch-up MnListDiff for {} not taken again, backing off: {}",
                        diff.block_hash,
                        e
                    );
                    self.sync_state.catch_up.fail(now);
                } else {
                    tracing::debug!(
                        "Catch-up MnListDiff for {} not taken, planning it again: {}",
                        diff.block_hash,
                        e
                    );
                }
            }
            Some(e) if e.blames_peer() => {
                tracing::warn!(
                    "Banning {} for a catch-up MnListDiff the engine refused: {}",
                    peer,
                    e
                );
                network.ban_peer(peer).await;
                self.sync_state.catch_up.refused_by(&wanted, peer);
                self.sync_state.catch_up.wanted = Some(wanted);
                return Ok(events);
            }
            Some(e) => {
                self.sync_state.catch_up.refused_by(&wanted, peer);
                // Answers two peers, or every peer there is, sent alike and the
                // engine refused, say more about our state than about theirs.
                // The step is given up rather than have the broker kick peer
                // after peer for it.
                let connected = network.connected_count().await as usize;
                if self.sync_state.catch_up.refusals(&wanted) >= connected.clamp(1, 2) {
                    tracing::warn!(
                        "Catch-up MnListDiff for {} refused from several peers, backing off: {}",
                        diff.block_hash,
                        e
                    );
                    self.sync_state.catch_up.refusers.remove(&(wanted.base, wanted.target));
                    Self::release_catch_up_request(&wanted, network).await;
                    self.sync_state.catch_up.fail(now);
                } else {
                    tracing::warn!(
                        "Catch-up MnListDiff for {} from {} refused, waiting for another peer: {}",
                        diff.block_hash,
                        peer,
                        e
                    );
                    self.sync_state.catch_up.wanted = Some(wanted);
                    return Ok(events);
                }
            }
        }
        events.extend(self.advance_catch_up(now, network).await?);
        Ok(events)
    }

    /// Stops the broker sending `wanted`, which the walk no longer waits for.
    /// The broker keys a request by its target only, so this also drops a
    /// request the diff pipeline made for the same target, which the pipeline
    /// declares again on its next tick.
    async fn release_catch_up_request(wanted: &Wanted, network: &Arc<dyn NetworkManager>) {
        network.release_request(RequestKey::MnListDiff(wanted.target)).await;
    }

    /// Sends the walk's next request. Ends the walk once caught up, and lets
    /// a QRInfo waiting for it go while it backs off or once it ended.
    async fn advance_catch_up(
        &mut self,
        now: Instant,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        let catch_up = &self.sync_state.catch_up;
        if !catch_up.active || catch_up.wanted.is_some() {
            return Ok(vec![]);
        }
        if catch_up.backing_off(now) {
            return self.release_qrinfo(network).await;
        }
        match self.next_catch_up_request().await {
            Next::Request(base, target, fetch) => {
                let wanted = Wanted {
                    base,
                    target,
                    fetch,
                    since: now,
                };
                Self::declare_catch_up_request(&wanted, network).await;
                self.sync_state.catch_up.wanted = Some(wanted);
                Ok(vec![])
            }
            Next::Done => {
                self.sync_state.catch_up.finish();
                self.release_qrinfo(network).await
            }
            Next::Failed => {
                tracing::warn!("No ChainLock anchored a catch-up step, backing off");
                self.sync_state.catch_up.fail(now);
                self.release_qrinfo(network).await
            }
        }
    }

    /// Hands `wanted` to the broker, which drops it while a request for the
    /// same target is in play.
    async fn declare_catch_up_request(wanted: &Wanted, network: &Arc<dyn NetworkManager>) {
        network
            .send(NetworkMessage::GetMnListD(GetMnListDiff {
                base_block_hash: wanted.base,
                block_hash: wanted.target,
            }))
            .await;
    }

    /// Sends the QRInfo of an initial sync once the walk no longer holds it.
    async fn release_qrinfo(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        if !std::mem::take(&mut self.sync_state.catch_up.qrinfo_after) {
            return Ok(vec![]);
        }
        self.sync_state.qrinfo_retry_count = 0;
        self.sync_state.clear_pending(network).await;
        self.send_qrinfo_for_tip(network).await
    }

    /// Lets a QRInfo that waited long enough go, gives the walk's request up
    /// past its deadline or declares it again, resumes the walk after a
    /// backoff, and starts it when the anchor fell behind a synced tip.
    pub(super) async fn tick_catch_up(
        &mut self,
        now: Instant,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();
        let waited_long = self
            .sync_state
            .catch_up
            .started_at
            .is_some_and(|started_at| now.saturating_duration_since(started_at) > QRINFO_WAIT);
        if self.sync_state.catch_up.qrinfo_after && waited_long {
            tracing::info!("Catch-up still walking, sending the QRInfo meanwhile");
            events.extend(self.release_qrinfo(network).await?);
        }
        if let Some(wanted) = self.sync_state.catch_up.wanted {
            if now.saturating_duration_since(wanted.since) > MNLISTDIFF_DEADLINE {
                tracing::warn!(
                    "No usable catch-up MnListDiff for {} within {}s, backing off",
                    wanted.target,
                    MNLISTDIFF_DEADLINE.as_secs()
                );
                Self::release_catch_up_request(&wanted, network).await;
                self.sync_state.catch_up.fail(now);
                events.extend(self.advance_catch_up(now, network).await?);
            } else {
                // The pipeline may have released the key for a target both
                // wanted, which leaves nothing in play for the walk; the
                // broker drops this while the walk's request is in play.
                Self::declare_catch_up_request(&wanted, network).await;
            }
            return Ok(events);
        }
        if self.sync_state.catch_up.active {
            events.extend(self.advance_catch_up(now, network).await?);
            return Ok(events);
        }
        let tip = self.progress.block_header_tip_height();
        if self.state() != SyncState::Synced
            || self.sync_state.has_pending_requests()
            || self.sync_state.catch_up.backing_off(now)
            || self.sync_state.catch_up.checked_tip == Some(tip)
        {
            return Ok(events);
        }
        self.sync_state.catch_up.checked_tip = Some(tip);
        events.extend(self.begin_catch_up(network, false).await?);
        Ok(events)
    }

    async fn hash_at(&self, height: CoreBlockHeight) -> Option<BlockHash> {
        match self.header_storage.read().await.get_header(height).await {
            Ok(header) => header.map(|header| *header.hash()),
            Err(e) => {
                tracing::warn!("Could not look up the block at {height} for catch-up: {e}");
                None
            }
        }
    }

    /// The hash of the newest list the engine holds below `height`, the base
    /// to fetch the list at `height` from; the zero hash for a full list.
    async fn base_below(&self, height: CoreBlockHeight) -> BlockHash {
        let engine = self.engine.read().await;
        engine
            .masternode_lists
            .range(..height)
            .next_back()
            .map_or(BlockHash::all_zeros(), |(_, list)| list.block_hash)
    }

    async fn next_catch_up_request(&mut self) -> Next {
        let Some(mut tip) = self.header_storage.read().await.get_tip_height().await else {
            return Next::Done;
        };
        // Once synced, tip updates keep the newest list, and the walk stays
        // below it, so a tip update in flight still extends the newest list.
        if self.state() == SyncState::Synced {
            if let Some(newest) = self.engine.read().await.latest_masternode_list() {
                tip = tip.min(newest.known_height);
            }
        }
        let chain_locks_type = self.engine.read().await.network().chain_locks_type();
        let Some(anchor) = self.engine.read().await.usable_anchor().await.filter(|anchor| {
            // Once synced, a list above the newest one is the tip updates'.
            anchor.height <= tip
        }) else {
            return Next::Done;
        };
        self.sync_state.catch_up.plan_from(anchor.height);

        let near = last_window_end_at_or_below(chain_locks_type, anchor.height);
        let held_near = {
            let engine = self.engine.read().await;
            engine
                .latest_anchored_list(anchor.height)
                .await
                .is_some_and(|list| list.known_height >= near)
        };
        if !held_near {
            return Next::Request(
                self.base_below(anchor.height).await,
                anchor.block_hash,
                Fetch::AnchorList,
            );
        }

        loop {
            let attempt = self.sync_state.catch_up.attempt;
            let Some(step) = plan_step(chain_locks_type, anchor.height, tip, attempt) else {
                return if attempt == 0 {
                    Next::Done
                } else {
                    Next::Failed
                };
            };
            let Some(list_hash) = self.hash_at(step.list_height).await else {
                return Next::Failed;
            };
            let held = self
                .engine
                .read()
                .await
                .masternode_lists
                .get(&step.list_height)
                .is_some_and(|list| list.block_hash == list_hash);
            if !held {
                return Next::Request(
                    self.base_below(step.list_height).await,
                    list_hash,
                    Fetch::StepList,
                );
            }
            let Some(&carrier) = step.carriers.get(self.sync_state.catch_up.carrier) else {
                self.sync_state.catch_up.next_attempt();
                continue;
            };
            let Some(carrier_hash) = self.hash_at(carrier).await else {
                return Next::Failed;
            };
            return Next::Request(list_hash, carrier_hash, Fetch::Carrier);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sml_engine::anchor::mining_windows_between;
    use crate::sml_engine::anchor::test_support::dkg;
    use test_case::test_case;

    /// Whether some block in `(from, to]` is in a mining window.
    fn crosses_a_window(
        chain_locks_type: LLMQType,
        from: CoreBlockHeight,
        to: CoreBlockHeight,
    ) -> bool {
        mining_windows_between(chain_locks_type, from, to) > 0
    }

    const TIP: CoreBlockHeight = 2_000_000;

    /// A step's list holds the ChainLock quorums active at every carrier's
    /// ChainLock, it crosses the windows the network allows, and no ChainLock
    /// of it is signed past the next window.
    #[test_case(Network::Mainnet, 1; "mainnet")]
    #[test_case(Network::Testnet, 11; "testnet")]
    #[test_case(Network::Regtest, 1; "regtest")]
    fn a_step_crosses_the_windows_the_network_allows_and_selects_exactly(
        network: Network,
        windows: u32,
    ) {
        let chain_locks_type = network.chain_locks_type();
        for anchor in [TIP - 100_003, TIP - 100_000, TIP - 99_990] {
            let step = plan_step(chain_locks_type, anchor, TIP, 0).expect("a step");
            let h = step.list_height;
            assert_eq!(mining_windows_between(chain_locks_type, anchor, h), windows);
            assert!(!crosses_a_window(chain_locks_type, h - 8, h));
            assert_eq!(step.carriers.first(), Some(&(h + 1)));
            for carrier in &step.carriers {
                let signing_height = carrier - 1 - 8;
                assert!(!crosses_a_window(
                    chain_locks_type,
                    h.min(signing_height),
                    h.max(signing_height)
                ));
            }
        }
    }

    /// Selection is a function of the height, so a retry must ask other
    /// ChainLocks: further carriers of the same list, then the list past one
    /// more window. Attempts stop before a step crosses as many windows as
    /// there are active quorums, past which none the anchor vouches for may
    /// still sign.
    #[test_case(Network::Mainnet; "mainnet")]
    #[test_case(Network::Testnet; "testnet")]
    #[test_case(Network::Regtest; "regtest")]
    fn a_retry_never_asks_the_same_chain_locks_again_and_attempts_end(network: Network) {
        let chain_locks_type = network.chain_locks_type();
        let active = chain_locks_type.active_quorum_count();
        let anchor = TIP - 100_000;
        let mut asked = std::collections::BTreeSet::new();
        let mut per_list = std::collections::BTreeMap::<CoreBlockHeight, u32>::new();
        let mut attempt = 0;
        while let Some(step) = plan_step(chain_locks_type, anchor, TIP, attempt) {
            *per_list.entry(step.list_height).or_default() += 1;
            assert!(
                mining_windows_between(chain_locks_type, anchor, step.list_height) < active.max(2)
            );
            for carrier in step.carriers {
                assert!(asked.insert(carrier), "carrier {carrier} asked twice");
            }
            attempt += 1;
        }
        // With two active quorums, a step past two windows may find all the
        // anchored ones retired, so only one list is ever tried.
        assert!(per_list.len() > 1 || active <= 2, "a list past one more window is tried");
        assert!(per_list.values().all(|steps| *steps <= STEPS_PER_LIST));
    }

    /// Near the tip a step crosses only the windows below it, and an anchor
    /// as close as a step brings it plans none.
    #[test]
    fn near_the_tip_a_step_crosses_fewer_windows_or_none_is_left() {
        let chain_locks_type = Network::Testnet.chain_locks_type();
        let dkg = dkg(chain_locks_type);
        assert!(windows_per_step(chain_locks_type) > 3);
        assert_eq!(plan_step(chain_locks_type, TIP - 1, TIP, 0), None, "caught up");

        let anchor = TIP - 3 * dkg.interval - 9;
        let step = plan_step(chain_locks_type, anchor, TIP, 0).expect("a step");
        assert!(mining_windows_between(chain_locks_type, anchor, step.list_height) < 4);
        assert!(step.list_height < TIP);
        assert!(step.carriers.iter().all(|carrier| *carrier <= TIP));
    }

    #[test_case(Network::Mainnet; "mainnet")]
    #[test_case(Network::Testnet; "testnet")]
    fn the_last_window_end_is_at_or_below_the_height(network: Network) {
        let chain_locks_type = network.chain_locks_type();
        let dkg = dkg(chain_locks_type);
        let cycle = 1_000 * dkg.interval;
        let end = cycle + dkg.mining_window_end;
        assert_eq!(last_window_end_at_or_below(chain_locks_type, end), end);
        assert_eq!(last_window_end_at_or_below(chain_locks_type, end + 1), end);
        assert_eq!(last_window_end_at_or_below(chain_locks_type, end - 1), end - dkg.interval);
    }

    mod walk {
        use std::sync::Arc;

        use super::super::*;
        use crate::sml_engine::anchor::test_support::{
            dkg, forged_chain_lock_quorum, sign_as_forger,
        };
        use crate::sml_engine::MasternodeListEngine;
        use crate::storage::{DiskStorageManager, PersistentBlockHeaderStorage, StorageManager};
        use crate::sync::masternodes::pipeline::DiffKind;
        use crate::test_utils::{test_socket_address, MockNetworkManager};
        use crate::types::HashedBlockHeader;
        use dashcore::block::Header;
        use dashcore::bls_sig_utils::BLSSignature;
        use dashcore::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
        use dashcore::network::message::NetworkMessage;
        use dashcore::network::message_sml::GetMnListDiff;
        use dashcore::sml::masternode_list::MasternodeList;
        use dashcore::transaction::special_transaction::coinbase::CoinbasePayload;
        use dashcore::transaction::special_transaction::TransactionPayload;
        use dashcore::{ChainLock, QuorumHash, TxMerkleNode};
        use std::collections::BTreeMap;
        use test_case::test_case;
        use tokio::sync::RwLock;

        type Manager = MasternodesManager<PersistentBlockHeaderStorage>;

        /// A walk over regtest headers, with the diffs that answer it.
        struct Walk {
            manager: Manager,
            hashes: Vec<BlockHash>,
            diffs: BTreeMap<CoreBlockHeight, MnListDiff>,
            network: Arc<dyn NetworkManager>,
            mock: Arc<MockNetworkManager>,
        }

        impl Walk {
            /// The `(base, target)` of each `GetMnListD` sent since the last call.
            async fn requested(&self) -> Vec<(BlockHash, BlockHash)> {
                let requests = self
                    .mock
                    .sent_messages()
                    .await
                    .into_iter()
                    .filter_map(|message| match message {
                        NetworkMessage::GetMnListD(request) => {
                            Some((request.base_block_hash, request.block_hash))
                        }
                        _ => None,
                    })
                    .collect();
                self.mock.clear_sent().await;
                requests
            }

            /// Hands `diff` to the manager as a peer's message.
            async fn deliver(&mut self, diff: &MnListDiff) {
                let message = NetworkMessage::MnListDiff(Box::new(diff.clone()));
                self.manager
                    .handle_message(test_socket_address(1), message.into(), &self.network)
                    .await
                    .unwrap();
            }

            async fn answer(
                &mut self,
                height: CoreBlockHeight,
                peer: SocketAddr,
            ) -> Vec<SyncEvent> {
                let diff = self.diffs.get(&height).expect("a diff for the height").clone();
                self.manager.handle_catch_up_diff(&diff, peer, &self.network).await.unwrap()
            }
        }

        /// The ChainLock quorum the anchor of every walk below vouches for.
        fn signer() -> QuorumHash {
            QuorumHash::from_byte_array([0x5a; 32])
        }

        /// The anchored list of every walk below, holding [`signer`].
        fn anchored_list(block_hash: BlockHash, anchor: CoreBlockHeight) -> MasternodeList {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let mut list = MasternodeList::empty(block_hash, anchor);
            Arc::make_mut(&mut list.quorums)
                .entry(chain_locks_type)
                .or_default()
                .insert(signer(), Arc::new(forged_chain_lock_quorum(chain_locks_type, signer())));
            list
        }

        /// An empty diff whose coinbase, at `height`, commits to `list` and
        /// carries `chain_lock` for the block below, proven as the only
        /// transaction of its block.
        fn proven_diff(
            height: CoreBlockHeight,
            list: &MasternodeList,
            chain_lock: Option<BLSSignature>,
        ) -> MnListDiff {
            let mut diff = MnListDiff::dummy_between(0, 0);
            let payload = CoinbasePayload {
                version: 3,
                height,
                merkle_root_masternode_list: list
                    .calculate_masternodes_merkle_root(height)
                    .unwrap_or_else(MerkleRootMasternodeList::all_zeros),
                merkle_root_quorums: list
                    .calculate_llmq_merkle_root()
                    .unwrap_or_else(MerkleRootQuorums::all_zeros),
                best_cl_height: Some(0),
                best_cl_signature: Some(chain_lock.unwrap_or(BLSSignature::from([0; 96]))),
                asset_locked_amount: Some(0),
                merkle_root_asset_unlocks: None,
            };
            diff.coinbase_tx.special_transaction_payload =
                Some(TransactionPayload::CoinbasePayloadType(payload));
            diff.merkle_hashes = vec![MerkleRootMasternodeList::from_raw_hash(
                diff.coinbase_tx.txid().to_raw_hash(),
            )];
            diff.merkle_flags = vec![1];
            diff
        }

        /// A regtest manager over headers up to `tip`, anchored at `anchor` by
        /// [`anchored_list`], and the diffs that answer its walk, each proven
        /// by the stored header of its block: the list of the first planned
        /// step, committing to what it builds on the anchored list, and at
        /// each of `carriers`, a coinbase with a ChainLock the given quorum
        /// signs for the block below. A coinbase does not depend on the hash
        /// of its block, so each header takes the merkle root of its diff, and
        /// the diff the hash of that header.
        async fn anchored_walk(
            anchor: CoreBlockHeight,
            tip: CoreBlockHeight,
            carriers: &[(CoreBlockHeight, QuorumHash)],
        ) -> Walk {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let step = plan_step(chain_locks_type, anchor, tip, 0);
            let template = anchored_list(BlockHash::all_zeros(), anchor);
            let mut diffs = BTreeMap::new();
            if let Some(step) = &step {
                diffs.insert(step.list_height, proven_diff(step.list_height, &template, None));
            }
            let mut stored = Vec::new();
            let mut hashes: Vec<BlockHash> = Vec::new();
            for height in 0..=tip {
                if let Some((_, quorum)) = carriers.iter().find(|(carrier, _)| *carrier == height) {
                    let chain_lock = ChainLock {
                        block_height: height - 1,
                        block_hash: hashes[height as usize - 1],
                        signature: BLSSignature::from([0; 96]),
                    };
                    let signature = sign_as_forger(&chain_lock, chain_locks_type, *quorum);
                    diffs.insert(height, proven_diff(height, &template, Some(signature)));
                }
                let mut header = Header::dummy(height);
                if let Some(diff) = diffs.get(&height) {
                    header.merkle_root =
                        TxMerkleNode::from_raw_hash(diff.coinbase_tx.txid().to_raw_hash());
                }
                let header = HashedBlockHeader::from(header);
                hashes.push(*header.hash());
                stored.push(header);
            }
            for (height, diff) in diffs.iter_mut() {
                diff.block_hash = hashes[*height as usize];
                diff.base_block_hash = match &step {
                    Some(step) if *height == step.list_height => hashes[anchor as usize],
                    Some(step) => hashes[step.list_height as usize],
                    None => hashes[anchor as usize],
                };
            }

            let storage = DiskStorageManager::with_temp_dir().await.unwrap();
            let headers = storage.block_headers();
            headers.write().await.store_headers(&stored).await.unwrap();
            let mut engine = MasternodeListEngine::new(Network::Regtest, Arc::clone(&headers));
            engine.masternode_lists.insert(anchor, anchored_list(hashes[anchor as usize], anchor));
            engine.restore_chain_lock_anchor(ChainLockAnchor {
                height: anchor,
                block_hash: hashes[anchor as usize],
                root: AnchorRoot::FirstChainLock,
            });
            let manager = MasternodesManager::new(
                headers,
                Arc::new(RwLock::new(engine)),
                Network::Regtest,
                None,
            )
            .await;
            let mock = Arc::new(MockNetworkManager::new());
            Walk {
                manager,
                hashes,
                diffs,
                network: mock.clone(),
                mock,
            }
        }

        /// The anchor of the walks below, past a ChainLock mining window.
        fn anchor_height() -> CoreBlockHeight {
            let dkg = dkg(Network::Regtest.chain_locks_type());
            100 * dkg.interval + dkg.mining_window_end + 1
        }

        /// The walk fetches the list a window above the anchor, then a block's
        /// coinbase above it. The ChainLock in it, signed by the anchored quorum,
        /// raises the anchor, which is announced as a validated ChainLock.
        #[tokio::test]
        async fn a_coinbase_chain_lock_an_anchored_quorum_signs_raises_the_anchor() {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(chain_locks_type).interval;
            let step = plan_step(chain_locks_type, anchor, tip, 0).expect("a step");
            let carrier = step.carriers[0];
            let mut walk = anchored_walk(anchor, tip, &[(carrier, signer())]).await;

            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let step_list = (walk.hashes[anchor as usize], walk.hashes[step.list_height as usize]);
            assert_eq!(walk.requested().await, vec![step_list]);
            // The walk keeps its own request; tip updates and QRInfo still go.
            assert!(walk.manager.sync_state.catch_up.wanted.is_some());
            assert!(!walk.manager.sync_state.has_pending_requests());

            let events = walk.answer(step.list_height, test_socket_address(1)).await;
            assert!(events.is_empty());
            assert!(walk.mock.released_keys().await.contains(&RequestKey::MnListDiff(step_list.1)));
            assert_eq!(walk.requested().await, vec![(step_list.1, walk.hashes[carrier as usize])]);

            let events = walk.answer(carrier, test_socket_address(1)).await;

            let anchored = carrier - 1;
            assert!(matches!(
                events.as_slice(),
                [SyncEvent::ChainLockReceived { chain_lock, validated: true }]
                    if chain_lock.block_height == anchored
            ));
            let engine = walk.manager.engine.read().await;
            assert_eq!(engine.usable_anchor().await.map(|anchor| anchor.height), Some(anchored));
            assert_eq!(
                engine.latest_anchored_list(u32::MAX).await.map(|list| list.known_height),
                Some(step.list_height)
            );
        }

        /// The broker sends a request until it is released, so the walk sets
        /// one aside only once it waited [`MNLISTDIFF_DEADLINE`] for it. Then it
        /// backs off rather than holding the pipeline, and lets the QRInfo of an
        /// initial sync go meanwhile.
        #[tokio::test]
        async fn a_walk_whose_request_goes_unanswered_backs_off_and_lets_the_qrinfo_go() {
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(Network::Regtest.chain_locks_type()).interval;
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.progress.update_block_header_tip_height(tip);
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let [(_, target)] = walk.requested().await[..] else {
                panic!("one request");
            };
            let since = walk.manager.sync_state.catch_up.wanted.expect("wanted").since;
            // Only the backoff, not the wait for the walk, lets the QRInfo go.
            walk.manager.sync_state.catch_up.started_at = Some(since + MNLISTDIFF_DEADLINE);

            walk.manager.tick_catch_up(since + MNLISTDIFF_DEADLINE, &walk.network).await.unwrap();
            assert!(walk.manager.sync_state.catch_up.wanted.is_some(), "not past its deadline");
            assert!(walk
                .mock
                .sent_messages()
                .await
                .iter()
                .all(|message| !matches!(message, NetworkMessage::GetQRInfo(_))));

            let late = since + MNLISTDIFF_DEADLINE + Duration::from_secs(1);
            walk.manager.tick_catch_up(late, &walk.network).await.unwrap();

            assert!(walk.manager.sync_state.catch_up.backing_off(late));
            assert!(walk.manager.sync_state.catch_up.wanted.is_none());
            assert_eq!(walk.mock.released_keys().await, vec![RequestKey::MnListDiff(target)]);
            assert!(walk
                .mock
                .sent_messages()
                .await
                .iter()
                .any(|message| matches!(message, NetworkMessage::GetQRInfo(_))));
        }

        /// The diff pipeline may release, or clear, a request for a target the
        /// walk wants too, which leaves nothing in play for the walk. Each tick
        /// declares the walk's request again, which the broker drops while it is
        /// in play.
        #[tokio::test]
        async fn a_tick_declares_the_walks_request_again() {
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(Network::Regtest.chain_locks_type()).interval;
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let requested = walk.requested().await;
            let now = Instant::now();

            walk.manager.tick_catch_up(now, &walk.network).await.unwrap();
            assert!(walk.requested().await.is_empty(), "still in play");

            walk.mock.release_requests_in_play().await;
            walk.manager.tick_catch_up(now, &walk.network).await.unwrap();
            assert_eq!(walk.requested().await, requested);
        }

        /// A diff the pipeline and the walk both want is the pipeline's, which
        /// releases its target. The walk declares its request again on its
        /// next tick and takes the next answer.
        #[tokio::test]
        async fn a_diff_the_pipeline_wants_too_is_the_pipelines_then_the_walks() {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(chain_locks_type).interval;
            let step = plan_step(chain_locks_type, anchor, tip, 0).expect("a step");
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let requested = walk.requested().await;
            walk.manager
                .sync_state
                .mnlistdiff_pipeline
                .queue_requests(
                    DiffKind::WorkBlockList,
                    requested.clone(),
                    Instant::now(),
                    &walk.network,
                )
                .await;
            let diff = walk.diffs.get(&step.list_height).expect("the step list").clone();

            walk.deliver(&diff).await;
            assert!(walk.manager.sync_state.mnlistdiff_pipeline.is_complete(), "the pipeline's");
            let wanted = walk.manager.sync_state.catch_up.wanted.expect("the walk still waits");
            assert_eq!((wanted.base, wanted.target), requested[0]);

            walk.manager.tick_catch_up(Instant::now(), &walk.network).await.unwrap();
            assert_eq!(walk.requested().await, requested, "asked again");
            walk.deliver(&diff).await;
            assert!(walk.manager.sync_state.catch_up.built(step.list_height), "the walk's");
        }

        /// The broker keys a request by its target only, so the walk releases
        /// the target whenever it stops waiting for it, even while the pipeline
        /// wants it from another base: the pipeline declares its own again.
        #[tokio::test]
        async fn the_walk_releases_a_target_the_pipeline_wants_from_another_base() {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(chain_locks_type).interval;
            let step = plan_step(chain_locks_type, anchor, tip, 0).expect("a step");
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let [(_, target)] = walk.requested().await[..] else {
                panic!("one request");
            };
            let other_base = walk.hashes[anchor as usize - 1];
            walk.manager
                .sync_state
                .mnlistdiff_pipeline
                .queue_requests(
                    DiffKind::WorkBlockList,
                    vec![(other_base, target)],
                    Instant::now(),
                    &walk.network,
                )
                .await;
            walk.manager.sync_state.mnlistdiff_pipeline.send_pending(&walk.network).await.unwrap();
            assert!(walk.requested().await.is_empty(), "the walk's request is in play");

            walk.answer(step.list_height, test_socket_address(1)).await;
            assert!(walk.mock.released_keys().await.contains(&RequestKey::MnListDiff(target)));

            walk.manager.sync_state.mnlistdiff_pipeline.send_pending(&walk.network).await.unwrap();
            assert!(walk.requested().await.contains(&(other_base, target)));
        }

        /// A fresh mainnet sync starts trust at the newest checkpoint the
        /// header chain holds, and first fetches that checkpoint's full list,
        /// which the checkpoint vouches for by itself; then the step's list.
        #[tokio::test]
        async fn a_mainnet_walk_starts_at_the_checkpoint_with_its_full_list() {
            let checkpoint = CheckpointManager::for_network(Network::Mainnet)
                .checkpoints()
                .last()
                .expect("checkpoints");
            let (root, checkpoint_hash) = (checkpoint.height(), *checkpoint.hash());
            let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
            storage
                .store_headers_at_height(checkpoint.headers(), checkpoint.start_height())
                .await
                .unwrap();
            let above: Vec<_> = Header::dummy_chain(700, checkpoint_hash)
                .iter()
                .map(HashedBlockHeader::from)
                .collect();
            storage.store_headers(&above).await.unwrap();
            let headers = storage.block_headers();
            let engine = MasternodeListEngine::new(Network::Mainnet, Arc::clone(&headers));
            let mut manager = MasternodesManager::new(
                headers,
                Arc::new(RwLock::new(engine)),
                Network::Mainnet,
                None,
            )
            .await;
            let mock = Arc::new(MockNetworkManager::new());
            let network: Arc<dyn NetworkManager> = mock.clone();
            let requested = || async {
                let requests: Vec<_> = mock
                    .sent_messages()
                    .await
                    .into_iter()
                    .filter_map(|message| match message {
                        NetworkMessage::GetMnListD(GetMnListDiff {
                            base_block_hash,
                            block_hash,
                        }) => Some((base_block_hash, block_hash)),
                        _ => None,
                    })
                    .collect();
                mock.clear_sent().await;
                requests
            };

            manager.begin_catch_up(&network, true).await.unwrap();

            let anchor = manager.engine.read().await.usable_anchor().await;
            assert_eq!(anchor.map(|anchor| anchor.root), Some(AnchorRoot::Checkpoint(root)));
            assert_eq!(requested().await, vec![(BlockHash::all_zeros(), checkpoint_hash)]);

            // A full list the checkpoint's own header does not prove is not
            // taken: the checkpoint vouches only for the list of its block.
            // The peer that sent it is banned and the request stays wanted, for
            // the broker to send to another peer.
            let unproven = MnListDiff {
                base_block_hash: BlockHash::all_zeros(),
                block_hash: checkpoint_hash,
                ..MnListDiff::dummy(0x00, 0x01)
            };
            manager
                .handle_catch_up_diff(&unproven, test_socket_address(1), &network)
                .await
                .unwrap();
            assert!(manager.engine.read().await.masternode_lists.is_empty());
            assert_eq!(mock.banned_peers().await, vec![test_socket_address(1)]);
            assert!(mock.released_keys().await.is_empty());
            assert!(manager
                .sync_state
                .catch_up
                .wanted
                .is_some_and(|wanted| wanted.target == checkpoint_hash));

            // With the checkpoint's list held, the walk goes on to its step.
            manager.sync_state.catch_up.wanted = None;
            let list = MasternodeList::empty(checkpoint_hash, root);
            manager.engine.write().await.masternode_lists.insert(root, list);
            manager.advance_catch_up(Instant::now(), &network).await.unwrap();
            let step = plan_step(Network::Mainnet.chain_locks_type(), root, root + 700, 0)
                .expect("a step");
            assert_eq!(
                requested().await,
                vec![(checkpoint_hash, *above[(step.list_height - root - 1) as usize].hash())]
            );
        }

        /// A carrier whose coinbase its stored header proves is the block's own:
        /// when a quorum the anchor does not vouch for signed its ChainLock,
        /// the walk moves to the next carrier. An answer whose coinbase the
        /// header does not prove is not the block's: its peer is banned, and
        /// the request stays wanted for the broker to send to another peer.
        #[tokio::test]
        async fn a_carrier_that_cannot_anchor_is_followed_by_the_next_and_junk_bans_its_peer() {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(chain_locks_type).interval;
            let step = plan_step(chain_locks_type, anchor, tip, 0).expect("a step");
            let [first, second] = [step.carriers[0], step.carriers[1]];
            // A quorum mined in the window the step crossed, which selection
            // picks for the first carrier's ChainLock: its request id depends
            // only on the height.
            let request_id = ChainLock {
                block_height: first - 1,
                block_hash: BlockHash::all_zeros(),
                signature: BLSSignature::from([0; 96]),
            }
            .request_id()
            .expect("request id");
            let order = |hash| {
                dashcore::hash_types::QuorumOrderingHash::create(
                    &forged_chain_lock_quorum(chain_locks_type, hash).quorum_entry,
                    &request_id,
                )
            };
            let mined = (0x60..=u8::MAX)
                .map(|byte| QuorumHash::from_byte_array([byte; 32]))
                .find(|mined| order(*mined) < order(signer()))
                .expect("a hash selection picks");
            let mut walk = anchored_walk(anchor, tip, &[(first, mined)]).await;
            let list_hash = walk.hashes[step.list_height as usize];
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            walk.answer(step.list_height, test_socket_address(1)).await;
            walk.requested().await;

            {
                let mut engine = walk.manager.engine.write().await;
                let list = engine.masternode_lists.get_mut(&step.list_height).expect("step list");
                Arc::make_mut(&mut list.quorums)
                    .entry(chain_locks_type)
                    .or_default()
                    .insert(mined, Arc::new(forged_chain_lock_quorum(chain_locks_type, mined)));
            }
            // The carrier's coinbase with a proof its stored header does not
            // hold. Taken for the block's, its ChainLock would wait for a
            // signer and use the carrier up.
            let carrier_diff = walk.diffs.get(&first).expect("the carrier").clone();
            let junk = MnListDiff {
                merkle_hashes: vec![MerkleRootMasternodeList::all_zeros()],
                ..carrier_diff.clone()
            };
            let junk_peer = test_socket_address(2);
            walk.manager.handle_catch_up_diff(&junk, junk_peer, &walk.network).await.unwrap();
            assert_eq!(walk.mock.banned_peers().await, vec![junk_peer]);
            assert!(walk.requested().await.is_empty(), "junk moves nothing");
            let wanted = walk.manager.sync_state.catch_up.wanted.expect("still wanted");
            assert_eq!(wanted.target, walk.hashes[first as usize]);
            assert!(!walk.manager.sync_state.catch_up.backing_off(Instant::now()));

            let events = walk.answer(first, test_socket_address(3)).await;

            assert!(events.is_empty(), "the anchor stays");
            assert_eq!(
                walk.requested().await,
                vec![(list_hash, walk.hashes[second as usize])],
                "the next carrier"
            );
        }

        /// A proven coinbase is the block's own, so a ChainLock in it that
        /// cannot be final is the block's too: asking again would bring the
        /// same one. The walk moves to the next carrier, blaming no peer.
        #[tokio::test]
        async fn a_proven_carrier_whose_chain_lock_cannot_be_final_is_passed_over() {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(chain_locks_type).interval;
            let step = plan_step(chain_locks_type, anchor, tip, 0).expect("a step");
            let [first, second] = [step.carriers[0], step.carriers[1]];
            // Signed for a quorum no list holds, so the anchored signer's key
            // does not verify it.
            let stranger = QuorumHash::from_byte_array([0x77; 32]);
            let mut walk = anchored_walk(anchor, tip, &[(first, stranger)]).await;
            let list_hash = walk.hashes[step.list_height as usize];
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            walk.answer(step.list_height, test_socket_address(1)).await;
            walk.requested().await;

            let events = walk.answer(first, test_socket_address(1)).await;

            assert!(events.is_empty(), "the anchor stays");
            assert_eq!(
                walk.requested().await,
                vec![(list_hash, walk.hashes[second as usize])],
                "the next carrier"
            );
            assert!(walk.mock.banned_peers().await.is_empty());
        }

        /// A list whose coinbase its stored header proves, but whose entries
        /// do not match it, was refused for what the peer sent, though not in a
        /// way that proves it lied. The request stays wanted and that peer is
        /// not heard again for it, so one peer cannot stall the walk; another
        /// peer's answer is taken.
        #[tokio::test]
        async fn a_list_refused_for_its_entries_waits_for_another_peer() {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(chain_locks_type).interval;
            let step = plan_step(chain_locks_type, anchor, tip, 0).expect("a step");
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.mock.set_connected(3);
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let [(_, target)] = walk.requested().await[..] else {
                panic!("one request");
            };
            let genuine = walk.diffs.get(&step.list_height).expect("the step list").clone();
            let forged = with_entries_its_coinbase_does_not_commit_to(&genuine);
            let refuser = test_socket_address(2);

            walk.manager.handle_catch_up_diff(&forged, refuser, &walk.network).await.unwrap();
            assert!(walk.mock.banned_peers().await.is_empty(), "nothing proves it lied");
            assert!(walk.mock.released_keys().await.is_empty(), "the broker asks another peer");
            assert!(!walk.manager.sync_state.catch_up.backing_off(Instant::now()));
            assert!(walk.manager.sync_state.catch_up.wanted.is_some_and(|w| w.target == target));

            walk.manager.handle_catch_up_diff(&genuine, refuser, &walk.network).await.unwrap();
            assert!(
                !walk.manager.engine.read().await.masternode_lists.contains_key(&step.list_height),
                "the refuser is not heard again for it"
            );

            walk.answer(step.list_height, test_socket_address(3)).await;
            assert!(walk
                .manager
                .engine
                .read()
                .await
                .masternode_lists
                .contains_key(&step.list_height));
            assert_eq!(walk.mock.released_keys().await, vec![RequestKey::MnListDiff(target)]);
        }

        /// The step list `genuine` answers, with its proven coinbase, but with a
        /// masternode its coinbase does not commit to.
        fn with_entries_its_coinbase_does_not_commit_to(genuine: &MnListDiff) -> MnListDiff {
            MnListDiff {
                new_masternodes: vec![
                    dashcore::sml::masternode_list_entry::MasternodeListEntry::dummy(1),
                ],
                ..genuine.clone()
            }
        }

        /// Answers that two peers, or every peer there is, sent and the engine
        /// refused without blame say more about our state than about theirs,
        /// as when a network mines a quorum type the library does not know. The
        /// walk backs off rather than have the broker kick peer after peer.
        #[test_case(1, 1; "the only peer")]
        #[test_case(3, 2; "two of several peers")]
        #[tokio::test]
        async fn a_list_several_peers_answer_alike_and_is_refused_backs_the_walk_off(
            connected: u32,
            refusers: u8,
        ) {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(chain_locks_type).interval;
            let step = plan_step(chain_locks_type, anchor, tip, 0).expect("a step");
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.mock.set_connected(connected);
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let [(_, target)] = walk.requested().await[..] else {
                panic!("one request");
            };
            let genuine = walk.diffs.get(&step.list_height).expect("the step list").clone();
            let refused = with_entries_its_coinbase_does_not_commit_to(&genuine);

            for peer in 1..=refusers {
                assert!(walk.manager.sync_state.catch_up.wanted.is_some());
                let peer = test_socket_address(peer);
                walk.manager.handle_catch_up_diff(&refused, peer, &walk.network).await.unwrap();
            }

            assert!(walk.mock.banned_peers().await.is_empty());
            assert_eq!(walk.mock.released_keys().await, vec![RequestKey::MnListDiff(target)]);
            assert!(walk.manager.sync_state.catch_up.backing_off(Instant::now()));
            assert!(walk.manager.sync_state.catch_up.refusers.is_empty(), "heard afresh");
        }

        /// A base list the engine no longer holds is a gap of ours, which every
        /// peer's answer would hit: the walk plans the step again at once, and
        /// backs off only when the same step hits a gap again.
        #[tokio::test]
        async fn a_gap_of_ours_plans_again_once_then_backs_the_walk_off() {
            let chain_locks_type = Network::Regtest.chain_locks_type();
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(chain_locks_type).interval;
            let step = plan_step(chain_locks_type, anchor, tip, 0).expect("a step");
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let step_list = walk.requested().await;
            let anchored = walk.manager.engine.write().await.masternode_lists.remove(&anchor);

            walk.answer(step.list_height, test_socket_address(1)).await;
            assert!(walk.mock.banned_peers().await.is_empty());
            assert!(!walk.manager.sync_state.catch_up.backing_off(Instant::now()));
            assert_eq!(
                walk.requested().await,
                vec![(BlockHash::all_zeros(), walk.hashes[anchor as usize])],
                "planned again: the anchor's list"
            );

            let wanted = walk.manager.sync_state.catch_up.wanted.take().expect("the anchor's list");
            Manager::release_catch_up_request(&wanted, &walk.network).await;
            walk.manager
                .engine
                .write()
                .await
                .masternode_lists
                .insert(anchor, anchored.expect("the anchored list"));
            walk.manager.advance_catch_up(Instant::now(), &walk.network).await.unwrap();
            assert_eq!(walk.requested().await, step_list, "the step's list again");
            walk.manager.engine.write().await.masternode_lists.remove(&anchor);

            walk.answer(step.list_height, test_socket_address(1)).await;
            assert!(walk.manager.sync_state.catch_up.wanted.is_none());
            assert!(walk.manager.sync_state.catch_up.backing_off(Instant::now()));
        }

        /// A synced client whose anchor fell more than a step behind the tip,
        /// as after a day without network, walks it up; one whose anchor is
        /// near the tip does not.
        #[test_case(10, true; "a step behind")]
        #[test_case(0, false; "caught up")]
        #[tokio::test]
        async fn a_synced_client_walks_up_an_anchor_that_fell_behind(
            intervals_behind: u32,
            walks: bool,
        ) {
            let anchor = anchor_height();
            let tip =
                anchor + intervals_behind * dkg(Network::Regtest.chain_locks_type()).interval + 8;
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            // The list tip updates keep at the tip.
            let newest = MasternodeList::empty(walk.hashes[tip as usize], tip);
            walk.manager.engine.write().await.masternode_lists.insert(tip, newest);
            walk.manager.set_state(SyncState::Synced);
            walk.manager.progress.update_block_header_tip_height(tip);

            walk.manager.tick_catch_up(Instant::now(), &walk.network).await.unwrap();

            assert_eq!(!walk.requested().await.is_empty(), walks);
        }

        /// Once synced, tip updates keep the newest list, so the walk does not
        /// build lists above it: a tip update in flight still extends the
        /// newest list, and asks for the work-block lists its quorums need.
        #[tokio::test]
        async fn a_synced_walk_stays_below_the_newest_list() {
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(Network::Regtest.chain_locks_type()).interval;
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.set_state(SyncState::Synced);
            walk.manager.progress.update_block_header_tip_height(tip);

            walk.manager.tick_catch_up(Instant::now(), &walk.network).await.unwrap();

            assert!(walk.requested().await.is_empty(), "the newest list is the anchored one");
        }

        /// A QRInfo that failed every attempt ends an initial sync only once
        /// the engine holds a list the walk did not build: the walk's lie far
        /// below the tip, and the stall watchdog retries the QRInfo meanwhile.
        #[tokio::test]
        async fn the_walks_lists_alone_do_not_end_an_initial_sync() {
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(Network::Regtest.chain_locks_type()).interval;
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.set_state(SyncState::Syncing);
            walk.manager.sync_state.catch_up.built.insert(anchor);

            assert!(walk.manager.complete_quorum_validation(None).await.unwrap().is_empty());
            assert_eq!(walk.manager.state(), SyncState::Syncing);

            let list = MasternodeList::empty(walk.hashes[tip as usize], tip);
            walk.manager.engine.write().await.masternode_lists.insert(tip, list);
            assert!(!walk.manager.complete_quorum_validation(None).await.unwrap().is_empty());
            assert_eq!(walk.manager.state(), SyncState::Synced);
        }

        /// A disconnect drops the backoff earned with the gone peers. The next
        /// start of masternode sync resumes the walk and still lets its QRInfo
        /// go, instead of waiting out a backoff earned with other peers. A
        /// request still wanted stays wanted, with its deadline counted from
        /// the reconnect, as the broker sends it to the next peers.
        #[tokio::test]
        async fn a_reconnect_drops_the_backoff_and_restarts_the_wait() {
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(Network::Regtest.chain_locks_type()).interval;
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            let requested = walk.requested().await;
            let wanted = walk.manager.sync_state.catch_up.wanted.expect("a request");
            Manager::release_catch_up_request(&wanted, &walk.network).await;
            walk.manager.sync_state.catch_up.fail(Instant::now());
            assert!(walk
                .manager
                .advance_catch_up(Instant::now(), &walk.network)
                .await
                .unwrap()
                .is_empty());
            walk.requested().await;

            walk.manager.on_disconnect();
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();

            assert_eq!(walk.requested().await, requested, "the walk resumes");
            assert!(walk.manager.sync_state.catch_up.qrinfo_after, "its QRInfo still follows");

            // A request kept across the outage waits its whole deadline again,
            // and peers that refused it before may answer it.
            let mut wanted = walk.manager.sync_state.catch_up.wanted.expect("still wanted");
            wanted.since = Instant::now()
                .checked_sub(MNLISTDIFF_DEADLINE + Duration::from_secs(1))
                .expect("a clock past the deadline");
            walk.manager.sync_state.catch_up.wanted = Some(wanted);
            walk.manager.sync_state.catch_up.refused_by(&wanted, test_socket_address(2));
            walk.manager.on_disconnect();
            // Masternode sync starts again once peers are back.
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            walk.manager.tick_catch_up(Instant::now(), &walk.network).await.unwrap();
            assert!(walk.manager.sync_state.catch_up.wanted.is_some(), "not past its deadline");
            assert!(walk.manager.sync_state.catch_up.refusers.is_empty());
        }

        /// An initial sync starts the walk from the header sync's completion, and
        /// `tick` drives it on: the walk asks first, holding the QRInfo, and a
        /// request past its deadline backs the walk off and lets the QRInfo go.
        #[tokio::test]
        async fn header_sync_completion_starts_the_walk_and_tick_drives_it() {
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(Network::Regtest.chain_locks_type()).interval;
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.set_state(SyncState::WaitForEvents);
            let sent_qrinfo = |messages: Vec<NetworkMessage>| {
                messages.iter().any(|message| matches!(message, NetworkMessage::GetQRInfo(_)))
            };

            let completed = SyncEvent::BlockHeaderSyncComplete {
                tip_height: tip,
            };
            walk.manager.handle_sync_event(&completed, &walk.network).await.unwrap();

            assert!(!sent_qrinfo(walk.mock.sent_messages().await), "the QRInfo waits");
            let [(_, target)] = walk.requested().await[..] else {
                panic!("one walk request");
            };
            assert_eq!(walk.manager.state(), SyncState::Syncing);

            let since = walk.manager.sync_state.catch_up.wanted.expect("wanted").since;
            let late = since + MNLISTDIFF_DEADLINE + Duration::from_secs(1);
            walk.manager.tick_at(late, &walk.network).await.unwrap();

            assert!(walk.mock.released_keys().await.contains(&RequestKey::MnListDiff(target)));
            assert!(walk.manager.sync_state.catch_up.backing_off(late));
            assert!(sent_qrinfo(walk.mock.sent_messages().await), "the QRInfo goes");
        }

        /// The QRInfo of an initial sync does not wait for a long walk.
        #[tokio::test]
        async fn the_qrinfo_goes_once_it_waited_long_enough_for_the_walk() {
            let anchor = anchor_height();
            let tip = anchor + 10 * dkg(Network::Regtest.chain_locks_type()).interval;
            let mut walk = anchored_walk(anchor, tip, &[]).await;
            walk.manager.begin_catch_up(&walk.network, true).await.unwrap();
            walk.requested().await;

            let started_at = walk.manager.sync_state.catch_up.started_at.expect("started");
            walk.manager
                .tick_catch_up(started_at + QRINFO_WAIT + Duration::from_secs(1), &walk.network)
                .await
                .unwrap();

            assert!(walk
                .mock
                .sent_messages()
                .await
                .iter()
                .any(|message| matches!(message, NetworkMessage::GetQRInfo(_))));
            assert!(walk.manager.sync_state.catch_up.wanted.is_some(), "the walk goes on");
        }
    }

    /// Trust starts at the newest checkpoint the stored chain holds, past V20
    /// so its coinbases carry ChainLocks; never on a network without
    /// checkpoints, and not before the chain reaches one.
    #[tokio::test]
    async fn trust_starts_at_the_newest_stored_checkpoint_past_v20() {
        use crate::storage::{DiskStorageManager, StorageManager};

        let checkpoint = CheckpointManager::for_network(Network::Mainnet)
            .checkpoints()
            .last()
            .expect("checkpoints");
        let newest = checkpoint.height();
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        storage
            .store_headers_at_height(checkpoint.headers(), checkpoint.start_height())
            .await
            .unwrap();
        let headers = storage.block_headers();
        let headers = headers.read().await;

        let root = root_checkpoint(Network::Mainnet, &*headers, newest + 1).await;
        assert_eq!(
            root,
            Some(ChainLockAnchor {
                height: newest,
                block_hash: *checkpoint.hash(),
                root: AnchorRoot::Checkpoint(newest),
            })
        );
        assert_eq!(
            root_checkpoint(Network::Mainnet, &*headers, newest - 1).await,
            None,
            "no older checkpoint is stored, and the chain does not reach the newest"
        );
        assert_eq!(root_checkpoint(Network::Regtest, &*headers, newest + 1).await, None);
    }

    /// A refused answer is the peer's for one request: the same peer is heard
    /// again once the anchor moved, or for the target from another base.
    #[test]
    fn refusers_are_forgotten_when_the_anchor_moves() {
        let peer = crate::test_utils::test_socket_address(1);
        let (base, target) = (BlockHash::dummy(1), BlockHash::dummy(2));
        let wanted = Wanted {
            base,
            target,
            fetch: Fetch::Carrier,
            since: Instant::now(),
        };
        let answer = |base| MnListDiff {
            base_block_hash: base,
            block_hash: target,
            ..MnListDiff::dummy_empty(0, 0)
        };
        let mut catch_up = CatchUp::default();
        catch_up.plan_from(100);
        catch_up.refused_by(&wanted, peer);

        assert!(catch_up.has_refused(&answer(base), peer));
        assert!(!catch_up.has_refused(&answer(BlockHash::dummy(3)), peer), "another base");
        catch_up.plan_from(100);
        assert!(catch_up.has_refused(&answer(base), peer), "the anchor stayed");
        catch_up.plan_from(200);
        assert!(!catch_up.has_refused(&answer(base), peer));
    }

    #[test]
    fn the_backoff_doubles_up_to_its_cap_and_resets_when_the_anchor_moves() {
        let now = Instant::now();
        let mut catch_up = CatchUp::default();
        catch_up.plan_from(100);
        catch_up.fail(now);
        assert!(catch_up.backing_off(now + MIN_BACKOFF - Duration::from_secs(1)));
        assert!(!catch_up.backing_off(now + MIN_BACKOFF));
        catch_up.fail(now);
        assert!(catch_up.backing_off(now + 2 * MIN_BACKOFF - Duration::from_secs(1)));
        assert!(!catch_up.backing_off(now + 2 * MIN_BACKOFF));
        for _ in 0..10 {
            catch_up.fail(now);
        }
        assert!(!catch_up.backing_off(now + MAX_BACKOFF));

        catch_up.plan_from(200);
        catch_up.fail(now);
        assert!(!catch_up.backing_off(now + MIN_BACKOFF));
    }
}
