use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::BlockHash;
use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;

use crate::network::costs::ResponseCosts;
use crate::network::peer::{PeerHandle, PeerId};

const KICKING_ATTEMPTS: u32 = 2;
/// How many timeouts a request lives on bytes of a message still arriving, without an
/// answer. A big answer on a slow link must fit, but a message that never finishes must
/// not keep its request alive forever.
const ANSWER_TIMEOUTS: u32 = 6;
const HEDGE_AFTER: Duration = Duration::from_secs(2);
/// A request on the wire this long gets a second copy even while its peer delivers other
/// replies, unless [`HEDGE_QUEUE_FACTOR`] gives it longer.
const HEDGE_OVERDUE: Duration = Duration::from_secs(10);
/// A request may wait this many times its peer's queue at send before a second copy is sent
/// to a peer still delivering, so it is hedged only once its peer serves at under half the
/// rate the request was routed by. A peer's queue can hold many seconds of work, and a copy
/// sent while the batch merely waits in it is downloaded twice.
const HEDGE_QUEUE_FACTOR: f64 = 2.0;
const MIN_IN_FLIGHT_PER_CLASS: usize = 4;
const MSG_CLASSES: usize = 5;
const DRAIN_PRIORITY: [MsgClass; MSG_CLASSES] =
    [MsgClass::Other, MsgClass::Blocks, MsgClass::CFilters, MsgClass::CfHeaders, MsgClass::Headers];

/// De-dup, timeout and retry key of a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RequestKey {
    /// Locator's first hash.
    Headers(BlockHash),
    /// Stop hash.
    CfHeaders(BlockHash),
    /// Stop hash.
    CFilters(BlockHash),
    MnListDiff(BlockHash),
    Block(BlockHash),
}

pub fn request_keys(msg: &NetworkMessage) -> Vec<RequestKey> {
    match msg {
        NetworkMessage::GetHeaders(m) | NetworkMessage::GetHeaders2(m) => {
            m.locator_hashes.first().map(|h| RequestKey::Headers(*h)).into_iter().collect()
        }
        NetworkMessage::GetCFHeaders(m) => vec![RequestKey::CfHeaders(m.stop_hash)],
        NetworkMessage::GetCFilters(m) => vec![RequestKey::CFilters(m.stop_hash)],
        NetworkMessage::GetMnListD(m) => vec![RequestKey::MnListDiff(m.block_hash)],
        NetworkMessage::GetData(inv) => inv
            .iter()
            .filter_map(|i| match i {
                Inventory::Block(h) => Some(RequestKey::Block(*h)),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

enum ReqState {
    /// Attempts so far.
    Queued(u32),
    OnWire(Box<OnWire>),
    /// The whole reply was received and waits for its manager to release the key.
    Arrived,
}

struct OnWire {
    /// The connection, not the address: a late close of an old connection must not
    /// pull back the work of a new one to the same address.
    peer: PeerId,
    /// Refreshed by every answer and by bytes of a message still arriving, since a big
    /// answer can take longer than a timeout to arrive.
    last_progress: Instant,
    /// Refreshed only by answers, so a block still arriving slowly can be hedged and a
    /// message that never finishes cannot keep the request alive forever.
    last_answer: Instant,
    sent: Instant,
    /// How long after `sent` the request is overdue although its peer keeps delivering.
    overdue_after: Duration,
    msg: NetworkMessage,
    height: u32,
    hedge: Option<PeerId>,
    attempts: u32,
}

/// The request queue plus the registry of every keyed request in play, queued, on the
/// wire or arrived. A key stays registered until released, so re-declaring it is a no-op.
pub struct Broker {
    queue: MsgQueue,
    requests: Mutex<HashMap<RequestKey, ReqState>>,
}

impl Broker {
    pub fn new() -> Self {
        Self {
            queue: MsgQueue::new(),
            requests: Mutex::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn wake(&self) {
        self.queue.notify.notify_one();
    }

    pub async fn notified(&self) {
        self.queue.notify.notified().await
    }

    pub async fn enqueue(&self, height: u32, msg: NetworkMessage) {
        let keys = request_keys(&msg);
        if !keys.is_empty() {
            let mut reqs = self.requests.lock().await;
            if keys.iter().any(|k| reqs.contains_key(k)) {
                return;
            }
            for key in keys {
                reqs.insert(key, ReqState::Queued(0));
            }
        }
        self.queue.push(height, msg).await;
    }

    /// Unregisters `key`. If its request was on the wire, wakes the router to send more.
    /// If it was still queued, drops it unless another of its keys is still registered,
    /// since sent later it would go out untracked or under a new request for the same key.
    pub async fn release(&self, key: &RequestKey) {
        let mut reqs = self.requests.lock().await;
        match reqs.remove(key) {
            Some(ReqState::OnWire(_)) => {
                drop(reqs);
                self.wake();
            }
            Some(ReqState::Queued(_)) => self.drop_queued(key, &reqs).await,
            Some(ReqState::Arrived) | None => {}
        }
    }

    /// Drops the queued messages carrying `key` that no other registered key still needs.
    async fn drop_queued(&self, key: &RequestKey, reqs: &HashMap<RequestKey, ReqState>) {
        self.queue
            .remove(|msg| {
                let keys = request_keys(msg);
                keys.contains(key) && !keys.iter().any(|k| reqs.contains_key(k))
            })
            .await;
    }

    pub async fn clear(&self) {
        self.requests.lock().await.clear();
        self.queue.pop_n(self.queue.len()).await;
    }

    async fn requeue(&self, matches: impl Fn(&RequestKey, &OnWire) -> bool) -> usize {
        let retried: Vec<(u32, NetworkMessage)> = {
            let mut reqs = self.requests.lock().await;
            let keys: Vec<RequestKey> = reqs
                .iter()
                .filter_map(|(k, s)| match s {
                    ReqState::OnWire(o) if matches(k, o) => Some(k.clone()),
                    _ => None,
                })
                .collect();
            keys.into_iter()
                .filter_map(|key| match reqs.remove(&key) {
                    Some(ReqState::OnWire(o)) => {
                        reqs.insert(key, ReqState::Queued(o.attempts));
                        Some((o.height, o.msg))
                    }
                    _ => None,
                })
                .collect()
        };
        let n = retried.len();
        self.queue.push_front_all(retried).await;
        n
    }

    /// Re-queues the requests of the `gone` peers. A request they only hedged stays with its
    /// peer and may be hedged again, since the copy is lost.
    pub async fn requeue_from(&self, gone: &HashSet<PeerId>) -> usize {
        for state in self.requests.lock().await.values_mut() {
            if let ReqState::OnWire(o) = state {
                if o.hedge.is_some_and(|hedge| gone.contains(&hedge)) {
                    o.hedge = None;
                }
            }
        }
        self.requeue(|_, o| gone.contains(&o.peer)).await
    }

    pub async fn not_found(&self, peer: PeerId, inv: &[Inventory]) {
        let keys: HashSet<RequestKey> = inv
            .iter()
            .filter_map(|i| match i {
                Inventory::Block(hash) => Some(RequestKey::Block(*hash)),
                _ => None,
            })
            .collect();
        if !keys.is_empty() {
            self.requeue(|k, o| o.peer == peer && keys.contains(k)).await;
        }
    }

    /// Settles `key` on arrival of its whole reply from `peer`, not when processed, since
    /// the wait for a manager is not the peer's. The first copy of a hedged request settles
    /// it. A request put back in the queue is settled by a copy from any peer, and its message
    /// dropped. The key stays registered until released, so a re-declare before then sends
    /// nothing, and a manager that cannot use the reply must release the key.
    pub async fn arrived(&self, peer: PeerId, key: RequestKey) {
        let mut reqs = self.requests.lock().await;
        match reqs.get(&key) {
            Some(ReqState::OnWire(o)) if o.peer == peer || o.hedge == Some(peer) => {}
            Some(ReqState::Queued(_)) => {
                reqs.remove(&key);
                self.drop_queued(&key, &reqs).await;
            }
            _ => return,
        }
        reqs.insert(key, ReqState::Arrived);
        drop(reqs);
        self.wake();
    }

    /// Peers answer in order, so any answer is progress on all of its requests.
    pub async fn progress(&self, peer: PeerId) {
        self.refresh(&[peer], true).await;
    }

    /// Bytes of a message still arriving from any of `peers` are progress on their requests.
    pub async fn receiving(&self, peers: &[PeerId]) {
        if !peers.is_empty() {
            self.refresh(peers, false).await;
        }
    }

    async fn refresh(&self, peers: &[PeerId], answered: bool) {
        let now = Instant::now();
        for state in self.requests.lock().await.values_mut() {
            if let ReqState::OnWire(o) = state {
                if peers.contains(&o.peer) {
                    o.last_progress = now;
                    if answered {
                        o.last_answer = now;
                    }
                }
            }
        }
    }

    /// Returns the peers to kick for a stalled request, each with the earliest instant
    /// its stalled requests are blamed from. A request stalls after a timeout without
    /// progress, or after [`ANSWER_TIMEOUTS`] timeouts without an answer. A request that
    /// already stalled [`KICKING_ATTEMPTS`] times is retried without blaming its peer.
    pub async fn expire(&self, timeout: impl Fn(&PeerId) -> Duration) -> HashMap<PeerId, Instant> {
        let now = Instant::now();
        let mut culprits: HashMap<PeerId, Instant> = HashMap::new();
        let mut unanswerable = HashSet::new();
        for (key, state) in self.requests.lock().await.iter() {
            let ReqState::OnWire(o) = state else {
                continue;
            };
            let timeout = timeout(&o.peer);
            let silent_since = if now.duration_since(o.last_progress) > timeout {
                o.last_progress
            } else if now.duration_since(o.last_answer) > timeout * ANSWER_TIMEOUTS {
                // Blamed from the answer, not the recent bytes, so those bytes show our
                // link works and the peer is not held as a link stall.
                o.last_answer
            } else {
                continue;
            };
            if o.attempts < KICKING_ATTEMPTS {
                let since = culprits.entry(o.peer).or_insert(silent_since);
                *since = (*since).min(silent_since);
            } else {
                tracing::debug!(
                    target: "dash_spv::network",
                    "{key:?} unanswered after {} attempts, retrying without kicking {}",
                    o.attempts,
                    o.peer,
                );
                unanswerable.insert(key.clone());
            }
        }
        if !unanswerable.is_empty() {
            self.requeue(|k, _| unanswerable.contains(k)).await;
        }
        culprits
    }

    /// Sends what fits in the peers' byte caps, each message to the peer [`choose_peer`]
    /// picks.
    pub async fn route(&self, peers: &[PeerHandle], costs: &ResponseCosts) -> usize {
        if peers.is_empty() {
            return 0;
        }
        let budget: u64 = peers.iter().map(|p| p.cap().saturating_sub(p.in_flight_bytes())).sum();
        if budget == 0 {
            return 0;
        }

        // A class with almost nothing on the wire goes first, so strict priority
        // never parks a stage.
        let mut guaranteed = [MIN_IN_FLIGHT_PER_CLASS; MSG_CLASSES];
        for state in self.requests.lock().await.values() {
            if let ReqState::OnWire(o) = state {
                let slot = &mut guaranteed[classify(&o.msg) as usize];
                *slot = slot.saturating_sub(1);
            }
        }
        let msgs = self.queue.pop_guaranteed(budget, &guaranteed, |m| costs.cost(m)).await;
        let mut sent = 0;
        // Popped but unsent goes back: its key is registered, so a dropped message
        // would stall its pipeline.
        let mut unsent: Vec<(u32, NetworkMessage)> = Vec::new();
        let mut on_wire: Vec<(u32, NetworkMessage, PeerHandle, Duration)> = Vec::new();
        let mut msgs = msgs.into_iter();
        for (height, msg) in msgs.by_ref() {
            // `peers` can be a snapshot taken before the timeout monitor closed one of them.
            let open = peers.iter().filter(|p| !p.is_closed() && p.in_flight_bytes() < p.cap());
            let Some(peer) = choose_peer(open, classify(&msg)) else {
                unsent.push((height, msg));
                break;
            };
            if peer.send(&msg).await.is_ok() {
                sent += 1;
                // Before the next send, which queues behind this request.
                let overdue_after = overdue_after(peer);
                on_wire.push((height, msg, peer.clone(), overdue_after));
            } else {
                tracing::warn!(target: "dash_spv::network", "router: send to {} failed", peer.addr());
                unsent.push((height, msg));
            }
        }
        unsent.extend(msgs);
        self.queue.push_front_all(unsent).await;

        if !on_wire.is_empty() {
            let mut reqs = self.requests.lock().await;
            for (height, msg, peer, overdue_after) in on_wire {
                for key in request_keys(&msg) {
                    if let Some(slot) = reqs.get_mut(&key) {
                        let attempts = match slot {
                            ReqState::Queued(attempts) => *attempts,
                            ReqState::OnWire(o) => o.attempts,
                            // The reply to a requeued request can arrive while it is resent.
                            ReqState::Arrived => continue,
                        };
                        *slot = ReqState::OnWire(Box::new(OnWire {
                            peer: peer.id(),
                            msg: msg.clone(),
                            height,
                            last_progress: Instant::now(),
                            last_answer: Instant::now(),
                            sent: Instant::now(),
                            overdue_after,
                            hedge: None,
                            attempts: attempts + 1,
                        }));
                    }
                }
            }
        }

        if sent > 0 {
            tracing::debug!(
                target: "dash_spv::network",
                "router: sent {} | peers={} queue={}",
                sent,
                peers.len(),
                self.queue.len(),
            );
        }
        sent
    }

    /// Endgame: asks a second peer for the lowest block on the wire once it is
    /// [`OnWire::overdue`], and returns its height. Blocks are processed in height
    /// order, so only the lowest one holds up progress and a second copy of any other is wasted.
    pub async fn hedge(&self, peers: &[PeerHandle]) -> Option<u32> {
        let (key, msg, height, peer) = {
            let reqs = self.requests.lock().await;
            let (key, o) = lowest_on_wire(&reqs, |key| matches!(key, RequestKey::Block(_)))?;
            if o.hedge.is_some() || !o.overdue() {
                return None;
            }
            let others = peers
                .iter()
                .filter(|p| !p.is_closed() && p.id() != o.peer && p.in_flight_bytes() < p.cap());
            let peer = hedge_peer(others)?;
            (key.clone(), o.msg.clone(), o.height, peer.clone())
        };
        self.send_hedge(key, msg, height, peer).await
    }

    /// Asks a second peer for the lowest filter batch not yet delivered once it is
    /// [`OnWire::overdue`], and returns its height. Filters are stored in height order, so
    /// that batch holds back everything above it however much is downloaded. One queued
    /// lower goes out next, so it is no reason to hedge the batch above it.
    pub async fn hedge_filters(&self, peers: &[PeerHandle]) -> Option<u32> {
        let (key, msg, height, peer) = {
            let reqs = self.requests.lock().await;
            let (key, o) = lowest_on_wire(&reqs, |key| matches!(key, RequestKey::CFilters(_)))?;
            if o.hedge.is_some()
                || !o.overdue()
                || self.queue.lowest_height(MsgClass::CFilters).await.is_some_and(|h| h < o.height)
            {
                return None;
            }
            // Bulk download keeps every peer at its cap, so a cap would rule out all of them.
            let others = peers.iter().filter(|p| p.id() != o.peer && !p.is_closed());
            let peer = hedge_peer(others)?;
            (key.clone(), o.msg.clone(), o.height, peer.clone())
        };
        self.send_hedge(key, msg, height, peer).await
    }

    async fn send_hedge(
        &self,
        key: RequestKey,
        msg: NetworkMessage,
        height: u32,
        peer: PeerHandle,
    ) -> Option<u32> {
        peer.send(&msg).await.ok()?;
        match self.requests.lock().await.get_mut(&key) {
            Some(ReqState::OnWire(o)) if o.hedge.is_none() => {
                o.hedge = Some(peer.id());
                tracing::debug!(
                    target: "dash_spv::network",
                    "hedge at {}: on the wire {:.1}s at {} (overdue after {:.1}s, silent {:.1}s), copy to {}",
                    height,
                    o.sent.elapsed().as_secs_f64(),
                    o.peer.addr(),
                    o.overdue_after.as_secs_f64(),
                    o.last_answer.elapsed().as_secs_f64(),
                    peer.addr(),
                );
                Some(height)
            }
            _ => None,
        }
    }

    #[cfg(test)]
    pub async fn mark_on_wire(&self, msg: &NetworkMessage, peer: PeerId) {
        let mut reqs = self.requests.lock().await;
        for key in request_keys(msg) {
            let on_wire = OnWire {
                peer,
                last_progress: Instant::now(),
                last_answer: Instant::now(),
                sent: Instant::now(),
                overdue_after: HEDGE_OVERDUE,
                msg: msg.clone(),
                height: 0,
                hedge: None,
                attempts: 1,
            };
            reqs.insert(key, ReqState::OnWire(Box::new(on_wire)));
        }
    }

    #[cfg(test)]
    pub async fn carrier_of(&self, key: &RequestKey) -> Option<PeerId> {
        match self.requests.lock().await.get(key) {
            Some(ReqState::OnWire(o)) => Some(o.peer),
            _ => None,
        }
    }

    #[cfg(test)]
    pub async fn state_of(&self, key: &RequestKey) -> Option<&'static str> {
        self.requests.lock().await.get(key).map(|s| match s {
            ReqState::Queued(_) => "queued",
            ReqState::OnWire(_) => "on_wire",
            ReqState::Arrived => "arrived",
        })
    }
}

impl OnWire {
    /// Whether the request waited long enough for a second copy: its peer answered nothing
    /// for [`HEDGE_AFTER`], or the request has been on the wire for `overdue_after`.
    fn overdue(&self) -> bool {
        self.last_answer.elapsed() >= HEDGE_AFTER || self.sent.elapsed() >= self.overdue_after
    }
}

/// Returns the on-wire request of the lowest height among the keys `wanted` selects.
fn lowest_on_wire(
    reqs: &HashMap<RequestKey, ReqState>,
    wanted: impl Fn(&RequestKey) -> bool,
) -> Option<(&RequestKey, &OnWire)> {
    reqs.iter()
        .filter_map(|(key, state)| match state {
            ReqState::OnWire(o) if wanted(key) => Some((key, o.as_ref())),
            _ => None,
        })
        .min_by_key(|(_, o)| o.height)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MsgClass {
    Other,
    Blocks,
    CFilters,
    CfHeaders,
    Headers,
}

fn classify(msg: &NetworkMessage) -> MsgClass {
    match msg {
        NetworkMessage::GetData(inv)
            if !inv.is_empty() && inv.iter().all(|i| matches!(i, Inventory::Block(_))) =>
        {
            MsgClass::Blocks
        }
        NetworkMessage::GetCFilters(_) => MsgClass::CFilters,
        NetworkMessage::GetCFHeaders(_) => MsgClass::CfHeaders,
        NetworkMessage::GetHeaders(_) | NetworkMessage::GetHeaders2(_) => MsgClass::Headers,
        _ => MsgClass::Other,
    }
}

/// Picks the peer among `open` for a message of `class`. A header or block request goes to
/// the peer that will answer it soonest, since sync waits on each of them in height order.
/// Bulk filter traffic goes to the peer least loaded relative to its own cap, and so does
/// any request while no peer has a rate yet.
fn choose_peer<'a>(
    open: impl Iterator<Item = &'a PeerHandle> + Clone,
    class: MsgClass,
) -> Option<&'a PeerHandle> {
    if matches!(class, MsgClass::Headers | MsgClass::Blocks) && open.clone().any(|p| rate(p) > 0) {
        // A busy peer that has not delivered anything yet has no known queue, so it goes last.
        let wait = |p: &PeerHandle| queued_secs(p).unwrap_or(f64::INFINITY);
        return open.min_by(|a, b| wait(a).total_cmp(&wait(b)));
    }
    open.min_by(|a, b| {
        (a.in_flight_bytes() as u128 * b.cap() as u128)
            .cmp(&(b.in_flight_bytes() as u128 * a.cap() as u128))
    })
}

/// Picks the peer among `others` for the second copy of a request: the one that answers it
/// soonest. A peer without a serving rate looks idle before it gets work and may be slow, so
/// it is asked only when no peer with a serving rate is among `others`.
fn hedge_peer<'a>(others: impl Iterator<Item = &'a PeerHandle> + Clone) -> Option<&'a PeerHandle> {
    let measured = others.clone().filter(|p| p.serving_rate() > 0);
    if measured.clone().next().is_some() {
        return choose_peer(measured, MsgClass::Headers);
    }
    choose_peer(others, MsgClass::Headers)
}

/// Bytes/s the peer serves: its serving rate once measured, its last two seconds before.
fn rate(peer: &PeerHandle) -> u64 {
    match peer.serving_rate() {
        0 => peer.served(),
        rate => rate,
    }
}

/// Returns how long a request just sent to `peer` may stay on the wire while `peer` keeps
/// delivering: [`HEDGE_QUEUE_FACTOR`] times the queue it waits behind, at least
/// [`HEDGE_OVERDUE`]. The queue is taken at send. Requests sent later wait behind this one,
/// and a rate taken later would give a peer that slowed down the more time the slower it got.
fn overdue_after(peer: &PeerHandle) -> Duration {
    queued_secs(peer)
        .and_then(|secs| Duration::try_from_secs_f64(secs * HEDGE_QUEUE_FACTOR).ok())
        .map_or(HEDGE_OVERDUE, |queued| queued.max(HEDGE_OVERDUE))
}

/// Seconds the peer needs to serve what it already holds, `None` while it holds work
/// but has no rate. Peers answer in order, so a new request waits that long.
fn queued_secs(peer: &PeerHandle) -> Option<f64> {
    match (peer.in_flight_bytes(), rate(peer)) {
        (0, _) => Some(0.0),
        (_, 0) => None,
        (bytes, rate) => Some(bytes as f64 / rate as f64),
    }
}

/// `(height, seq)`: lowest height first, then FIFO; front inserts take negative seqs.
type QueueKey = (u32, i64);

/// One queue per class, drained by strict [`DRAIN_PRIORITY`].
struct MsgQueue {
    other: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    blocks: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    cfilters: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    cfheaders: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    headers: Mutex<BTreeMap<QueueKey, NetworkMessage>>,
    back_seq: AtomicI64,
    front_seq: AtomicI64,
    len: AtomicUsize,
    notify: Notify,
}

impl MsgQueue {
    fn new() -> Self {
        Self {
            other: Mutex::new(BTreeMap::new()),
            blocks: Mutex::new(BTreeMap::new()),
            cfilters: Mutex::new(BTreeMap::new()),
            cfheaders: Mutex::new(BTreeMap::new()),
            headers: Mutex::new(BTreeMap::new()),
            back_seq: AtomicI64::new(0),
            front_seq: AtomicI64::new(-1),
            len: AtomicUsize::new(0),
            notify: Notify::new(),
        }
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::SeqCst)
    }

    fn queue(&self, class: MsgClass) -> &Mutex<BTreeMap<QueueKey, NetworkMessage>> {
        match class {
            MsgClass::Other => &self.other,
            MsgClass::Blocks => &self.blocks,
            MsgClass::CFilters => &self.cfilters,
            MsgClass::CfHeaders => &self.cfheaders,
            MsgClass::Headers => &self.headers,
        }
    }

    async fn lowest_height(&self, class: MsgClass) -> Option<u32> {
        self.queue(class).lock().await.first_key_value().map(|(&(height, _), _)| height)
    }

    async fn pop_n(&self, n: usize) -> Vec<(u32, NetworkMessage)> {
        self.pop_guaranteed(n as u64, &[0; MSG_CLASSES], |_| 1).await
    }

    /// Pops by `cost` until `budget` (the last may overshoot), first up to
    /// `guaranteed[class]` from each class.
    async fn pop_guaranteed(
        &self,
        budget: u64,
        guaranteed: &[usize; MSG_CLASSES],
        cost: impl Fn(&NetworkMessage) -> u64,
    ) -> Vec<(u32, NetworkMessage)> {
        let mut out: Vec<(u32, NetworkMessage)> = Vec::new();
        let mut spent = 0u64;
        for class in DRAIN_PRIORITY {
            let mut q = self.queue(class).lock().await;
            let mut take = guaranteed[class as usize];
            while take > 0 && spent < budget {
                let Some(((height, _), msg)) = q.pop_first() else {
                    break;
                };
                spent += cost(&msg);
                out.push((height, msg));
                take -= 1;
            }
        }
        for class in DRAIN_PRIORITY {
            let mut q = self.queue(class).lock().await;
            while spent < budget {
                let Some(((height, _), msg)) = q.pop_first() else {
                    break;
                };
                spent += cost(&msg);
                out.push((height, msg));
            }
        }
        self.len.fetch_sub(out.len(), Ordering::SeqCst);
        out
    }

    async fn remove(&self, matches: impl Fn(&NetworkMessage) -> bool) {
        let mut removed = 0;
        for class in DRAIN_PRIORITY {
            let mut q = self.queue(class).lock().await;
            let before = q.len();
            q.retain(|_, msg| !matches(msg));
            removed += before - q.len();
        }
        self.len.fetch_sub(removed, Ordering::SeqCst);
    }

    async fn push(&self, height: u32, msg: NetworkMessage) {
        let key = (height, self.back_seq.fetch_add(1, Ordering::SeqCst));
        self.queue(classify(&msg)).lock().await.insert(key, msg);
        self.len.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
    }

    async fn push_front_all(&self, msgs: Vec<(u32, NetworkMessage)>) {
        if msgs.is_empty() {
            return;
        }
        let n = msgs.len();
        for (height, msg) in msgs.into_iter().rev() {
            let key = (height, self.front_seq.fetch_sub(1, Ordering::SeqCst));
            self.queue(classify(&msg)).lock().await.insert(key, msg);
        }
        self.len.fetch_add(n, Ordering::SeqCst);
        self.notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::peer::ConnectedPeer;
    use crate::test_utils::test_socket_address;
    use dashcore::network::message_blockdata::GetHeadersMessage;
    use dashcore::network::message_filter::{GetCFHeaders, GetCFilters};
    use dashcore::network::message_sml::GetMnListDiff;
    use dashcore::Txid;
    use test_case::test_case;

    fn get_headers(locator: u32) -> NetworkMessage {
        NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![BlockHash::dummy(locator)],
            BlockHash::dummy(0),
        ))
    }

    fn get_cfilters(start: u32) -> NetworkMessage {
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: start,
            stop_hash: BlockHash::dummy(start),
        })
    }

    fn get_cfheaders(stop: u32) -> NetworkMessage {
        NetworkMessage::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height: 0,
            stop_hash: BlockHash::dummy(stop),
        })
    }

    /// Requests the diff from block `base` to block 4.
    fn get_mnlistdiff(base: u32) -> NetworkMessage {
        NetworkMessage::GetMnListD(GetMnListDiff {
            base_block_hash: BlockHash::dummy(base),
            block_hash: BlockHash::dummy(4),
        })
    }

    fn block(n: u32) -> Inventory {
        Inventory::Block(BlockHash::dummy(n))
    }

    fn get_block(n: u32) -> NetworkMessage {
        NetworkMessage::GetData(vec![block(n)])
    }

    fn tx(n: u8) -> Inventory {
        Inventory::Transaction(Txid::from_byte_array([n; 32]))
    }

    fn conn(addr: u8, n: u64) -> PeerId {
        PeerId::for_test(test_socket_address(addr), n)
    }

    fn start_heights(msgs: &[(u32, NetworkMessage)]) -> Vec<u32> {
        msgs.iter()
            .map(|(_, m)| match m {
                NetworkMessage::GetCFilters(g) => g.start_height,
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    #[test_case(get_headers(1) => vec![RequestKey::Headers(BlockHash::dummy(1))]; "getheaders")]
    #[test_case(get_cfheaders(2) => vec![RequestKey::CfHeaders(BlockHash::dummy(2))]; "getcfheaders")]
    #[test_case(get_cfilters(100) => vec![RequestKey::CFilters(BlockHash::dummy(100))]; "getcfilters")]
    #[test_case(get_mnlistdiff(3) => vec![RequestKey::MnListDiff(BlockHash::dummy(4))]; "getmnlistd")]
    #[test_case(NetworkMessage::GetData(vec![block(1), tx(7), block(2)])
        => vec![RequestKey::Block(BlockHash::dummy(1)), RequestKey::Block(BlockHash::dummy(2))];
        "getdata splits per block and ignores other inventory")]
    #[test_case(NetworkMessage::GetData(vec![tx(1)]) => Vec::<RequestKey>::new(); "getdata tx")]
    #[test_case(NetworkMessage::MemPool => Vec::<RequestKey>::new(); "mempool")]
    fn request_keys_identify_tracked_requests(msg: NetworkMessage) -> Vec<RequestKey> {
        request_keys(&msg)
    }

    #[test_case(conn(1, 0), conn(2, 0), conn(1, 0), &[0]; "another peer's work is untouched")]
    #[test_case(conn(1, 0), conn(1, 1), conn(1, 0), &[0]; "the closed connection gives its work back")]
    #[test_case(conn(1, 1), conn(2, 0), conn(1, 0), &[]; "a late close leaves the replacement's work")]
    #[tokio::test]
    async fn losing_a_connection_requeues_only_its_requests(
        carrier_of_0: PeerId,
        carrier_of_1000: PeerId,
        gone: PeerId,
        expected: &[u32],
    ) {
        let broker = Broker::new();
        broker.mark_on_wire(&get_cfilters(0), carrier_of_0).await;
        broker.mark_on_wire(&get_cfilters(1000), carrier_of_1000).await;

        broker.requeue_from(&HashSet::from([gone])).await;

        assert_eq!(start_heights(&broker.queue.pop_n(2).await), expected);
        for height in [0, 1000] {
            let want = if expected.contains(&height) {
                "queued"
            } else {
                "on_wire"
            };
            assert_eq!(
                broker.state_of(&RequestKey::CFilters(BlockHash::dummy(height))).await,
                Some(want)
            );
        }
    }

    #[tokio::test]
    async fn requeued_work_skips_a_closed_peer_still_listed() {
        let broker = Broker::new();
        let gone = ConnectedPeer::for_test(conn(1, 0)).await;
        let other = ConnectedPeer::for_test(conn(2, 0)).await;
        broker.mark_on_wire(&get_cfilters(0), gone.id()).await;
        gone.close();
        broker.requeue_from(&HashSet::from([gone.id()])).await;

        // Only the charge matters here: the loopback has no reader to answer it.
        broker.route(&[gone.handle(), other.handle()], &ResponseCosts::new()).await;

        assert_eq!(gone.in_flight_bytes(), 0);
        assert!(other.in_flight_bytes() > 0);
    }

    #[tokio::test]
    async fn a_requeued_request_dedups_until_its_response_arrives() {
        let broker = Broker::new();
        let peer = conn(1, 0);
        broker.mark_on_wire(&get_cfilters(0), peer).await;
        broker.requeue_from(&HashSet::from([peer])).await;
        broker.queue.pop_n(1).await;
        assert_eq!(
            broker.state_of(&RequestKey::CFilters(BlockHash::dummy(0))).await,
            Some("queued")
        );

        broker.enqueue(0, get_cfilters(0)).await;
        assert_eq!(broker.len(), 0);

        broker.release(&RequestKey::CFilters(BlockHash::dummy(0))).await;
        assert_eq!(broker.state_of(&RequestKey::CFilters(BlockHash::dummy(0))).await, None);
        broker.enqueue(0, get_cfilters(0)).await;
        assert_eq!(broker.len(), 1);
    }

    /// A block at a slow peer gets a second copy only once it is the lowest on the wire and
    /// its peer stopped delivering. Peer 3 has the most room but was kicked after the
    /// snapshot of `peers` was taken, so it never gets the copy.
    #[tokio::test(start_paused = true)]
    async fn hedge_asks_another_peer_only_for_the_lowest_stalled_block() {
        let broker = Broker::new();
        let costs = ResponseCosts::new();
        let kicked = ConnectedPeer::for_test(conn(3, 0)).await;
        kicked.set_cap(u64::MAX);
        kicked.close();
        let peers = [
            ConnectedPeer::for_test(conn(1, 0)).await.handle(),
            ConnectedPeer::for_test(conn(2, 0)).await.handle(),
            kicked.handle(),
        ];
        let (slow, idle) = (&peers[..1], peers[1].id());
        let hedged_blocks = || async {
            let mut hedged: Vec<u32> = broker
                .requests
                .lock()
                .await
                .values()
                .filter_map(|state| match state {
                    ReqState::OnWire(o) if o.hedge == Some(idle) => Some(o.height),
                    _ => None,
                })
                .collect();
            hedged.sort();
            hedged
        };

        for n in [11, 12] {
            broker.enqueue(n, get_block(n)).await;
        }
        assert_eq!(broker.route(slow, &costs).await, 2);
        tokio::time::advance(HEDGE_AFTER).await;
        broker.enqueue(10, get_block(10)).await;
        assert_eq!(broker.route(slow, &costs).await, 1);
        assert_eq!(broker.hedge(&peers).await, None, "the lowest block has not waited long enough");

        tokio::time::advance(HEDGE_AFTER / 2).await;
        broker.progress(slow[0].id()).await;
        tokio::time::advance(HEDGE_AFTER / 2).await;
        assert_eq!(broker.hedge(&peers).await, None, "the slow peer is still delivering");

        broker.receiving(&[slow[0].id()]).await;
        tokio::time::advance(HEDGE_AFTER / 2).await;
        assert_eq!(broker.hedge(&peers).await, Some(10), "a block still arriving is hedged");
        assert_eq!(broker.hedge(&peers).await, None, "later blocks wait for the lowest");
        assert_eq!(hedged_blocks().await, [10]);

        broker.arrived(idle, RequestKey::Block(BlockHash::dummy(10))).await;
        assert_eq!(broker.hedge(&peers).await, Some(11));
        assert_eq!(hedged_blocks().await, [11]);
        assert_eq!(broker.hedge(slow).await, None, "no other peer to ask");
    }

    #[tokio::test]
    async fn a_new_peer_holds_two_header_requests() {
        let broker = Broker::new();
        let peer = ConnectedPeer::for_test(conn(1, 0)).await;
        for n in 0..3 {
            broker.enqueue(n, get_headers(n)).await;
        }

        assert_eq!(broker.route(&[peer.handle()], &ResponseCosts::new()).await, 2);
        assert_eq!(broker.len(), 1);
    }

    #[test_case(NetworkMessage::GetData(vec![block(1)]), RequestKey::Block(BlockHash::dummy(1)); "a block")]
    #[test_case(get_cfilters(1), RequestKey::CFilters(BlockHash::dummy(1)); "a filter batch")]
    #[test_case(get_cfheaders(1), RequestKey::CfHeaders(BlockHash::dummy(1)); "a filter header batch")]
    #[tokio::test]
    async fn an_arrived_reply_dedups_until_released(request: NetworkMessage, key: RequestKey) {
        let broker = Broker::new();
        let id = conn(1, 0);
        let peer = ConnectedPeer::for_test(id).await;

        broker.enqueue(0, request.clone()).await;
        assert_eq!(broker.route(&[peer.handle()], &ResponseCosts::new()).await, 1);
        broker.arrived(conn(2, 0), key.clone()).await;
        assert_eq!(broker.state_of(&key).await, Some("on_wire"), "only its carrier settles it");
        broker.arrived(id, key.clone()).await;
        assert_eq!(broker.state_of(&key).await, Some("arrived"));

        broker.enqueue(0, request.clone()).await;
        assert_eq!(broker.len(), 0, "a re-declare before the release must not fetch it again");
        assert_eq!(broker.requeue_from(&HashSet::from([id])).await, 0);
        assert!(broker.expire(|_| Duration::ZERO).await.is_empty());
        assert_eq!(broker.state_of(&key).await, Some("arrived"));

        broker.release(&key).await;
        assert_eq!(broker.state_of(&key).await, None);
        broker.enqueue(0, request).await;
        assert_eq!(broker.len(), 1);
    }

    #[test_case(NetworkMessage::GetData(vec![block(1)]), RequestKey::Block(BlockHash::dummy(1)); "a block")]
    #[test_case(get_cfilters(1), RequestKey::CFilters(BlockHash::dummy(1)); "a filter batch")]
    #[tokio::test]
    async fn a_requeued_request_is_settled_by_a_copy_from_any_peer(
        request: NetworkMessage,
        key: RequestKey,
    ) {
        let broker = Broker::new();
        let carrier = conn(1, 0);

        broker.mark_on_wire(&request, carrier).await;
        assert_eq!(broker.requeue_from(&HashSet::from([carrier])).await, 1);
        assert_eq!(broker.state_of(&key).await, Some("queued"));

        broker.arrived(conn(2, 0), key.clone()).await;
        assert_eq!(broker.state_of(&key).await, Some("arrived"));
        assert_eq!(broker.len(), 0, "the queued request must not go out after its reply arrived");

        broker.enqueue(0, request).await;
        assert_eq!(broker.len(), 0);
    }

    /// Peers at their caps must not stop it: the batch blocks the store, and every bulk
    /// download keeps them there. Peer 2 is at its cap with the batch that completes first.
    #[tokio::test(start_paused = true)]
    async fn hedge_filters_asks_another_peer_once_for_the_lowest_missing_batch() {
        let broker = Broker::new();
        let costs = ResponseCosts::new();
        let slow = ConnectedPeer::for_test(conn(1, 0)).await;
        let idle = ConnectedPeer::for_test(conn(2, 0)).await;
        let peers = [slow.handle(), idle.handle()];
        let lowest = RequestKey::CFilters(BlockHash::dummy(1000));

        slow.set_cap(1 << 30);
        for start in [1000, 2000] {
            broker.enqueue(start, get_cfilters(start)).await;
        }
        assert_eq!(broker.route(&peers[..1], &costs).await, 2);
        broker.enqueue(3000, get_cfilters(3000)).await;
        assert_eq!(broker.route(&peers[1..], &costs).await, 1);
        broker.arrived(idle.id(), RequestKey::CFilters(BlockHash::dummy(3000))).await;
        idle.set_cap(idle.in_flight_bytes().max(1));

        assert_eq!(broker.hedge_filters(&peers).await, None, "it has not waited long enough");
        tokio::time::advance(HEDGE_AFTER).await;

        broker.enqueue(500, get_cfilters(500)).await;
        assert_eq!(broker.hedge_filters(&peers).await, None, "the lowest one is queued");
        broker.queue.pop_n(1).await;
        broker.release(&RequestKey::CFilters(BlockHash::dummy(500))).await;

        assert_eq!(broker.hedge_filters(&peers).await, Some(1000));
        assert_eq!(broker.hedge_filters(&peers).await, None, "a batch is hedged once");
        assert_eq!(broker.hedge_filters(&peers[..1]).await, None);

        broker.arrived(idle.id(), lowest.clone()).await;
        assert_eq!(broker.state_of(&lowest).await, Some("arrived"), "the first copy settles it");
        assert_eq!(broker.hedge_filters(&peers).await, Some(2000));
        assert_eq!(broker.hedge_filters(&peers[..1]).await, None, "no other peer to ask");
    }

    /// Peer 2 is idle and unmeasured, peer 3 measured and busy. Returns the peer asked for
    /// the second copy.
    #[test_case(get_cfilters(0), false => Some(3); "a filter batch goes to the measured peer")]
    #[test_case(get_cfilters(0), true => Some(3); "a filter batch goes to the measured peer at its cap")]
    #[test_case(get_block(0), false => Some(3); "a block goes to the measured peer")]
    #[test_case(get_block(0), true => Some(2); "a block goes to an unmeasured peer while the measured one is full")]
    #[tokio::test(start_paused = true)]
    async fn a_hedge_prefers_a_measured_peer(request: NetworkMessage, full: bool) -> Option<u8> {
        let broker = Broker::new();
        let holder = ConnectedPeer::for_test(conn(1, 0)).await;
        let unmeasured = ConnectedPeer::for_test(conn(2, 0)).await;
        let measured = ConnectedPeer::for_test(conn(3, 0)).await;
        measured.handle().send(&get_cfilters(5000)).await.expect("loopback send");
        measured.set_serving_rate(100 << 10);
        if full {
            measured.set_cap(measured.in_flight_bytes());
        }
        broker.mark_on_wire(&request, holder.id()).await;
        tokio::time::advance(HEDGE_AFTER).await;

        let peers = [holder.handle(), unmeasured.handle(), measured.handle()];
        let hedged = match request {
            NetworkMessage::GetCFilters(_) => broker.hedge_filters(&peers).await,
            _ => broker.hedge(&peers).await,
        };
        assert_eq!(hedged, Some(0));
        let hedge = broker.requests.lock().await.values().find_map(|state| match state {
            ReqState::OnWire(o) => o.hedge,
            _ => None,
        });
        [2, 3].into_iter().find(|n| hedge == Some(conn(*n, 0)))
    }

    /// The holder keeps delivering a 20 s queue it took the request behind, so a second copy
    /// waits for twice that rather than for `HEDGE_OVERDUE`.
    #[test_case(get_cfilters(1000); "a filter batch")]
    #[test_case(get_block(1); "a block")]
    #[tokio::test(start_paused = true)]
    async fn a_request_queued_at_a_steady_peer_is_hedged_only_past_twice_its_queue(
        request: NetworkMessage,
    ) {
        let broker = Broker::new();
        let costs = ResponseCosts::new();
        let holder = ConnectedPeer::for_test(conn(1, 0)).await;
        let other = ConnectedPeer::for_test(conn(2, 0)).await;
        for start in [0, 1, 2, 3] {
            holder.handle().send(&get_cfilters(start)).await.expect("loopback send");
        }
        holder.set_cap(1 << 30);
        let queued = holder.in_flight_bytes() + costs.cost(&request);
        holder.set_serving_rate(queued / 20);
        broker.enqueue(1000, request.clone()).await;
        assert_eq!(broker.route(&[holder.handle()], &costs).await, 1);

        let peers = [holder.handle(), other.handle()];
        let hedge = || async {
            match request {
                NetworkMessage::GetCFilters(_) => broker.hedge_filters(&peers).await,
                _ => broker.hedge(&peers).await,
            }
        };
        let step = HEDGE_AFTER / 2;
        let mut waited = Duration::ZERO;
        // The integer rate rounds the queue up a little, so the copy goes just after 40 s.
        for deadline in [HEDGE_OVERDUE, Duration::from_secs(39), Duration::from_secs(41)] {
            while waited < deadline {
                tokio::time::advance(step).await;
                broker.progress(holder.id()).await;
                waited += step;
            }
            let hedged = if deadline < Duration::from_secs(40) {
                None
            } else {
                Some(1000)
            };
            assert_eq!(hedge().await, hedged, "after {deadline:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_hedge_lost_with_its_peer_is_sent_again() {
        let broker = Broker::new();
        let holder = ConnectedPeer::for_test(conn(1, 0)).await.handle();
        let first = ConnectedPeer::for_test(conn(2, 0)).await.handle();
        let second = ConnectedPeer::for_test(conn(3, 0)).await.handle();
        broker.mark_on_wire(&get_cfilters(0), holder.id()).await;
        tokio::time::advance(HEDGE_AFTER).await;

        assert_eq!(broker.hedge_filters(&[holder.clone(), first.clone()]).await, Some(0));
        assert_eq!(broker.hedge_filters(&[holder.clone(), second.clone()]).await, None);

        assert_eq!(broker.requeue_from(&HashSet::from([first.id()])).await, 0);
        let key = RequestKey::CFilters(BlockHash::dummy(0));
        assert_eq!(broker.carrier_of(&key).await, Some(holder.id()), "the request stays put");
        assert_eq!(broker.hedge_filters(&[holder, second]).await, Some(0));
    }

    #[test_case(get_cfilters(0), false, HEDGE_AFTER => Some(0); "a batch at a silent peer")]
    #[test_case(get_cfilters(0), true, HEDGE_AFTER => None; "a batch at a peer still delivering")]
    #[test_case(get_cfilters(0), true, HEDGE_OVERDUE - HEDGE_AFTER => None; "a batch at a peer still delivering, short of the deadline")]
    #[test_case(get_cfilters(0), true, HEDGE_OVERDUE => Some(0); "a batch at a peer still delivering, past the deadline")]
    #[test_case(get_block(0), false, HEDGE_AFTER => Some(0); "a block at a silent peer")]
    #[test_case(get_block(0), true, HEDGE_OVERDUE - HEDGE_AFTER => None; "a block at a peer still delivering, short of the deadline")]
    #[test_case(get_block(0), true, HEDGE_OVERDUE => Some(0); "a block at a peer still delivering, past the deadline")]
    #[tokio::test(start_paused = true)]
    async fn hedge_asks_another_peer_only_for_a_request_stuck_at_a_silent_or_slow_one(
        request: NetworkMessage,
        delivering: bool,
        waited: Duration,
    ) -> Option<u32> {
        let broker = Broker::new();
        let slow = ConnectedPeer::for_test(conn(1, 0)).await;
        let idle = ConnectedPeer::for_test(conn(2, 0)).await;
        broker.mark_on_wire(&request, conn(1, 0)).await;

        let step = HEDGE_AFTER / 2;
        for _ in 0..waited.as_millis() / step.as_millis() {
            tokio::time::advance(step).await;
            if delivering {
                broker.progress(conn(1, 0)).await;
            }
        }

        let peers = [slow.handle(), idle.handle()];
        match request {
            NetworkMessage::GetCFilters(_) => broker.hedge_filters(&peers).await,
            _ => broker.hedge(&peers).await,
        }
    }

    #[test_case(get_mnlistdiff(3), vec![RequestKey::MnListDiff(BlockHash::dummy(4))], 0; "its only key")]
    #[test_case(NetworkMessage::GetData(vec![block(1), block(2)]), vec![RequestKey::Block(BlockHash::dummy(1))], 1; "one of its keys")]
    #[test_case(NetworkMessage::GetData(vec![block(1), block(2)]), vec![RequestKey::Block(BlockHash::dummy(1)), RequestKey::Block(BlockHash::dummy(2))], 0; "all of its keys")]
    #[tokio::test]
    async fn a_released_request_is_dropped_once_none_of_its_keys_is_in_play(
        msg: NetworkMessage,
        released: Vec<RequestKey>,
        queued: usize,
    ) {
        let broker = Broker::new();
        broker.enqueue(0, msg).await;
        broker.enqueue(0, get_cfilters(0)).await;
        for key in &released {
            broker.release(key).await;
        }
        assert_eq!(broker.len(), queued + 1, "the other request stays queued");
        assert_eq!(broker.queue.pop_n(broker.len()).await.len(), queued + 1);
    }

    #[tokio::test]
    async fn a_request_released_and_declared_from_another_base_replaces_the_queued_one() {
        let broker = Broker::new();
        broker.enqueue(0, get_mnlistdiff(3)).await;
        broker.release(&RequestKey::MnListDiff(BlockHash::dummy(4))).await;
        broker.enqueue(0, get_mnlistdiff(5)).await;

        let queued: Vec<NetworkMessage> =
            broker.queue.pop_n(broker.len()).await.into_iter().map(|(_, msg)| msg).collect();
        assert_eq!(queued, vec![get_mnlistdiff(5)]);
    }

    #[test_case(vec![get_cfilters(0), get_cfilters(0), get_cfilters(1000)], 2, 2; "a request in play is dropped")]
    #[test_case(vec![NetworkMessage::MemPool, NetworkMessage::MemPool], 2, 0; "untracked traffic is never deduplicated")]
    #[tokio::test]
    async fn enqueue_dedups_by_request_key(
        msgs: Vec<NetworkMessage>,
        queued: usize,
        tracked: usize,
    ) {
        let broker = Broker::new();
        for msg in msgs {
            broker.enqueue(0, msg).await;
        }
        assert_eq!(broker.len(), queued);
        assert_eq!(broker.requests.lock().await.len(), tracked);
    }

    /// `slow` holds 1 MB, a tenth of its cap, served at `slow_rate`. `fast` holds 256 KB, half
    /// its cap, served at `fast_rate`, or at `fast_served` over the last two seconds while its
    /// serving rate is unmeasured. Returns which of them `msg` is routed to.
    #[test_case(get_headers(1), 100 << 10, 1 << 20, 0 => "fast"; "a header request goes to the shortest queue")]
    #[test_case(get_headers(1), 100 << 10, 0, 1 << 20 => "fast"; "a peer still being measured is timed by its last two seconds")]
    #[test_case(get_headers(1), 0, 1 << 20, 0 => "fast"; "a busy peer that delivered nothing yet goes last")]
    #[test_case(get_headers(1), 0, 0, 0 => "slow"; "the cap ratio while no peer has a rate")]
    #[test_case(get_block(1), 100 << 10, 1 << 20, 0 => "fast"; "a block request goes to the shortest queue")]
    #[test_case(get_block(1), 100 << 10, 0, 1 << 20 => "fast"; "a block request times a peer by its last two seconds")]
    #[test_case(get_cfilters(0), 100 << 10, 1 << 20, 0 => "slow"; "bulk requests keep the cap ratio")]
    #[tokio::test]
    async fn route_picks_the_peer_by_class(
        msg: NetworkMessage,
        slow_rate: u64,
        fast_rate: u64,
        fast_served: u64,
    ) -> &'static str {
        let costs = ResponseCosts::new();
        let slow = ConnectedPeer::for_test(conn(1, 0)).await;
        let fast = ConnectedPeer::for_test(conn(2, 0)).await;
        for start in [0, 1000, 2000, 3000] {
            slow.handle().send(&get_cfilters(start)).await.expect("loopback send");
        }
        fast.handle().send(&get_cfilters(4000)).await.expect("loopback send");
        slow.set_cap(slow.in_flight_bytes() * 10);
        fast.set_cap(fast.in_flight_bytes() * 2);
        slow.set_serving_rate(slow_rate);
        fast.set_serving_rate(fast_rate);
        fast.set_served(fast_served);
        let before = (slow.in_flight_bytes(), fast.in_flight_bytes());

        let broker = Broker::new();
        broker.enqueue(0, msg).await;
        assert_eq!(broker.route(&[slow.handle(), fast.handle()], &costs).await, 1);

        match (slow.in_flight_bytes() > before.0, fast.in_flight_bytes() > before.1) {
            (true, false) => "slow",
            (false, true) => "fast",
            other => panic!("routed to {other:?}"),
        }
    }

    #[test_case(get_headers(1) => MsgClass::Headers)]
    #[test_case(get_cfheaders(1) => MsgClass::CfHeaders)]
    #[test_case(get_cfilters(0) => MsgClass::CFilters)]
    #[test_case(NetworkMessage::GetData(vec![block(1)]) => MsgClass::Blocks; "getdata blocks")]
    #[test_case(NetworkMessage::GetData(vec![tx(1)]) => MsgClass::Other; "getdata tx is control traffic")]
    #[test_case(NetworkMessage::MemPool => MsgClass::Other)]
    fn classify_cases(msg: NetworkMessage) -> MsgClass {
        classify(&msg)
    }

    #[tokio::test]
    async fn queue_drains_in_strict_priority_order() {
        let q = MsgQueue::new();
        q.push(0, get_cfilters(0)).await;
        q.push(0, NetworkMessage::GetData(vec![block(1)])).await;
        q.push(0, get_cfheaders(1)).await;
        q.push(0, get_headers(1)).await;
        q.push(0, NetworkMessage::MemPool).await;

        let drained: Vec<MsgClass> = q.pop_n(5).await.iter().map(|(_, m)| classify(m)).collect();
        assert_eq!(
            drained,
            [
                MsgClass::Other,
                MsgClass::Blocks,
                MsgClass::CFilters,
                MsgClass::CfHeaders,
                MsgClass::Headers
            ]
        );
        assert_eq!(q.len(), 0);
    }

    #[tokio::test]
    async fn pop_n_respects_its_budget_and_unsent_messages_go_back_to_the_front() {
        let q = MsgQueue::new();
        for start in [0, 1000, 2000] {
            q.push(start, get_cfilters(start)).await;
        }

        let popped = q.pop_n(1).await;
        assert_eq!(start_heights(&popped), [0]);
        assert!(q.pop_n(0).await.is_empty());
        assert_eq!(q.len(), 2);

        q.push_front_all(popped).await;
        assert_eq!(start_heights(&q.pop_n(3).await), [0, 1000, 2000]);
    }
}
