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
const HEDGE_AFTER: Duration = Duration::from_secs(2);
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
    /// Start height.
    CFilters(u32),
    MnListDiff(BlockHash),
    Block(BlockHash),
}

pub fn request_keys(msg: &NetworkMessage) -> Vec<RequestKey> {
    match msg {
        NetworkMessage::GetHeaders(m) | NetworkMessage::GetHeaders2(m) => {
            m.locator_hashes.first().map(|h| RequestKey::Headers(*h)).into_iter().collect()
        }
        NetworkMessage::GetCFHeaders(m) => vec![RequestKey::CfHeaders(m.stop_hash)],
        NetworkMessage::GetCFilters(m) => vec![RequestKey::CFilters(m.start_height)],
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
    /// The block was received and waits for its manager to release the key.
    Arrived,
}

struct OnWire {
    /// The connection, not the address: a late close of an old connection must not
    /// pull back the work of a new one to the same address.
    peer: PeerId,
    /// Refreshed by every piece of a streaming response.
    last_progress: Instant,
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

    pub async fn requeue_from(&self, gone: &HashSet<PeerId>) -> usize {
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

    /// Settled on arrival, not when processed: blocks wait in height order, and that
    /// wait is not the peer's. The first copy of a hedged block settles it. A request
    /// put back in the queue is settled by a copy from any peer, and its message dropped.
    /// The key stays registered until released, so a re-declare before then sends nothing.
    pub async fn block_arrived(&self, peer: PeerId, hash: BlockHash) {
        let key = RequestKey::Block(hash);
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
        let now = Instant::now();
        for state in self.requests.lock().await.values_mut() {
            if let ReqState::OnWire(o) = state {
                if o.peer == peer {
                    o.last_progress = now;
                }
            }
        }
    }

    /// Returns the peers to kick for a stalled request. A request that already
    /// stalled [`KICKING_ATTEMPTS`] times is retried without blaming its peer.
    pub async fn expire(&self, timeout: impl Fn(&PeerId) -> Duration) -> HashSet<PeerId> {
        let now = Instant::now();
        let mut culprits = HashSet::new();
        let mut unanswerable = HashSet::new();
        for (key, state) in self.requests.lock().await.iter() {
            let ReqState::OnWire(o) = state else {
                continue;
            };
            if now.duration_since(o.last_progress) <= timeout(&o.peer) {
                continue;
            }
            if o.attempts < KICKING_ATTEMPTS {
                culprits.insert(o.peer);
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

    /// Sends what fits in both the peers' and the global byte caps, each message to
    /// the peer [`choose_peer`] picks.
    pub async fn route(
        &self,
        peers: &[PeerHandle],
        global_cap: u64,
        costs: &ResponseCosts,
    ) -> usize {
        if peers.is_empty() {
            return 0;
        }
        let total_in_flight: u64 = peers.iter().map(PeerHandle::in_flight_bytes).sum();
        let per_peer_room: u64 =
            peers.iter().map(|p| p.cap().saturating_sub(p.in_flight_bytes())).sum();
        let budget = per_peer_room.min(global_cap.saturating_sub(total_in_flight));
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
        let mut on_wire: Vec<(u32, NetworkMessage, PeerHandle)> = Vec::new();
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
                on_wire.push((height, msg, peer.clone()));
            } else {
                tracing::warn!(target: "dash_spv::network", "router: send to {} failed", peer.addr());
                unsent.push((height, msg));
            }
        }
        unsent.extend(msgs);
        self.queue.push_front_all(unsent).await;

        if !on_wire.is_empty() {
            let mut reqs = self.requests.lock().await;
            for (height, msg, peer) in on_wire {
                for key in request_keys(&msg) {
                    if let Some(slot) = reqs.get_mut(&key) {
                        let attempts = match slot {
                            ReqState::Queued(attempts) => *attempts,
                            ReqState::OnWire(o) => o.attempts,
                            // The block of a requeued request can arrive while it is resent.
                            ReqState::Arrived => continue,
                        };
                        *slot = ReqState::OnWire(Box::new(OnWire {
                            peer: peer.id(),
                            msg: msg.clone(),
                            height,
                            last_progress: Instant::now(),
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

    /// Endgame: asks a second peer for the lowest block on the wire once its peer delivered
    /// nothing for [`HEDGE_AFTER`], and returns its height. Blocks are processed in height
    /// order, so only the lowest one holds up progress and a second copy of any other is wasted.
    pub async fn hedge(&self, peers: &[PeerHandle]) -> Option<u32> {
        let (key, msg, height, peer) = {
            let reqs = self.requests.lock().await;
            let (key, o) = reqs
                .iter()
                .filter_map(|(key, state)| match state {
                    ReqState::OnWire(o) if matches!(key, RequestKey::Block(_)) => {
                        Some((key, o.as_ref()))
                    }
                    _ => None,
                })
                .min_by_key(|(_, o)| o.height)?;
            if o.hedge.is_some() || o.last_progress.elapsed() < HEDGE_AFTER {
                return None;
            }
            let peer = peers
                .iter()
                .filter(|p| p.id() != o.peer && p.in_flight_bytes() < p.cap())
                .max_by_key(|p| p.cap().saturating_sub(p.in_flight_bytes()))?;
            (key.clone(), o.msg.clone(), o.height, peer.clone())
        };
        peer.send(&msg).await.ok()?;
        match self.requests.lock().await.get_mut(&key) {
            Some(ReqState::OnWire(o)) if o.hedge.is_none() => {
                o.hedge = Some(peer.id());
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
                msg: msg.clone(),
                height: 0,
                hedge: None,
                attempts: 1,
            };
            reqs.insert(key, ReqState::OnWire(Box::new(on_wire)));
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
/// any request while a busy peer has no serving rate yet.
fn choose_peer<'a>(
    open: impl Iterator<Item = &'a PeerHandle> + Clone,
    class: MsgClass,
) -> Option<&'a PeerHandle> {
    if matches!(class, MsgClass::Headers | MsgClass::Blocks) {
        let waits: Option<Vec<(f64, &PeerHandle)>> =
            open.clone().map(|p| Some((queued_secs(p)?, p))).collect();
        if let Some(waits) = waits {
            return waits.into_iter().min_by(|a, b| a.0.total_cmp(&b.0)).map(|(_, p)| p);
        }
    }
    open.min_by(|a, b| {
        (a.in_flight_bytes() as u128 * b.cap() as u128)
            .cmp(&(b.in_flight_bytes() as u128 * a.cap() as u128))
    })
}

/// Seconds the peer needs to serve what it already holds, `None` while it holds work
/// but has no measured serving rate. Peers answer in order, so a new request waits that long.
fn queued_secs(peer: &PeerHandle) -> Option<f64> {
    match (peer.in_flight_bytes(), peer.serving_rate()) {
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
            stop_hash: BlockHash::dummy(9),
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
    #[test_case(get_cfilters(100) => vec![RequestKey::CFilters(100)]; "getcfilters")]
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
            assert_eq!(broker.state_of(&RequestKey::CFilters(height)).await, Some(want));
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
        broker.route(&[gone.handle(), other.handle()], u64::MAX, &ResponseCosts::new()).await;

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
        assert_eq!(broker.state_of(&RequestKey::CFilters(0)).await, Some("queued"));

        broker.enqueue(0, get_cfilters(0)).await;
        assert_eq!(broker.len(), 0);

        broker.release(&RequestKey::CFilters(0)).await;
        assert_eq!(broker.state_of(&RequestKey::CFilters(0)).await, None);
        broker.enqueue(0, get_cfilters(0)).await;
        assert_eq!(broker.len(), 1);
    }

    /// A block at a slow peer gets a second copy only once it is the lowest on the wire and
    /// its peer stopped delivering.
    #[tokio::test(start_paused = true)]
    async fn hedge_asks_another_peer_only_for_the_lowest_stalled_block() {
        let broker = Broker::new();
        let costs = ResponseCosts::new();
        let peers = [
            ConnectedPeer::for_test(conn(1, 0)).await.handle(),
            ConnectedPeer::for_test(conn(2, 0)).await.handle(),
        ];
        let (slow, idle) = (&peers[..1], peers[1].id());
        let get_block = |n: u32| NetworkMessage::GetData(vec![block(n)]);
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
        assert_eq!(broker.route(slow, u64::MAX, &costs).await, 2);
        tokio::time::advance(HEDGE_AFTER).await;
        broker.enqueue(10, get_block(10)).await;
        assert_eq!(broker.route(slow, u64::MAX, &costs).await, 1);
        assert_eq!(broker.hedge(&peers).await, None, "the lowest block has not waited long enough");

        tokio::time::advance(HEDGE_AFTER / 2).await;
        broker.progress(slow[0].id()).await;
        tokio::time::advance(HEDGE_AFTER / 2).await;
        assert_eq!(broker.hedge(&peers).await, None, "the slow peer is still delivering");

        tokio::time::advance(HEDGE_AFTER / 2).await;
        assert_eq!(broker.hedge(&peers).await, Some(10));
        assert_eq!(broker.hedge(&peers).await, None, "later blocks wait for the lowest");
        assert_eq!(hedged_blocks().await, [10]);

        broker.block_arrived(idle, BlockHash::dummy(10)).await;
        assert_eq!(broker.hedge(&peers).await, Some(11));
        assert_eq!(hedged_blocks().await, [11]);
        assert_eq!(broker.hedge(slow).await, None, "no other peer to ask");
    }

    #[tokio::test]
    async fn an_arrived_block_dedups_until_released() {
        let broker = Broker::new();
        let id = conn(1, 0);
        let getdata = NetworkMessage::GetData(vec![block(1)]);
        let key = RequestKey::Block(BlockHash::dummy(1));

        broker.enqueue(0, getdata.clone()).await;
        assert_eq!(broker.queue.pop_n(1).await.len(), 1);
        broker.mark_on_wire(&getdata, id).await;
        broker.block_arrived(conn(2, 0), BlockHash::dummy(1)).await;
        assert_eq!(broker.state_of(&key).await, Some("on_wire"), "only its carrier settles it");
        broker.block_arrived(id, BlockHash::dummy(1)).await;
        assert_eq!(broker.state_of(&key).await, Some("arrived"));

        broker.enqueue(0, getdata.clone()).await;
        assert_eq!(broker.len(), 0, "a re-declare before the release must not fetch it again");
        assert_eq!(broker.requeue_from(&HashSet::from([id])).await, 0);
        assert!(broker.expire(|_| Duration::ZERO).await.is_empty());
        assert_eq!(broker.state_of(&key).await, Some("arrived"));

        broker.release(&key).await;
        assert_eq!(broker.state_of(&key).await, None);
        broker.enqueue(0, getdata).await;
        assert_eq!(broker.len(), 1);
    }

    #[tokio::test]
    async fn a_requeued_block_is_settled_by_a_copy_from_any_peer() {
        let broker = Broker::new();
        let carrier = conn(1, 0);
        let getdata = NetworkMessage::GetData(vec![block(1)]);
        let key = RequestKey::Block(BlockHash::dummy(1));

        broker.mark_on_wire(&getdata, carrier).await;
        assert_eq!(broker.requeue_from(&HashSet::from([carrier])).await, 1);
        assert_eq!(broker.state_of(&key).await, Some("queued"));

        broker.block_arrived(conn(2, 0), BlockHash::dummy(1)).await;
        assert_eq!(broker.state_of(&key).await, Some("arrived"));
        assert_eq!(broker.len(), 0, "the queued getdata must not go out after the block arrived");

        broker.enqueue(0, getdata).await;
        assert_eq!(broker.len(), 0);
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

    /// `slow` holds 1 MB at 100 KB/s, a 10 s queue at a tenth of its cap. `fast` holds
    /// 256 KB at `fast_rate`, half its cap. Returns which of them `msg` is routed to.
    #[test_case(get_headers(1), 1 << 20 => "fast"; "a header request goes to the shortest queue")]
    #[test_case(get_headers(1), 0 => "slow"; "a header request falls back to the cap ratio while a busy peer is unmeasured")]
    #[test_case(NetworkMessage::GetData(vec![block(1)]), 1 << 20 => "fast"; "a block request goes to the shortest queue")]
    #[test_case(NetworkMessage::GetData(vec![block(1)]), 0 => "slow"; "a block request falls back to the cap ratio while a busy peer is unmeasured")]
    #[test_case(get_cfilters(0), 1 << 20 => "slow"; "bulk requests keep the cap ratio")]
    #[tokio::test]
    async fn route_picks_the_peer_by_class(msg: NetworkMessage, fast_rate: u64) -> &'static str {
        let costs = ResponseCosts::new();
        let slow = ConnectedPeer::for_test(conn(1, 0)).await;
        let fast = ConnectedPeer::for_test(conn(2, 0)).await;
        for start in [0, 1000, 2000, 3000] {
            slow.handle().send(&get_cfilters(start)).await.expect("loopback send");
        }
        fast.handle().send(&get_cfilters(4000)).await.expect("loopback send");
        slow.set_cap(slow.in_flight_bytes() * 10);
        fast.set_cap(fast.in_flight_bytes() * 2);
        slow.set_serving_rate(100 << 10);
        fast.set_serving_rate(fast_rate);
        let before = (slow.in_flight_bytes(), fast.in_flight_bytes());

        let broker = Broker::new();
        broker.enqueue(0, msg).await;
        assert_eq!(broker.route(&[slow.handle(), fast.handle()], u64::MAX, &costs).await, 1);

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
