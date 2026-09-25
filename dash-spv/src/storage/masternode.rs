use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use dashcore::consensus::{deserialize, serialize, Decodable, Encodable};
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list_engine::{qr_info_diffs, MasternodeListEngine, WORK_DIFF_DEPTH};
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{BlockHash, Network, QuorumHash};

use crate::error::{StorageError, StorageResult};
use crate::storage::{io::atomic_write, BlockHeaderStorage};

type IndexMap = BTreeMap<CoreBlockHeight, PathBuf>;

enum Message {
    Diff(Box<MnListDiff>),
    QrInfo(Box<QRInfo>),
}

/// At one height a diff replays before a QRInfo.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Diff,
    QrInfo,
}

/// Which lists a replay keeps once it has moved past them.
#[derive(Clone, Copy)]
enum Retain {
    /// What a live engine at the same height would keep.
    Obsolete,
    /// Lists in `floor..=height`, the nearest list on either side of `height`.
    Around {
        floor: CoreBlockHeight,
        height: CoreBlockHeight,
    },
}

#[derive(Debug, Default)]
struct ReplayStats {
    total: usize,
    applied: usize,
    peak_lists: usize,
}

#[async_trait]
pub trait MasternodeStorage: Send + Sync + 'static {
    async fn store_diff(&mut self, height: CoreBlockHeight, diff: &MnListDiff)
        -> StorageResult<()>;

    async fn store_qr_info(
        &mut self,
        height: CoreBlockHeight,
        qr_info: &QRInfo,
    ) -> StorageResult<()>;

    async fn load_engine(&self) -> StorageResult<MasternodeListEngine>;

    /// The quorum as [`MasternodeListEngine::quorum_entry_for_hash_at_or_before_height`]
    /// would resolve it from the lists stored up to `height`.
    async fn quorum_entry_at_or_before(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<QualifiedQuorumEntry>>;
}

pub struct PersistentMasternodeStorage<H: BlockHeaderStorage> {
    storage_path: PathBuf,
    headers: Arc<RwLock<H>>,
    network: Network,
    diffs: IndexMap,
    qr_infos: IndexMap,
}

/// The stored messages as of when it was taken, and where their heights
/// resolve. A replay runs on this rather than on the storage, so a caller can
/// release the storage lock first and a long replay does not hold up the
/// masternode sync storing the next message.
pub struct MessageLog<H: BlockHeaderStorage> {
    headers: Arc<RwLock<H>>,
    network: Network,
    diffs: IndexMap,
    qr_infos: IndexMap,
}

impl<H: BlockHeaderStorage> PersistentMasternodeStorage<H> {
    const FOLDER_NAME: &str = "masternodes";
    const DIFF_PREFIX: &str = "diff_";
    const QRINFO_PREFIX: &str = "qrinfo_";
    const EXTENSION: &str = "dat";

    pub async fn open(
        storage_path: impl Into<PathBuf> + Send,
        headers: Arc<RwLock<H>>,
        network: Network,
    ) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let (diffs, qr_infos) = Self::index_folder(&storage_path.join(Self::FOLDER_NAME)).await?;

        Ok(PersistentMasternodeStorage {
            storage_path,
            headers,
            network,
            diffs,
            qr_infos,
        })
    }

    fn folder(&self) -> PathBuf {
        self.storage_path.join(Self::FOLDER_NAME)
    }

    fn file_name(prefix: &str, height: CoreBlockHeight) -> String {
        format!("{prefix}{height}.{}", Self::EXTENSION)
    }

    fn height_from_file_name(name: &str, prefix: &str) -> Option<CoreBlockHeight> {
        name.strip_prefix(prefix)?.strip_suffix(&format!(".{}", Self::EXTENSION))?.parse().ok()
    }

    async fn index_folder(folder: &Path) -> StorageResult<(IndexMap, IndexMap)> {
        let mut diffs = BTreeMap::new();
        let mut qr_infos = BTreeMap::new();

        if !folder.exists() {
            return Ok((diffs, qr_infos));
        }

        let mut entries = tokio::fs::read_dir(folder).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(height) = Self::height_from_file_name(name, Self::DIFF_PREFIX) {
                diffs.insert(height, path);
            } else if let Some(height) = Self::height_from_file_name(name, Self::QRINFO_PREFIX) {
                qr_infos.insert(height, path);
            }
        }

        Ok((diffs, qr_infos))
    }

    async fn store_message<T: Encodable + Sync>(
        folder: &Path,
        index: &mut IndexMap,
        prefix: &str,
        height: CoreBlockHeight,
        message: &T,
    ) -> StorageResult<()> {
        tokio::fs::create_dir_all(folder).await?;
        let path = folder.join(Self::file_name(prefix, height));
        atomic_write(&path, &serialize(message)).await?;
        index.insert(height, path);
        Ok(())
    }

    async fn read_message<T: Decodable>(path: &Path) -> StorageResult<T> {
        let bytes = tokio::fs::read(path).await?;
        deserialize(&bytes).map_err(|e| {
            StorageError::Corruption(format!("Failed to decode {}: {e}", path.display()))
        })
    }

    async fn read_entry(path: &Path, kind: Kind) -> StorageResult<Message> {
        Ok(match kind {
            Kind::Diff => Message::Diff(Box::new(Self::read_message(path).await?)),
            Kind::QrInfo => Message::QrInfo(Box::new(Self::read_message(path).await?)),
        })
    }

    pub fn message_log(&self) -> MessageLog<H> {
        MessageLog {
            headers: Arc::clone(&self.headers),
            network: self.network,
            diffs: self.diffs.clone(),
            qr_infos: self.qr_infos.clone(),
        }
    }

    fn apply(engine: &mut MasternodeListEngine, height: CoreBlockHeight, message: Message) -> bool {
        match message {
            Message::QrInfo(qr_info) => engine.feed_qr_info(*qr_info, true, true).is_ok(),
            Message::Diff(diff) => engine.apply_diff(*diff, Some(height), false, None).is_ok(),
        }
    }
}

impl<H: BlockHeaderStorage> MessageLog<H> {
    /// Rebuilds the lists in `floor..=height`. A QRInfo builds lists back to its
    /// `h-4c` work block, so messages stored up to six cycles above `height` can
    /// still produce one of them.
    async fn replay_around(
        &self,
        floor: CoreBlockHeight,
        height: CoreBlockHeight,
    ) -> StorageResult<(MasternodeListEngine, ReplayStats)> {
        let cycle = self.network.isd_llmq_type().params().dkg_params.interval;
        let until = height.saturating_add(cycle.saturating_mul(6)).saturating_add(WORK_DIFF_DEPTH);
        let retain = Retain::Around {
            floor,
            height,
        };
        self.replay(Some(until), retain).await
    }

    /// Rebuilds the engine from the messages stored up to `until`, pruning as it
    /// goes so memory stays bounded by `retain` rather than by history. Messages
    /// apply in the order of their newest base, so each comes after the one that
    /// built the list it extends, and a list outside `retain` survives only while
    /// a message still to be applied builds on it. They are read once to plan
    /// that order and again to apply, so only one is held in memory at a time,
    /// and the header storage is locked per message rather than for the pass.
    async fn replay(
        &self,
        until: Option<CoreBlockHeight>,
        retain: Retain,
    ) -> StorageResult<(MasternodeListEngine, ReplayStats)> {
        let mut engine = MasternodeListEngine::default_for_network(self.network);
        let until = until.unwrap_or(CoreBlockHeight::MAX);

        let entries =
            self.diffs.range(..=until).map(|(height, path)| (*height, Kind::Diff, path)).chain(
                self.qr_infos.range(..=until).map(|(height, path)| (*height, Kind::QrInfo, path)),
            );

        let mut plan = Vec::new();
        let mut needed: HashMap<BlockHash, usize> = HashMap::new();
        for (height, kind, path) in entries {
            let message = match PersistentMasternodeStorage::<H>::read_entry(path, kind).await {
                Ok(message) => message,
                Err(e) => {
                    tracing::warn!("Skipping unreadable masternode message at {height}: {e}");
                    continue;
                }
            };
            let headers = self.headers.read().await;
            match &message {
                Message::QrInfo(qr_info) => {
                    feed_qrinfo_heights_to_engine(&mut engine, qr_info, &*headers).await;
                }
                Message::Diff(diff) => {
                    engine.feed_block_height(height, diff.block_hash);
                    if let Ok(Some(base_height)) =
                        headers.get_header_height_by_hash(&diff.base_block_hash).await
                    {
                        engine.feed_block_height(base_height, diff.base_block_hash);
                    }
                }
            }
            drop(headers);
            let bases = message.base_hashes();
            for base in &bases {
                *needed.entry(*base).or_default() += 1;
            }
            plan.push((height, kind, path, bases));
        }

        let newest_base = |bases: &[BlockHash]| {
            bases.iter().filter_map(|base| engine.block_container.get_height(base)).max()
        };
        plan.sort_by_cached_key(|(height, kind, _, bases)| {
            (newest_base(bases).unwrap_or(*height), *height, *kind)
        });

        let mut stats = ReplayStats {
            total: plan.len(),
            ..ReplayStats::default()
        };
        let replayed_to = plan.iter().map(|(height, ..)| *height).max();
        for (height, kind, path, bases) in plan {
            match PersistentMasternodeStorage::<H>::read_entry(path, kind).await {
                Ok(message) => {
                    match PersistentMasternodeStorage::<H>::apply(&mut engine, height, message) {
                        true => stats.applied += 1,
                        false => tracing::warn!("Masternode message at {height} does not apply"),
                    }
                }
                Err(e) => tracing::warn!("Masternode message at {height} became unreadable: {e}"),
            }
            for base in &bases {
                if let Some(count) = needed.get_mut(base) {
                    *count -= 1;
                    if *count == 0 {
                        needed.remove(base);
                    }
                }
            }

            stats.peak_lists = stats.peak_lists.max(engine.masternode_lists.len());
            prune_unneeded(&mut engine, retain, height, &needed);
        }

        if let (Retain::Obsolete, Some(tip)) = (retain, replayed_to) {
            engine.prune_obsolete_lists(tip, &BTreeSet::new());
        }

        tracing::debug!(
            "Replayed {}/{} masternode messages into {} masternode lists, peak {}",
            stats.applied,
            stats.total,
            engine.masternode_lists.len(),
            stats.peak_lists
        );

        Ok((engine, stats))
    }

    /// The quorum as [`MasternodeListEngine::quorum_entry_for_hash_at_or_before_height`]
    /// would resolve it from the lists stored up to `height`.
    pub async fn quorum_entry_at_or_before(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<QualifiedQuorumEntry>> {
        let floor = MasternodeListEngine::quorum_walk_back_floor(llmq_type, height);
        let (engine, _) = self.replay_around(floor, height).await?;
        Ok(engine
            .quorum_entry_for_hash_at_or_before_height(llmq_type, quorum_hash, height)
            .map(|(_, quorum)| quorum.clone()))
    }
}

fn prune_unneeded(
    engine: &mut MasternodeListEngine,
    retain: Retain,
    replayed_to: CoreBlockHeight,
    needed: &HashMap<BlockHash, usize>,
) {
    let lists = &engine.masternode_lists;
    let keep: Box<dyn Fn(CoreBlockHeight) -> bool> = match retain {
        Retain::Obsolete => {
            let newest = lists.keys().next_back().copied();
            let needed_lists = engine.needed_lists(replayed_to);
            Box::new(move |height| needed_lists.contains(height) || Some(height) == newest)
        }
        Retain::Around {
            floor,
            height,
        } => {
            let below = lists.range(..=height).next_back().map(|(h, _)| *h);
            let above =
                height.checked_add(1).and_then(|h| lists.range(h..).next()).map(|(h, _)| *h);
            Box::new(move |h| (floor..=height).contains(&h) || [below, above].contains(&Some(h)))
        }
    };

    let doomed: Vec<CoreBlockHeight> = lists
        .iter()
        .filter(|(height, list)| !keep(**height) && !needed.contains_key(&list.block_hash))
        .map(|(height, _)| *height)
        .collect();
    for height in doomed {
        engine.masternode_lists.remove(&height);
    }
}

impl Message {
    /// Block hashes of the lists this message is applied on top of. A QRInfo's
    /// diffs chain from its oldest one, which Core sends as an empty diff from
    /// the base to itself, so only bases no other diff of it produces count.
    fn base_hashes(&self) -> Vec<BlockHash> {
        match self {
            Message::Diff(diff) => vec![diff.base_block_hash],
            Message::QrInfo(qr_info) => {
                let diffs = qr_info_diffs(qr_info);
                let produced: HashSet<BlockHash> = diffs
                    .iter()
                    .filter(|d| d.block_hash != d.base_block_hash)
                    .map(|d| d.block_hash)
                    .collect();
                let bases: HashSet<BlockHash> = diffs
                    .iter()
                    .map(|d| d.base_block_hash)
                    .filter(|base| !produced.contains(base))
                    .collect();
                bases.into_iter().collect()
            }
        }
    }
}

#[async_trait]
impl<H: BlockHeaderStorage> MasternodeStorage for PersistentMasternodeStorage<H> {
    async fn store_diff(
        &mut self,
        height: CoreBlockHeight,
        diff: &MnListDiff,
    ) -> StorageResult<()> {
        let folder = self.folder();
        Self::store_message(&folder, &mut self.diffs, Self::DIFF_PREFIX, height, diff).await
    }

    async fn store_qr_info(
        &mut self,
        height: CoreBlockHeight,
        qr_info: &QRInfo,
    ) -> StorageResult<()> {
        let folder = self.folder();
        Self::store_message(&folder, &mut self.qr_infos, Self::QRINFO_PREFIX, height, qr_info).await
    }

    async fn load_engine(&self) -> StorageResult<MasternodeListEngine> {
        Ok(self.message_log().replay(None, Retain::Obsolete).await?.0)
    }

    async fn quorum_entry_at_or_before(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<QualifiedQuorumEntry>> {
        self.message_log().quorum_entry_at_or_before(llmq_type, quorum_hash, height).await
    }
}

/// Feed QRInfo block heights to the engine from storage.
///
/// Resolves heights for every hash enumerated by
/// [`MasternodeListEngine::qr_info_referenced_block_hashes`], plus the cycle boundary
/// block of each [work block](MasternodeListEngine::qr_info_work_block_hashes), which
/// is needed for rotated quorum storage key calculation.
pub(crate) async fn feed_qrinfo_heights_to_engine<S: BlockHeaderStorage>(
    engine: &mut MasternodeListEngine,
    qr_info: &QRInfo,
    storage: &S,
) -> usize {
    let mut fed_count = 0;
    for block_hash in MasternodeListEngine::qr_info_referenced_block_hashes(qr_info) {
        if let Ok(Some(height)) = storage.get_header_height_by_hash(&block_hash).await {
            engine.feed_block_height(height, block_hash);
            fed_count += 1;
            tracing::trace!("Fed height {} for block {}", height, block_hash);
        }
    }

    for work_block_hash in MasternodeListEngine::qr_info_work_block_hashes(qr_info) {
        if let Ok(Some(work_block_height)) =
            storage.get_header_height_by_hash(&work_block_hash).await
        {
            let cycle_boundary_height =
                MasternodeListEngine::cycle_boundary_height(work_block_height);
            if let Ok(Some(cycle_boundary_header)) = storage.get_header(cycle_boundary_height).await
            {
                let cycle_boundary_hash = *cycle_boundary_header.hash();
                engine.feed_block_height(cycle_boundary_height, cycle_boundary_hash);
                fed_count += 1;
                tracing::debug!(
                    "Fed cycle boundary height {} for block {}",
                    cycle_boundary_height,
                    cycle_boundary_hash
                );
            }
        }
    }

    fed_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockHeaderStorage;
    use dashcore_hashes::Hash;

    use tempfile::TempDir;

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_slice(&[byte; 32]).unwrap()
    }

    async fn open_storage(
        dir: &TempDir,
        heights: &[(u8, u32)],
    ) -> PersistentMasternodeStorage<MockHeaderStorage> {
        let map = heights.iter().map(|(b, h)| (hash(*b), *h)).collect();
        PersistentMasternodeStorage::open(
            dir.path(),
            Arc::new(RwLock::new(MockHeaderStorage(map))),
            Network::Regtest,
        )
        .await
        .expect("open")
    }

    #[tokio::test]
    async fn a_reopened_storage_replays_what_was_stored() {
        let dir = TempDir::new().unwrap();
        let heights = [(0x00, 0), (0xAA, 100), (0xBB, 200)];
        {
            let mut storage = open_storage(&dir, &heights).await;
            storage.store_diff(100, &MnListDiff::dummy(0x00, 0xAA)).await.unwrap();
            storage.store_diff(200, &MnListDiff::dummy(0xAA, 0xBB)).await.unwrap();
        }

        let engine = open_storage(&dir, &heights).await.load_engine().await.unwrap();

        assert_eq!(
            engine.masternode_lists.keys().copied().collect::<Vec<_>>(),
            vec![200],
            "the list at 100 is one a live engine at 200 would have pruned"
        );
        assert_eq!(engine.masternode_lists[&200].block_hash, hash(0xBB));
        assert_eq!(engine.masternode_lists[&200].masternodes.len(), 2);
    }

    #[tokio::test]
    async fn replay_skips_an_orphan_and_keeps_going() {
        let dir = TempDir::new().unwrap();
        let mut storage =
            open_storage(&dir, &[(0x00, 0), (0xAA, 100), (0xBB, 150), (0xDD, 120)]).await;

        storage.store_diff(100, &MnListDiff::dummy(0x00, 0xAA)).await.unwrap();
        storage.store_diff(120, &MnListDiff::dummy(0xEE, 0xDD)).await.unwrap();
        storage.store_diff(150, &MnListDiff::dummy(0xAA, 0xBB)).await.unwrap();

        let engine = storage.load_engine().await.expect("replay must not fail on an orphan");

        assert!(
            !engine.masternode_lists.contains_key(&120),
            "the orphan has no base to apply on and is left to the network"
        );
        assert!(engine.masternode_lists.contains_key(&150), "the diff after it still applies");
    }

    #[tokio::test]
    async fn storing_the_same_height_twice_keeps_the_newer_message() {
        let dir = TempDir::new().unwrap();
        let mut storage = open_storage(&dir, &[]).await;

        storage.store_diff(100, &MnListDiff::dummy(0x00, 0xAA)).await.unwrap();
        storage.store_diff(100, &MnListDiff::dummy(0x00, 0xBB)).await.unwrap();

        assert_eq!(storage.diffs.len(), 1, "one file per height");
        let stored: MnListDiff =
            PersistentMasternodeStorage::<MockHeaderStorage>::read_message(&storage.diffs[&100])
                .await
                .expect("read back");
        assert_eq!(stored.block_hash, hash(0xBB), "the second write wins");
    }

    #[tokio::test]
    async fn replay_survives_unreadable_files_and_ignores_foreign_names() {
        let dir = TempDir::new().unwrap();
        let folder = dir.path().join(PersistentMasternodeStorage::<MockHeaderStorage>::FOLDER_NAME);
        tokio::fs::create_dir_all(&folder).await.unwrap();

        {
            let mut storage = open_storage(&dir, &[(0x00, 0), (0xAA, 100)]).await;
            storage.store_diff(100, &MnListDiff::dummy(0x00, 0xAA)).await.unwrap();
        }

        tokio::fs::write(folder.join("diff_50.dat"), b"not a diff").await.unwrap();
        tokio::fs::write(folder.join("diff_abc.dat"), b"x").await.unwrap();

        let storage = open_storage(&dir, &[(0x00, 0), (0xAA, 100)]).await;
        assert_eq!(
            storage.diffs.keys().copied().collect::<Vec<_>>(),
            vec![50, 100],
            "only well-formed names are indexed"
        );
        assert!(storage.qr_infos.is_empty());

        let engine = storage.load_engine().await.expect("a corrupt file must not fail the load");
        assert!(
            engine.masternode_lists.contains_key(&100),
            "the readable message still rebuilds its list"
        );
    }

    fn height_hash(height: u32) -> BlockHash {
        if height == 0 {
            return BlockHash::all_zeros();
        }
        let mut bytes = [0xF0; 32];
        bytes[..4].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_byte_array(bytes)
    }

    fn diff_between(base: u32, tip: u32) -> MnListDiff {
        MnListDiff {
            base_block_hash: height_hash(base),
            block_hash: height_hash(tip),
            ..MnListDiff::dummy(0x00, 0x01)
        }
    }

    /// One diff per height from 1 to `tip`, each on top of the one before.
    async fn chained_storage(
        dir: &TempDir,
        tip: u32,
    ) -> PersistentMasternodeStorage<MockHeaderStorage> {
        let map = (0..=tip + 1).map(|h| (height_hash(h), h)).collect();
        let mut storage = PersistentMasternodeStorage::open(
            dir.path(),
            Arc::new(RwLock::new(MockHeaderStorage(map))),
            Network::Regtest,
        )
        .await
        .unwrap();
        for height in 1..=tip {
            storage.store_diff(height, &diff_between(height - 1, height)).await.unwrap();
        }
        storage
    }

    #[tokio::test]
    async fn startup_replay_prunes_as_it_goes() {
        let dir = TempDir::new().unwrap();
        let tip = 300;
        let storage = chained_storage(&dir, tip).await;

        let (engine, stats) = storage.message_log().replay(None, Retain::Obsolete).await.unwrap();
        let needed_lists = engine.needed_lists(tip);
        let interval = Network::Regtest.isd_llmq_type().params().dkg_params.interval as usize;

        assert_eq!(stats.applied, tip as usize, "every diff applies");
        assert!(
            engine.masternode_lists.keys().all(|height| needed_lists.contains(*height)),
            "nothing a live engine at the tip would drop: {:?} kept for {needed_lists:?}",
            engine.masternode_lists.keys().collect::<Vec<_>>()
        );
        assert!(
            stats.peak_lists <= interval + 3,
            "memory is bounded by the last cycle during the replay, not only after it: \
             peak {} lists for a cycle of {interval}",
            stats.peak_lists
        );
    }

    #[tokio::test]
    async fn startup_replay_keeps_an_old_list_a_later_message_builds_on() {
        let dir = TempDir::new().unwrap();
        let tip = 300;
        let mut storage = chained_storage(&dir, tip).await;
        storage.store_diff(tip + 1, &diff_between(10, tip + 1)).await.unwrap();

        let (engine, stats) = storage.message_log().replay(None, Retain::Obsolete).await.unwrap();

        assert_eq!(
            stats.applied,
            tip as usize + 1,
            "the diff anchored far below the floor applies"
        );
        assert!(engine.masternode_lists.contains_key(&(tip + 1)));
        assert!(
            !engine.masternode_lists.contains_key(&10),
            "once its last dependant has applied the anchor is released"
        );
    }

    #[tokio::test]
    async fn bounded_replay_stops_within_reach_and_keeps_only_what_it_needs() {
        let dir = TempDir::new().unwrap();
        let storage = chained_storage(&dir, 400).await;
        let until = 150 + 6 * 24 + 8;

        let (engine, stats) = storage.message_log().replay_around(150, 150).await.unwrap();

        assert_eq!(stats.total, until as usize, "messages past the reach are not read");
        assert_eq!(
            engine.masternode_lists.keys().copied().collect::<Vec<_>>(),
            vec![150, 151],
            "the list at the height and the nearest one above it"
        );
        assert!(
            stats.peak_lists <= 4,
            "a chained replay only ever holds those two plus the base and the list built on it, \
             peak {}",
            stats.peak_lists
        );
    }

    #[tokio::test]
    async fn quorum_lookup_rebuilds_a_list_the_live_engine_pruned() {
        use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
        use dashcore::hash_types::QuorumVVecHash;
        use dashcore::sml::llmq_type::network::NetworkLLMQExt;
        use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;

        let dir = TempDir::new().unwrap();
        let tip = 300;
        let mut storage = chained_storage(&dir, tip).await;

        let llmq_type = Network::Regtest.platform_type();
        let quorum_hash = QuorumHash::from_byte_array([0xAB; 32]);
        let mut with_quorum = diff_between(0, 1);
        with_quorum.new_quorums.push(QuorumEntry {
            version: 1,
            llmq_type,
            quorum_hash,
            quorum_index: None,
            signers: vec![true; 3],
            valid_members: vec![true; 3],
            quorum_public_key: BLSPublicKey::from([7; 48]),
            quorum_vvec_hash: QuorumVVecHash::all_zeros(),
            threshold_sig: BLSSignature::from([1; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([1; 96]),
        });
        with_quorum.quorums_chainlock_signatures.push(
            dashcore::network::message_sml::QuorumCLSigObject {
                signature: BLSSignature::from([1; 96]),
                index_set: vec![0],
            },
        );
        storage.store_diff(1, &with_quorum).await.unwrap();
        let mut retiring = diff_between(1, 2);
        retiring.deleted_quorums.push(dashcore::network::message_sml::DeletedQuorum {
            llmq_type,
            quorum_hash,
        });
        storage.store_diff(2, &retiring).await.unwrap();

        let engine = storage.load_engine().await.unwrap();
        assert!(
            engine.quorum_entry_for_hash_at_or_before_height(llmq_type, quorum_hash, tip).is_none(),
            "the engine a restart loads has pruned the only list holding the quorum"
        );

        let quorum = storage
            .quorum_entry_at_or_before(llmq_type, quorum_hash, tip)
            .await
            .unwrap()
            .expect("storage rebuilds the list the walk-back reaches");
        assert_eq!(quorum.quorum_entry.quorum_hash, quorum_hash);
    }

    /// Mainnet-shaped history: the real full list at 2_227_096 (≈3300 masternodes)
    /// followed by `blocks` incremental diffs, one per block, as the live
    /// Incremental pipeline stores them. Files are written without fsync to keep
    /// setup fast; the replay path reads them exactly as it would in production.
    async fn mainnet_history(
        dir: &TempDir,
        blocks: u32,
    ) -> (PersistentMasternodeStorage<MockHeaderStorage>, CoreBlockHeight) {
        type S = PersistentMasternodeStorage<MockHeaderStorage>;
        let full: MnListDiff = deserialize(include_bytes!(
            "../../../dash/tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin"
        ))
        .unwrap();
        let base = 2_227_096;
        let folder = dir.path().join(S::FOLDER_NAME);
        std::fs::create_dir_all(&folder).unwrap();
        let mut map: HashMap<BlockHash, u32> = HashMap::new();
        map.insert(full.block_hash, base);
        std::fs::write(folder.join(S::file_name(S::DIFF_PREFIX, base)), serialize(&full)).unwrap();
        let mut prev = full.block_hash;
        for height in base + 1..=base + blocks {
            let hash = height_hash(height);
            map.insert(hash, height);
            let diff = MnListDiff {
                base_block_hash: prev,
                block_hash: hash,
                new_masternodes: vec![],
                ..MnListDiff::dummy(0x00, 0x01)
            };
            std::fs::write(folder.join(S::file_name(S::DIFF_PREFIX, height)), serialize(&diff))
                .unwrap();
            prev = hash;
        }
        let storage = PersistentMasternodeStorage::open(
            dir.path(),
            Arc::new(RwLock::new(MockHeaderStorage(map))),
            Network::Mainnet,
        )
        .await
        .unwrap();
        (storage, base + blocks)
    }

    /// A lookup replays from a [`MessageLog`] taken under the storage lock and
    /// released before the replay, so the next message the masternode sync
    /// stores does not wait for the replay to finish.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_storage_lookup_does_not_hold_up_storing_the_next_message() {
        let dir = TempDir::new().unwrap();
        let (storage, tip) = mainnet_history(&dir, 576).await;
        let storage = Arc::new(RwLock::new(storage));

        let log = storage.read().await.message_log();
        let lookup = tokio::spawn(async move {
            log.quorum_entry_at_or_before(
                LLMQType::Llmqtype100_67,
                QuorumHash::from_byte_array([0x42; 32]),
                tip,
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let next = MnListDiff {
            base_block_hash: height_hash(tip),
            block_hash: height_hash(tip + 1),
            ..MnListDiff::dummy(0x00, 0x01)
        };
        storage.write().await.store_diff(tip + 1, &next).await.unwrap();

        assert!(
            !lookup.is_finished(),
            "the next diff was only stored once the lookup's replay had finished"
        );
        assert!(lookup.await.unwrap().unwrap().is_none());
    }

    /// Header storage whose hash lookups take a while, as a disk-backed one can.
    struct SlowHeaderStorage(MockHeaderStorage);

    #[async_trait]
    impl BlockHeaderStorage for SlowHeaderStorage {
        async fn store_headers(
            &mut self,
            headers: &[crate::types::HashedBlockHeader],
        ) -> StorageResult<()> {
            self.0.store_headers(headers).await
        }
        async fn store_headers_at_height(
            &mut self,
            headers: &[crate::types::HashedBlockHeader],
            height: u32,
        ) -> StorageResult<()> {
            self.0.store_headers_at_height(headers, height).await
        }
        async fn load_headers(
            &self,
            range: std::ops::Range<u32>,
        ) -> StorageResult<Vec<crate::types::HashedBlockHeader>> {
            self.0.load_headers(range).await
        }
        async fn get_tip_height(&self) -> Option<u32> {
            self.0.get_tip_height().await
        }
        async fn get_tip(&self) -> Option<crate::storage::BlockHeaderTip> {
            self.0.get_tip().await
        }
        async fn get_start_height(&self) -> Option<u32> {
            self.0.get_start_height().await
        }
        async fn get_stored_headers_len(&self) -> u32 {
            self.0.get_stored_headers_len().await
        }
        async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            self.0.get_header_height_by_hash(hash).await
        }
        async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
            self.0.truncate_above(target_height).await
        }
    }

    /// Planning a replay resolves every message's heights against the header
    /// storage. It locks that storage per message, so a header write lands
    /// between two messages instead of after the whole pass.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replay_does_not_hold_the_header_storage_for_the_whole_pass() {
        type S = PersistentMasternodeStorage<SlowHeaderStorage>;
        let dir = TempDir::new().unwrap();
        let tip = 300;
        let folder = dir.path().join(S::FOLDER_NAME);
        std::fs::create_dir_all(&folder).unwrap();
        for height in 1..=tip {
            std::fs::write(
                folder.join(S::file_name(S::DIFF_PREFIX, height)),
                serialize(&diff_between(height - 1, height)),
            )
            .unwrap();
        }
        let map = (0..=tip).map(|h| (height_hash(h), h)).collect();
        let headers = Arc::new(RwLock::new(SlowHeaderStorage(MockHeaderStorage(map))));
        let storage = S::open(dir.path(), Arc::clone(&headers), Network::Regtest).await.unwrap();

        let log = storage.message_log();
        let replay = tokio::spawn(async move { log.replay(None, Retain::Obsolete).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let start = std::time::Instant::now();
        drop(headers.write().await);
        let waited = start.elapsed();

        assert!(!replay.is_finished(), "the replay has to still be planning for this to test it");
        replay.await.unwrap().unwrap();
        assert!(
            waited < std::time::Duration::from_millis(500),
            "a header write waited {waited:?} behind a replay's planning pass"
        );
    }

    #[test]
    fn qr_info_bases_are_what_its_chain_starts_from() {
        let mut qr_info = QRInfo::dummy(0x00);
        qr_info.mn_list_diff_at_h_minus_3c = MnListDiff::dummy_empty(0xA0, 0xA0);
        qr_info.mn_list_diff_at_h_minus_2c = MnListDiff::dummy_empty(0xA0, 0xB0);
        qr_info.mn_list_diff_at_h_minus_c = MnListDiff::dummy_empty(0xB0, 0xC0);
        qr_info.mn_list_diff_h = MnListDiff::dummy_empty(0xC0, 0xD0);
        qr_info.mn_list_diff_tip = MnListDiff::dummy_empty(0xD0, 0xE0);

        assert_eq!(
            Message::QrInfo(Box::new(qr_info)).base_hashes(),
            vec![hash(0xA0)],
            "the empty diff at the start of the chain needs its list to exist already"
        );
    }
}
