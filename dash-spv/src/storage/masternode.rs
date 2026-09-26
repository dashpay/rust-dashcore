use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use dashcore::consensus::{deserialize, serialize, Decodable, Encodable};
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::masternode_list_engine::{qr_info_diffs, MasternodeListEngine};
use dashcore::{BlockHash, Network};

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
}

pub struct PersistentMasternodeStorage<H: BlockHeaderStorage> {
    storage_path: PathBuf,
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

    /// Rebuilds the engine from every stored message. Messages apply in the
    /// order of their newest base, so each comes after the one that built the
    /// list it extends. They are read once to plan that order and again to
    /// apply, so only one is held in memory at a time.
    async fn replay(&self) -> StorageResult<MasternodeListEngine> {
        let mut engine = MasternodeListEngine::default_for_network(self.network);

        let entries = self
            .diffs
            .iter()
            .map(|(height, path)| (*height, Kind::Diff, path))
            .chain(self.qr_infos.iter().map(|(height, path)| (*height, Kind::QrInfo, path)));

        let mut plan = Vec::new();
        {
            let headers = self.headers.read().await;
            for (height, kind, path) in entries {
                let message = match Self::read_entry(path, kind).await {
                    Ok(message) => message,
                    Err(e) => {
                        tracing::warn!("Skipping unreadable masternode message at {height}: {e}");
                        continue;
                    }
                };
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
                plan.push((height, kind, path, message.base_hashes()));
            }
        }

        let newest_base = |bases: &[BlockHash]| {
            bases.iter().filter_map(|base| engine.block_container.get_height(base)).max()
        };
        plan.sort_by_cached_key(|(height, kind, _, bases)| {
            (newest_base(bases).unwrap_or(*height), *height, *kind)
        });

        let total = plan.len();
        let mut applied = 0;
        for (height, kind, path, _) in plan {
            match Self::read_entry(path, kind).await {
                Ok(message) => match Self::apply(&mut engine, height, message) {
                    true => applied += 1,
                    false => tracing::warn!("Masternode message at {height} does not apply"),
                },
                Err(e) => tracing::warn!("Masternode message at {height} became unreadable: {e}"),
            }
        }

        tracing::debug!(
            "Replayed {applied}/{total} masternode messages into {} masternode lists",
            engine.masternode_lists.len()
        );

        Ok(engine)
    }

    fn apply(engine: &mut MasternodeListEngine, height: CoreBlockHeight, message: Message) -> bool {
        match message {
            Message::QrInfo(qr_info) => engine.feed_qr_info(*qr_info, true, true).is_ok(),
            Message::Diff(diff) => engine.apply_diff(*diff, Some(height), false, None).is_ok(),
        }
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
        self.replay().await
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

        assert_eq!(engine.masternode_lists.keys().copied().collect::<Vec<_>>(), vec![100, 200]);
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
