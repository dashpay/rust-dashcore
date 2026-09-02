use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};

use dashcore::consensus::{deserialize, serialize, Decodable, Encodable};
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::{MasternodeListEngine, WORK_DIFF_DEPTH};
use dashcore::Network;

use crate::error::{StorageError, StorageResult};
use crate::storage::{io::atomic_write, BlockHeaderStorage};

type IndexMap = BTreeMap<CoreBlockHeight, PathBuf>;

struct CachedList {
    from: CoreBlockHeight,
    until: Option<CoreBlockHeight>,
    list: Option<MasternodeList>,
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

    async fn load_engine(&self, network: Network) -> StorageResult<MasternodeListEngine>;

    async fn masternode_list_at_or_before(
        &self,
        network: Network,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<MasternodeList>>;
}

pub struct PersistentMasternodeStorage<H: BlockHeaderStorage> {
    storage_path: PathBuf,
    headers: Arc<RwLock<H>>,
    diffs: IndexMap,
    qr_infos: IndexMap,
    cached_list: Mutex<Option<CachedList>>,
}

impl<H: BlockHeaderStorage> PersistentMasternodeStorage<H> {
    const FOLDER_NAME: &str = "masternodes";
    const DIFF_PREFIX: &str = "diff_";
    const QRINFO_PREFIX: &str = "qrinfo_";
    const EXTENSION: &str = "dat";

    pub async fn open(
        storage_path: impl Into<PathBuf> + Send,
        headers: Arc<RwLock<H>>,
    ) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let (diffs, qr_infos) = Self::index_folder(&storage_path.join(Self::FOLDER_NAME)).await?;

        Ok(PersistentMasternodeStorage {
            storage_path,
            headers,
            diffs,
            qr_infos,
            cached_list: Mutex::new(None),
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
        if index.contains_key(&height) {
            return Ok(());
        }
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

    async fn load_pending<T: Decodable>(
        index: &IndexMap,
        label: &str,
    ) -> Vec<(CoreBlockHeight, T)> {
        let mut pending = Vec::new();
        for (height, path) in index {
            match Self::read_message::<T>(path).await {
                Ok(message) => pending.push((*height, message)),
                Err(e) => tracing::warn!("Skipping unreadable {label} at {height}: {e}"),
            }
        }
        pending
    }

    async fn cached_list_at(&self, height: CoreBlockHeight) -> Option<Option<MasternodeList>> {
        let cached = self.cached_list.lock().await;
        let cached = cached.as_ref()?;
        (height >= cached.from && cached.until.is_none_or(|until| height < until))
            .then(|| cached.list.clone())
    }

    fn invalidate_cached_list(&mut self) {
        *self.cached_list.get_mut() = None;
    }

    async fn replay(&self, network: Network) -> StorageResult<MasternodeListEngine> {
        let mut engine = MasternodeListEngine::default_for_network(network);

        let mut pending_qr_infos: Vec<(CoreBlockHeight, QRInfo)> =
            Self::load_pending(&self.qr_infos, "QRInfo").await;
        let mut pending_diffs: Vec<(CoreBlockHeight, MnListDiff)> =
            Self::load_pending(&self.diffs, "MnListDiff").await;

        {
            let headers = self.headers.read().await;
            for (_, qr_info) in &pending_qr_infos {
                feed_qrinfo_heights_to_engine(&mut engine, qr_info, &*headers).await;
            }
            for (height, diff) in &pending_diffs {
                engine.feed_block_height(*height, diff.block_hash);
                if let Ok(Some(base_height)) =
                    headers.get_header_height_by_hash(&diff.base_block_hash).await
                {
                    engine.feed_block_height(base_height, diff.base_block_hash);
                }
            }
        }

        let qr_info_count = pending_qr_infos.len();
        let diff_count = pending_diffs.len();

        loop {
            let remaining = pending_qr_infos.len() + pending_diffs.len();

            pending_qr_infos
                .retain(|(_, qr_info)| engine.feed_qr_info(qr_info.clone(), true, true).is_err());

            pending_diffs.retain(|(height, diff)| {
                engine.apply_diff(diff.clone(), Some(*height), false, None).is_err()
            });

            if pending_qr_infos.len() + pending_diffs.len() == remaining {
                break;
            }
        }

        for (height, _) in &pending_qr_infos {
            tracing::warn!("QRInfo at {height} has no reachable base, leaving it to the network");
        }

        for (height, _) in &pending_diffs {
            tracing::warn!(
                "MnListDiff at {height} has no reachable base, leaving it to the network"
            );
        }

        tracing::debug!(
            "Replayed {}/{} QRInfo and {}/{} MnListDiff messages into {} masternode lists",
            qr_info_count - pending_qr_infos.len(),
            qr_info_count,
            diff_count - pending_diffs.len(),
            diff_count,
            engine.masternode_lists.len()
        );

        Ok(engine)
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
        self.invalidate_cached_list();
        Self::store_message(&folder, &mut self.diffs, Self::DIFF_PREFIX, height, diff).await
    }

    async fn store_qr_info(
        &mut self,
        height: CoreBlockHeight,
        qr_info: &QRInfo,
    ) -> StorageResult<()> {
        let folder = self.folder();
        self.invalidate_cached_list();
        Self::store_message(&folder, &mut self.qr_infos, Self::QRINFO_PREFIX, height, qr_info).await
    }

    async fn load_engine(&self, network: Network) -> StorageResult<MasternodeListEngine> {
        self.replay(network).await
    }

    async fn masternode_list_at_or_before(
        &self,
        network: Network,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<MasternodeList>> {
        if let Some(hit) = self.cached_list_at(height).await {
            return Ok(hit);
        }

        let engine = self.replay(network).await?;
        let (before, after) = engine.masternode_lists_around_height(height);
        let list = before.cloned();

        *self.cached_list.lock().await = Some(CachedList {
            from: before.map_or(0, |list| list.known_height),
            until: after.map(|next| next.known_height),
            list: list.clone(),
        });

        Ok(list)
    }
}

/// Feed QRInfo block heights to the engine from the header storage.
///
/// Resolves heights for every hash enumerated by
/// [`MasternodeListEngine::qr_info_referenced_block_hashes`], plus the cycle boundary
/// block for each work-block diff (`work_height + WORK_DIFF_DEPTH`), which is needed
/// for rotated quorum storage key calculation.
pub(crate) async fn feed_qrinfo_heights_to_engine<S: BlockHeaderStorage>(
    engine: &mut MasternodeListEngine,
    qr_info: &QRInfo,
    storage: &S,
) {
    let mut fed_count = 0;
    for block_hash in MasternodeListEngine::qr_info_referenced_block_hashes(qr_info) {
        if let Ok(Some(height)) = storage.get_header_height_by_hash(&block_hash).await {
            engine.feed_block_height(height, block_hash);
            fed_count += 1;
            tracing::trace!("Fed height {} for block {}", height, block_hash);
        }
    }

    // Feed cycle boundary heights for all diffs (current and historical cycles).
    // Each diff's block_hash is at the "work block" height; the cycle boundary is
    // WORK_DIFF_DEPTH higher.
    let mut work_block_hashes = vec![
        qr_info.mn_list_diff_h.block_hash,
        qr_info.mn_list_diff_at_h_minus_c.block_hash,
        qr_info.mn_list_diff_at_h_minus_2c.block_hash,
        qr_info.mn_list_diff_at_h_minus_3c.block_hash,
    ];

    if let Some((_, diff)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
        work_block_hashes.push(diff.block_hash);
    }

    for work_block_hash in work_block_hashes {
        if let Ok(Some(work_block_height)) =
            storage.get_header_height_by_hash(&work_block_hash).await
        {
            let cycle_boundary_height = work_block_height + WORK_DIFF_DEPTH;
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

    tracing::info!("Fed {} block heights to engine", fed_count);
}
