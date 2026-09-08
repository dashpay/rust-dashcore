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
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::Network;

use crate::error::{StorageError, StorageResult};
use crate::storage::{io::atomic_write, BlockHeaderStorage};

type IndexMap = BTreeMap<CoreBlockHeight, PathBuf>;

enum Pending {
    Diff(Box<MnListDiff>),
    QrInfo(Box<QRInfo>),
}

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

    async fn load_engine(&self) -> StorageResult<MasternodeListEngine>;

    async fn masternode_list_at_or_before(
        &self,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<MasternodeList>>;
}

pub struct PersistentMasternodeStorage<H: BlockHeaderStorage> {
    storage_path: PathBuf,
    headers: Arc<RwLock<H>>,
    network: Network,
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

    async fn cached_list_at(&self, height: CoreBlockHeight) -> Option<Option<MasternodeList>> {
        let cached = self.cached_list.lock().await;
        let cached = cached.as_ref()?;
        (height >= cached.from && cached.until.is_none_or(|until| height < until))
            .then(|| cached.list.clone())
    }

    fn invalidate_cached_list(&mut self) {
        *self.cached_list.get_mut() = None;
    }

    async fn replay(&self) -> StorageResult<MasternodeListEngine> {
        let mut engine = MasternodeListEngine::default_for_network(self.network);

        let mut ordered: Vec<(CoreBlockHeight, &PathBuf, bool)> = self
            .qr_infos
            .iter()
            .map(|(height, path)| (*height, path, true))
            .chain(self.diffs.iter().map(|(height, path)| (*height, path, false)))
            .collect();
        ordered.sort_by_key(|(height, _, is_qr_info)| (*height, *is_qr_info));

        let mut queue: Vec<(CoreBlockHeight, Pending)> = Vec::with_capacity(ordered.len());
        {
            let headers = self.headers.read().await;
            for (height, path, is_qr_info) in ordered {
                if is_qr_info {
                    match Self::read_message::<QRInfo>(path).await {
                        Ok(qr_info) => {
                            feed_qrinfo_heights_to_engine(&mut engine, &qr_info, &*headers).await;
                            queue.push((height, Pending::QrInfo(Box::new(qr_info))));
                        }
                        Err(e) => tracing::warn!("Skipping unreadable QRInfo at {height}: {e}"),
                    }
                } else {
                    match Self::read_message::<MnListDiff>(path).await {
                        Ok(diff) => {
                            engine.feed_block_height(height, diff.block_hash);
                            if let Ok(Some(base_height)) =
                                headers.get_header_height_by_hash(&diff.base_block_hash).await
                            {
                                engine.feed_block_height(base_height, diff.base_block_hash);
                            }
                            queue.push((height, Pending::Diff(Box::new(diff))));
                        }
                        Err(e) => tracing::warn!("Skipping unreadable MnListDiff at {height}: {e}"),
                    }
                }
            }
        }

        let total = queue.len();
        let mut pending = Vec::new();
        for (height, message) in queue {
            if let Some(unapplied) = Self::apply(&mut engine, height, message) {
                pending.push((height, unapplied));
            }
        }

        while !pending.is_empty() {
            let remaining = pending.len();
            let mut still_pending = Vec::with_capacity(remaining);
            for (height, message) in pending {
                if let Some(unapplied) = Self::apply(&mut engine, height, message) {
                    still_pending.push((height, unapplied));
                }
            }
            pending = still_pending;
            if pending.len() == remaining {
                break;
            }
        }

        for (height, _) in &pending {
            tracing::warn!("Message at {height} has no reachable base, leaving it to the network");
        }

        tracing::debug!(
            "Replayed {}/{} masternode messages into {} masternode lists",
            total - pending.len(),
            total,
            engine.masternode_lists.len()
        );

        Ok(engine)
    }

    fn apply(
        engine: &mut MasternodeListEngine,
        height: CoreBlockHeight,
        message: Pending,
    ) -> Option<Pending> {
        match message {
            Pending::QrInfo(qr_info) => engine
                .feed_qr_info((*qr_info).clone(), true, true)
                .is_err()
                .then_some(Pending::QrInfo(qr_info)),
            Pending::Diff(diff) => engine
                .apply_diff((*diff).clone(), Some(height), false, None)
                .is_err()
                .then_some(Pending::Diff(diff)),
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

    async fn load_engine(&self) -> StorageResult<MasternodeListEngine> {
        self.replay().await
    }

    async fn masternode_list_at_or_before(
        &self,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<MasternodeList>> {
        if let Some(hit) = self.cached_list_at(height).await {
            return Ok(hit);
        }

        let engine = self.replay().await?;
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

    tracing::info!("Fed {} block heights to engine", fed_count);
}
