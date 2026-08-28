use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use dashcore::bls_sig_utils::BLSPublicKey;
use dashcore::consensus::{deserialize, serialize, Decodable, Encodable};
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::{
    MasternodeListEngine, MasternodeListEngineBlockContainer,
};
use dashcore::{Network, QuorumHash};

use crate::error::{StorageError, StorageResult};
use crate::storage::{io::atomic_write, PersistentStorage};

type QuorumStatuses = BTreeMap<
    LLMQType,
    BTreeMap<QuorumHash, (BTreeSet<CoreBlockHeight>, BLSPublicKey, LLMQEntryVerificationStatus)>,
>;

type EngineContext = (MasternodeListEngineBlockContainer, QuorumStatuses);

#[async_trait]
pub trait MasternodeStorage: Send + Sync + 'static {
    async fn store_diff(&mut self, height: CoreBlockHeight, diff: &MnListDiff)
        -> StorageResult<()>;

    async fn store_qr_info(
        &mut self,
        height: CoreBlockHeight,
        qr_info: &QRInfo,
    ) -> StorageResult<()>;

    async fn store_context(&mut self, engine: &MasternodeListEngine) -> StorageResult<()>;

    async fn load_engine(&self, network: Network) -> StorageResult<MasternodeListEngine>;

    async fn masternode_list_at_or_before(
        &self,
        network: Network,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<MasternodeList>>;
}

pub struct PersistentMasternodeStorage {
    storage_path: PathBuf,
    diffs: BTreeMap<CoreBlockHeight, PathBuf>,
    qr_infos: BTreeMap<CoreBlockHeight, PathBuf>,
}

impl PersistentMasternodeStorage {
    const FOLDER_NAME: &str = "masternodes";
    const DIFF_PREFIX: &str = "diff_";
    const QRINFO_PREFIX: &str = "qrinfo_";
    const EXTENSION: &str = "dat";
    const CONTEXT_FILE_NAME: &str = "context.dat";

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

    async fn write_message<T: Encodable>(
        &mut self,
        prefix: &str,
        height: CoreBlockHeight,
        message: &T,
    ) -> StorageResult<PathBuf> {
        let folder = self.folder();
        tokio::fs::create_dir_all(&folder).await?;
        let path = folder.join(Self::file_name(prefix, height));
        atomic_write(&path, &serialize(message)).await?;
        Ok(path)
    }

    async fn read_message<T: Decodable>(path: &Path) -> StorageResult<T> {
        let bytes = tokio::fs::read(path).await?;
        deserialize(&bytes).map_err(|e| {
            StorageError::Corruption(format!("Failed to decode {}: {e}", path.display()))
        })
    }

    async fn load_context(&self) -> StorageResult<Option<EngineContext>> {
        let path = self.folder().join(Self::CONTEXT_FILE_NAME);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = tokio::fs::read(&path).await?;
        let (context, _) = bincode::decode_from_slice(&bytes, bincode::config::standard())
            .map_err(|e| {
                StorageError::Corruption(format!("Failed to decode masternode context: {e}"))
            })?;
        Ok(Some(context))
    }

    async fn replay(&self, network: Network) -> StorageResult<MasternodeListEngine> {
        let mut engine = MasternodeListEngine::default_for_network(network);

        if let Some((block_container, quorum_statuses)) = self.load_context().await? {
            engine.block_container = block_container;
            engine.quorum_statuses = quorum_statuses;
        }

        let mut pending_qr_infos = Vec::new();
        for (height, path) in &self.qr_infos {
            match Self::read_message::<QRInfo>(path).await {
                Ok(qr_info) => pending_qr_infos.push((*height, qr_info)),
                Err(e) => tracing::warn!("Skipping unreadable QRInfo at {height}: {e}"),
            }
        }

        let mut pending_diffs = Vec::new();
        for (height, path) in &self.diffs {
            match Self::read_message::<MnListDiff>(path).await {
                Ok(diff) => pending_diffs.push((*height, diff)),
                Err(e) => tracing::warn!("Skipping unreadable MnListDiff at {height}: {e}"),
            }
        }

        let qr_info_count = pending_qr_infos.len();
        let diff_count = pending_diffs.len();

        loop {
            let remaining = pending_qr_infos.len() + pending_diffs.len();

            pending_qr_infos
                .retain(|(_, qr_info)| engine.feed_qr_info(qr_info.clone(), true, true).is_err());

            pending_diffs.retain(|(height, diff)| {
                engine.feed_block_height(*height, diff.block_hash);
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

type IndexMap = BTreeMap<CoreBlockHeight, PathBuf>;

#[async_trait]
impl PersistentStorage for PersistentMasternodeStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let (diffs, qr_infos) = Self::index_folder(&storage_path.join(Self::FOLDER_NAME)).await?;

        Ok(PersistentMasternodeStorage {
            storage_path,
            diffs,
            qr_infos,
        })
    }

    async fn persist(&mut self, _storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        Ok(())
    }
}

#[async_trait]
impl MasternodeStorage for PersistentMasternodeStorage {
    async fn store_diff(
        &mut self,
        height: CoreBlockHeight,
        diff: &MnListDiff,
    ) -> StorageResult<()> {
        if self.diffs.contains_key(&height) {
            return Ok(());
        }
        let path = self.write_message(Self::DIFF_PREFIX, height, diff).await?;
        self.diffs.insert(height, path);
        Ok(())
    }

    async fn store_qr_info(
        &mut self,
        height: CoreBlockHeight,
        qr_info: &QRInfo,
    ) -> StorageResult<()> {
        if self.qr_infos.contains_key(&height) {
            return Ok(());
        }
        let path = self.write_message(Self::QRINFO_PREFIX, height, qr_info).await?;
        self.qr_infos.insert(height, path);
        Ok(())
    }

    async fn store_context(&mut self, engine: &MasternodeListEngine) -> StorageResult<()> {
        let folder = self.folder();
        tokio::fs::create_dir_all(&folder).await?;

        let bytes = bincode::encode_to_vec(
            (&engine.block_container, &engine.quorum_statuses),
            bincode::config::standard(),
        )
        .map_err(|e| {
            StorageError::Serialization(format!("Failed to encode masternode context: {e}"))
        })?;

        atomic_write(&folder.join(Self::CONTEXT_FILE_NAME), &bytes).await
    }

    async fn load_engine(&self, network: Network) -> StorageResult<MasternodeListEngine> {
        self.replay(network).await
    }

    async fn masternode_list_at_or_before(
        &self,
        network: Network,
        height: CoreBlockHeight,
    ) -> StorageResult<Option<MasternodeList>> {
        let engine = self.replay(network).await?;
        Ok(engine.masternode_lists_around_height(height).0.cloned())
    }
}
