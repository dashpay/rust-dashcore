use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::sml_engine::{qr_info_diffs, MasternodeListEngine, WORK_DIFF_DEPTH};
use dashcore::consensus::{deserialize, serialize, Decodable, Encodable};
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::LLMQType;
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

#[async_trait]
pub trait MasternodeStorage: Send + Sync + 'static {
    async fn store_diff(&mut self, height: CoreBlockHeight, diff: &MnListDiff)
        -> StorageResult<()>;

    async fn store_qr_info(
        &mut self,
        height: CoreBlockHeight,
        qr_info: &QRInfo,
    ) -> StorageResult<()>;

    /// Drops the messages stored above `height`.
    async fn truncate_above(&mut self, height: CoreBlockHeight) -> StorageResult<()>;
}

pub struct PersistentMasternodeStorage<H: BlockHeaderStorage> {
    storage_path: PathBuf,
    headers: Arc<RwLock<H>>,
    network: Network,
    diffs: IndexMap,
    qr_infos: IndexMap,
}

/// The stored messages as of when it was taken. A replay runs on this, so the
/// caller can release the storage lock before it starts.
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

    pub(crate) async fn load_engine(&self) -> MasternodeListEngine<H> {
        self.message_log().replay(CoreBlockHeight::MAX, |_| {}).await
    }
}

impl<H: BlockHeaderStorage> MessageLog<H> {
    /// Rebuilds the engine from the messages stored up to `until`, calling
    /// `visit` after each one. Messages apply in the order of their newest
    /// base, so each comes after the one that built the list it extends. They
    /// are read once to plan that order and again to apply, so only one is held
    /// in memory at a time, and the header storage is locked per message.
    async fn replay(
        &self,
        until: CoreBlockHeight,
        mut visit: impl FnMut(&MasternodeListEngine<H>),
    ) -> MasternodeListEngine<H> {
        let mut engine = MasternodeListEngine::new(self.network, Arc::clone(&self.headers));

        let entries =
            self.diffs.range(..=until).map(|(height, path)| (*height, Kind::Diff, path)).chain(
                self.qr_infos.range(..=until).map(|(height, path)| (*height, Kind::QrInfo, path)),
            );

        let mut plan = Vec::new();
        for (height, kind, path) in entries {
            let Some(message) = self.read_entry(height, kind, path).await else {
                continue;
            };
            let mut newest_base = None;
            for base in message.base_hashes() {
                newest_base = newest_base.max(engine.height_if_known(&base).await);
            }
            plan.push((newest_base.unwrap_or(height), height, kind, path));
        }
        plan.sort_by_key(|(newest_base, height, kind, _)| (*newest_base, *height, *kind));

        let total = plan.len();
        let mut applied = 0;
        for (_, height, kind, path) in plan {
            if let Some(message) = self.read_entry(height, kind, path).await {
                match message.apply(&mut engine).await {
                    Ok(()) => applied += 1,
                    Err(e) => tracing::warn!("Masternode message at {height} does not apply: {e}"),
                }
            }
            visit(&engine);
        }

        tracing::debug!(
            "Replayed {applied}/{total} masternode messages into {} masternode lists",
            engine.masternode_lists.len()
        );

        engine
    }

    /// Reads the message stored at `height` while its block is still in the
    /// header chain there, or logs why it is skipped.
    async fn read_entry(
        &self,
        height: CoreBlockHeight,
        kind: Kind,
        path: &Path,
    ) -> Option<Message> {
        let message = match PersistentMasternodeStorage::<H>::read_entry(path, kind).await {
            Ok(message) => message,
            Err(e) => {
                tracing::warn!("Skipping unreadable masternode message at {height}: {e}");
                return None;
            }
        };
        let block_hash = message.block_hash();
        let stored_height =
            self.headers.read().await.get_header_height_by_hash(&block_hash).await.ok().flatten();
        if stored_height != Some(height) {
            tracing::warn!(
                "Skipping masternode message at {height}: {block_hash} is no longer in the \
                 header chain"
            );
            return None;
        }
        Some(message)
    }

    /// The quorum as the engine would have resolved it at `height` before its
    /// retention window dropped the lists holding it. A QRInfo builds lists
    /// back to its h-4c work block, so messages stored up to six rotation
    /// cycles above `height` still count.
    pub async fn quorum_entry_at_or_before(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        height: CoreBlockHeight,
    ) -> Option<QualifiedQuorumEntry> {
        let cycle = self.network.isd_llmq_type().params().dkg_params.interval;
        let until = height.saturating_add(cycle.saturating_mul(6)).saturating_add(WORK_DIFF_DEPTH);
        let mut found: Option<(CoreBlockHeight, QualifiedQuorumEntry)> = None;
        self.replay(until, |engine| {
            let hit =
                engine.quorum_entry_for_hash_at_or_before_height(llmq_type, quorum_hash, height);
            if let Some((list_height, quorum)) = hit {
                if found.as_ref().is_none_or(|(best, _)| list_height >= *best) {
                    found = Some((list_height, quorum.clone()));
                }
            }
        })
        .await;
        found.map(|(_, quorum)| quorum)
    }
}

impl Message {
    /// Feeds the message to `engine`, failing with why it was not taken.
    async fn apply<H: BlockHeaderStorage>(
        self,
        engine: &mut MasternodeListEngine<H>,
    ) -> Result<(), String> {
        match self {
            Message::QrInfo(qr_info) => {
                engine.feed_qr_info(*qr_info).await.map(drop).map_err(|e| e.to_string())
            }
            Message::Diff(diff) => engine.apply_diff(*diff).await.map_err(|e| e.to_string()),
        }
    }

    fn block_hash(&self) -> BlockHash {
        match self {
            Message::Diff(diff) => diff.block_hash,
            Message::QrInfo(qr_info) => qr_info.mn_list_diff_tip.block_hash,
        }
    }

    /// Block hashes of the lists this message is applied on top of. A QRInfo's
    /// diffs chain from its oldest one, which Core sends as an empty diff from
    /// the base to itself, so only bases no other diff of it produces count.
    fn base_hashes(&self) -> Vec<BlockHash> {
        match self {
            Message::Diff(diff) => vec![diff.base_block_hash],
            Message::QrInfo(qr_info) => qr_info_bases(qr_info).into_iter().collect(),
        }
    }
}

/// Block hashes of the lists a QRInfo's diffs build.
fn qr_info_built(qr_info: &QRInfo) -> HashSet<BlockHash> {
    qr_info_diffs(qr_info)
        .iter()
        .filter(|d| d.block_hash != d.base_block_hash)
        .map(|d| d.block_hash)
        .collect()
}

/// Block hashes of the lists a QRInfo is applied on top of.
fn qr_info_bases(qr_info: &QRInfo) -> HashSet<BlockHash> {
    let built = qr_info_built(qr_info);
    qr_info_diffs(qr_info)
        .iter()
        .map(|d| d.base_block_hash)
        .filter(|base| !built.contains(base))
        .collect()
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
        // A QRInfo for the tip already stored, requested from a list the stored
        // one built, would replace the message it is applied on top of.
        if let Some(path) = self.qr_infos.get(&height) {
            if let Ok(stored) = Self::read_message::<QRInfo>(path).await {
                if stored.mn_list_diff_tip.block_hash == qr_info.mn_list_diff_tip.block_hash
                    && !qr_info_bases(qr_info).is_disjoint(&qr_info_built(&stored))
                {
                    return Ok(());
                }
            }
        }
        let folder = self.folder();
        Self::store_message(&folder, &mut self.qr_infos, Self::QRINFO_PREFIX, height, qr_info).await
    }

    async fn truncate_above(&mut self, height: CoreBlockHeight) -> StorageResult<()> {
        // A message leaves its index only once its file is gone, so a retry
        // finds what a failed deletion left.
        for index in [&mut self.diffs, &mut self.qr_infos] {
            while let Some(entry) = index.last_entry().filter(|entry| *entry.key() > height) {
                match tokio::fs::remove_file(entry.get()).await {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                    _ => entry.remove(),
                };
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockHeaderStorage;
    use dashcore::sml::masternode_list::MasternodeList;
    use dashcore_hashes::Hash;

    use tempfile::TempDir;
    use test_case::test_case;

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_slice(&[byte; 32]).unwrap()
    }

    /// [`MnListDiff::dummy`] from genesis to the first block of `chain`, then
    /// from each block to the next, each at its height and committing to the
    /// list it builds on the one before it.
    fn dummy_chain(chain: &[(u8, u32)]) -> Vec<MnListDiff> {
        let mut diffs = Vec::new();
        let mut list: Option<MasternodeList> = None;
        let mut base = 0x00;
        for &(tip, height) in chain {
            let diff = MnListDiff::dummy(base, tip).committing_on(list.as_ref(), height);
            list = Some(
                match &list {
                    Some(list) => list.apply_diff(diff.clone(), height, Network::Regtest),
                    None => MasternodeList::from_diff(diff.clone(), height, Network::Regtest),
                }
                .expect("the dummy diff applies"),
            );
            diffs.push(diff);
            base = tip;
        }
        diffs
    }

    /// A storage in `dir` over a header chain holding `heights`, whose headers
    /// prove the coinbases of `proven`.
    async fn open_storage(
        dir: &TempDir,
        heights: &[(u8, u32)],
        proven: &[&MnListDiff],
    ) -> PersistentMasternodeStorage<MockHeaderStorage> {
        let mut headers =
            MockHeaderStorage::new(heights.iter().map(|(b, h)| (hash(*b), *h)).collect());
        for diff in proven {
            headers.prove(diff);
        }
        PersistentMasternodeStorage::open(
            dir.path(),
            Arc::new(RwLock::new(headers)),
            Network::Regtest,
        )
        .await
        .expect("open")
    }

    #[tokio::test]
    async fn truncating_drops_the_messages_stored_above() {
        let dir = TempDir::new().unwrap();
        let heights = [(0x00, 0), (0xAA, 100), (0xBB, 200)];
        let mut storage = open_storage(&dir, &heights, &[]).await;

        storage.store_diff(100, &MnListDiff::dummy(0x00, 0xAA)).await.unwrap();
        storage.store_diff(200, &MnListDiff::dummy(0xAA, 0xBB)).await.unwrap();
        storage.store_qr_info(200, &QRInfo::dummy(0xBB)).await.unwrap();

        storage.truncate_above(100).await.unwrap();

        let reopened = open_storage(&dir, &heights, &[]).await;
        assert_eq!(reopened.diffs.keys().copied().collect::<Vec<_>>(), vec![100]);
        assert!(reopened.qr_infos.is_empty());
    }

    #[tokio::test]
    async fn a_reopened_storage_replays_what_was_stored() {
        let dir = TempDir::new().unwrap();
        let heights = [(0x00, 0), (0xAA, 100), (0xBB, 200)];
        let diffs = dummy_chain(&[(0xAA, 100), (0xBB, 200)]);
        {
            let mut storage = open_storage(&dir, &heights, &[]).await;
            storage.store_diff(100, &diffs[0]).await.unwrap();
            storage.store_diff(200, &diffs[1]).await.unwrap();
        }

        let engine =
            open_storage(&dir, &heights, &[&diffs[0], &diffs[1]]).await.load_engine().await;

        assert_eq!(engine.masternode_lists.keys().copied().collect::<Vec<_>>(), vec![100, 200]);
        assert_eq!(engine.masternode_lists[&200].block_hash, hash(0xBB));
        assert_eq!(engine.masternode_lists[&200].masternodes.len(), 2);
    }

    #[tokio::test]
    async fn replay_verifies_the_newest_lists_non_rotating_quorums() {
        use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
        use dashcore::hash_types::QuorumVVecHash;
        use dashcore::network::message_sml::QuorumCLSigObject;
        use dashcore::sml::llmq_entry_verification::{
            LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
        };
        use dashcore::sml::llmq_type::LLMQType;
        use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
        use dashcore::QuorumHash;

        let dir = TempDir::new().unwrap();
        let quorum_hash = QuorumHash::from_byte_array([0xAB; 32]);
        let diff = MnListDiff {
            new_quorums: vec![QuorumEntry {
                version: 1,
                llmq_type: LLMQType::LlmqtypeTest,
                quorum_hash,
                quorum_index: None,
                signers: vec![true; 3],
                valid_members: vec![true; 3],
                quorum_public_key: BLSPublicKey::from([7; 48]),
                quorum_vvec_hash: QuorumVVecHash::all_zeros(),
                threshold_sig: BLSSignature::from([1; 96]),
                all_commitment_aggregated_signature: BLSSignature::from([1; 96]),
            }],
            quorums_chainlock_signatures: vec![QuorumCLSigObject {
                signature: BLSSignature::from([1; 96]),
                index_set: vec![0],
            }],
            ..MnListDiff::dummy(0x00, 0xAA)
        }
        .committing_on(None, 100);
        let mut storage = open_storage(&dir, &[(0x00, 0), (0xAA, 100)], &[&diff]).await;
        storage.store_diff(100, &diff).await.unwrap();

        let engine = storage.load_engine().await;

        let status =
            &engine.masternode_lists[&100].quorums[&LLMQType::LlmqtypeTest][&quorum_hash].verified;
        assert_ne!(
            *status,
            LLMQEntryVerificationStatus::Skipped(
                LLMQEntryVerificationSkipStatus::NotMarkedForVerification
            ),
            "the replay never tried to verify it"
        );
    }

    /// A reorg truncates the headers above 100, but the diff stored for the
    /// orphaned block at 200 stays on disk until a new one replaces it.
    #[tokio::test]
    async fn replay_skips_a_message_whose_block_left_the_chain() {
        let dir = TempDir::new().unwrap();
        let diffs = dummy_chain(&[(0xAA, 100), (0xBB, 200)]);
        let mut storage = open_storage(&dir, &[(0x00, 0), (0xAA, 100)], &[&diffs[0]]).await;
        storage.store_diff(100, &diffs[0]).await.unwrap();
        storage.store_diff(200, &diffs[1]).await.unwrap();

        let engine = storage.load_engine().await;

        assert_eq!(engine.masternode_lists.keys().copied().collect::<Vec<_>>(), vec![100]);
    }

    #[tokio::test]
    async fn replay_skips_an_orphan_and_keeps_going() {
        let dir = TempDir::new().unwrap();
        let diffs = dummy_chain(&[(0xAA, 100), (0xBB, 150)]);
        let heights = [(0x00, 0), (0xAA, 100), (0xBB, 150), (0xDD, 120)];
        let mut storage = open_storage(&dir, &heights, &[&diffs[0], &diffs[1]]).await;

        storage.store_diff(100, &diffs[0]).await.unwrap();
        storage.store_diff(120, &MnListDiff::dummy(0xEE, 0xDD)).await.unwrap();
        storage.store_diff(150, &diffs[1]).await.unwrap();

        let engine = storage.load_engine().await;

        assert!(
            !engine.masternode_lists.contains_key(&120),
            "the orphan has no base to apply on and is left to the network"
        );
        assert!(engine.masternode_lists.contains_key(&150), "the diff after it still applies");
    }

    #[tokio::test]
    async fn storing_the_same_height_twice_keeps_the_newer_message() {
        let dir = TempDir::new().unwrap();
        let mut storage = open_storage(&dir, &[], &[]).await;

        storage.store_diff(100, &MnListDiff::dummy(0x00, 0xAA)).await.unwrap();
        storage.store_diff(100, &MnListDiff::dummy(0x00, 0xBB)).await.unwrap();

        assert_eq!(storage.diffs.len(), 1, "one file per height");
        let stored: MnListDiff =
            PersistentMasternodeStorage::<MockHeaderStorage>::read_message(&storage.diffs[&100])
                .await
                .expect("read back");
        assert_eq!(stored.block_hash, hash(0xBB), "the second write wins");
    }

    /// A QRInfo chaining `start`, `start + 1`, `start + 2`, `start + 3` and
    /// `tip`, applied on top of the list at `start`.
    fn chained_qr_info(start: u8, tip: u8) -> QRInfo {
        QRInfo {
            mn_list_diff_at_h_minus_3c: MnListDiff::dummy_empty(start, start),
            mn_list_diff_at_h_minus_2c: MnListDiff::dummy_empty(start, start + 1),
            mn_list_diff_at_h_minus_c: MnListDiff::dummy_empty(start + 1, start + 2),
            mn_list_diff_h: MnListDiff::dummy_empty(start + 2, start + 3),
            mn_list_diff_tip: MnListDiff::dummy_empty(start + 3, tip),
            ..QRInfo::dummy(tip)
        }
    }

    /// The QRInfo stored at `height`, `None` when the file does not decode.
    async fn stored_qr_info(
        storage: &PersistentMasternodeStorage<MockHeaderStorage>,
        height: CoreBlockHeight,
    ) -> Option<QRInfo> {
        PersistentMasternodeStorage::<MockHeaderStorage>::read_message(&storage.qr_infos[&height])
            .await
            .ok()
    }

    #[test_case(chained_qr_info(0xA2, 0xE0), false, false; "keeps the stored one it builds on")]
    #[test_case(chained_qr_info(0x10, 0xE0), false, true; "replaces it when unrelated")]
    #[test_case(chained_qr_info(0xA2, 0xEF), false, true; "replaces it for another tip after a reorg")]
    #[test_case(chained_qr_info(0xA2, 0xE0), true, true; "replaces a stored file that does not decode")]
    #[tokio::test]
    async fn a_same_tip_qr_info_replaces_the_stored_one_unless_built_on_it(
        incoming: QRInfo,
        corrupt_stored: bool,
        replaces: bool,
    ) {
        let height = 100;
        let stored = chained_qr_info(0xA0, 0xE0);
        let dir = TempDir::new().unwrap();
        let mut storage = open_storage(&dir, &[], &[]).await;
        storage.store_qr_info(height, &stored).await.unwrap();
        if corrupt_stored {
            tokio::fs::write(&storage.qr_infos[&height], b"not a qrinfo").await.unwrap();
        }

        storage.store_qr_info(height, &incoming).await.unwrap();

        let expected = if replaces {
            incoming
        } else {
            stored
        };
        assert_eq!(stored_qr_info(&storage, height).await, Some(expected));
    }

    #[tokio::test]
    async fn replay_survives_unreadable_files_and_ignores_foreign_names() {
        let dir = TempDir::new().unwrap();
        let folder = dir.path().join(PersistentMasternodeStorage::<MockHeaderStorage>::FOLDER_NAME);
        tokio::fs::create_dir_all(&folder).await.unwrap();

        let diff = dummy_chain(&[(0xAA, 100)]).remove(0);
        {
            let mut storage = open_storage(&dir, &[(0x00, 0), (0xAA, 100)], &[]).await;
            storage.store_diff(100, &diff).await.unwrap();
        }

        tokio::fs::write(folder.join("diff_50.dat"), b"not a diff").await.unwrap();
        tokio::fs::write(folder.join("diff_abc.dat"), b"x").await.unwrap();

        let storage = open_storage(&dir, &[(0x00, 0), (0xAA, 100)], &[&diff]).await;
        assert_eq!(
            storage.diffs.keys().copied().collect::<Vec<_>>(),
            vec![50, 100],
            "only well-formed names are indexed"
        );
        assert!(storage.qr_infos.is_empty());

        let engine = storage.load_engine().await;
        assert!(
            engine.masternode_lists.contains_key(&100),
            "the readable message still rebuilds its list"
        );
    }

    /// A Platform quorum mined at 1 and retired at 2, then a diff per block up to
    /// past the retention window, written without fsync to keep the setup fast.
    #[tokio::test]
    async fn a_lookup_rebuilds_a_quorum_only_lists_out_of_the_window_held() {
        use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
        use dashcore::hash_types::QuorumVVecHash;
        use dashcore::network::message_sml::{DeletedQuorum, QuorumCLSigObject};
        use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
        type S = PersistentMasternodeStorage<MockHeaderStorage>;

        let tip = 2_500;
        let llmq_type = Network::Regtest.platform_type();
        let quorum_hash = QuorumHash::from_byte_array([0xAB; 32]);
        let mined = MnListDiff {
            block_hash: BlockHash::dummy(1),
            new_quorums: vec![QuorumEntry {
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
            }],
            quorums_chainlock_signatures: vec![QuorumCLSigObject {
                signature: BLSSignature::from([1; 96]),
                index_set: vec![0],
            }],
            ..MnListDiff::dummy(0x00, 0x01)
        }
        .committing_on(None, 1);
        let with_quorum = MasternodeList::from_diff(mined.clone(), 1, Network::Regtest).unwrap();
        let retired = MnListDiff {
            deleted_quorums: vec![DeletedQuorum {
                llmq_type,
                quorum_hash,
            }],
            ..MnListDiff::dummy_between(1, 2)
        }
        .committing_on(Some(&with_quorum), 2);
        let without_quorum = with_quorum.apply_diff(retired.clone(), 2, Network::Regtest).unwrap();

        let dir = TempDir::new().unwrap();
        let folder = dir.path().join(S::FOLDER_NAME);
        std::fs::create_dir_all(&folder).unwrap();
        let write = |height, diff: &MnListDiff| {
            std::fs::write(folder.join(S::file_name(S::DIFF_PREFIX, height)), serialize(diff))
                .unwrap()
        };
        let mut headers = MockHeaderStorage::new(
            (1..=tip).map(|height| (BlockHash::dummy(height), height)).collect(),
        );
        write(1, &mined);
        headers.prove(&mined);
        write(2, &retired);
        headers.prove(&retired);
        for height in 3..=tip {
            let unchanged = MnListDiff::dummy_between(height - 1, height)
                .committing_on(Some(&without_quorum), height);
            write(height, &unchanged);
            headers.prove(&unchanged);
        }
        let storage =
            S::open(dir.path(), Arc::new(RwLock::new(headers)), Network::Regtest).await.unwrap();

        let engine = storage.load_engine().await;
        assert!(engine
            .quorum_entry_for_hash_at_or_before_height(llmq_type, quorum_hash, 100)
            .is_none());

        let log = storage.message_log();
        let quorum = log.quorum_entry_at_or_before(llmq_type, quorum_hash, 100).await;
        assert_eq!(quorum.map(|quorum| quorum.quorum_entry.quorum_hash), Some(quorum_hash));
        let unknown = QuorumHash::from_byte_array([0xCD; 32]);
        assert!(log.quorum_entry_at_or_before(llmq_type, unknown, 100).await.is_none());
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

    /// Mainnet headers start at a checkpoint, so the genesis a first QRInfo
    /// is built from has no height. A work-block diff requested from a list
    /// that QRInfo built still has to replay after it.
    #[tokio::test]
    async fn replay_applies_a_diff_on_a_list_of_a_qr_info_built_from_genesis() {
        use crate::sml_engine::test_support::fixture_heights;
        use dashcore::network::constants::NetworkExt;

        let qr_info: QRInfo = bincode::decode_from_slice(
            include_bytes!("../../../dash/tests/data/test_DML_diffs/qrinfo_2518986.dat"),
            bincode::config::standard(),
        )
        .unwrap()
        .0;

        let mut heights = fixture_heights(include_bytes!(
            "../../../dash/tests/data/test_DML_diffs/block_container_2518986.dat"
        ));
        heights.remove(&Network::Mainnet.known_genesis_block_hash().unwrap());
        let tip_height = heights[&qr_info.mn_list_diff_tip.block_hash];
        let base = qr_info.mn_list_diff_at_h_minus_c.block_hash;
        // A block of its own, above the h-c list and below the tip.
        let work_block_height = (heights[&base] + 1..)
            .find(|height| !heights.values().any(|held| held == height))
            .expect("a free height");
        heights.insert(hash(0xEE), work_block_height);

        let mut headers = MockHeaderStorage::new(heights);
        for diff in qr_info_diffs(&qr_info) {
            headers.prove(diff);
        }
        let dir = TempDir::new().unwrap();
        let mut storage = PersistentMasternodeStorage::open(
            dir.path(),
            Arc::new(RwLock::new(headers)),
            Network::Mainnet,
        )
        .await
        .unwrap();
        storage.store_qr_info(tip_height, &qr_info).await.unwrap();
        let replayed = storage.load_engine().await;
        let base_list = replayed
            .masternode_lists
            .values()
            .find(|list| list.block_hash == base)
            .expect("the QRInfo builds its h-c list");
        let diff = MnListDiff {
            base_block_hash: base,
            ..MnListDiff::dummy(0x00, 0xEE)
        }
        .committing_on(Some(base_list), work_block_height);
        storage.headers.write().await.prove(&diff);
        storage.store_diff(work_block_height, &diff).await.unwrap();

        let engine = storage.load_engine().await;

        assert!(engine.masternode_lists.contains_key(&tip_height), "the QRInfo replays");
        assert!(
            engine.masternode_lists.contains_key(&work_block_height),
            "the diff on the QRInfo's h-c list replays after the QRInfo"
        );
    }
}
