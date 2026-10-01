use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use dashcore::consensus::{deserialize, serialize, Decodable, Encodable};
use dashcore::network::constants::NetworkExt;
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list_engine::{qr_info_diffs, MasternodeListEngine, WORK_DIFF_DEPTH};
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{BlockHash, Network, QuorumHash};

use crate::error::{StorageError, StorageResult, SyncError, SyncResult};
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
        mut visit: impl FnMut(&MasternodeListEngine),
    ) -> MasternodeListEngine {
        let mut engine = MasternodeListEngine::default_for_network(self.network);
        if let Some(genesis) = self.network.known_genesis_block_hash() {
            engine.feed_block_height(0, genesis);
        }

        let entries =
            self.diffs.range(..=until).map(|(height, path)| (*height, Kind::Diff, path)).chain(
                self.qr_infos.range(..=until).map(|(height, path)| (*height, Kind::QrInfo, path)),
            );

        let mut plan = Vec::new();
        for (height, kind, path) in entries {
            let message = match PersistentMasternodeStorage::<H>::read_entry(path, kind).await {
                Ok(message) => message,
                Err(e) => {
                    tracing::warn!("Skipping unreadable masternode message at {height}: {e}");
                    continue;
                }
            };
            let headers = self.headers.read().await;
            let block_hash = message.block_hash();
            if headers.get_header_height_by_hash(&block_hash).await.ok().flatten() != Some(height) {
                tracing::warn!(
                    "Skipping masternode message at {height}: {block_hash} is no longer in the \
                     header chain"
                );
                continue;
            }
            let proven = match &message {
                Message::Diff(diff) => verify_diff_coinbase(&*headers, diff).await,
                Message::QrInfo(qr_info) => verify_qr_info_coinbases(&*headers, qr_info).await,
            };
            if let Err(e) = proven {
                tracing::warn!("Skipping masternode message at {height}: {e}");
                continue;
            }
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

        let newest_base = |bases: &[BlockHash]| {
            bases.iter().filter_map(|base| engine.block_container.get_height(base)).max()
        };
        plan.sort_by_cached_key(|(height, kind, _, bases)| {
            (newest_base(bases).unwrap_or(*height), *height, *kind)
        });

        let total = plan.len();
        let mut applied = 0;
        for (height, kind, path, _) in plan {
            match PersistentMasternodeStorage::<H>::read_entry(path, kind).await {
                Ok(message) => match apply(&mut engine, height, message) {
                    true => applied += 1,
                    false => tracing::warn!("Masternode message at {height} does not apply"),
                },
                Err(e) => tracing::warn!("Masternode message at {height} became unreadable: {e}"),
            }
            visit(&engine);
        }

        tracing::debug!(
            "Replayed {applied}/{total} masternode messages into {} masternode lists",
            engine.masternode_lists.len()
        );

        engine
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

fn apply(engine: &mut MasternodeListEngine, height: CoreBlockHeight, message: Message) -> bool {
    match message {
        Message::QrInfo(qr_info) => engine.feed_qr_info(*qr_info).is_ok(),
        Message::Diff(diff) => engine.apply_diff(*diff, Some(height), None).is_ok(),
    }
}

impl Message {
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
        Ok(self.message_log().replay(CoreBlockHeight::MAX, |_| {}).await)
    }
}

/// Checks that `diff`'s coinbase is the first transaction of the stored block
/// the diff names, see [`MnListDiff::verify_coinbase_merkle_proof`].
///
/// The engine checks the list a diff builds against that coinbase whenever it
/// applies the diff, so a diff that passes both ties its list to the header
/// chain. A diff naming a block without a stored header cannot be checked and
/// fails with `SyncError::MissingDependency`, an unproven one with
/// `SyncError::Validation`.
pub(crate) async fn verify_diff_coinbase<S: BlockHeaderStorage>(
    storage: &S,
    diff: &MnListDiff,
) -> SyncResult<()> {
    let header = match storage.get_header_height_by_hash(&diff.block_hash).await? {
        Some(height) => storage.get_header(height).await?,
        None => None,
    }
    .filter(|header| *header.hash() == diff.block_hash)
    .ok_or_else(|| {
        SyncError::MissingDependency(format!(
            "no stored header for the masternode list diff block {}",
            diff.block_hash
        ))
    })?;
    diff.verify_coinbase_merkle_proof(header.header().merkle_root)
        .map_err(|e| SyncError::Validation(e.to_string()))
}

/// [`verify_diff_coinbase`] for every diff a QRInfo carries.
pub(crate) async fn verify_qr_info_coinbases<S: BlockHeaderStorage>(
    storage: &S,
    qr_info: &QRInfo,
) -> SyncResult<()> {
    for diff in qr_info_diffs(qr_info) {
        verify_diff_coinbase(storage, diff).await?;
    }
    Ok(())
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
    use dashcore::block::Header;
    use dashcore::network::message::{NetworkMessage, RawNetworkMessage};
    use dashcore::sml::masternode_list_entry::MasternodeListEntry;
    use dashcore::TxMerkleNode;
    use dashcore_hashes::Hash;

    use tempfile::TempDir;

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_slice(&[byte; 32]).unwrap()
    }

    /// Knows the heights of `heights` and holds the header that proves the
    /// coinbase of each of `diffs`.
    fn headers(heights: &[(u8, u32)], diffs: &[&MnListDiff]) -> MockHeaderStorage {
        let map = heights.iter().map(|(b, h)| (hash(*b), *h)).collect();
        diffs
            .iter()
            .fold(MockHeaderStorage::new(map), |headers, diff| headers.with_header_for(diff))
    }

    async fn open_storage(
        dir: &TempDir,
        headers: MockHeaderStorage,
    ) -> PersistentMasternodeStorage<MockHeaderStorage> {
        PersistentMasternodeStorage::open(
            dir.path(),
            Arc::new(RwLock::new(headers)),
            Network::Regtest,
        )
        .await
        .expect("open")
    }

    /// [`MnListDiff::dummy`] from `base` to `tip` applied on the list the
    /// dummy diff from genesis to `base` built.
    fn dummy_on_dummy(base: u8, tip: u8) -> MnListDiff {
        MnListDiff::dummy(base, tip).with_coinbase_committing_to(
            &[MasternodeListEntry::dummy(base), MasternodeListEntry::dummy(tip)],
            &[],
        )
    }

    #[tokio::test]
    async fn a_reopened_storage_replays_what_was_stored() {
        let dir = TempDir::new().unwrap();
        let heights = [(0x00, 0), (0xAA, 100), (0xBB, 200)];
        let (first, second) = (MnListDiff::dummy(0x00, 0xAA), dummy_on_dummy(0xAA, 0xBB));
        {
            let mut storage = open_storage(&dir, headers(&heights, &[])).await;
            storage.store_diff(100, &first).await.unwrap();
            storage.store_diff(200, &second).await.unwrap();
        }

        let engine = open_storage(&dir, headers(&heights, &[&first, &second]))
            .await
            .load_engine()
            .await
            .unwrap();

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
        let quorum = QuorumEntry {
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
        };
        let diff = MnListDiff {
            new_quorums: vec![quorum.clone()],
            quorums_chainlock_signatures: vec![QuorumCLSigObject {
                signature: BLSSignature::from([1; 96]),
                index_set: vec![0],
            }],
            ..MnListDiff::dummy(0x00, 0xAA)
        }
        .with_coinbase_committing_to(&[MasternodeListEntry::dummy(0xAA)], &[quorum]);
        let mut storage = open_storage(&dir, headers(&[(0x00, 0), (0xAA, 100)], &[&diff])).await;
        storage.store_diff(100, &diff).await.unwrap();

        let engine = storage.load_engine().await.unwrap();

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
        let first = MnListDiff::dummy(0x00, 0xAA);
        let mut storage = open_storage(&dir, headers(&[(0x00, 0), (0xAA, 100)], &[&first])).await;
        storage.store_diff(100, &first).await.unwrap();
        storage.store_diff(200, &dummy_on_dummy(0xAA, 0xBB)).await.unwrap();

        let engine = storage.load_engine().await.unwrap();

        assert_eq!(engine.masternode_lists.keys().copied().collect::<Vec<_>>(), vec![100]);
    }

    #[tokio::test]
    async fn replay_skips_an_orphan_and_keeps_going() {
        let dir = TempDir::new().unwrap();
        let (first, orphan, second) = (
            MnListDiff::dummy(0x00, 0xAA),
            MnListDiff::dummy(0xEE, 0xDD),
            dummy_on_dummy(0xAA, 0xBB),
        );
        let heights = [(0x00, 0), (0xAA, 100), (0xBB, 150), (0xDD, 120)];
        let mut storage = open_storage(&dir, headers(&heights, &[&first, &orphan, &second])).await;

        storage.store_diff(100, &first).await.unwrap();
        storage.store_diff(120, &orphan).await.unwrap();
        storage.store_diff(150, &second).await.unwrap();

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
        let mut storage = open_storage(&dir, MockHeaderStorage::default()).await;

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

        let diff = MnListDiff::dummy(0x00, 0xAA);
        let heights = [(0x00, 0), (0xAA, 100)];
        {
            let mut storage = open_storage(&dir, headers(&heights, &[&diff])).await;
            storage.store_diff(100, &diff).await.unwrap();
        }

        tokio::fs::write(folder.join("diff_50.dat"), b"not a diff").await.unwrap();
        tokio::fs::write(folder.join("diff_abc.dat"), b"x").await.unwrap();

        let storage = open_storage(&dir, headers(&heights, &[&diff])).await;
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
        let quorum = QuorumEntry {
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
        };
        let masternodes = [MasternodeListEntry::dummy(0x01)];
        let mined = MnListDiff {
            block_hash: BlockHash::dummy(1),
            new_quorums: vec![quorum.clone()],
            quorums_chainlock_signatures: vec![QuorumCLSigObject {
                signature: BLSSignature::from([1; 96]),
                index_set: vec![0],
            }],
            ..MnListDiff::dummy(0x00, 0x01)
        }
        .with_coinbase_committing_to(&masternodes, &[quorum]);
        let retired = MnListDiff {
            deleted_quorums: vec![DeletedQuorum {
                llmq_type,
                quorum_hash,
            }],
            ..MnListDiff::dummy_between(1, 2)
        }
        .with_coinbase_committing_to(&masternodes, &[]);
        let unchanged = |height| {
            MnListDiff::dummy_between(height - 1, height)
                .with_coinbase_committing_to(&masternodes, &[])
        };

        let dir = TempDir::new().unwrap();
        let folder = dir.path().join(S::FOLDER_NAME);
        std::fs::create_dir_all(&folder).unwrap();
        let write = |height, diff: &MnListDiff| {
            std::fs::write(folder.join(S::file_name(S::DIFF_PREFIX, height)), serialize(diff))
                .unwrap()
        };
        let heights = (1..=tip).map(|height| (BlockHash::dummy(height), height)).collect();
        let mut headers =
            MockHeaderStorage::new(heights).with_header_for(&mined).with_header_for(&retired);
        write(1, &mined);
        write(2, &retired);
        for height in 3..=tip {
            let diff = unchanged(height);
            write(height, &diff);
            headers = headers.with_header_for(&diff);
        }
        let storage =
            S::open(dir.path(), Arc::new(RwLock::new(headers)), Network::Regtest).await.unwrap();

        let engine = storage.load_engine().await.unwrap();
        assert!(engine
            .quorum_entry_for_hash_at_or_before_height(llmq_type, quorum_hash, 100)
            .is_none());

        let log = storage.message_log();
        let quorum = log.quorum_entry_at_or_before(llmq_type, quorum_hash, 100).await;
        assert_eq!(quorum.map(|quorum| quorum.quorum_entry.quorum_hash), Some(quorum_hash));
        let unknown = QuorumHash::from_byte_array([0xCD; 32]);
        assert!(log.quorum_entry_at_or_before(llmq_type, unknown, 100).await.is_none());
    }

    #[tokio::test]
    async fn replay_skips_a_message_its_block_header_does_not_prove() {
        let dir = TempDir::new().unwrap();
        let diff = MnListDiff::dummy(0x00, 0xAA);
        let heights = [(0x00, 0), (0xAA, 100)];
        let unproven = headers(&heights, &[]).with_header(hash(0xAA), TxMerkleNode::all_zeros());
        let mut storage = open_storage(&dir, unproven).await;
        storage.store_diff(100, &diff).await.unwrap();

        let engine = storage.load_engine().await.unwrap();
        assert!(engine.masternode_lists.is_empty(), "a coinbase the header does not prove");

        let engine =
            open_storage(&dir, headers(&heights, &[&diff])).await.load_engine().await.unwrap();
        assert!(engine.masternode_lists.contains_key(&100), "the header that proves it");
    }

    /// The mainnet QRInfo capture and a header storage holding the headers of
    /// its blocks, as public block explorers serve them. Each header hashes to
    /// the block hash of one of the diffs.
    fn mainnet_qr_info_with_headers() -> (QRInfo, MockHeaderStorage) {
        const HEADERS: [(u32, &str); 5] = [
            (2224359, "00000020552ffd09b040ec6aafd6a76fe586eed37dca3a88b653732027000000000000001a28433a3aaf9be619f3d9ae713e329a48c35a366afd488662a159df84d4484f08deb367ccfe2619980e0ae3"),
            (2224216, "000000203d986f88b0a06213229d3ab8a3650bc86af8e04fb3d9be9b20000000000000000bbea6733e6180f312fbd891d5dbd72f3089d66af33e9292aa4e1be985652ffc8186b367773b2c196646dce8"),
            (2223928, "000000200c2693bfeffebad43ea41aca74fb652f58e3264d65454ace1d0000000000000040a50328f3f6e173ce97b4d1fa9e0b3f36948e6888be0adf39d024540e4bb950a2d5b26799c12b19821af24e"),
            (2223640, "00000020174c02dd39c2371274cf025eeb2b70b9a156ad1327ecded51200000000000000785ec2546f5347f4960171ee93b319094a34aa4cab8277f985434b6b4b4fa6e9fb21b267ba072f19b46b3938"),
            (2223352, "000000207654d9fcd141892f9d47cf5c40d46d133d573e8bb9fbaf350400000000000000925d75e37bfd754cc73d6f54629ab6e1e38eb917a3452a73d1377be0d6c62876d36eb16781f3231902819b59"),
        ];
        let hex = include_str!("../../../dash/tests/data/test_DML_diffs/QR_INFO_0_2224359.hex");
        let message: RawNetworkMessage = deserialize(&hex::decode(hex).unwrap()).unwrap();
        let NetworkMessage::QRInfo(qr_info) = message.payload else {
            panic!("expected a qrinfo message");
        };

        let headers: Vec<(u32, Header)> = HEADERS
            .iter()
            .map(|(height, header)| (*height, deserialize(&hex::decode(header).unwrap()).unwrap()))
            .collect();
        let heights =
            headers.iter().map(|(height, header)| (header.block_hash(), *height)).collect();
        let storage =
            headers.iter().fold(MockHeaderStorage::new(heights), |storage, (_, header)| {
                storage.with_header(header.block_hash(), header.merkle_root)
            });
        (qr_info, storage)
    }

    #[tokio::test]
    async fn every_diff_of_a_qr_info_is_proven_by_its_stored_block_header() {
        let (qr_info, storage) = mainnet_qr_info_with_headers();
        verify_qr_info_coinbases(&storage, &qr_info).await.expect("every coinbase is proven");

        let mut swapped = qr_info.clone();
        swapped.mn_list_diff_h.coinbase_tx = qr_info.mn_list_diff_tip.coinbase_tx.clone();
        assert!(matches!(
            verify_qr_info_coinbases(&storage, &swapped).await,
            Err(SyncError::Validation(_))
        ));

        let mut unknown = qr_info;
        unknown.mn_list_diff_h.block_hash = hash(0x09);
        assert!(matches!(
            verify_qr_info_coinbases(&storage, &unknown).await,
            Err(SyncError::MissingDependency(_))
        ));
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
        use dashcore::sml::masternode_list_engine::MasternodeListEngineBlockContainer;

        fn decode<T: bincode::Decode<()>>(bytes: &[u8]) -> T {
            bincode::decode_from_slice(bytes, bincode::config::standard()).unwrap().0
        }

        let MasternodeListEngineBlockContainer::BTreeMapContainer(container) = decode(
            include_bytes!("../../../dash/tests/data/test_DML_diffs/block_container_2518986.dat"),
        );
        let qr_info: QRInfo =
            decode(include_bytes!("../../../dash/tests/data/test_DML_diffs/qrinfo_2518986.dat"));

        let mut heights: std::collections::HashMap<_, _> =
            container.block_heights.into_iter().collect();
        heights.remove(&Network::Mainnet.known_genesis_block_hash().unwrap());
        let tip_height = heights[&qr_info.mn_list_diff_tip.block_hash];
        let base = qr_info.mn_list_diff_at_h_minus_c.block_hash;
        let work_block_height = heights[&base] + 24;
        heights.insert(hash(0xEE), work_block_height);

        let dir = TempDir::new().unwrap();
        let mut storage = PersistentMasternodeStorage::open(
            dir.path(),
            Arc::new(RwLock::new(MockHeaderStorage(heights))),
            Network::Mainnet,
        )
        .await
        .unwrap();
        storage.store_qr_info(tip_height, &qr_info).await.unwrap();
        let diff = MnListDiff {
            base_block_hash: base,
            ..MnListDiff::dummy(0x00, 0xEE)
        };
        storage.store_diff(work_block_height, &diff).await.unwrap();

        let engine = storage.load_engine().await.unwrap();

        assert!(engine.masternode_lists.contains_key(&tip_height), "the QRInfo replays");
        assert!(
            engine.masternode_lists.contains_key(&work_block_height),
            "the diff on the QRInfo's h-c list replays after the QRInfo"
        );
    }
}
