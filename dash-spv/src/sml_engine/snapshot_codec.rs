//! The engine snapshot format. Lists share their maps and entries in memory,
//! so the snapshot writes every distinct entry once, and every list as a
//! reference to an earlier list's map or as the changes from the previous
//! list's map. Equal entries are written once even when separate allocations
//! hold them, so a restored engine shares at least what the engine did.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use bincode::de::Decoder;
use bincode::enc::Encoder;
use bincode::error::{DecodeError, EncodeError};
use bincode::{Decode, Encode};
use dashcore::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::{MasternodeList, MasternodeMap, QuorumMap};
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{BlockHash, Network, ProTxHash, QuorumHash};
use tokio::sync::RwLock;

use super::MasternodeListEngine;
use crate::storage::BlockHeaderStorage;

const MAGIC: [u8; 4] = *b"DMLE";
const VERSION: u8 = 1;

/// Bounds what a corrupt length prefix can make the decoder allocate up front:
/// bincode claims `len * size_of::<T>()` against it before preallocating.
const DECODE_LIMIT: usize = 64 * 1024 * 1024;

pub(super) fn config() -> impl bincode::config::Config {
    bincode::config::standard().with_limit::<DECODE_LIMIT>()
}

/// A list's map: the map of the list at that index, or the changes from the
/// previous list's map (an empty map for the first list). Values are indices
/// into the snapshot's entry table.
#[derive(Encode, Decode)]
enum MapRecord<D> {
    SameAs(u32),
    Changed(D),
}

trait Changes {
    fn is_empty(&self) -> bool;
}

#[derive(Encode, Decode)]
struct Delta<K> {
    removed: Vec<K>,
    upserted: Vec<(K, u32)>,
}

impl<K> Changes for Delta<K> {
    fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.upserted.is_empty()
    }
}

/// Quorum map changes per type. A listed type exists in the map afterwards,
/// even with no quorums, as an empty type map can be held.
#[derive(Encode, Decode)]
struct QuorumDelta {
    removed_types: Vec<LLMQType>,
    types: Vec<(LLMQType, Delta<QuorumHash>)>,
}

impl Changes for QuorumDelta {
    fn is_empty(&self) -> bool {
        self.removed_types.is_empty() && self.types.is_empty()
    }
}

#[derive(Encode, Decode)]
struct ListRecord {
    height: CoreBlockHeight,
    block_hash: BlockHash,
    known_height: u32,
    masternode_merkle_root: Option<MerkleRootMasternodeList>,
    llmq_merkle_root: Option<MerkleRootQuorums>,
    masternodes: MapRecord<Delta<ProTxHash>>,
    quorums: MapRecord<QuorumDelta>,
}

/// Indexes entries by value, remembering each allocation it saw so a shared
/// `Arc` is encoded for comparison once.
struct Interner<'a, T> {
    by_allocation: HashMap<*const T, u32>,
    by_value: HashMap<Vec<u8>, u32>,
    values: Vec<&'a T>,
}

impl<'a, T: Encode> Interner<'a, T> {
    fn new() -> Self {
        Self {
            by_allocation: HashMap::new(),
            by_value: HashMap::new(),
            values: Vec::new(),
        }
    }

    fn intern(&mut self, value: &'a Arc<T>) -> Result<u32, EncodeError> {
        if let Some(index) = self.by_allocation.get(&Arc::as_ptr(value)) {
            return Ok(*index);
        }
        let next = u32::try_from(self.values.len())
            .map_err(|_| EncodeError::Other("too many entries for a snapshot"))?;
        let encoded = bincode::encode_to_vec(&**value, bincode::config::standard())?;
        let index = *self.by_value.entry(encoded).or_insert(next);
        if index == next {
            self.values.push(value);
        }
        self.by_allocation.insert(Arc::as_ptr(value), index);
        Ok(index)
    }

    fn interned(&self, value: &Arc<T>) -> Option<u32> {
        self.by_allocation.get(&Arc::as_ptr(value)).copied()
    }
}

/// The changes turning `base` into `next`, walking both in key order. Every
/// entry of `base` was interned with the list holding it.
fn delta<'a, K: Ord + Copy, V: Encode>(
    base: &BTreeMap<K, Arc<V>>,
    next: &'a BTreeMap<K, Arc<V>>,
    interner: &mut Interner<'a, V>,
) -> Result<Delta<K>, EncodeError> {
    let mut delta = Delta {
        removed: Vec::new(),
        upserted: Vec::new(),
    };
    let mut base = base.iter().peekable();
    for (key, value) in next {
        while let Some((old_key, _)) = base.next_if(|(old_key, _)| *old_key < key) {
            delta.removed.push(*old_key);
        }
        let old = base.next_if(|(old_key, _)| *old_key == key).map(|(_, old)| old);
        if old.is_some_and(|old| Arc::ptr_eq(old, value)) {
            continue;
        }
        let index = interner.intern(value)?;
        if old.and_then(|old| interner.interned(old)) != Some(index) {
            delta.upserted.push((*key, index));
        }
    }
    delta.removed.extend(base.map(|(old_key, _)| *old_key));
    Ok(delta)
}

fn quorum_delta<'a>(
    base: &QuorumMap,
    next: &'a QuorumMap,
    interner: &mut Interner<'a, QualifiedQuorumEntry>,
) -> Result<QuorumDelta, EncodeError> {
    let mut quorum_delta = QuorumDelta {
        removed_types: base
            .keys()
            .filter(|llmq_type| !next.contains_key(llmq_type))
            .copied()
            .collect(),
        types: Vec::new(),
    };
    for (llmq_type, quorums) in next {
        let type_delta = match base.get(llmq_type) {
            Some(base_quorums) => {
                let type_delta = delta(base_quorums, quorums, interner)?;
                if type_delta.is_empty() {
                    continue;
                }
                type_delta
            }
            None => delta(&BTreeMap::new(), quorums, interner)?,
        };
        quorum_delta.types.push((*llmq_type, type_delta));
    }
    Ok(quorum_delta)
}

/// Where each map was first written, so later lists holding it refer back.
struct MapIndex<M> {
    first_list: HashMap<*const M, u32>,
    previous: Option<u32>,
}

impl<M> MapIndex<M> {
    fn new() -> Self {
        Self {
            first_list: HashMap::new(),
            previous: None,
        }
    }

    /// The record of `map` held by list `list_index`: a reference to the list
    /// that first wrote the same `Arc`, or to the previous list's map when
    /// `changes` from it are empty, or the changes.
    fn record<D: Changes>(
        &mut self,
        map: &Arc<M>,
        list_index: u32,
        changes: impl FnOnce() -> Result<D, EncodeError>,
    ) -> Result<MapRecord<D>, EncodeError> {
        let record = match self.first_list.get(&Arc::as_ptr(map)) {
            Some(index) => MapRecord::SameAs(*index),
            None => {
                let changes = changes()?;
                match self.previous {
                    Some(previous) if changes.is_empty() => MapRecord::SameAs(previous),
                    _ => MapRecord::Changed(changes),
                }
            }
        };
        let written_at = match record {
            MapRecord::SameAs(index) => index,
            MapRecord::Changed(_) => list_index,
        };
        self.first_list.entry(Arc::as_ptr(map)).or_insert(written_at);
        self.previous = Some(written_at);
        Ok(record)
    }
}

/// The snapshot format. [`MasternodeListEngine::snapshot`] and
/// [`MasternodeListEngine::from_snapshot`] use it with the configuration
/// bounding what a corrupt snapshot makes decoding allocate.
impl<H: BlockHeaderStorage> Encode for MasternodeListEngine<H> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        let mut masternodes = Interner::new();
        let mut quorums = Interner::new();
        let mut masternode_maps = MapIndex::new();
        let mut quorum_maps = MapIndex::new();
        let empty_masternodes = Arc::new(MasternodeMap::new());
        let empty_quorums = Arc::new(QuorumMap::new());
        let mut previous: Option<&MasternodeList> = None;
        let mut records = Vec::with_capacity(self.masternode_lists.len());

        for (index, (height, list)) in self.masternode_lists.iter().enumerate() {
            let index = u32::try_from(index)
                .map_err(|_| EncodeError::Other("too many lists for a snapshot"))?;
            let previous_masternodes =
                previous.map_or(&empty_masternodes, |list| &list.masternodes);
            let previous_quorums = previous.map_or(&empty_quorums, |list| &list.quorums);
            records.push(ListRecord {
                height: *height,
                block_hash: list.block_hash,
                known_height: list.known_height,
                masternode_merkle_root: list.masternode_merkle_root,
                llmq_merkle_root: list.llmq_merkle_root,
                masternodes: masternode_maps.record(&list.masternodes, index, || {
                    delta(previous_masternodes, &list.masternodes, &mut masternodes)
                })?,
                quorums: quorum_maps.record(&list.quorums, index, || {
                    quorum_delta(previous_quorums, &list.quorums, &mut quorums)
                })?,
            });
            previous = Some(list);
        }

        MAGIC.encode(encoder)?;
        VERSION.encode(encoder)?;
        self.network.encode(encoder)?;
        masternodes.values.encode(encoder)?;
        quorums.values.encode(encoder)?;
        records.encode(encoder)?;
        self.rotated_quorums_per_cycle.encode(encoder)
    }
}

type Decoded = (
    Vec<QualifiedMasternodeListEntry>,
    Vec<QualifiedQuorumEntry>,
    Vec<ListRecord>,
    BTreeMap<BlockHash, BTreeMap<u16, QualifiedQuorumEntry>>,
);

fn entry<T>(entries: &[Arc<T>], index: u32) -> Result<Arc<T>, DecodeError> {
    entries
        .get(index as usize)
        .map(Arc::clone)
        .ok_or(DecodeError::Other("snapshot references a missing entry"))
}

fn apply<K: Ord, V>(
    map: &mut BTreeMap<K, Arc<V>>,
    delta: Delta<K>,
    entries: &[Arc<V>],
) -> Result<(), DecodeError> {
    let upserted = delta.upserted.into_iter().map(|(key, index)| Ok((key, entry(entries, index)?)));
    if map.is_empty() {
        // Built in bulk, as `from_diff` collects it, the map packs its nodes.
        *map = upserted.collect::<Result<_, DecodeError>>()?;
        return Ok(());
    }
    for key in delta.removed {
        map.remove(&key);
    }
    for upsert in upserted {
        let (key, entry) = upsert?;
        map.insert(key, entry);
    }
    Ok(())
}

fn rebuild<M: Clone + Default, D>(
    record: MapRecord<D>,
    built: &[Arc<M>],
    changes: impl FnOnce(&mut M, D) -> Result<(), DecodeError>,
) -> Result<Arc<M>, DecodeError> {
    match record {
        MapRecord::SameAs(index) => built
            .get(index as usize)
            .map(Arc::clone)
            .ok_or(DecodeError::Other("snapshot references a later list")),
        MapRecord::Changed(delta) => {
            let mut map = built.last().map_or_else(M::default, |map| M::clone(map));
            changes(&mut map, delta)?;
            Ok(Arc::new(map))
        }
    }
}

/// Decodes a snapshot of an engine for the context's network, looking block
/// heights up in the context's header chain.
impl<H: BlockHeaderStorage> Decode<(Network, Arc<RwLock<H>>)> for MasternodeListEngine<H> {
    fn decode<D: Decoder<Context = (Network, Arc<RwLock<H>>)>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let (network, headers) = decoder.context().clone();
        if <[u8; 4]>::decode(decoder)? != MAGIC {
            return Err(DecodeError::Other("not a masternode engine snapshot"));
        }
        if u8::decode(decoder)? != VERSION {
            return Err(DecodeError::Other("unsupported snapshot version"));
        }
        if Network::decode(decoder)? != network {
            return Err(DecodeError::Other("snapshot of another network"));
        }
        let (masternode_entries, quorum_entries, records, rotated_quorums_per_cycle) =
            Decoded::decode(decoder)?;

        let masternode_entries: Vec<_> = masternode_entries.into_iter().map(Arc::new).collect();
        let quorum_entries: Vec<_> = quorum_entries.into_iter().map(Arc::new).collect();
        let mut masternode_maps: Vec<Arc<MasternodeMap>> = Vec::with_capacity(records.len());
        let mut quorum_maps: Vec<Arc<QuorumMap>> = Vec::with_capacity(records.len());
        let mut masternode_lists = BTreeMap::new();

        for record in records {
            let masternodes = rebuild(record.masternodes, &masternode_maps, |map, delta| {
                apply(map, delta, &masternode_entries)
            })?;
            let quorums = rebuild(record.quorums, &quorum_maps, |map, delta: QuorumDelta| {
                for llmq_type in delta.removed_types {
                    map.remove(&llmq_type);
                }
                for (llmq_type, type_delta) in delta.types {
                    apply(map.entry(llmq_type).or_default(), type_delta, &quorum_entries)?;
                }
                Ok(())
            })?;
            masternode_maps.push(Arc::clone(&masternodes));
            quorum_maps.push(Arc::clone(&quorums));
            let list = MasternodeList {
                block_hash: record.block_hash,
                known_height: record.known_height,
                masternode_merkle_root: record.masternode_merkle_root,
                llmq_merkle_root: record.llmq_merkle_root,
                masternodes,
                quorums,
            };
            if masternode_lists.insert(record.height, list).is_some() {
                return Err(DecodeError::Other("snapshot holds a height twice"));
            }
        }

        Ok(Self {
            masternode_lists,
            rotated_quorums_per_cycle,
            ..Self::new(network, headers)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::Arc;

    use bincode::error::DecodeError;
    use dashcore::consensus::deserialize;
    use dashcore::network::message_qrinfo::QRInfo;
    use dashcore::network::message_sml::MnListDiff;
    use dashcore::prelude::CoreBlockHeight;
    use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
    use dashcore::sml::llmq_type::LLMQType;
    use dashcore::sml::masternode_list::MasternodeList;
    use dashcore::sml::masternode_list_entry::net_info::{
        Bip155Network, ExtNetInfo, NetInfoEntry, NetInfoPurpose,
    };
    use dashcore::sml::masternode_list_entry::MasternodeNetInfo;
    use dashcore::sml::quorum_validation_error::QuorumValidationError;
    use dashcore::Network;
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

    use crate::sml_engine::test_support::{fixture_heights, TestEngine};

    use super::{MAGIC, VERSION};

    /// Allocation identities of every map and entry of `lists`, in a fixed walk order.
    fn allocations(lists: &BTreeMap<CoreBlockHeight, MasternodeList>) -> Vec<usize> {
        let mut walk = Vec::new();
        for list in lists.values() {
            walk.push(Arc::as_ptr(&list.masternodes) as usize);
            walk.push(Arc::as_ptr(&list.quorums) as usize);
            walk.extend(list.masternodes.values().map(|entry| Arc::as_ptr(entry) as usize));
            walk.extend(
                list.quorums
                    .values()
                    .flat_map(|quorums| quorums.values())
                    .map(|quorum| Arc::as_ptr(quorum) as usize),
            );
        }
        walk
    }

    /// Whether `restored` shares every allocation `original` shares: each
    /// original allocation maps to a single restored one.
    fn shares_at_least(
        original: &BTreeMap<CoreBlockHeight, MasternodeList>,
        restored: &BTreeMap<CoreBlockHeight, MasternodeList>,
    ) -> bool {
        let mut mapping = HashMap::new();
        allocations(original)
            .into_iter()
            .zip(allocations(restored))
            .all(|(original, restored)| *mapping.entry(original).or_insert(restored) == restored)
    }

    fn distinct(lists: &BTreeMap<CoreBlockHeight, MasternodeList>) -> usize {
        allocations(lists).into_iter().collect::<HashSet<_>>().len()
    }

    /// No two restored entries are separate allocations of equal values.
    fn entries_deduplicated(lists: &BTreeMap<CoreBlockHeight, MasternodeList>) -> bool {
        let mut masternodes = HashMap::new();
        let mut quorums = HashMap::new();
        lists.values().all(|list| {
            list.masternodes.values().all(|entry| {
                let encoded =
                    bincode::encode_to_vec(&**entry, bincode::config::standard()).expect("encodes");
                Arc::ptr_eq(masternodes.entry(encoded).or_insert_with(|| Arc::clone(entry)), entry)
            }) && list.quorums.values().flat_map(|quorums| quorums.values()).all(|quorum| {
                let encoded = bincode::encode_to_vec(&**quorum, bincode::config::standard())
                    .expect("encodes");
                Arc::ptr_eq(quorums.entry(encoded).or_insert_with(|| Arc::clone(quorum)), quorum)
            })
        })
    }

    /// A tip-following chain whose oldest quorum changes status in every list
    /// holding it, and one list holding an empty type map.
    fn chain_engine() -> TestEngine {
        let mut engine = TestEngine::mainnet_list_chain(300, 20);
        let (llmq_type, quorum_hash) = engine
            .masternode_lists
            .values()
            .next()
            .and_then(|list| list.quorums.iter().next())
            .and_then(|(llmq_type, quorums)| Some((*llmq_type, *quorums.keys().next()?)))
            .expect("the chain holds quorums");
        engine.set_quorum_status(
            llmq_type,
            quorum_hash,
            &LLMQEntryVerificationStatus::Invalid(QuorumValidationError::InvalidQuorumPublicKey),
        );
        let list = engine.masternode_lists.values_mut().nth(150).expect("150 lists");
        Arc::make_mut(&mut list.quorums).entry(LLMQType::LlmqtypeTest).or_default();
        let list = engine.masternode_lists.values_mut().nth(200).expect("200 lists");
        let addresses = [
            MasternodeNetInfo::Extended(ExtNetInfo {
                version: 1,
                purposes: vec![(
                    NetInfoPurpose::CoreP2P,
                    vec![
                        NetInfoEntry::Service {
                            network: Bip155Network::TorV3,
                            addr: vec![7; 32],
                            port: 9999,
                        },
                        NetInfoEntry::Domain {
                            host: "node.example".to_string(),
                            port: 443,
                        },
                    ],
                )],
            }),
            MasternodeNetInfo::Legacy(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                9999,
                0,
                0,
            ))),
        ];
        let masternodes = Arc::make_mut(&mut list.masternodes);
        for (entry, address) in masternodes.values_mut().zip(addresses) {
            Arc::make_mut(entry).masternode_list_entry.service_address = address;
        }
        engine
    }

    /// The real 2240504 diffs on the 2227096 list, then the real QRInfo, which
    /// rebuilds lists in fresh allocations equal to ones the diffs left.
    async fn qr_info_engine() -> TestEngine {
        let mut engine = TestEngine::knowing(
            Network::Mainnet,
            fixture_heights(include_bytes!(
                "../../../dash/tests/data/test_DML_diffs/block_container_2240504.dat"
            )),
        );
        let base: MnListDiff = deserialize(include_bytes!(
            "../../../dash/tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin"
        ))
        .expect("base diff");
        engine.masternode_lists.insert(
            2227096,
            MasternodeList::from_diff(base, 2227096, Network::Mainnet).expect("base list"),
        );
        let diffs: BTreeMap<(CoreBlockHeight, CoreBlockHeight), MnListDiff> =
            bincode::decode_from_slice(
                include_bytes!("../../../dash/tests/data/test_DML_diffs/mnlistdiffs_2240504.dat"),
                bincode::config::standard(),
            )
            .expect("diffs")
            .0;
        for ((base_height, height), diff) in diffs {
            engine.feed_block_height(base_height, diff.base_block_hash);
            engine.feed_block_height(height, diff.block_hash);
            engine.apply_diff(diff).await.expect("applies");
        }
        let qr_info: QRInfo = bincode::decode_from_slice(
            include_bytes!("../../../dash/tests/data/test_DML_diffs/qrinfo_2240504.dat"),
            bincode::config::standard(),
        )
        .expect("qrinfo")
        .0;
        engine.feed_qr_info(qr_info).await.expect("feeds");
        engine
    }

    #[tokio::test]
    async fn a_snapshot_restores_the_lists_cycles_and_their_sharing() {
        for engine in [TestEngine::mainnet_fixture(), chain_engine(), qr_info_engine().await] {
            let bytes = engine.snapshot().expect("encodes");
            let restored = TestEngine::from_snapshot(Network::Mainnet, engine.headers(), &bytes)
                .expect("decodes");

            assert_eq!(restored.masternode_lists, engine.masternode_lists);
            assert_eq!(restored.rotated_quorums_per_cycle, engine.rotated_quorums_per_cycle);
            assert!(shares_at_least(&engine.masternode_lists, &restored.masternode_lists));
            assert!(distinct(&restored.masternode_lists) <= distinct(&engine.masternode_lists));
            assert!(entries_deduplicated(&restored.masternode_lists));
            assert_eq!(restored.snapshot().expect("encodes"), bytes);
        }
    }

    #[test]
    fn a_full_retention_window_snapshots_to_about_one_list() {
        let window = TestEngine::empty(Network::Mainnet).retention_window() as usize;
        let one_list = TestEngine::mainnet_list_chain(1, 1).snapshot().expect("encodes");
        let full_window = TestEngine::mainnet_list_chain(window, 1).snapshot().expect("encodes");

        assert!(
            full_window.len() < 2 * one_list.len(),
            "{window} lists take {} bytes, one list {}",
            full_window.len(),
            one_list.len()
        );
    }

    #[test]
    fn a_corrupt_or_foreign_snapshot_is_refused() {
        let engine = chain_engine();
        let bytes = engine.snapshot().expect("encodes");
        let decode = |network, bytes: &[u8]| {
            TestEngine::from_snapshot(network, engine.headers(), bytes).map(|_| ())
        };
        let header = [&MAGIC[..], &[VERSION]].concat();

        assert!(decode(Network::Mainnet, &bytes).is_ok());
        assert!(decode(Network::Testnet, &bytes).is_err());
        assert!(decode(Network::Mainnet, &[]).is_err());
        assert!(decode(Network::Mainnet, &[&b"DMLX"[..], &bytes[MAGIC.len()..]].concat()).is_err());
        assert!(decode(
            Network::Mainnet,
            &[&MAGIC[..], &[VERSION + 1], &bytes[MAGIC.len() + 1..]].concat()
        )
        .is_err());
        assert!(decode(Network::Mainnet, &[&bytes[..], &[0]].concat()).is_err());
        assert!(decode(Network::Mainnet, &bytes[..bytes.len() / 2]).is_err());

        // Mainnet, then an entry count of 2^60 that bincode would preallocate.
        let huge_entry_count = [&header[..], &[0, 253, 0, 0, 0, 0, 0, 0, 0, 0x10]].concat();
        assert!(matches!(
            decode(Network::Mainnet, &huge_entry_count),
            Err(DecodeError::LimitExceeded)
        ));
    }
}
