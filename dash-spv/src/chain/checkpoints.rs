//! Checkpoints are known blocks a client can start syncing from instead of genesis.
//!
//! Each checkpoint holds its block header and the [`CHECKPOINT_HEADERS`] - 1 headers before
//! it, so the difficulty of the blocks after it can be checked from the first one on. The
//! checkpoints of mainnet and testnet are generated from the network by the
//! `generate-checkpoints` binary into `checkpoints/<network>.json`, which `build.rs` encodes
//! for embedding.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::LazyLock;

use dashcore::block::Header;
use dashcore::consensus::{encode, Decodable, Encodable};
use dashcore::{BlockHash, Network};

use crate::types::HashedBlockHeader;

/// Headers each checkpoint holds, the checkpoint block last.
pub const CHECKPOINT_HEADERS: usize = 25;

const MAINNET_CHECKPOINTS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mainnet.checkpoints"));
const TESTNET_CHECKPOINTS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/testnet.checkpoints"));

// The embedded files are decoded and validated by the tests.
static MAINNET: LazyLock<CheckpointManager> = LazyLock::new(|| {
    CheckpointManager::new(
        decode_checkpoints(MAINNET_CHECKPOINTS).expect("embedded checkpoints must decode"),
    )
});
static TESTNET: LazyLock<CheckpointManager> = LazyLock::new(|| {
    CheckpointManager::new(
        decode_checkpoints(TESTNET_CHECKPOINTS).expect("embedded checkpoints must decode"),
    )
});
static NO_CHECKPOINTS: CheckpointManager = CheckpointManager {
    checkpoints: BTreeMap::new(),
};

/// A known block and the [`CHECKPOINT_HEADERS`] - 1 headers before it.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    height: u32,
    headers: Vec<HashedBlockHeader>,
}

impl Checkpoint {
    /// A checkpoint at `height` from `headers`, the last of which is the block at `height`.
    ///
    /// Returns `None` unless there are exactly [`CHECKPOINT_HEADERS`] headers that fit
    /// below `height`.
    pub fn new(height: u32, headers: Vec<HashedBlockHeader>) -> Option<Self> {
        let fits = headers.len() == CHECKPOINT_HEADERS && height >= CHECKPOINT_HEADERS as u32 - 1;

        fits.then_some(Self {
            height,
            headers,
        })
    }

    /// Height of the checkpoint block.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Hash of the checkpoint block.
    pub fn hash(&self) -> &BlockHash {
        self.header().hash()
    }

    /// Header of the checkpoint block.
    pub fn header(&self) -> &HashedBlockHeader {
        &self.headers[CHECKPOINT_HEADERS - 1]
    }

    /// All the headers of the checkpoint, oldest first, from [`Self::start_height`].
    pub fn headers(&self) -> &[HashedBlockHeader] {
        &self.headers
    }

    /// Height of the first of [`Self::headers`].
    pub fn start_height(&self) -> u32 {
        self.height - (CHECKPOINT_HEADERS as u32 - 1)
    }
}

impl Encodable for Checkpoint {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = self.height.consensus_encode(writer)?;
        for header in &self.headers {
            len += header.header().consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl Decodable for Checkpoint {
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        let height = u32::consensus_decode(reader)?;
        let headers = (0..CHECKPOINT_HEADERS)
            .map(|_| Header::consensus_decode(reader).map(HashedBlockHeader::from))
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(height, headers)
            .ok_or(encode::Error::ParseFailed("checkpoint height below its headers"))
    }
}

/// Decode the checkpoints encoded one after another in `bytes`.
fn decode_checkpoints(mut bytes: &[u8]) -> Result<Vec<Checkpoint>, encode::Error> {
    let mut checkpoints = Vec::new();
    while !bytes.is_empty() {
        checkpoints.push(Checkpoint::consensus_decode(&mut bytes)?);
    }
    Ok(checkpoints)
}

/// The checkpoints of a network, by height.
pub struct CheckpointManager {
    checkpoints: BTreeMap<u32, Checkpoint>,
}

impl CheckpointManager {
    /// The checkpoints embedded for `network`. Networks without any (devnet, regtest)
    /// have none.
    pub fn for_network(network: Network) -> &'static Self {
        match network {
            Network::Mainnet => &MAINNET,
            Network::Testnet => &TESTNET,
            _ => &NO_CHECKPOINTS,
        }
    }

    fn new(checkpoints: Vec<Checkpoint>) -> Self {
        Self {
            checkpoints: checkpoints
                .into_iter()
                .map(|checkpoint| (checkpoint.height(), checkpoint))
                .collect(),
        }
    }

    /// The highest checkpoint at or below `height`.
    pub fn last_checkpoint_before_height(&self, height: u32) -> Option<&Checkpoint> {
        self.checkpoints.range(..=height).next_back().map(|(_, checkpoint)| checkpoint)
    }

    /// All the checkpoints, lowest first.
    pub fn checkpoints(&self) -> impl Iterator<Item = &Checkpoint> {
        self.checkpoints.values()
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;
    use crate::validation::{BlockHeaderValidator, Validator};

    fn checkpoints() -> Vec<Checkpoint> {
        [50_000, 100_000, 150_000].map(Checkpoint::dummy).to_vec()
    }

    #[test]
    fn new_requires_exactly_the_checkpoint_headers() {
        let headers = Checkpoint::dummy(100).headers().to_vec();

        assert!(Checkpoint::new(100, headers[1..].to_vec()).is_none());
        assert!(Checkpoint::new(23, headers.clone()).is_none());
        assert!(Checkpoint::new(24, headers).is_some());
    }

    #[test]
    fn checkpoint_block_is_the_last_header() {
        let checkpoint = Checkpoint::dummy(100);

        assert_eq!(checkpoint.start_height(), 76);
        assert_eq!(checkpoint.hash(), checkpoint.headers()[CHECKPOINT_HEADERS - 1].hash());
    }

    #[test]
    fn encoding_round_trips() {
        let checkpoints = checkpoints();
        let mut bytes = Vec::new();
        for checkpoint in &checkpoints {
            checkpoint.consensus_encode(&mut bytes).unwrap();
        }

        let decoded = decode_checkpoints(&bytes).unwrap();

        assert_eq!(decoded.len(), checkpoints.len());
        for (decoded, checkpoint) in decoded.iter().zip(&checkpoints) {
            assert_eq!(decoded.height(), checkpoint.height());
            assert_eq!(decoded.hash(), checkpoint.hash());
        }
    }

    #[test]
    fn truncated_encoding_is_rejected() {
        let mut bytes = Vec::new();
        Checkpoint::dummy(100).consensus_encode(&mut bytes).unwrap();
        bytes.pop();

        assert!(decode_checkpoints(&bytes).is_err());
    }

    #[test_case(0, None)]
    #[test_case(49_999, None)]
    #[test_case(50_000, Some(50_000))]
    #[test_case(120_000, Some(100_000))]
    #[test_case(u32::MAX, Some(150_000))]
    fn last_checkpoint_before_height(height: u32, expected: Option<u32>) {
        let manager = CheckpointManager::new(checkpoints());

        assert_eq!(manager.last_checkpoint_before_height(height).map(Checkpoint::height), expected);
    }

    #[test]
    fn checkpoints_are_sorted_by_height() {
        let mut unsorted = checkpoints();
        unsorted.reverse();
        let manager = CheckpointManager::new(unsorted);

        let heights: Vec<u32> = manager.checkpoints().map(Checkpoint::height).collect();
        assert_eq!(heights, [50_000, 100_000, 150_000]);
    }

    #[test_case(Network::Mainnet)]
    #[test_case(Network::Testnet)]
    fn embedded_checkpoints_are_valid(network: Network) {
        let manager = CheckpointManager::for_network(network);
        assert!(manager.checkpoints().next().is_some(), "{network} must have checkpoints");

        for checkpoint in manager.checkpoints() {
            BlockHeaderValidator::new().validate(checkpoint.headers()).unwrap_or_else(|e| {
                panic!("checkpoint {} of {network} is invalid: {e}", checkpoint.height())
            });
        }
    }

    // Hand-written, this checkpoint had the wrong time and bits.
    #[test]
    fn mainnet_checkpoint_750000_is_the_real_block() {
        let manager = CheckpointManager::for_network(Network::Mainnet);
        let checkpoint = manager.last_checkpoint_before_height(750_000).expect("checkpoint 750000");
        let header = checkpoint.header().header();

        assert_eq!(
            checkpoint.hash().to_string(),
            "00000000000000b4181bbbdddbae464ce11fede5d0292fb63fdede1e7c8ab21c"
        );
        assert_eq!(header.time, 1507424630);
        assert_eq!(header.bits.to_consensus(), 0x1a027884);
    }

    #[test_case(Network::Devnet)]
    #[test_case(Network::Regtest)]
    fn networks_without_embedded_checkpoints(network: Network) {
        assert!(CheckpointManager::for_network(network).checkpoints().next().is_none());
    }
}
