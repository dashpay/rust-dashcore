//! Common type definitions for the Dash SPV client.

use std::time::{Duration, Instant};

use dashcore::{
    block::Header as BlockHeader,
    consensus::{Decodable, Encodable},
    Amount, Block, BlockHash, Transaction, Txid,
};
use serde::{Deserialize, Serialize};

/// A block header with its cached hash to avoid expensive X11 recomputation.
///
/// During header sync, each header's hash is computed multiple times:
/// - For existence checks in storage
/// - For validation logging
/// - For chain continuity validation
/// - For storage indexing
///
/// This wrapper caches the hash after first computation, providing ~4-6x reduction
/// in X11 hashing operations per header.
#[derive(Debug, Clone)]
pub struct HashedBlockHeader {
    /// The block header
    header: BlockHeader,
    hash: BlockHash,
}

impl HashedBlockHeader {
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }
}

impl From<BlockHeader> for HashedBlockHeader {
    fn from(header: BlockHeader) -> Self {
        Self {
            header,
            hash: header.block_hash(),
        }
    }
}

impl From<&BlockHeader> for HashedBlockHeader {
    fn from(header: &BlockHeader) -> Self {
        Self {
            header: *header,
            hash: header.block_hash(),
        }
    }
}

impl PartialEq for HashedBlockHeader {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
    }
}

impl Encodable for HashedBlockHeader {
    #[inline]
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        Ok(self.header().consensus_encode(writer)? + self.hash().consensus_encode(writer)?)
    }
}

impl Decodable for HashedBlockHeader {
    #[inline]
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, dashcore::consensus::encode::Error> {
        Ok(Self {
            header: BlockHeader::consensus_decode(reader)?,
            hash: BlockHash::consensus_decode(reader)?,
        })
    }
}

/// A block with its cached hash to avoid expensive X11 recomputation.
#[derive(Debug, Clone)]
pub struct HashedBlock {
    hash: BlockHash,
    block: Block,
}

impl HashedBlock {
    /// Get a reference to the cached block hash.
    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }

    /// Get a reference to the block.
    pub fn block(&self) -> &Block {
        &self.block
    }
}

impl From<Block> for HashedBlock {
    fn from(block: Block) -> Self {
        Self {
            hash: block.block_hash(),
            block,
        }
    }
}

impl From<&Block> for HashedBlock {
    fn from(block: &Block) -> Self {
        Self {
            hash: block.block_hash(),
            block: block.clone(),
        }
    }
}

impl PartialEq for HashedBlock {
    fn eq(&self, other: &Self) -> bool {
        self.block == other.block
    }
}

impl Encodable for HashedBlock {
    #[inline]
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        Ok(self.hash().consensus_encode(writer)? + self.block().consensus_encode(writer)?)
    }
}

impl Decodable for HashedBlock {
    #[inline]
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, dashcore::consensus::encode::Error> {
        Ok(Self {
            hash: BlockHash::consensus_decode(reader)?,
            block: Block::consensus_decode(reader)?,
        })
    }
}

/// Unique identifier for a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub u64);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer_{}", self.0)
    }
}

/// Validation mode for the SPV client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ValidationMode {
    /// Validate only basic structure and signatures.
    Basic,

    /// Validate proof of work and chain rules.
    #[default]
    Full,

    /// Skip most validation (useful for testing).
    None,
}

/// Filter match result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterMatch {
    /// Block hash where match was found.
    pub block_hash: BlockHash,

    /// Block height.
    pub height: u32,

    /// Whether we requested the full block.
    pub block_requested: bool,
}

/// Unconfirmed transaction in mempool.
#[derive(Debug, Clone)]
pub struct UnconfirmedTransaction {
    /// The transaction itself.
    pub transaction: Transaction,
    /// Time when first seen.
    pub first_seen: Instant,
    /// Fee paid by the transaction.
    pub fee: Amount,
    /// Size of transaction in bytes.
    pub size: usize,
    /// Whether this is an InstantSend transaction.
    pub is_instant_send: bool,
    /// Whether this transaction was sent by our wallet.
    pub is_outgoing: bool,
    /// Addresses involved (for quick filtering).
    pub addresses: Vec<dashcore::Address>,
    /// Net amount change for our wallet.
    pub net_amount: i64,
}

impl UnconfirmedTransaction {
    /// Create a new unconfirmed transaction.
    pub fn new(
        transaction: Transaction,
        fee: Amount,
        is_instant_send: bool,
        is_outgoing: bool,
        addresses: Vec<dashcore::Address>,
        net_amount: i64,
    ) -> Self {
        let size = dashcore::consensus::encode::serialize(&transaction).len();

        Self {
            transaction,
            first_seen: Instant::now(),
            fee,
            size,
            is_instant_send,
            is_outgoing,
            addresses,
            net_amount,
        }
    }

    /// Get the transaction ID.
    pub fn txid(&self) -> Txid {
        self.transaction.txid()
    }

    /// Check if transaction has expired.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.first_seen.elapsed() > timeout
    }

    /// Get fee rate in satoshis per byte.
    pub fn fee_rate(&self) -> f64 {
        if self.size == 0 {
            return 0.0;
        }
        self.fee.to_sat() as f64 / self.size as f64
    }
}
