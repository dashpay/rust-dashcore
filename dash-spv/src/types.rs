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

/// Mempool balance information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolBalance {
    /// Pending balance from mempool transactions (not InstantLocked).
    pub pending: dashcore::Amount,

    /// Pending balance from InstantLocked mempool transactions.
    pub pending_instant: dashcore::Amount,
}

/// Reason for removing a transaction from mempool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MempoolRemovalReason {
    /// Transaction expired (exceeded timeout).
    Expired,
    /// Transaction was replaced by another transaction.
    Replaced {
        by_txid: Txid,
    },
    /// Transaction was double-spent.
    DoubleSpent {
        conflicting_txid: Txid,
    },
    /// Transaction was included in a block.
    Confirmed,
    /// Manual removal (e.g., user action).
    Manual,
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

/// Mempool state tracking.
#[derive(Debug, Clone, Default)]
pub struct MempoolState {
    /// Currently tracked unconfirmed transactions.
    pub transactions: std::collections::HashMap<Txid, UnconfirmedTransaction>,
    /// Recent sends (txid -> timestamp) for Selective strategy.
    pub recent_sends: std::collections::HashMap<Txid, Instant>,
    /// Total pending balance change.
    pub pending_balance: i64,
    /// Total pending InstantSend balance.
    pub pending_instant_balance: i64,
}

impl MempoolState {
    /// Add a transaction to mempool.
    pub fn add_transaction(&mut self, tx: UnconfirmedTransaction) {
        if tx.is_instant_send {
            self.pending_instant_balance += tx.net_amount;
        } else {
            self.pending_balance += tx.net_amount;
        }

        let txid = tx.txid();
        self.transactions.insert(txid, tx);
    }

    /// Remove a transaction from mempool.
    pub fn remove_transaction(&mut self, txid: &Txid) -> Option<UnconfirmedTransaction> {
        if let Some(tx) = self.transactions.remove(txid) {
            if tx.is_instant_send {
                self.pending_instant_balance -= tx.net_amount;
            } else {
                self.pending_balance -= tx.net_amount;
            }
            Some(tx)
        } else {
            None
        }
    }

    /// Prune expired transactions.
    pub fn prune_expired(&mut self, timeout: Duration) -> Vec<Txid> {
        let mut expired = Vec::new();

        self.transactions.retain(|txid, tx| {
            if tx.is_expired(timeout) {
                expired.push(*txid);
                if tx.is_instant_send {
                    self.pending_instant_balance -= tx.net_amount;
                } else {
                    self.pending_balance -= tx.net_amount;
                }
                false
            } else {
                true
            }
        });

        // Also prune old recent sends
        if let Some(cutoff) = Instant::now().checked_sub(timeout) {
            self.recent_sends.retain(|_, &mut timestamp| timestamp > cutoff);
        }

        expired
    }

    /// Record a recent send.
    pub fn record_send(&mut self, txid: Txid) {
        self.recent_sends.insert(txid, Instant::now());
    }

    /// Check if a transaction was recently sent.
    pub fn is_recent_send(&self, txid: &Txid, window: Duration) -> bool {
        self.recent_sends.get(txid).map(|&timestamp| timestamp.elapsed() < window).unwrap_or(false)
    }

    /// Get total pending balance (regular + InstantSend).
    pub fn total_pending_balance(&self) -> i64 {
        self.pending_balance + self.pending_instant_balance
    }
}
