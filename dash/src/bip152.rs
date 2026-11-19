// SPDX-License-Identifier: CC0-1.0

//! BIP152 Compact Blocks
//!
//! Implementation of compact blocks data structure and algorithms.
//!

use core::convert::{TryFrom, TryInto};
use core::{convert, fmt};
use std::error;

use hashes::{sha256, siphash24};
use internals::{impl_array_newtype, impl_bytes_newtype};

use crate::consensus::encode::{self, Decodable, Encodable, VarInt};
use crate::internal_macros::impl_consensus_encoding;
use crate::prelude::*;
use crate::{Block, BlockHash, Transaction, block, io};

/// A BIP-152 error
#[derive(Clone, PartialEq, Eq, Debug, Copy, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Error {
    /// An unknown version number was used.
    UnknownVersion,
    /// The prefill slice provided was invalid.
    InvalidPrefill,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownVersion => write!(f, "an unknown version number was used"),
            Error::InvalidPrefill => write!(f, "the prefill slice provided was invalid"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            UnknownVersion | InvalidPrefill => None,
        }
    }
}

/// A [PrefilledTransaction] structure is used in [HeaderAndShortIds] to
/// provide a list of a few transactions explicitly.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct PrefilledTransaction {
    /// The index of the transaction in the block.
    ///
    /// This field is differentially encoded relative to the previous
    /// prefilled transaction as described as follows:
    ///
    /// > Several uses of CompactSize below are "differentially encoded". For
    /// > these, instead of using raw indexes, the number encoded is the
    /// > difference between the current index and the previous index, minus one.
    /// > For example, a first index of 0 implies a real index of 0, a second
    /// > index of 0 thereafter refers to a real index of 1, etc.
    pub idx: u16,
    /// The actual transaction.
    pub tx: Transaction,
}

impl convert::AsRef<Transaction> for PrefilledTransaction {
    fn as_ref(&self) -> &Transaction {
        &self.tx
    }
}

impl Encodable for PrefilledTransaction {
    #[inline]
    fn consensus_encode<S: io::Write + ?Sized>(&self, mut s: &mut S) -> Result<usize, io::Error> {
        Ok(VarInt(self.idx as u64).consensus_encode(&mut s)? + self.tx.consensus_encode(&mut s)?)
    }
}

impl Decodable for PrefilledTransaction {
    #[inline]
    fn consensus_decode<D: io::Read + ?Sized>(
        mut d: &mut D,
    ) -> Result<PrefilledTransaction, encode::Error> {
        let idx = encode::read_compact_size_len(&mut d)?;
        let idx = u16::try_from(idx)
            .map_err(|_| encode::Error::ParseFailed("BIP152 prefilled tx index out of bounds"))?;
        let tx = Transaction::consensus_decode(&mut d)?;
        Ok(PrefilledTransaction {
            idx,
            tx,
        })
    }
}

/// Short transaction IDs are used to represent a transaction without sending a full 256-bit hash.
#[derive(PartialEq, Eq, Clone, Copy, Hash, Default, PartialOrd, Ord)]
pub struct ShortId([u8; 6]);
impl_array_newtype!(ShortId, u8, 6);
impl_bytes_newtype!(ShortId, 6);

impl ShortId {
    /// Calculate the SipHash24 keys used to calculate short IDs.
    pub fn calculate_siphash_keys(header: &block::Header, nonce: u64) -> (u64, u64) {
        // 1. single-SHA256 hashing the block header with the nonce appended (in little-endian)
        let h = {
            let mut engine = sha256::Hash::engine();
            header.consensus_encode(&mut engine).expect("engines don't error");
            nonce.consensus_encode(&mut engine).expect("engines don't error");
            sha256::Hash::from_engine(engine).to_byte_array()
        };

        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        (
            u64::from_le_bytes(h[0..8].try_into().expect("8 byte slice")),
            u64::from_le_bytes(h[8..16].try_into().expect("8 byte slice")),
        )
    }

    /// Calculate the short ID with the given (w)txid and using the provided SipHash keys.
    pub fn with_siphash_keys<T: AsRef<[u8]>>(txid: &T, siphash_keys: (u64, u64)) -> ShortId {
        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        let hash = siphash24::siphash(siphash_keys.0, siphash_keys.1, txid.as_ref());

        // 3. Dropping the 2 most significant bytes from the SipHash output to make it 6 bytes.
        let mut id = ShortId([0; 6]);
        id.0.copy_from_slice(&hash.to_le_bytes()[0..6]);
        id
    }
}

impl Encodable for ShortId {
    #[inline]
    fn consensus_encode<S: io::Write + ?Sized>(&self, s: &mut S) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for ShortId {
    #[inline]
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<ShortId, encode::Error> {
        Ok(ShortId(Decodable::consensus_decode(d)?))
    }
}

/// A [HeaderAndShortIds] structure is used to relay a block header, the short
/// transactions IDs used for matching already-available transactions, and a
/// select few transactions which we expect a peer may be missing.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct HeaderAndShortIds {
    /// The header of the block being provided.
    pub header: block::Header,
    ///  A nonce for use in short transaction ID calculations.
    pub nonce: u64,
    ///  The short transaction IDs calculated from the transactions
    ///  which were not provided explicitly in prefilled_txs.
    pub short_ids: Vec<ShortId>,
    ///  Used to provide the coinbase transaction and a select few
    ///  which we expect a peer may be missing.
    pub prefilled_txs: Vec<PrefilledTransaction>,
}

impl Encodable for HeaderAndShortIds {
    #[inline]
    fn consensus_encode<S: io::Write + ?Sized>(&self, s: &mut S) -> Result<usize, io::Error> {
        let mut len = self.header.consensus_encode(s)?;
        len += self.nonce.consensus_encode(s)?;
        len += self.short_ids.consensus_encode(s)?;
        len += self.prefilled_txs.consensus_encode(s)?;
        Ok(len)
    }
}

impl Decodable for HeaderAndShortIds {
    /// Refuses more than [`u16::MAX`] short IDs and prefilled transactions together, because
    /// every transaction in a compact block has a 16-bit index.
    #[inline]
    fn consensus_decode_from_finite_reader<D: io::Read + ?Sized>(
        d: &mut D,
    ) -> Result<HeaderAndShortIds, encode::Error> {
        let compact = HeaderAndShortIds {
            header: Decodable::consensus_decode_from_finite_reader(d)?,
            nonce: Decodable::consensus_decode_from_finite_reader(d)?,
            short_ids: Decodable::consensus_decode_from_finite_reader(d)?,
            prefilled_txs: Decodable::consensus_decode_from_finite_reader(d)?,
        };
        if compact.short_ids.len() + compact.prefilled_txs.len() > usize::from(u16::MAX) {
            return Err(encode::Error::ParseFailed("indexes overflowed 16 bits"));
        }
        Ok(compact)
    }
}

impl HeaderAndShortIds {
    /// Create a new [HeaderAndShortIds] from a full block.
    ///
    /// The version number must be 1, the only compact block version Dash Core supports.
    ///
    /// The `prefill` slice indicates which transactions should be prefilled in
    /// the block. It should contain the indexes in the block of the txs to
    /// prefill. It must be ordered. 0 should not be included as the
    /// coinbase tx is always prefilled.
    ///
    /// > Nodes SHOULD NOT use the same nonce across multiple different blocks.
    pub fn from_block(
        block: &Block,
        nonce: u64,
        version: u32,
        mut prefill: &[usize],
    ) -> Result<HeaderAndShortIds, Error> {
        if version != 1 {
            return Err(Error::UnknownVersion);
        }

        let siphash_keys = ShortId::calculate_siphash_keys(&block.header, nonce);

        let mut prefilled = Vec::with_capacity(prefill.len() + 1); // +1 for coinbase tx
        let mut short_ids = Vec::with_capacity(block.txdata.len() - prefill.len());
        let mut last_prefill = 0;
        for (idx, tx) in block.txdata.iter().enumerate() {
            // Check if we should prefill this tx.
            let prefill_tx = if prefill.first() == Some(&idx) {
                prefill = &prefill[1..];
                true
            } else {
                idx == 0 // Always prefill coinbase.
            };

            if prefill_tx {
                let diff_idx = idx - last_prefill;
                last_prefill = idx + 1;
                prefilled.push(PrefilledTransaction {
                    idx: diff_idx as u16,
                    // As encoded in "tx" messages sent in response to getdata MSG_TX.
                    tx: {
                        let mut no_witness = tx.clone();
                        no_witness.input.iter_mut().for_each(|i| i.witness.clear());
                        no_witness
                    },
                });
            } else {
                short_ids.push(ShortId::with_siphash_keys(
                    // Dash Core hashes the full serialization (`GetInstanceHash()`), which
                    // differs from the txid for version 2+ asset unlocks; its mempool is
                    // indexed the same way.
                    &tx.instance_hash().to_raw_hash(),
                    siphash_keys,
                ));
            }
        }

        if !prefill.is_empty() {
            return Err(Error::InvalidPrefill);
        }

        Ok(HeaderAndShortIds {
            header: block.header,
            nonce,
            // Provide coinbase prefilled.
            prefilled_txs: prefilled,
            short_ids,
        })
    }
}

/// A [BlockTransactionsRequest] structure is used to list transaction indexes
/// in a block being requested.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct BlockTransactionsRequest {
    ///  The blockhash of the block which the transactions being requested are in.
    pub block_hash: BlockHash,
    ///  The indexes of the transactions being requested in the block.
    ///
    ///  They must be strictly increasing and at most [`u16::MAX`]. See
    ///  [`BlockTransactionsRequest::consensus_encode()`]. Serializing a request that breaks this
    ///  with [`serialize`](crate::consensus::encode::serialize) panics.
    pub indexes: Vec<u64>,
}

impl Encodable for BlockTransactionsRequest {
    /// Writes each index as `index - (previous + 1)`, and the first one as itself.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if an index is not above the one before it, or is
    /// above [`u16::MAX`].
    fn consensus_encode<S: io::Write + ?Sized>(&self, mut s: &mut S) -> Result<usize, io::Error> {
        let mut len = self.block_hash.consensus_encode(&mut s)?;
        // Manually encode indexes because they are differentially encoded VarInts.
        len += VarInt(self.indexes.len() as u64).consensus_encode(&mut s)?;
        let mut shift: u64 = 0;
        for idx in &self.indexes {
            if *idx < shift || *idx > u64::from(u16::MAX) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "differential value overflow",
                ));
            }
            len += VarInt(*idx - shift).consensus_encode(&mut s)?;
            shift = *idx + 1;
        }
        Ok(len)
    }
}

impl Decodable for BlockTransactionsRequest {
    /// Reads the count and each differential as a CompactSize of at most 32 MiB, and refuses an
    /// absolute index above [`u16::MAX`].
    fn consensus_decode<D: io::Read + ?Sized>(
        mut d: &mut D,
    ) -> Result<BlockTransactionsRequest, encode::Error> {
        let block_hash = BlockHash::consensus_decode(&mut d)?;
        let count = encode::read_compact_size_len(&mut d)?;
        // Indexes increase and stop at `u16::MAX`, so at most 65,536 are read before an error.
        let max_indexes = u64::from(u16::MAX) + 1;
        let mut indexes = Vec::with_capacity(count.min(max_indexes) as usize);
        let mut shift: u64 = 0;
        for _ in 0..count {
            let differential = encode::read_compact_size_len(&mut d)?;
            shift += differential;
            if shift > u64::from(u16::MAX) {
                return Err(encode::Error::ParseFailed("differential value overflow"));
            }
            indexes.push(shift);
            shift += 1;
        }
        Ok(BlockTransactionsRequest {
            block_hash,
            indexes,
        })
    }
}

/// A transaction index is requested that is out of range from the
/// corresponding block.
#[derive(Clone, PartialEq, Eq, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct TxIndexOutOfRangeError(u64);

impl fmt::Display for TxIndexOutOfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "a transaction index is requested that is \
            out of range from the corresponding block: {}",
            self.0,
        )
    }
}

impl error::Error for TxIndexOutOfRangeError {}

/// A [BlockTransactions] structure is used to provide some of the transactions
/// in a block, as requested.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct BlockTransactions {
    ///  The blockhash of the block which the transactions being provided are in.
    pub block_hash: BlockHash,
    ///  The transactions provided.
    pub transactions: Vec<Transaction>,
}
impl_consensus_encoding!(BlockTransactions, block_hash, transactions);

impl BlockTransactions {
    /// Construct a [BlockTransactions] from a [BlockTransactionsRequest] and
    /// the corresponding full [Block] by providing all requested transactions.
    pub fn from_request(
        request: &BlockTransactionsRequest,
        block: &Block,
    ) -> Result<BlockTransactions, TxIndexOutOfRangeError> {
        Ok(BlockTransactions {
            block_hash: request.block_hash,
            transactions: {
                let mut txs = Vec::with_capacity(request.indexes.len());
                for idx in &request.indexes {
                    if *idx >= block.txdata.len() as u64 {
                        return Err(TxIndexOutOfRangeError(*idx));
                    }
                    txs.push(block.txdata[*idx as usize].clone());
                }
                txs
            },
        })
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::blockdata::locktime::absolute;
    use crate::blockdata::script::ScriptBuf;
    use crate::blockdata::transaction::Transaction;
    use crate::blockdata::transaction::outpoint::OutPoint;
    use crate::blockdata::transaction::txin::TxIn;
    use crate::blockdata::transaction::txout::TxOut;
    use crate::blockdata::witness::Witness;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::hash_types::{TxMerkleNode, Txid};
    use crate::pow::CompactTarget;
    use hashes::sha256d;
    use test_case::test_case;

    fn dummy_tx(nonce: &[u8]) -> Transaction {
        Transaction {
            version: 1,
            lock_time: absolute::LockTime::from_consensus(2).to_consensus_u32(),
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_raw_hash(sha256d::Hash::hash(nonce)), 0),
                script_sig: ScriptBuf::new(),
                sequence: 1,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: 1,
                script_pubkey: ScriptBuf::new(),
            }],
            special_transaction_payload: None,
        }
    }

    fn dummy_block() -> Block {
        Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_raw_hash(sha256d::Hash::hash(&[1])),
                time: 2,
                bits: CompactTarget::from_consensus(3),
                nonce: 4,
            },
            txdata: vec![dummy_tx(&[2]), dummy_tx(&[3]), dummy_tx(&[4])],
        }
    }

    #[test]
    fn short_ids_use_the_instance_hash() {
        use crate::blockdata::transaction::special_transaction::TransactionPayload;

        // An asset unlock with a version 2 payload: its txid leaves out the quorum signature.
        let mut payload = vec![7u8; 145];
        payload[0] = 2;
        let mut unlock = dummy_tx(&[5]);
        unlock.version = 3;
        unlock.special_transaction_payload = Some(TransactionPayload::RawPayloadType(9, payload));
        assert_ne!(unlock.txid(), unlock.instance_hash());
        let mut block = dummy_block();
        block.txdata.push(unlock.clone());

        let compact = HeaderAndShortIds::from_block(&block, 42, 1, &[]).unwrap();
        let keys = ShortId::calculate_siphash_keys(&block.header, 42);
        let expected = ShortId::with_siphash_keys(&unlock.instance_hash().to_raw_hash(), keys);
        assert_eq!(compact.short_ids.last(), Some(&expected));
        assert_ne!(ShortId::with_siphash_keys(&unlock.txid().to_raw_hash(), keys), expected);
    }

    #[test]
    fn test_header_and_short_ids_from_block() {
        let block = dummy_block();

        let compact = HeaderAndShortIds::from_block(&block, 42, 1, &[]).unwrap();
        assert_eq!(compact.nonce, 42);
        assert_eq!(compact.short_ids.len(), 2);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].idx, 0);
        assert_eq!(&compact.prefilled_txs[0].tx, &block.txdata[0]);

        let compact = HeaderAndShortIds::from_block(&block, 42, 1, &[0, 1, 2]).unwrap();
        let idxs = compact.prefilled_txs.iter().map(|t| t.idx).collect::<Vec<_>>();
        assert_eq!(idxs, vec![0, 0, 0]);

        let compact = HeaderAndShortIds::from_block(&block, 42, 1, &[2]).unwrap();
        let idxs = compact.prefilled_txs.iter().map(|t| t.idx).collect::<Vec<_>>();
        assert_eq!(idxs, vec![0, 1]);
    }

    #[test_case(&[4, 0, 5, 1, 10] => matches Ok(v) if v == [0, 6, 8, 19]; "four indexes")]
    #[test_case(&[1, 0] => matches Ok(v) if v == [0]; "one index")]
    #[test_case(&[5, 0, 0, 0, 0, 0] => matches Ok(v) if v == [0, 1, 2, 3, 4]; "consecutive indexes")]
    #[test_case(&[3, 1, 1, 1] => matches Ok(v) if v == [1, 3, 5]; "gaps of one")]
    #[test_case(&[3, 0, 0, 253, 0, 1] => matches Ok(v) if v == [0, 1, 258]; "three-byte differential")]
    #[test_case(&[1, 0xfd, 0xff, 0xff] => matches Ok(v) if v == [65_535]; "absolute index u16 max")]
    #[test_case(&[[0xfe, 0, 0, 1, 0].as_slice(), &[0; 65_536]].concat()
        => matches Ok(v) if v.len() == 65_536 && v.last() == Some(&65_535); "65,536 indexes")]
    #[test_case(&[1, 0xfe, 0, 0, 1, 0]
        => matches Err(encode::Error::ParseFailed("differential value overflow")); "absolute index 65,536")]
    #[test_case(&[2, 0xfd, 0xff, 0xff, 0]
        => matches Err(encode::Error::ParseFailed("differential value overflow")); "index after u16 max")]
    #[test_case(&[[0xfe, 1, 0, 1, 0].as_slice(), &[0; 65_537]].concat()
        => matches Err(encode::Error::ParseFailed("differential value overflow")); "65,537 indexes")]
    #[test_case(&[0xfe, 0, 0, 0, 2, 0xfd, 0xff, 0xff, 0xfd, 0xff, 0xff]
        => matches Err(encode::Error::ParseFailed("differential value overflow")); "count of 32 MiB, second index above u16 max")]
    #[test_case(&[1, 0xfe, 0, 0, 0, 2]
        => matches Err(encode::Error::ParseFailed("differential value overflow")); "differential of 32 MiB")]
    #[test_case(&[0xfe, 1, 0, 0, 2]
        => matches Err(encode::Error::OversizedVectorAllocation { .. }); "count above 32 MiB")]
    #[test_case(&[1, 0xfe, 1, 0, 0, 2]
        => matches Err(encode::Error::OversizedVectorAllocation { .. }); "differential above 32 MiB")]
    #[test_case(&[2, 255, 254, 255, 255, 255, 255, 255, 255, 255, 0]
        => matches Err(encode::Error::OversizedVectorAllocation { .. }); "differential u64 max minus one")]
    #[test_case(&[1, 255, 255, 255, 255, 255, 255, 255, 255, 255]
        => matches Err(encode::Error::OversizedVectorAllocation { .. }); "differential u64 max")]
    #[test_case(&[0xfe, 0, 0, 0, 2] => matches Err(encode::Error::Io(_)); "count of 32 MiB, no indexes follow")]
    fn test_getblocktx_differential_encoding_de_and_serialization(
        encoded: &[u8],
    ) -> Result<Vec<u64>, encode::Error> {
        let mut raw = vec![0; 32];
        raw.extend_from_slice(encoded);
        let streamed = BlockTransactionsRequest::consensus_decode(&mut &raw[..]);
        let sliced = deserialize::<BlockTransactionsRequest>(&raw);
        assert_eq!(format!("{:?}", streamed), format!("{:?}", sliced));
        let request = streamed?;
        assert_eq!(serialize(&request), raw);
        Ok(request.indexes)
    }

    #[test]
    fn getblocktxn_encoding_refuses_indexes_not_increasing_or_above_u16() {
        for indexes in [
            vec![u64::MAX],
            vec![u64::MAX - 1],
            vec![65_536],
            vec![0, 65_536],
            vec![1, 0],
            vec![5, 5],
            vec![0, 3, 2],
        ] {
            let err = request(indexes.clone())
                .consensus_encode(&mut Vec::new())
                .expect_err("indexes must be refused");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{:?}", indexes);
        }
        for indexes in [vec![65_535], vec![0, 1], vec![1, 3, 65_535]] {
            let request = request(indexes);
            let raw = serialize(&request);
            assert_eq!(deserialize::<BlockTransactionsRequest>(&raw).unwrap(), request);
        }
    }

    fn request(indexes: Vec<u64>) -> BlockTransactionsRequest {
        BlockTransactionsRequest {
            block_hash: BlockHash::all_zeros(),
            indexes,
        }
    }

    #[test]
    fn prefilled_transaction_index_is_a_compact_size_bounded_by_u16() {
        let tx = serialize(&dummy_tx(&[7]));
        let with_index = |index: &[u8]| {
            let mut raw = index.to_vec();
            raw.extend_from_slice(&tx);
            raw
        };
        let ok = deserialize::<PrefilledTransaction>(&with_index(&[0xfd, 0xff, 0xff])).unwrap();
        assert_eq!(ok.idx, 65_535);
        let err = deserialize::<PrefilledTransaction>(&with_index(&[0xfe, 0x00, 0x00, 0x01, 0x00]))
            .expect_err("65,536 is above u16::MAX");
        assert!(matches!(
            err,
            encode::Error::ParseFailed("BIP152 prefilled tx index out of bounds")
        ));
        let err = deserialize::<PrefilledTransaction>(&with_index(&[0xfe, 0x01, 0x00, 0x00, 0x02]))
            .expect_err("index above 32 MiB");
        assert!(matches!(err, encode::Error::OversizedVectorAllocation { .. }), "{:?}", err);
    }

    #[test]
    fn compact_block_decoding_refuses_more_than_u16_transactions() {
        let block = dummy_block();
        let mut compact = HeaderAndShortIds::from_block(&block, 42, 1, &[]).unwrap();
        compact.short_ids = vec![ShortId([0; 6]); 65_534];
        let raw = serialize(&compact);
        assert_eq!(deserialize::<HeaderAndShortIds>(&raw).unwrap(), compact);
        assert_eq!(HeaderAndShortIds::consensus_decode(&mut &raw[..]).unwrap(), compact);

        compact.short_ids.push(ShortId([0; 6]));
        let raw = serialize(&compact);
        for err in [
            deserialize::<HeaderAndShortIds>(&raw).expect_err("65,536 transactions"),
            HeaderAndShortIds::consensus_decode(&mut &raw[..]).expect_err("65,536 transactions"),
        ] {
            assert!(matches!(err, encode::Error::ParseFailed("indexes overflowed 16 bits")));
        }
    }
}
