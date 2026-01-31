// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Updated for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash hash types.
//!
//! This module defines types for hashes used throughout the library. These
//! types are needed in order to avoid mixing data of the same hash format
//! (e.g. `SHA256d`) but of different meaning (such as transaction id, block
//! hash).
//!

#[rustfmt::skip]
macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl $crate::consensus::Encodable for $hashtype {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, $crate::io::Error> {
                self.0.consensus_encode(w)
            }
        }

        impl $crate::consensus::Decodable for $hashtype {
            fn consensus_decode<R: $crate::io::Read + ?Sized>(r: &mut R) -> Result<Self, $crate::consensus::encode::Error> {
                use $crate::hashes::Hash;
                Ok(Self::from_byte_array(<<$hashtype as $crate::hashes::Hash>::Bytes>::consensus_decode(r)?))
            }
        }
    };
}

#[rustfmt::skip]
macro_rules! impl_asref_push_bytes {
    ($($hashtype:ident),*) => {
        $(
            impl AsRef<$crate::blockdata::script::PushBytes> for $hashtype {
                fn as_ref(&self) -> &$crate::blockdata::script::PushBytes {
                    use $crate::hashes::Hash;
                    self.as_byte_array().into()
                }
            }

            impl From<$hashtype> for $crate::blockdata::script::PushBytesBuf {
                fn from(hash: $hashtype) -> Self {
                    use $crate::hashes::Hash;
                    hash.as_byte_array().into()
                }
            }
        )*
    };
}

// newtypes module is solely here so we can rustfmt::skip.
pub use newtypes::*;

mod newtypes {

    use core::str::FromStr;
    use std::cmp::Ordering;

    #[cfg(feature = "core-block-hash-use-x11")]
    use hashes::hash_x11;
    use hashes::hex::Error;
    use hashes::{Hash, hash_newtype, hash_newtype_no_ord, hash160, sha256, sha256d};

    use crate::alloc::string::ToString;
    use crate::prelude::String;
    use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

    #[cfg(feature = "core-block-hash-use-x11")]
    hash_newtype! {
        /// A dash block hash.
        pub struct BlockHash(hash_x11::Hash);
    }
    #[cfg(not(feature = "core-block-hash-use-x11"))]
    hash_newtype! {
        /// A dash block hash.
        pub struct BlockHash(sha256d::Hash);
    }

    hash_newtype! {
        /// A dash transaction hash/transaction ID.
        pub struct Txid(sha256d::Hash);

        /// A hash of a public key.
        pub struct PubkeyHash(hash160::Hash);
        /// A hash of Dash Script bytecode.
        pub struct ScriptHash(hash160::Hash);

        /// A hash of the Merkle tree branch or root for transactions
        pub struct TxMerkleNode(sha256d::Hash);
        /// XpubIdentifier as defined in BIP-32.
        pub struct XpubIdentifier(hash160::Hash);

        /// Filter hash, as defined in BIP-157
        pub struct FilterHash(sha256d::Hash);
        /// Filter header, as defined in BIP-157
        pub struct FilterHeader(sha256d::Hash);

        /// Dash Additions
        ///
        ///
        pub struct ChainLockHash(sha256d::Hash);
        pub struct InstantSendLockHash(sha256d::Hash);
        /// The merkle root of the masternode list
        #[hash_newtype(forward)]
        pub struct MerkleRootMasternodeList(sha256d::Hash);
        /// The merkle root of the quorums
        #[hash_newtype(forward)]
        pub struct MerkleRootQuorums(sha256d::Hash);
        /// A special transaction payload hash
        pub struct SpecialTransactionPayloadHash(sha256d::Hash);
        /// A hash of all transaction inputs
        pub struct InputsHash(sha256d::Hash);
        /// A hash of a quorum verification vector
        pub struct QuorumVVecHash(sha256d::Hash);
        /// A hash of a quorum signing request id
        pub struct QuorumSigningRequestId(sha256d::Hash);
        /// A hash of a quorum signing sign id
        pub struct QuorumSigningSignId(sha256d::Hash);
        /// ProTxHash is a pro-tx hash
        #[hash_newtype(forward)]
        pub struct ProTxHash(sha256d::Hash);
        pub struct ConfirmedHash(sha256d::Hash);
        pub struct ConfirmedHashHashedWithProRegTx(sha256::Hash);
        pub struct QuorumModifierHash(sha256d::Hash);
        pub struct QuorumEntryHash(sha256d::Hash);
        pub struct QuorumCommitmentHash(sha256d::Hash);

        pub struct Sha256dHash(sha256d::Hash);
        pub struct QuorumOrderingHash(sha256d::Hash);
    }

    hash_newtype_no_ord! {
        pub struct ScoreHash(sha256::Hash);
    }

    impl Ord for ScoreHash {
        fn cmp(&self, other: &Self) -> Ordering {
            let mut self_bytes = self.0.to_byte_array();
            let mut other_bytes = other.0.to_byte_array();

            self_bytes.reverse();
            other_bytes.reverse();

            self_bytes.cmp(&other_bytes)
        }
    }

    impl PartialOrd for ScoreHash {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    /// A hash used to identify a quorum
    pub type QuorumHash = BlockHash;

    /// A hash used to identity a cycle
    pub type CycleHash = BlockHash;

    impl_hashencode!(Txid);
    impl_hashencode!(BlockHash);

    impl_hashencode!(TxMerkleNode);

    impl_hashencode!(FilterHash);
    impl_hashencode!(FilterHeader);

    impl_hashencode!(ChainLockHash);
    impl_hashencode!(InstantSendLockHash);

    impl_hashencode!(MerkleRootMasternodeList);
    impl_hashencode!(MerkleRootQuorums);

    impl_hashencode!(SpecialTransactionPayloadHash);
    impl_hashencode!(InputsHash);

    impl_hashencode!(QuorumVVecHash);
    impl_hashencode!(QuorumSigningRequestId);
    impl_hashencode!(PubkeyHash);

    impl_hashencode!(ConfirmedHash);
    impl_hashencode!(ConfirmedHashHashedWithProRegTx);
    impl_hashencode!(QuorumModifierHash);
    impl_hashencode!(QuorumEntryHash);
    impl_hashencode!(QuorumCommitmentHash);
    impl_hashencode!(ScoreHash);
    impl_hashencode!(QuorumOrderingHash);
    impl_hashencode!(ProTxHash);
    impl_hashencode!(Sha256dHash);

    impl_asref_push_bytes!(PubkeyHash, ScriptHash);

    impl Txid {
        /// Create a Txid from a string
        pub fn from_hex(s: &str) -> Result<Txid, Error> {
            Ok(Self(sha256d::Hash::from_str(s)?))
        }

        /// Convert a Txid to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }
    }

    impl ProTxHash {
        /// Create a ProTxHash from a string
        pub fn from_hex(s: &str) -> Result<ProTxHash, Error> {
            Ok(Self(sha256d::Hash::from_str(s)?))
        }

        /// Convert a ProTxHash to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }
    }

    impl ScoreHash {
        /// Create a ScoreHash from a string
        pub fn from_hex(s: &str) -> Result<ScoreHash, Error> {
            Ok(Self(sha256::Hash::from_str(s)?))
        }

        /// Convert a ScoreHash to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }

        /// Creates a score based on the optional confirmed hash and the quorum modifier.
        ///
        /// # Arguments
        /// * `confirmed_hash_hashed_with_pro_reg_tx` - An optional hash combining the confirmed hash and ProRegTx.
        /// * `modifier` - A quorum modifier hash used in the calculation.
        ///
        /// # Returns
        /// * A hashed score derived from the input values.
        pub fn create_score(
            confirmed_hash_hashed_with_pro_reg_tx: Option<ConfirmedHashHashedWithProRegTx>,
            modifier: QuorumModifierHash,
        ) -> Self {
            let mut bytes = vec![];
            if let Some(confirmed_hash_hashed_with_pro_reg_tx) =
                confirmed_hash_hashed_with_pro_reg_tx
            {
                bytes.append(&mut confirmed_hash_hashed_with_pro_reg_tx.to_byte_array().to_vec());
            }
            bytes.append(&mut modifier.to_byte_array().to_vec());
            Self::hash(bytes.as_slice())
        }
    }

    impl QuorumOrderingHash {
        /// Create a ScoreHash from a string
        pub fn from_hex(s: &str) -> Result<QuorumOrderingHash, Error> {
            Ok(Self(sha256d::Hash::from_str(s)?))
        }

        /// Convert a ScoreHash to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }

        /// Creates an ordering hash based on the quorum and request id.
        ///
        /// # Arguments
        /// * `quorum` - The quorum to create the ordering hash.
        /// * `request_id` - The request id.
        ///
        /// # Returns
        /// * A hashed score derived from the input values.
        pub fn create(quorum: &QuorumEntry, request_id: &QuorumSigningRequestId) -> Self {
            let mut bytes = vec![quorum.llmq_type as u8];
            bytes.extend_from_slice(quorum.quorum_hash.as_byte_array());
            bytes.extend_from_slice(request_id.as_byte_array());
            Self::hash(bytes.as_slice())
        }
    }

    impl Default for ConfirmedHash {
        fn default() -> Self {
            ConfirmedHash::from_byte_array([0; 32])
        }
    }

    impl ConfirmedHash {
        /// Create a ConfirmedHash from a string
        pub fn from_hex(s: &str) -> Result<ConfirmedHash, Error> {
            Ok(Self(sha256d::Hash::from_str(s)?))
        }

        /// Convert a ConfirmedHash to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }
    }

    impl ConfirmedHashHashedWithProRegTx {
        /// Create a ConfirmedHash from a string
        pub fn from_hex(s: &str) -> Result<ConfirmedHashHashedWithProRegTx, Error> {
            Ok(Self(sha256::Hash::from_str(s)?))
        }

        /// Convert a ConfirmedHash to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }

        /// Hashes the members
        pub fn hash_members(pro_tx_hash: &ProTxHash, confirmed_hash: &ConfirmedHash) -> Self {
            Self::hash(&[pro_tx_hash.to_byte_array(), confirmed_hash.to_byte_array()].concat())
        }
        /// Hashes the members
        pub fn hash_members_confirmed_hash_optional(
            pro_tx_hash: &ProTxHash,
            confirmed_hash: Option<&ConfirmedHash>,
        ) -> Option<Self> {
            confirmed_hash.map(|confirmed_hash| {
                Self::hash(&[pro_tx_hash.to_byte_array(), confirmed_hash.to_byte_array()].concat())
            })
        }
    }

    impl Sha256dHash {
        /// Create a Sha256dHash from a string
        pub fn from_hex(s: &str) -> Result<Sha256dHash, Error> {
            Ok(Self(sha256d::Hash::from_str(s)?))
        }

        /// Convert a ConfirmedHash to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }
    }

    impl InputsHash {
        /// Create an InputsHash from a string
        pub fn from_hex(s: &str) -> Result<InputsHash, Error> {
            Ok(Self(sha256d::Hash::from_str(s)?))
        }

        /// Convert an InputsHash to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }
    }

    impl SpecialTransactionPayloadHash {
        /// Create a SpecialTransactionPayloadHash from a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }
    }

    impl PubkeyHash {
        /// Create a PubkeyHash from a string
        pub fn from_hex(s: &str) -> Result<PubkeyHash, Error> {
            Ok(Self(hash160::Hash::from_str(s)?))
        }

        /// Convert a PubkeyHash to a string
        pub fn to_hex(&self) -> String {
            self.0.to_string()
        }
    }
}
