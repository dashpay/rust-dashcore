// Rust Dash Library
// Written for Dash in 2022 by
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

//! Dash Credit Withdrawal Special Transaction.
//!
//! The credit withdrawal special transaction is used to withdraw from the asset lock credit pool.
//!
//!
//! It is defined in DIPX [dip-000X.md](https://github.com/dashpay/dips/blob/master/dip-000X.md) as follows:
//!
//!
//! The special transaction type used for CrWithTx Transactions is 9.

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;

use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::blockdata::transaction::special_transaction::asset_unlock::request_info::AssetUnlockRequestInfo;
use crate::blockdata::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload;
use crate::bls_sig_utils::BLSSignature;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::SpecialTransactionPayloadHash;
use crate::transaction::special_transaction::TransactionPayload;
use crate::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBaseTransactionInfo;
use crate::{Transaction, TxIn, consensus, io};

// Asset unlock tx size is constant since it has zero inputs and single output only
pub const ASSET_UNLOCK_TX_SIZE: usize = 190;

/// A Credit Withdrawal payload. This is contained as the payload of a credit withdrawal special
/// transaction.
/// The Credit Withdrawal Special transaction and this payload is described in the Asset Lock DIP2X
/// (todo:update this).
/// The Credit Withdrawal Payload is signed by a quorum.
///
/// Transaction using it have no inputs. Hence the proof of validity lies solely on the BLS signature.
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AssetUnlockPayload {
    /// The base information about the asset unlock. This base information is the information that
    /// should be put into a queue.
    pub base: AssetUnlockBasePayload,
    /// The request information. This should be added to the unlock transaction as it is being sent
    /// to be signed.
    pub request_info: AssetUnlockRequestInfo,
    /// The threshold signature. This should be returned by the consensus engine.
    pub quorum_sig: BLSSignature,
}

impl AssetUnlockPayload {
    /// First payload version whose txid excludes the quorum signing info, so every re-signed
    /// instance of one withdrawal shares one txid.
    pub const STABLE_TXID_VERSION: u8 = 2;

    /// Size of the trailing quorum signing info (`request_info` and `quorum_sig`), the only
    /// fields Platform changes when it re-signs a withdrawal.
    pub const QUORUM_INFO_SIZE: usize = AssetUnlockRequestInfo::SIZE + 96;

    /// Size of the payload: version, index and fee, then the quorum signing info.
    pub const SIZE: usize = 1 + 8 + 4 + Self::QUORUM_INFO_SIZE;

    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        self.base.size() + self.request_info.size() + 96
    }
}

impl SpecialTransactionBasePayloadEncodable for AssetUnlockPayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base.consensus_encode(&mut s)?;
        len += self.request_info.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

pub fn build_asset_unlock_tx(withdrawal_info_bytes: &[u8]) -> Result<Transaction, encode::Error> {
    let size_request_info: usize = AssetUnlockRequestInfo::SIZE;
    let size_asset_unlock_info = withdrawal_info_bytes.len() - size_request_info;
    let bytes_asset_unlock = &withdrawal_info_bytes[0..size_asset_unlock_info].to_vec();
    let bytes_request_info = &withdrawal_info_bytes[size_asset_unlock_info..].to_vec();
    let withdrawal_info: AssetUnlockBaseTransactionInfo =
        consensus::encode::deserialize(bytes_asset_unlock)?;
    let withdrawal_request_info: AssetUnlockRequestInfo =
        consensus::encode::deserialize(bytes_request_info)?;

    // Create the AssetUnlockPayload with empty signature
    let tx_payload_asset_unlock = AssetUnlockPayload {
        base: withdrawal_info.base_payload,
        request_info: withdrawal_request_info,
        quorum_sig: BLSSignature::from([0; 96]),
    };
    let tx_special_payload = TransactionPayload::AssetUnlockPayloadType(tx_payload_asset_unlock);

    let empty_input: Vec<TxIn> = Vec::new();
    let tx_asset_unlock = Transaction {
        version: 3,
        lock_time: withdrawal_info.lock_time,
        input: empty_input,
        output: withdrawal_info.output,
        special_transaction_payload: Some(tx_special_payload),
    };

    Ok(tx_asset_unlock)
}

impl Encodable for AssetUnlockPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base.consensus_encode(w)?;
        len += self.request_info.consensus_encode(w)?;
        len += self.quorum_sig.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for AssetUnlockPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let base = AssetUnlockBasePayload::consensus_decode(r)?;
        let request_info = AssetUnlockRequestInfo::consensus_decode(r)?;
        let quorum_sig = BLSSignature::consensus_decode(r)?;
        Ok(AssetUnlockPayload {
            base,
            request_info,
            quorum_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use hashes::Hash;
    use hex_conservative::{Case, DisplayHex};

    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus::Encodable;
    use crate::hash_types::QuorumHash;
    use crate::transaction::special_transaction::TransactionPayload;
    use crate::transaction::special_transaction::asset_unlock::qualified_asset_unlock::{
        ASSET_UNLOCK_TX_SIZE, AssetUnlockPayload, build_asset_unlock_tx,
    };
    use crate::transaction::special_transaction::asset_unlock::request_info::AssetUnlockRequestInfo;
    use crate::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload;
    use crate::{PubkeyHash, ScriptBuf, Transaction, TxOut, Txid, consensus};
    use test_case::test_case;

    #[test]
    fn size() {
        let want = 145;
        let payload = AssetUnlockPayload {
            base: AssetUnlockBasePayload {
                version: 0,
                index: 0,
                fee: 0,
            },
            request_info: AssetUnlockRequestInfo {
                request_height: 0,
                quorum_hash: QuorumHash::all_zeros(),
            },
            quorum_sig: BLSSignature::from([0; 96]),
        };
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(payload.size(), want);
        assert_eq!(actual, want);
    }

    #[test]
    fn deserialize() {
        let payload_bytes = hex_conservative::decode_to_vec("012d0100000000000070110100250500004acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7")
            .unwrap();

        let payload: AssetUnlockPayload = consensus::encode::deserialize(&payload_bytes).unwrap();
        assert_eq!(payload.base.version, 1);
        assert_eq!(payload.base.index, 301);
        assert_eq!(payload.base.fee, 70000);
        assert_eq!(payload.request_info.request_height, 1317);
        assert_eq!(
            payload.request_info.quorum_hash,
            QuorumHash::from_str(
                "4acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448"
            )
            .unwrap()
            .reverse()
        );
        assert_eq!(payload.quorum_sig, BLSSignature::from_str("aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7").unwrap());
    }

    #[test]
    fn serialize() {
        let payload = AssetUnlockPayload {
            base: AssetUnlockBasePayload {
                version: 1,
                index: 301,
                fee: 70000,
            },
            request_info: AssetUnlockRequestInfo {
                request_height: 1317,
                quorum_hash: QuorumHash::from_str("4acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448").unwrap().reverse(),
            },
            quorum_sig: BLSSignature::from_str("aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7").unwrap()
        };

        let serialized_bytes = consensus::serialize(&payload).to_lower_hex_string();

        let expected_payload_bytes = "012d0100000000000070110100250500004acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7";
        assert_eq!(serialized_bytes, expected_payload_bytes);
    }

    #[test]
    fn test_asset_unlock_construction_3() {
        let tx_bytes = hex_conservative::decode_to_vec("010009000001c8000000000000001976a914c35b782432294088e354bc28aa56d95736cb630288ac0000000001000000000000000070f915129f05000053c006055af6d0ae9aa9627df8615a71c312421a28c4712c8add83c8e1bfdadd").unwrap();
        let tx_asset_unlock = build_asset_unlock_tx(&tx_bytes).unwrap();
        let bytes_tx_asset_unlock = consensus::serialize(&tx_asset_unlock);
        println!("tx_asset_unlock: {:?}", bytes_tx_asset_unlock);

        let hex_tx_asset_unlock = bytes_tx_asset_unlock.to_hex_string(Case::Lower);
        println!("hex_tx_asset_unlock: {:?}", hex_tx_asset_unlock);
        println!("OK");
    }

    #[test]
    fn test_asset_unlock_size() {
        let payload = AssetUnlockPayload {
            base: AssetUnlockBasePayload {
                version: 1,
                index: 301,
                fee: 70000,
            },
            request_info: AssetUnlockRequestInfo {
                request_height: 1317,
                quorum_hash: QuorumHash::from_str("4acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448").unwrap(),
            },
            quorum_sig: BLSSignature::from_str("aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7").unwrap()
        };

        let tx = Transaction {
            version: 3,
            lock_time: 0,
            input: Vec::new(),
            output: vec![TxOut {
                value: 200,
                script_pubkey: ScriptBuf::from_hex(
                    "76a914c35b782432294088e354bc28aa56d95736cb630288ac",
                )
                .unwrap(),
            }],
            special_transaction_payload: Some(TransactionPayload::AssetUnlockPayloadType(payload)),
        };

        assert_eq!(tx.size(), ASSET_UNLOCK_TX_SIZE);
    }

    /// The DIP-0027 example unlock: one 1 DASH output to a P2PKH of `0x11` bytes.
    fn unlock_tx(version: u8, index: u64, request_height: u32, quorum_sig: u8) -> Transaction {
        let mut quorum_hash = [0; 32];
        quorum_hash[0] = 1;
        Transaction {
            version: 3,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut {
                value: 100_000_000,
                script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0x11; 20])),
            }],
            special_transaction_payload: Some(TransactionPayload::AssetUnlockPayloadType(
                AssetUnlockPayload {
                    base: AssetUnlockBasePayload {
                        version,
                        index,
                        fee: 70_000,
                    },
                    request_info: AssetUnlockRequestInfo {
                        request_height,
                        quorum_hash: QuorumHash::from_byte_array(quorum_hash),
                    },
                    quorum_sig: BLSSignature::from([quorum_sig; 96]),
                },
            )),
        }
    }

    // Core's `evo_assetunlock` test, from dip-0027/dip-0027-txid-calc.py.
    #[test_case(101, "3c4db73c8356407a5d7c78df5045bd280f2dc4fd644b06c4bfbdead3d5ae41cf")]
    #[test_case(123456789, "a67e1107ae6e04b813bc8e81348266f5206d1ca93d305dc4323940e18cdbaf34")]
    fn version_2_txid_matches_dip_0027(index: u64, txid: &str) {
        assert_eq!(unlock_tx(2, index, 500, 0).txid(), Txid::from_str(txid).unwrap());
    }

    // Core tells a stable txid from the payload bytes, so a payload kept raw hashes the same.
    #[test_case(1; "version 1")]
    #[test_case(2; "version 2")]
    fn raw_payload_has_the_typed_txid(version: u8) {
        let typed = unlock_tx(version, 101, 500, 0);
        let payload = typed.special_transaction_payload.as_ref().unwrap();
        let raw = Transaction {
            special_transaction_payload: Some(TransactionPayload::RawPayloadType(
                9,
                consensus::serialize(payload),
            )),
            ..typed.clone()
        };
        assert_eq!(raw.txid(), typed.txid());
        assert_eq!(raw.instance_hash(), typed.instance_hash());
    }

    #[test]
    fn version_2_txid_excludes_the_quorum_signing_info() {
        let tx = unlock_tx(2, 101, 500, 0);
        let resigned = unlock_tx(2, 101, 700, 1);
        assert_eq!(resigned.txid(), tx.txid());
        assert_ne!(resigned.instance_hash(), tx.instance_hash());
        assert_eq!(tx.instance_hash(), Txid::hash(&consensus::serialize(&tx)));

        let v1 = unlock_tx(1, 101, 500, 0);
        assert_eq!(v1.txid(), v1.instance_hash());
        assert_ne!(unlock_tx(1, 101, 700, 1).txid(), v1.txid());
    }
}
