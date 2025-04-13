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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
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

pub fn build_asset_unlock_tx(
    withdrawal_info_bytes: &Vec<u8>,
) -> Result<Transaction, encode::Error> {
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
    use hex::FromHex;
    use internals::hex::Case;
    use internals::hex::display::DisplayHex;

    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus::Encodable;
    use crate::hash_types::QuorumHash;
    use crate::transaction::special_transaction::TransactionPayload;
    use crate::transaction::special_transaction::asset_unlock::qualified_asset_unlock::{
        ASSET_UNLOCK_TX_SIZE, AssetUnlockPayload, build_asset_unlock_tx,
    };
    use crate::transaction::special_transaction::asset_unlock::request_info::AssetUnlockRequestInfo;
    use crate::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload;
    use crate::{ScriptBuf, Transaction, TxOut, consensus};

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
        let payload_bytes = Vec::from_hex("012d0100000000000070110100250500004acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7")
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

        let serialized_bytes = hex::encode(consensus::serialize(&payload));

        let expected_payload_bytes = "012d0100000000000070110100250500004acfa5c6d92071d206da5b767039d42f24e7ab1a694a5b8014cddc088311e448aee468c03feec7caada0599457136ef0dfe9365657a42ef81bb4aa53af383d05d90552b2cd23480cae24036b953ba8480d2f98291271a338e4235265dea94feacb54d1fd96083151001eff4156e7475e998154a8e6082575e2ee461b394d24f7";
        assert_eq!(serialized_bytes, expected_payload_bytes);
    }

    #[test]
    fn test_asset_unlock_construction_3() {
        let tx_bytes = Vec::from_hex("010009000001c8000000000000001976a914c35b782432294088e354bc28aa56d95736cb630288ac0000000001000000000000000070f915129f05000053c006055af6d0ae9aa9627df8615a71c312421a28c4712c8add83c8e1bfdadd").unwrap();
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
}
