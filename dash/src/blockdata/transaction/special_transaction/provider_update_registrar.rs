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

//! Dash Provider Update Registrar Special Transaction.
//!
//! The provider update registrar special transaction is used to update the owner controlled options
//! for a masternode.
//!
//! It is defined in DIP3 [dip-0003](https://github.com/dashpay/dips/blob/master/dip-0003.md) as follows:
//!
//! To registrar update a masternode, the masternode owner must submit another special transaction
//! (DIP2) to the network. This special transaction is called a Provider Update Registrar
//! Transaction and is abbreviated as ProUpRegTx. It can only be done by the owner.
//!
//! A ProUpRegTx is only valid for masternodes in the registered masternodes subset. When
//! processed, it updates the metadata of the masternode entry. It does not revive masternodes
//! previously marked as PoSe-banned.
//!
//! The special transaction type used for ProUpRegTx Transactions is 3.

use hashes::Hash;

use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::blockdata::transaction::special_transaction::provider_registration::{
    MasternodePayoutShare, decode_payouts, encode_payouts,
};
use crate::blockdata::transaction::special_transaction::provider_update_service::ProTxVersion;
use crate::bls_sig_utils::BLSPublicKey;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, PubkeyHash, SpecialTransactionPayloadHash, Txid};
use crate::prelude::*;
use crate::{ScriptBuf, VarInt, io};

/// A Provider Update Registrar Payload used in a Provider Update Registrar Special Transaction.
/// This is used to update the base aspects a Masternode on the network.
/// It must be signed by the owner's key that was set at registration.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ProviderUpdateRegistrarPayload {
    pub version: u16,
    pub pro_tx_hash: Txid,
    pub provider_mode: u16,
    pub operator_public_key: BLSPublicKey,
    pub voting_key_hash: PubkeyHash,
    /// Payout script before version 3, empty from version 3 (see `payouts`).
    pub script_payout: ScriptBuf,
    pub inputs_hash: InputsHash,
    pub payload_sig: Vec<u8>, // TODO: Need to figure out, is this signature BLS Signature (length 96)
    /// DIP-0026 payouts, present from version 3 in place of `script_payout`.
    pub payouts: Option<Vec<MasternodePayoutShare>>,
}

impl ProviderUpdateRegistrarPayload {
    /// Latest spec version of the ProUpRegTx payload.
    pub const CURRENT_VERSION: u16 = 2;

    /// Create a new ProUpRegTx payload at [`Self::CURRENT_VERSION`].
    pub fn new(
        pro_tx_hash: Txid,
        provider_mode: u16,
        operator_public_key: BLSPublicKey,
        voting_key_hash: PubkeyHash,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        payload_sig: Vec<u8>,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            pro_tx_hash,
            provider_mode,
            operator_public_key,
            voting_key_hash,
            script_payout,
            inputs_hash,
            payload_sig,
            payouts: None,
        }
    }

    fn is_ext_addr(&self) -> bool {
        self.version >= ProTxVersion::ExtAddr as u16
    }

    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        let mut size = 2 + 32 + 2 + 48 + 20 + 32; // 136
        if self.is_ext_addr() {
            let payouts = self.payouts.as_deref().unwrap_or_default();
            size += 1 + payouts.iter().map(MasternodePayoutShare::size).sum::<usize>();
        } else {
            size += VarInt(self.script_payout.len() as u64).len() + self.script_payout.len();
        }
        size += VarInt(self.payload_sig.len() as u64).len() + self.payload_sig.len();
        size
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateRegistrarPayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += self.provider_mode.consensus_encode(&mut s)?;
        len += self.operator_public_key.consensus_encode(&mut s)?;
        len += self.voting_key_hash.consensus_encode(&mut s)?;
        if self.is_ext_addr() {
            let Some(payouts) = &self.payouts else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "payouts is not set"));
            };
            len += encode_payouts(payouts, &mut s)?;
        } else {
            len += self.script_payout.consensus_encode(&mut s)?;
        }
        len += self.inputs_hash.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderUpdateRegistrarPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut w)?;
        len += self.payload_sig.consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateRegistrarPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;

        // Version validation like C++ SERIALIZE_METHODS
        if version == 0 || version > ProTxVersion::ExtAddr as u16 {
            return Err(encode::Error::ParseFailed("unsupported ProUpRegTx version"));
        }

        let pro_tx_hash = Txid::consensus_decode(r)?;
        let provider_mode = u16::consensus_decode(r)?;
        let operator_public_key = BLSPublicKey::consensus_decode(r)?;
        let voting_key_hash = PubkeyHash::consensus_decode(r)?;
        let (script_payout, payouts) = if version >= ProTxVersion::ExtAddr as u16 {
            (ScriptBuf::new(), Some(decode_payouts(r)?))
        } else {
            (ScriptBuf::consensus_decode(r)?, None)
        };
        let inputs_hash = InputsHash::consensus_decode(r)?;
        let payload_sig = Vec::<u8>::consensus_decode(r)?;

        Ok(ProviderUpdateRegistrarPayload {
            version,
            pro_tx_hash,
            provider_mode,
            operator_public_key,
            voting_key_hash,
            script_payout,
            inputs_hash,
            payload_sig,
            payouts,
        })
    }
}

// Same layout as a derived impl, with `payouts` only from version 3, so payloads persisted
// before the field existed keep decoding.
#[cfg(feature = "bincode")]
impl bincode::Encode for ProviderUpdateRegistrarPayload {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.version.encode(encoder)?;
        self.pro_tx_hash.encode(encoder)?;
        self.provider_mode.encode(encoder)?;
        self.operator_public_key.encode(encoder)?;
        self.voting_key_hash.encode(encoder)?;
        self.script_payout.encode(encoder)?;
        self.inputs_hash.encode(encoder)?;
        self.payload_sig.encode(encoder)?;
        if self.is_ext_addr() {
            self.payouts.encode(encoder)?;
        }
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ProviderUpdateRegistrarPayload {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::Decode;

        let version = u16::decode(decoder)?;
        Ok(ProviderUpdateRegistrarPayload {
            version,
            pro_tx_hash: Decode::decode(decoder)?,
            provider_mode: Decode::decode(decoder)?,
            operator_public_key: Decode::decode(decoder)?,
            voting_key_hash: Decode::decode(decoder)?,
            script_payout: Decode::decode(decoder)?,
            inputs_hash: Decode::decode(decoder)?,
            payload_sig: Decode::decode(decoder)?,
            payouts: if version >= ProTxVersion::ExtAddr as u16 {
                Decode::decode(decoder)?
            } else {
                None
            },
        })
    }
}

#[cfg(feature = "bincode")]
bincode::impl_borrow_decode!(ProviderUpdateRegistrarPayload);

// Same shape as the earlier derived impl, with `payouts` only from version 3, so payloads
// persisted through binary serde before the field existed keep decoding.
#[cfg(feature = "serde")]
impl serde::Serialize for ProviderUpdateRegistrarPayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let ext_addr = self.is_ext_addr();
        let len = if ext_addr {
            9
        } else {
            8
        };
        let mut state = serializer.serialize_struct("ProviderUpdateRegistrarPayload", len)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("pro_tx_hash", &self.pro_tx_hash)?;
        state.serialize_field("provider_mode", &self.provider_mode)?;
        state.serialize_field("operator_public_key", &self.operator_public_key)?;
        state.serialize_field("voting_key_hash", &self.voting_key_hash)?;
        state.serialize_field("script_payout", &self.script_payout)?;
        state.serialize_field("inputs_hash", &self.inputs_hash)?;
        state.serialize_field("payload_sig", &self.payload_sig)?;
        if ext_addr {
            state.serialize_field("payouts", &self.payouts)?;
        }
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ProviderUpdateRegistrarPayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use core::fmt;

        use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};

        const FIELDS: &[&str] = &[
            "version",
            "pro_tx_hash",
            "provider_mode",
            "operator_public_key",
            "voting_key_hash",
            "script_payout",
            "inputs_hash",
            "payload_sig",
            "payouts",
        ];

        struct PayloadVisitor;

        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = ProviderUpdateRegistrarPayload;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a provider update registrar payload")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                macro_rules! next {
                    ($index:expr) => {
                        seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length($index, &self))?
                    };
                }
                let version: u16 = next!(0);
                Ok(ProviderUpdateRegistrarPayload {
                    version,
                    pro_tx_hash: next!(1),
                    provider_mode: next!(2),
                    operator_public_key: next!(3),
                    voting_key_hash: next!(4),
                    script_payout: next!(5),
                    inputs_hash: next!(6),
                    payload_sig: next!(7),
                    // Read only from version 3: earlier payloads were written without it.
                    payouts: if version >= ProTxVersion::ExtAddr as u16 {
                        next!(8)
                    } else {
                        None
                    },
                })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut version = None;
                let mut pro_tx_hash = None;
                let mut provider_mode = None;
                let mut operator_public_key = None;
                let mut voting_key_hash = None;
                let mut script_payout = None;
                let mut inputs_hash = None;
                let mut payload_sig = None;
                let mut payouts = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "pro_tx_hash" => pro_tx_hash = Some(map.next_value()?),
                        "provider_mode" => provider_mode = Some(map.next_value()?),
                        "operator_public_key" => operator_public_key = Some(map.next_value()?),
                        "voting_key_hash" => voting_key_hash = Some(map.next_value()?),
                        "script_payout" => script_payout = Some(map.next_value()?),
                        "inputs_hash" => inputs_hash = Some(map.next_value()?),
                        "payload_sig" => payload_sig = Some(map.next_value()?),
                        "payouts" => payouts = map.next_value()?,
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                // `payouts` only exists from version 3, as in `visit_seq`; reject it rather than
                // drop it silently on the next encode.
                let version: u16 = version.ok_or_else(|| de::Error::missing_field("version"))?;
                if version < ProTxVersion::ExtAddr as u16 && payouts.is_some() {
                    return Err(de::Error::custom("payouts only exist from version 3"));
                }
                Ok(ProviderUpdateRegistrarPayload {
                    version,
                    pro_tx_hash: pro_tx_hash
                        .ok_or_else(|| de::Error::missing_field("pro_tx_hash"))?,
                    provider_mode: provider_mode
                        .ok_or_else(|| de::Error::missing_field("provider_mode"))?,
                    operator_public_key: operator_public_key
                        .ok_or_else(|| de::Error::missing_field("operator_public_key"))?,
                    voting_key_hash: voting_key_hash
                        .ok_or_else(|| de::Error::missing_field("voting_key_hash"))?,
                    script_payout: script_payout
                        .ok_or_else(|| de::Error::missing_field("script_payout"))?,
                    inputs_hash: inputs_hash
                        .ok_or_else(|| de::Error::missing_field("inputs_hash"))?,
                    payload_sig: payload_sig
                        .ok_or_else(|| de::Error::missing_field("payload_sig"))?,
                    payouts,
                })
            }
        }

        deserializer.deserialize_struct("ProviderUpdateRegistrarPayload", FIELDS, PayloadVisitor)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use hashes::Hash;

    use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
    use crate::blockdata::transaction::special_transaction::provider_registration::MasternodePayoutShare;
    use crate::bls_sig_utils::BLSPublicKey;
    use crate::consensus::Decodable;
    use crate::consensus::{Encodable, deserialize};
    use crate::hash_types::InputsHash;
    use crate::internal_macros::hex;
    use crate::transaction::special_transaction::TransactionPayload::ProviderUpdateRegistrarPayloadType;
    use crate::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
    use crate::{Network, PubkeyHash, ScriptBuf, Transaction, Txid};
    use hex_conservative::DisplayHex;

    #[test]
    fn test_provider_update_registrar_transaction() {
        // This is a test for testnet
        let _network = Network::Testnet;

        let expected_transaction_bytes = hex!(
            "0300030001c7de76dac8dd96f9b49b12a06fe39c8caf0cad12d23ad6026094d9b11b2b260d000000006b483045022100b31895e8cea95a965c82d842eadd6eef3c7b29e677c62a5c8e2b5dce05b4ddfc02206c7b5a9ea8b71983c3b21f4ff75ac1aa44090d28af8b2d9b93e794e6eb5835e20121032ea8be689184f329dce575776bc956cd52230f4c04755d5753d9491ea5bf8f2affffffff01c94670d0060000001976a914345f07bc7ebaf9f82f273be249b6066d2d5c236688ac00000000e4010049aa692330179f95c1342715102e37777df91cc0f3a4ae7e8f9e214ee97dbb3d0000139b654f0b1c031e1cf2b934c2d895178875cfe7c6a4f6758f02bc66eea7fc292d0040701acbe31f5e14a911cb061a2f6cc4a7bb877a80c11ae06b988d98305773f93b981976a91456bcf3cac49235537d6ce0fb3214d8850a6db77788ac2d7f857a2f15eb9340a0cfbce3ff8cf09b40e582d05b1f98c7468caa0f942bcf411ff69c9cb072660cc10048332c14c08621e7461f1f4f54b448baedc0e3434d9a7c3a1780885aaef4dd44c597b49b97595e02ad54728f572967d3ce0c2c0ceac174"
        );

        let expected_transaction: Transaction =
            deserialize(expected_transaction_bytes.as_slice()).expect("expected a transaction");

        let expected_provider_update_registrar_payload = expected_transaction
            .special_transaction_payload
            .clone()
            .unwrap()
            .to_update_registrar_payload()
            .expect("expected to get an update registrar payload");

        let tx_id =
            Txid::from_str("bd98378ca37d3ae6f4850b82e77be675feb3c9bc6e33cb0c23de1b38a08034c7")
                .expect("expected to decode tx id");

        let provider_update_registrar_payload_version = 1;
        assert_eq!(
            expected_provider_update_registrar_payload.version,
            provider_update_registrar_payload_version
        );
        let pro_tx_hash =
            Txid::from_str("3dbb7de94e219e8f7eaea4f3c01cf97d77372e10152734c1959f17302369aa49")
                .expect("expected to decode tx id");
        assert_eq!(expected_provider_update_registrar_payload.pro_tx_hash, pro_tx_hash);

        let provider_mode = 0;
        assert_eq!(provider_mode, expected_provider_update_registrar_payload.provider_mode);

        let operator_key_hex = "139b654f0b1c031e1cf2b934c2d895178875cfe7c6a4f6758f02bc66eea7fc292d0040701acbe31f5e14a911cb061a2f";
        assert_eq!(
            operator_key_hex,
            expected_provider_update_registrar_payload
                .operator_public_key
                .as_bytes()
                .to_lower_hex_string()
        );

        let voting_key_hash_hex = "6cc4a7bb877a80c11ae06b988d98305773f93b98";
        assert_eq!(
            voting_key_hash_hex,
            expected_provider_update_registrar_payload
                .voting_key_hash
                .as_byte_array()
                .to_lower_hex_string()
        );

        let inputs_hash_hex = "cf2b940faa8c46c7981f5bd082e5409bf08cffe3bccfa04093eb152f7a857f2d";
        assert_eq!(
            expected_provider_update_registrar_payload.inputs_hash.to_hex(),
            inputs_hash_hex,
            "inputs hash calculation has issues"
        );

        assert_eq!(
            expected_provider_update_registrar_payload.base_payload_hash().to_hex(),
            "85deffc85d2304f0305356e1dc8d02eecdb3220576abb370bc67be446c854296",
            "Payload hash calculation has issues"
        );

        // We should verify the script payouts match
        let pubkey_hash = PubkeyHash::from_str("56bcf3cac49235537d6ce0fb3214d8850a6db777")
            .expect("expected to get pubkey hash");
        let script_payout = ScriptBuf::new_p2pkh(&pubkey_hash);
        assert_eq!(expected_provider_update_registrar_payload.script_payout, script_payout);

        assert_eq!(expected_transaction.txid(), tx_id);

        //todo: once we have a BLS signatures library in rust we should implement signing
        let payload_sig = expected_transaction
            .special_transaction_payload
            .clone()
            .unwrap()
            .to_update_registrar_payload()
            .unwrap()
            .payload_sig;

        let transaction = Transaction {
            version: 3,
            lock_time: 0,
            input: expected_transaction.input.clone(), // todo:implement this
            output: expected_transaction.output.clone(), // todo:implement this
            special_transaction_payload: Some(ProviderUpdateRegistrarPayloadType(
                ProviderUpdateRegistrarPayload {
                    version: provider_update_registrar_payload_version,
                    pro_tx_hash,
                    provider_mode,
                    operator_public_key: BLSPublicKey::from_hex(operator_key_hex).unwrap(),
                    voting_key_hash: PubkeyHash::from_str(voting_key_hash_hex).unwrap(),
                    script_payout,
                    inputs_hash: InputsHash::from_hex(inputs_hash_hex).unwrap(),
                    payload_sig,
                    payouts: None,
                },
            )),
        };

        assert_eq!(transaction.hash_inputs().to_hex(), inputs_hash_hex);

        assert_eq!(transaction, expected_transaction);

        assert_eq!(transaction.txid(), tx_id);
    }

    #[test]
    fn size() {
        let want = 244;
        let payload = ProviderUpdateRegistrarPayload {
            version: 0,
            pro_tx_hash: Txid::all_zeros(),
            provider_mode: 0,
            operator_public_key: BLSPublicKey::from([0; 48]),
            voting_key_hash: PubkeyHash::all_zeros(),
            script_payout: ScriptBuf::from_hex("00000000000000000000").unwrap(), // 10 bytes
            inputs_hash: InputsHash::all_zeros(),
            payload_sig: vec![0; 96],
            payouts: None,
        };
        assert_eq!(payload.size(), want);
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(actual, want);
    }

    fn v3_payload() -> ProviderUpdateRegistrarPayload {
        ProviderUpdateRegistrarPayload {
            version: 3,
            pro_tx_hash: Txid::all_zeros(),
            provider_mode: 0,
            operator_public_key: BLSPublicKey::from([0; 48]),
            voting_key_hash: PubkeyHash::all_zeros(),
            script_payout: ScriptBuf::new(),
            inputs_hash: InputsHash::all_zeros(),
            payload_sig: vec![0; 65],
            payouts: Some(vec![
                MasternodePayoutShare {
                    script_payout: ScriptBuf::from(vec![0xaa; 25]),
                    reward: 7000,
                },
                MasternodePayoutShare {
                    script_payout: ScriptBuf::from(vec![0xbb; 23]),
                    reward: 3000,
                },
            ]),
        }
    }

    #[test]
    fn round_trip_v3_payouts() {
        let original = v3_payload();
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // A u8 payout count follows the voting key, in place of `scriptPayout`:
        // version(2) + pro_tx_hash(32) + mode(2) + operator key(48) + voting key(20).
        assert_eq!(encoded[104], 2);
        assert_eq!(&encoded[105..107], &[25, 0xaa]);
        // count(1) + (1 + 25 + 2) + (1 + 23 + 2) + inputs_hash(32) + sig(1 + 65)
        assert_eq!(encoded.len(), 104 + 1 + 28 + 26 + 32 + 66);
        assert_eq!(original.size(), encoded.len());

        let mut reader = &encoded[..];
        let decoded = ProviderUpdateRegistrarPayload::consensus_decode(&mut reader).unwrap();
        assert!(reader.is_empty());
        assert_eq!(decoded, original);
    }

    #[test]
    fn v3_without_payouts_fails_to_encode() {
        let payload = ProviderUpdateRegistrarPayload {
            payouts: None,
            ..v3_payload()
        };
        assert!(payload.consensus_encode(&mut Vec::new()).is_err());
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn bincode_round_trip_v3() {
        let original = v3_payload();
        let bytes = bincode::encode_to_vec(&original, bincode::config::standard()).unwrap();
        let (decoded, read): (ProviderUpdateRegistrarPayload, usize) =
            bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(read, bytes.len());
    }

    #[test]
    fn max_signed_size_reserves_the_largest_ecdsa_signature() {
        use crate::blockdata::transaction::special_transaction::MAX_PAYLOAD_ECDSA_SIGNATURE_SIZE;

        let unsigned = ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload {
            payload_sig: vec![],
            ..v3_payload()
        });
        let signed = ProviderUpdateRegistrarPayloadType(v3_payload());

        // Unsigned and signed placeholders reserve the same bound, so a fee set from one
        // covers the other.
        assert_eq!(unsigned.max_signed_size(), unsigned.size() + MAX_PAYLOAD_ECDSA_SIGNATURE_SIZE);
        assert_eq!(signed.max_signed_size(), unsigned.max_signed_size());
        assert!(signed.max_signed_size() >= signed.size());
    }

    #[test]
    fn transaction_size_counts_a_multi_byte_payload_length_prefix() {
        // A payload above 252 bytes takes a 3-byte length prefix.
        let payload = ProviderUpdateRegistrarPayload {
            payouts: Some(vec![MasternodePayoutShare {
                script_payout: ScriptBuf::from(vec![0xaa; 200]),
                reward: 10000,
            }]),
            ..v3_payload()
        };
        assert!(payload.size() > 252);
        let tx = Transaction {
            version: 3,
            lock_time: 0,
            input: vec![crate::TxIn::default()],
            output: vec![],
            special_transaction_payload: Some(ProviderUpdateRegistrarPayloadType(payload)),
        };
        assert_eq!(tx.size(), crate::consensus::encode::serialize(&tx).len());
    }

    #[test_case::test_case(0; "version 0")]
    #[test_case::test_case(4; "version above ExtAddr")]
    fn rejects_unknown_version(version: u16) {
        let mut encoded = Vec::new();
        v3_payload().consensus_encode(&mut encoded).unwrap();
        encoded[..2].copy_from_slice(&version.to_le_bytes());
        assert!(ProviderUpdateRegistrarPayload::consensus_decode(&mut &encoded[..]).is_err());
    }

    /// The shape `ProviderUpdateRegistrarPayload` had with derived serde before version 3.
    #[cfg(feature = "serde")]
    #[derive(serde::Serialize, serde::Deserialize)]
    struct PreV3ProviderUpdateRegistrarPayload {
        version: u16,
        pro_tx_hash: Txid,
        provider_mode: u16,
        operator_public_key: BLSPublicKey,
        voting_key_hash: PubkeyHash,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        payload_sig: Vec<u8>,
    }

    #[cfg(feature = "serde")]
    fn v2_payloads() -> (ProviderUpdateRegistrarPayload, PreV3ProviderUpdateRegistrarPayload) {
        let payload = ProviderUpdateRegistrarPayload {
            version: 2,
            script_payout: ScriptBuf::from(vec![0xaa; 25]),
            payouts: None,
            ..v3_payload()
        };
        let pre_v3 = PreV3ProviderUpdateRegistrarPayload {
            version: 2,
            pro_tx_hash: payload.pro_tx_hash,
            provider_mode: payload.provider_mode,
            operator_public_key: payload.operator_public_key,
            voting_key_hash: payload.voting_key_hash,
            script_payout: payload.script_payout.clone(),
            inputs_hash: payload.inputs_hash,
            payload_sig: payload.payload_sig.clone(),
        };
        (payload, pre_v3)
    }

    #[cfg(all(feature = "serde", feature = "bincode"))]
    #[test]
    fn binary_serde_keeps_the_pre_v3_shape_before_version_3() {
        let (payload, pre_v3) = v2_payloads();
        let config = bincode::config::standard();
        let old_bytes = bincode::serde::encode_to_vec(&pre_v3, config).unwrap();
        assert_eq!(bincode::serde::encode_to_vec(&payload, config).unwrap(), old_bytes);
        let (decoded, read): (ProviderUpdateRegistrarPayload, usize) =
            bincode::serde::decode_from_slice(&old_bytes, config).unwrap();
        assert_eq!((decoded, read), (payload, old_bytes.len()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_keeps_the_pre_v3_shape_before_version_3() {
        let (payload, pre_v3) = v2_payloads();
        let old_json = serde_json::to_value(&pre_v3).unwrap();
        assert_eq!(serde_json::to_value(&payload).unwrap(), old_json);
        assert_eq!(
            serde_json::from_value::<ProviderUpdateRegistrarPayload>(old_json).unwrap(),
            payload
        );
    }

    #[cfg(all(feature = "serde", feature = "bincode"))]
    #[test]
    fn serde_round_trips_the_payouts_at_version_3() {
        let payload = v3_payload();
        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&payload, config).unwrap();
        let (decoded, read): (ProviderUpdateRegistrarPayload, usize) =
            bincode::serde::decode_from_slice(&bytes, config).unwrap();
        assert_eq!((decoded, read), (payload.clone(), bytes.len()));

        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            serde_json::from_value::<ProviderUpdateRegistrarPayload>(json).unwrap(),
            payload
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_rejects_payouts_before_version_3() {
        let mut json = serde_json::to_value(v3_payload()).unwrap();
        json["version"] = 2.into();
        assert!(serde_json::from_value::<ProviderUpdateRegistrarPayload>(json).is_err());
    }
}
