use std::collections::BTreeMap;
use std::io::{Read, Write};
#[cfg(feature = "bls")]
use blsful::{Bls12381G2Impl, PublicKey};
use crate::internal_macros::impl_consensus_encoding;
use crate::{ProTxHash, PubkeyHash};
use crate::bls_sig_utils::BLSPublicKey;
use crate::consensus::{Decodable, Encodable};
use crate::consensus::encode::Error;
use crate::hash_types::{ConfirmedHash, Sha256dHash};
use crate::sml::address::ServiceAddress;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum MasternodeType {
    Regular,
    HighPerformance {
        platform_http_port: u16,
        platform_node_id: PubkeyHash,
    },
}

impl Encodable for MasternodeType {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        match self {
            MasternodeType::Regular => {
                // Write variant tag 0 for Regular
                len += (0u8).consensus_encode(writer)?;
            },
            MasternodeType::HighPerformance { platform_http_port, platform_node_id } => {
                // Write variant tag 1 for HighPerformance,
                // then the u16 port and the PubkeyHash
                len += (1u8).consensus_encode(writer)?;
                len += platform_http_port.consensus_encode(writer)?;
                len += platform_node_id.consensus_encode(writer)?;
            },
        }
        Ok(len)
    }
}

impl Decodable for MasternodeType {
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        // First decode the variant tag.
        let variant: u16 = Decodable::consensus_decode(reader)?;
        match variant {
            0 => Ok(MasternodeType::Regular),
            1 => {
                let platform_http_port = Decodable::consensus_decode(reader)?;
                let platform_node_id = Decodable::consensus_decode(reader)?;
                Ok(MasternodeType::HighPerformance {
                    platform_http_port,
                    platform_node_id
                })
            },
            received => Err(Error::InvalidEnumValue {
                max: 1,
                received: received as u16,
                msg: "Invalid MasternodeType variant".to_string(),
            }),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct OperatorPublicKey {
    pub data: [u8; 48],
    pub version: u16,
}

impl_consensus_encoding!(OperatorPublicKey, data, version);

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MasternodeListEntry {
    pub version: u16,
    pub pro_reg_tx_hash: ProTxHash,
    pub confirmed_hash: ConfirmedHash,
    pub service_address: ServiceAddress,
    pub operator_public_key: BLSPublicKey,
    pub key_id_voting: PubkeyHash,
    pub is_valid: bool,
    pub mn_type: MasternodeType,
}

impl Encodable for MasternodeListEntry {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(writer)?;
        len += self.pro_reg_tx_hash.consensus_encode(writer)?;
        len += self.confirmed_hash.consensus_encode(writer)?;
        len += self.service_address.consensus_encode(writer)?;
        len += self.operator_public_key.consensus_encode(writer)?;
        len += self.key_id_voting.consensus_encode(writer)?;
        len += self.is_valid.consensus_encode(writer)?;
        len += self.mn_type.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for MasternodeListEntry {
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let version: u16 = Decodable::consensus_decode(reader)?;
        let pro_reg_tx_hash: ProTxHash = Decodable::consensus_decode(reader)?;
        let confirmed_hash: ConfirmedHash = Decodable::consensus_decode(reader)?;
        let service_address: ServiceAddress = Decodable::consensus_decode(reader)?;
        let operator_public_key: BLSPublicKey = Decodable::consensus_decode(reader)?;
        let key_id_voting: PubkeyHash = Decodable::consensus_decode(reader)?;
        let is_valid: bool = Decodable::consensus_decode(reader)?;
        let mn_type: MasternodeType = if version >= 2 {
            Decodable::consensus_decode(reader)?
        } else {
            MasternodeType::Regular
        };

        Ok(MasternodeListEntry {
            version,
            pro_reg_tx_hash,
            confirmed_hash,
            service_address,
            operator_public_key,
            key_id_voting,
            is_valid,
            mn_type,
        })
    }
}
#[cfg(feature = "bls")]
#[derive(Clone, Eq, PartialEq)]
pub struct MasternodeListEntryInfo {
    pub base_entry: MasternodeListEntry,
    pub loaded_operator_public_key: Option<PublicKey<Bls12381G2Impl>>,
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: ConfirmedHash,
    pub previous_operator_public_keys: BTreeMap<u64, OperatorPublicKey>,
    pub previous_entry_hashes: BTreeMap<u64, [u8; 32]>,
    pub previous_validity: BTreeMap<u64, bool>,
    pub known_confirmed_at_height: Option<u32>,
    pub update_height: u32,
    pub entry_hash: Sha256dHash,
}