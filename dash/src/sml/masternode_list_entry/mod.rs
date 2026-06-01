mod hash;
mod helpers;
pub mod net_info;
pub mod qualified_masternode_list_entry;
mod score;

use std::cmp::Ordering;
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;

use crate::bls_sig_utils::BLSPublicKey;
use crate::consensus::encode::Error;
use crate::consensus::{Decodable, Encodable};
use crate::hash_types::ConfirmedHash;
use crate::internal_macros::impl_consensus_encoding;
use crate::sml::masternode_list_entry::net_info::{
    Bip155Network, ExtNetInfo, NetInfoEntry, NetInfoPurpose,
};
use crate::{ProTxHash, PubkeyHash};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EntryMasternodeType {
    Regular,
    HighPerformance {
        platform_http_port: u16,
        platform_node_id: PubkeyHash,
    },
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct OperatorPublicKey {
    // TODO: We are using two different public keys here
    pub data: BLSPublicKey,
    pub version: u16,
}

impl_consensus_encoding!(OperatorPublicKey, data, version);

/// Service address of a masternode entry.
///
/// Pre-v3 entries carry a single fixed-length legacy `SocketAddr`; v3 entries carry a
/// variable-length `ExtNetInfo` map.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MasternodeNetInfo {
    Legacy(SocketAddr),
    Extended(ExtNetInfo),
}

// `Legacy` reuses bincode's bare `SocketAddr` layout (leading u32 variant 0/1) so existing
// pre-v3 persisted snapshots keep decoding; `Extended` claims the next free variant tag.
#[cfg(feature = "bincode")]
impl bincode::Encode for MasternodeNetInfo {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        match self {
            MasternodeNetInfo::Legacy(addr) => addr.encode(encoder),
            MasternodeNetInfo::Extended(info) => {
                2u32.encode(encoder)?;
                info.encode(encoder)
            }
        }
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for MasternodeNetInfo {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        match u32::decode(decoder)? {
            0 => Ok(MasternodeNetInfo::Legacy(SocketAddr::V4(SocketAddrV4::decode(decoder)?))),
            1 => Ok(MasternodeNetInfo::Legacy(SocketAddr::V6(SocketAddrV6::decode(decoder)?))),
            2 => Ok(MasternodeNetInfo::Extended(ExtNetInfo::decode(decoder)?)),
            found => Err(bincode::error::DecodeError::UnexpectedVariant {
                allowed: &bincode::error::AllowedEnumVariants::Range {
                    min: 0,
                    max: 2,
                },
                found,
                type_name: "MasternodeNetInfo",
            }),
        }
    }
}

#[cfg(feature = "bincode")]
bincode::impl_borrow_decode!(MasternodeNetInfo);

impl MasternodeNetInfo {
    /// Returns the primary routable IPv4/IPv6 service address, if one is present.
    ///
    /// Tor, I2P, CJDNS and domain entries have no `SocketAddr` representation and yield `None`.
    pub fn primary_service_address(&self) -> Option<SocketAddr> {
        match self {
            MasternodeNetInfo::Legacy(addr) => Some(*addr),
            MasternodeNetInfo::Extended(info) => {
                info.entries_for(NetInfoPurpose::CoreP2P).iter().find_map(|entry| match entry {
                    NetInfoEntry::Service {
                        network: Bip155Network::Ipv4,
                        addr,
                        port,
                    } => {
                        let octets: [u8; 4] = addr.as_slice().try_into().ok()?;
                        Some(SocketAddr::V4(SocketAddrV4::new(octets.into(), *port)))
                    }
                    NetInfoEntry::Service {
                        network: Bip155Network::Ipv6,
                        addr,
                        port,
                    } => {
                        let octets: [u8; 16] = addr.as_slice().try_into().ok()?;
                        Some(SocketAddr::V6(SocketAddrV6::new(octets.into(), *port, 0, 0)))
                    }
                    _ => None,
                })
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasternodeListEntry {
    pub version: u16,
    pub pro_reg_tx_hash: ProTxHash,
    pub confirmed_hash: Option<ConfirmedHash>,
    pub service_address: MasternodeNetInfo,
    pub operator_public_key: BLSPublicKey,
    pub key_id_voting: PubkeyHash,
    pub is_valid: bool,
    pub mn_type: EntryMasternodeType,
}

impl Ord for MasternodeListEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pro_reg_tx_hash.cmp(&other.pro_reg_tx_hash)
    }
}

impl PartialOrd for MasternodeListEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Encodable for MasternodeListEntry {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        debug_assert_eq!(
            matches!(self.service_address, MasternodeNetInfo::Legacy(_)),
            self.version < 3,
            "Legacy service address must be used iff version < 3"
        );
        let mut len = 0;
        len += self.version.consensus_encode(writer)?;
        len += self.pro_reg_tx_hash.consensus_encode(writer)?;
        if let Some(confirmed_hash) = self.confirmed_hash {
            len += confirmed_hash.consensus_encode(writer)?;
        } else {
            len += [0; 32].consensus_encode(writer)?;
        }
        match &self.service_address {
            MasternodeNetInfo::Legacy(addr) => len += addr.consensus_encode(writer)?,
            MasternodeNetInfo::Extended(info) => len += info.consensus_encode_ext(writer)?,
        }
        len += self.operator_public_key.consensus_encode(writer)?;
        len += self.key_id_voting.consensus_encode(writer)?;
        len += self.is_valid.consensus_encode(writer)?;
        if self.version >= 2 {
            match &self.mn_type {
                EntryMasternodeType::Regular => {
                    len += 0u16.consensus_encode(writer)?;
                }
                EntryMasternodeType::HighPerformance {
                    platform_http_port,
                    platform_node_id,
                } => {
                    len += 1u16.consensus_encode(writer)?;
                    if self.version < 3 {
                        len += platform_http_port.consensus_encode(writer)?;
                    }
                    len += platform_node_id.consensus_encode(writer)?;
                }
            }
        }
        Ok(len)
    }
}

impl Decodable for MasternodeListEntry {
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let version: u16 = Decodable::consensus_decode(reader)?;
        let pro_reg_tx_hash: ProTxHash = Decodable::consensus_decode(reader)?;
        let confirmed_hash: ConfirmedHash = Decodable::consensus_decode(reader)?;
        let confirmed_hash = if confirmed_hash.to_byte_array() == [0; 32] {
            None
        } else {
            Some(confirmed_hash)
        };
        let service_address = if version >= 3 {
            MasternodeNetInfo::Extended(ExtNetInfo::consensus_decode_ext(reader)?)
        } else {
            MasternodeNetInfo::Legacy(SocketAddr::consensus_decode(reader)?)
        };
        let operator_public_key: BLSPublicKey = Decodable::consensus_decode(reader)?;
        let key_id_voting: PubkeyHash = Decodable::consensus_decode(reader)?;
        let is_valid: bool = Decodable::consensus_decode(reader)?;
        let mn_type = if version >= 2 {
            let variant: u16 = Decodable::consensus_decode(reader)?;
            match variant {
                0 => EntryMasternodeType::Regular,
                1 => {
                    if version >= 3 {
                        let platform_node_id = Decodable::consensus_decode(reader)?;
                        let platform_http_port = match &service_address {
                            MasternodeNetInfo::Extended(info) => {
                                info.platform_https_port().unwrap_or(0)
                            }
                            MasternodeNetInfo::Legacy(_) => 0,
                        };
                        EntryMasternodeType::HighPerformance {
                            platform_http_port,
                            platform_node_id,
                        }
                    } else {
                        let platform_http_port = Decodable::consensus_decode(reader)?;
                        let platform_node_id = Decodable::consensus_decode(reader)?;
                        EntryMasternodeType::HighPerformance {
                            platform_http_port,
                            platform_node_id,
                        }
                    }
                }
                received => {
                    return Err(Error::InvalidEnumValue {
                        max: 1,
                        received,
                        msg: "Invalid MasternodeType variant".to_string(),
                    });
                }
            }
        } else {
            EntryMasternodeType::Regular
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
