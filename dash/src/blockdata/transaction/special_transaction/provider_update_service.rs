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

//! Dash Provider Update Service Special Transaction.
//!
//! The provider update service special transaction is used to update the operator controlled
//! options for a masternode.
//!
//! It is defined in DIP3 [dip-0003](https://github.com/dashpay/dips/blob/master/dip-0003.md) as follows:
//!
//! To service update a masternode, the masternode operator must submit another special
//! transaction (DIP2) to the network. This special transaction is called a Provider Update
//! Service Transaction and is abbreviated as ProUpServTx. It can only be done by the operator.
//!
//! An operator can update the IP address and port fields of a masternode entry. If a non-zero
//! operatorReward was set in the initial ProRegTx, the operator may also set the
//! scriptOperatorPayout field in the ProUpServTx. If scriptOperatorPayout is not set and
//! operatorReward is non-zero, the owner gets the full masternode reward.
//!
//! A ProUpServTx is only valid for masternodes in the registered masternodes subset. When
//! processed, it updates the metadata of the masternode entry and revives the masternode if it was
//! previously marked as PoSe-banned.
//!
//! The special transaction type used for ProUpServTx Transactions is 2.

use std::net::SocketAddr;

use hashes::Hash;

use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::blockdata::transaction::special_transaction::provider_registration::ProviderMasternodeType;
use crate::bls_sig_utils::BLSSignature;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, SpecialTransactionPayloadHash, Txid};
use crate::platform_node_id::PlatformNodeId;
use crate::sml::masternode_list_entry::MasternodeNetInfo;
use crate::sml::masternode_list_entry::net_info::ExtNetInfo;
use crate::{ScriptBuf, VarInt, io};

/// ProTx version constants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProTxVersion {
    LegacyBLS = 1,
    BasicBLS = 2,
    /// Extended addresses (`netInfo`) and DIP-0026 payouts.
    ExtAddr = 3,
}

/// A Provider Update Service Payload used in a Provider Update Service Special Transaction.
/// This is used to update the operational aspects a Masternode on the network.
/// It must be signed by the operator's key that was set either at registration or by the last
/// registrar update of the masternode.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ProviderUpdateServicePayload {
    pub version: u16,
    pub mn_type: Option<u16>, // Only present from BasicBLS version (2)
    pub pro_tx_hash: Txid,
    /// The service address: [`MasternodeNetInfo::Legacy`] before version 3,
    /// [`MasternodeNetInfo::Extended`] from version 3.
    pub service_address: MasternodeNetInfo,
    pub script_payout: ScriptBuf,
    pub inputs_hash: InputsHash,
    // Platform fields (only from BasicBLS version and Evo masternode type).
    // The node ID is a Tenderdash/CometBFT node ID (SHA256 of the ed25519
    // public key truncated to 20 bytes), not a hash160 public key hash.
    pub platform_node_id: Option<PlatformNodeId>,
    /// Only before version 3; from version 3 the platform ports are in `service_address`.
    pub platform_p2p_port: Option<u16>,
    /// Only before version 3; from version 3 the platform ports are in `service_address`.
    pub platform_http_port: Option<u16>,
    pub payload_sig: BLSSignature,
}

impl ProviderUpdateServicePayload {
    /// Latest spec version of the ProUpServTx payload (BasicBLS).
    pub const CURRENT_VERSION: u16 = 2;

    /// Create a new ProUpServTx payload at [`Self::CURRENT_VERSION`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mn_type: Option<u16>,
        pro_tx_hash: Txid,
        service_address: SocketAddr,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        platform_node_id: Option<PlatformNodeId>,
        platform_p2p_port: Option<u16>,
        platform_http_port: Option<u16>,
        payload_sig: BLSSignature,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            mn_type,
            pro_tx_hash,
            service_address: MasternodeNetInfo::Legacy(service_address),
            script_payout,
            inputs_hash,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
            payload_sig,
        }
    }

    fn is_ext_addr(&self) -> bool {
        self.version >= ProTxVersion::ExtAddr as u16
    }

    fn is_evo(&self) -> bool {
        self.version >= ProTxVersion::BasicBLS as u16
            && self.mn_type == Some(ProviderMasternodeType::HighPerformance as u16)
    }

    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        let mut size = 2 + 32 + 32 + 96; // version + pro_tx_hash + inputs_hash + payload_sig
        size += VarInt(self.script_payout.len() as u64).len() + self.script_payout.len();

        size += match &self.service_address {
            MasternodeNetInfo::Legacy(_) => 16 + 2, // ip + port
            MasternodeNetInfo::Extended(info) => info.size(),
        };

        // Additional fields from BasicBLS version (v2+)
        if self.version >= ProTxVersion::BasicBLS as u16 {
            size += 2; // mn_type
        }

        // Platform fields for Evo masternodes; the ports moved to `service_address` in v3
        if self.is_evo() {
            size += 20; // platform_node_id
            if !self.is_ext_addr() {
                size += 2 + 2; // p2p_port + http_port
            }
        }

        size
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateServicePayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;

        // Write mn_type from BasicBLS version (v2+)
        if self.version >= ProTxVersion::BasicBLS as u16 {
            len += self.mn_type.unwrap_or_default().consensus_encode(&mut s)?;
        }

        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += match (self.is_ext_addr(), &self.service_address) {
            (false, MasternodeNetInfo::Legacy(addr)) => addr.consensus_encode(&mut s)?,
            (true, MasternodeNetInfo::Extended(info)) => info.consensus_encode_ext(&mut s)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "service_address does not match the payload version",
                ));
            }
        };
        len += self.script_payout.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;

        // Write platform fields for Evo masternodes (v2+, ports only before v3)
        if self.is_evo() {
            len += self.platform_node_id.unwrap_or_default().consensus_encode(&mut s)?;
            if !self.is_ext_addr() {
                len += self.platform_p2p_port.unwrap_or_default().consensus_encode(&mut s)?;
                len += self.platform_http_port.unwrap_or_default().consensus_encode(&mut s)?;
            }
        }

        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderUpdateServicePayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut w)?;
        len += self.payload_sig.consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateServicePayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;

        // Version validation like C++ SERIALIZE_METHODS
        if version == 0 || version > ProTxVersion::ExtAddr as u16 {
            return Err(encode::Error::ParseFailed("unsupported ProUpServTx version"));
        }
        let is_ext_addr = version >= ProTxVersion::ExtAddr as u16;

        // Read nType from BasicBLS version
        let mn_type = if version >= ProTxVersion::BasicBLS as u16 {
            Some(u16::consensus_decode(r)?)
        } else {
            None
        };

        // Read core fields
        let pro_tx_hash = Txid::consensus_decode(r)?;
        let service_address = if is_ext_addr {
            MasternodeNetInfo::Extended(ExtNetInfo::consensus_decode_ext(r)?)
        } else {
            MasternodeNetInfo::Legacy(SocketAddr::consensus_decode(r)?)
        };
        let script_payout = ScriptBuf::consensus_decode(r)?;
        let inputs_hash = InputsHash::consensus_decode(r)?;

        // Read Evo platform fields if needed; the ports moved to `service_address` in v3
        let (platform_node_id, platform_p2p_port, platform_http_port) = if version
            >= ProTxVersion::BasicBLS as u16
            && mn_type == Some(ProviderMasternodeType::HighPerformance as u16)
        {
            let node_id = PlatformNodeId::consensus_decode(r)?;
            if is_ext_addr {
                (Some(node_id), None, None)
            } else {
                let p2p_port = u16::consensus_decode(r)?;
                let http_port = u16::consensus_decode(r)?;
                (Some(node_id), Some(p2p_port), Some(http_port))
            }
        } else {
            (None, None, None)
        };

        // Read BLS signature (assuming not SER_GETHASH context)
        let payload_sig = BLSSignature::consensus_decode(r)?;

        Ok(ProviderUpdateServicePayload {
            version,
            mn_type,
            pro_tx_hash,
            service_address,
            script_payout,
            inputs_hash,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
            payload_sig,
        })
    }
}

/// The `u128` the pre-v3 bincode layout stored the service ip as: its little-endian bytes are
/// the 16 IPv6 octets in network order, IPv4 addresses mapped.
#[cfg(any(feature = "bincode", feature = "serde"))]
fn legacy_ip_bits(addr: &SocketAddr) -> u128 {
    let octets = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => v6.octets(),
    };
    u128::from_le_bytes(octets)
}

/// Inverse of [`legacy_ip_bits`].
#[cfg(any(feature = "bincode", feature = "serde"))]
fn legacy_socket_addr(ip_bits: u128, port: u16) -> SocketAddr {
    let v6 = std::net::Ipv6Addr::from(ip_bits.to_le_bytes());
    match v6.to_ipv4_mapped() {
        Some(v4) => SocketAddr::new(v4.into(), port),
        None => SocketAddr::new(v6.into(), port),
    }
}

// Keeps the layout of the earlier derived impl, which stored the service as an ip `u128` and a
// port: payloads persisted before keep decoding. Version 3 stores the extended addresses there.
#[cfg(feature = "bincode")]
impl bincode::Encode for ProviderUpdateServicePayload {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.version.encode(encoder)?;
        self.mn_type.encode(encoder)?;
        self.pro_tx_hash.encode(encoder)?;
        match (self.is_ext_addr(), &self.service_address) {
            (false, MasternodeNetInfo::Legacy(addr)) => {
                legacy_ip_bits(addr).encode(encoder)?;
                addr.port().encode(encoder)?;
            }
            (true, MasternodeNetInfo::Extended(info)) => info.encode(encoder)?,
            _ => {
                return Err(bincode::error::EncodeError::Other(
                    "service_address does not match the payload version",
                ));
            }
        }
        self.script_payout.encode(encoder)?;
        self.inputs_hash.encode(encoder)?;
        self.platform_node_id.encode(encoder)?;
        self.platform_p2p_port.encode(encoder)?;
        self.platform_http_port.encode(encoder)?;
        self.payload_sig.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ProviderUpdateServicePayload {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::Decode;

        let version = u16::decode(decoder)?;
        Ok(ProviderUpdateServicePayload {
            version,
            mn_type: Decode::decode(decoder)?,
            pro_tx_hash: Decode::decode(decoder)?,
            service_address: if version >= ProTxVersion::ExtAddr as u16 {
                MasternodeNetInfo::Extended(Decode::decode(decoder)?)
            } else {
                let ip_bits = u128::decode(decoder)?;
                MasternodeNetInfo::Legacy(legacy_socket_addr(ip_bits, u16::decode(decoder)?))
            },
            script_payout: Decode::decode(decoder)?,
            inputs_hash: Decode::decode(decoder)?,
            platform_node_id: Decode::decode(decoder)?,
            platform_p2p_port: Decode::decode(decoder)?,
            platform_http_port: Decode::decode(decoder)?,
            payload_sig: Decode::decode(decoder)?,
        })
    }
}

#[cfg(feature = "bincode")]
bincode::impl_borrow_decode!(ProviderUpdateServicePayload);

// Same shape as the earlier derived impl before version 3: the service as an ip `u128` and a
// port. Version 3 writes `service_address` (the extended addresses) in their place. Payloads
// persisted through binary serde before this field changed keep decoding.
#[cfg(feature = "serde")]
impl serde::Serialize for ProviderUpdateServicePayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};

        let ext_addr = self.is_ext_addr();
        let len = if ext_addr {
            10
        } else {
            11
        };
        let mut state = serializer.serialize_struct("ProviderUpdateServicePayload", len)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("mn_type", &self.mn_type)?;
        state.serialize_field("pro_tx_hash", &self.pro_tx_hash)?;
        match (ext_addr, &self.service_address) {
            (false, MasternodeNetInfo::Legacy(addr)) => {
                state.serialize_field("ip_address", &legacy_ip_bits(addr))?;
                state.serialize_field("port", &addr.port())?;
            }
            (true, MasternodeNetInfo::Extended(info)) => {
                state.serialize_field("service_address", info)?;
            }
            _ => {
                return Err(S::Error::custom("service_address does not match the payload version"));
            }
        }
        state.serialize_field("script_payout", &self.script_payout)?;
        state.serialize_field("inputs_hash", &self.inputs_hash)?;
        state.serialize_field("platform_node_id", &self.platform_node_id)?;
        state.serialize_field("platform_p2p_port", &self.platform_p2p_port)?;
        state.serialize_field("platform_http_port", &self.platform_http_port)?;
        state.serialize_field("payload_sig", &self.payload_sig)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ProviderUpdateServicePayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use core::fmt;

        use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};

        const FIELDS: &[&str] = &[
            "version",
            "mn_type",
            "pro_tx_hash",
            "ip_address",
            "port",
            "script_payout",
            "inputs_hash",
            "platform_node_id",
            "platform_p2p_port",
            "platform_http_port",
            "payload_sig",
            "service_address",
        ];

        struct PayloadVisitor;

        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = ProviderUpdateServicePayload;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a provider update service payload")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut index = 0;
                macro_rules! next {
                    () => {{
                        let value = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                        #[allow(unused_assignments)]
                        {
                            index += 1;
                        }
                        value
                    }};
                }
                let version: u16 = next!();
                let mn_type = next!();
                let pro_tx_hash = next!();
                let service_address = if version >= ProTxVersion::ExtAddr as u16 {
                    MasternodeNetInfo::Extended(next!())
                } else {
                    let ip_bits: u128 = next!();
                    MasternodeNetInfo::Legacy(legacy_socket_addr(ip_bits, next!()))
                };
                Ok(ProviderUpdateServicePayload {
                    version,
                    mn_type,
                    pro_tx_hash,
                    service_address,
                    script_payout: next!(),
                    inputs_hash: next!(),
                    platform_node_id: next!(),
                    platform_p2p_port: next!(),
                    platform_http_port: next!(),
                    payload_sig: next!(),
                })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut version = None;
                let mut mn_type = None;
                let mut pro_tx_hash = None;
                let mut ip_address: Option<u128> = None;
                let mut port: Option<u16> = None;
                let mut service_address = None;
                let mut script_payout = None;
                let mut inputs_hash = None;
                let mut platform_node_id = None;
                let mut platform_p2p_port = None;
                let mut platform_http_port = None;
                let mut payload_sig = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "mn_type" => mn_type = map.next_value()?,
                        "pro_tx_hash" => pro_tx_hash = Some(map.next_value()?),
                        "ip_address" => ip_address = Some(map.next_value()?),
                        "port" => port = Some(map.next_value()?),
                        "service_address" => service_address = Some(map.next_value()?),
                        "script_payout" => script_payout = Some(map.next_value()?),
                        "inputs_hash" => inputs_hash = Some(map.next_value()?),
                        "platform_node_id" => platform_node_id = map.next_value()?,
                        "platform_p2p_port" => platform_p2p_port = map.next_value()?,
                        "platform_http_port" => platform_http_port = map.next_value()?,
                        "payload_sig" => payload_sig = Some(map.next_value()?),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                // The version picks the address form, as in `visit_seq`; the other form's
                // fields are rejected rather than read into a payload that can't be encoded.
                let version: u16 = version.ok_or_else(|| de::Error::missing_field("version"))?;
                let service_address = if version >= ProTxVersion::ExtAddr as u16 {
                    if ip_address.is_some() || port.is_some() {
                        return Err(de::Error::custom(
                            "ip_address and port only exist before version 3",
                        ));
                    }
                    MasternodeNetInfo::Extended(
                        service_address
                            .ok_or_else(|| de::Error::missing_field("service_address"))?,
                    )
                } else {
                    if service_address.is_some() {
                        return Err(de::Error::custom(
                            "service_address only exists from version 3",
                        ));
                    }
                    let ip_bits =
                        ip_address.ok_or_else(|| de::Error::missing_field("ip_address"))?;
                    let port = port.ok_or_else(|| de::Error::missing_field("port"))?;
                    MasternodeNetInfo::Legacy(legacy_socket_addr(ip_bits, port))
                };
                Ok(ProviderUpdateServicePayload {
                    version,
                    mn_type,
                    pro_tx_hash: pro_tx_hash
                        .ok_or_else(|| de::Error::missing_field("pro_tx_hash"))?,
                    service_address,
                    script_payout: script_payout
                        .ok_or_else(|| de::Error::missing_field("script_payout"))?,
                    inputs_hash: inputs_hash
                        .ok_or_else(|| de::Error::missing_field("inputs_hash"))?,
                    platform_node_id,
                    platform_p2p_port,
                    platform_http_port,
                    payload_sig: payload_sig
                        .ok_or_else(|| de::Error::missing_field("payload_sig"))?,
                })
            }
        }

        deserializer.deserialize_struct("ProviderUpdateServicePayload", FIELDS, PayloadVisitor)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use std::net::{Ipv4Addr, SocketAddr};

    use hashes::Hash;

    use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
    use crate::blockdata::transaction::special_transaction::TransactionPayload::ProviderUpdateServicePayloadType;
    use crate::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus::{Decodable, Encodable, deserialize};
    use crate::hash_types::InputsHash;
    use crate::internal_macros::hex;
    use crate::platform_node_id::PlatformNodeId;
    use crate::sml::masternode_list_entry::MasternodeNetInfo;
    use crate::sml::masternode_list_entry::net_info::{
        Bip155Network, ExtNetInfo, NetInfoEntry, NetInfoPurpose,
    };
    use crate::{Network, ScriptBuf, Transaction, Txid};

    fn ext_net_info() -> ExtNetInfo {
        ExtNetInfo {
            version: 1,
            purposes: vec![(
                NetInfoPurpose::CoreP2P,
                vec![NetInfoEntry::Service {
                    network: Bip155Network::Ipv4,
                    addr: vec![1, 2, 3, 4],
                    port: 9999,
                }],
            )],
        }
    }

    fn v3_payload(
        mn_type: u16,
        platform_node_id: Option<PlatformNodeId>,
    ) -> ProviderUpdateServicePayload {
        ProviderUpdateServicePayload {
            version: 3,
            mn_type: Some(mn_type),
            pro_tx_hash: Txid::all_zeros(),
            service_address: MasternodeNetInfo::Extended(ext_net_info()),
            script_payout: ScriptBuf::new(),
            inputs_hash: InputsHash::all_zeros(),
            platform_node_id,
            platform_p2p_port: None,
            platform_http_port: None,
            payload_sig: BLSSignature::from([0; 96]),
        }
    }

    #[test]
    fn round_trip_v3_ext_addr_regular_masternode() {
        let original = v3_payload(0, None);
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // `netInfo` follows version(2) + mn_type(2) + pro_tx_hash(32), in place of ip + port.
        let mut net_info = Vec::new();
        ext_net_info().consensus_encode_ext(&mut net_info).unwrap();
        assert_eq!(&encoded[36..36 + net_info.len()], net_info.as_slice());
        // version(2) + mn_type(2) + pro_tx_hash(32) + net_info + script(1) + inputs_hash(32) + sig(96)
        assert_eq!(encoded.len(), 165 + net_info.len());
        assert_eq!(original.size(), encoded.len());

        let decoded = ProviderUpdateServicePayload::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_v3_ext_addr_evo_masternode_without_platform_ports() {
        let original = v3_payload(1, Some(PlatformNodeId::from_bytes([7; 20])));
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // The node id sits right before the signature, with no p2p/http ports after it.
        assert_eq!(&encoded[encoded.len() - 96 - 20..encoded.len() - 96], &[7; 20]);
        assert_eq!(original.size(), encoded.len());

        let mut reader = &encoded[..];
        let decoded = ProviderUpdateServicePayload::consensus_decode(&mut reader).unwrap();
        assert!(reader.is_empty());
        assert_eq!(decoded, original);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut encoded = Vec::new();
        v3_payload(0, None).consensus_encode(&mut encoded).unwrap();
        encoded[0] = 4;
        assert!(ProviderUpdateServicePayload::consensus_decode(&mut &encoded[..]).is_err());
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn bincode_round_trip_v3() {
        let original = v3_payload(1, Some(PlatformNodeId::from_bytes([7; 20])));
        let bytes = bincode::encode_to_vec(&original, bincode::config::standard()).unwrap();
        let (decoded, read): (ProviderUpdateServicePayload, usize) =
            bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(read, bytes.len());
    }

    #[test]
    fn test_provider_update_service_transaction() {
        // This is a test for testnet
        let _network = Network::Testnet;

        let expected_transaction_bytes = hex!(
            "03000200018f3fe6683e36326669b6e34876fb2a2264e8327e822f6fec304b66f47d61b3e1010000006b48304502210082af6727408f0f2ec16c7da1c42ccf0a026abea6a3a422776272b03c8f4e262a022033b406e556f6de980b2d728e6812b3ae18ee1c863ae573ece1cbdf777ca3e56101210351036c1192eaf763cd8345b44137482ad24b12003f23e9022ce46752edf47e6effffffff0180220e43000000001976a914123cbc06289e768ca7d743c8174b1e6eeb610f1488ac00000000b501003a72099db84b1c1158568eec863bea1b64f90eccee3304209cebe1df5e7539fd00000000000000000000ffff342440944e1f00e6725f799ea20480f06fb105ebe27e7c4845ab84155e4c2adf2d6e5b73a998b1174f9621bbeda5009c5a6487bdf75edcf602b67fe0da15c275cc91777cb25f5fd4bb94e84fd42cb2bb547c83792e57c80d196acd47020e4054895a0640b7861b3729c41dd681d4996090d5750f65c4b649a5cd5b2bdf55c880459821e53d91c9"
        );

        let expected_transaction: Transaction =
            deserialize(expected_transaction_bytes.as_slice()).expect("expected a transaction");

        let expected_provider_update_service_payload = expected_transaction
            .special_transaction_payload
            .clone()
            .unwrap()
            .to_update_service_payload()
            .expect("expected to get a provider registration payload");

        let tx_id =
            Txid::from_str("fa2f2eba320c56fb0efebe2ace3333024104d8d0a30753da36db4bf97c119be7")
                .expect("expected to decode tx id");

        let provider_update_service_payload_version = 1;
        assert_eq!(
            expected_provider_update_service_payload.version,
            provider_update_service_payload_version
        );
        let pro_tx_hash =
            Txid::from_str("fd39755edfe1eb9c200433eecc0ef9641bea3b86ec8e5658111c4bb89d09723a")
                .expect("expected to decode tx id");
        assert_eq!(expected_provider_update_service_payload.pro_tx_hash, pro_tx_hash);

        let service_address = MasternodeNetInfo::Legacy(SocketAddr::from((
            Ipv4Addr::from_str("52.36.64.148").expect("expected an ipv4 address"),
            19999,
        )));
        assert_eq!(expected_provider_update_service_payload.service_address, service_address);

        let inputs_hash_hex = "b198a9735b6e2ddf2a4c5e1584ab45487c7ee2eb05b16ff08004a29e795f72e6";
        assert_eq!(
            expected_provider_update_service_payload.inputs_hash.to_hex().as_str(),
            inputs_hash_hex,
            "inputs hash calculation has issues"
        );

        assert_eq!(
            expected_provider_update_service_payload.base_payload_hash().to_hex().as_str(),
            "9784b3663039784858420677b00f0b3f34af8ff1f1788adfd0e681d345b776ba",
            "Payload hash calculation has issues"
        );

        // We should verify the script payouts match
        let script_payout = ScriptBuf::new();
        assert_eq!(expected_provider_update_service_payload.script_payout, script_payout);

        assert_eq!(expected_transaction.txid(), tx_id);

        //todo: once we have a BLS signatures library in rust we should implement signing
        let payload_sig = expected_transaction
            .special_transaction_payload
            .clone()
            .unwrap()
            .to_update_service_payload()
            .unwrap()
            .payload_sig;

        let transaction = Transaction {
            version: 3,
            lock_time: 0,
            input: expected_transaction.input.clone(), // todo:implement this
            output: expected_transaction.output.clone(), // todo:implement this
            special_transaction_payload: Some(ProviderUpdateServicePayloadType(
                ProviderUpdateServicePayload {
                    version: provider_update_service_payload_version,
                    mn_type: None, // LegacyBLS version
                    pro_tx_hash,
                    service_address,
                    script_payout,
                    inputs_hash: InputsHash::from_str(inputs_hash_hex).unwrap(),
                    platform_node_id: None,
                    platform_p2p_port: None,
                    platform_http_port: None,
                    payload_sig,
                },
            )),
        };

        assert_eq!(transaction.hash_inputs().to_hex(), inputs_hash_hex);

        assert_eq!(transaction, expected_transaction);

        assert_eq!(transaction.txid(), tx_id);
    }

    #[test]
    fn round_trip_v1_legacy_bls() {
        let original = ProviderUpdateServicePayload {
            version: 1,
            mn_type: None,
            pro_tx_hash: Txid::all_zeros(),
            service_address: MasternodeNetInfo::Legacy(SocketAddr::from(([0; 16], 0))),
            script_payout: ScriptBuf::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            inputs_hash: InputsHash::all_zeros(),
            platform_node_id: None,
            platform_p2p_port: None,
            platform_http_port: None,
            payload_sig: BLSSignature::from([0; 96]),
        };

        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // version(2) + pro_tx_hash(32) + ip(16) + port(2) + script(10) + inputs_hash(32) + sig(96)
        assert_eq!(encoded.len(), 191);

        let decoded = ProviderUpdateServicePayload::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_v2_basic_bls_regular_masternode() {
        let original = ProviderUpdateServicePayload {
            version: 2,
            mn_type: Some(0), // Regular
            pro_tx_hash: Txid::all_zeros(),
            service_address: MasternodeNetInfo::Legacy(SocketAddr::from(([0; 16], 0))),
            script_payout: ScriptBuf::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            inputs_hash: InputsHash::all_zeros(),
            platform_node_id: None,
            platform_p2p_port: None,
            platform_http_port: None,
            payload_sig: BLSSignature::from([0; 96]),
        };

        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // v1 base (191) + mn_type(2) = 193
        assert_eq!(encoded.len(), 193);

        let decoded = ProviderUpdateServicePayload::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_v2_basic_bls_evo_masternode() {
        let original = ProviderUpdateServicePayload {
            version: 2,
            mn_type: Some(1), // HighPerformance (Evo)
            pro_tx_hash: Txid::all_zeros(),
            service_address: MasternodeNetInfo::Legacy(SocketAddr::from(([0; 16], 0))),
            script_payout: ScriptBuf::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            inputs_hash: InputsHash::all_zeros(),
            platform_node_id: Some(PlatformNodeId::from_bytes([0; 20])),
            platform_p2p_port: Some(0),
            platform_http_port: Some(0),
            payload_sig: BLSSignature::from([0; 96]),
        };

        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // v1 base (191) + mn_type(2) + platform_node_id(20) + p2p_port(2) + http_port(2) = 217
        assert_eq!(encoded.len(), 217);

        let decoded = ProviderUpdateServicePayload::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, original);
    }

    /// A v2 Evo payload with absent platform fields still writes the
    /// zero-filled node id and ports on the wire.
    #[test]
    fn v2_evo_masternode_none_platform_fields_encode_zero_filled() {
        let original = ProviderUpdateServicePayload {
            version: 2,
            mn_type: Some(1), // HighPerformance (Evo)
            pro_tx_hash: Txid::all_zeros(),
            service_address: MasternodeNetInfo::Legacy(SocketAddr::from(([0; 16], 0))),
            script_payout: ScriptBuf::new(),
            inputs_hash: InputsHash::all_zeros(),
            platform_node_id: None,
            platform_p2p_port: None,
            platform_http_port: None,
            payload_sig: BLSSignature::from([0; 96]),
        };

        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // version(2) + mn_type(2) + pro_tx_hash(32) + ip(16) + port(2) +
        // script(1) + inputs_hash(32) + node_id(20) + p2p(2) + http(2) + sig(96)
        assert_eq!(encoded.len(), 207);

        let decoded = ProviderUpdateServicePayload::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.platform_node_id, Some(PlatformNodeId::from_bytes([0; 20])));
        assert_eq!(decoded.platform_p2p_port, Some(0));
        assert_eq!(decoded.platform_http_port, Some(0));
    }

    #[test]
    fn test_protx_update_v2_block_parsing() {
        use crate::blockdata::block::Block;
        use crate::blockdata::transaction::special_transaction::TransactionType;
        use crate::consensus::deserialize;
        use std::fs;
        use std::path::Path;

        // Load block data containing ProTx Update Service v2 transactions (BasicBLS version)
        let block_data_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("dash/contrib/protx_update_v2_block.data");

        println!("🔍 Testing ProTx Update Service v2 (BasicBLS) block parsing");

        let block_hex_string = match fs::read_to_string(&block_data_path) {
            Ok(content) => content.trim().to_string(),
            Err(_e) => {
                println!("⚠️  Skipping test - protx_update_v2_block.data not found");
                return; // Skip test if file not found
            }
        };

        // Decode hex to bytes
        let block_bytes = match hex_conservative::decode_to_vec(&block_hex_string) {
            Ok(bytes) => bytes,
            Err(e) => {
                panic!("❌ Failed to decode hex: {}", e);
            }
        };

        // Try to compute block hash from header first
        let expected_block_hash = if block_bytes.len() >= 80 {
            match crate::blockdata::block::Header::consensus_decode(&mut std::io::Cursor::new(
                &block_bytes[0..80],
            )) {
                Ok(header) => {
                    let hash = header.block_hash();
                    println!("🔗 Block hash: {}", hash);
                    Some(hash)
                }
                Err(e) => {
                    panic!("❌ Failed to decode block header: {}", e);
                }
            }
        } else {
            panic!("❌ Block data too short");
        };

        // Now try to deserialize the full block - this should succeed with our ProTx fix
        match deserialize::<Block>(&block_bytes) {
            Ok(block) => {
                let actual_hash = block.block_hash();
                println!("✅ Successfully deserialized block with ProTx transactions!");
                println!("  Block hash: {}", actual_hash);
                println!("  Transaction count: {}", block.txdata.len());

                // Verify block hash matches
                if let Some(expected_hash) = expected_block_hash {
                    assert_eq!(expected_hash, actual_hash, "Block hash mismatch");
                }

                // Analyze transactions for ProUpServTx (Type 2) transactions
                let mut found_protx = false;
                for (i, tx) in block.txdata.iter().enumerate() {
                    let tx_type = tx.tx_type();
                    if tx_type == TransactionType::ProviderUpdateService {
                        println!("  🎯 Found ProUpServTx (Type 2) at index {}", i);
                        found_protx = true;

                        // Test that we can parse the payload
                        if let Some(payload) = &tx.special_transaction_payload {
                            match payload.clone().to_update_service_payload() {
                                Ok(protx_payload) => {
                                    println!("    ✅ Successfully parsed ProUpServTx payload:");
                                    println!("       Version: {}", protx_payload.version);
                                    println!("       ProTxHash: {}", protx_payload.pro_tx_hash);
                                    println!("       Service: {:?}", protx_payload.service_address);
                                    println!(
                                        "       Script length: {}",
                                        protx_payload.script_payout.len()
                                    );
                                    println!(
                                        "       Has nType: {}",
                                        protx_payload.mn_type.is_some()
                                    );
                                    println!(
                                        "       Has platform fields: {}",
                                        protx_payload.platform_node_id.is_some()
                                    );
                                }
                                Err(e) => {
                                    panic!("❌ Failed to parse ProUpServTx payload: {}", e);
                                }
                            }
                        }
                    }
                }

                if !found_protx {
                    println!("⚠️  No ProUpServTx transactions found in this block");
                }

                println!("🎉 ProTx block parsing test passed!");
            }
            Err(e) => {
                panic!("❌ Block parsing failed even with ProTx fix: {}", e);
            }
        }
    }

    #[test]
    fn test_protx_block_parsing_with_pro_reg_tx() {
        use crate::blockdata::block::Block;
        use crate::blockdata::transaction::special_transaction::TransactionType;
        use crate::consensus::deserialize;
        use std::fs;
        use std::path::Path;

        // Test block with Provider Registration transactions
        let block_data_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("dash/contrib/block_with_pro_reg_tx.data");

        println!("🔍 Testing ProTx block parsing with ProRegTx transactions");

        let block_hex_string = match fs::read_to_string(&block_data_path) {
            Ok(content) => content.trim().to_string(),
            Err(_e) => {
                println!("⚠️  Skipping test - block_with_pro_reg_tx.data not found");
                return; // Skip test if file not found
            }
        };

        let block_bytes = match hex_conservative::decode_to_vec(&block_hex_string) {
            Ok(bytes) => bytes,
            Err(e) => {
                panic!("❌ Failed to decode hex: {}", e);
            }
        };

        let expected_hash = "000000000000002016c49d804e7b5d6ca84663ed032222e9061b2efec302edc3";

        // Verify block hash from header
        if block_bytes.len() >= 80 {
            match crate::blockdata::block::Header::consensus_decode(&mut std::io::Cursor::new(
                &block_bytes[0..80],
            )) {
                Ok(header) => {
                    let hash = header.block_hash();
                    assert_eq!(hash.to_string(), expected_hash, "Wrong block - hash mismatch");
                    println!("🔗 Confirmed correct block hash: {}", expected_hash);
                }
                Err(e) => {
                    panic!("❌ Failed to decode block header: {}", e);
                }
            }
        }

        // Parse the full block
        match deserialize::<Block>(&block_bytes) {
            Ok(block) => {
                println!("✅ Successfully parsed block with ProRegTx transactions!");
                println!("  Transaction count: {}", block.txdata.len());

                // Look for Provider Registration transactions
                let mut found_pro_reg = false;
                for (i, tx) in block.txdata.iter().enumerate() {
                    let tx_type = tx.tx_type();
                    if tx_type == TransactionType::ProviderRegistration {
                        println!("  🎯 Found ProRegTx (Type 1) at index {}", i);
                        found_pro_reg = true;

                        // Test payload parsing
                        if let Some(payload) = &tx.special_transaction_payload {
                            match payload.clone().to_provider_registration_payload() {
                                Ok(pro_reg_payload) => {
                                    println!("    ✅ Successfully parsed ProRegTx payload:");
                                    println!("       Version: {}", pro_reg_payload.version);
                                    println!(
                                        "       Masternode type: {:?}",
                                        pro_reg_payload.masternode_type
                                    );
                                    println!(
                                        "       Service address: {}",
                                        pro_reg_payload.service_address
                                    );
                                    println!(
                                        "       Platform fields: node_id={:?}, p2p_port={:?}, http_port={:?}",
                                        pro_reg_payload.platform_node_id.is_some(),
                                        pro_reg_payload.platform_p2p_port,
                                        pro_reg_payload.platform_http_port
                                    );
                                }
                                Err(e) => {
                                    panic!("❌ Failed to parse ProRegTx payload: {}", e);
                                }
                            }
                        }
                    }
                }

                if !found_pro_reg {
                    println!("⚠️  No ProRegTx transactions found in this block");
                }

                println!("🎉 ProRegTx block parsing test passed!");
            }
            Err(e) => {
                panic!("❌ Block parsing failed: {}", e);
            }
        }
    }

    #[test_case::test_case(2, MasternodeNetInfo::Extended(ext_net_info()); "extended before v3")]
    #[test_case::test_case(3, MasternodeNetInfo::Legacy(SocketAddr::from(([127, 0, 0, 1], 9999))); "legacy at v3")]
    fn service_address_must_match_the_version(version: u16, service_address: MasternodeNetInfo) {
        let payload = ProviderUpdateServicePayload {
            version,
            service_address,
            ..v3_payload(0, None)
        };
        assert!(payload.consensus_encode(&mut Vec::new()).is_err());
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn bincode_decodes_the_pre_v3_layout() {
        // The earlier derived impl stored the service as an ip `u128`, whose little-endian bytes
        // are the IPv6 octets, followed by the port.
        let mut octets = [0u8; 16];
        octets[10..12].copy_from_slice(&[0xff, 0xff]);
        octets[12..].copy_from_slice(&[52, 36, 64, 148]);
        let old_layout = (
            2u16,
            Some(0u16),
            Txid::all_zeros(),
            u128::from_le_bytes(octets),
            19999u16,
            ScriptBuf::new(),
            InputsHash::all_zeros(),
            None::<PlatformNodeId>,
            None::<u16>,
            None::<u16>,
            BLSSignature::from([0; 96]),
        );
        let bytes = bincode::encode_to_vec(&old_layout, bincode::config::standard()).unwrap();
        let (decoded, _): (ProviderUpdateServicePayload, usize) =
            bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(
            decoded.service_address,
            MasternodeNetInfo::Legacy(SocketAddr::from(([52, 36, 64, 148], 19999)))
        );
        assert_eq!(bincode::encode_to_vec(&decoded, bincode::config::standard()).unwrap(), bytes);
    }

    /// The shape `ProviderUpdateServicePayload` had with derived serde before version 3.
    #[cfg(feature = "serde")]
    #[derive(serde::Serialize, serde::Deserialize)]
    struct PreV3ProviderUpdateServicePayload {
        version: u16,
        mn_type: Option<u16>,
        pro_tx_hash: Txid,
        ip_address: u128,
        port: u16,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        platform_node_id: Option<PlatformNodeId>,
        platform_p2p_port: Option<u16>,
        platform_http_port: Option<u16>,
        payload_sig: BLSSignature,
    }

    /// A v2 Evo payload at 52.36.64.148:19999 and its pre-v3 derived shape.
    #[cfg(feature = "serde")]
    fn v2_payloads() -> (ProviderUpdateServicePayload, PreV3ProviderUpdateServicePayload) {
        let node_id = Some(PlatformNodeId::from_bytes([7; 20]));
        let payload = ProviderUpdateServicePayload {
            version: 2,
            mn_type: Some(1),
            pro_tx_hash: Txid::from_byte_array([1; 32]),
            service_address: MasternodeNetInfo::Legacy(SocketAddr::from((
                [52, 36, 64, 148],
                19999,
            ))),
            script_payout: ScriptBuf::from(vec![0xaa; 4]),
            inputs_hash: InputsHash::from_byte_array([2; 32]),
            platform_node_id: node_id,
            platform_p2p_port: Some(26656),
            platform_http_port: Some(443),
            payload_sig: BLSSignature::from([3; 96]),
        };
        let mut octets = [0u8; 16];
        octets[10..12].copy_from_slice(&[0xff, 0xff]);
        octets[12..].copy_from_slice(&[52, 36, 64, 148]);
        let pre_v3 = PreV3ProviderUpdateServicePayload {
            version: 2,
            mn_type: Some(1),
            pro_tx_hash: payload.pro_tx_hash,
            ip_address: u128::from_le_bytes(octets),
            port: 19999,
            script_payout: payload.script_payout.clone(),
            inputs_hash: payload.inputs_hash,
            platform_node_id: node_id,
            platform_p2p_port: Some(26656),
            platform_http_port: Some(443),
            payload_sig: BLSSignature::from([3; 96]),
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
        let (decoded, read): (ProviderUpdateServicePayload, usize) =
            bincode::serde::decode_from_slice(&old_bytes, config).unwrap();
        assert_eq!((decoded, read), (payload, old_bytes.len()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_keeps_the_pre_v3_shape_before_version_3() {
        // As a string: `serde_json::Value` can't hold the `u128` ip.
        let (payload, pre_v3) = v2_payloads();
        let old_json = serde_json::to_string(&pre_v3).unwrap();
        assert_eq!(serde_json::to_string(&payload).unwrap(), old_json);
        assert_eq!(
            serde_json::from_str::<ProviderUpdateServicePayload>(&old_json).unwrap(),
            payload
        );
    }

    #[cfg(all(feature = "serde", feature = "bincode"))]
    #[test]
    fn serde_round_trips_the_extended_addresses_at_version_3() {
        let payload = v3_payload(1, Some(PlatformNodeId::from_bytes([7; 20])));
        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&payload, config).unwrap();
        let (decoded, read): (ProviderUpdateServicePayload, usize) =
            bincode::serde::decode_from_slice(&bytes, config).unwrap();
        assert_eq!((decoded, read), (payload.clone(), bytes.len()));

        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(serde_json::from_value::<ProviderUpdateServicePayload>(json).unwrap(), payload);
    }

    /// The JSON of a valid payload relabelled with the other address form's version.
    #[cfg(feature = "serde")]
    #[test_case::test_case(v3_payload(0, None), 2; "service_address before version 3")]
    #[test_case::test_case(v2_payloads().0, 3; "ip_address and port at version 3")]
    fn json_rejects_the_address_form_of_another_version(
        payload: ProviderUpdateServicePayload,
        version: u16,
    ) {
        let json = serde_json::to_string(&payload).unwrap().replacen(
            &format!("\"version\":{}", payload.version),
            &format!("\"version\":{version}"),
            1,
        );
        assert!(serde_json::from_str::<ProviderUpdateServicePayload>(&json).is_err());
    }
}
