use std::io;
use std::io::{Read, Write};
use std::mem;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::consensus::encode::{Error, MAX_VEC_SIZE, VarInt};
use crate::consensus::{Decodable, Encodable};

const EXTNETINFO_CURRENT_VERSION: u8 = 1;

const NET_TYPE_SERVICE: u8 = 0x01;
const NET_TYPE_DOMAIN: u8 = 0x02;
const NET_TYPE_INVALID: u8 = 0xff;

/// BIP155 network identifiers as used inside an ADDRV2-form `CService`.
///
/// Tor v2 (id 3) and unknown ids are never emitted by Core and are rejected on decode.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Bip155Network {
    Ipv4,
    Ipv6,
    TorV3,
    I2p,
    Cjdns,
}

impl Bip155Network {
    fn from_u8(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Bip155Network::Ipv4),
            2 => Ok(Bip155Network::Ipv6),
            4 => Ok(Bip155Network::TorV3),
            5 => Ok(Bip155Network::I2p),
            6 => Ok(Bip155Network::Cjdns),
            received => Err(Error::InvalidEnumValue {
                max: 6,
                received: received as u16,
                msg: "Invalid BIP155 network id".to_string(),
            }),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Bip155Network::Ipv4 => 1,
            Bip155Network::Ipv6 => 2,
            Bip155Network::TorV3 => 4,
            Bip155Network::I2p => 5,
            Bip155Network::Cjdns => 6,
        }
    }

    fn address_len(self) -> usize {
        match self {
            Bip155Network::Ipv4 => 4,
            Bip155Network::Ipv6 => 16,
            Bip155Network::TorV3 => 32,
            Bip155Network::I2p => 32,
            Bip155Network::Cjdns => 16,
        }
    }
}

/// A single network info entry within an `ExtNetInfo` purpose list.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetInfoEntry {
    Service {
        network: Bip155Network,
        addr: Vec<u8>,
        port: u16,
    },
    Domain {
        host: String,
        port: u16,
    },
    Invalid,
}

impl NetInfoEntry {
    fn consensus_encode_ext<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        match self {
            NetInfoEntry::Service {
                network,
                addr,
                port,
            } => {
                len += NET_TYPE_SERVICE.consensus_encode(writer)?;
                len += network.to_u8().consensus_encode(writer)?;
                len += VarInt(addr.len() as u64).consensus_encode(writer)?;
                writer.write_all(addr)?;
                len += addr.len();
                writer.write_all(&port.to_be_bytes())?;
                len += 2;
            }
            NetInfoEntry::Domain {
                host,
                port,
            } => {
                len += NET_TYPE_DOMAIN.consensus_encode(writer)?;
                len += host.consensus_encode(writer)?;
                writer.write_all(&port.to_be_bytes())?;
                len += 2;
            }
            NetInfoEntry::Invalid => {
                len += NET_TYPE_INVALID.consensus_encode(writer)?;
            }
        }
        Ok(len)
    }

    fn consensus_decode_ext<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let net_type: u8 = Decodable::consensus_decode(reader)?;
        match net_type {
            NET_TYPE_SERVICE => {
                let network = Bip155Network::from_u8(Decodable::consensus_decode(reader)?)?;
                let addr_len = VarInt::consensus_decode(reader)?.0 as usize;
                if addr_len != network.address_len() {
                    return Err(Error::ParseFailed("BIP155 address length does not match network"));
                }
                let mut addr = vec![0u8; addr_len];
                reader.read_exact(&mut addr)?;
                let mut port_bytes = [0u8; 2];
                reader.read_exact(&mut port_bytes)?;
                let port = u16::from_be_bytes(port_bytes);
                Ok(NetInfoEntry::Service {
                    network,
                    addr,
                    port,
                })
            }
            NET_TYPE_DOMAIN => {
                let host = String::consensus_decode(reader)?;
                let mut port_bytes = [0u8; 2];
                reader.read_exact(&mut port_bytes)?;
                let port = u16::from_be_bytes(port_bytes);
                Ok(NetInfoEntry::Domain {
                    host,
                    port,
                })
            }
            NET_TYPE_INVALID => Ok(NetInfoEntry::Invalid),
            received => Err(Error::InvalidEnumValue {
                max: 0xff,
                received: received as u16,
                msg: "Invalid NetInfoEntry type".to_string(),
            }),
        }
    }
}

/// Purpose codes keyed in an `ExtNetInfo` map.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetInfoPurpose {
    CoreP2P,
    PlatformP2P,
    PlatformHttps,
}

impl NetInfoPurpose {
    fn from_u8(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(NetInfoPurpose::CoreP2P),
            1 => Ok(NetInfoPurpose::PlatformP2P),
            2 => Ok(NetInfoPurpose::PlatformHttps),
            received => Err(Error::InvalidEnumValue {
                max: 2,
                received: received as u16,
                msg: "Invalid NetInfoPurpose".to_string(),
            }),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            NetInfoPurpose::CoreP2P => 0,
            NetInfoPurpose::PlatformP2P => 1,
            NetInfoPurpose::PlatformHttps => 2,
        }
    }
}

/// Variable-length extended network info introduced for ProTx version 3.
///
/// `purposes` preserves the exact on-wire pair order so that a decode followed by an encode
/// reproduces the original bytes.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtNetInfo {
    pub version: u8,
    pub purposes: Vec<(NetInfoPurpose, Vec<NetInfoEntry>)>,
}

impl ExtNetInfo {
    pub(super) fn consensus_encode_ext<W: Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, io::Error> {
        let mut len = self.version.consensus_encode(writer)?;
        // Unknown versions carry no further payload, mirroring Core's short-circuit.
        if self.version == 0 || self.version > EXTNETINFO_CURRENT_VERSION {
            return Ok(len);
        }
        len += VarInt(self.purposes.len() as u64).consensus_encode(writer)?;
        for (purpose, entries) in &self.purposes {
            len += purpose.to_u8().consensus_encode(writer)?;
            len += VarInt(entries.len() as u64).consensus_encode(writer)?;
            for entry in entries {
                len += entry.consensus_encode_ext(writer)?;
            }
        }
        Ok(len)
    }

    pub(super) fn consensus_decode_ext<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let version: u8 = Decodable::consensus_decode(reader)?;
        if version == 0 || version > EXTNETINFO_CURRENT_VERSION {
            return Ok(ExtNetInfo {
                version,
                purposes: Vec::new(),
            });
        }
        let n_purposes = VarInt::consensus_decode(reader)?.0;
        // Cap speculative allocation so a malicious count cannot trigger an unbounded reserve.
        let max_purposes = MAX_VEC_SIZE / 4 / mem::size_of::<(NetInfoPurpose, Vec<NetInfoEntry>)>();
        let mut purposes = Vec::with_capacity(core::cmp::min(n_purposes as usize, max_purposes));
        for _ in 0..n_purposes {
            let purpose = NetInfoPurpose::from_u8(Decodable::consensus_decode(reader)?)?;
            let n_entries = VarInt::consensus_decode(reader)?.0;
            let max_entries = MAX_VEC_SIZE / 4 / mem::size_of::<NetInfoEntry>();
            let mut entries = Vec::with_capacity(core::cmp::min(n_entries as usize, max_entries));
            for _ in 0..n_entries {
                entries.push(NetInfoEntry::consensus_decode_ext(reader)?);
            }
            purposes.push((purpose, entries));
        }
        Ok(ExtNetInfo {
            version,
            purposes,
        })
    }

    pub fn platform_https_port(&self) -> Option<u16> {
        self.entries_for(NetInfoPurpose::PlatformHttps).iter().find_map(|entry| match entry {
            NetInfoEntry::Service {
                port,
                ..
            }
            | NetInfoEntry::Domain {
                port,
                ..
            } => Some(*port),
            NetInfoEntry::Invalid => None,
        })
    }

    pub(super) fn entries_for(&self, purpose: NetInfoPurpose) -> &[NetInfoEntry] {
        self.purposes
            .iter()
            .find(|(p, _)| *p == purpose)
            .map(|(_, entries)| entries.as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(entry: &NetInfoEntry) -> Vec<u8> {
        let mut buf = Vec::new();
        entry.consensus_encode_ext(&mut buf).unwrap();
        let decoded = NetInfoEntry::consensus_decode_ext(&mut buf.as_slice()).unwrap();
        assert_eq!(*entry, decoded);
        buf
    }

    fn roundtrip_ext(info: &ExtNetInfo) -> Vec<u8> {
        let mut buf = Vec::new();
        info.consensus_encode_ext(&mut buf).unwrap();
        let decoded = ExtNetInfo::consensus_decode_ext(&mut buf.as_slice()).unwrap();
        assert_eq!(*info, decoded);
        buf
    }

    #[test]
    fn service_ipv4() {
        let entry = NetInfoEntry::Service {
            network: Bip155Network::Ipv4,
            addr: vec![1, 2, 3, 4],
            port: 9999,
        };
        let bytes = roundtrip(&entry);
        assert_eq!(bytes, vec![0x01, 0x01, 0x04, 1, 2, 3, 4, 0x27, 0x0f]);
    }

    #[test]
    fn service_ipv6() {
        let entry = NetInfoEntry::Service {
            network: Bip155Network::Ipv6,
            addr: (0..16).collect(),
            port: 1,
        };
        roundtrip(&entry);
    }

    #[test]
    fn domain_entry() {
        let entry = NetInfoEntry::Domain {
            host: "example.org".to_string(),
            port: 443,
        };
        let bytes = roundtrip(&entry);
        assert_eq!(bytes[0], 0x02);
        assert_eq!(&bytes[bytes.len() - 2..], &443u16.to_be_bytes());
    }

    #[test]
    fn invalid_entry() {
        let entry = NetInfoEntry::Invalid;
        let bytes = roundtrip(&entry);
        assert_eq!(bytes, vec![0xff]);
    }

    #[test]
    fn multi_purpose_map() {
        let info = ExtNetInfo {
            version: 1,
            purposes: vec![
                (
                    NetInfoPurpose::CoreP2P,
                    vec![NetInfoEntry::Service {
                        network: Bip155Network::Ipv4,
                        addr: vec![10, 0, 0, 1],
                        port: 9999,
                    }],
                ),
                (
                    NetInfoPurpose::PlatformP2P,
                    vec![NetInfoEntry::Service {
                        network: Bip155Network::Ipv4,
                        addr: vec![10, 0, 0, 1],
                        port: 26656,
                    }],
                ),
                (
                    NetInfoPurpose::PlatformHttps,
                    vec![NetInfoEntry::Service {
                        network: Bip155Network::Ipv4,
                        addr: vec![10, 0, 0, 1],
                        port: 443,
                    }],
                ),
            ],
        };
        roundtrip_ext(&info);
        assert_eq!(info.platform_https_port(), Some(443));
    }

    #[test]
    fn multiple_entries_one_purpose() {
        let info = ExtNetInfo {
            version: 1,
            purposes: vec![(
                NetInfoPurpose::CoreP2P,
                vec![
                    NetInfoEntry::Service {
                        network: Bip155Network::Ipv4,
                        addr: vec![1, 1, 1, 1],
                        port: 1,
                    },
                    NetInfoEntry::Service {
                        network: Bip155Network::Ipv6,
                        addr: (0..16).collect(),
                        port: 2,
                    },
                    NetInfoEntry::Domain {
                        host: "node.example".to_string(),
                        port: 3,
                    },
                    NetInfoEntry::Invalid,
                ],
            )],
        };
        roundtrip_ext(&info);
    }

    #[test]
    fn empty_map() {
        let info = ExtNetInfo {
            version: 1,
            purposes: Vec::new(),
        };
        let bytes = roundtrip_ext(&info);
        assert_eq!(bytes, vec![0x01, 0x00]);
    }

    #[test]
    fn unknown_version_short_circuit() {
        for version in [0u8, 2, 255] {
            let info = ExtNetInfo {
                version,
                purposes: Vec::new(),
            };
            let bytes = roundtrip_ext(&info);
            assert_eq!(bytes, vec![version]);
        }
    }

    #[test]
    fn unknown_network_rejected() {
        let bytes = [NET_TYPE_SERVICE, 3u8, 0x04, 0, 0, 0, 0, 0, 0];
        assert!(NetInfoEntry::consensus_decode_ext(&mut bytes.as_slice()).is_err());
    }
}
