use std::collections::BTreeSet;
use std::io;
use std::io::{Read, Write};
use std::mem;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use thiserror::Error;

use crate::consensus::encode::{Error, MAX_VEC_SIZE, VarInt};
use crate::consensus::{Decodable, Encodable};

const EXTNETINFO_CURRENT_VERSION: u8 = 1;

const NET_TYPE_SERVICE: u8 = 0x01;
const NET_TYPE_DOMAIN: u8 = 0x02;
const NET_TYPE_INVALID: u8 = 0xff;

/// Dash Core's `PRIVILEGED_PORTS_THRESHOLD`: the last of the RFC 6335 system ports, all of
/// which `IsBadPort` refuses.
const PRIVILEGED_PORTS_THRESHOLD: u16 = 1023;

/// The ports above the system ports that Dash Core's `IsBadPort` refuses, from `src/netbase.cpp`
/// in Dash Core v24.0.0-rc.4.
const BAD_PORTS: [u16; 21] = [
    1719,  // h323gatestat
    1720,  // h323hostcall
    1723,  // pptp
    2049,  // nfs
    3659,  // apple-sasl / PasswordServer
    4045,  // lockd
    5060,  // sip
    5061,  // sips
    6000,  // X11
    6566,  // sane-port
    6665,  // Alternate IRC
    6666,  // Alternate IRC
    6667,  // Standard IRC
    6668,  // Alternate IRC
    6669,  // Alternate IRC
    6697,  // IRC + TLS
    8332,  // Bitcoin RPC
    8333,  // Bitcoin P2P
    10080, // Amanda
    18332, // Bitcoin testnet RPC
    18333, // Bitcoin testnet RPC
];

/// The one port `IsBadPort` refuses that Dash Core lets Platform HTTPS use
/// (`IsAllowedPlatformHTTPPort`): Core allows it for a Platform HTTPS service entry and for every
/// domain entry.
const PLATFORM_HTTPS_PORT: u16 = 443;

/// BIP155 network identifiers as used inside an ADDRV2-form `CService`.
///
/// Tor v2 (id 3) and unknown ids are never emitted by Core and are rejected on decode.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
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
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
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
    /// The port of a service or domain entry; an invalid entry has none.
    pub fn port(&self) -> Option<u16> {
        match self {
            NetInfoEntry::Service {
                port,
                ..
            }
            | NetInfoEntry::Domain {
                port,
                ..
            } => Some(*port),
            NetInfoEntry::Invalid => None,
        }
    }

    /// The serialized size of the entry in bytes.
    fn size(&self) -> usize {
        match self {
            NetInfoEntry::Service {
                addr,
                ..
            } => 1 + 1 + VarInt(addr.len() as u64).len() + addr.len() + 2,
            NetInfoEntry::Domain {
                host,
                ..
            } => 1 + VarInt(host.len() as u64).len() + host.len() + 2,
            NetInfoEntry::Invalid => 1,
        }
    }

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
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
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
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtNetInfo {
    pub version: u8,
    pub purposes: Vec<(NetInfoPurpose, Vec<NetInfoEntry>)>,
}

impl ExtNetInfo {
    /// The serialized size of the network info in bytes.
    pub fn size(&self) -> usize {
        // Unknown versions carry no further payload, mirroring Core's short-circuit.
        if self.version == 0 || self.version > EXTNETINFO_CURRENT_VERSION {
            return 1;
        }
        1 + VarInt(self.purposes.len() as u64).len()
            + self
                .purposes
                .iter()
                .map(|(_, entries)| {
                    1 + VarInt(entries.len() as u64).len()
                        + entries.iter().map(NetInfoEntry::size).sum::<usize>()
                })
                .sum::<usize>()
    }

    pub(crate) fn consensus_encode_ext<W: Write + ?Sized>(
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

    pub(crate) fn consensus_decode_ext<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
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
        self.entries_for(NetInfoPurpose::PlatformHttps).iter().find_map(NetInfoEntry::port)
    }

    /// Checks the map against the port and duplicate-entry rules of Dash Core's
    /// `ExtNetInfo::Validate` (`src/evo/netinfo.cpp` in Dash Core v24.0.0-rc.4), in the order Core
    /// applies them, so a builder can find a ProRegTx or ProUpServTx Core would refuse before it
    /// signs one. Core's other rules are not checked, so a map that passes may still be refused.
    pub fn validate_ports_and_duplicates(&self) -> Result<(), ExtNetInfoError> {
        let mut known = BTreeSet::new();
        for (_, entries) in &self.purposes {
            for entry in entries {
                if !known.insert(entry) {
                    return Err(ExtNetInfoError::Duplicate);
                }
            }
        }
        for (purpose, entries) in &self.purposes {
            let mut addresses = BTreeSet::new();
            for entry in entries {
                if !addresses.insert(AddressKey::of(entry)) {
                    return Err(ExtNetInfoError::Duplicate);
                }
            }
            for entry in entries {
                if let Some(port) = refused_port(*purpose, entry) {
                    return Err(ExtNetInfoError::BadPort(port));
                }
            }
        }
        Ok(())
    }

    pub(super) fn entries_for(&self, purpose: NetInfoPurpose) -> &[NetInfoEntry] {
        self.purposes
            .iter()
            .find(|(p, _)| *p == purpose)
            .map(|(_, entries)| entries.as_slice())
            .unwrap_or(&[])
    }
}

/// A port or duplicate-entry rule of Dash Core's `ExtNetInfo::Validate` that an [`ExtNetInfo`]
/// breaks, as found by [`ExtNetInfo::validate_ports_and_duplicates`]. The variants are the
/// `NetInfoStatus` codes Core returns for those rules.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtNetInfoError {
    /// An entry repeats the address and port of another entry, under any purpose, or the address
    /// of another entry of its purpose. Core refuses the map with `bad-protx-dup-netinfo-entry`.
    #[error("Address map has a duplicate entry")]
    Duplicate,
    /// An entry has a port Core refuses for its purpose. Core refuses the map with
    /// `bad-protx-netinfo-port`.
    #[error("Dash Core refuses port {0} for this entry")]
    BadPort(u16),
}

/// Whether Dash Core's `IsBadPort` (`src/netbase.cpp` in Dash Core v24.0.0-rc.4) refuses `port`:
/// every system port and the well-known ports in [`BAD_PORTS`]. Port 0 is not a bad port; Core
/// refuses it separately.
fn is_bad_port(port: u16) -> bool {
    (1..=PRIVILEGED_PORTS_THRESHOLD).contains(&port) || BAD_PORTS.contains(&port)
}

/// The port of `entry` if Dash Core refuses it for `purpose` (`ExtNetInfo::ValidateService` and
/// `ExtNetInfo::ValidateDomainPort`). An invalid entry has no port to refuse.
fn refused_port(purpose: NetInfoPurpose, entry: &NetInfoEntry) -> Option<u16> {
    let port = entry.port()?;
    let refused = match entry {
        // I2P SAM 3.1 has no ports, so Core holds every I2P entry to port 0.
        NetInfoEntry::Service {
            network: Bip155Network::I2p,
            ..
        } => port != 0,
        _ => {
            let allowed_https_port = port == PLATFORM_HTTPS_PORT
                && (purpose == NetInfoPurpose::PlatformHttps
                    || matches!(entry, NetInfoEntry::Domain { .. }));
            port == 0 || (is_bad_port(port) && !allowed_https_port)
        }
    };
    refused.then_some(port)
}

/// The address of an entry without its port, as Dash Core compares it when it refuses two
/// entries of one purpose that share an address (`HasAddrDuplicates` compares `ToStringAddr`).
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
enum AddressKey<'a> {
    Service(Bip155Network, &'a [u8]),
    Domain(&'a str),
    Invalid,
}

impl<'a> AddressKey<'a> {
    /// Core prints a CJDNS address the way it prints an IPv6 one, so the two networks share
    /// their keys.
    fn of(entry: &'a NetInfoEntry) -> Self {
        match entry {
            NetInfoEntry::Service {
                network: Bip155Network::Cjdns,
                addr,
                ..
            } => AddressKey::Service(Bip155Network::Ipv6, addr),
            NetInfoEntry::Service {
                network,
                addr,
                ..
            } => AddressKey::Service(*network, addr),
            NetInfoEntry::Domain {
                host,
                ..
            } => AddressKey::Domain(host),
            NetInfoEntry::Invalid => AddressKey::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::Bip155Network::{Cjdns, I2p, Ipv4, Ipv6, TorV3};
    use super::ExtNetInfoError::{BadPort, Duplicate};
    use super::NetInfoPurpose::{CoreP2P, PlatformHttps, PlatformP2P};
    use super::*;

    fn roundtrip(entry: &NetInfoEntry) -> Vec<u8> {
        let mut buf = Vec::new();
        entry.consensus_encode_ext(&mut buf).unwrap();
        let decoded = NetInfoEntry::consensus_decode_ext(&mut buf.as_slice()).unwrap();
        assert_eq!(*entry, decoded);
        assert_eq!(entry.size(), buf.len());
        buf
    }

    fn roundtrip_ext(info: &ExtNetInfo) -> Vec<u8> {
        let mut buf = Vec::new();
        info.consensus_encode_ext(&mut buf).unwrap();
        let decoded = ExtNetInfo::consensus_decode_ext(&mut buf.as_slice()).unwrap();
        assert_eq!(*info, decoded);
        assert_eq!(info.size(), buf.len());
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

    fn service(network: Bip155Network, port: u16) -> NetInfoEntry {
        NetInfoEntry::Service {
            network,
            addr: vec![0xfc; network.address_len()],
            port,
        }
    }

    fn domain(port: u16) -> NetInfoEntry {
        NetInfoEntry::Domain {
            host: "example.com".to_string(),
            port,
        }
    }

    /// The single `purpose` of a map, holding `entry`.
    fn one(
        purpose: NetInfoPurpose,
        entry: NetInfoEntry,
    ) -> Vec<(NetInfoPurpose, Vec<NetInfoEntry>)> {
        vec![(purpose, vec![entry])]
    }

    /// Core refuses port 0 and the ports `IsBadPort` lists (the system ports up to 1023 and
    /// well-known ports from 1719 to 18333), except 443 for a Platform HTTPS service, which mainnet
    /// evonodes serve on, and for a domain, whose port rule ignores the purpose. It holds I2P,
    /// which has no ports, to port 0. It refuses an entry that repeats the address and port of
    /// another under any purpose, and two entries of one purpose that share an address, comparing
    /// addresses as it prints them: IPv6 and CJDNS addresses of the same bytes collide, Tor and
    /// I2P ones do not. It looks for repeated entries in the whole map first, then checks each
    /// purpose in turn: a shared address, then the ports.
    #[test_case(one(CoreP2P, service(Ipv4, 9999)) => Ok(()) ; "a usual port")]
    #[test_case(one(CoreP2P, service(Ipv4, 0)) => Err(BadPort(0)) ; "port 0")]
    #[test_case(one(CoreP2P, service(Ipv4, 1)) => Err(BadPort(1)) ; "first system port")]
    #[test_case(one(PlatformP2P, service(Ipv4, 1023)) => Err(BadPort(1023)) ; "last system port")]
    #[test_case(one(PlatformP2P, service(Ipv4, 1024)) => Ok(()) ; "first port after system ports")]
    #[test_case(one(CoreP2P, service(Ipv4, 1719)) => Err(BadPort(1719)) ; "first well-known port")]
    #[test_case(one(CoreP2P, service(Ipv4, 18333)) => Err(BadPort(18333)) ; "last well-known port")]
    #[test_case(one(CoreP2P, service(Ipv4, 443)) => Err(BadPort(443)) ; "443 for core p2p")]
    #[test_case(one(PlatformP2P, service(Ipv4, 443)) => Err(BadPort(443)) ; "443 for platform p2p")]
    #[test_case(one(PlatformHttps, service(Ipv4, 443)) => Ok(()) ; "443 for platform https")]
    #[test_case(one(PlatformHttps, service(Ipv4, 80)) => Err(BadPort(80)) ; "80 for https")]
    #[test_case(one(PlatformHttps, domain(443)) => Ok(()) ; "domain 443")]
    #[test_case(one(CoreP2P, domain(443)) => Ok(()) ; "domain 443 under another purpose")]
    #[test_case(one(PlatformHttps, domain(1443)) => Ok(()) ; "domain usual port")]
    #[test_case(one(PlatformHttps, domain(0)) => Err(BadPort(0)) ; "domain port 0")]
    #[test_case(one(PlatformHttps, domain(80)) => Err(BadPort(80)) ; "domain system port")]
    #[test_case(one(PlatformHttps, domain(6000)) => Err(BadPort(6000)) ; "domain well-known port")]
    #[test_case(one(CoreP2P, service(I2p, 0)) => Ok(()) ; "i2p port 0")]
    #[test_case(one(CoreP2P, service(I2p, 9999)) => Err(BadPort(9999)) ; "i2p usual port")]
    #[test_case(one(PlatformHttps, service(I2p, 443)) => Err(BadPort(443)) ; "i2p 443 for https")]
    #[test_case(vec![(CoreP2P, vec![service(Ipv4, 9999), service(Ipv4, 9999)])]
        => Err(Duplicate) ; "an entry repeated within a purpose")]
    #[test_case(vec![
            (CoreP2P, vec![service(Ipv4, 9999)]),
            (PlatformHttps, vec![service(Ipv4, 9999)]),
        ]
        => Err(Duplicate) ; "an entry repeated across purposes")]
    #[test_case(vec![(PlatformHttps, vec![domain(443), domain(443)])]
        => Err(Duplicate) ; "a repeated domain")]
    #[test_case(vec![(CoreP2P, vec![service(Ipv4, 9999), service(Ipv4, 9998)])]
        => Err(Duplicate) ; "an address shared within a purpose")]
    #[test_case(vec![(PlatformHttps, vec![domain(443), domain(1443)])]
        => Err(Duplicate) ; "a host shared within a purpose")]
    #[test_case(vec![(CoreP2P, vec![service(Ipv6, 9999), service(Cjdns, 9998)])]
        => Err(Duplicate) ; "an ipv6 and a cjdns address of the same bytes")]
    #[test_case(vec![(CoreP2P, vec![service(TorV3, 9999), service(I2p, 0)])]
        => Ok(()) ; "a tor and an i2p address of the same bytes")]
    #[test_case(vec![
            (CoreP2P, vec![service(Ipv4, 9999)]),
            (PlatformP2P, vec![service(Ipv4, 26656)]),
            (PlatformHttps, vec![service(Ipv4, 443)]),
        ]
        => Ok(()) ; "an evonode serving every purpose from one address")]
    #[test_case(vec![
            (CoreP2P, vec![
                service(Ipv4, 9999),
                service(Ipv6, 9999),
                service(TorV3, 9999),
                service(I2p, 0),
            ]),
            (PlatformHttps, vec![service(Ipv4, 443), domain(443)]),
        ]
        => Ok(()) ; "several entries per purpose")]
    #[test_case(vec![] => Ok(()) ; "an empty map")]
    #[test_case(vec![(CoreP2P, vec![service(Ipv4, 80)]), (PlatformP2P, vec![service(Ipv4, 80)])]
        => Err(Duplicate) ; "a repeated entry before an earlier purpose's bad port")]
    #[test_case(vec![(CoreP2P, vec![service(Ipv4, 80), service(Ipv4, 9999)])]
        => Err(Duplicate) ; "a shared address before a bad port of its purpose")]
    #[test_case(vec![
            (CoreP2P, vec![service(Ipv4, 80)]),
            (PlatformP2P, vec![service(Ipv6, 9999), service(Ipv6, 9998)]),
        ]
        => Err(BadPort(80)) ; "a bad port before a later purpose's shared address")]
    fn port_and_duplicate_rules(
        purposes: Vec<(NetInfoPurpose, Vec<NetInfoEntry>)>,
    ) -> Result<(), ExtNetInfoError> {
        ExtNetInfo {
            version: 1,
            purposes,
        }
        .validate_ports_and_duplicates()
    }
}
