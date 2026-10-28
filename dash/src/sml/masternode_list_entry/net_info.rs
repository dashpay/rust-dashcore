use std::collections::BTreeMap;
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

/// The port Dash Core holds every I2P entry to (`I2P_SAM31_PORT`): I2P SAM 3.1 and earlier have
/// no ports.
const I2P_SAM31_PORT: u16 = 0;

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
    /// applies them:
    ///
    /// - no entry repeats the address and port of another, under any purpose
    ///   (`HasAddrPortDuplicates`);
    /// - no two entries of one purpose share an address, whatever their ports
    ///   (`HasAddrDuplicates`); entries of different purposes may;
    /// - every entry has a port Core accepts for its purpose: an I2P entry must use port 0, since
    ///   I2P SAM 3.1 has no ports, and any other entry may use neither port 0 nor a port
    ///   `IsBadPort` refuses, except 443 for a Platform HTTPS service and for a domain.
    ///
    /// Core refuses a ProRegTx or ProUpServTx whose map breaks one of these rules with
    /// `bad-protx-dup-netinfo-entry` or `bad-protx-netinfo-port`, so a builder can call this
    /// before it signs and broadcasts a transaction that would never confirm. Core walks the
    /// purposes in ascending order; so does this check, for a map listed that way.
    ///
    /// Nothing else is checked. Core also refuses a map that:
    ///
    /// - does not list each purpose once, in ascending order (it does not decode);
    /// - has an unknown version, no purposes, a purpose without entries, or more than four
    ///   entries for one purpose;
    /// - has an invalid entry, an address that is invalid, of an unsupported type or (on
    ///   every network but regtest) not routable, or a domain name Core refuses;
    /// - lists a domain under any purpose but Platform HTTPS;
    /// - has an entry another masternode already registered (`bad-protx-dup-netinfo-entry`,
    ///   checked against the masternode list).
    ///
    /// A map that passes may still be refused for one of those, and Core reports the code of
    /// whichever rule it checks first: it reads a domain entry at port 0 as an invalid entry, for
    /// instance, and refuses the map as malformed.
    pub fn validate_ports_and_duplicates(&self) -> Result<(), ExtNetInfoError> {
        let mut known = BTreeMap::new();
        for (purpose, entries) in &self.purposes {
            for entry in entries {
                if let Some(conflicting_purpose) = known.insert(entry, *purpose) {
                    return Err(ExtNetInfoError::DuplicateEntry {
                        purpose: *purpose,
                        entry: entry.clone(),
                        conflicting_purpose,
                    });
                }
            }
        }
        for (purpose, entries) in &self.purposes {
            let mut addresses = BTreeMap::new();
            for entry in entries {
                if let Some(conflicting_entry) = addresses.insert(AddressKey::of(entry), entry) {
                    return Err(ExtNetInfoError::DuplicateAddress {
                        purpose: *purpose,
                        entry: entry.clone(),
                        conflicting_entry: conflicting_entry.clone(),
                    });
                }
            }
            for entry in entries {
                if let Some(port) = refused_port(*purpose, entry) {
                    return Err(ExtNetInfoError::BadPort {
                        purpose: *purpose,
                        entry: entry.clone(),
                        port,
                    });
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
/// breaks, as found by [`ExtNetInfo::validate_ports_and_duplicates`]. The reject code each variant
/// names is the one Core gives a map that meets the rules Core checks before it.
#[derive(Debug, Error, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ExtNetInfoError {
    /// `entry`, listed under `purpose`, repeats the address and port of an earlier entry listed
    /// under `conflicting_purpose`, which may be `purpose` itself. Core refuses the map with
    /// `bad-protx-dup-netinfo-entry`.
    #[error(
        "{purpose:?} entry {entry:?} repeats the address and port of a {conflicting_purpose:?} entry"
    )]
    DuplicateEntry {
        purpose: NetInfoPurpose,
        entry: NetInfoEntry,
        conflicting_purpose: NetInfoPurpose,
    },
    /// `entry` has the address of `conflicting_entry`, an earlier entry of the same `purpose`.
    /// Core refuses the map with `bad-protx-dup-netinfo-entry`.
    #[error("{purpose:?} entries {conflicting_entry:?} and {entry:?} share an address")]
    DuplicateAddress {
        purpose: NetInfoPurpose,
        entry: NetInfoEntry,
        conflicting_entry: NetInfoEntry,
    },
    /// `entry`, listed under `purpose`, has a `port` Core refuses for it. Core refuses the map
    /// with `bad-protx-netinfo-port`.
    #[error("Dash Core refuses {purpose:?} port {port} of entry {entry:?}")]
    BadPort {
        purpose: NetInfoPurpose,
        entry: NetInfoEntry,
        port: u16,
    },
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
    let (port, refused) = match *entry {
        NetInfoEntry::Service {
            network: Bip155Network::I2p,
            port,
            ..
        } => (port, port != I2P_SAM31_PORT),
        NetInfoEntry::Service {
            port,
            ..
        } => {
            let allowed_https_port =
                purpose == NetInfoPurpose::PlatformHttps && port == PLATFORM_HTTPS_PORT;
            (port, port == 0 || (is_bad_port(port) && !allowed_https_port))
        }
        NetInfoEntry::Domain {
            port,
            ..
        } => (port, port == 0 || (is_bad_port(port) && port != PLATFORM_HTTPS_PORT)),
        NetInfoEntry::Invalid => return None,
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

    const PURPOSES: [NetInfoPurpose; 3] =
        [NetInfoPurpose::CoreP2P, NetInfoPurpose::PlatformP2P, NetInfoPurpose::PlatformHttps];

    fn ipv4(addr: [u8; 4], port: u16) -> NetInfoEntry {
        NetInfoEntry::Service {
            network: Bip155Network::Ipv4,
            addr: addr.to_vec(),
            port,
        }
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

    fn map(purposes: Vec<(NetInfoPurpose, Vec<NetInfoEntry>)>) -> ExtNetInfo {
        ExtNetInfo {
            version: 1,
            purposes,
        }
    }

    fn validate_one(purpose: NetInfoPurpose, entry: NetInfoEntry) -> Result<(), ExtNetInfoError> {
        map(vec![(purpose, vec![entry])]).validate_ports_and_duplicates()
    }

    /// The cases of Dash Core's own `isbadport` test, and the exact list of ports above the
    /// system ports that `IsBadPort` refuses in Dash Core v24.0.0-rc.4.
    #[test]
    fn is_bad_port_refuses_what_core_refuses() {
        for port in [1, 22, 80, 443, 1023, 6000, 8332, 8333, 18332, 18333] {
            assert!(is_bad_port(port), "port {port}");
        }
        for port in [0, 1024, 9998, 9999, 26656, 65535] {
            assert!(!is_bad_port(port), "port {port}");
        }
        assert!((1..=1023).all(is_bad_port));
        let above_system_ports: Vec<u16> =
            (1024..=u16::MAX).filter(|port| is_bad_port(*port)).collect();
        assert_eq!(
            above_system_ports,
            [
                1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668,
                6669, 6697, 8332, 8333, 10080, 18332, 18333
            ]
        );
    }

    fn bad_port(purpose: NetInfoPurpose, entry: &NetInfoEntry) -> Result<(), ExtNetInfoError> {
        Err(ExtNetInfoError::BadPort {
            purpose,
            entry: entry.clone(),
            port: entry.port().expect("an entry with a port"),
        })
    }

    /// Port 0 and every port `IsBadPort` lists are refused for every purpose and every kind of
    /// service entry, and for a domain, which Core takes only for Platform HTTPS. The error
    /// names the purpose, the entry and the port.
    #[test]
    fn a_bad_port_is_refused_for_every_purpose() {
        let refused = [0, 1, 22, 80, 1023].into_iter().chain(BAD_PORTS);
        for port in refused {
            for purpose in PURPOSES {
                for entry in [
                    ipv4([1, 1, 1, 1], port),
                    service(Bip155Network::Ipv6, port),
                    service(Bip155Network::TorV3, port),
                    service(Bip155Network::Cjdns, port),
                ] {
                    assert_eq!(validate_one(purpose, entry.clone()), bad_port(purpose, &entry));
                }
            }
            let entry = domain(port);
            assert_eq!(
                validate_one(NetInfoPurpose::PlatformHttps, entry.clone()),
                bad_port(NetInfoPurpose::PlatformHttps, &entry)
            );
        }
    }

    /// Mainnet evonodes serve Platform HTTPS on 443, so Core lets Platform HTTPS use it, and
    /// refuses it for the other purposes.
    #[test]
    fn port_443_is_accepted_only_for_platform_https() {
        for entry in [
            ipv4([1, 1, 1, 1], 443),
            service(Bip155Network::Ipv6, 443),
            service(Bip155Network::TorV3, 443),
        ] {
            assert_eq!(validate_one(NetInfoPurpose::PlatformHttps, entry.clone()), Ok(()));
            for purpose in [NetInfoPurpose::CoreP2P, NetInfoPurpose::PlatformP2P] {
                assert_eq!(validate_one(purpose, entry.clone()), bad_port(purpose, &entry));
            }
        }
        assert_eq!(validate_one(NetInfoPurpose::PlatformHttps, domain(443)), Ok(()));
    }

    /// I2P SAM 3.1 has no ports: Core takes an I2P entry only at port 0, while a Tor entry at
    /// port 0 is refused like any other.
    #[test]
    fn an_i2p_entry_is_held_to_port_zero() {
        for purpose in PURPOSES {
            assert_eq!(validate_one(purpose, service(Bip155Network::I2p, 0)), Ok(()));
            for port in [9998, 443, 80] {
                let entry = service(Bip155Network::I2p, port);
                assert_eq!(validate_one(purpose, entry.clone()), bad_port(purpose, &entry));
            }
        }
        let tor = service(Bip155Network::TorV3, 0);
        assert_eq!(
            validate_one(NetInfoPurpose::CoreP2P, tor.clone()),
            bad_port(NetInfoPurpose::CoreP2P, &tor)
        );
    }

    /// Core's `extnetinfo_rules_reg`: the same address and port may not repeat within a purpose
    /// or across purposes.
    #[test]
    fn an_entry_repeating_an_address_and_port_is_refused() {
        let entry = ipv4([1, 1, 1, 1], 9998);
        for purpose in PURPOSES {
            for conflicting_purpose in PURPOSES.into_iter().filter(|other| *other < purpose) {
                let info = map(vec![
                    (conflicting_purpose, vec![entry.clone()]),
                    (purpose, vec![entry.clone()]),
                ]);
                assert_eq!(
                    info.validate_ports_and_duplicates(),
                    Err(ExtNetInfoError::DuplicateEntry {
                        purpose,
                        entry: entry.clone(),
                        conflicting_purpose
                    })
                );
            }
            let info = map(vec![(purpose, vec![entry.clone(), entry.clone()])]);
            assert_eq!(
                info.validate_ports_and_duplicates(),
                Err(ExtNetInfoError::DuplicateEntry {
                    purpose,
                    entry: entry.clone(),
                    conflicting_purpose: purpose
                })
            );
        }
        let domains = map(vec![(NetInfoPurpose::PlatformHttps, vec![domain(443), domain(443)])]);
        assert_eq!(
            domains.validate_ports_and_duplicates(),
            Err(ExtNetInfoError::DuplicateEntry {
                purpose: NetInfoPurpose::PlatformHttps,
                entry: domain(443),
                conflicting_purpose: NetInfoPurpose::PlatformHttps
            })
        );
    }

    /// Core's `extnetinfo_rules_reg`: two entries of one purpose may not share an address even
    /// on different ports, while entries of different purposes may, as an evonode's services
    /// on one IP do.
    #[test]
    fn two_entries_of_one_purpose_sharing_an_address_are_refused() {
        let first = ipv4([1, 1, 1, 1], 9998);
        let second = ipv4([1, 1, 1, 1], 9997);
        let info = map(vec![(NetInfoPurpose::CoreP2P, vec![first.clone(), second.clone()])]);
        assert_eq!(
            info.validate_ports_and_duplicates(),
            Err(ExtNetInfoError::DuplicateAddress {
                purpose: NetInfoPurpose::CoreP2P,
                entry: second.clone(),
                conflicting_entry: first.clone()
            })
        );

        let across = map(vec![
            (NetInfoPurpose::CoreP2P, vec![first]),
            (NetInfoPurpose::PlatformP2P, vec![second]),
        ]);
        assert_eq!(across.validate_ports_and_duplicates(), Ok(()));

        let domains = map(vec![(NetInfoPurpose::PlatformHttps, vec![domain(443), domain(1443)])]);
        assert_eq!(
            domains.validate_ports_and_duplicates(),
            Err(ExtNetInfoError::DuplicateAddress {
                purpose: NetInfoPurpose::PlatformHttps,
                entry: domain(1443),
                conflicting_entry: domain(443)
            })
        );
    }

    /// Core compares addresses as it prints them, and it prints a CJDNS address as IPv6, so the
    /// two collide on the same bytes. Tor and I2P addresses of the same bytes print differently
    /// and do not.
    #[test]
    fn a_cjdns_and_an_ipv6_entry_with_the_same_bytes_share_an_address() {
        let ipv6 = service(Bip155Network::Ipv6, 9998);
        let cjdns = service(Bip155Network::Cjdns, 9997);
        let info = map(vec![(NetInfoPurpose::CoreP2P, vec![ipv6.clone(), cjdns.clone()])]);
        assert_eq!(
            info.validate_ports_and_duplicates(),
            Err(ExtNetInfoError::DuplicateAddress {
                purpose: NetInfoPurpose::CoreP2P,
                entry: cjdns,
                conflicting_entry: ipv6
            })
        );

        let tor_and_i2p = map(vec![(
            NetInfoPurpose::CoreP2P,
            vec![service(Bip155Network::TorV3, 9998), service(Bip155Network::I2p, 0)],
        )]);
        assert_eq!(tor_and_i2p.validate_ports_and_duplicates(), Ok(()));
    }

    /// Core looks for a repeated address and port across the whole map before it checks any
    /// purpose's ports, so that is the refusal reported.
    #[test]
    fn a_repeated_entry_is_reported_before_a_bad_port_of_another_purpose() {
        let entry = ipv4([1, 1, 1, 1], 80);
        let info = map(vec![
            (NetInfoPurpose::CoreP2P, vec![entry.clone()]),
            (NetInfoPurpose::PlatformP2P, vec![entry.clone()]),
        ]);
        assert_eq!(
            info.validate_ports_and_duplicates(),
            Err(ExtNetInfoError::DuplicateEntry {
                purpose: NetInfoPurpose::PlatformP2P,
                entry,
                conflicting_purpose: NetInfoPurpose::CoreP2P
            })
        );
    }

    /// Within one purpose, Core looks for a shared address before it checks the ports.
    #[test]
    fn a_shared_address_is_reported_before_a_bad_port_of_the_same_purpose() {
        let first = ipv4([1, 1, 1, 1], 80);
        let second = ipv4([1, 1, 1, 1], 9998);
        let info = map(vec![(NetInfoPurpose::CoreP2P, vec![first.clone(), second.clone()])]);
        assert_eq!(
            info.validate_ports_and_duplicates(),
            Err(ExtNetInfoError::DuplicateAddress {
                purpose: NetInfoPurpose::CoreP2P,
                entry: second,
                conflicting_entry: first
            })
        );
    }

    /// Maps that meet the port and duplicate-entry rules pass, among them a devnet and a mainnet
    /// evonode's.
    #[test]
    fn maps_meeting_the_rules_pass() {
        let evonode = |core_p2p, platform_p2p, platform_https| {
            map(vec![
                (NetInfoPurpose::CoreP2P, vec![ipv4([68, 67, 122, 237], core_p2p)]),
                (NetInfoPurpose::PlatformP2P, vec![ipv4([68, 67, 122, 237], platform_p2p)]),
                (NetInfoPurpose::PlatformHttps, vec![ipv4([68, 67, 122, 237], platform_https)]),
            ])
        };
        // A devnet evonode, and a mainnet one with Platform HTTPS on 443.
        assert_eq!(evonode(20001, 26656, 1443).validate_ports_and_duplicates(), Ok(()));
        assert_eq!(evonode(9999, 26656, 443).validate_ports_and_duplicates(), Ok(()));

        let several = map(vec![
            (
                NetInfoPurpose::CoreP2P,
                vec![
                    ipv4([1, 1, 1, 1], 9999),
                    ipv4([1, 1, 1, 2], 9999),
                    service(Bip155Network::TorV3, 9999),
                    service(Bip155Network::I2p, 0),
                ],
            ),
            (NetInfoPurpose::PlatformHttps, vec![ipv4([1, 1, 1, 1], 443), domain(443)]),
        ]);
        assert_eq!(several.validate_ports_and_duplicates(), Ok(()));
        assert_eq!(map(Vec::new()).validate_ports_and_duplicates(), Ok(()));
    }
}
