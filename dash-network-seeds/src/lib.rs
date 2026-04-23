//! Hardcoded masternode IP seed lists for Dash mainnet and testnet.
//!
//! The seed lists are regenerated weekly by CI from the live Dash P2P network
//! using the `masternode-seeds-fetcher` tool (which issues a `getmnlistd`
//! request and parses the resulting `mnlistdiff`). Consumers that need a
//! bootstrap peer list — for example SPV wallets, light clients, or block
//! explorers — can depend on this crate directly rather than on `dash-spv`
//! and its full networking stack.
//!
//! # Example
//!
//! ```rust
//! use dash_network_seeds::{MasternodeType, Network, seeds};
//!
//! let mainnet = seeds(Network::Mainnet);
//! assert!(!mainnet.is_empty());
//!
//! let evo_only: Vec<_> = mainnet.iter().filter(|s| s.mn_type == MasternodeType::Evo).collect();
//! # let _ = evo_only;
//! ```
//!
//! # File format
//!
//! Each seed file is plain text with one masternode per line:
//!
//! ```text
//! # Comment lines start with `#` and are ignored.
//! regular 1.2.3.4:9999
//! evo     68.67.122.1:19999
//! ```
//!
//! The first token is the masternode type (`regular` or `evo`); the second is
//! a socket address (`ip:port`). Blank lines and comment lines are ignored.
//! Lines with only an address (no type prefix) default to `regular` for
//! backwards compatibility with older seed files.

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};

/// The Dash network for which a seed list is provided.
///
/// Only networks that actually have a masternode system (mainnet and testnet)
/// are represented here. Devnet/regtest have no hardcoded seeds.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum Network {
    /// Dash mainnet.
    Mainnet,
    /// Dash testnet.
    Testnet,
}

impl Network {
    /// Default P2P port for this network.
    pub const fn default_p2p_port(self) -> u16 {
        match self {
            Network::Mainnet => 9999,
            Network::Testnet => 19999,
        }
    }

    /// Raw embedded seed file contents, as a `&'static str`.
    pub const fn raw_seed_file(self) -> &'static str {
        match self {
            Network::Mainnet => MAINNET_SEED_FILE,
            Network::Testnet => TESTNET_SEED_FILE,
        }
    }
}

/// Masternode type as encoded in a seed entry.
///
/// The underlying protocol uses `EntryMasternodeType::HighPerformance` for
/// what Dash Platform documentation, users, and the Dash Core RPC all refer
/// to as an "Evo" or "HPMN" (High-Performance Masternode). This crate uses
/// "Evo" because that's the ecosystem-facing name.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MasternodeType {
    /// Regular masternode.
    Regular,
    /// Evo (a.k.a. HPMN) masternode — runs Dash Platform in addition to Core.
    Evo,
}

impl MasternodeType {
    /// Parse the seed-file token (`"regular"` or `"evo"`, case-insensitive).
    pub fn parse(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "regular" => Some(MasternodeType::Regular),
            "evo" | "hpmn" | "highperformance" => Some(MasternodeType::Evo),
            _ => None,
        }
    }

    /// The seed-file token for this type.
    pub const fn as_str(self) -> &'static str {
        match self {
            MasternodeType::Regular => "regular",
            MasternodeType::Evo => "evo",
        }
    }
}

/// A single masternode seed entry.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MasternodeSeed {
    /// The masternode's advertised P2P service address.
    pub address: SocketAddr,
    /// Whether this masternode is a regular or Evo (HPMN) node.
    pub mn_type: MasternodeType,
}

// ---------- Embedded files ----------

const MAINNET_SEED_FILE: &str = include_str!("../seeds/mainnet.txt");
const TESTNET_SEED_FILE: &str = include_str!("../seeds/testnet.txt");

// ---------- Public API ----------

/// Return all hardcoded masternode seeds for the given network.
pub fn seeds(network: Network) -> Vec<MasternodeSeed> {
    parse(network.raw_seed_file(), network.default_p2p_port())
}

/// Return just the socket addresses for all hardcoded masternode seeds,
/// dropping type information.
pub fn addresses(network: Network) -> Vec<SocketAddr> {
    seeds(network).into_iter().map(|s| s.address).collect()
}

/// Return only Evo (HPMN) masternode seeds.
pub fn evo_seeds(network: Network) -> Vec<MasternodeSeed> {
    seeds(network).into_iter().filter(|s| s.mn_type == MasternodeType::Evo).collect()
}

/// Return only regular masternode seeds.
pub fn regular_seeds(network: Network) -> Vec<MasternodeSeed> {
    seeds(network).into_iter().filter(|s| s.mn_type == MasternodeType::Regular).collect()
}

/// Parse a seed-file body (as produced by `masternode-seeds-fetcher`) into a
/// list of entries. Exposed for tooling — library consumers should usually
/// call [`seeds`] instead.
///
/// Lines that begin with `#` and blank lines are ignored. Each remaining line
/// is parsed as `<type> <ip>:<port>` or `<type> <ip>` (in which case the
/// given `default_port` is used). Lines containing only an address default
/// to [`MasternodeType::Regular`] for backwards compatibility.
///
/// Unparsable lines are silently skipped so that a malformed line never
/// prevents the rest of the list from loading.
pub fn parse(raw: &str, default_port: u16) -> Vec<MasternodeSeed> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(seed) = parse_line(line, default_port) {
            out.push(seed);
        }
    }
    out
}

fn parse_line(line: &str, default_port: u16) -> Option<MasternodeSeed> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;

    // Case 1: "<type> <addr>"
    if let Some(mn_type) = MasternodeType::parse(first) {
        let addr_tok = tokens.next()?;
        if tokens.next().is_some() {
            // Extra garbage after the address — reject.
            return None;
        }
        let address = parse_address(addr_tok, default_port)?;
        return Some(MasternodeSeed {
            address,
            mn_type,
        });
    }

    // Case 2: just "<addr>" (bare IP for backwards compat, default to Regular)
    if tokens.next().is_some() {
        return None;
    }
    let address = parse_address(first, default_port)?;
    Some(MasternodeSeed {
        address,
        mn_type: MasternodeType::Regular,
    })
}

fn parse_address(tok: &str, default_port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = tok.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = tok.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    None
}

// ---------- dashcore interop (feature-gated) ----------

#[cfg(feature = "dashcore")]
impl TryFrom<dashcore::Network> for Network {
    type Error = UnsupportedNetwork;

    fn try_from(n: dashcore::Network) -> Result<Self, Self::Error> {
        match n {
            dashcore::Network::Mainnet => Ok(Network::Mainnet),
            dashcore::Network::Testnet => Ok(Network::Testnet),
            other => Err(UnsupportedNetwork(other)),
        }
    }
}

/// Returned by [`Network::try_from`] when a `dashcore::Network` has no
/// hardcoded seed list (devnet / regtest).
#[cfg(feature = "dashcore")]
#[derive(Clone, Copy, Debug)]
pub struct UnsupportedNetwork(pub dashcore::Network);

#[cfg(feature = "dashcore")]
impl std::fmt::Display for UnsupportedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no hardcoded seeds are shipped for network {:?}", self.0)
    }
}

#[cfg(feature = "dashcore")]
impl std::error::Error for UnsupportedNetwork {}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_with_type_prefix() {
        let s = parse_line("evo 68.67.122.1:19999", 19999).unwrap();
        assert_eq!(s.mn_type, MasternodeType::Evo);
        assert_eq!(s.address, "68.67.122.1:19999".parse().unwrap());

        let s = parse_line("regular 1.2.3.4:9999", 9999).unwrap();
        assert_eq!(s.mn_type, MasternodeType::Regular);
    }

    #[test]
    fn parse_line_bare_address_defaults_to_regular() {
        let s = parse_line("1.2.3.4:9999", 9999).unwrap();
        assert_eq!(s.mn_type, MasternodeType::Regular);
        assert_eq!(s.address, "1.2.3.4:9999".parse().unwrap());
    }

    #[test]
    fn parse_line_applies_default_port_when_missing() {
        let s = parse_line("regular 9.9.9.9", 19999).unwrap();
        assert_eq!(s.address, "9.9.9.9:19999".parse().unwrap());
    }

    #[test]
    fn parse_line_rejects_trailing_garbage() {
        assert!(parse_line("regular 1.2.3.4:9999 extra", 9999).is_none());
        assert!(parse_line("1.2.3.4:9999 extra", 9999).is_none());
    }

    #[test]
    fn parse_line_rejects_unknown_type() {
        // Unknown first token with extra tokens → reject (would look like typed entry).
        assert!(parse_line("supernode 1.2.3.4:9999", 9999).is_none());
    }

    #[test]
    fn parse_ignores_comments_and_blanks() {
        let raw = "# header\n\n# another\nevo 1.2.3.4:9999\n\n";
        let list = parse(raw, 9999);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].mn_type, MasternodeType::Evo);
    }

    #[test]
    fn parse_skips_invalid_lines() {
        let raw = "not-an-ip\nevo 1.2.3.4:9999\nregular ::: :::\n";
        let list = parse(raw, 9999);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn masternode_type_parse_case_insensitive() {
        assert_eq!(MasternodeType::parse("EVO"), Some(MasternodeType::Evo));
        assert_eq!(MasternodeType::parse("Regular"), Some(MasternodeType::Regular));
        assert_eq!(MasternodeType::parse("hpmn"), Some(MasternodeType::Evo));
        assert_eq!(MasternodeType::parse("Nope"), None);
    }

    #[test]
    fn testnet_seeds_contain_expected_evo_ips() {
        let list = seeds(Network::Testnet);
        // The 29 HP-MN IPs at 68.67.122.1-29 must all be present and marked Evo.
        let hpmn_count = list
            .iter()
            .filter(|s| s.mn_type == MasternodeType::Evo)
            .filter(|s| s.address.ip().to_string().starts_with("68.67.122."))
            .count();
        assert!(hpmn_count >= 29, "expected >=29 HP-MN seeds at 68.67.122.x, got {}", hpmn_count);
    }

    #[test]
    fn mainnet_seeds_non_empty_and_well_formed() {
        let list = seeds(Network::Mainnet);
        assert!(!list.is_empty(), "mainnet seeds must not be empty");
        for s in &list {
            assert_eq!(
                s.address.port(),
                Network::Mainnet.default_p2p_port(),
                "mainnet seed must use the default port: {:?}",
                s
            );
        }
    }
}
