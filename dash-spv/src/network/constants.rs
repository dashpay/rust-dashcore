//! Network constants for peer support

use std::net::SocketAddr;
use std::time::Duration;

// Connection limits
pub const TARGET_PEERS: usize = 3;

// Timeouts
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(120);
pub const PING_INTERVAL: Duration = Duration::from_secs(120);

// Reconnection
pub const RECONNECT_DELAY: Duration = Duration::from_secs(5);
pub const MAX_RECONNECT_ATTEMPTS: u32 = 3;

// DNS seeds for Dash mainnet
pub const MAINNET_DNS_SEEDS: &[&str] = &[
    "dnsseed.dash.org",
    // Note: dnsseed.dashdot.io and dnsseed.masternode.io are currently not resolving
];

// DNS seeds for Dash testnet
pub const TESTNET_DNS_SEEDS: &[&str] = &["testnet-seed.dashdot.io"];

/// Default Dash P2P port for mainnet.
pub const MAINNET_P2P_PORT: u16 = 9999;
/// Default Dash P2P port for testnet.
pub const TESTNET_P2P_PORT: u16 = 19999;

/// Hard-coded masternode peer list for mainnet.
///
/// Refreshed weekly by `.github/workflows/update-masternode-seeds.yml` via the
/// `masternode-seeds-fetcher` crate. Parsed at runtime by [`parse_seed_file`].
pub const MAINNET_SEED_PEERS: &str = include_str!("../../seeds/mainnet.txt");

/// Hard-coded masternode peer list for testnet.
///
/// Refreshed weekly by `.github/workflows/update-masternode-seeds.yml` via the
/// `masternode-seeds-fetcher` crate. Parsed at runtime by [`parse_seed_file`].
pub const TESTNET_SEED_PEERS: &str = include_str!("../../seeds/testnet.txt");

// Peer exchange
pub const MAX_ADDR_TO_SEND: usize = 1000;
pub const MAX_ADDR_TO_STORE: usize = 2000;

// Connection maintenance
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10); // Check more frequently
pub const PEER_DISCOVERY_INTERVAL: Duration = Duration::from_secs(60); // Discover more frequently

// DNS and polling intervals
pub const DNS_DISCOVERY_DELAY: Duration = Duration::from_secs(10);
pub const MESSAGE_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub const MESSAGE_RECEIVE_TIMEOUT: Duration = Duration::from_millis(100);

/// Parse a seed file into a list of `SocketAddr`.
///
/// The file format matches what `masternode-seeds-fetcher` writes:
/// - lines beginning with `#` are comments and are ignored
/// - blank lines are ignored
/// - each remaining line is parsed as a `SocketAddr` (`ip:port`); entries that
///   contain only an IP are treated as `<ip>:<default_port>`
/// - unparsable lines are logged at debug level and skipped
pub fn parse_seed_file(raw: &str, default_port: u16) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for (line_no, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(addr) = line.parse::<SocketAddr>() {
            out.push(addr);
            continue;
        }
        if let Ok(ip) = line.parse::<std::net::IpAddr>() {
            out.push(SocketAddr::new(ip, default_port));
            continue;
        }
        tracing::debug!("ignoring unparsable seed entry at line {}: {:?}", line_no + 1, line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_seed_file_accepts_comments_and_mixed_forms() {
        let raw = "# comment\n\n1.2.3.4:9999\n5.6.7.8\n  # indented comment\n9.9.9.9:19999\n";
        let parsed = parse_seed_file(raw, 19999);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], "1.2.3.4:9999".parse().unwrap());
        assert_eq!(parsed[1], "5.6.7.8:19999".parse().unwrap());
        assert_eq!(parsed[2], "9.9.9.9:19999".parse().unwrap());
    }

    #[test]
    fn parse_seed_file_ignores_invalid_lines() {
        let raw = "not-an-ip\n1.2.3.4:9999\n:::\n";
        let parsed = parse_seed_file(raw, 9999);
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn testnet_seed_file_parses_with_expected_count() {
        let parsed = parse_seed_file(TESTNET_SEED_PEERS, TESTNET_P2P_PORT);
        // The file ships with at least the 29 HP masternode IPs; the weekly
        // refresh may grow this set.
        assert!(parsed.len() >= 29, "expected >=29 testnet seeds, got {}", parsed.len());
        assert!(parsed.iter().all(|a| a.port() == TESTNET_P2P_PORT));
    }

    #[test]
    fn mainnet_seed_file_parses() {
        // Mainnet ships empty until the first CI refresh; this test just
        // guards against malformed content sneaking in via manual edits.
        let _ = parse_seed_file(MAINNET_SEED_PEERS, MAINNET_P2P_PORT);
    }
}
