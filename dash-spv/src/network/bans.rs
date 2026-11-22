use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

const MAX_DIAL_BACKOFF: Duration = Duration::from_secs(60);
const KICK_BAN: Duration = Duration::from_secs(10 * 60);
const MISBEHAVIOUR_BAN: Duration = Duration::from_secs(24 * 60 * 60);

pub enum Ban {
    DialFailed,
    Kicked,
    /// Lacks a service the client needs, which does not change within a session.
    MissingServices,
    Misbehaved,
}

pub struct Bans {
    entries: Mutex<HashMap<SocketAddr, (u32, Instant)>>,
    /// The configured peers: never kicked out of the dial set, only backed off on a
    /// failed dial. Banning one can leave a restricted client with nothing to dial.
    configured: HashSet<SocketAddr>,
}

impl Bans {
    pub fn new(configured: impl IntoIterator<Item = SocketAddr>) -> Self {
        Self {
            entries: Mutex::default(),
            configured: configured.into_iter().collect(),
        }
    }

    pub async fn ban(&self, addr: SocketAddr, ban: Ban) {
        if self.configured.contains(&addr) && !matches!(ban, Ban::DialFailed) {
            return;
        }
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        let (fails, until) = entries.entry(addr).or_insert((0, now));
        let duration = match ban {
            Ban::DialFailed => {
                *fails += 1;
                MAX_DIAL_BACKOFF.min(Duration::from_secs(1 << (*fails).min(6)))
            }
            Ban::Kicked => KICK_BAN,
            Ban::MissingServices => MISBEHAVIOUR_BAN,
            Ban::Misbehaved => {
                tracing::warn!(target: "dash_spv::network", "banning {} for misbehaving", addr);
                MISBEHAVIOUR_BAN
            }
        };
        *until = (*until).max(now + duration);
    }

    /// Resets the dial backoff of `addr` after a handshake. A ban recorded while the dial was
    /// in flight stays: only an unbanned address is dialed, so a live expiry here is that ban.
    pub async fn dialed(&self, addr: SocketAddr) {
        let mut entries = self.entries.lock().await;
        match entries.get_mut(&addr) {
            Some((fails, until)) if *until > Instant::now() => *fails = 0,
            _ => {
                entries.remove(&addr);
            }
        }
    }

    pub async fn banned(&self) -> HashSet<SocketAddr> {
        let now = Instant::now();
        self.entries
            .lock()
            .await
            .iter()
            .filter(|(_, (_, until))| *until > now)
            .map(|(addr, _)| *addr)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node lacking a service the client needs stays banned past the longest dial
    /// backoff.
    #[tokio::test(start_paused = true)]
    async fn missing_services_outlast_the_dial_backoff() {
        let bans = Bans::new([]);
        let addr: SocketAddr = "46.224.41.173:19999".parse().expect("an address");
        bans.ban(addr, Ban::MissingServices).await;

        tokio::time::advance(MAX_DIAL_BACKOFF * 10).await;

        assert!(bans.banned().await.contains(&addr));
    }

    /// A handshake resets the dial backoff but keeps a ban recorded during the dial.
    #[tokio::test(start_paused = true)]
    async fn a_handshake_keeps_a_ban_from_during_the_dial() {
        let bans = Bans::new([]);
        let addr: SocketAddr = "46.224.41.173:19999".parse().expect("an address");
        for _ in 0..6 {
            bans.ban(addr, Ban::DialFailed).await;
        }
        tokio::time::advance(MAX_DIAL_BACKOFF).await;
        assert!(bans.banned().await.is_empty());

        bans.ban(addr, Ban::Misbehaved).await;
        bans.dialed(addr).await;
        assert!(bans.banned().await.contains(&addr), "the handshake erased the ban");

        tokio::time::advance(MISBEHAVIOUR_BAN).await;
        bans.ban(addr, Ban::DialFailed).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(bans.banned().await.is_empty(), "the handshake kept the dial backoff");
    }
}
