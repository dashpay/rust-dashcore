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

/// The dial backoff and the ban of one address, apart so a handshake can clear the backoff
/// alone.
struct Entry {
    fails: u32,
    backoff_until: Instant,
    banned_until: Instant,
}

pub struct Bans {
    entries: Mutex<HashMap<SocketAddr, Entry>>,
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
        let entry = entries.entry(addr).or_insert(Entry {
            fails: 0,
            backoff_until: now,
            banned_until: now,
        });
        let (until, duration) = match ban {
            Ban::DialFailed => {
                entry.fails += 1;
                let backoff = Duration::from_secs(1 << entry.fails.min(6));
                (&mut entry.backoff_until, MAX_DIAL_BACKOFF.min(backoff))
            }
            Ban::Kicked => (&mut entry.banned_until, KICK_BAN),
            Ban::MissingServices => (&mut entry.banned_until, MISBEHAVIOUR_BAN),
            Ban::Misbehaved => {
                tracing::warn!(target: "dash_spv::network", "banning {} for misbehaving", addr);
                (&mut entry.banned_until, MISBEHAVIOUR_BAN)
            }
        };
        *until = (*until).max(now + duration);
    }

    /// Clears the dial backoff of `addr` after a handshake and returns whether `addr` is
    /// still banned. A ban recorded while the dial was in flight survives the handshake.
    pub async fn dialed(&self, addr: SocketAddr) -> bool {
        let mut entries = self.entries.lock().await;
        let Some(entry) = entries.get_mut(&addr) else {
            return false;
        };
        let now = Instant::now();
        if entry.banned_until > now {
            entry.fails = 0;
            entry.backoff_until = now;
            return true;
        }
        entries.remove(&addr);
        false
    }

    /// Locks the table until the returned guard drops. A test holds it to stop a task at its
    /// next ban.
    #[cfg(test)]
    pub(super) async fn hold(&self) -> impl Sized + '_ {
        self.entries.lock().await
    }

    pub async fn banned(&self) -> HashSet<SocketAddr> {
        let now = Instant::now();
        self.entries
            .lock()
            .await
            .iter()
            .filter(|(_, entry)| entry.backoff_until.max(entry.banned_until) > now)
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

    /// A handshake clears the dial backoff, even one a parallel dial just set, but keeps a
    /// ban recorded during the dial.
    #[tokio::test(start_paused = true)]
    async fn a_handshake_keeps_a_ban_from_during_the_dial() {
        let bans = Bans::new([]);
        let addr: SocketAddr = "46.224.41.173:19999".parse().expect("an address");
        for _ in 0..6 {
            bans.ban(addr, Ban::DialFailed).await;
        }
        assert!(!bans.dialed(addr).await);
        assert!(bans.banned().await.is_empty(), "the handshake kept a live dial backoff");

        for _ in 0..6 {
            bans.ban(addr, Ban::DialFailed).await;
        }
        bans.ban(addr, Ban::Misbehaved).await;
        assert!(bans.dialed(addr).await);
        assert!(bans.banned().await.contains(&addr), "the handshake erased the ban");

        tokio::time::advance(MISBEHAVIOUR_BAN).await;
        bans.ban(addr, Ban::DialFailed).await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(bans.banned().await.is_empty(), "the handshake kept the fail count");
    }
}
