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
            Ban::Misbehaved => {
                tracing::warn!(target: "dash_spv::network", "banning {} for misbehaving", addr);
                MISBEHAVIOUR_BAN
            }
        };
        *until = (*until).max(now + duration);
    }

    pub async fn dialed(&self, addr: SocketAddr) {
        self.entries.lock().await.remove(&addr);
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
