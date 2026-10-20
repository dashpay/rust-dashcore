use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dash_spv::sync::{SyncEvent, SyncProgress};
use dash_spv::EventHandler;
use tokio::sync::Notify;

use crate::dashboard::Dashboard;

pub const MILESTONE_BLOCK_HEADERS: &str = "block_headers_complete";
pub const MILESTONE_FILTER_HEADERS: &str = "filter_headers_complete";
pub const MILESTONE_FILTERS: &str = "filters_complete";
pub const MILESTONE_SYNC: &str = "sync_complete";

#[derive(Debug)]
pub struct RunMetrics {
    total_ms: u64,
    completed: bool,
    block_headers_ms: Option<u64>,
    filter_headers_ms: Option<u64>,
    filters_ms: Option<u64>,
    transactions: u32,
    error: Option<String>,
}

impl fmt::Display for RunMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = |o: Option<u64>| o.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string());

        writeln!(f, "=== dash-spv sync ===")?;
        writeln!(
            f,
            "completed:         {}{}",
            self.completed,
            if self.completed {
                ""
            } else {
                " (TIMED OUT)"
            }
        )?;
        writeln!(f, "total_ms:          {}", self.total_ms)?;
        writeln!(f, "block_headers_ms:  {}", ms(self.block_headers_ms))?;
        writeln!(f, "filter_headers_ms: {}", ms(self.filter_headers_ms))?;
        writeln!(f, "filters_ms:        {}", ms(self.filters_ms))?;
        write!(f, "transactions:      {}", self.transactions)?;
        if let Some(e) = &self.error {
            write!(f, "\nerror:             {e}")?;
        }

        Ok(())
    }
}

pub struct BenchEventHandler {
    start: Instant,
    inner: Mutex<Inner>,
    done: Notify,
    dashboard: Arc<Dashboard>,
}

struct Inner {
    milestones: BTreeMap<&'static str, u64>,
    error: Option<String>,
    completed: bool,
    transactions: u32,
}

impl BenchEventHandler {
    pub fn new(dashboard: Arc<Dashboard>) -> Self {
        Self {
            start: Instant::now(),
            inner: Mutex::new(Inner {
                milestones: BTreeMap::new(),
                error: None,
                completed: false,
                transactions: 0,
            }),
            done: Notify::new(),
            dashboard,
        }
    }

    fn record(&self, label: &'static str) {
        let elapsed = self.start.elapsed().as_millis() as u64;
        let mut inner = self.inner.lock().unwrap();
        inner.milestones.entry(label).or_insert(elapsed);
    }

    pub async fn wait_done(&self) {
        let notified = self.done.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self.inner.lock().unwrap().completed {
            return;
        }

        notified.await;
    }

    pub fn snapshot(&self) -> RunMetrics {
        let inner = self.inner.lock().unwrap();
        let bh = inner.milestones.get(MILESTONE_BLOCK_HEADERS).copied();
        let fh = inner.milestones.get(MILESTONE_FILTER_HEADERS).copied();
        let fl = inner.milestones.get(MILESTONE_FILTERS).copied();
        let sc = inner.milestones.get(MILESTONE_SYNC).copied();

        RunMetrics {
            total_ms: sc.unwrap_or_else(|| self.start.elapsed().as_millis() as u64),
            completed: inner.completed,
            block_headers_ms: bh,
            filter_headers_ms: fh,
            filters_ms: fl,
            transactions: inner.transactions,
            error: inner.error.clone(),
        }
    }
}

impl EventHandler for BenchEventHandler {
    fn on_sync_event(&self, event: &SyncEvent) {
        match event {
            SyncEvent::BlockHeaderSyncComplete {
                ..
            } => self.record(MILESTONE_BLOCK_HEADERS),
            SyncEvent::FilterHeadersSyncComplete {
                ..
            } => self.record(MILESTONE_FILTER_HEADERS),
            SyncEvent::FiltersSyncComplete {
                ..
            } => self.record(MILESTONE_FILTERS),
            SyncEvent::SyncComplete {
                ..
            } => {
                self.record(MILESTONE_SYNC);
                self.dashboard.finish();
                let mut inner = self.inner.lock().unwrap();
                inner.completed = true;
                drop(inner);
                self.done.notify_waiters();
            }
            _ => {}
        }
    }

    /// Every progress change repaints the bars (throttled inside).
    fn on_progress(&self, progress: &SyncProgress) {
        if let Ok(blocks) = progress.blocks() {
            let seen = blocks.transactions();
            let mut inner = self.inner.lock().unwrap();
            // Highest seen rather than last: the final repaint is whichever
            // progress change happened to land last, not necessarily the one
            // carrying the highest count.
            inner.transactions = inner.transactions.max(seen);
        }
        self.dashboard.render(progress);
    }

    fn on_error(&self, error: &str) {
        let mut inner = self.inner.lock().unwrap();
        if inner.error.is_none() {
            inner.error = Some(error.to_string());
        }
    }
}
