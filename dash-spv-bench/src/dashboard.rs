use std::io::{self, IsTerminal, Write};

use dash_spv::sync::{ProgressPercentage, SyncProgress};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use tracing_subscriber::fmt::MakeWriter;

const REDRAW_HZ: u8 = 10;
const BAR_WIDTH: usize = 32;
const NOT_ENABLED: &str = "not enabled";

pub struct Dashboard {
    multi: MultiProgress,
    block_headers: ProgressBar,
    filter_headers: ProgressBar,
    filters: ProgressBar,
    masternodes: ProgressBar,
    blocks: ProgressBar,
    chainlocks: ProgressBar,
    instantsend: ProgressBar,
    mempool: ProgressBar,
}

impl Dashboard {
    pub fn new() -> Self {
        let target = if io::stderr().is_terminal() {
            ProgressDrawTarget::stderr_with_hz(REDRAW_HZ)
        } else {
            ProgressDrawTarget::hidden()
        };
        let multi = MultiProgress::with_draw_target(target);

        let bar_style = ProgressStyle::with_template(&format!(
            "  {{prefix:<15}} [{{bar:{BAR_WIDTH}}}] {{percent:>3}}%  {{msg}}"
        ))
        .expect("static template")
        .progress_chars("=> ");

        let info_style = ProgressStyle::with_template(&format!(
            "  {{prefix:<15}}  {:BAR_WIDTH$}    {{msg}}",
            ""
        ))
        .expect("static template");

        let mk = |label: &'static str, style: &ProgressStyle| {
            let pb = multi.add(ProgressBar::new(1));
            pb.set_style(style.clone());
            pb.set_prefix(label);
            pb.set_message(NOT_ENABLED);
            pb
        };

        Self {
            block_headers: mk("block headers", &bar_style),
            filter_headers: mk("filter headers", &bar_style),
            filters: mk("filters", &bar_style),
            masternodes: mk("masternodes", &bar_style),
            blocks: mk("matched blocks", &bar_style),
            chainlocks: mk("chainlocks", &info_style),
            instantsend: mk("instantsend", &info_style),
            mempool: mk("mempool", &info_style),
            multi,
        }
    }

    pub fn log_writer(&self) -> BarWriter {
        BarWriter(self.multi.clone())
    }

    pub fn render(&self, progress: &SyncProgress) {
        fn set(pb: &ProgressBar, p: &impl ProgressPercentage) {
            let (current, target) = (p.current_height(), p.target_height());
            pb.set_length(target.max(1) as u64);
            pb.set_position(current.min(target) as u64);
            pb.set_message(format!("{} / {}", current, target));
        }

        if let Ok(p) = progress.headers() {
            set(&self.block_headers, p);
        }
        if let Ok(p) = progress.filter_headers() {
            let (current, target) = (p.current_height(), p.target_height());
            self.filter_headers.set_length(target.max(1) as u64);
            self.filter_headers.set_position(current.min(target) as u64);
            self.filter_headers.set_message(format!(
                "{} / {}  (verified {})",
                current,
                target,
                p.current_height()
            ));
        }
        if let Ok(p) = progress.filters() {
            set(&self.filters, p);
        }
        if let Ok(p) = progress.masternodes() {
            let (current, target) = (p.current_height(), p.target_height());
            self.masternodes.set_length(target.max(1) as u64);
            self.masternodes.set_position(current.min(target) as u64);
            self.masternodes.set_message(format!(
                "{} / {}  ({} diffs, {} cycles)",
                current,
                target,
                p.diffs_processed(),
                p.validated_cycles()
            ));
        }
        if let Ok(p) = progress.blocks() {
            let tip = progress.headers().map(|h| h.target_height()).unwrap_or(0);
            let done = p.last_processed();
            self.blocks.set_length(tip.max(1) as u64);
            self.blocks.set_position(done.min(tip) as u64);
            self.blocks.set_message(format!(
                "{} / {}  ({} blocks, {} txs)",
                done,
                tip,
                p.processed(),
                p.transactions()
            ));
        }
        if let Ok(p) = progress.chainlocks() {
            self.chainlocks.set_message(format!(
                "{:?}  best {}  ({} valid, {} invalid)",
                p.state(),
                p.best_validated_height(),
                p.valid(),
                p.invalid()
            ));
        }
        if let Ok(p) = progress.instantsend() {
            self.instantsend.set_message(format!(
                "{:?}  {} valid, {} invalid, {} pending",
                p.state(),
                p.valid(),
                p.invalid(),
                p.pending()
            ));
        }
        if let Ok(p) = progress.mempool() {
            self.mempool.set_message(format!(
                "{:?}  {} tracked ({} relevant of {} seen)",
                p.state(),
                p.tracked(),
                p.relevant(),
                p.received()
            ));
        }
    }

    pub fn finish(&self) {
        for pb in [
            &self.block_headers,
            &self.filter_headers,
            &self.filters,
            &self.masternodes,
            &self.blocks,
            &self.chainlocks,
            &self.instantsend,
            &self.mempool,
        ] {
            if pb.message() == NOT_ENABLED {
                pb.abandon();
            } else {
                pb.finish();
            }
        }
    }
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct BarWriter(MultiProgress);

impl<'a> MakeWriter<'a> for BarWriter {
    type Writer = BarWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        BarWriterGuard {
            multi: self.0.clone(),
            buf: Vec::new(),
        }
    }
}

pub struct BarWriterGuard {
    multi: MultiProgress,
    buf: Vec<u8>,
}

impl Write for BarWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let line = std::mem::take(&mut self.buf);
        self.multi.suspend(|| {
            let mut err = io::stderr().lock();
            let _ = err.write_all(&line);
            let _ = err.flush();
        });
        Ok(())
    }
}

impl Drop for BarWriterGuard {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}
