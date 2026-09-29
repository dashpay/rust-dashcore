use std::path::Path;

#[cfg(feature = "heap-profile")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "heap-profile")]
#[export_name = "_rjem_malloc_conf"]
pub static MALLOC_CONF: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

#[cfg(feature = "heap-profile")]
type HeapPeak = std::sync::Arc<std::sync::Mutex<Option<(u64, jemalloc_pprof::StackProfile)>>>;

pub(crate) struct Profilers {
    #[cfg(feature = "cpu-profile")]
    cpu: Option<pprof::ProfilerGuard<'static>>,
    #[cfg(feature = "heap-profile")]
    heap_peak: HeapPeak,
}

pub(crate) fn start() -> Profilers {
    let profilers = Profilers {
        #[cfg(feature = "cpu-profile")]
        cpu: pprof::ProfilerGuardBuilder::default()
            .frequency(99)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
            .inspect_err(|e| tracing::warn!("cpu profiler not started: {e}"))
            .ok(),
        #[cfg(feature = "heap-profile")]
        heap_peak: HeapPeak::default(),
    };
    #[cfg(feature = "heap-profile")]
    {
        let peak = profilers.heap_peak.clone();
        std::thread::spawn(move || {
            let Some(ctl) = jemalloc_pprof::PROF_CTL.as_ref() else {
                tracing::warn!("jemalloc heap profiling is not enabled");
                return;
            };
            let mut dumped_kb = 0;
            while let Some(rss_kb) = crate::proc_status_kb("VmRSS:") {
                if rss_kb > dumped_kb + dumped_kb / 20 {
                    match ctl.blocking_lock().dump_profile() {
                        Ok(profile) => {
                            dumped_kb = rss_kb;
                            if let Ok(mut slot) = peak.lock() {
                                *slot = Some((rss_kb, profile));
                            }
                        }
                        Err(e) => {
                            tracing::warn!("heap snapshot failed: {e}");
                            return;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });
    }
    profilers
}

impl Profilers {
    #[allow(unused_variables)]
    pub(crate) fn finish(self, dir: &Path) {
        #[cfg(feature = "heap-profile")]
        if let Some((rss_kb, profile)) = self.heap_peak.lock().ok().and_then(|mut slot| slot.take())
        {
            let mut opts = jemalloc_pprof::FlamegraphOptions::default();
            opts.title = format!("dash-spv live heap at the RSS peak ({} MiB)", rss_kb / 1024);
            opts.count_name = "bytes".to_string();
            let written =
                profile.to_flamegraph(&mut opts).map_err(|e| e.to_string()).and_then(|svg| {
                    std::fs::write(dir.join("heap-peak.svg"), svg).map_err(|e| e.to_string())
                });
            if let Err(e) = written {
                tracing::warn!("could not write heap-peak.svg: {e}");
            }
        }
        #[cfg(feature = "cpu-profile")]
        if let Some(report) = self.cpu.as_ref().and_then(|guard| guard.report().build().ok()) {
            let written = std::fs::File::create(dir.join("flamegraph.svg"))
                .map_err(|e| e.to_string())
                .and_then(|file| report.flamegraph(file).map_err(|e| e.to_string()));
            if let Err(e) = written {
                tracing::warn!("could not write flamegraph.svg: {e}");
            }
        }
    }
}
