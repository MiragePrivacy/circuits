//! Parallel fixture runner with visible progress.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Memory one Keccacheck satisfaction check may need: a native check peaks at
/// 7.2 GiB, so this keeps ~25% headroom.
const JOB_BYTES: u64 = 9 << 30;

/// `FIXTURE_JOBS`, or as many jobs as available memory and CPUs allow.
pub fn jobs() -> usize {
    if let Some(n) = std::env::var("FIXTURE_JOBS").ok().and_then(|v| v.parse().ok()) {
        return n;
    }
    let available = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemAvailable:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map(|kb| kb * 1024)
        .unwrap_or(JOB_BYTES);
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    ((available / JOB_BYTES) as usize).clamp(1, cpus)
}

/// Runs `check` over every item on [`jobs`] threads, printing one line per
/// completed item, and returns the failures' messages.
pub fn run<T: Sync>(
    items: &[T],
    name: impl Fn(&T) -> String + Sync,
    check: impl Fn(&T) -> Result<(), String> + Sync,
) -> Vec<String> {
    let jobs = jobs().min(items.len()).max(1);
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let failed = Mutex::new(Vec::new());
    let start = Instant::now();
    eprintln!("checking {} fixtures on {jobs} jobs", items.len());
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(i) else { break };
                let t = Instant::now();
                let result = check(item);
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!(
                    "[{n}/{}] {} {} ({:.1}s, {:.0}s total)",
                    items.len(),
                    name(item),
                    if result.is_ok() { "ok" } else { "FAILED" },
                    t.elapsed().as_secs_f64(),
                    start.elapsed().as_secs_f64()
                );
                if let Err(e) = result {
                    failed.lock().unwrap().push(format!("{}: {e}", name(item)));
                }
            });
        }
    });
    failed.into_inner().unwrap()
}
