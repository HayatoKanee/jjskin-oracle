use std::fs::read_to_string;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Default)]
pub struct OracleRuntimeMetrics {
    active_notarizations: AtomicUsize,
    inventory_attestation_cache_hits: AtomicU64,
    inventory_attestation_cache_misses: AtomicU64,
    mpc_tls_timeouts: AtomicU64,
}

impl OracleRuntimeMetrics {
    pub fn increment_active_notarizations(&self) -> usize {
        self.active_notarizations.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn decrement_active_notarizations(&self) -> usize {
        self.active_notarizations.fetch_sub(1, Ordering::Relaxed) - 1
    }

    pub fn active_notarizations(&self) -> usize {
        self.active_notarizations.load(Ordering::Relaxed)
    }

    pub fn record_inventory_attestation_cache_hit(&self) -> u64 {
        self.inventory_attestation_cache_hits
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_inventory_attestation_cache_miss(&self) -> u64 {
        self.inventory_attestation_cache_misses
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn inventory_attestation_cache_hits(&self) -> u64 {
        self.inventory_attestation_cache_hits.load(Ordering::Relaxed)
    }

    pub fn inventory_attestation_cache_misses(&self) -> u64 {
        self.inventory_attestation_cache_misses.load(Ordering::Relaxed)
    }

    pub fn record_mpc_tls_timeout(&self) -> u64 {
        self.mpc_tls_timeouts.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn mpc_tls_timeouts(&self) -> u64 {
        self.mpc_tls_timeouts.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessCpuSample {
    process_ticks: u64,
    total_ticks: u64,
}

pub fn current_rss_bytes() -> Option<u64> {
    let status = read_to_string("/proc/self/status").ok()?;
    let rss_kib = parse_status_value_kib(&status, "VmRSS")?;
    Some(rss_kib * 1024)
}

pub fn current_thread_count() -> Option<u64> {
    let status = read_to_string("/proc/self/status").ok()?;
    parse_status_value_u64(&status, "Threads")
}

pub fn current_loadavg_1m() -> Option<f64> {
    let loadavg = read_to_string("/proc/loadavg").ok()?;
    parse_loadavg_1m(&loadavg)
}

pub fn current_process_cpu_sample() -> Option<ProcessCpuSample> {
    let process_stat = read_to_string("/proc/self/stat").ok()?;
    let system_stat = read_to_string("/proc/stat").ok()?;

    Some(ProcessCpuSample {
        process_ticks: parse_process_ticks(&process_stat)?,
        total_ticks: parse_total_cpu_ticks(&system_stat)?,
    })
}

pub fn process_cpu_percent(
    previous: ProcessCpuSample,
    current: ProcessCpuSample,
    cpu_count: usize,
) -> Option<f64> {
    if cpu_count == 0 || current.total_ticks <= previous.total_ticks {
        return None;
    }

    let process_delta = current.process_ticks.saturating_sub(previous.process_ticks);
    let total_delta = current.total_ticks.saturating_sub(previous.total_ticks);

    if total_delta == 0 {
        return None;
    }

    let cpu_ratio = process_delta as f64 / total_delta as f64;
    Some(cpu_ratio * cpu_count as f64 * 100.0)
}

fn parse_status_value_kib(status: &str, key: &str) -> Option<u64> {
    let value = status
        .lines()
        .find(|line| line.starts_with(&format!("{key}:")))?
        .split_whitespace()
        .nth(1)?;

    value.parse::<u64>().ok()
}

fn parse_status_value_u64(status: &str, key: &str) -> Option<u64> {
    let value = status
        .lines()
        .find(|line| line.starts_with(&format!("{key}:")))?
        .split_whitespace()
        .nth(1)?;

    value.parse::<u64>().ok()
}

fn parse_loadavg_1m(loadavg: &str) -> Option<f64> {
    loadavg.split_whitespace().next()?.parse::<f64>().ok()
}

fn parse_process_ticks(stat: &str) -> Option<u64> {
    let (_, fields) = stat.rsplit_once(") ")?;
    let mut parts = fields.split_whitespace();

    let utime = parts.nth(11)?.parse::<u64>().ok()?;
    let stime = parts.next()?.parse::<u64>().ok()?;

    Some(utime + stime)
}

fn parse_total_cpu_ticks(stat: &str) -> Option<u64> {
    let cpu_line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let ticks = cpu_line
        .split_whitespace()
        .skip(1)
        .map(|value| value.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;

    Some(ticks.into_iter().sum())
}

#[cfg(test)]
mod tests {
    use super::{
        ProcessCpuSample, parse_loadavg_1m, parse_process_ticks, parse_status_value_kib,
        parse_status_value_u64, parse_total_cpu_ticks, process_cpu_percent,
    };

    #[test]
    fn parses_process_ticks_from_proc_stat() {
        let sample = "1234 (tlsn-server) R 1 2 3 4 5 6 7 8 9 10 120 30 14 15 16";
        assert_eq!(parse_process_ticks(sample), Some(150));
    }

    #[test]
    fn parses_total_cpu_ticks_from_proc_stat() {
        let sample = "cpu  100 200 300 400 500 600 700 800 900 1000\ncpu0 1 2 3 4";
        assert_eq!(parse_total_cpu_ticks(sample), Some(5500));
    }

    #[test]
    fn parses_rss_and_thread_count_from_status() {
        let status = "Name:\ttlsn-server\nVmRSS:\t  12345 kB\nThreads:\t7\n";
        assert_eq!(parse_status_value_kib(status, "VmRSS"), Some(12345));
        assert_eq!(parse_status_value_u64(status, "Threads"), Some(7));
    }

    #[test]
    fn parses_loadavg() {
        assert_eq!(parse_loadavg_1m("0.42 0.10 0.05 1/123 456"), Some(0.42));
    }

    #[test]
    fn computes_process_cpu_percent() {
        let previous = ProcessCpuSample {
            process_ticks: 100,
            total_ticks: 1_000,
        };
        let current = ProcessCpuSample {
            process_ticks: 150,
            total_ticks: 1_500,
        };

        let cpu_pct = process_cpu_percent(previous, current, 2).unwrap();
        assert!((cpu_pct - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cpu_percent_returns_none_for_zero_delta() {
        let sample = ProcessCpuSample {
            process_ticks: 100,
            total_ticks: 1_000,
        };
        assert_eq!(process_cpu_percent(sample, sample, 2), None);
    }
}
