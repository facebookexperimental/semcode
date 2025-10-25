// SPDX-License-Identifier: MIT OR Apache-2.0
use gxhash::{HashMap, HashMapExt};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Global flag to enable/disable performance monitoring (set by --perf flag)
pub static PERF_MONITORING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Global performance statistics tracker
pub static PERF_STATS: Lazy<Mutex<PerfStats>> = Lazy::new(|| Mutex::new(PerfStats::new()));

/// Enable performance monitoring (call this from main when --perf flag is set)
pub fn enable_performance_monitoring() {
    PERF_MONITORING_ENABLED.store(true, Ordering::Relaxed);
}

/// Check if performance monitoring is enabled
pub fn is_performance_monitoring_enabled() -> bool {
    PERF_MONITORING_ENABLED.load(Ordering::Relaxed)
}

#[derive(Debug, Default)]
pub struct PerfStats {
    metrics: HashMap<String, MetricData>,
}

#[derive(Debug, Default)]
struct MetricData {
    count: u64,
    total_duration: Duration,
    min_duration: Option<Duration>,
    max_duration: Option<Duration>,
}

impl PerfStats {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
        }
    }

    pub fn record(&mut self, name: &str, duration: Duration) {
        let metric = self.metrics.entry(name.to_string()).or_default();
        metric.count += 1;
        metric.total_duration += duration;

        // Update min duration
        metric.min_duration = Some(match metric.min_duration {
            Some(min) => min.min(duration),
            None => duration,
        });

        // Update max duration
        metric.max_duration = Some(match metric.max_duration {
            Some(max) => max.max(duration),
            None => duration,
        });
    }

    pub fn print_summary(&self) {
        if self.metrics.is_empty() {
            return;
        }

        println!("\n=== Performance Statistics ===");

        let mut sorted_metrics: Vec<_> = self.metrics.iter().collect();
        sorted_metrics.sort_by_key(|(name, _)| name.as_str());

        for (name, data) in sorted_metrics {
            let avg_duration = data.total_duration / data.count as u32;
            println!(
                "{:<30} count={:>6} avg={:>8.2}ms min={:>8.2}ms max={:>8.2}ms total={:>10.2}ms",
                name,
                data.count,
                avg_duration.as_secs_f64() * 1000.0,
                data.min_duration.unwrap_or_default().as_secs_f64() * 1000.0,
                data.max_duration.unwrap_or_default().as_secs_f64() * 1000.0,
                data.total_duration.as_secs_f64() * 1000.0,
            );
        }

        let total_time: Duration = self.metrics.values().map(|m| m.total_duration).sum();
        println!("\nTotal time tracked: {:.2}s", total_time.as_secs_f64());
    }

    pub fn reset(&mut self) {
        self.metrics.clear();
    }
}

/// Measure the duration of a code block and record it
#[macro_export]
macro_rules! measure {
    ($name:expr, $block:expr) => {{
        let _start = std::time::Instant::now();
        let _result = $block;
        let _duration = _start.elapsed();

        // Only record if performance monitoring is enabled (fast atomic check)
        if $crate::perf_monitor::is_performance_monitoring_enabled() {
            if let Ok(mut stats) = $crate::perf_monitor::PERF_STATS.lock() {
                stats.record($name, _duration);
            }
        }

        _result
    }};
}

/// Performance guard that records duration when dropped
pub struct PerfGuard {
    name: String,
    start: Instant,
}

impl PerfGuard {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            start: Instant::now(),
        }
    }
}

impl Drop for PerfGuard {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        // Only record if performance monitoring is enabled (fast atomic check)
        if is_performance_monitoring_enabled() {
            if let Ok(mut stats) = PERF_STATS.lock() {
                stats.record(&self.name, duration);
            }
        }
    }
}

/// Create a performance guard for the current scope
pub fn perf_guard(name: impl Into<String>) -> PerfGuard {
    PerfGuard::new(name)
}
