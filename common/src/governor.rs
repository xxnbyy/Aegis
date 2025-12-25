use std::time::{Duration, Instant};

use crate::config::{GovernorConfig, PidConfig, TokenBucketConfig};

#[derive(Debug, Clone)]
pub struct PidController {
    k_p: f64,
    k_i: f64,
    k_d: f64,
    integral: f64,
    last_error: Option<f64>,
}

impl PidController {
    pub fn new(cfg: &PidConfig) -> Self {
        Self {
            k_p: cfg.k_p,
            k_i: cfg.k_i,
            k_d: cfg.k_d,
            integral: 0.0,
            last_error: None,
        }
    }

    pub fn update_params(&mut self, cfg: &PidConfig) {
        self.k_p = cfg.k_p;
        self.k_i = cfg.k_i;
        self.k_d = cfg.k_d;
    }

    pub fn reset(&mut self) {
        self.integral = 0.0;
        self.last_error = None;
    }

    pub fn compute_sleep(
        &mut self,
        target_percent: u32,
        current_percent: u32,
        dt: Duration,
    ) -> Duration {
        let dt_secs = dt.as_secs_f64();
        if !dt_secs.is_finite() || dt_secs <= 0.0 {
            return Duration::from_secs(0);
        }

        let error = (f64::from(current_percent) - f64::from(target_percent)).max(0.0);
        self.integral = (self.integral + error * dt_secs).clamp(0.0, 10_000.0);

        let derivative = match self.last_error {
            None => 0.0,
            Some(prev) => (error - prev) / dt_secs,
        };
        self.last_error = Some(error);

        let output_ms = (self.k_p * error) + (self.k_i * self.integral) + (self.k_d * derivative);
        if !output_ms.is_finite() || output_ms <= 0.0 {
            return Duration::from_secs(0);
        }

        let max_ms = 1_000.0;
        let ms = output_ms.clamp(0.0, max_ms);
        Duration::from_secs_f64(ms / 1_000.0)
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u32,
    refill_per_sec: u32,
    tokens: f64,
    last_refill: Instant,
    dropped: u64,
}

impl TokenBucket {
    pub fn new(cfg: &TokenBucketConfig, now: Instant) -> Self {
        Self {
            capacity: cfg.capacity,
            refill_per_sec: cfg.refill_per_sec,
            tokens: f64::from(cfg.capacity),
            last_refill: now,
            dropped: 0,
        }
    }

    pub fn has_budget(&mut self, cost: u32) -> bool {
        self.has_budget_at(cost, Instant::now())
    }

    pub fn has_budget_at(&mut self, cost: u32, now: Instant) -> bool {
        self.refill(now);
        if cost == 0 {
            return true;
        }
        self.tokens >= f64::from(cost)
    }

    pub fn try_consume(&mut self, cost: u32) -> bool {
        self.try_consume_at(cost, Instant::now())
    }

    pub fn try_consume_at(&mut self, cost: u32, now: Instant) -> bool {
        self.refill(now);
        if cost == 0 {
            return true;
        }
        let cost_f = f64::from(cost);
        if self.tokens >= cost_f {
            self.tokens -= cost_f;
            return true;
        }
        false
    }

    pub fn update_params(&mut self, cfg: &TokenBucketConfig) {
        self.capacity = cfg.capacity;
        self.refill_per_sec = cfg.refill_per_sec;
        self.tokens = self.tokens.clamp(0.0, f64::from(self.capacity));
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn check_budget(&mut self, cost: u32) -> bool {
        self.check_budget_at(cost, Instant::now())
    }

    pub fn check_budget_at(&mut self, cost: u32, now: Instant) -> bool {
        if self.try_consume_at(cost, now) {
            return true;
        }
        self.dropped = self.dropped.saturating_add(u64::from(cost));
        false
    }

    fn refill(&mut self, now: Instant) {
        if now <= self.last_refill {
            return;
        }
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if !elapsed.is_finite() || elapsed <= 0.0 {
            return;
        }
        let added = elapsed * f64::from(self.refill_per_sec);
        self.tokens = (self.tokens + added).clamp(0.0, f64::from(self.capacity));
        self.last_refill = now;
    }
}

#[derive(Debug, Clone)]
pub struct IoLimiter {
    limit_bytes_per_sec: u64,
    capacity_bytes: u64,
    tokens_bytes: u64,
    last_refill: Instant,
}

impl IoLimiter {
    pub fn new(limit_mb_per_sec: u32, now: Instant) -> Self {
        let limit_bytes_per_sec = u64::from(limit_mb_per_sec).saturating_mul(1024 * 1024);
        let capacity_bytes = limit_bytes_per_sec;
        Self {
            limit_bytes_per_sec,
            capacity_bytes,
            tokens_bytes: capacity_bytes,
            last_refill: now,
        }
    }

    pub fn update_limit(&mut self, limit_mb_per_sec: u32) {
        self.limit_bytes_per_sec = u64::from(limit_mb_per_sec).saturating_mul(1024 * 1024);
        self.capacity_bytes = self.limit_bytes_per_sec;
        self.tokens_bytes = self.tokens_bytes.min(self.capacity_bytes);
    }

    pub fn reserve(&mut self, bytes: u64) -> Duration {
        self.reserve_at(bytes, Instant::now())
    }

    pub fn reserve_at(&mut self, bytes: u64, now: Instant) -> Duration {
        if bytes == 0 {
            return Duration::from_secs(0);
        }
        if self.limit_bytes_per_sec == 0 {
            return Duration::from_secs(0);
        }

        self.refill(now);

        if self.tokens_bytes >= bytes {
            self.tokens_bytes = self.tokens_bytes.saturating_sub(bytes);
            return Duration::from_secs(0);
        }

        let missing = bytes.saturating_sub(self.tokens_bytes);
        self.tokens_bytes = 0;

        let limit = self.limit_bytes_per_sec.max(1);
        let nanos =
            ((u128::from(missing) * 1_000_000_000u128) + u128::from(limit - 1)) / u128::from(limit);
        let nanos_u64 = u64::try_from(nanos).unwrap_or(u64::MAX);
        Duration::from_nanos(nanos_u64)
    }

    fn refill(&mut self, now: Instant) {
        if now <= self.last_refill {
            return;
        }
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_nanos = elapsed.as_nanos().min(u128::from(u64::MAX));

        let added = (elapsed_nanos * u128::from(self.limit_bytes_per_sec)) / 1_000_000_000u128;
        let added_u64 = u64::try_from(added).unwrap_or(u64::MAX);
        self.tokens_bytes = self
            .tokens_bytes
            .saturating_add(added_u64)
            .min(self.capacity_bytes);
        self.last_refill = now;
    }
}

#[derive(Debug)]
pub struct Governor {
    cfg: GovernorConfig,
    pid: PidController,
    bucket: TokenBucket,
    io: IoLimiter,
    cpu: CpuUsageTracker,
    last_tick: Instant,
}

impl Governor {
    pub fn new(cfg: &GovernorConfig) -> Self {
        let now = Instant::now();
        let cfg = cfg.effective_profile_applied();
        let pid = PidController::new(&cfg.pid);
        let token_bucket_cfg = cfg.effective_token_bucket();
        let bucket = TokenBucket::new(&token_bucket_cfg, now);
        let io = IoLimiter::new(cfg.io_limit_mb, now);
        let cpu = CpuUsageTracker::new();
        Self {
            cfg,
            pid,
            bucket,
            io,
            cpu,
            last_tick: now,
        }
    }

    pub fn apply_config(&mut self, cfg: &GovernorConfig) {
        let cfg = cfg.effective_profile_applied();
        self.pid.update_params(&cfg.pid);
        let token_bucket_cfg = cfg.effective_token_bucket();
        self.bucket.update_params(&token_bucket_cfg);
        self.io.update_limit(cfg.io_limit_mb);
        self.cfg = cfg;
    }

    pub fn get_max_single_core_usage(&mut self) -> u32 {
        self.cpu.get_max_single_core_usage()
    }

    pub fn check_budget(&mut self, cost: u32) -> bool {
        self.bucket.check_budget(cost)
    }

    pub fn has_budget(&mut self, cost: u32) -> bool {
        self.bucket.has_budget(cost)
    }

    pub fn try_consume_budget(&mut self, cost: u32) -> bool {
        self.bucket.check_budget(cost)
    }

    pub fn dropped_events(&self) -> u64 {
        self.bucket.dropped()
    }

    pub fn throttle_io(&mut self, bytes: u64) -> Duration {
        self.io.reserve(bytes)
    }

    pub fn tick_with_usage(&mut self) -> (u32, Duration) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_tick);
        self.last_tick = now;
        let usage = self.get_max_single_core_usage();
        let sleep = self
            .pid
            .compute_sleep(self.cfg.max_single_core_usage, usage, dt);
        (usage, sleep)
    }

    pub fn tick(&mut self) -> Duration {
        self.tick_with_usage().1
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(not(windows))]
struct CpuTimes {
    idle: u64,
    total: u64,
}

#[derive(Debug)]
pub struct CpuUsageTracker {
    #[cfg(not(windows))]
    prev: Option<Vec<CpuTimes>>,
    #[cfg(windows)]
    sys: sysinfo::System,
    #[cfg(windows)]
    initialized: bool,
}

impl Default for CpuUsageTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuUsageTracker {
    pub fn new() -> Self {
        Self {
            #[cfg(not(windows))]
            prev: None,
            #[cfg(windows)]
            sys: sysinfo::System::new_all(),
            #[cfg(windows)]
            initialized: false,
        }
    }

    pub fn get_max_single_core_usage(&mut self) -> u32 {
        #[cfg(windows)]
        {
            self.sample_windows_max_core_usage()
        }
        #[cfg(not(windows))]
        {
            self.sample_linux_max_core_usage()
        }
    }

    #[cfg(not(windows))]
    fn sample_linux_max_core_usage(&mut self) -> u32 {
        let Ok(text) = std::fs::read_to_string("/proc/stat") else {
            return 0;
        };
        let current = parse_proc_stat_cores(text.as_str());
        match self.prev.as_mut() {
            None => {
                self.prev = Some(current);
                0
            }
            Some(prev) => {
                let usage = compute_max_usage_percent(prev.as_slice(), current.as_slice());
                *prev = current;
                usage
            }
        }
    }

    #[cfg(windows)]
    fn sample_windows_max_core_usage(&mut self) -> u32 {
        self.sys.refresh_all();
        if !self.initialized {
            self.initialized = true;
            return 0;
        }
        let max = self
            .sys
            .cpus()
            .iter()
            .map(sysinfo::Cpu::cpu_usage)
            .fold(0.0f32, |acc, v| if v > acc { v } else { acc })
            .round()
            .clamp(0.0, 100.0);
        #[allow(clippy::cast_possible_truncation)]
        u32::try_from(max as i32).unwrap_or(0)
    }
}

#[cfg(not(windows))]
fn parse_proc_stat_cores(text: &str) -> Vec<CpuTimes> {
    let mut out: Vec<(usize, CpuTimes)> = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(label) = it.next() else {
            continue;
        };
        if !label.starts_with("cpu") || label == "cpu" {
            continue;
        }
        let idx_str = &label[3..];
        let Ok(idx) = idx_str.parse::<usize>() else {
            continue;
        };

        let mut vals = [0u64; 8];
        for v in &mut vals {
            let Some(tok) = it.next() else {
                *v = 0;
                continue;
            };
            *v = tok.parse::<u64>().unwrap_or(0);
        }
        let idle = vals[3].saturating_add(vals[4]);
        let total = vals.iter().fold(0u64, |acc, x| acc.saturating_add(*x));
        out.push((idx, CpuTimes { idle, total }));
    }
    out.sort_by_key(|(idx, _)| *idx);
    out.into_iter().map(|(_, t)| t).collect()
}

#[cfg(not(windows))]
fn compute_max_usage_percent(prev: &[CpuTimes], curr: &[CpuTimes]) -> u32 {
    let n = prev.len().min(curr.len());
    if n == 0 {
        return 0;
    }
    let mut max: u32 = 0;
    for i in 0..n {
        let idle_delta = curr[i].idle.saturating_sub(prev[i].idle);
        let total_delta = curr[i].total.saturating_sub(prev[i].total);
        if total_delta == 0 {
            continue;
        }
        let busy = total_delta.saturating_sub(idle_delta);
        let usage = ((u128::from(busy) * 100u128) + (u128::from(total_delta) / 2u128))
            / u128::from(total_delta);
        let usage = usage.min(100);
        let usage_u32 = u32::try_from(usage).unwrap_or(100);
        if usage_u32 > max {
            max = usage_u32;
        }
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_sleep_increases_under_constant_overload() {
        let cfg = PidConfig {
            k_p: 0.8,
            k_i: 0.2,
            k_d: 0.0,
        };
        let mut pid = PidController::new(&cfg);
        let mut prev = Duration::from_millis(0);
        for _ in 0..10 {
            let out = pid.compute_sleep(5, 60, Duration::from_millis(100));
            assert!(out >= prev);
            prev = out;
        }
        assert!(prev >= Duration::from_millis(1));
    }

    #[test]
    fn token_bucket_drops_when_empty_and_refills() {
        let cfg = TokenBucketConfig {
            capacity: 10,
            refill_per_sec: 10,
        };
        let t0 = Instant::now();
        let mut b = TokenBucket::new(&cfg, t0);
        assert!(b.check_budget_at(10, t0));
        assert!(!b.check_budget_at(1, t0));
        assert_eq!(b.dropped(), 1);

        let t1 = t0 + Duration::from_secs(1);
        assert!(b.check_budget_at(10, t1));
        assert!(!b.check_budget_at(1, t1));
        assert_eq!(b.dropped(), 2);
    }

    #[test]
    fn io_limiter_returns_sleep_when_exceeding_rate() {
        let t0 = Instant::now();
        let mut io = IoLimiter::new(1, t0);
        assert_eq!(io.reserve_at(1_048_576, t0), Duration::from_secs(0));
        let sleep = io.reserve_at(1, t0);
        assert!(sleep > Duration::from_secs(0));

        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(io.reserve_at(1_048_576, t1), Duration::from_secs(0));
    }

    #[cfg(not(windows))]
    #[test]
    fn proc_stat_parser_extracts_cores() {
        let text = "cpu  1 2 3 4 5 6 7 8\ncpu0 10 0 0 10 0 0 0 0\ncpu1 20 0 0 20 0 0 0 0\n";
        let cores = parse_proc_stat_cores(text);
        assert_eq!(cores.len(), 2);
        assert_eq!(cores[0].total, 20);
        assert_eq!(cores[1].total, 40);
    }
}
