use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use sha2::Digest;

use crate::error::AegisError;
#[cfg(target_os = "linux")]
use crate::error::ErrorCode;
use crate::governor::Governor;
use crate::protocol::ProcessInfo;

#[derive(Debug, Default)]
pub struct DroppedEventCounter {
    total: AtomicU64,
}

impl DroppedEventCounter {
    pub fn add(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

pub fn exec_id_from_start_boottime_ns(start_boottime_ns: u64) -> u64 {
    start_boottime_ns
}

#[cfg(target_os = "linux")]
fn proc_clk_ticks_per_sec() -> Option<u64> {
    #[allow(unsafe_code)]
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v <= 0 {
        return None;
    }
    u64::try_from(v).ok()
}

#[cfg(target_os = "linux")]
fn parse_proc_stat_ppid_and_starttime_ticks(stat: &str) -> Option<(u32, u64)> {
    let close = stat.rfind(')')?;
    let after = stat.get(close.saturating_add(1)..)?;
    let mut it = after.split_whitespace();
    let _state = it.next()?;
    let ppid_s = it.next()?;
    let ppid = ppid_s.parse::<u32>().ok()?;

    let mut starttime_ticks: Option<u64> = None;
    for idx in 2u32..=19u32 {
        let s = it.next()?;
        if idx == 19 {
            starttime_ticks = s.parse::<u64>().ok();
            break;
        }
    }
    starttime_ticks.map(|ticks| (ppid, ticks))
}

#[cfg(target_os = "linux")]
fn read_to_string_trimmed(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let s = String::from_utf8_lossy(bytes.as_slice()).to_string();
    Some(s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn read_cmdline(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let parts: Vec<String> = bytes
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).to_string())
        .collect();
    if parts.is_empty() {
        return None;
    }
    Some(parts.join(" "))
}

#[cfg(target_os = "linux")]
fn read_proc_uid(path: &std::path::Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut it = rest.split_whitespace();
        let uid_s = it.next()?;
        return uid_s.parse::<u32>().ok();
    }
    None
}

#[cfg(target_os = "linux")]
fn read_proc_uptime_seconds() -> Option<i64> {
    let content = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = content.split_whitespace().next()?;
    let (secs_s, frac_s) = first.split_once('.').unwrap_or((first, ""));
    let secs = secs_s.parse::<i64>().ok()?;
    let frac_first = frac_s.as_bytes().first().copied();
    let should_round_up = matches!(frac_first, Some(b'5'..=b'9'));
    if should_round_up {
        secs.checked_add(1)
    } else {
        Some(secs)
    }
}

#[cfg(target_os = "linux")]
fn unix_timestamp_now_seconds() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs().try_into().unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(target_os = "linux")]
pub fn list_proc_pids(max_pids: usize) -> Vec<u32> {
    if max_pids == 0 {
        return Vec::new();
    }
    let mut pids: Vec<u32> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for entry in rd.flatten() {
            if pids.len() >= max_pids {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(pid) = name.parse::<u32>() {
                pids.push(pid);
            }
        }
    }
    pids.sort_unstable();
    pids
}

#[cfg(target_os = "linux")]
pub fn bruteforce_proc_pids(max_pids: usize) -> Vec<u32> {
    if max_pids == 0 {
        return Vec::new();
    }

    let pid_max = std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(65_536)
        .clamp(1, 262_144);

    let mut out: Vec<u32> = Vec::new();
    for pid in 1..=pid_max {
        if out.len() >= max_pids {
            break;
        }
        let path = std::path::PathBuf::from("/proc").join(pid.to_string());
        let Ok(meta) = std::fs::metadata(path.as_path()) else {
            continue;
        };
        if meta.is_dir() {
            out.push(pid);
        }
    }
    out
}

#[cfg(target_os = "linux")]
pub fn bruteforce_proc_pids_governed(governor: &mut Governor, max_pids: usize) -> Vec<u32> {
    if max_pids == 0 {
        return Vec::new();
    }

    let pid_max = std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(65_536)
        .clamp(1, 262_144);

    let mut out: Vec<u32> = Vec::new();
    for pid in 1..=pid_max {
        if out.len() >= max_pids {
            break;
        }
        if pid == 1 || pid % 256 == 0 {
            wait_for_budget(governor, 1);
        }
        let path = std::path::PathBuf::from("/proc").join(pid.to_string());
        let Ok(meta) = std::fs::metadata(path.as_path()) else {
            continue;
        };
        if meta.is_dir() {
            out.push(pid);
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn parse_ns_inode_from_link_target(target: &str) -> Option<u64> {
    let open = target.rfind('[')?;
    let close = target.rfind(']')?;
    if close <= open {
        return None;
    }
    let inner = target.get(open.saturating_add(1)..close)?;
    inner.parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn ns_inode_for_pid(pid: u32, ns: &str) -> Option<u64> {
    let path = std::path::PathBuf::from("/proc")
        .join(pid.to_string())
        .join("ns")
        .join(ns);
    let target = std::fs::read_link(path.as_path()).ok()?;
    let s = target.to_string_lossy().to_string();
    parse_ns_inode_from_link_target(s.as_str())
}

#[cfg(target_os = "linux")]
fn parse_nspid_first(status: &str) -> Option<u32> {
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("NSpid:") else {
            continue;
        };
        let first = rest.split_whitespace().next()?;
        return first.parse::<u32>().ok();
    }
    None
}

#[cfg(target_os = "linux")]
fn open_pidns_files(target_pid: u32) -> Option<(std::fs::File, std::fs::File)> {
    let mnt_ns_path = std::path::PathBuf::from("/proc")
        .join(target_pid.to_string())
        .join("ns")
        .join("mnt");
    let pid_ns_path = std::path::PathBuf::from("/proc")
        .join(target_pid.to_string())
        .join("ns")
        .join("pid");

    let mnt_ns = std::fs::File::open(mnt_ns_path.as_path()).ok()?;
    let pid_ns = std::fs::File::open(pid_ns_path.as_path()).ok()?;
    Some((mnt_ns, pid_ns))
}

#[cfg(target_os = "linux")]
fn create_pipe_cloexec() -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    #[allow(unsafe_code)]
    let ok = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ok != 0 {
        return None;
    }
    Some((fds[0], fds[1]))
}

#[cfg(target_os = "linux")]
fn enumerate_pidns_host_pids(limit: usize) -> Vec<u32> {
    if limit == 0 {
        return Vec::new();
    }
    let mut host_pids: Vec<u32> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for entry in rd.flatten() {
            if host_pids.len() >= limit {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let Ok(proc_pid) = name.parse::<u32>() else {
                continue;
            };
            let status_path = std::path::PathBuf::from("/proc")
                .join(proc_pid.to_string())
                .join("status");
            let Ok(status) = std::fs::read_to_string(status_path.as_path()) else {
                continue;
            };
            let Some(host_pid) = parse_nspid_first(status.as_str()) else {
                continue;
            };
            host_pids.push(host_pid);
        }
    }
    host_pids.sort_unstable();
    host_pids.dedup();
    host_pids
}

#[cfg(target_os = "linux")]
fn remount_proc_best_effort() {
    use std::ffi::CString;

    #[allow(unsafe_code)]
    unsafe {
        if libc::unshare(libc::CLONE_NEWNS) != 0 {
            libc::_exit(1);
        }
    }

    let root = CString::new("/").ok();
    let Some(root) = root else {
        #[allow(unsafe_code)]
        unsafe {
            libc::_exit(1);
        }
    };

    #[allow(unsafe_code)]
    unsafe {
        if libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        ) != 0
        {
            libc::_exit(1);
        }
    }

    let src = CString::new("proc").ok();
    let fstype = CString::new("proc").ok();
    let target = CString::new("/proc").ok();
    let (Some(src), Some(fstype), Some(target)) = (src, fstype, target) else {
        #[allow(unsafe_code)]
        unsafe {
            libc::_exit(1);
        }
    };

    #[allow(unsafe_code)]
    unsafe {
        let _ = libc::umount2(target.as_ptr(), libc::MNT_DETACH);
    }
    #[allow(unsafe_code)]
    unsafe {
        let _ = libc::mount(
            src.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong,
            std::ptr::null(),
        );
    }
}

#[cfg(target_os = "linux")]
fn collect_host_pids_in_target_pidns(target_pid: u32, limit: usize) -> Vec<u32> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};

    if limit == 0 {
        return Vec::new();
    }

    let Some((mnt_ns, pid_ns)) = open_pidns_files(target_pid) else {
        return Vec::new();
    };
    let Some((read_fd, write_fd)) = create_pipe_cloexec() else {
        return Vec::new();
    };

    #[allow(unsafe_code)]
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        #[allow(unsafe_code)]
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Vec::new();
    }

    if child_pid == 0 {
        #[allow(unsafe_code)]
        unsafe {
            libc::close(read_fd);
        }

        #[allow(unsafe_code)]
        unsafe {
            if libc::setns(mnt_ns.as_raw_fd(), libc::CLONE_NEWNS) != 0 {
                libc::_exit(1);
            }
            if libc::setns(pid_ns.as_raw_fd(), libc::CLONE_NEWPID) != 0 {
                libc::_exit(1);
            }
        }

        #[allow(unsafe_code)]
        let grandchild_pid = unsafe { libc::fork() };
        if grandchild_pid < 0 {
            #[allow(unsafe_code)]
            unsafe {
                libc::_exit(1);
            }
        }

        if grandchild_pid == 0 {
            use std::io::Write;

            remount_proc_best_effort();

            let host_pids = enumerate_pidns_host_pids(limit);
            #[allow(unsafe_code)]
            let mut writer = unsafe { std::fs::File::from_raw_fd(write_fd) };
            for pid_value in host_pids {
                let _write_result = writer.write_all(format!("{pid_value}\n").as_bytes());
            }
            #[allow(unsafe_code)]
            unsafe {
                libc::_exit(0);
            }
        }

        #[allow(unsafe_code)]
        unsafe {
            let mut status: i32 = 0;
            let _ = libc::waitpid(grandchild_pid, &raw mut status, 0);
            libc::_exit(0);
        }
    }

    #[allow(unsafe_code)]
    unsafe {
        libc::close(write_fd);
    }

    #[allow(unsafe_code)]
    let mut reader = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let mut bytes: Vec<u8> = Vec::new();
    let _read_result = reader.read_to_end(&mut bytes);
    drop(reader);

    #[allow(unsafe_code)]
    unsafe {
        let mut status: i32 = 0;
        let _ = libc::waitpid(child_pid, &raw mut status, 0);
    }

    let s = String::from_utf8_lossy(bytes.as_slice()).to_string();
    let mut out: Vec<u32> = Vec::new();
    for line in s.lines() {
        let Ok(v) = line.trim().parse::<u32>() else {
            continue;
        };
        out.push(v);
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(target_os = "linux")]
pub fn collect_host_pids_via_fork_setns(max_namespaces: usize, per_ns_limit: usize) -> Vec<u32> {
    if max_namespaces == 0 || per_ns_limit == 0 {
        return Vec::new();
    }

    let mut reps: Vec<u32> = Vec::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for pid in list_proc_pids(65_536) {
        if reps.len() >= max_namespaces {
            break;
        }
        let Some(inode) = ns_inode_for_pid(pid, "mnt") else {
            continue;
        };
        if seen.insert(inode) {
            reps.push(pid);
        }
    }

    let mut out: Vec<u32> = Vec::new();
    for pid in reps {
        out.extend(collect_host_pids_in_target_pidns(pid, per_ns_limit));
    }

    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(target_os = "linux")]
pub fn collect_host_pids_via_fork_setns_governed(
    governor: &mut Governor,
    max_namespaces: usize,
    per_ns_limit: usize,
) -> Vec<u32> {
    if max_namespaces == 0 || per_ns_limit == 0 {
        return Vec::new();
    }

    let mut reps: Vec<u32> = Vec::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for pid in list_proc_pids(65_536) {
        if reps.len() >= max_namespaces {
            break;
        }
        if pid == 1 || pid % 128 == 0 {
            wait_for_budget(governor, 1);
        }
        let Some(inode) = ns_inode_for_pid(pid, "mnt") else {
            continue;
        };
        if seen.insert(inode) {
            reps.push(pid);
        }
    }

    let mut out: Vec<u32> = Vec::new();
    for pid in reps {
        wait_for_budget(governor, 1);
        out.extend(collect_host_pids_in_target_pidns(pid, per_ns_limit));
    }

    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(target_os = "linux")]
fn collect_process_info_for_pid_with_ctx(
    pid: u32,
    hz: u64,
    now: i64,
    uptime_sec: i64,
    exec_id_counter: &AtomicU64,
) -> ProcessInfo {
    let base = std::path::PathBuf::from("/proc").join(pid.to_string());
    let stat_path = base.join("stat");
    let status_path = base.join("status");
    let comm_path = base.join("comm");
    let cmdline_path = base.join("cmdline");
    let exe_link = base.join("exe");

    let stat = std::fs::read_to_string(stat_path.as_path()).ok();
    let (parent_pid, start_ticks) = stat
        .as_deref()
        .and_then(parse_proc_stat_ppid_and_starttime_ticks)
        .unwrap_or((0, 0));

    let hz_nonzero = hz.max(1);
    let start_uptime_sec = start_ticks / hz_nonzero;
    let start_uptime_i64 = i64::try_from(start_uptime_sec).unwrap_or(i64::MAX);
    let age_sec = if uptime_sec > start_uptime_i64 {
        uptime_sec.saturating_sub(start_uptime_i64)
    } else {
        0
    };
    let start_time = now.saturating_sub(age_sec);

    let name = read_to_string_trimmed(comm_path.as_path()).unwrap_or_default();
    let cmdline = read_cmdline(cmdline_path.as_path()).unwrap_or_else(|| name.clone());
    let exe_path = std::fs::read_link(exe_link.as_path())
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let uid = read_proc_uid(status_path.as_path()).unwrap_or(0);

    let (exec_id, exec_id_quality) = if start_ticks != 0 {
        let ns = u128::from(start_ticks)
            .saturating_mul(1_000_000_000u128)
            .checked_div(u128::from(hz.max(1)))
            .unwrap_or(0);
        (
            exec_id_from_start_boottime_ns(u64::try_from(ns).unwrap_or(u64::MAX)),
            "linux:procfs_starttime_ticks".to_string(),
        )
    } else {
        (
            exec_id_counter
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
            "linux:fallback_counter".to_string(),
        )
    };

    ProcessInfo {
        pid,
        ppid: parent_pid,
        name,
        cmdline,
        exe_path,
        uid,
        start_time,
        is_ghost: false,
        is_mismatched: false,
        has_floating_code: false,
        exec_id,
        exec_id_quality,
    }
}

#[cfg(target_os = "linux")]
pub fn collect_process_info_for_pid(pid: u32, exec_id_counter: &AtomicU64) -> ProcessInfo {
    let hz = proc_clk_ticks_per_sec().unwrap_or(100);
    let now = unix_timestamp_now_seconds();
    let uptime_sec = read_proc_uptime_seconds().unwrap_or(0);
    collect_process_info_for_pid_with_ctx(pid, hz, now, uptime_sec, exec_id_counter)
}

#[cfg(target_os = "linux")]
pub fn collect_cgroup_pids(max_pids: usize, max_files: usize) -> Vec<u32> {
    collect_cgroup_pids_inner(None, max_pids, max_files)
}

#[cfg(target_os = "linux")]
pub fn collect_cgroup_pids_governed(
    governor: &mut Governor,
    max_pids: usize,
    max_files: usize,
) -> Vec<u32> {
    collect_cgroup_pids_inner(Some(governor), max_pids, max_files)
}

#[cfg(target_os = "linux")]
fn collect_cgroup_pids_inner(
    governor: Option<&mut Governor>,
    max_pids: usize,
    max_files: usize,
) -> Vec<u32> {
    if max_pids == 0 || max_files == 0 {
        return Vec::new();
    }

    let Some(root) = cgroup_root_path() else {
        return Vec::new();
    };

    let mut c = CgroupPidCollector::new(governor, max_pids, max_files, root);
    c.collect()
}

#[cfg(target_os = "linux")]
fn cgroup_root_path() -> Option<std::path::PathBuf> {
    let root = std::path::PathBuf::from("/sys/fs/cgroup");
    if root.exists() { Some(root) } else { None }
}

#[cfg(target_os = "linux")]
struct CgroupPidCollector<'a> {
    governor: Option<&'a mut Governor>,
    max_pids: usize,
    max_files: usize,
    files_scanned: usize,
    dirs: Vec<std::path::PathBuf>,
    out: Vec<u32>,
}

#[cfg(target_os = "linux")]
impl<'a> CgroupPidCollector<'a> {
    fn new(
        governor: Option<&'a mut Governor>,
        max_pids: usize,
        max_files: usize,
        root: std::path::PathBuf,
    ) -> Self {
        Self {
            governor,
            max_pids,
            max_files,
            files_scanned: 0,
            dirs: vec![root],
            out: Vec::new(),
        }
    }

    fn collect(&mut self) -> Vec<u32> {
        while self.step() {}
        self.out.sort_unstable();
        self.out.dedup();
        std::mem::take(&mut self.out)
    }

    fn step(&mut self) -> bool {
        let Some(dir) = self.next_dir() else {
            return false;
        };
        self.scan_dir(dir.as_path());
        true
    }

    fn next_dir(&mut self) -> Option<std::path::PathBuf> {
        if self.should_stop() {
            None
        } else {
            self.dirs.pop()
        }
    }

    fn should_stop(&self) -> bool {
        self.out.len() >= self.max_pids || self.files_scanned >= self.max_files
    }

    fn budget(&mut self, cost: u32) {
        if let Some(g) = self.governor.as_deref_mut() {
            wait_for_budget(g, cost);
        }
    }

    fn scan_dir(&mut self, dir: &std::path::Path) {
        self.budget(1);
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in rd.flatten() {
            if self.should_stop() {
                break;
            }
            self.handle_entry(entry);
        }
    }

    fn handle_entry(&mut self, entry: std::fs::DirEntry) {
        let Some(path) = self.cgroup_procs_path_from_entry(&entry) else {
            return;
        };
        self.files_scanned = self.files_scanned.saturating_add(1);
        self.budget(1);
        self.append_pids_from_file(path.as_path());
    }

    fn cgroup_procs_path_from_entry(
        &mut self,
        entry: &std::fs::DirEntry,
    ) -> Option<std::path::PathBuf> {
        let path = entry.path();
        let ft = entry.file_type().ok()?;

        if ft.is_dir() {
            self.dirs.push(path);
            return None;
        }
        if !ft.is_file() {
            return None;
        }
        let name = path.file_name()?.to_str()?;
        if name == "cgroup.procs" {
            Some(path)
        } else {
            None
        }
    }

    fn append_pids_from_file(&mut self, path: &std::path::Path) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        for line in text.lines() {
            if self.out.len() >= self.max_pids {
                break;
            }
            let Ok(pid) = line.trim().parse::<u32>() else {
                continue;
            };
            self.out.push(pid);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn collect_process_infos(limit: usize, exec_id_counter: &AtomicU64) -> Vec<ProcessInfo> {
    if limit == 0 {
        return Vec::new();
    }

    let hz = proc_clk_ticks_per_sec().unwrap_or(100);
    let now = unix_timestamp_now_seconds();
    let uptime_sec = read_proc_uptime_seconds().unwrap_or(0);

    let pids = list_proc_pids(usize::MAX);

    let mut out: Vec<ProcessInfo> = Vec::new();
    for pid in pids {
        if out.len() >= limit {
            break;
        }
        out.push(collect_process_info_for_pid_with_ctx(
            pid,
            hz,
            now,
            uptime_sec,
            exec_id_counter,
        ));
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub fn collect_process_infos(_limit: usize, _exec_id_counter: &AtomicU64) -> Vec<ProcessInfo> {
    Vec::new()
}

pub fn wait_for_budget(governor: &mut Governor, cost: u32) {
    loop {
        if governor.check_budget(cost) {
            return;
        }
        let sleep = governor.tick();
        thread::sleep(Duration::from_millis(5).saturating_add(sleep));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfRisk {
    HighRisk,
    Suspicious,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfProgramInfo {
    pub id: u32,
    pub expected_attach_type: u32,
    pub has_symbols: bool,
    pub map_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfHeuristicResult {
    pub risk: BpfRisk,
    pub reasons: Vec<String>,
}

pub fn classify_bpf_program(
    info: &BpfProgramInfo,
    high_risk_attach_types: &[u32],
) -> BpfHeuristicResult {
    let mut reasons: Vec<String> = Vec::new();
    if high_risk_attach_types.contains(&info.expected_attach_type) {
        reasons.push(format!(
            "attach_type_high_risk:{}",
            info.expected_attach_type
        ));
        return BpfHeuristicResult {
            risk: BpfRisk::HighRisk,
            reasons,
        };
    }

    if !info.has_symbols {
        reasons.push("missing_symbols".to_string());
    }
    if info.map_count == 0 {
        reasons.push("zero_maps".to_string());
    }

    let risk = if reasons.is_empty() {
        BpfRisk::Low
    } else {
        BpfRisk::Suspicious
    };
    BpfHeuristicResult { risk, reasons }
}

#[allow(clippy::missing_errors_doc)]
pub trait BpfEnumerator {
    fn get_next_id(&mut self, start: Option<u32>) -> Result<Option<u32>, AegisError>;
    fn get_prog_info(&mut self, id: u32) -> Result<BpfProgramInfo, AegisError>;
}

#[allow(clippy::missing_errors_doc)]
pub fn enumerate_bpf_programs<E: BpfEnumerator>(
    enumerator: &mut E,
    governor: &mut Governor,
    max_programs: usize,
) -> Result<Vec<BpfProgramInfo>, AegisError> {
    let mut out: Vec<BpfProgramInfo> = Vec::new();
    let mut cursor: Option<u32> = None;
    for _ in 0..max_programs {
        wait_for_budget(governor, 1);
        let next = enumerator.get_next_id(cursor)?;
        let Some(id) = next else {
            break;
        };
        wait_for_budget(governor, 1);
        out.push(enumerator.get_prog_info(id)?);
        cursor = Some(id);
    }
    Ok(out)
}

pub fn diff_hidden_u32(view_a: &[u32], view_b: &[u32]) -> Vec<u32> {
    let mut a = view_a.to_vec();
    a.sort_unstable();
    a.dedup();
    let mut b = view_b.to_vec();
    b.sort_unstable();
    b.dedup();

    let mut out: Vec<u32> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => {
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
            std::cmp::Ordering::Less => {
                i = i.saturating_add(1);
            }
            std::cmp::Ordering::Greater => {
                out.push(b[j]);
                j = j.saturating_add(1);
            }
        }
    }
    while j < b.len() {
        out.push(b[j]);
        j = j.saturating_add(1);
    }
    out
}

pub fn is_fileless_exe_target(target: &str) -> bool {
    let t = target.trim();
    let lower = t.to_ascii_lowercase();
    if lower.contains("/dev/shm") {
        return true;
    }
    if lower.contains("/memfd:") && lower.contains("deleted") {
        return true;
    }
    false
}

pub fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

pub const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub const FS_APPEND_FL: u32 = 0x0000_0020;

pub fn is_locked_flags(flags: u32) -> bool {
    flags & (FS_IMMUTABLE_FL | FS_APPEND_FL) != 0
}

pub fn is_core_pattern_suspicious(pattern: &str) -> bool {
    let p = pattern.trim();
    if !p.starts_with('|') {
        return false;
    }
    let lower = p.to_ascii_lowercase();
    let allow = ["systemd-coredump", "apport"];
    !allow.iter().any(|s| lower.contains(s))
}

pub fn diff_hidden_names(view_a: &[String], view_b: &[String]) -> Vec<String> {
    let mut a = view_a.to_vec();
    a.sort();
    a.dedup();
    let mut b = view_b.to_vec();
    b.sort();
    b.dedup();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => {
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
            std::cmp::Ordering::Less => {
                i = i.saturating_add(1);
            }
            std::cmp::Ordering::Greater => {
                out.push(b[j].clone());
                j = j.saturating_add(1);
            }
        }
    }
    while j < b.len() {
        out.push(b[j].clone());
        j = j.saturating_add(1);
    }
    out
}

#[cfg(target_os = "linux")]
pub struct SysBpfEnumerator;

#[cfg(target_os = "linux")]
impl SysBpfEnumerator {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
impl Default for SysBpfEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl BpfEnumerator for SysBpfEnumerator {
    fn get_next_id(&mut self, start: Option<u32>) -> Result<Option<u32>, AegisError> {
        let mut attr = BpfAttrProgGetNextId {
            start_id: start.unwrap_or(0),
            next_id: 0,
            open_flags: 0,
            _pad: 0,
        };
        match bpf_syscall(BPF_PROG_GET_NEXT_ID, &mut attr) {
            Ok(()) => Ok(Some(attr.next_id)),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(e) => Err(map_bpf_errno(e, "BPF_PROG_GET_NEXT_ID 失败")),
        }
    }

    fn get_prog_info(&mut self, id: u32) -> Result<BpfProgramInfo, AegisError> {
        let mut attr = BpfAttrProgGetFdById {
            prog_id: id,
            open_flags: 0,
        };
        let fd = match bpf_syscall_ret_fd(BPF_PROG_GET_FD_BY_ID, &mut attr) {
            Ok(fd) => fd,
            Err(e) => return Err(map_bpf_errno(e, "BPF_PROG_GET_FD_BY_ID 失败")),
        };

        #[allow(unsafe_code)]
        let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let mut info = BpfProgInfo::default();
        let mut info_len = u32::try_from(std::mem::size_of::<BpfProgInfo>()).unwrap_or(u32::MAX);
        let mut attr = BpfAttrObjGetInfoByFd {
            bpf_fd: std::os::fd::AsRawFd::as_raw_fd(&owned).cast_unsigned(),
            info_len,
            info: std::ptr::from_mut(&mut info) as u64,
        };
        match bpf_syscall(BPF_OBJ_GET_INFO_BY_FD, &mut attr) {
            Ok(()) => {
                info_len = attr.info_len;
                let _ = info_len;
            }
            Err(e) => return Err(map_bpf_errno(e, "BPF_OBJ_GET_INFO_BY_FD 失败")),
        }

        Ok(BpfProgramInfo {
            id,
            expected_attach_type: info.expected_attach_type,
            has_symbols: info.nr_jited_ksyms != 0,
            map_count: info.nr_map_ids,
        })
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::missing_errors_doc)]
pub fn collect_bpf_program_infos(
    governor: &mut Governor,
    max_programs: usize,
) -> Result<Vec<BpfProgramInfo>, AegisError> {
    let mut e = SysBpfEnumerator::new();
    enumerate_bpf_programs(&mut e, governor, max_programs)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::missing_errors_doc)]
pub fn collect_bpf_program_infos(
    _governor: &mut Governor,
    _max_programs: usize,
) -> Result<Vec<BpfProgramInfo>, AegisError> {
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
const BPF_PROG_GET_NEXT_ID: u32 = 11;

#[cfg(target_os = "linux")]
const BPF_PROG_GET_FD_BY_ID: u32 = 13;

#[cfg(target_os = "linux")]
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfAttrProgGetNextId {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
    _pad: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfAttrProgGetFdById {
    prog_id: u32,
    open_flags: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfAttrObjGetInfoByFd {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[cfg(target_os = "linux")]
const BPF_TAG_SIZE: usize = 8;

#[cfg(target_os = "linux")]
const BPF_OBJ_NAME_LEN: usize = 16;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct BpfProgInfo {
    prog_type: u32,
    id: u32,
    tag: [u8; BPF_TAG_SIZE],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; BPF_OBJ_NAME_LEN],
    ifindex: u32,
    gpl_compatible: u32,
    netns_dev: u64,
    netns_ino: u64,
    nr_jited_ksyms: u32,
    nr_jited_func_lens: u32,
    jited_ksyms: u64,
    jited_func_lens: u64,
    nr_func_info: u32,
    func_info_rec_size: u32,
    func_info: u64,
    nr_line_info: u32,
    line_info_rec_size: u32,
    line_info: u64,
    jited_line_info: u64,
    nr_jited_line_info: u32,
    jited_line_info_rec_size: u32,
    nr_prog_tags: u32,
    prog_tags_rec_size: u32,
    prog_tags: u64,
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
    verified_insns: u32,
    attach_type: u32,
    attach_flags: u32,
    helper_access_mask: u32,
    expected_attach_type: u32,
}

#[cfg(target_os = "linux")]
fn bpf_syscall<T>(cmd: u32, attr: &mut T) -> Result<(), std::io::Error> {
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            libc::c_long::from(cmd),
            std::ptr::from_mut(attr).cast::<libc::c_void>(),
            libc::c_long::try_from(std::mem::size_of::<T>()).unwrap_or(libc::c_long::MAX),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bpf_syscall_ret_fd<T>(cmd: u32, attr: &mut T) -> Result<i32, std::io::Error> {
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            libc::c_long::from(cmd),
            std::ptr::from_mut(attr).cast::<libc::c_void>(),
            libc::c_long::try_from(std::mem::size_of::<T>()).unwrap_or(libc::c_long::MAX),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    i32::try_from(ret).map_err(|_| std::io::Error::other("bpf() fd 返回值溢出"))
}

#[cfg(target_os = "linux")]
fn map_bpf_errno(err: std::io::Error, message: &str) -> AegisError {
    match err.raw_os_error() {
        Some(code)
            if code == libc::EPERM
                || code == libc::EACCES
                || code == libc::ENOSYS
                || code == libc::EOPNOTSUPP
                || code == libc::EINVAL =>
        {
            AegisError::ProtocolError {
                message: message.to_string(),
                code: Some(ErrorCode::Probe201),
            }
        }
        _ => AegisError::IoError(err),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BpfEnumerator, BpfProgramInfo, BpfRisk, DroppedEventCounter, classify_bpf_program,
        diff_hidden_names, diff_hidden_u32, enumerate_bpf_programs, exec_id_from_start_boottime_ns,
        is_core_pattern_suspicious, is_fileless_exe_target, is_locked_flags, sha256_32,
    };
    use crate::config::{GovernorConfig, PidConfig, TokenBucketConfig};
    use crate::error::AegisError;
    use crate::governor::Governor;
    use std::collections::VecDeque;

    #[test]
    fn dropped_event_counter_accumulates() {
        let c = DroppedEventCounter::default();
        assert_eq!(c.total(), 0);
        c.add(2);
        c.add(0);
        c.add(5);
        assert_eq!(c.total(), 7);
    }

    #[test]
    fn exec_id_is_boottime_value() {
        assert_eq!(exec_id_from_start_boottime_ns(123), 123);
    }

    #[test]
    fn rootkit_diff_returns_b_minus_a() {
        let a = vec![1u32, 2u32, 3u32];
        let b = vec![1u32, 2u32, 3u32, 9u32, 10u32];
        assert_eq!(diff_hidden_u32(a.as_slice(), b.as_slice()), vec![9, 10]);
    }

    #[test]
    fn fileless_target_checks_match_doc05() {
        assert!(is_fileless_exe_target("/memfd:abc (deleted)"));
        assert!(is_fileless_exe_target("/dev/shm/x"));
        assert!(!is_fileless_exe_target("/usr/bin/bash"));
    }

    #[test]
    fn sha256_returns_32_bytes() {
        let h1 = sha256_32(b"abc");
        let h2 = sha256_32(b"abc");
        assert_eq!(h1, h2);
    }

    #[test]
    fn immutable_or_append_marks_locked() {
        assert!(is_locked_flags(0x0000_0010));
        assert!(is_locked_flags(0x0000_0020));
        assert!(is_locked_flags(0x0000_0030));
        assert!(!is_locked_flags(0));
    }

    #[test]
    fn core_pattern_pipe_to_unknown_is_suspicious() {
        assert!(is_core_pattern_suspicious("|/tmp/x.sh"));
        assert!(!is_core_pattern_suspicious(
            "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e"
        ));
        assert!(!is_core_pattern_suspicious("core"));
    }

    #[test]
    fn module_diff_returns_sysfs_minus_proc_modules() {
        let a = vec!["x".to_string(), "y".to_string()];
        let b = vec!["x".to_string(), "y".to_string(), "rk".to_string()];
        assert_eq!(
            diff_hidden_names(a.as_slice(), b.as_slice()),
            vec!["rk".to_string()]
        );
    }

    #[test]
    fn bpf_heuristics_flags_high_risk_attach_type() {
        let info = BpfProgramInfo {
            id: 1,
            expected_attach_type: 7,
            has_symbols: true,
            map_count: 1,
        };
        let res = classify_bpf_program(&info, &[7]);
        assert_eq!(res.risk, BpfRisk::HighRisk);
        assert!(!res.reasons.is_empty());
    }

    #[test]
    fn bpf_heuristics_flags_suspicious_when_missing_symbols() {
        let info = BpfProgramInfo {
            id: 2,
            expected_attach_type: 1,
            has_symbols: false,
            map_count: 0,
        };
        let res = classify_bpf_program(&info, &[]);
        assert_eq!(res.risk, BpfRisk::Suspicious);
        assert_eq!(res.reasons.len(), 2);
    }

    #[derive(Default)]
    struct FakeBpfEnum {
        ids: VecDeque<u32>,
    }

    impl BpfEnumerator for FakeBpfEnum {
        fn get_next_id(&mut self, start: Option<u32>) -> Result<Option<u32>, AegisError> {
            if start.is_none() {
                return Ok(self.ids.front().copied());
            }
            while let Some(id) = self.ids.pop_front() {
                if Some(id) == start {
                    break;
                }
            }
            Ok(self.ids.front().copied())
        }

        fn get_prog_info(&mut self, id: u32) -> Result<BpfProgramInfo, AegisError> {
            Ok(BpfProgramInfo {
                id,
                expected_attach_type: 0,
                has_symbols: true,
                map_count: 1,
            })
        }
    }

    #[test]
    fn bpf_enumeration_obeys_max_items() -> Result<(), AegisError> {
        let mut gov = Governor::new(GovernorConfig {
            pid: PidConfig {
                k_p: 0.0,
                k_i: 0.0,
                k_d: 0.0,
            },
            token_bucket: TokenBucketConfig {
                capacity: 100,
                refill_per_sec: 100,
            },
            max_single_core_usage: 100,
            net_packet_limit_per_sec: 0,
            io_limit_mb: 0,
        });
        let _ = gov.check_budget(0);
        let mut e = FakeBpfEnum {
            ids: VecDeque::from(vec![1u32, 2u32, 3u32]),
        };
        let out = enumerate_bpf_programs(&mut e, &mut gov, 2)?;
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, 1);
        assert_eq!(out[1].id, 2);
        Ok(())
    }
}
