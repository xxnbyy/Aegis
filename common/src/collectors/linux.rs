use std::sync::atomic::{AtomicU64, Ordering};

use sha2::Digest;

use crate::error::AegisError;
#[cfg(target_os = "linux")]
use crate::error::ErrorCode;
use crate::governor::Governor;
#[cfg(target_os = "linux")]
use crate::protocol::EbpfEvent;
use crate::protocol::ProcessInfo;

#[cfg(target_os = "linux")]
pub type AegisFd = std::os::fd::OwnedFd;

#[cfg(not(target_os = "linux"))]
pub struct AegisFd;

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

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn read_ringbuf_dropped_events_best_effort(
    governor: &mut Governor,
    pin_dir: Option<&str>,
) -> u64 {
    for path in ringbuf_dropped_candidates(pin_dir) {
        let Ok(c_path) = std::ffi::CString::new(path) else {
            continue;
        };

        if !consume_budget_best_effort(governor, 1) {
            return 0;
        }
        let fd = match bpf_obj_get_fd(c_path.as_c_str()) {
            Ok(v) => v,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::ENOENT) => continue,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES) =>
            {
                return 0;
            }
            Err(_) => continue,
        };

        let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };

        let key: u32 = 0;
        let mut value: u64 = 0;
        let mut attr = BpfAttrMapElem {
            map_fd: std::os::fd::AsRawFd::as_raw_fd(&owned).cast_unsigned(),
            key: std::ptr::from_ref(&key) as u64,
            value: std::ptr::from_mut(&mut value) as u64,
            flags: 0,
        };

        if !consume_budget_best_effort(governor, 1) {
            return 0;
        }
        match bpf_syscall(BPF_MAP_LOOKUP_ELEM, &mut attr) {
            Ok(()) => return value,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES) =>
            {
                return 0;
            }
            Err(_) => continue,
        }
    }

    0
}

#[cfg(not(target_os = "linux"))]
pub fn read_ringbuf_dropped_events_best_effort(
    _governor: &mut Governor,
    _pin_dir: Option<&str>,
) -> u64 {
    0
}

#[cfg(target_os = "linux")]
const AEGIS_RINGBUF_CANDIDATES: [&str; 2] =
    ["/sys/fs/bpf/aegis_ringbuf", "/sys/fs/bpf/aegis/ringbuf"];

#[cfg(target_os = "linux")]
const AEGIS_EXEC_ID_MAP_CANDIDATES: [&str; 2] =
    ["/sys/fs/bpf/aegis_exec_id", "/sys/fs/bpf/aegis/exec_id"];

#[cfg(target_os = "linux")]
fn ringbuf_candidates(pin_dir: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = AEGIS_RINGBUF_CANDIDATES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if let Some(d) = pin_dir {
        let d = d.trim().trim_end_matches('/');
        if !d.is_empty() {
            out.push(format!("{d}/ringbuf"));
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn ringbuf_dropped_candidates(pin_dir: Option<&str>) -> Vec<String> {
    let mut out = vec![
        "/sys/fs/bpf/aegis_ringbuf_dropped_events".to_string(),
        "/sys/fs/bpf/aegis/ringbuf_dropped_events".to_string(),
    ];
    if let Some(d) = pin_dir {
        let d = d.trim().trim_end_matches('/');
        if !d.is_empty() {
            out.push(format!("{d}/ringbuf_dropped_events"));
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn exec_id_map_candidates(pin_dir: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = AEGIS_EXEC_ID_MAP_CANDIDATES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if let Some(d) = pin_dir {
        let d = d.trim().trim_end_matches('/');
        if !d.is_empty() {
            out.push(format!("{d}/exec_id"));
        }
    }
    out
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub struct EbpfProducer {
    _links: Vec<std::os::fd::OwnedFd>,
}

#[cfg(any(not(target_os = "linux"), not(target_arch = "x86_64")))]
pub struct EbpfProducer;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(clippy::missing_errors_doc)]
pub fn load_and_attach_aegis_ebpf_best_effort(
    governor: &mut Governor,
    ebpf_object_path: Option<&str>,
    ebpf_bpftool_path: Option<&str>,
    ebpf_pin_dir: Option<&str>,
) -> Result<Option<EbpfProducer>, AegisError> {
    if !consume_budget_best_effort(governor, 1) {
        return Ok(None);
    }

    let mut has_ringbuf = false;
    for path in ringbuf_candidates(ebpf_pin_dir) {
        let Ok(c_path) = std::ffi::CString::new(path.as_str()) else {
            continue;
        };
        if !consume_budget_best_effort(governor, 1) {
            return Ok(None);
        }
        match bpf_obj_get_fd(c_path.as_c_str()) {
            Ok(fd) => {
                #[allow(unsafe_code)]
                let owned =
                    unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
                drop(owned);
                has_ringbuf = true;
                break;
            }
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::ENOENT) => continue,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES) =>
            {
                return Ok(None);
            }
            Err(_) => continue,
        }
    }

    if has_ringbuf {
        return Ok(Some(EbpfProducer { _links: Vec::new() }));
    }

    let bpftool_path = ebpf_bpftool_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("bpftool");

    let object_path = ebpf_object_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| try_compile_aegis_ebpf_object_best_effort(governor, bpftool_path))
        .unwrap_or_default();

    if object_path.is_empty() {
        return Ok(None);
    }

    let pin_dir = ebpf_pin_dir
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("/sys/fs/bpf/aegis");

    if !consume_budget_best_effort(governor, 2) {
        return Ok(None);
    }

    let _ = std::fs::create_dir_all(pin_dir);
    let out = std::process::Command::new(bpftool_path)
        .args([
            "prog",
            "loadall",
            object_path.as_str(),
            pin_dir,
            "autoattach",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .or_else(|| {
            std::process::Command::new(bpftool_path)
                .args(["prog", "loadall", object_path.as_str(), pin_dir])
                .output()
                .ok()
                .filter(|o| o.status.success())
        });
    if out.is_none() {
        return Ok(None);
    }

    for path in ringbuf_candidates(Some(pin_dir)) {
        let Ok(c_path) = std::ffi::CString::new(path.as_str()) else {
            continue;
        };
        if !consume_budget_best_effort(governor, 1) {
            return Ok(None);
        }
        match bpf_obj_get_fd(c_path.as_c_str()) {
            Ok(fd) => {
                #[allow(unsafe_code)]
                let owned =
                    unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
                drop(owned);
                return Ok(Some(EbpfProducer { _links: Vec::new() }));
            }
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::ENOENT) => continue,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES) =>
            {
                return Ok(None);
            }
            Err(_) => continue,
        }
    }

    Ok(None)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AEGIS_EBPF_SOURCE: &str = r#"
#include "vmlinux.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)2;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} exec_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_dropped_events SEC(".maps");

struct aegis_event_header {
    char magic[4];
    __u8 kind;
    __u8 pad[3];
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u64 exec_id;
    __u16 comm_len;
    __u16 detail_len;
};

static __inline void inc_dropped(void) {
    __u32 k = 0;
    __u64 *v = bpf_map_lookup_elem(&ringbuf_dropped_events, &k);
    if (v) {
        __sync_fetch_and_add(v, 1);
    }
}

static __inline void emit_event(__u8 kind, __u64 exec_id_val, const char *detail, __u16 detail_len) {
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    __u16 comm_len = sizeof(comm);
    __u64 size = sizeof(struct aegis_event_header) + comm_len + detail_len;
    struct aegis_event_header *ev = bpf_ringbuf_reserve(&ringbuf, size, 0);
    if (!ev) {
        inc_dropped();
        return;
    }

    __builtin_memcpy(ev->magic, "AEB1", 4);
    ev->kind = kind;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = pid;
    ev->tgid = tgid;
    ev->exec_id = exec_id_val;
    ev->comm_len = comm_len;
    ev->detail_len = detail_len;

    char *p = (char *)(ev + 1);
    __builtin_memcpy(p, comm, comm_len);
    if (detail_len > 0 && detail) {
        __builtin_memcpy(p + comm_len, detail, detail_len);
    }
    bpf_ringbuf_submit(ev, 0);
}

SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u64 ts = bpf_ktime_get_ns();
    __u64 v = (ts << 32) | (__u64)tgid;
    if (v == 0) {
        v = 1;
    }
    bpf_map_update_elem(&exec_id, &tgid, &v, 0);
    emit_event(1, v, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 exec_id_val = 0;
    __u64 *v = bpf_map_lookup_elem(&exec_id, &tgid);
    if (v) {
        exec_id_val = *v;
    }
    const char d[] = "connect";
    emit_event(2, exec_id_val, d, sizeof(d) - 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tp_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 exec_id_val = 0;
    __u64 *v = bpf_map_lookup_elem(&exec_id, &tgid);
    if (v) {
        exec_id_val = *v;
    }
    const char d[] = "accept";
    emit_event(3, exec_id_val, d, sizeof(d) - 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
"#;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn try_compile_aegis_ebpf_object_best_effort(
    governor: &mut Governor,
    bpftool_path: &str,
) -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;

    if !consume_budget_best_effort(governor, 5) {
        return None;
    }

    let pid = std::process::id();
    let tmp_dir = std::env::temp_dir().join(format!("aegis_ebpf_{pid}"));
    let _ = std::fs::create_dir_all(tmp_dir.as_path());

    let source_path = tmp_dir.join("aegis.bpf.c");
    let vmlinux_h_path = tmp_dir.join("vmlinux.h");
    let object_path = tmp_dir.join("aegis.bpf.o");

    if object_path.exists() {
        return Some(object_path.to_string_lossy().to_string());
    }

    if std::fs::write(source_path.as_path(), AEGIS_EBPF_SOURCE.as_bytes()).is_err() {
        return None;
    }

    let vmlinux_file = std::fs::File::create(vmlinux_h_path.as_path()).ok()?;
    let out = std::process::Command::new(bpftool_path)
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .stdout(Stdio::from(vmlinux_file))
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !out.success() {
        return None;
    }

    if !consume_budget_best_effort(governor, 5) {
        return None;
    }

    let compile = std::process::Command::new("clang")
        .args(["-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-c"])
        .arg(source_path.as_os_str())
        .args(["-I"])
        .arg(tmp_dir.as_os_str())
        .args(["-o"])
        .arg(object_path.as_os_str())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    if !compile.status.success() {
        let _ = std::fs::remove_file(object_path.as_path());
        return None;
    }

    let _ = std::fs::OpenOptions::new()
        .write(true)
        .open(object_path.as_path())
        .and_then(|mut f| f.flush());

    Some(object_path.to_string_lossy().to_string())
}

#[cfg(any(not(target_os = "linux"), not(target_arch = "x86_64")))]
#[allow(clippy::missing_errors_doc)]
pub fn load_and_attach_aegis_ebpf_best_effort(
    _governor: &mut Governor,
    _ebpf_object_path: Option<&str>,
    _ebpf_bpftool_path: Option<&str>,
    _ebpf_pin_dir: Option<&str>,
) -> Result<Option<EbpfProducer>, AegisError> {
    Ok(None)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub struct RingbufReader {
    fd: std::os::fd::OwnedFd,
    mmap_ptr: *mut libc::c_void,
    mmap_len: usize,
    page_size: usize,
    data_size: usize,
    data_off: usize,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct RingbufDrainResult {
    pub events: Vec<EbpfEvent>,
    pub bytes_read: usize,
    pub records_seen: usize,
}

#[cfg(target_os = "linux")]
#[allow(clippy::missing_errors_doc)]
pub fn open_aegis_ringbuf_best_effort(
    governor: &mut Governor,
    pin_dir: Option<&str>,
) -> Result<Option<RingbufReader>, AegisError> {
    for path in ringbuf_candidates(pin_dir) {
        let Ok(c_path) = std::ffi::CString::new(path.as_str()) else {
            continue;
        };

        if !consume_budget_best_effort(governor, 1) {
            return Ok(None);
        }
        let fd = match bpf_obj_get_fd(c_path.as_c_str()) {
            Ok(v) => v,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::ENOENT) => continue,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES) =>
            {
                return Err(AegisError::ProtocolError {
                    message: "eBPF RingBuffer 无权限或被拒绝".to_string(),
                    code: Some(ErrorCode::Probe201),
                });
            }
            Err(e) => return Err(map_bpf_errno(e, "BPF_OBJ_GET ringbuf 失败")),
        };

        #[allow(unsafe_code)]
        let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };

        if !consume_budget_best_effort(governor, 1) {
            return Ok(None);
        }
        let info = match bpf_obj_get_info_by_fd_map(std::os::fd::AsRawFd::as_raw_fd(&owned)) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let page_size = page_size()?;
        let data_size = usize::try_from(info.max_entries).unwrap_or(0);
        if data_size == 0 {
            return Err(AegisError::ProtocolError {
                message: "eBPF RingBuffer max_entries 无效".to_string(),
                code: Some(ErrorCode::Probe201),
            });
        }
        if !data_size.is_power_of_two() {
            return Err(AegisError::ProtocolError {
                message: "eBPF RingBuffer max_entries 非 2 的幂".to_string(),
                code: Some(ErrorCode::Probe201),
            });
        }

        let mmap_len = data_size
            .checked_add(page_size.saturating_mul(2))
            .ok_or_else(|| AegisError::ProtocolError {
                message: "eBPF RingBuffer mmap size 溢出".to_string(),
                code: Some(ErrorCode::Probe201),
            })?;

        #[allow(unsafe_code)]
        let mmap_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                std::os::fd::AsRawFd::as_raw_fd(&owned),
                0,
            )
        };
        if mmap_ptr == libc::MAP_FAILED {
            return Err(map_bpf_errno(
                std::io::Error::last_os_error(),
                "mmap ringbuf 失败",
            ));
        }

        let mut reader = RingbufReader {
            fd: owned,
            mmap_ptr,
            mmap_len,
            page_size,
            data_size,
            data_off: page_size.saturating_mul(2),
        };
        reader.fast_forward();
        return Ok(Some(reader));
    }

    Ok(None)
}

#[cfg(target_os = "linux")]
#[allow(clippy::missing_errors_doc)]
pub fn open_aegis_exec_id_map_best_effort(
    governor: &mut Governor,
    pin_dir: Option<&str>,
) -> Result<Option<AegisFd>, AegisError> {
    for path in exec_id_map_candidates(pin_dir) {
        let Ok(c_path) = std::ffi::CString::new(path.as_str()) else {
            continue;
        };
        if !consume_budget_best_effort(governor, 1) {
            return Ok(None);
        }
        let fd = match bpf_obj_get_fd(c_path.as_c_str()) {
            Ok(v) => v,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::ENOENT) => continue,
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(map_bpf_errno(e, "BPF_OBJ_GET exec_id map 失败")),
        };

        #[allow(unsafe_code)]
        let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        return Ok(Some(owned));
    }
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::missing_errors_doc)]
pub fn open_aegis_exec_id_map_best_effort(
    _governor: &mut Governor,
    _pin_dir: Option<&str>,
) -> Result<Option<AegisFd>, AegisError> {
    Ok(None)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
#[allow(clippy::missing_errors_doc)]
pub fn lookup_aegis_exec_id_best_effort(
    governor: &mut Governor,
    map_fd: &AegisFd,
    pid: u32,
) -> Result<Option<u64>, AegisError> {
    let mut key: u32 = pid;
    let mut value: u64 = 0;
    let mut attr = BpfAttrMapElem {
        map_fd: std::os::fd::AsRawFd::as_raw_fd(map_fd).cast_unsigned(),
        key: std::ptr::from_mut(&mut key) as u64,
        value: std::ptr::from_mut(&mut value) as u64,
        flags: 0,
    };

    if !consume_budget_best_effort(governor, 1) {
        return Ok(None);
    }
    match bpf_syscall(BPF_MAP_LOOKUP_ELEM, &mut attr) {
        Ok(()) => Ok(Some(value)),
        Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::ENOENT) => Ok(None),
        Err(e) if matches!(e.raw_os_error(), Some(code) if code == libc::EPERM || code == libc::EACCES) => {
            Ok(None)
        }
        Err(e) => Err(map_bpf_errno(e, "BPF_MAP_LOOKUP_ELEM exec_id 失败")),
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::missing_errors_doc)]
pub fn lookup_aegis_exec_id_best_effort(
    _governor: &mut Governor,
    _map_fd: &AegisFd,
    _pid: u32,
) -> Result<Option<u64>, AegisError> {
    Ok(None)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
impl RingbufReader {
    pub fn drain_events_best_effort(
        &mut self,
        governor: &mut Governor,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<RingbufDrainResult, AegisError> {
        let mut out: Vec<EbpfEvent> = Vec::new();
        let mut bytes_read: usize = 0;
        let mut records_seen: usize = 0;

        if max_events == 0 || max_bytes == 0 {
            return Ok(RingbufDrainResult {
                events: out,
                bytes_read,
                records_seen,
            });
        }

        let mut consumer = self.consumer_pos();
        let producer = self.producer_pos();

        while consumer < producer {
            if out.len() >= max_events || bytes_read >= max_bytes {
                break;
            }
            if !consume_budget_best_effort(governor, 1) {
                break;
            }

            let off = (consumer as usize) & (self.data_size.saturating_sub(1));
            let available_to_end = self.data_size.saturating_sub(off);
            if available_to_end < 8 {
                consumer = consumer.saturating_add(available_to_end as u64);
                continue;
            }

            let hdr = self.read_u64_data(off);
            let len_flags = u32::try_from(hdr & 0xffff_ffffu64).unwrap_or(u32::MAX);
            let busy = (len_flags & 0x8000_0000u32) != 0;
            if busy {
                break;
            }
            let discard = (len_flags & 0x4000_0000u32) != 0;
            let payload_len = (len_flags & 0x3fff_ffffu32) as usize;
            let total_len = 8usize
                .checked_add(payload_len)
                .map(|v| (v + 7) & !7usize)
                .unwrap_or(0);
            if total_len == 0 || total_len > self.data_size {
                consumer = consumer.saturating_add(8);
                continue;
            }

            records_seen = records_seen.saturating_add(1);
            bytes_read = bytes_read.saturating_add(total_len);

            if !discard {
                let payload = self.read_payload_bytes(off.saturating_add(8), payload_len);
                if let Some(ev) = decode_ringbuf_event_payload(payload.as_slice()) {
                    out.push(ev);
                }
            }

            consumer = consumer.saturating_add(total_len as u64);
        }

        self.set_consumer_pos(consumer);
        Ok(RingbufDrainResult {
            events: out,
            bytes_read,
            records_seen,
        })
    }

    fn fast_forward(&mut self) {
        let producer = self.producer_pos();
        self.set_consumer_pos(producer);
    }

    fn consumer_pos(&self) -> u64 {
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::read_volatile(self.mmap_ptr.cast::<u64>())
        }
    }

    fn producer_pos(&self) -> u64 {
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::read_volatile(self.mmap_ptr.add(self.page_size).cast::<u64>())
        }
    }

    fn set_consumer_pos(&mut self, v: u64) {
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::write_volatile(self.mmap_ptr.cast::<u64>(), v);
        }
    }

    fn read_u64_data(&self, off: usize) -> u64 {
        let p = self
            .mmap_ptr
            .wrapping_add(self.data_off.saturating_add(off))
            .cast::<u64>();
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::read_unaligned(p)
        }
    }

    fn read_payload_bytes(&self, off: usize, len: usize) -> Vec<u8> {
        if len == 0 {
            return Vec::new();
        }
        let start = off & (self.data_size.saturating_sub(1));
        let available_to_end = self.data_size.saturating_sub(start);
        if len <= available_to_end {
            let p = self
                .mmap_ptr
                .wrapping_add(self.data_off.saturating_add(start));
            #[allow(unsafe_code)]
            unsafe {
                std::slice::from_raw_parts(p.cast::<u8>(), len).to_vec()
            }
        } else {
            let p1 = self
                .mmap_ptr
                .wrapping_add(self.data_off.saturating_add(start));
            let p2 = self.mmap_ptr.wrapping_add(self.data_off);
            let mut out = Vec::with_capacity(len);
            #[allow(unsafe_code)]
            unsafe {
                out.extend_from_slice(std::slice::from_raw_parts(
                    p1.cast::<u8>(),
                    available_to_end,
                ));
                out.extend_from_slice(std::slice::from_raw_parts(
                    p2.cast::<u8>(),
                    len.saturating_sub(available_to_end),
                ));
            }
            out
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
impl Drop for RingbufReader {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            if !self.mmap_ptr.is_null() && self.mmap_ptr != libc::MAP_FAILED {
                let _ = libc::munmap(self.mmap_ptr, self.mmap_len);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn page_size() -> Result<usize, AegisError> {
    #[allow(unsafe_code)]
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v <= 0 {
        return Err(AegisError::ProtocolError {
            message: "读取 pagesize 失败".to_string(),
            code: Some(ErrorCode::Probe201),
        });
    }
    usize::try_from(v).map_err(|_| AegisError::ProtocolError {
        message: "pagesize 溢出".to_string(),
        code: Some(ErrorCode::Probe201),
    })
}

#[cfg(target_os = "linux")]
fn decode_ringbuf_event_payload(bytes: &[u8]) -> Option<EbpfEvent> {
    if bytes.is_empty() {
        return None;
    }
    if bytes.len() >= 36 && bytes.get(0..4) == Some(b"AEB1") {
        let kind_code = *bytes.get(4)?;
        let timestamp_ns = u64::from_le_bytes(bytes.get(8..16)?.try_into().ok()?);
        let pid = u32::from_le_bytes(bytes.get(16..20)?.try_into().ok()?);
        let tgid = u32::from_le_bytes(bytes.get(20..24)?.try_into().ok()?);
        let exec_id = u64::from_le_bytes(bytes.get(24..32)?.try_into().ok()?);
        let comm_len = u16::from_le_bytes(bytes.get(32..34)?.try_into().ok()?) as usize;
        let detail_len = u16::from_le_bytes(bytes.get(34..36)?.try_into().ok()?) as usize;
        let s0 = 36usize;
        let s1 = s0.saturating_add(comm_len);
        let s2 = s1.saturating_add(detail_len);
        let comm = bytes
            .get(s0..s1)
            .map(|v| String::from_utf8_lossy(v).trim().to_string())
            .unwrap_or_default();
        let detail = bytes
            .get(s1..s2)
            .map(|v| String::from_utf8_lossy(v).trim().to_string())
            .unwrap_or_default();
        let kind = match kind_code {
            1 => "exec",
            2 => "connect",
            3 => "accept",
            _ => "event",
        }
        .to_string();
        return Some(EbpfEvent {
            timestamp_ns,
            pid,
            tgid,
            exec_id,
            kind,
            comm,
            detail,
        });
    }

    let s = String::from_utf8_lossy(bytes).trim().to_string();
    if s.is_empty() {
        return None;
    }
    Some(EbpfEvent {
        timestamp_ns: 0,
        pid: 0,
        tgid: 0,
        exec_id: 0,
        kind: "raw".to_string(),
        comm: String::new(),
        detail: s,
    })
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
            if !consume_budget_best_effort(governor, 1) {
                break;
            }
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
            if !consume_budget_best_effort(governor, 1) {
                break;
            }
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
        if !consume_budget_best_effort(governor, 1) {
            break;
        }
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
    let has_floating_code = is_fileless_exe_target(exe_path.as_str());
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
        has_floating_code,
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

    fn budget(&mut self, cost: u32) -> bool {
        let Some(g) = self.governor.as_deref_mut() else {
            return true;
        };
        if consume_budget_best_effort(g, cost) {
            true
        } else {
            self.dirs.clear();
            false
        }
    }

    fn scan_dir(&mut self, dir: &std::path::Path) {
        if !self.budget(1) {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in rd.flatten() {
            if self.should_stop() {
                break;
            }
            self.handle_entry(&entry);
        }
    }

    fn handle_entry(&mut self, entry: &std::fs::DirEntry) {
        let Some(path) = self.cgroup_procs_path_from_entry(entry) else {
            return;
        };
        self.files_scanned = self.files_scanned.saturating_add(1);
        if !self.budget(1) {
            return;
        }
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
    collect_process_infos_impl(limit, exec_id_counter, None)
}

#[cfg(not(target_os = "linux"))]
pub fn collect_process_infos(_limit: usize, _exec_id_counter: &AtomicU64) -> Vec<ProcessInfo> {
    Vec::new()
}

#[cfg(target_os = "linux")]
pub fn collect_process_infos_with_exec_id_overrides(
    limit: usize,
    exec_id_counter: &AtomicU64,
    exec_id_overrides: &std::collections::HashMap<u32, u64>,
) -> Vec<ProcessInfo> {
    collect_process_infos_impl(limit, exec_id_counter, Some(exec_id_overrides))
}

#[cfg(target_os = "linux")]
fn collect_process_infos_impl(
    limit: usize,
    exec_id_counter: &AtomicU64,
    exec_id_overrides: Option<&std::collections::HashMap<u32, u64>>,
) -> Vec<ProcessInfo> {
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
        let mut info =
            collect_process_info_for_pid_with_ctx(pid, hz, now, uptime_sec, exec_id_counter);
        if let Some(map) = exec_id_overrides
            && let Some(v) = map.get(&pid).copied()
        {
            info.exec_id = v;
            info.exec_id_quality = "linux:ebpf_exec_id_map".to_string();
        }
        out.push(info);
    }
    out
}

pub fn consume_budget_best_effort(governor: &mut Governor, cost: u32) -> bool {
    governor.check_budget(cost)
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
        if !consume_budget_best_effort(governor, 1) {
            break;
        }
        let next = enumerator.get_next_id(cursor)?;
        let Some(id) = next else {
            break;
        };
        if !consume_budget_best_effort(governor, 1) {
            break;
        }
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
pub fn read_core_pattern_best_effort(governor: &mut Governor) -> Option<String> {
    if !consume_budget_best_effort(governor, 1) {
        return None;
    }
    let bytes = std::fs::read("/proc/sys/kernel/core_pattern").ok()?;
    let head_len = bytes.len().min(4096);
    let head = bytes.get(0..head_len).unwrap_or_default();
    Some(String::from_utf8_lossy(head).trim().to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn read_core_pattern_best_effort(_governor: &mut Governor) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
pub fn list_proc_modules_best_effort(governor: &mut Governor, max_modules: usize) -> Vec<String> {
    if max_modules == 0 {
        return Vec::new();
    }
    if !consume_budget_best_effort(governor, 1) {
        return Vec::new();
    }
    let Ok(s) = std::fs::read_to_string("/proc/modules") else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for line in s.lines() {
        if out.len() >= max_modules {
            break;
        }
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        out.push(name.to_string());
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub fn list_proc_modules_best_effort(_governor: &mut Governor, _max_modules: usize) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "linux")]
pub fn list_sysfs_modules_best_effort(governor: &mut Governor, max_modules: usize) -> Vec<String> {
    if max_modules == 0 {
        return Vec::new();
    }
    if !consume_budget_best_effort(governor, 1) {
        return Vec::new();
    }
    let Ok(rd) = std::fs::read_dir("/sys/module") else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for e in rd.flatten() {
        if out.len() >= max_modules {
            break;
        }
        if !consume_budget_best_effort(governor, 1) {
            break;
        }
        let name = e.file_name().to_string_lossy().to_string();
        if name.is_empty() {
            continue;
        }
        out.push(name);
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub fn list_sysfs_modules_best_effort(
    _governor: &mut Governor,
    _max_modules: usize,
) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "linux")]
pub fn list_hidden_kernel_modules_best_effort(
    governor: &mut Governor,
    max_modules: usize,
) -> Vec<String> {
    let a = list_proc_modules_best_effort(governor, max_modules);
    let b = list_sysfs_modules_best_effort(governor, max_modules);
    diff_hidden_names(a.as_slice(), b.as_slice())
}

#[cfg(not(target_os = "linux"))]
pub fn list_hidden_kernel_modules_best_effort(
    _governor: &mut Governor,
    _max_modules: usize,
) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "linux")]
pub fn read_ftrace_enabled_functions_best_effort(
    governor: &mut Governor,
    max_lines: usize,
) -> Vec<String> {
    if max_lines == 0 {
        return Vec::new();
    }
    if !consume_budget_best_effort(governor, 1) {
        return Vec::new();
    }
    const CANDIDATES: [&str; 2] = [
        "/sys/kernel/debug/tracing/enabled_functions",
        "/sys/kernel/tracing/enabled_functions",
    ];
    let mut content: Option<String> = None;
    for path in CANDIDATES {
        if let Ok(s) = std::fs::read_to_string(path) {
            content = Some(s);
            break;
        }
    }
    let Some(s) = content else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for line in s.lines() {
        if out.len() >= max_lines {
            break;
        }
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        out.push(t.to_string());
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub fn read_ftrace_enabled_functions_best_effort(
    _governor: &mut Governor,
    _max_lines: usize,
) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn read_fs_flags_best_effort(governor: &mut Governor, path: &std::path::Path) -> Option<u32> {
    if !consume_budget_best_effort(governor, 1) {
        return None;
    }
    if !path.exists() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut flags: libc::c_long = 0;
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
    let ret = unsafe {
        libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            FS_IOC_GETFLAGS,
            std::ptr::from_mut(&mut flags),
        )
    };
    if ret != 0 {
        return None;
    }
    u32::try_from(flags).ok()
}

#[cfg(not(target_os = "linux"))]
pub fn read_fs_flags_best_effort(_governor: &mut Governor, _path: &std::path::Path) -> Option<u32> {
    None
}

#[cfg(target_os = "linux")]
pub fn read_vdso_sha256_best_effort(governor: &mut Governor, pid: u32) -> Option<[u8; 32]> {
    if !consume_budget_best_effort(governor, 1) {
        return None;
    }
    let base = std::path::PathBuf::from("/proc").join(pid.to_string());
    let maps_path = base.join("maps");
    let mem_path = base.join("mem");
    let maps = std::fs::read_to_string(maps_path.as_path()).ok()?;
    let mut start: u64 = 0;
    for line in maps.lines() {
        if !line.contains("[vdso]") {
            continue;
        }
        let range = line.split_whitespace().next()?;
        let (s, _) = range.split_once('-')?;
        start = u64::from_str_radix(s, 16).ok()?;
        break;
    }
    if start == 0 {
        return None;
    }
    if !consume_budget_best_effort(governor, 1) {
        return None;
    }
    let file = std::fs::File::open(mem_path.as_path()).ok()?;
    let mut buf = [0u8; 4096];
    use std::os::unix::fs::FileExt;
    let n = file.read_at(&mut buf, start).ok()?;
    if n == 0 {
        return None;
    }
    Some(sha256_32(buf.get(0..n).unwrap_or_default()))
}

#[cfg(not(target_os = "linux"))]
pub fn read_vdso_sha256_best_effort(_governor: &mut Governor, _pid: u32) -> Option<[u8; 32]> {
    None
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
const BPF_MAP_LOOKUP_ELEM: u32 = 1;

#[cfg(target_os = "linux")]
const BPF_OBJ_GET: u32 = 7;

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
#[repr(C)]
struct BpfAttrObjGet {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfAttrMapElem {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64,
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
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct BpfMapInfoSmall {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [u8; BPF_OBJ_NAME_LEN],
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
fn bpf_obj_get_fd(path: &std::ffi::CStr) -> Result<i32, std::io::Error> {
    let mut attr = BpfAttrObjGet {
        pathname: path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    bpf_syscall_ret_fd(BPF_OBJ_GET, &mut attr)
}

#[cfg(target_os = "linux")]
fn bpf_obj_get_info_by_fd_map(fd: i32) -> Result<BpfMapInfoSmall, AegisError> {
    let mut info = BpfMapInfoSmall::default();
    let mut info_len = u32::try_from(std::mem::size_of::<BpfMapInfoSmall>()).unwrap_or(u32::MAX);
    let mut attr = BpfAttrObjGetInfoByFd {
        bpf_fd: u32::try_from(fd).unwrap_or(u32::MAX),
        info_len,
        info: std::ptr::from_mut(&mut info) as u64,
    };
    match bpf_syscall(BPF_OBJ_GET_INFO_BY_FD, &mut attr) {
        Ok(()) => {
            info_len = attr.info_len;
            let _ = info_len;
            Ok(info)
        }
        Err(e) => Err(map_bpf_errno(e, "BPF_OBJ_GET_INFO_BY_FD(map) 失败")),
    }
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
        let gov_cfg = GovernorConfig {
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
            ..GovernorConfig::default()
        };
        let mut gov = Governor::new(&gov_cfg);
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
