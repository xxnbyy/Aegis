#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::fs::File;
use std::fs::OpenOptions;
#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::error::{AegisError, ErrorCode};
use crate::governor::Governor;
use crate::protocol::{
    FileInfo, ModuleIntegrityFinding, PeFingerprint, ProcessGhostingEvidence, ProcessInfo,
    WindowsCallStackSample, WindowsMemoryForensicsEvidence, WindowsPrivateExecRegionSample,
};
#[cfg(windows)]
use sysinfo::System;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND,
    GetLastError, INVALID_HANDLE_VALUE,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileStandardInfo,
    GetFileInformationByHandleEx,
};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, GetThreadContext, ReadProcessMemory,
};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::DeviceIoControl;
#[cfg(windows)]
use windows_sys::Win32::System::Ioctl::{FSCTL_ENUM_USN_DATA, FSCTL_QUERY_USN_JOURNAL};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, VirtualQueryEx,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME,
};
#[cfg(windows)]
use wmi::{Variant, WMIConnection};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeStaticFingerprint {
    pub time_date_stamp: u32,
    pub size_of_image: u32,
    pub number_of_sections: u16,
    pub section_names: Vec<[u8; 8]>,
}

fn pe_fingerprint_to_proto(fp: &PeStaticFingerprint) -> PeFingerprint {
    PeFingerprint {
        time_date_stamp: fp.time_date_stamp,
        size_of_image: fp.size_of_image,
        number_of_sections: u32::from(fp.number_of_sections),
        section_names: fp.section_names.iter().map(|n| n.to_vec()).collect(),
    }
}

#[cfg(windows)]
fn utf16_nul_terminated_to_string(words: &[u16]) -> String {
    let end = words.iter().position(|c| *c == 0).unwrap_or(words.len());
    String::from_utf16_lossy(&words[..end])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccessPlan {
    VssSnapshot,
    RawVolume,
    Win32Api,
}

pub fn is_registry_hive_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let upper = name.to_ascii_uppercase();
    matches!(upper.as_str(), "SYSTEM" | "SOFTWARE" | "SAM" | "NTUSER.DAT")
}

pub fn choose_file_access_plan(vss_available: bool, path: &Path) -> FileAccessPlan {
    if vss_available {
        return FileAccessPlan::VssSnapshot;
    }
    if is_registry_hive_path(path) {
        return FileAccessPlan::Win32Api;
    }
    FileAccessPlan::RawVolume
}

pub fn exec_id_from_process_sequence_number(psn: Option<u64>, fallback: &AtomicU64) -> u64 {
    if let Some(v) = psn {
        return v;
    }
    fallback.fetch_add(1, Ordering::Relaxed).saturating_add(1)
}

#[cfg(windows)]
fn exec_id_from_start_uptime_seconds(start_uptime_sec: u64, pid: u32) -> Option<u64> {
    if start_uptime_sec == 0 {
        return None;
    }
    let v = (start_uptime_sec << 32) | u64::from(pid);
    if v == 0 { None } else { Some(v) }
}

#[cfg(windows)]
fn query_process_sequence_numbers_wmi() -> Option<HashMap<u32, u64>> {
    fn as_u64(v: &Variant) -> Option<u64> {
        match v {
            Variant::UI8(x) => Some(*x),
            Variant::I8(x) => u64::try_from(*x).ok(),
            Variant::UI4(x) => Some(u64::from(*x)),
            Variant::I4(x) => u64::try_from(*x).ok(),
            Variant::UI2(x) => Some(u64::from(*x)),
            Variant::I2(x) => u64::try_from(*x).ok(),
            Variant::String(s) => s.parse::<u64>().ok(),
            _ => None,
        }
    }

    let con = WMIConnection::new().ok()?;
    let rows: Vec<HashMap<String, Variant>> = con
        .raw_query("SELECT ProcessId, ProcessSequenceNumber FROM Win32_Process")
        .ok()?;

    let mut out: HashMap<u32, u64> = HashMap::new();
    for row in rows {
        let Some(pid) = row.get("ProcessId").and_then(as_u64) else {
            continue;
        };
        let Some(psn) = row.get("ProcessSequenceNumber").and_then(as_u64) else {
            continue;
        };
        let Ok(pid_u32) = u32::try_from(pid) else {
            continue;
        };
        if psn != 0 {
            out.insert(pid_u32, psn);
        }
    }
    Some(out)
}

pub fn collect_file_infos(
    scan_whitelist: &[String],
    timestomp_threshold_ms: u64,
    vss_snapshot_drive_letter: Option<char>,
    vss_snapshot_device_path: Option<&str>,
) -> Vec<FileInfo> {
    collect_file_infos_governed(
        None,
        scan_whitelist,
        timestomp_threshold_ms,
        vss_snapshot_drive_letter,
        vss_snapshot_device_path,
    )
}

pub fn collect_file_infos_governed(
    governor: Option<&mut Governor>,
    scan_whitelist: &[String],
    timestomp_threshold_ms: u64,
    vss_snapshot_drive_letter: Option<char>,
    vss_snapshot_device_path: Option<&str>,
) -> Vec<FileInfo> {
    if scan_whitelist.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<FileInfo> = Vec::new();
    let mut governor = governor;
    for path_str in scan_whitelist {
        let path = Path::new(path_str);
        #[cfg(windows)]
        let drive = drive_letter(path);
        #[cfg(not(windows))]
        let drive: Option<char> = None;

        let vss_available_for_path = matches!((drive, vss_snapshot_drive_letter, vss_snapshot_device_path), (Some(d), Some(vss_d), Some(_)) if d.eq_ignore_ascii_case(&vss_d));
        let plan = choose_file_access_plan(vss_available_for_path, path);

        #[cfg(windows)]
        let vss_path = match (plan, vss_snapshot_drive_letter, vss_snapshot_device_path) {
            (FileAccessPlan::VssSnapshot, Some(vss_drive), Some(device_path)) => {
                vss_path_for_file(device_path, vss_drive, path)
            }
            _ => None,
        };
        #[cfg(not(windows))]
        let vss_path: Option<PathBuf> = None;

        let meta = if let Some(m) = vss_path.as_deref().and_then(|p| std::fs::metadata(p).ok()) {
            m
        } else {
            let Ok(m) = std::fs::metadata(path) else {
                continue;
            };
            m
        };

        let created_ms = meta.created().map(system_time_to_unix_ms).unwrap_or(0);
        let modified_ms = meta.modified().map(system_time_to_unix_ms).unwrap_or(0);

        let mut created_si = created_ms;
        let mut created_fn = created_ms;
        let mut ads_streams = Vec::new();

        #[cfg(windows)]
        {
            match plan {
                FileAccessPlan::VssSnapshot => {
                    if let (Some(file_path), Some(device_path)) =
                        (vss_path.as_deref(), vss_snapshot_device_path)
                        && governor.as_deref_mut().is_none_or(|g| g.check_budget(1))
                        && let Some(ev) = mft_evidence_for_path_best_effort(
                            file_path,
                            VolumeSource::DevicePath(device_path),
                        )
                    {
                        created_si = ev.si_created_ms;
                        created_fn = ev.fn_created_ms;
                        ads_streams = ev.ads_streams;
                    }
                }
                FileAccessPlan::RawVolume => {
                    if let Some(d) = drive
                        && governor.as_deref_mut().is_none_or(|g| g.check_budget(1))
                        && let Some(ev) =
                            mft_evidence_for_path_best_effort(path, VolumeSource::Drive(d))
                    {
                        created_si = ev.si_created_ms;
                        created_fn = ev.fn_created_ms;
                        ads_streams = ev.ads_streams;
                    }
                }
                FileAccessPlan::Win32Api => {}
            }
        }

        let is_locked = is_locked_by_share_violation(path);
        let is_timestomped = timestomp_detected(created_si, created_fn, timestomp_threshold_ms);

        out.push(FileInfo {
            path: path_str.clone(),
            size: meta.len(),
            created_si,
            created_fn,
            modified: modified_ms,
            is_timestomped,
            is_locked,
            ads_streams,
        });
    }

    out
}

#[cfg(windows)]
#[repr(C)]
struct UsnJournalDataV0 {
    usn_journal_id: u64,
    first_usn: i64,
    next_usn: i64,
    lowest_valid_usn: i64,
    max_usn: i64,
    maximum_size: u64,
    allocation_delta: u64,
}

#[cfg(windows)]
#[repr(C)]
struct MftEnumDataV0 {
    start_file_reference_number: u64,
    low_usn: i64,
    high_usn: i64,
}

#[cfg(windows)]
fn read_u16_le_opt(bytes: &[u8], off: usize) -> Option<u16> {
    let b = bytes.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

#[cfg(windows)]
fn read_u32_le_opt(bytes: &[u8], off: usize) -> Option<u32> {
    let b = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(windows)]
fn read_u64_le_opt(bytes: &[u8], off: usize) -> Option<u64> {
    let b = bytes.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[cfg(windows)]
fn read_i64_le_opt(bytes: &[u8], off: usize) -> Option<i64> {
    let b = bytes.get(off..off + 8)?;
    Some(i64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[cfg(windows)]
fn sanitize_tsv_field(s: &str) -> String {
    s.replace(['\t', '\r', '\n'], " ")
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn query_usn_journal_best_effort(handle: isize) -> Option<UsnJournalDataV0> {
    let mut out: UsnJournalDataV0 = unsafe { std::mem::zeroed() };
    let mut bytes_returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            std::ptr::from_mut(&mut out).cast(),
            u32::try_from(std::mem::size_of::<UsnJournalDataV0>()).unwrap_or(u32::MAX),
            std::ptr::from_mut(&mut bytes_returned),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 { None } else { Some(out) }
}

#[cfg(windows)]
fn parse_usn_record_v2_line_best_effort(record: &[u8]) -> Option<String> {
    let major = read_u16_le_opt(record, 4)?;
    if major != 2 {
        return None;
    }

    let frn = read_u64_le_opt(record, 8)?;
    let parent_frn = read_u64_le_opt(record, 16)?;
    let usn = read_i64_le_opt(record, 24)?;
    let ts_100ns = read_i64_le_opt(record, 32)?;
    let reason = read_u32_le_opt(record, 40)?;
    let source_info = read_u32_le_opt(record, 44)?;
    let security_id = read_u32_le_opt(record, 48)?;
    let file_attributes = read_u32_le_opt(record, 52)?;
    let name_len = read_u16_le_opt(record, 56)? as usize;
    let name_off = read_u16_le_opt(record, 58)? as usize;
    let name_bytes = record.get(name_off..name_off.saturating_add(name_len))?;
    if name_bytes.len() % 2 != 0 {
        return None;
    }
    let mut words: Vec<u16> = Vec::with_capacity(name_bytes.len() / 2);
    for chunk in name_bytes.chunks_exact(2) {
        words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let name = sanitize_tsv_field(String::from_utf16_lossy(words.as_slice()).as_str());

    Some(format!(
        "{frn}\t{parent_frn}\t{usn}\t{ts_100ns}\t{reason}\t{source_info}\t{security_id}\t{file_attributes}\t{name}\n"
    ))
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn collect_usn_journal_tsv_best_effort(
    governor: &mut Governor,
    drive_letter: char,
    max_records: usize,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    if max_records == 0 || max_bytes == 0 {
        return None;
    }
    if !governor.try_consume_budget(1) {
        return None;
    }

    let path = format!(r"\\.\{drive_letter}:");
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path.as_str())
        .ok()?;
    let handle = volume.as_raw_handle() as isize;
    if handle == 0 {
        return None;
    }

    let journal = query_usn_journal_best_effort(handle)?;
    let mut input = MftEnumDataV0 {
        start_file_reference_number: 0,
        low_usn: journal.first_usn.min(0),
        high_usn: journal.next_usn,
    };

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(
        b"frn\tparent_frn\tusn\ttimestamp_100ns\treason\tsource_info\tsecurity_id\tfile_attributes\tname\n",
    );

    let mut records: usize = 0;
    let mut buf: Vec<u8> = vec![0u8; 64 * 1024];

    loop {
        if records >= max_records || out.len() >= max_bytes {
            break;
        }
        if !governor.try_consume_budget(1) {
            break;
        }

        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_ENUM_USN_DATA,
                std::ptr::from_mut(&mut input).cast(),
                u32::try_from(std::mem::size_of::<MftEnumDataV0>()).unwrap_or(u32::MAX),
                buf.as_mut_ptr().cast(),
                u32::try_from(buf.len()).unwrap_or(u32::MAX),
                std::ptr::from_mut(&mut bytes_returned),
                std::ptr::null_mut(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_HANDLE_EOF {
                break;
            }
            if err == ERROR_MORE_DATA {
                continue;
            }
            break;
        }

        let got = usize::try_from(bytes_returned).unwrap_or(0);
        if got < 8 {
            break;
        }

        let next_frn = read_u64_le_opt(buf.as_slice(), 0).unwrap_or(0);
        input.start_file_reference_number = next_frn;

        let mut off = 8usize;
        while off < got {
            if records >= max_records || out.len() >= max_bytes {
                break;
            }
            let record_len = read_u32_le_opt(buf.as_slice(), off).unwrap_or(0) as usize;
            if record_len < 60 {
                break;
            }
            let end = off.saturating_add(record_len);
            let slice = buf.get(off..end).unwrap_or_default();
            if slice.len() != record_len {
                break;
            }

            if let Some(line) = parse_usn_record_v2_line_best_effort(slice) {
                let remaining = max_bytes.saturating_sub(out.len());
                let bytes = line.as_bytes();
                if bytes.len() <= remaining {
                    out.extend_from_slice(bytes);
                } else {
                    out.extend_from_slice(&bytes[..remaining]);
                }
                records = records.saturating_add(1);
            }

            if end <= off {
                break;
            }
            off = end;
        }

        if input.start_file_reference_number == 0 {
            break;
        }
    }

    Some(out)
}

#[cfg(not(windows))]
pub fn collect_usn_journal_tsv_best_effort(
    _governor: &mut Governor,
    _drive_letter: char,
    _max_records: usize,
    _max_bytes: usize,
) -> Option<Vec<u8>> {
    None
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn file_delete_pending_best_effort(file: &File) -> Option<bool> {
    let h = file.as_raw_handle() as isize;
    if h == 0 {
        return None;
    }

    let mut standard: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileStandardInfo,
            std::ptr::from_mut(&mut standard).cast(),
            u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>()).unwrap_or(u32::MAX),
        )
    };
    if ok == 0 {
        None
    } else {
        Some(standard.DeletePending != 0)
    }
}

#[cfg(windows)]
fn read_disk_fingerprint_and_delete_pending(
    exe_path: &str,
) -> Result<(Option<PeStaticFingerprint>, bool, Vec<u8>), u32> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(exe_path)
        .map_err(|e| {
            e.raw_os_error()
                .and_then(|c| u32::try_from(c).ok())
                .unwrap_or(0)
        })?;

    let delete_pending = file_delete_pending_best_effort(&file).unwrap_or(false);

    let mut bytes = vec![0u8; 0x1000];
    let read = file.read(bytes.as_mut_slice()).map_err(|e| {
        e.raw_os_error()
            .and_then(|c| u32::try_from(c).ok())
            .unwrap_or(0)
    })?;
    bytes.truncate(read);
    let fp = parse_pe_static_fingerprint(bytes.as_slice()).ok();
    Ok((fp, delete_pending, bytes))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_process_memory_fingerprint(pid: u32) -> Option<(Option<PeStaticFingerprint>, Vec<u8>)> {
    let process =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if process == 0 {
        return None;
    }

    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        unsafe {
            CloseHandle(process);
        }
        return None;
    }

    let mut me32: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    me32.dwSize = u32::try_from(std::mem::size_of::<MODULEENTRY32W>()).unwrap_or(u32::MAX);

    let ok = unsafe { Module32FirstW(snapshot, std::ptr::from_mut(&mut me32)) };
    unsafe {
        CloseHandle(snapshot);
    }
    if ok == 0 {
        unsafe {
            CloseHandle(process);
        }
        return None;
    }

    let base = me32.modBaseAddr as usize;
    if base == 0 {
        unsafe {
            CloseHandle(process);
        }
        return None;
    }

    let mut buf = vec![0u8; 0x1000];
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            base as _,
            buf.as_mut_ptr().cast(),
            buf.len(),
            std::ptr::from_mut(&mut read),
        )
    };
    unsafe {
        CloseHandle(process);
    }
    if ok == 0 {
        return Some((None, Vec::new()));
    }
    buf.truncate(read);
    let fp = parse_pe_static_fingerprint(buf.as_slice()).ok();
    Some((fp, buf))
}

#[cfg(windows)]
fn ghosting_suspected_for_process_governed(
    pid: u32,
    exe_path: &str,
    mut governor: Option<&mut Governor>,
) -> Option<bool> {
    if exe_path.is_empty() {
        return Some(false);
    }

    if governor.as_mut().is_some_and(|g| !g.try_consume_budget(1)) {
        return Some(false);
    }
    let disk = match read_disk_fingerprint_and_delete_pending(exe_path) {
        Ok(v) => v,
        Err(code) if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND => {
            return Some(true);
        }
        Err(_) => return None,
    };
    let (disk_fp, delete_pending, _) = disk;
    if governor.as_mut().is_some_and(|g| !g.try_consume_budget(1)) {
        return Some(false);
    }
    let (mem_fp, _) = read_process_memory_fingerprint(pid)?;
    if let (Some(mem), Some(disk)) = (mem_fp.as_ref(), disk_fp.as_ref()) {
        return Some(ghosting_suspected(mem, disk, delete_pending));
    }
    Some(false)
}

#[cfg(windows)]
pub fn collect_process_infos_governed(
    governor: Option<&mut Governor>,
    limit: usize,
    exec_id_counter: &AtomicU64,
) -> Vec<ProcessInfo> {
    if limit == 0 {
        return Vec::new();
    }

    let mut sys = System::new_all();
    sys.refresh_all();

    let psn_by_pid = query_process_sequence_numbers_wmi();
    let now = crate::telemetry::unix_timestamp_now();
    let mut out: Vec<ProcessInfo> = Vec::new();
    let mut governor = governor;
    for (pid, proc_) in sys.processes() {
        if out.len() >= limit {
            break;
        }

        let pid_num = pid.as_u32();
        let parent_pid_num = proc_.parent().map_or(0, sysinfo::Pid::as_u32);
        let run_time = proc_.run_time();
        let start_uptime_sec = proc_.start_time();
        let start_time = now.saturating_sub(i64::try_from(run_time).unwrap_or(i64::MAX));

        let cmdline = proc_.cmd().join(" ");
        let exe_path = proc_
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let is_ghost = ghosting_suspected_for_process_governed(
            pid_num,
            exe_path.as_str(),
            governor.as_deref_mut(),
        )
        .unwrap_or(false);

        let (exec_id, exec_id_quality) =
            if let Some(psn) = psn_by_pid.as_ref().and_then(|m| m.get(&pid_num).copied()) {
                (
                    exec_id_from_process_sequence_number(Some(psn), exec_id_counter),
                    "windows:psn".to_string(),
                )
            } else if let Some(v) = exec_id_from_start_uptime_seconds(start_uptime_sec, pid_num) {
                (v, "windows:sysinfo_start_uptime_seconds".to_string())
            } else {
                (
                    exec_id_from_process_sequence_number(None, exec_id_counter),
                    "windows:fallback_counter".to_string(),
                )
            };

        out.push(ProcessInfo {
            pid: pid_num,
            ppid: parent_pid_num,
            name: proc_.name().to_string(),
            cmdline,
            exe_path,
            uid: 0,
            start_time,
            is_ghost,
            is_mismatched: false,
            has_floating_code: false,
            exec_id,
            exec_id_quality,
        });
    }
    out
}

#[cfg(not(windows))]
pub fn collect_process_infos_governed(
    _governor: Option<&mut Governor>,
    _limit: usize,
    _exec_id_counter: &AtomicU64,
) -> Vec<ProcessInfo> {
    Vec::new()
}

#[cfg(windows)]
pub fn collect_process_infos(limit: usize, exec_id_counter: &AtomicU64) -> Vec<ProcessInfo> {
    collect_process_infos_governed(None, limit, exec_id_counter)
}

#[cfg(not(windows))]
pub fn collect_process_infos(_limit: usize, _exec_id_counter: &AtomicU64) -> Vec<ProcessInfo> {
    Vec::new()
}

pub fn timestomp_detected(si_created_ms: i64, fn_created_ms: i64, threshold_ms: u64) -> bool {
    let delta = si_created_ms.saturating_sub(fn_created_ms).abs();
    let threshold_i64 = i64::try_from(threshold_ms).unwrap_or(i64::MAX);
    delta > threshold_i64
}

pub fn ghosting_suspected(
    mem: &PeStaticFingerprint,
    disk: &PeStaticFingerprint,
    delete_pending: bool,
) -> bool {
    if delete_pending {
        return true;
    }
    if mem.time_date_stamp != disk.time_date_stamp {
        return true;
    }
    if mem.size_of_image != disk.size_of_image {
        return true;
    }
    if mem.number_of_sections != disk.number_of_sections {
        return true;
    }
    mem.section_names != disk.section_names
}

#[cfg(windows)]
pub fn collect_process_ghosting_evidence_governed(
    governor: &mut Governor,
    pid: u32,
    exe_path: &str,
) -> Option<ProcessGhostingEvidence> {
    if exe_path.is_empty() {
        return None;
    }
    if !governor.try_consume_budget(1) {
        return None;
    }

    let (disk_fp, delete_pending, disk_missing, disk_header) =
        match read_disk_fingerprint_and_delete_pending(exe_path) {
            Ok((fp, delete_pending, header)) => (fp, delete_pending, false, header),
            Err(code) if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND => {
                (None, false, true, Vec::new())
            }
            Err(_) => return None,
        };

    if !governor.try_consume_budget(1) {
        return None;
    }
    let (mem_fp, mem_header) = read_process_memory_fingerprint(pid).unwrap_or((None, Vec::new()));

    let suspected = if disk_missing {
        true
    } else if let (Some(mem), Some(disk)) = (mem_fp.as_ref(), disk_fp.as_ref()) {
        ghosting_suspected(mem, disk, delete_pending)
    } else {
        false
    };

    Some(ProcessGhostingEvidence {
        pid,
        exe_path: exe_path.to_string(),
        delete_pending,
        suspected,
        mem: mem_fp.as_ref().map(pe_fingerprint_to_proto),
        disk: disk_fp.as_ref().map(pe_fingerprint_to_proto),
        mem_header,
        disk_header,
    })
}

#[cfg(not(windows))]
pub fn collect_process_ghosting_evidence_governed(
    _governor: &mut Governor,
    _pid: u32,
    _exe_path: &str,
) -> Option<ProcessGhostingEvidence> {
    None
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn count_private_exec_regions(governor: &mut Governor, process: isize) -> u32 {
    let mut private_exec_region_count: u32 = 0;
    let mut addr: usize = 0;
    loop {
        if !governor.try_consume_budget(1) {
            break;
        }
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let queried = unsafe {
            VirtualQueryEx(
                process,
                addr as _,
                std::ptr::from_mut(&mut mbi),
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            break;
        }

        let protect = mbi.Protect;
        let exec = protect
            & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            != 0;
        let guard = protect & PAGE_GUARD != 0;
        if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && exec && !guard {
            private_exec_region_count = private_exec_region_count.saturating_add(1);
        }

        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let next = base.saturating_add(size);
        if next <= addr {
            break;
        }
        addr = next;
    }
    private_exec_region_count
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn collect_private_exec_region_samples(
    governor: &mut Governor,
    process: isize,
    max_samples: usize,
    sample_size: usize,
) -> Vec<WindowsPrivateExecRegionSample> {
    let mut samples: Vec<WindowsPrivateExecRegionSample> = Vec::new();
    if max_samples == 0 || sample_size == 0 {
        return samples;
    }

    let mut addr: usize = 0;
    loop {
        if samples.len() >= max_samples {
            break;
        }
        if !governor.try_consume_budget(1) {
            break;
        }

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let queried = unsafe {
            VirtualQueryEx(
                process,
                addr as _,
                std::ptr::from_mut(&mut mbi),
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            break;
        }

        let protect = mbi.Protect;
        let exec = protect
            & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            != 0;
        let guard = protect & PAGE_GUARD != 0;
        if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && exec && !guard {
            let base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;
            if base != 0 && region_size > 0 && governor.try_consume_budget(1) {
                let max_len = region_size.min(sample_size);
                let max_len = max_len.min(4096);
                let mut buf: Vec<u8> = vec![0u8; max_len];
                let mut read: usize = 0;
                let ok_read = unsafe {
                    ReadProcessMemory(
                        process,
                        base as _,
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        std::ptr::from_mut(&mut read),
                    )
                };
                if ok_read != 0 {
                    buf.truncate(read);
                } else {
                    buf.clear();
                }
                samples.push(WindowsPrivateExecRegionSample {
                    base_address: u64::try_from(base).unwrap_or(u64::MAX),
                    region_size: u64::try_from(region_size).unwrap_or(u64::MAX),
                    protect,
                    state: mbi.State,
                    ty: mbi.Type,
                    sample: buf,
                });
            }
        }

        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let next = base.saturating_add(size);
        if next <= addr {
            break;
        }
        addr = next;
    }

    samples
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn collect_module_integrity_findings(
    governor: &mut Governor,
    process: isize,
    pid: u32,
    max_modules: usize,
) -> Vec<ModuleIntegrityFinding> {
    let mut module_findings: Vec<ModuleIntegrityFinding> = Vec::new();
    if !governor.try_consume_budget(1) {
        return module_findings;
    }

    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        return module_findings;
    }

    let mut me32: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    me32.dwSize = u32::try_from(std::mem::size_of::<MODULEENTRY32W>()).unwrap_or(u32::MAX);
    let mut ok = unsafe { Module32FirstW(snapshot, std::ptr::from_mut(&mut me32)) };
    let mut seen: usize = 0;

    while ok != 0 {
        if seen >= max_modules {
            break;
        }
        seen = seen.saturating_add(1);
        if !governor.try_consume_budget(1) {
            break;
        }

        let module_path = utf16_nul_terminated_to_string(&me32.szExePath);
        let base_address = me32.modBaseAddr as usize;
        let module_size = me32.modBaseSize;

        let mem_fp = if base_address != 0 && governor.try_consume_budget(1) {
            let mut buf = vec![0u8; 0x1000];
            let mut read: usize = 0;
            let ok_read = unsafe {
                ReadProcessMemory(
                    process,
                    base_address as _,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    std::ptr::from_mut(&mut read),
                )
            };
            if ok_read != 0 {
                buf.truncate(read);
                parse_pe_static_fingerprint(buf.as_slice()).ok()
            } else {
                None
            }
        } else {
            None
        };

        let disk_fp = if !module_path.is_empty() && governor.try_consume_budget(1) {
            read_disk_fingerprint_and_delete_pending(module_path.as_str())
                .ok()
                .and_then(|v| v.0)
        } else {
            None
        };

        if let (Some(mem), Some(disk)) = (mem_fp.as_ref(), disk_fp.as_ref())
            && (mem.time_date_stamp != disk.time_date_stamp
                || mem.size_of_image != disk.size_of_image
                || mem.number_of_sections != disk.number_of_sections
                || mem.section_names != disk.section_names)
        {
            module_findings.push(ModuleIntegrityFinding {
                module_path: module_path.clone(),
                base_address: u64::try_from(base_address).unwrap_or(u64::MAX),
                module_size,
                finding: "pe_header_mismatch".to_string(),
                confidence: 80,
                mem_time_date_stamp: mem.time_date_stamp,
                disk_time_date_stamp: disk.time_date_stamp,
            });
        }

        ok = unsafe { Module32NextW(snapshot, std::ptr::from_mut(&mut me32)) };
    }

    unsafe {
        CloseHandle(snapshot);
    }
    module_findings
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn collect_windows_memory_forensics_evidence_governed(
    governor: &mut Governor,
    pid: u32,
    exec_id: u64,
    max_modules: usize,
) -> Option<WindowsMemoryForensicsEvidence> {
    collect_windows_memory_forensics_evidence_governed_with_params(
        governor,
        pid,
        exec_id,
        max_modules,
        5,
        128,
        4,
        24,
    )
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn collect_windows_memory_forensics_evidence_governed_with_depth(
    governor: &mut Governor,
    pid: u32,
    exec_id: u64,
    depth: crate::config::WindowsMemoryScanDepth,
) -> Option<WindowsMemoryForensicsEvidence> {
    let (max_modules, max_samples, sample_size, max_threads, max_frames) = match depth {
        crate::config::WindowsMemoryScanDepth::Fast => (32, 5, 128, 4, 24),
        crate::config::WindowsMemoryScanDepth::Full => (256, 20, 512, 16, 64),
    };
    collect_windows_memory_forensics_evidence_governed_with_params(
        governor,
        pid,
        exec_id,
        max_modules,
        max_samples,
        sample_size,
        max_threads,
        max_frames,
    )
}

#[cfg(windows)]
#[allow(unsafe_code)]
#[allow(clippy::too_many_arguments)]
fn collect_windows_memory_forensics_evidence_governed_with_params(
    governor: &mut Governor,
    pid: u32,
    exec_id: u64,
    max_modules: usize,
    max_samples: usize,
    sample_size: usize,
    max_threads: usize,
    max_frames: usize,
) -> Option<WindowsMemoryForensicsEvidence> {
    if !governor.try_consume_budget(1) {
        return None;
    }

    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if process == 0 {
        return None;
    }

    let private_exec_region_count = count_private_exec_regions(governor, process);
    let private_exec_region_samples =
        collect_private_exec_region_samples(governor, process, max_samples, sample_size);
    let mut module_findings =
        collect_module_integrity_findings(governor, process, pid, max_modules);
    module_findings.extend(collect_etw_amsi_patch_findings_best_effort(
        governor,
        process,
        pid,
        max_modules,
    ));
    let call_stack_samples = collect_process_call_stack_samples_best_effort(
        governor,
        process,
        pid,
        max_threads,
        max_frames,
    );

    unsafe {
        CloseHandle(process);
    }

    Some(WindowsMemoryForensicsEvidence {
        pid,
        exec_id,
        collected_at: crate::telemetry::unix_timestamp_now(),
        private_exec_region_count,
        module_findings,
        private_exec_region_samples,
        call_stack_samples,
    })
}

#[cfg(not(windows))]
pub fn collect_windows_memory_forensics_evidence_governed(
    _governor: &mut Governor,
    _pid: u32,
    _exec_id: u64,
    _max_modules: usize,
) -> Option<WindowsMemoryForensicsEvidence> {
    None
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn collect_process_call_stack_samples_best_effort(
    governor: &mut Governor,
    process: isize,
    pid: u32,
    max_threads: usize,
    max_frames: usize,
) -> Vec<WindowsCallStackSample> {
    let mut out: Vec<WindowsCallStackSample> = Vec::new();
    if max_threads == 0 || max_frames == 0 {
        return out;
    }
    if !governor.try_consume_budget(1) {
        return out;
    }

    let ok = unsafe { sym_initialize_best_effort(process) };
    if !ok {
        return out;
    }

    let tids = list_process_threads_best_effort(governor, pid, max_threads);
    for tid in tids {
        if !governor.try_consume_budget(1) {
            break;
        }
        if let Some(sample) =
            collect_thread_call_stack_best_effort(governor, process, tid, max_frames)
        {
            out.push(sample);
        }
    }

    unsafe {
        sym_cleanup_best_effort(process);
    }
    out
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn list_process_threads_best_effort(governor: &mut Governor, pid: u32, limit: usize) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    if limit == 0 {
        return out;
    }
    if !governor.try_consume_budget(1) {
        return out;
    }

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return out;
    }

    let mut te32 = THREADENTRY32 {
        dwSize: u32::try_from(std::mem::size_of::<THREADENTRY32>()).unwrap_or(u32::MAX),
        ..unsafe { std::mem::zeroed() }
    };
    let mut ok = unsafe { Thread32First(snapshot, std::ptr::from_mut(&mut te32)) };
    while ok != 0 {
        if out.len() >= limit {
            break;
        }
        if te32.th32OwnerProcessID == pid {
            out.push(te32.th32ThreadID);
        }
        ok = unsafe { Thread32Next(snapshot, std::ptr::from_mut(&mut te32)) };
    }

    unsafe {
        CloseHandle(snapshot);
    }
    out
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn collect_thread_call_stack_best_effort(
    governor: &mut Governor,
    process: isize,
    tid: u32,
    max_frames: usize,
) -> Option<WindowsCallStackSample> {
    if max_frames == 0 {
        return None;
    }
    let thread = unsafe {
        OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            0,
            tid,
        )
    };
    if thread == 0 {
        return None;
    }

    let mut suspended = false;
    let suspend_rc = unsafe { SuspendThread(thread) };
    if suspend_rc != u32::MAX {
        suspended = true;
    }

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = windows_context_control_flags();
    let ctx_ok = unsafe { GetThreadContext(thread, std::ptr::from_mut(&mut ctx)) };
    if ctx_ok == 0 {
        if suspended {
            unsafe {
                ResumeThread(thread);
            }
        }
        unsafe {
            CloseHandle(thread);
        }
        return None;
    }

    let mut out: Vec<u64> = Vec::new();
    let (rip, rsp) = thread_rip_rsp(&ctx);
    if rip != 0 {
        out.push(rip);
    }

    if out.len() < max_frames {
        let frames = stackwalk_collect_best_effort(governor, process, thread, &mut ctx, max_frames);
        for a in frames {
            if out.len() >= max_frames {
                break;
            }
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }

    if suspended {
        unsafe {
            ResumeThread(thread);
        }
    }
    unsafe {
        CloseHandle(thread);
    }

    Some(WindowsCallStackSample {
        tid,
        rip,
        rsp,
        return_addresses: out,
    })
}

#[cfg(windows)]
fn windows_context_control_flags() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        0x0010_0001
    }
    #[cfg(target_arch = "x86")]
    {
        0x0001_0001
    }
    #[cfg(target_arch = "aarch64")]
    {
        0x0040_0001
    }
    #[cfg(all(
        not(target_arch = "x86_64"),
        not(target_arch = "x86"),
        not(target_arch = "aarch64")
    ))]
    {
        0
    }
}

#[cfg(windows)]
fn thread_rip_rsp(ctx: &CONTEXT) -> (u64, u64) {
    #[cfg(target_arch = "x86_64")]
    {
        (ctx.Rip, ctx.Rsp)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        (0, 0)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn stackwalk_collect_best_effort(
    governor: &mut Governor,
    process: isize,
    thread: isize,
    ctx: &mut CONTEXT,
    max_frames: usize,
) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    if max_frames == 0 {
        return out;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (governor, process, thread, ctx);
        return out;
    }
    #[cfg(target_arch = "x86_64")]
    {
        const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;
        const ADDR_MODE_FLAT: i32 = 3;

        let mut frame: windows_sys::Win32::System::Diagnostics::Debug::STACKFRAME64 =
            unsafe { std::mem::zeroed() };
        frame.AddrPC.Offset = ctx.Rip;
        frame.AddrPC.Mode = ADDR_MODE_FLAT;
        frame.AddrFrame.Offset = ctx.Rbp;
        frame.AddrFrame.Mode = ADDR_MODE_FLAT;
        frame.AddrStack.Offset = ctx.Rsp;
        frame.AddrStack.Mode = ADDR_MODE_FLAT;

        for _ in 0..max_frames {
            if !governor.try_consume_budget(1) {
                break;
            }
            let ok = unsafe {
                let ctx_ptr = std::ptr::from_mut(ctx).cast();
                windows_sys::Win32::System::Diagnostics::Debug::StackWalk64(
                    IMAGE_FILE_MACHINE_AMD64,
                    process,
                    thread,
                    std::ptr::from_mut(&mut frame),
                    ctx_ptr,
                    None,
                    Some(windows_sys::Win32::System::Diagnostics::Debug::SymFunctionTableAccess64),
                    Some(windows_sys::Win32::System::Diagnostics::Debug::SymGetModuleBase64),
                    None,
                )
            };
            if ok == 0 {
                break;
            }
            let pc = frame.AddrPC.Offset;
            if pc == 0 {
                break;
            }
            out.push(pc);
        }
        out
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
unsafe fn sym_initialize_best_effort(process: isize) -> bool {
    unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::SymInitialize(process, std::ptr::null(), 1)
            != 0
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
unsafe fn sym_cleanup_best_effort(process: isize) {
    unsafe {
        let _ = windows_sys::Win32::System::Diagnostics::Debug::SymCleanup(process);
    }
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct ModuleEntry {
    name_lower: String,
    path: String,
    base_address: u64,
    size: u32,
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn collect_process_module_entries_best_effort(
    governor: &mut Governor,
    pid: u32,
    max_modules: usize,
) -> Vec<ModuleEntry> {
    let mut out: Vec<ModuleEntry> = Vec::new();
    if max_modules == 0 {
        return out;
    }
    if !governor.try_consume_budget(1) {
        return out;
    }

    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        return out;
    }

    let mut me32 = MODULEENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<MODULEENTRY32W>()).unwrap_or(u32::MAX),
        ..unsafe { std::mem::zeroed() }
    };
    let mut ok = unsafe { Module32FirstW(snapshot, std::ptr::from_mut(&mut me32)) };
    while ok != 0 {
        if out.len() >= max_modules {
            break;
        }
        let name = utf16_nul_terminated_to_string(me32.szModule.as_slice());
        let path = utf16_nul_terminated_to_string(me32.szExePath.as_slice());
        out.push(ModuleEntry {
            name_lower: name.to_ascii_lowercase(),
            path,
            base_address: me32.modBaseAddr as usize as u64,
            size: me32.modBaseSize,
        });
        ok = unsafe { Module32NextW(snapshot, std::ptr::from_mut(&mut me32)) };
    }

    unsafe {
        CloseHandle(snapshot);
    }
    out
}

#[cfg(windows)]
fn resolve_export_rva_from_disk_best_effort(module_path: &str, func_name: &str) -> Option<u32> {
    let meta = std::fs::metadata(module_path).ok()?;
    let len = usize::try_from(meta.len()).ok()?;
    if len == 0 || len > 16 * 1024 * 1024 {
        return None;
    }
    let bytes = std::fs::read(module_path).ok()?;
    resolve_export_rva_from_pe_best_effort(bytes.as_slice(), func_name)
}

#[cfg(windows)]
fn resolve_export_rva_from_pe_best_effort(pe: &[u8], func_name: &str) -> Option<u32> {
    let pe_off = read_u32_le(pe, 0x3c).ok()? as usize;
    let sig = pe.get(pe_off..pe_off + 4)?;
    if sig != b"PE\0\0" {
        return None;
    }
    let coff_off = pe_off + 4;
    let section_count = read_u16_le(pe, coff_off + 2).ok()? as usize;
    let size_of_optional_header = read_u16_le(pe, coff_off + 16).ok()? as usize;
    let opt_off = coff_off + 20;
    let opt = pe.get(opt_off..opt_off + size_of_optional_header)?;
    if opt.len() < 2 {
        return None;
    }
    let magic = u16::from_le_bytes([opt[0], opt[1]]);
    let data_dir_off = match magic {
        0x20b => 0x70usize,
        0x10b => 0x60usize,
        _ => return None,
    };
    if opt.len() < data_dir_off + 8 {
        return None;
    }
    let export_rva = u32::from_le_bytes(opt[data_dir_off..data_dir_off + 4].try_into().ok()?);
    let export_size = u32::from_le_bytes(opt[data_dir_off + 4..data_dir_off + 8].try_into().ok()?);
    if export_rva == 0 || export_size == 0 {
        return None;
    }

    let sections_off = opt_off + size_of_optional_header;
    let section_table_len = section_count.saturating_mul(40);
    let section_table = pe.get(sections_off..sections_off + section_table_len)?;

    let export_off = rva_to_file_offset_best_effort(section_table, export_rva)?;
    let export_dir = pe.get(export_off..export_off + 40)?;

    let number_of_functions = u32::from_le_bytes(export_dir[20..24].try_into().ok()?);
    let number_of_names = u32::from_le_bytes(export_dir[24..28].try_into().ok()?);
    let address_of_functions = u32::from_le_bytes(export_dir[28..32].try_into().ok()?);
    let address_of_names = u32::from_le_bytes(export_dir[32..36].try_into().ok()?);
    let address_of_name_ordinals = u32::from_le_bytes(export_dir[36..40].try_into().ok()?);
    if number_of_functions == 0 || number_of_names == 0 {
        return None;
    }

    let names_off = rva_to_file_offset_best_effort(section_table, address_of_names)?;
    let ords_off = rva_to_file_offset_best_effort(section_table, address_of_name_ordinals)?;
    let funcs_off = rva_to_file_offset_best_effort(section_table, address_of_functions)?;

    let target = func_name.as_bytes();
    for i in 0..number_of_names {
        let idx = usize::try_from(i).ok()?;
        let name_rva_off = names_off.saturating_add(idx.saturating_mul(4));
        let name_rva_bytes = pe.get(name_rva_off..name_rva_off + 4)?;
        let name_rva = u32::from_le_bytes(name_rva_bytes.try_into().ok()?);
        let export_name_off = rva_to_file_offset_best_effort(section_table, name_rva)?;
        let name = read_c_string_best_effort(pe, export_name_off)?;
        if name.as_bytes() != target {
            continue;
        }
        let ordinal_off = ords_off.saturating_add(idx.saturating_mul(2));
        let ord_bytes = pe.get(ordinal_off..ordinal_off + 2)?;
        let ordinal = u32::from(u16::from_le_bytes(ord_bytes.try_into().ok()?));
        if ordinal >= number_of_functions {
            return None;
        }
        let func_rva_off =
            funcs_off.saturating_add(usize::try_from(ordinal).ok()?.saturating_mul(4));
        let func_rva_bytes = pe.get(func_rva_off..func_rva_off + 4)?;
        let func_rva = u32::from_le_bytes(func_rva_bytes.try_into().ok()?);
        if func_rva >= export_rva && func_rva < export_rva.saturating_add(export_size) {
            return None;
        }
        return Some(func_rva);
    }
    None
}

#[cfg(windows)]
fn rva_to_file_offset_best_effort(section_table: &[u8], rva: u32) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut best_end: u32 = 0;
    for i in 0..(section_table.len() / 40) {
        let base = i.saturating_mul(40);
        let sec = section_table.get(base..base + 40)?;
        let virtual_size = u32::from_le_bytes(sec[8..12].try_into().ok()?);
        let virtual_address = u32::from_le_bytes(sec[12..16].try_into().ok()?);
        let size_of_raw_data = u32::from_le_bytes(sec[16..20].try_into().ok()?);
        let pointer_to_raw_data = u32::from_le_bytes(sec[20..24].try_into().ok()?);
        let span = u32::max(virtual_size, size_of_raw_data);
        if span == 0 {
            continue;
        }
        let end = virtual_address.saturating_add(span);
        if rva >= virtual_address && rva < end && (best.is_none() || end > best_end) {
            let off = pointer_to_raw_data.saturating_add(rva.saturating_sub(virtual_address));
            best = Some(usize::try_from(off).ok()?);
            best_end = end;
        }
    }
    best
}

#[cfg(windows)]
fn read_c_string_best_effort(bytes: &[u8], start: usize) -> Option<String> {
    let mut end = start;
    while end < bytes.len() {
        if bytes[end] == 0 {
            break;
        }
        end = end.saturating_add(1);
        if end.saturating_sub(start) > 512 {
            return None;
        }
    }
    let slice = bytes.get(start..end)?;
    Some(String::from_utf8_lossy(slice).to_string())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_remote_bytes_best_effort(
    governor: &mut Governor,
    process: isize,
    address: u64,
    len: usize,
) -> Option<Vec<u8>> {
    if len == 0 || len > 256 {
        return None;
    }
    if !governor.try_consume_budget(1) {
        return None;
    }
    let mut buf: Vec<u8> = vec![0u8; len];
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address as _,
            buf.as_mut_ptr().cast(),
            buf.len(),
            std::ptr::from_mut(&mut read),
        )
    };
    if ok == 0 || read == 0 {
        return None;
    }
    buf.truncate(read);
    Some(buf)
}

#[cfg(windows)]
fn detect_patch_kind_best_effort(code: &[u8]) -> Option<&'static str> {
    let b0 = *code.first().unwrap_or(&0);
    if b0 == 0xC3 {
        return Some("ret");
    }
    if b0 == 0xE9 || b0 == 0xEB {
        return Some("jmp");
    }
    if code.len() >= 3 && code[0] == 0x33 && code[1] == 0xC0 && code[2] == 0xC3 {
        return Some("xor_eax_eax_ret");
    }
    if code.len() >= 4 && code[0] == 0x48 && code[1] == 0x31 && code[2] == 0xC0 && code[3] == 0xC3 {
        return Some("xor_rax_rax_ret");
    }
    if code.len() >= 6 && code[0] == 0xB8 && code[5] == 0xC3 {
        return Some("mov_eax_imm_ret");
    }
    None
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn collect_etw_amsi_patch_findings_best_effort(
    governor: &mut Governor,
    process: isize,
    pid: u32,
    max_modules: usize,
) -> Vec<ModuleIntegrityFinding> {
    let mut out: Vec<ModuleIntegrityFinding> = Vec::new();
    if !governor.try_consume_budget(1) {
        return out;
    }

    let modules = collect_process_module_entries_best_effort(governor, pid, max_modules);
    let mut ntdll: Option<ModuleEntry> = None;
    let mut amsi: Option<ModuleEntry> = None;
    for m in modules {
        if m.name_lower == "ntdll.dll" {
            ntdll = Some(m);
        } else if m.name_lower == "amsi.dll" {
            amsi = Some(m);
        }
    }

    let targets: Vec<(ModuleEntry, &'static str)> = [
        ntdll.map(|m| (m, "EtwEventWrite")),
        amsi.map(|m| (m, "AmsiScanBuffer")),
    ]
    .into_iter()
    .flatten()
    .collect();

    for (m, func) in targets {
        if !governor.try_consume_budget(1) {
            break;
        }
        let rva = resolve_export_rva_from_disk_best_effort(m.path.as_str(), func);
        let Some(rva) = rva else {
            continue;
        };
        let addr = m.base_address.saturating_add(u64::from(rva));
        let Some(code) = read_remote_bytes_best_effort(governor, process, addr, 16) else {
            continue;
        };
        let Some(kind) = detect_patch_kind_best_effort(code.as_slice()) else {
            continue;
        };
        out.push(ModuleIntegrityFinding {
            module_path: format!("{}!{func}", m.name_lower),
            base_address: addr,
            module_size: m.size,
            finding: format!("patch_suspected:{kind}"),
            confidence: 90,
            mem_time_date_stamp: 0,
            disk_time_date_stamp: 0,
        });
    }

    out
}

#[allow(clippy::missing_errors_doc)]
pub fn parse_pe_static_fingerprint(bytes: &[u8]) -> Result<PeStaticFingerprint, AegisError> {
    if bytes.len() < 0x100 {
        return Err(AegisError::ProtocolError {
            message: "PE 数据太短".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    if bytes.get(0..2) != Some(b"MZ") {
        return Err(AegisError::ProtocolError {
            message: "缺少 MZ header".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let pe_off = read_u32_le(bytes, 0x3c)? as usize;
    let pe_sig = bytes
        .get(pe_off..pe_off + 4)
        .ok_or(AegisError::ProtocolError {
            message: "PE header 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        })?;
    if pe_sig != b"PE\0\0" {
        return Err(AegisError::ProtocolError {
            message: "缺少 PE signature".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let coff_off = pe_off + 4;
    let number_of_sections = read_u16_le(bytes, coff_off + 2)?;
    let time_date_stamp = read_u32_le(bytes, coff_off + 4)?;
    let size_of_optional_header = read_u16_le(bytes, coff_off + 16)? as usize;

    let opt_off = coff_off + 20;
    let opt = bytes
        .get(opt_off..opt_off + size_of_optional_header)
        .ok_or(AegisError::ProtocolError {
            message: "Optional header 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        })?;
    if opt.len() < 0x3c {
        return Err(AegisError::ProtocolError {
            message: "Optional header 太短".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let size_of_image = read_u32_le(opt, 0x38)?;

    let sections_off = opt_off + size_of_optional_header;
    let section_table_len = usize::from(number_of_sections).saturating_mul(40);
    let section_table = bytes
        .get(sections_off..sections_off + section_table_len)
        .ok_or(AegisError::ProtocolError {
            message: "Section table 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        })?;
    let mut section_names: Vec<[u8; 8]> = Vec::with_capacity(number_of_sections.into());
    for i in 0..usize::from(number_of_sections) {
        let base = i.saturating_mul(40);
        let mut name = [0u8; 8];
        let src = section_table
            .get(base..base + 8)
            .ok_or(AegisError::ProtocolError {
                message: "Section header 越界".to_string(),
                code: Some(ErrorCode::Probe101),
            })?;
        name.copy_from_slice(src);
        section_names.push(name);
    }

    Ok(PeStaticFingerprint {
        time_date_stamp,
        size_of_image,
        number_of_sections,
        section_names,
    })
}

fn read_u16_le(bytes: &[u8], off: usize) -> Result<u16, AegisError> {
    let b = bytes.get(off..off + 2).ok_or(AegisError::ProtocolError {
        message: "读取 u16 越界".to_string(),
        code: Some(ErrorCode::Probe101),
    })?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32, AegisError> {
    let b = bytes.get(off..off + 4).ok_or(AegisError::ProtocolError {
        message: "读取 u32 越界".to_string(),
        code: Some(ErrorCode::Probe101),
    })?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VssAsyncState {
    Pending,
    FinishedOk,
    Failed,
}

#[allow(clippy::missing_errors_doc)]
pub fn wait_vss_async_with_timeout<F, S>(
    timeout: Duration,
    mut query_status: F,
    mut sleep: S,
) -> Result<(), AegisError>
where
    F: FnMut() -> Result<VssAsyncState, AegisError>,
    S: FnMut(Duration),
{
    let started = Instant::now();
    loop {
        if started.elapsed() > timeout {
            return Err(AegisError::ProtocolError {
                message: "VSS DoSnapshotSet 超时".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }

        match query_status()? {
            VssAsyncState::Pending => {
                sleep(Duration::from_millis(5));
            }
            VssAsyncState::FinishedOk => return Ok(()),
            VssAsyncState::Failed => {
                return Err(AegisError::ProtocolError {
                    message: "VSS DoSnapshotSet 失败".to_string(),
                    code: Some(ErrorCode::Probe101),
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsBootSectorInfo {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub cluster_size: u32,
    pub mft_lcn: u64,
    pub clusters_per_mft_record: i8,
    pub mft_record_size: u32,
}

#[allow(clippy::missing_errors_doc)]
pub fn parse_ntfs_boot_sector(boot_sector: &[u8]) -> Result<NtfsBootSectorInfo, AegisError> {
    if boot_sector.len() < 90 {
        return Err(AegisError::ProtocolError {
            message: "NTFS boot sector 太短".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let bytes_per_sector = read_u16_le(boot_sector, 11)?;
    let sectors_per_cluster = *boot_sector.get(13).ok_or(AegisError::ProtocolError {
        message: "读取 sectors_per_cluster 越界".to_string(),
        code: Some(ErrorCode::Probe101),
    })?;
    if bytes_per_sector == 0 || sectors_per_cluster == 0 {
        return Err(AegisError::ProtocolError {
            message: "NTFS BPB 字段非法".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let cluster_size = u32::from(bytes_per_sector).saturating_mul(u32::from(sectors_per_cluster));
    let mft_lcn =
        u64::from(read_u32_le(boot_sector, 48)?) | (u64::from(read_u32_le(boot_sector, 52)?) << 32);
    let clusters_per_mft_record = i8::from_le_bytes(
        boot_sector
            .get(64..65)
            .ok_or(AegisError::ProtocolError {
                message: "读取 clusters_per_mft_record 越界".to_string(),
                code: Some(ErrorCode::Probe101),
            })?
            .try_into()
            .map_err(|_| AegisError::ProtocolError {
                message: "clusters_per_mft_record 读取失败".to_string(),
                code: Some(ErrorCode::Probe101),
            })?,
    );
    let mft_record_size = ntfs_mft_record_size(cluster_size, clusters_per_mft_record);

    Ok(NtfsBootSectorInfo {
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size,
        mft_lcn,
        clusters_per_mft_record,
        mft_record_size,
    })
}

pub fn ntfs_mft_record_size(cluster_size: u32, clusters_per_record: i8) -> u32 {
    if clusters_per_record > 0 {
        cluster_size.saturating_mul(u32::from(clusters_per_record.unsigned_abs()))
    } else {
        let exp = u32::from((clusters_per_record.unsigned_abs()).min(31));
        1u32.checked_shl(exp).unwrap_or(u32::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftFileRecordEvidence {
    pub si_created_ms: i64,
    pub fn_created_ms: i64,
    pub ads_streams: Vec<String>,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NtfsRun {
    vcn_start: u64,
    lcn_start: u64,
    cluster_len: u64,
}

#[cfg(windows)]
fn decode_ntfs_runlist(bytes: &[u8]) -> Result<Vec<NtfsRun>, AegisError> {
    let mut runs: Vec<NtfsRun> = Vec::new();
    let mut cursor = 0usize;
    let mut lcn_acc: i64 = 0;
    let mut vcn_acc: u64 = 0;

    while cursor < bytes.len() {
        let Some(run) = decode_ntfs_run(bytes, &mut cursor, &mut lcn_acc, &mut vcn_acc)? else {
            break;
        };
        runs.push(run);
    }

    if runs.is_empty() {
        return Err(ntfs_proto_err("NTFS runlist 为空"));
    }

    Ok(runs)
}

#[cfg(windows)]
fn ntfs_proto_err(message: &str) -> AegisError {
    AegisError::ProtocolError {
        message: message.to_string(),
        code: Some(ErrorCode::Probe101),
    }
}

#[cfg(windows)]
fn decode_ntfs_run(
    bytes: &[u8],
    cursor: &mut usize,
    lcn_acc: &mut i64,
    vcn_acc: &mut u64,
) -> Result<Option<NtfsRun>, AegisError> {
    let header = *bytes.get(*cursor).unwrap_or(&0);
    *cursor = cursor.saturating_add(1);
    if header == 0 {
        return Ok(None);
    }

    let (len_size, off_size) = ntfs_run_header_sizes(header)?;
    if cursor.saturating_add(len_size).saturating_add(off_size) > bytes.len() {
        return Err(ntfs_proto_err("NTFS runlist 越界"));
    }

    let len = ntfs_read_u64_le_sized(bytes, *cursor, len_size)?;
    *cursor = cursor.saturating_add(len_size);
    if len == 0 {
        return Err(ntfs_proto_err("NTFS runlist cluster_len 为 0"));
    }

    let delta = ntfs_read_i64_le_sized(bytes, *cursor, off_size)?;
    *cursor = cursor.saturating_add(off_size);

    *lcn_acc = lcn_acc.saturating_add(delta);
    if *lcn_acc < 0 {
        return Err(ntfs_proto_err("NTFS runlist LCN 变为负数"));
    }

    let run = NtfsRun {
        vcn_start: *vcn_acc,
        lcn_start: u64::try_from(*lcn_acc).unwrap_or(0),
        cluster_len: len,
    };
    *vcn_acc = vcn_acc.saturating_add(len);
    Ok(Some(run))
}

#[cfg(windows)]
fn ntfs_run_header_sizes(header: u8) -> Result<(usize, usize), AegisError> {
    let len_size = usize::from(header & 0x0F);
    let off_size = usize::from((header >> 4) & 0x0F);
    if len_size == 0 {
        return Err(ntfs_proto_err("NTFS runlist 长度字段为空"));
    }
    if off_size == 0 {
        return Err(ntfs_proto_err("NTFS runlist sparse run 不支持"));
    }
    Ok((len_size, off_size))
}

#[cfg(windows)]
fn ntfs_read_u64_le_sized(bytes: &[u8], off: usize, len: usize) -> Result<u64, AegisError> {
    let slice = bytes
        .get(off..off.saturating_add(len))
        .ok_or(ntfs_proto_err("NTFS runlist 越界"))?;
    let mut out: u64 = 0;
    for (k, b) in slice.iter().copied().enumerate() {
        out |= u64::from(b) << (k.saturating_mul(8));
    }
    Ok(out)
}

#[cfg(windows)]
fn ntfs_read_i64_le_sized(bytes: &[u8], off: usize, len: usize) -> Result<i64, AegisError> {
    let slice = bytes
        .get(off..off.saturating_add(len))
        .ok_or(ntfs_proto_err("NTFS runlist 越界"))?;
    let mut out: i64 = 0;
    for (k, b) in slice.iter().copied().enumerate() {
        out |= i64::from(b) << (k.saturating_mul(8));
    }
    let sign_bit = 1i64 << ((len.saturating_mul(8)).saturating_sub(1));
    if (out & sign_bit) != 0 {
        let mask = (!0i64) << (len.saturating_mul(8));
        out |= mask;
    }
    Ok(out)
}

#[cfg(windows)]
fn find_run_for_vcn(runs: &[NtfsRun], vcn: u64) -> Option<(NtfsRun, u64)> {
    for r in runs {
        let end = r.vcn_start.saturating_add(r.cluster_len);
        if vcn >= r.vcn_start && vcn < end {
            return Some((*r, end.saturating_sub(vcn)));
        }
    }
    None
}

#[cfg(windows)]
fn parse_mft_runs_from_mft_record_zero(record: &[u8]) -> Result<Vec<NtfsRun>, AegisError> {
    let attr_off = parse_mft_attr_start_off(record, "MFT record#0")?;

    let mut off = attr_off;
    while off + 4 <= record.len() {
        let (attr_type, total_len) = parse_mft_attr_header(record, off)?;
        if attr_type == 0xFFFF_FFFF {
            break;
        }

        if let Some(runlist) = mft_data_runlist_if_present(record, off, total_len)? {
            return decode_ntfs_runlist(runlist);
        }

        off = off.saturating_add(total_len);
    }

    Err(AegisError::ProtocolError {
        message: "MFT record#0 缺少 $MFT $DATA runlist".to_string(),
        code: Some(ErrorCode::Probe101),
    })
}

#[allow(clippy::missing_errors_doc)]
#[allow(clippy::too_many_lines)]
pub fn parse_mft_file_record(record: &[u8]) -> Result<MftFileRecordEvidence, AegisError> {
    let attr_off = parse_mft_attr_start_off(record, "MFT record")?;
    let mut state = MftRecordParseState::new();

    let mut off = attr_off;
    while off + 4 <= record.len() {
        let (attr_type, total_len) = parse_mft_attr_header(record, off)?;
        if attr_type == 0xFFFF_FFFF {
            break;
        }
        parse_mft_record_attribute(record, off, total_len, attr_type, &mut state)?;

        off = off.saturating_add(total_len);
    }
    state.into_evidence()
}

fn parse_mft_attr_start_off(record: &[u8], label: &str) -> Result<usize, AegisError> {
    if record.len() < 0x30 || record.get(0..4) != Some(b"FILE") {
        return Err(AegisError::ProtocolError {
            message: format!("{label} 非法"),
            code: Some(ErrorCode::Probe101),
        });
    }
    let attr_off = read_u16_le(record, 0x14)? as usize;
    if attr_off >= record.len() {
        return Err(AegisError::ProtocolError {
            message: format!("{label} attribute offset 越界"),
            code: Some(ErrorCode::Probe101),
        });
    }
    Ok(attr_off)
}

fn parse_mft_attr_header(record: &[u8], off: usize) -> Result<(u32, usize), AegisError> {
    let attr_type = read_u32_le(record, off)?;
    if attr_type == 0xFFFF_FFFF {
        return Ok((attr_type, 0));
    }
    let total_len = read_u32_le(record, off + 4)? as usize;
    if total_len < 24 || off + total_len > record.len() {
        return Err(AegisError::ProtocolError {
            message: "MFT attribute 长度非法".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    Ok((attr_type, total_len))
}

fn mft_data_runlist_if_present(
    record: &[u8],
    off: usize,
    total_len: usize,
) -> Result<Option<&[u8]>, AegisError> {
    let non_resident = *record.get(off + 8).ok_or(AegisError::ProtocolError {
        message: "读取 non_resident 越界".to_string(),
        code: Some(ErrorCode::Probe101),
    })?;
    let name_len = *record.get(off + 9).ok_or(AegisError::ProtocolError {
        message: "读取 name_len 越界".to_string(),
        code: Some(ErrorCode::Probe101),
    })? as usize;
    let attr_type = read_u32_le(record, off)?;

    if attr_type != 0x80 || non_resident == 0 || name_len != 0 {
        return Ok(None);
    }
    if total_len < 0x40 {
        return Err(AegisError::ProtocolError {
            message: "$MFT $DATA non-resident header 太短".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    let runlist_off = read_u16_le(record, off + 0x20)? as usize;
    if runlist_off >= total_len {
        return Err(AegisError::ProtocolError {
            message: "$MFT runlist offset 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    let runlist =
        record
            .get(off + runlist_off..off + total_len)
            .ok_or(AegisError::ProtocolError {
                message: "读取 $MFT runlist 越界".to_string(),
                code: Some(ErrorCode::Probe101),
            })?;
    Ok(Some(runlist))
}

struct MftRecordParseState {
    si_created: Option<i64>,
    fn_created: Option<i64>,
    ads_streams: Vec<String>,
}

impl MftRecordParseState {
    fn new() -> Self {
        Self {
            si_created: None,
            fn_created: None,
            ads_streams: Vec::new(),
        }
    }

    fn into_evidence(self) -> Result<MftFileRecordEvidence, AegisError> {
        let Some(si_created_ms) = self.si_created else {
            return Err(AegisError::ProtocolError {
                message: "MFT record 缺少 $STANDARD_INFORMATION".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        };
        let Some(fn_created_ms) = self.fn_created else {
            return Err(AegisError::ProtocolError {
                message: "MFT record 缺少 $FILE_NAME".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        };

        Ok(MftFileRecordEvidence {
            si_created_ms,
            fn_created_ms,
            ads_streams: self.ads_streams,
        })
    }
}

fn parse_mft_record_attribute(
    record: &[u8],
    base_off: usize,
    total_len: usize,
    attr_type: u32,
    state: &mut MftRecordParseState,
) -> Result<(), AegisError> {
    let non_resident = *record.get(base_off + 8).ok_or(AegisError::ProtocolError {
        message: "读取 non_resident 越界".to_string(),
        code: Some(ErrorCode::Probe101),
    })?;
    let name_len = *record.get(base_off + 9).ok_or(AegisError::ProtocolError {
        message: "读取 name_len 越界".to_string(),
        code: Some(ErrorCode::Probe101),
    })? as usize;
    let name_off = read_u16_le(record, base_off + 10)? as usize;

    if name_len > 0 {
        let end = name_off.saturating_add(name_len.saturating_mul(2));
        if end > total_len {
            return Err(AegisError::ProtocolError {
                message: "MFT attribute name 越界".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }
    }

    if attr_type == 0x80 && name_len > 0 {
        let name_bytes = record
            .get(base_off + name_off..base_off + name_off + name_len.saturating_mul(2))
            .ok_or(AegisError::ProtocolError {
                message: "$DATA name 越界".to_string(),
                code: Some(ErrorCode::Probe101),
            })?;
        let name = decode_utf16le(name_bytes)?;
        if !name.is_empty() {
            state.ads_streams.push(name);
        }
    }

    if non_resident != 0 {
        return Ok(());
    }

    let value = mft_resident_value(record, base_off, total_len)?;
    match attr_type {
        0x10 => {
            if value.len() < 8 {
                return Err(AegisError::ProtocolError {
                    message: "$STANDARD_INFORMATION 太短".to_string(),
                    code: Some(ErrorCode::Probe101),
                });
            }
            let created_ft = read_u64_le(value, 0)?;
            state.si_created = Some(filetime_100ns_to_unix_ms(created_ft));
        }
        0x30 => {
            if value.len() < 0x20 {
                return Err(AegisError::ProtocolError {
                    message: "$FILE_NAME 太短".to_string(),
                    code: Some(ErrorCode::Probe101),
                });
            }
            let created_ft = read_u64_le(value, 8)?;
            state.fn_created = Some(filetime_100ns_to_unix_ms(created_ft));
        }
        _ => {}
    }

    Ok(())
}

fn mft_resident_value(
    record: &[u8],
    base_off: usize,
    total_len: usize,
) -> Result<&[u8], AegisError> {
    let value_len = read_u32_le(record, base_off + 16)? as usize;
    let value_off = read_u16_le(record, base_off + 20)? as usize;
    if value_off > total_len || value_off.saturating_add(value_len) > total_len {
        return Err(AegisError::ProtocolError {
            message: "MFT resident value 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    record
        .get(base_off + value_off..base_off + value_off + value_len)
        .ok_or(AegisError::ProtocolError {
            message: "读取 attribute value 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        })
}

pub fn filetime_100ns_to_unix_ms(filetime_100ns: u64) -> i64 {
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    if filetime_100ns < EPOCH_DIFF_100NS {
        return 0;
    }
    let diff = filetime_100ns.saturating_sub(EPOCH_DIFF_100NS);
    let ms = diff / 10_000;
    i64::try_from(ms).unwrap_or(i64::MAX)
}

fn system_time_to_unix_ms(t: SystemTime) -> i64 {
    let Ok(d) = t.duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

fn is_locked_by_share_violation(path: &Path) -> bool {
    let Err(err) = OpenOptions::new().read(true).open(path) else {
        return false;
    };
    matches!(err.raw_os_error(), Some(code) if code == 32 || code == 33)
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum VolumeSource<'a> {
    Drive(char),
    DevicePath(&'a str),
}

#[cfg(windows)]
fn mft_evidence_for_path_best_effort(
    path_for_file_id: &Path,
    volume: VolumeSource<'_>,
) -> Option<MftFileRecordEvidence> {
    let mft_record_number = mft_record_number_from_path_best_effort(path_for_file_id)?;
    mft_evidence_for_record_best_effort(volume, mft_record_number).ok()
}

#[cfg(windows)]
fn mft_record_number_from_path_best_effort(path: &Path) -> Option<u64> {
    let handle = winapi_util::Handle::from_path_any(path).ok()?;
    let info = winapi_util::file::information(&handle).ok()?;
    let record = info.file_index() & 0x0000_FFFF_FFFF_FFFF;
    if record == 0 {
        return None;
    }
    Some(record)
}

#[cfg(windows)]
pub fn drive_letter(path: &Path) -> Option<char> {
    use std::path::Component;
    use std::path::Prefix;

    let mut it = path.components();
    let Component::Prefix(prefix) = it.next()? else {
        return None;
    };
    match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(char::from(letter)),
        _ => None,
    }
}

#[cfg(not(windows))]
pub fn drive_letter(_path: &Path) -> Option<char> {
    None
}

#[cfg(windows)]
fn vss_path_for_file(
    device_path: &str,
    vss_drive_letter: char,
    original: &Path,
) -> Option<PathBuf> {
    let original_drive = drive_letter(original)?;
    if !original_drive.eq_ignore_ascii_case(&vss_drive_letter) {
        return None;
    }
    let relative = relative_path_without_drive(original)?;
    Some(PathBuf::from(device_path).join(relative))
}

#[cfg(windows)]
fn relative_path_without_drive(original: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut it = original.components();
    let Component::Prefix(_) = it.next()? else {
        return None;
    };
    let Component::RootDir = it.next()? else {
        return None;
    };
    let mut rel = PathBuf::new();
    for c in it {
        rel.push(c.as_os_str());
    }
    Some(rel)
}

#[cfg(windows)]
fn open_raw_volume(drive_letter: char) -> Result<File, AegisError> {
    let path = format!(r"\\.\{drive_letter}:");
    File::open(path.as_str()).map_err(AegisError::IoError)
}

#[cfg(windows)]
fn open_vss_volume(device_path: &str) -> Result<File, AegisError> {
    File::open(device_path).map_err(AegisError::IoError)
}

#[cfg(windows)]
fn read_boot_sector(mut volume: &File) -> Result<[u8; 512], AegisError> {
    let mut buf = [0u8; 512];
    volume
        .seek(SeekFrom::Start(0))
        .map_err(AegisError::IoError)?;
    volume.read_exact(&mut buf).map_err(AegisError::IoError)?;
    Ok(buf)
}

#[cfg(windows)]
fn read_exact_at(f: &mut File, off: u64, buf: &mut [u8]) -> Result<(), AegisError> {
    f.seek(SeekFrom::Start(off)).map_err(AegisError::IoError)?;
    f.read_exact(buf).map_err(AegisError::IoError)?;
    Ok(())
}

#[cfg(windows)]
fn read_mft_record_bytes_using_runs(
    f: &mut File,
    info: &NtfsBootSectorInfo,
    mft_runs: &[NtfsRun],
    record_number: u64,
) -> Result<Vec<u8>, AegisError> {
    let record_len = info.mft_record_size as usize;
    if record_len == 0 {
        return Err(AegisError::ProtocolError {
            message: "mft_record_size 为 0".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    let record_size_u64 = u64::from(info.mft_record_size);

    let cluster_size = u64::from(info.cluster_size);
    if cluster_size == 0 {
        return Err(AegisError::ProtocolError {
            message: "cluster_size 为 0".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let mut record = vec![0u8; record_len];

    let record_logical_off = record_number.saturating_mul(record_size_u64);
    let mut written = 0usize;
    while written < record.len() {
        let logical_off = record_logical_off.saturating_add(written as u64);
        let vcn = logical_off / cluster_size;
        let intra = logical_off % cluster_size;

        let (run, clusters_left_in_run) =
            find_run_for_vcn(mft_runs, vcn).ok_or(AegisError::ProtocolError {
                message: "MFT runlist 不覆盖目标 VCN".to_string(),
                code: Some(ErrorCode::Probe101),
            })?;

        let lcn = run
            .lcn_start
            .saturating_add(vcn.saturating_sub(run.vcn_start));
        let phys_off = lcn.saturating_mul(cluster_size).saturating_add(intra);

        let max_bytes_in_this_run = clusters_left_in_run
            .saturating_mul(cluster_size)
            .saturating_sub(intra);
        let remaining = (record.len().saturating_sub(written)) as u64;
        let to_read = remaining.min(max_bytes_in_this_run);
        if to_read == 0 {
            return Err(AegisError::ProtocolError {
                message: "MFT runlist 计算得到 0 字节可读".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }

        let to_read_usize = usize::try_from(to_read).map_err(|_| AegisError::ProtocolError {
            message: "MFT 读取长度溢出".to_string(),
            code: Some(ErrorCode::Probe101),
        })?;
        let end = written.saturating_add(to_read_usize);
        read_exact_at(f, phys_off, &mut record[written..end])?;
        written = end;
    }

    Ok(record)
}

#[cfg(windows)]
fn mft_evidence_for_record_best_effort(
    volume: VolumeSource<'_>,
    record_number: u64,
) -> Result<MftFileRecordEvidence, AegisError> {
    let volume_file = match volume {
        VolumeSource::Drive(drive_letter) => open_raw_volume(drive_letter)?,
        VolumeSource::DevicePath(device_path) => open_vss_volume(device_path)?,
    };
    let boot = read_boot_sector(&volume_file)?;
    let info = parse_ntfs_boot_sector(boot.as_slice())?;

    if info.mft_record_size == 0 || info.mft_record_size > 4096 {
        return Err(AegisError::ProtocolError {
            message: format!("mft_record_size 非法: {}", info.mft_record_size),
            code: Some(ErrorCode::Probe101),
        });
    }

    let mut f = volume_file;
    let mft_base = info.mft_lcn.saturating_mul(u64::from(info.cluster_size));

    let mut record0 = vec![0u8; info.mft_record_size as usize];
    read_exact_at(&mut f, mft_base, record0.as_mut_slice())?;
    apply_mft_fixup(record0.as_mut_slice(), info.bytes_per_sector)?;

    if record_number == 0 {
        return parse_mft_file_record(record0.as_slice());
    }

    let mft_runs = parse_mft_runs_from_mft_record_zero(record0.as_slice())?;
    let mut record =
        read_mft_record_bytes_using_runs(&mut f, &info, mft_runs.as_slice(), record_number)?;
    apply_mft_fixup(record.as_mut_slice(), info.bytes_per_sector)?;
    parse_mft_file_record(record.as_slice())
}

#[cfg(windows)]
fn apply_mft_fixup(record: &mut [u8], bytes_per_sector: u16) -> Result<(), AegisError> {
    let bytes_per_sector = usize::from(bytes_per_sector);
    if bytes_per_sector == 0 || !record.len().is_multiple_of(bytes_per_sector) {
        return Err(AegisError::ProtocolError {
            message: "MFT record/sector 尺寸非法".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let usa_off = read_u16_le(record, 4)? as usize;
    let usa_count = read_u16_le(record, 6)? as usize;
    if usa_count == 0 || usa_off >= record.len() {
        return Err(AegisError::ProtocolError {
            message: "MFT fixup header 非法".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let usa_bytes = usa_count.saturating_mul(2);
    if usa_off.saturating_add(usa_bytes) > record.len() {
        return Err(AegisError::ProtocolError {
            message: "MFT fixup array 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let sectors = record.len() / bytes_per_sector;
    if usa_count != sectors.saturating_add(1) {
        return Err(AegisError::ProtocolError {
            message: "MFT fixup array size 不匹配".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let usn = read_u16_le(record, usa_off)?;
    for i in 0..sectors {
        let sector_end = (i.saturating_add(1)).saturating_mul(bytes_per_sector);
        let sig_off = sector_end.saturating_sub(2);
        let sig = read_u16_le(record, sig_off)?;
        if sig != usn {
            return Err(AegisError::ProtocolError {
                message: "MFT fixup signature 不匹配".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }
        let repl = read_u16_le(record, usa_off.saturating_add((i.saturating_add(1)) * 2))?;
        record[sig_off..sig_off + 2].copy_from_slice(repl.to_le_bytes().as_slice());
    }
    Ok(())
}

fn read_u64_le(bytes: &[u8], off: usize) -> Result<u64, AegisError> {
    let b = bytes.get(off..off + 8).ok_or(AegisError::ProtocolError {
        message: "读取 u64 越界".to_string(),
        code: Some(ErrorCode::Probe101),
    })?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn decode_utf16le(bytes: &[u8]) -> Result<String, AegisError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(AegisError::ProtocolError {
            message: "UTF-16LE 字节长度非法".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    let mut words: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        words.push(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
        i = i.saturating_add(2);
    }
    String::from_utf16(words.as_slice()).map_err(|e| AegisError::ProtocolError {
        message: format!("UTF-16LE 解码失败: {e}"),
        code: Some(ErrorCode::Probe101),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        FileAccessPlan, VssAsyncState, choose_file_access_plan,
        exec_id_from_process_sequence_number, filetime_100ns_to_unix_ms, ghosting_suspected,
        is_registry_hive_path, parse_mft_file_record, parse_pe_static_fingerprint,
        timestomp_detected, wait_vss_async_with_timeout,
    };
    use std::path::Path;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    #[cfg(windows)]
    use super::{
        NtfsBootSectorInfo, NtfsRun, decode_ntfs_runlist, parse_mft_runs_from_mft_record_zero,
        read_mft_record_bytes_using_runs,
    };

    #[test]
    fn registry_hive_detection_matches_doc04_fix8() {
        let p = Path::new(r"C:\Windows\System32\config\SYSTEM");
        assert!(is_registry_hive_path(p));
        let p = Path::new(r"C:\Windows\System32\config\software");
        assert!(is_registry_hive_path(p));
        let p = Path::new(r"C:\Users\a\NTUSER.DAT");
        assert!(is_registry_hive_path(p));
        let p = Path::new(r"C:\Temp\not_hive.bin");
        assert!(!is_registry_hive_path(p));
    }

    #[test]
    fn file_access_plan_follows_doc04_priority_and_hive_exception() {
        let hive = Path::new(r"C:\Windows\System32\config\SYSTEM");
        let normal = Path::new(r"C:\Temp\a.pst");
        assert_eq!(
            choose_file_access_plan(true, hive),
            FileAccessPlan::VssSnapshot
        );
        assert_eq!(
            choose_file_access_plan(true, normal),
            FileAccessPlan::VssSnapshot
        );
        assert_eq!(
            choose_file_access_plan(false, hive),
            FileAccessPlan::Win32Api
        );
        assert_eq!(
            choose_file_access_plan(false, normal),
            FileAccessPlan::RawVolume
        );
    }

    #[test]
    fn exec_id_falls_back_to_monotonic_counter() {
        let counter = AtomicU64::new(0);
        assert_eq!(exec_id_from_process_sequence_number(Some(42), &counter), 42);
        assert_eq!(exec_id_from_process_sequence_number(None, &counter), 1);
        assert_eq!(exec_id_from_process_sequence_number(None, &counter), 2);
    }

    #[test]
    fn timestomp_threshold_works() {
        assert!(!timestomp_detected(1000, 1100, 200));
        assert!(timestomp_detected(1000, 3000, 1000));
    }

    #[test]
    fn pe_fingerprint_parses_static_fields() -> Result<(), crate::error::AegisError> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        bytes[coff + 4..coff + 8].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes());

        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[opt + 0x38..opt + 0x3c].copy_from_slice(&0x5566_7788u32.to_le_bytes());

        let sec = opt + 0xe0;
        bytes[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        bytes[sec + 40..sec + 48].copy_from_slice(b".rdata\0\0");

        let fp = parse_pe_static_fingerprint(bytes.as_slice())?;
        assert_eq!(fp.number_of_sections, 2);
        assert_eq!(fp.time_date_stamp, 0x1122_3344);
        assert_eq!(fp.size_of_image, 0x5566_7788);

        let mut names: Vec<String> = fp
            .section_names
            .iter()
            .map(|n| {
                String::from_utf8_lossy(n)
                    .trim_end_matches('\0')
                    .to_string()
            })
            .collect();
        names.sort();
        assert_eq!(names, vec![".rdata".to_string(), ".text".to_string()]);
        Ok(())
    }

    #[test]
    fn ghosting_suspected_flags_mismatch_or_delete_pending() -> Result<(), crate::error::AegisError>
    {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 4..coff + 8].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes());

        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[opt + 0x38..opt + 0x3c].copy_from_slice(&0x1000u32.to_le_bytes());

        let sec = opt + 0xe0;
        bytes[sec..sec + 8].copy_from_slice(b".text\0\0\0");

        let disk = parse_pe_static_fingerprint(bytes.as_slice())?;

        bytes[coff + 4..coff + 8].copy_from_slice(&0x1111_1111u32.to_le_bytes());
        let mem = parse_pe_static_fingerprint(bytes.as_slice())?;

        assert!(ghosting_suspected(&mem, &disk, false));
        assert!(ghosting_suspected(&disk, &disk, true));
        assert!(!ghosting_suspected(&disk, &disk, false));
        Ok(())
    }

    #[test]
    fn filetime_epoch_converts_to_unix_zero() {
        assert_eq!(filetime_100ns_to_unix_ms(116_444_736_000_000_000), 0);
    }

    #[test]
    fn vss_wait_returns_ok_or_timeout() {
        let mut calls = 0u32;
        let ok = wait_vss_async_with_timeout(
            Duration::from_millis(50),
            || {
                calls = calls.saturating_add(1);
                if calls >= 2 {
                    Ok(VssAsyncState::FinishedOk)
                } else {
                    Ok(VssAsyncState::Pending)
                }
            },
            |_| {},
        );
        assert!(ok.is_ok());

        let mut always_pending = 0u32;
        let timeout = wait_vss_async_with_timeout(
            Duration::from_millis(1),
            || {
                always_pending = always_pending.saturating_add(1);
                Ok(VssAsyncState::Pending)
            },
            |_| {},
        );
        assert!(timeout.is_err());
    }

    #[test]
    fn mft_parser_extracts_si_fn_and_ads() -> Result<(), crate::error::AegisError> {
        let mut record = vec![0u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        record[0x14..0x16].copy_from_slice(&0x30u16.to_le_bytes());

        let si_attr_off = 0x30usize;
        let si_value = 116_444_736_000_000_000u64.to_le_bytes();
        let si_attr = build_resident_attr(0x10, 0, si_value.as_slice());
        record[si_attr_off..si_attr_off + si_attr.len()].copy_from_slice(si_attr.as_slice());

        let fn_attr_off = si_attr_off + si_attr.len();
        let mut fn_value = vec![0u8; 0x40];
        let fn_created = (116_444_736_000_000_000u64).saturating_add(20_000_000u64);
        fn_value[8..16].copy_from_slice(fn_created.to_le_bytes().as_slice());
        let fn_attr = build_resident_attr(0x30, 0, fn_value.as_slice());
        record[fn_attr_off..fn_attr_off + fn_attr.len()].copy_from_slice(fn_attr.as_slice());

        let data_attr_off = fn_attr_off + fn_attr.len();
        let name_utf16 = "hidden.ps1"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>();
        let data_attr = build_resident_attr_named(0x80, name_utf16.as_slice(), b"x");
        record[data_attr_off..data_attr_off + data_attr.len()]
            .copy_from_slice(data_attr.as_slice());

        let end_off = data_attr_off + data_attr.len();
        record[end_off..end_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let ev = parse_mft_file_record(record.as_slice())?;
        assert_eq!(ev.si_created_ms, 0);
        assert_eq!(ev.fn_created_ms, 2000);
        assert_eq!(ev.ads_streams, vec!["hidden.ps1".to_string()]);

        assert!(timestomp_detected(ev.si_created_ms, ev.fn_created_ms, 1000));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn ntfs_runlist_decodes_positive_and_negative_deltas() -> Result<(), crate::error::AegisError> {
        let runlist = [0x11, 0x03, 0x0A, 0x11, 0x02, 0x02, 0x00];
        let runs = decode_ntfs_runlist(runlist.as_slice())?;
        assert_eq!(
            runs,
            vec![
                NtfsRun {
                    vcn_start: 0,
                    lcn_start: 10,
                    cluster_len: 3
                },
                NtfsRun {
                    vcn_start: 3,
                    lcn_start: 12,
                    cluster_len: 2
                }
            ]
        );

        let runlist_neg = [0x11, 0x03, 0x0A, 0x11, 0x02, 0xFF, 0x00];
        let runs = decode_ntfs_runlist(runlist_neg.as_slice())?;
        assert_eq!(runs[0].lcn_start, 10);
        assert_eq!(runs[1].lcn_start, 9);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn mft_record0_extracts_mft_data_runlist() -> Result<(), crate::error::AegisError> {
        let runlist = [0x11, 0x03, 0x0A, 0x11, 0x02, 0x02, 0x00];
        let mut record = vec![0u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        record[0x14..0x16].copy_from_slice(&0x30u16.to_le_bytes());

        let attr_off = 0x30usize;
        let mut attr = vec![0u8; 0x40];
        attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        attr[8] = 1;
        attr[9] = 0;
        attr[0x20..0x22].copy_from_slice(&0x40u16.to_le_bytes());
        attr.extend_from_slice(runlist.as_slice());
        let total_len = u32::try_from(attr.len()).unwrap_or(0);
        attr[4..8].copy_from_slice(total_len.to_le_bytes().as_slice());

        record[attr_off..attr_off + attr.len()].copy_from_slice(attr.as_slice());
        let end_off = attr_off + attr.len();
        record[end_off..end_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let runs = parse_mft_runs_from_mft_record_zero(record.as_slice())?;
        assert_eq!(runs[0].lcn_start, 10);
        assert_eq!(runs[1].vcn_start, 3);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn mft_record_read_spans_run_boundary() -> Result<(), crate::error::AegisError> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut tmp = std::env::temp_dir();
        tmp.push(format!("aegis_mft_runs_test_{}.bin", std::process::id()));

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(tmp.as_path())
            .map_err(crate::error::AegisError::IoError)?;

        let mut content = vec![0u8; 128];
        for (i, b) in content.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        file.write_all(content.as_slice())
            .map_err(crate::error::AegisError::IoError)?;
        drop(file);

        let mut file = OpenOptions::new()
            .read(true)
            .open(tmp.as_path())
            .map_err(crate::error::AegisError::IoError)?;

        let info = NtfsBootSectorInfo {
            bytes_per_sector: 1,
            sectors_per_cluster: 4,
            cluster_size: 4,
            mft_lcn: 0,
            clusters_per_mft_record: 0,
            mft_record_size: 10,
        };
        let runs = vec![
            NtfsRun {
                vcn_start: 0,
                lcn_start: 0,
                cluster_len: 4,
            },
            NtfsRun {
                vcn_start: 4,
                lcn_start: 10,
                cluster_len: 4,
            },
        ];

        let record = read_mft_record_bytes_using_runs(&mut file, &info, runs.as_slice(), 1)?;
        assert_eq!(record, vec![10, 11, 12, 13, 14, 15, 40, 41, 42, 43]);

        let _ignored = std::fs::remove_file(tmp.as_path());
        Ok(())
    }

    fn build_resident_attr(attr_type: u32, name_len_u16: usize, value: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 24];
        out[0..4].copy_from_slice(attr_type.to_le_bytes().as_slice());
        out[8] = 0;
        out[9] = u8::try_from(name_len_u16).unwrap_or(0);
        out[10..12].copy_from_slice(&24u16.to_le_bytes());
        let value_off = 24u16;
        out[16..20].copy_from_slice(
            u32::try_from(value.len())
                .unwrap_or(0)
                .to_le_bytes()
                .as_slice(),
        );
        out[20..22].copy_from_slice(value_off.to_le_bytes().as_slice());
        let mut full = out;
        full.extend_from_slice(value);
        let total_len = u32::try_from(full.len()).unwrap_or(0);
        full[4..8].copy_from_slice(total_len.to_le_bytes().as_slice());
        full
    }

    fn build_resident_attr_named(attr_type: u32, name_utf16le: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 24];
        out[0..4].copy_from_slice(attr_type.to_le_bytes().as_slice());
        out[8] = 0;
        let name_len_u16 = name_utf16le.len() / 2;
        out[9] = u8::try_from(name_len_u16).unwrap_or(0);
        out[10..12].copy_from_slice(&24u16.to_le_bytes());
        let value_off =
            u16::try_from(24usize.saturating_add(name_utf16le.len())).unwrap_or(u16::MAX);
        out[16..20].copy_from_slice(
            u32::try_from(value.len())
                .unwrap_or(0)
                .to_le_bytes()
                .as_slice(),
        );
        out[20..22].copy_from_slice(value_off.to_le_bytes().as_slice());
        let mut full = out;
        full.extend_from_slice(name_utf16le);
        full.extend_from_slice(value);
        let total_len = u32::try_from(full.len()).unwrap_or(0);
        full[4..8].copy_from_slice(total_len.to_le_bytes().as_slice());
        full
    }
}
