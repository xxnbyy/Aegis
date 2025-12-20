#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::fs::File;
use std::fs::OpenOptions;
#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::error::{AegisError, ErrorCode};
use crate::protocol::{FileInfo, ProcessInfo};
#[cfg(windows)]
use sysinfo::System;
#[cfg(windows)]
use wmi::{Variant, WMIConnection};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeStaticFingerprint {
    pub time_date_stamp: u32,
    pub size_of_image: u32,
    pub number_of_sections: u16,
    pub section_names: Vec<[u8; 8]>,
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
    if scan_whitelist.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<FileInfo> = Vec::new();
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
pub fn collect_process_infos(limit: usize, exec_id_counter: &AtomicU64) -> Vec<ProcessInfo> {
    if limit == 0 {
        return Vec::new();
    }

    let mut sys = System::new_all();
    sys.refresh_all();

    let psn_by_pid = query_process_sequence_numbers_wmi();
    let now = crate::telemetry::unix_timestamp_now();
    let mut out: Vec<ProcessInfo> = Vec::new();
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
            is_ghost: false,
            is_mismatched: false,
            has_floating_code: false,
            exec_id,
            exec_id_quality,
        });
    }
    out
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
        match 1u32.checked_shl(exp) {
            Some(v) => v,
            None => u32::MAX,
        }
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
    let mut i = 0usize;
    let mut lcn_acc: i64 = 0;
    let mut vcn_acc: u64 = 0;

    while i < bytes.len() {
        let header = bytes[i];
        i = i.saturating_add(1);
        if header == 0 {
            break;
        }

        let len_size = usize::from(header & 0x0F);
        let off_size = usize::from((header >> 4) & 0x0F);
        if len_size == 0 {
            return Err(AegisError::ProtocolError {
                message: "NTFS runlist 长度字段为空".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }
        if off_size == 0 {
            return Err(AegisError::ProtocolError {
                message: "NTFS runlist sparse run 不支持".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }
        if i.saturating_add(len_size).saturating_add(off_size) > bytes.len() {
            return Err(AegisError::ProtocolError {
                message: "NTFS runlist 越界".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }

        let mut len: u64 = 0;
        for (k, b) in bytes[i..i + len_size].iter().copied().enumerate() {
            len |= u64::from(b) << (k.saturating_mul(8));
        }
        i = i.saturating_add(len_size);
        if len == 0 {
            return Err(AegisError::ProtocolError {
                message: "NTFS runlist cluster_len 为 0".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }

        let off_bytes = &bytes[i..i + off_size];
        i = i.saturating_add(off_size);
        let mut delta: i64 = 0;
        for (k, b) in off_bytes.iter().copied().enumerate() {
            delta |= i64::from(b) << (k.saturating_mul(8));
        }
        let sign_bit = 1i64 << ((off_size.saturating_mul(8)).saturating_sub(1));
        if (delta & sign_bit) != 0 {
            let mask = (!0i64) << (off_size.saturating_mul(8));
            delta |= mask;
        }

        lcn_acc = lcn_acc.saturating_add(delta);
        if lcn_acc < 0 {
            return Err(AegisError::ProtocolError {
                message: "NTFS runlist LCN 变为负数".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }

        runs.push(NtfsRun {
            vcn_start: vcn_acc,
            lcn_start: u64::try_from(lcn_acc).unwrap_or(0),
            cluster_len: len,
        });
        vcn_acc = vcn_acc.saturating_add(len);
    }

    if runs.is_empty() {
        return Err(AegisError::ProtocolError {
            message: "NTFS runlist 为空".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    Ok(runs)
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
    if record.len() < 0x30 || record.get(0..4) != Some(b"FILE") {
        return Err(AegisError::ProtocolError {
            message: "MFT record#0 非法".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    let attr_off = read_u16_le(record, 0x14)? as usize;
    if attr_off >= record.len() {
        return Err(AegisError::ProtocolError {
            message: "MFT record#0 attribute offset 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let mut off = attr_off;
    while off + 4 <= record.len() {
        let attr_type = read_u32_le(record, off)?;
        if attr_type == 0xFFFF_FFFF {
            break;
        }
        let total_len = read_u32_le(record, off + 4)? as usize;
        if total_len < 24 || off + total_len > record.len() {
            return Err(AegisError::ProtocolError {
                message: "MFT attribute 长度非法".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }

        let non_resident = *record.get(off + 8).ok_or(AegisError::ProtocolError {
            message: "读取 non_resident 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        })?;
        let name_len = *record.get(off + 9).ok_or(AegisError::ProtocolError {
            message: "读取 name_len 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        })? as usize;

        if attr_type == 0x80 && non_resident != 0 && name_len == 0 {
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
            let runlist = record.get(off + runlist_off..off + total_len).ok_or(
                AegisError::ProtocolError {
                    message: "读取 $MFT runlist 越界".to_string(),
                    code: Some(ErrorCode::Probe101),
                },
            )?;
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
    if record.len() < 0x30 {
        return Err(AegisError::ProtocolError {
            message: "MFT record 太短".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }
    if record.get(0..4) != Some(b"FILE") {
        return Err(AegisError::ProtocolError {
            message: "MFT record 缺少 FILE 签名".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let attr_off = read_u16_le(record, 0x14)? as usize;
    if attr_off >= record.len() {
        return Err(AegisError::ProtocolError {
            message: "MFT attribute offset 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    }

    let mut si_created: Option<i64> = None;
    let mut fn_created: Option<i64> = None;
    let mut ads_streams: Vec<String> = Vec::new();

    let mut off = attr_off;
    while off + 4 <= record.len() {
        let attr_type = read_u32_le(record, off)?;
        if attr_type == 0xFFFF_FFFF {
            break;
        }
        let total_len = read_u32_le(record, off + 4)? as usize;
        if total_len < 24 || off + total_len > record.len() {
            return Err(AegisError::ProtocolError {
                message: "MFT attribute 长度非法".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }
        let non_resident = *record.get(off + 8).ok_or(AegisError::ProtocolError {
            message: "读取 non_resident 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        })?;
        let name_len = *record.get(off + 9).ok_or(AegisError::ProtocolError {
            message: "读取 name_len 越界".to_string(),
            code: Some(ErrorCode::Probe101),
        })? as usize;
        let name_off = read_u16_le(record, off + 10)? as usize;

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
                .get(off + name_off..off + name_off + name_len.saturating_mul(2))
                .ok_or(AegisError::ProtocolError {
                    message: "$DATA name 越界".to_string(),
                    code: Some(ErrorCode::Probe101),
                })?;
            let name = decode_utf16le(name_bytes)?;
            if !name.is_empty() {
                ads_streams.push(name);
            }
        }

        if non_resident != 0 {
            off = off.saturating_add(total_len);
            continue;
        }

        let value_len = read_u32_le(record, off + 16)? as usize;
        let value_off = read_u16_le(record, off + 20)? as usize;
        if value_off > total_len || value_off.saturating_add(value_len) > total_len {
            return Err(AegisError::ProtocolError {
                message: "MFT resident value 越界".to_string(),
                code: Some(ErrorCode::Probe101),
            });
        }
        let value = record
            .get(off + value_off..off + value_off + value_len)
            .ok_or(AegisError::ProtocolError {
                message: "读取 attribute value 越界".to_string(),
                code: Some(ErrorCode::Probe101),
            })?;

        match attr_type {
            0x10 => {
                if value.len() < 8 {
                    return Err(AegisError::ProtocolError {
                        message: "$STANDARD_INFORMATION 太短".to_string(),
                        code: Some(ErrorCode::Probe101),
                    });
                }
                let created_ft = read_u64_le(value, 0)?;
                si_created = Some(filetime_100ns_to_unix_ms(created_ft));
            }
            0x30 => {
                if value.len() < 0x20 {
                    return Err(AegisError::ProtocolError {
                        message: "$FILE_NAME 太短".to_string(),
                        code: Some(ErrorCode::Probe101),
                    });
                }
                let created_ft = read_u64_le(value, 8)?;
                fn_created = Some(filetime_100ns_to_unix_ms(created_ft));
            }
            _ => {}
        }

        off = off.saturating_add(total_len);
    }

    let Some(si_created_ms) = si_created else {
        return Err(AegisError::ProtocolError {
            message: "MFT record 缺少 $STANDARD_INFORMATION".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    };
    let Some(fn_created_ms) = fn_created else {
        return Err(AegisError::ProtocolError {
            message: "MFT record 缺少 $FILE_NAME".to_string(),
            code: Some(ErrorCode::Probe101),
        });
    };

    Ok(MftFileRecordEvidence {
        si_created_ms,
        fn_created_ms,
        ads_streams,
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
