use serde::{Deserialize, Serialize};

use std::io::{BufRead, BufReader, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AegisError, ErrorCode};

#[allow(clippy::all)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/aegis.rs"));
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct PayloadEnvelope {
    #[prost(
        oneof = "payload_envelope::Payload",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11"
    )]
    pub payload: Option<payload_envelope::Payload>,
}

pub mod payload_envelope {
    #[derive(Clone, PartialEq, Eq, prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "1")]
        SystemInfo(super::SystemInfo),
        #[prost(message, tag = "2")]
        ProcessInfo(super::ProcessInfo),
        #[prost(message, tag = "3")]
        FileInfo(super::FileInfo),
        #[prost(message, tag = "4")]
        NetworkInterfaceUpdate(super::NetworkInterfaceUpdate),
        #[prost(message, tag = "5")]
        AgentTelemetry(super::AgentTelemetry),
        #[prost(message, tag = "6")]
        ProcessGhostingEvidence(super::ProcessGhostingEvidence),
        #[prost(message, tag = "7")]
        WindowsMemoryForensicsEvidence(super::WindowsMemoryForensicsEvidence),
        #[prost(message, tag = "8")]
        EbpfEventBatch(super::EbpfEventBatch),
        #[prost(message, tag = "9")]
        SmartReflexEvidence(super::SmartReflexEvidence),
        #[prost(message, tag = "10")]
        EvidenceChunk(super::EvidenceChunk),
        #[prost(message, tag = "11")]
        LinuxKernelForensicsEvidence(super::LinuxKernelForensicsEvidence),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub header: MessageHeader,
    pub payload: MessagePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageHeader {
    pub request_id: u64,
    pub timestamp: i64,
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Command {
    StartProbe,
    StopProbe,
    FetchLogs,
    UploadArtifactChunk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessagePayload {
    Empty,
    SystemInfo(SystemInfo),
    ProcessInfo(ProcessInfo),
    FileInfo(FileInfo),
    NetworkInterfaceUpdate(NetworkInterfaceUpdate),
    AgentTelemetry(AgentTelemetry),
    ArtifactChunk(ArtifactChunk),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactChunk {
    pub sequence_id: u64,
    pub is_last: bool,
    pub bytes: Vec<u8>,
}

pub const DEFAULT_ARTIFACT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_ARTIFACT_CHUNK_SIZE: usize = 45 * 1024 * 1024;

pub struct Chunker<R> {
    reader: BufReader<R>,
    chunk_size: usize,
    request_id: u64,
    sequence_id: u64,
}

impl<R: Read> Chunker<R> {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(reader: R, chunk_size: usize, request_id: u64) -> Result<Self, AegisError> {
        if chunk_size == 0 || chunk_size > MAX_ARTIFACT_CHUNK_SIZE {
            return Err(AegisError::ConfigError {
                message: format!(
                    "chunk_size 必须在 1..={MAX_ARTIFACT_CHUNK_SIZE} 之间，当前: {chunk_size}"
                ),
            });
        }

        Ok(Self {
            reader: BufReader::new(reader),
            chunk_size,
            request_id,
            sequence_id: 0,
        })
    }

    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }
}

impl<R: Read> Iterator for Chunker<R> {
    type Item = Result<Message, AegisError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = Vec::with_capacity(self.chunk_size);
        let mut remaining = self.chunk_size;
        let mut hit_eof = false;

        while remaining > 0 {
            let available = match self.reader.fill_buf() {
                Ok(v) => v,
                Err(e) => return Some(Err(AegisError::IoError(e))),
            };
            if available.is_empty() {
                hit_eof = true;
                break;
            }

            let take = remaining.min(available.len());
            buf.extend_from_slice(&available[..take]);
            self.reader.consume(take);
            remaining -= take;
        }

        if buf.is_empty() {
            return None;
        }

        let is_last = if hit_eof {
            true
        } else {
            match self.reader.fill_buf() {
                Ok(v) => v.is_empty(),
                Err(e) => return Some(Err(AegisError::IoError(e))),
            }
        };

        let message = Message {
            header: MessageHeader {
                request_id: self.request_id,
                timestamp: timestamp_now(),
                command: Command::UploadArtifactChunk,
            },
            payload: MessagePayload::ArtifactChunk(ArtifactChunk {
                sequence_id: self.sequence_id,
                is_last,
                bytes: buf,
            }),
        };
        self.sequence_id = self.sequence_id.saturating_add(1);
        Some(Ok(message))
    }
}

pub struct EvidenceChunker<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_chunk_size: usize,
    evidence_id: u64,
    kind: String,
    content_type: String,
    sequence_id: u32,
}

impl<'a> EvidenceChunker<'a> {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        bytes: &'a [u8],
        max_chunk_size: usize,
        evidence_id: u64,
        kind: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Result<Self, AegisError> {
        if max_chunk_size == 0 || max_chunk_size > MAX_ARTIFACT_CHUNK_SIZE {
            return Err(AegisError::ConfigError {
                message: format!(
                    "max_chunk_size 必须在 1..={MAX_ARTIFACT_CHUNK_SIZE} 之间，当前: {max_chunk_size}"
                ),
            });
        }
        Ok(Self {
            bytes,
            offset: 0,
            max_chunk_size,
            evidence_id,
            kind: kind.into(),
            content_type: content_type.into(),
            sequence_id: 0,
        })
    }
}

impl Iterator for EvidenceChunker<'_> {
    type Item = PayloadEnvelope;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let end = self
            .offset
            .saturating_add(self.max_chunk_size)
            .min(self.bytes.len());
        let chunk_bytes = self
            .bytes
            .get(self.offset..end)
            .unwrap_or_default()
            .to_vec();
        let is_last = end >= self.bytes.len();

        let env = PayloadEnvelope::evidence_chunk(EvidenceChunk {
            evidence_id: self.evidence_id,
            sequence_id: self.sequence_id,
            is_last,
            kind: self.kind.clone(),
            content_type: self.content_type.clone(),
            bytes: chunk_bytes,
        });

        self.offset = end;
        self.sequence_id = self.sequence_id.saturating_add(1);
        Some(env)
    }
}

pub struct ArtifactBuilder<W> {
    request_id: u64,
    expected_sequence_id: u64,
    finished: bool,
    writer: W,
    bytes_written: u64,
}

impl<W: Write> ArtifactBuilder<W> {
    pub fn new(request_id: u64, writer: W) -> Self {
        Self {
            request_id,
            expected_sequence_id: 0,
            finished: false,
            writer,
            bytes_written: 0,
        }
    }

    pub fn new_with_state(
        request_id: u64,
        writer: W,
        expected_sequence_id: u64,
        bytes_written: u64,
    ) -> Self {
        Self {
            request_id,
            expected_sequence_id,
            finished: false,
            writer,
            bytes_written,
        }
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn push(&mut self, message: &Message) -> Result<(), AegisError> {
        if self.finished {
            return Err(AegisError::ProtocolError {
                message: "Artifact 已完成，不能再接收 chunk".to_string(),
                code: None,
            });
        }

        if message.header.request_id != self.request_id {
            return Err(AegisError::ProtocolError {
                message: "Artifact request_id 不匹配".to_string(),
                code: None,
            });
        }

        if message.header.command != Command::UploadArtifactChunk {
            return Err(AegisError::ProtocolError {
                message: "不支持的 command".to_string(),
                code: None,
            });
        }

        let MessagePayload::ArtifactChunk(chunk) = &message.payload else {
            return Err(AegisError::ProtocolError {
                message: "不支持的 payload".to_string(),
                code: None,
            });
        };

        if chunk.sequence_id != self.expected_sequence_id {
            return Err(AegisError::ProtocolError {
                message: "Artifact chunk 序号不连续".to_string(),
                code: None,
            });
        }

        self.writer
            .write_all(chunk.bytes.as_slice())
            .map_err(AegisError::IoError)?;
        self.writer.flush().map_err(AegisError::IoError)?;
        self.bytes_written = self
            .bytes_written
            .saturating_add(chunk.bytes.len().try_into().unwrap_or(0));
        self.expected_sequence_id = self.expected_sequence_id.saturating_add(1);
        if chunk.is_last {
            self.finished = true;
        }
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

fn timestamp_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs().try_into().unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct SystemInfo {
    #[prost(string, tag = "1")]
    pub hostname: String,
    #[prost(string, tag = "2")]
    pub os_version: String,
    #[prost(string, tag = "3")]
    pub kernel_version: String,
    #[prost(string, repeated, tag = "4")]
    pub ip_addresses: Vec<String>,
    #[prost(int64, tag = "5")]
    pub boot_time: i64,
}

impl PayloadEnvelope {
    pub fn system_info(v: SystemInfo) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::SystemInfo(v)),
        }
    }

    pub fn process_info(v: ProcessInfo) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::ProcessInfo(v)),
        }
    }

    pub fn file_info(v: FileInfo) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::FileInfo(v)),
        }
    }

    pub fn network_interface_update(v: NetworkInterfaceUpdate) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::NetworkInterfaceUpdate(v)),
        }
    }

    pub fn agent_telemetry(v: AgentTelemetry) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::AgentTelemetry(v)),
        }
    }

    pub fn process_ghosting_evidence(v: ProcessGhostingEvidence) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::ProcessGhostingEvidence(v)),
        }
    }

    pub fn windows_memory_forensics_evidence(v: WindowsMemoryForensicsEvidence) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::WindowsMemoryForensicsEvidence(v)),
        }
    }

    pub fn ebpf_event_batch(v: EbpfEventBatch) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::EbpfEventBatch(v)),
        }
    }

    pub fn smart_reflex_evidence(v: SmartReflexEvidence) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::SmartReflexEvidence(v)),
        }
    }

    pub fn evidence_chunk(v: EvidenceChunk) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::EvidenceChunk(v)),
        }
    }

    pub fn linux_kernel_forensics_evidence(v: LinuxKernelForensicsEvidence) -> Self {
        Self {
            payload: Some(payload_envelope::Payload::LinuxKernelForensicsEvidence(v)),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct ProcessInfo {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    #[prost(uint32, tag = "2")]
    pub ppid: u32,
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(string, tag = "4")]
    pub cmdline: String,
    #[prost(string, tag = "5")]
    pub exe_path: String,
    #[prost(uint32, tag = "6")]
    pub uid: u32,
    #[prost(int64, tag = "7")]
    pub start_time: i64,
    #[prost(bool, tag = "8")]
    pub is_ghost: bool,
    #[prost(bool, tag = "9")]
    pub is_mismatched: bool,
    #[prost(bool, tag = "10")]
    pub has_floating_code: bool,
    #[prost(uint64, tag = "11")]
    pub exec_id: u64,
    #[prost(string, tag = "12")]
    pub exec_id_quality: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct FileInfo {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(uint64, tag = "2")]
    pub size: u64,
    #[prost(int64, tag = "3")]
    pub created_si: i64,
    #[prost(int64, tag = "4")]
    pub created_fn: i64,
    #[prost(int64, tag = "5")]
    pub modified: i64,
    #[prost(bool, tag = "6")]
    pub is_timestomped: bool,
    #[prost(bool, tag = "7")]
    pub is_locked: bool,
    #[prost(string, repeated, tag = "8")]
    pub ads_streams: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct NetworkInterfaceUpdate {
    #[prost(int64, tag = "1")]
    pub timestamp: i64,
    #[prost(string, repeated, tag = "2")]
    pub new_ip_addresses: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct AgentTelemetry {
    #[prost(int64, tag = "1")]
    pub timestamp: i64,
    #[prost(uint32, tag = "2")]
    pub cpu_usage_percent: u32,
    #[prost(uint32, tag = "3")]
    pub memory_usage_mb: u32,
    #[prost(uint64, tag = "4")]
    pub dropped_events_count: u64,
    #[prost(uint64, tag = "5")]
    pub dropped_governor: u64,
    #[prost(uint64, tag = "6")]
    pub dropped_loop: u64,
    #[prost(uint64, tag = "7")]
    pub dropped_ringbuf: u64,
    #[prost(uint32, tag = "8")]
    pub dropped_rate_percent: u32,
    #[prost(bool, tag = "9")]
    pub overloaded: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct PeFingerprint {
    #[prost(uint32, tag = "1")]
    pub time_date_stamp: u32,
    #[prost(uint32, tag = "2")]
    pub size_of_image: u32,
    #[prost(uint32, tag = "3")]
    pub number_of_sections: u32,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub section_names: Vec<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct ProcessGhostingEvidence {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    #[prost(string, tag = "2")]
    pub exe_path: String,
    #[prost(bool, tag = "3")]
    pub delete_pending: bool,
    #[prost(bool, tag = "4")]
    pub suspected: bool,
    #[prost(message, optional, tag = "5")]
    pub mem: Option<PeFingerprint>,
    #[prost(message, optional, tag = "6")]
    pub disk: Option<PeFingerprint>,
    #[prost(bytes = "vec", tag = "7")]
    pub mem_header: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub disk_header: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct ModuleIntegrityFinding {
    #[prost(string, tag = "1")]
    pub module_path: String,
    #[prost(uint64, tag = "2")]
    pub base_address: u64,
    #[prost(uint32, tag = "3")]
    pub module_size: u32,
    #[prost(string, tag = "4")]
    pub finding: String,
    #[prost(uint32, tag = "5")]
    pub confidence: u32,
    #[prost(uint32, tag = "6")]
    pub mem_time_date_stamp: u32,
    #[prost(uint32, tag = "7")]
    pub disk_time_date_stamp: u32,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct WindowsPrivateExecRegionSample {
    #[prost(uint64, tag = "1")]
    pub base_address: u64,
    #[prost(uint64, tag = "2")]
    pub region_size: u64,
    #[prost(uint32, tag = "3")]
    pub protect: u32,
    #[prost(uint32, tag = "4")]
    pub state: u32,
    #[prost(uint32, tag = "5")]
    pub ty: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub sample: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct WindowsCallStackSample {
    #[prost(uint32, tag = "1")]
    pub tid: u32,
    #[prost(uint64, tag = "2")]
    pub rip: u64,
    #[prost(uint64, tag = "3")]
    pub rsp: u64,
    #[prost(uint64, repeated, tag = "4")]
    pub return_addresses: Vec<u64>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct WindowsMemoryForensicsEvidence {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    #[prost(uint64, tag = "2")]
    pub exec_id: u64,
    #[prost(int64, tag = "3")]
    pub collected_at: i64,
    #[prost(uint32, tag = "4")]
    pub private_exec_region_count: u32,
    #[prost(message, repeated, tag = "5")]
    pub module_findings: Vec<ModuleIntegrityFinding>,
    #[prost(message, repeated, tag = "6")]
    pub private_exec_region_samples: Vec<WindowsPrivateExecRegionSample>,
    #[prost(message, repeated, tag = "7")]
    pub call_stack_samples: Vec<WindowsCallStackSample>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct EbpfEvent {
    #[prost(uint64, tag = "1")]
    pub timestamp_ns: u64,
    #[prost(uint32, tag = "2")]
    pub pid: u32,
    #[prost(uint32, tag = "3")]
    pub tgid: u32,
    #[prost(uint64, tag = "4")]
    pub exec_id: u64,
    #[prost(string, tag = "5")]
    pub kind: String,
    #[prost(string, tag = "6")]
    pub comm: String,
    #[prost(string, tag = "7")]
    pub detail: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct EbpfEventBatch {
    #[prost(int64, tag = "1")]
    pub collected_at: i64,
    #[prost(uint64, tag = "2")]
    pub dropped_total: u64,
    #[prost(message, repeated, tag = "3")]
    pub events: Vec<EbpfEvent>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct SmartReflexEvidence {
    #[prost(int64, tag = "1")]
    pub matched_at: i64,
    #[prost(uint32, tag = "2")]
    pub score: u32,
    #[prost(string, tag = "3")]
    pub kind: String,
    #[prost(string, tag = "4")]
    pub indicator: String,
    #[prost(uint32, tag = "5")]
    pub pid: u32,
    #[prost(uint64, tag = "6")]
    pub exec_id: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct EvidenceChunk {
    #[prost(uint64, tag = "1")]
    pub evidence_id: u64,
    #[prost(uint32, tag = "2")]
    pub sequence_id: u32,
    #[prost(bool, tag = "3")]
    pub is_last: bool,
    #[prost(string, tag = "4")]
    pub kind: String,
    #[prost(string, tag = "5")]
    pub content_type: String,
    #[prost(bytes = "vec", tag = "6")]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct LinuxVdsoHash {
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    #[prost(uint64, tag = "2")]
    pub exec_id: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub sha256: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, prost::Message)]
pub struct LinuxKernelForensicsEvidence {
    #[prost(int64, tag = "1")]
    pub collected_at: i64,
    #[prost(string, tag = "2")]
    pub core_pattern: String,
    #[prost(bool, tag = "3")]
    pub core_pattern_suspicious: bool,
    #[prost(string, repeated, tag = "4")]
    pub hidden_kernel_modules: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub ftrace_enabled_functions: Vec<String>,
    #[prost(message, repeated, tag = "6")]
    pub vdso_hashes: Vec<LinuxVdsoHash>,
}

#[allow(clippy::missing_errors_doc)]
pub fn validate_first_chunk_is_system_info(first: &MessagePayload) -> Result<(), AegisError> {
    match first {
        MessagePayload::SystemInfo(_) => Ok(()),
        _ => Err(AegisError::CryptoError {
            message: "SystemInfo 块缺失或顺序错误".to_string(),
            code: Some(ErrorCode::Crypto003),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_chunk_must_be_system_info() {
        let ok = MessagePayload::SystemInfo(SystemInfo {
            hostname: String::new(),
            os_version: String::new(),
            kernel_version: String::new(),
            ip_addresses: Vec::new(),
            boot_time: 0,
        });
        assert!(validate_first_chunk_is_system_info(&ok).is_ok());

        let bad = MessagePayload::Empty;
        let err = validate_first_chunk_is_system_info(&bad).err();
        assert!(matches!(
            err,
            Some(AegisError::CryptoError {
                code: Some(ErrorCode::Crypto003),
                ..
            })
        ));
    }

    struct PatternReader {
        remaining: u64,
        offset: u64,
        checksum: u64,
    }

    impl PatternReader {
        fn new(size: u64) -> Self {
            Self {
                remaining: size,
                offset: 0,
                checksum: 0,
            }
        }

        fn checksum(&self) -> u64 {
            self.checksum
        }
    }

    impl Read for PatternReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            let remaining_usize = usize::try_from(self.remaining).unwrap_or(usize::MAX);
            let to_write = out.len().min(remaining_usize);
            for (i, slot) in out.iter_mut().enumerate().take(to_write) {
                let b = ((self.offset + i as u64) % 251) as u8;
                *slot = b;
                self.checksum = self.checksum.wrapping_mul(16_777_619) ^ u64::from(b);
            }
            self.offset = self.offset.saturating_add(to_write as u64);
            self.remaining = self.remaining.saturating_sub(to_write as u64);
            Ok(to_write)
        }
    }

    struct ChecksumWriter {
        checksum: u64,
        bytes: u64,
    }

    impl ChecksumWriter {
        fn new() -> Self {
            Self {
                checksum: 0,
                bytes: 0,
            }
        }
    }

    impl Write for ChecksumWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            for b in buf {
                self.checksum = self.checksum.wrapping_mul(16_777_619) ^ u64::from(*b);
            }
            self.bytes = self
                .bytes
                .saturating_add(buf.len().try_into().unwrap_or(u64::MAX));
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    #[ignore = "1GB roundtrip 流式测试耗时较长"]
    fn artifact_chunker_roundtrip_streaming_1gb() -> Result<(), AegisError> {
        let total_size = 1024u64 * 1024 * 1024;
        let request_id = 7u64;

        let source_reader = PatternReader::new(total_size);
        let mut chunker = Chunker::new(source_reader, DEFAULT_ARTIFACT_CHUNK_SIZE, request_id)?;

        let writer = ChecksumWriter::new();
        let mut builder = ArtifactBuilder::new(request_id, writer);

        for message in chunker.by_ref() {
            builder.push(&message?)?;
        }

        let source_reader = chunker.into_inner();
        let source_checksum = source_reader.checksum();
        let bytes_written = builder.bytes_written();
        let finished = builder.is_finished();
        let writer = builder.into_inner();

        assert!(finished);
        assert_eq!(bytes_written, total_size);
        assert_eq!(writer.bytes, total_size);
        assert_eq!(writer.checksum, source_checksum);
        Ok(())
    }

    #[test]
    fn artifact_chunker_roundtrip_streaming_64mb() -> Result<(), AegisError> {
        let total_size = 64u64 * 1024 * 1024;
        let request_id = 8u64;

        let source_reader = PatternReader::new(total_size);
        let mut chunker = Chunker::new(source_reader, DEFAULT_ARTIFACT_CHUNK_SIZE, request_id)?;

        let writer = ChecksumWriter::new();
        let mut builder = ArtifactBuilder::new(request_id, writer);

        for message in chunker.by_ref() {
            builder.push(&message?)?;
        }

        let source_reader = chunker.into_inner();
        let source_checksum = source_reader.checksum();
        let bytes_written = builder.bytes_written();
        let finished = builder.is_finished();
        let writer = builder.into_inner();

        assert!(finished);
        assert_eq!(bytes_written, total_size);
        assert_eq!(writer.bytes, total_size);
        assert_eq!(writer.checksum, source_checksum);
        Ok(())
    }

    #[test]
    fn chunker_rejects_invalid_chunk_size() {
        let ok = Chunker::new(std::io::empty(), 1, 1);
        assert!(ok.is_ok());

        let bad_zero = Chunker::new(std::io::empty(), 0, 1).err();
        assert!(matches!(bad_zero, Some(AegisError::ConfigError { .. })));

        let bad_big = Chunker::new(std::io::empty(), MAX_ARTIFACT_CHUNK_SIZE + 1, 1).err();
        assert!(matches!(bad_big, Some(AegisError::ConfigError { .. })));
    }

    #[test]
    fn evidence_chunker_roundtrip() -> Result<(), AegisError> {
        let bytes: Vec<u8> = (0..5_000_000u32)
            .map(|i| u8::try_from(i % 251).unwrap_or_default())
            .collect();
        let evidence_id = 123u64;
        let mut chunker = EvidenceChunker::new(
            bytes.as_slice(),
            777_777,
            evidence_id,
            "test",
            "application/octet-stream",
        )?;

        let mut rebuilt: Vec<u8> = Vec::new();
        let mut saw_last = false;
        let mut expected_seq = 0u32;

        for env in chunker.by_ref() {
            let Some(payload_envelope::Payload::EvidenceChunk(c)) = env.payload else {
                return Err(AegisError::ProtocolError {
                    message: "payload 不匹配".to_string(),
                    code: None,
                });
            };
            assert_eq!(c.evidence_id, evidence_id);
            assert_eq!(c.sequence_id, expected_seq);
            expected_seq = expected_seq.saturating_add(1);
            rebuilt.extend_from_slice(c.bytes.as_slice());
            if c.is_last {
                saw_last = true;
            }
        }

        assert!(saw_last);
        assert_eq!(rebuilt, bytes);
        Ok(())
    }

    #[test]
    fn builder_rejects_out_of_order_chunks() -> Result<(), AegisError> {
        let request_id = 9u64;
        let source_reader = PatternReader::new((DEFAULT_ARTIFACT_CHUNK_SIZE * 2 + 7) as u64);
        let mut chunker = Chunker::new(source_reader, DEFAULT_ARTIFACT_CHUNK_SIZE, request_id)?;
        let first = chunker.next().ok_or(AegisError::ProtocolError {
            message: "缺少 chunk".to_string(),
            code: None,
        })??;
        let second = chunker.next().ok_or(AegisError::ProtocolError {
            message: "缺少 chunk".to_string(),
            code: None,
        })??;

        let writer = ChecksumWriter::new();
        let mut builder = ArtifactBuilder::new(request_id, writer);
        let err = builder.push(&second).err();
        assert!(matches!(err, Some(AegisError::ProtocolError { .. })));

        builder.push(&first)?;
        Ok(())
    }

    #[test]
    fn builder_rejects_wrong_request_id() {
        let bytes = b"abc".to_vec();
        let msg = Message {
            header: MessageHeader {
                request_id: 1,
                timestamp: 0,
                command: Command::UploadArtifactChunk,
            },
            payload: MessagePayload::ArtifactChunk(ArtifactChunk {
                sequence_id: 0,
                is_last: true,
                bytes,
            }),
        };

        let writer = ChecksumWriter::new();
        let mut builder = ArtifactBuilder::new(2, writer);
        let err = builder.push(&msg).err();
        assert!(matches!(err, Some(AegisError::ProtocolError { .. })));
    }

    #[test]
    fn builder_rejects_wrong_command() {
        let bytes = b"abc".to_vec();
        let msg = Message {
            header: MessageHeader {
                request_id: 1,
                timestamp: 0,
                command: Command::FetchLogs,
            },
            payload: MessagePayload::ArtifactChunk(ArtifactChunk {
                sequence_id: 0,
                is_last: true,
                bytes,
            }),
        };

        let writer = ChecksumWriter::new();
        let mut builder = ArtifactBuilder::new(1, writer);
        let err = builder.push(&msg).err();
        assert!(matches!(err, Some(AegisError::ProtocolError { .. })));
    }

    #[test]
    fn builder_rejects_wrong_payload() {
        let msg = Message {
            header: MessageHeader {
                request_id: 1,
                timestamp: 0,
                command: Command::UploadArtifactChunk,
            },
            payload: MessagePayload::Empty,
        };

        let writer = ChecksumWriter::new();
        let mut builder = ArtifactBuilder::new(1, writer);
        let err = builder.push(&msg).err();
        assert!(matches!(err, Some(AegisError::ProtocolError { .. })));
    }

    #[test]
    fn builder_rejects_more_chunks_after_last() -> Result<(), AegisError> {
        let request_id = 5u64;

        let first = Message {
            header: MessageHeader {
                request_id,
                timestamp: 0,
                command: Command::UploadArtifactChunk,
            },
            payload: MessagePayload::ArtifactChunk(ArtifactChunk {
                sequence_id: 0,
                is_last: true,
                bytes: b"first".to_vec(),
            }),
        };
        let second = Message {
            header: MessageHeader {
                request_id,
                timestamp: 0,
                command: Command::UploadArtifactChunk,
            },
            payload: MessagePayload::ArtifactChunk(ArtifactChunk {
                sequence_id: 1,
                is_last: true,
                bytes: b"second".to_vec(),
            }),
        };

        let writer = ChecksumWriter::new();
        let mut builder = ArtifactBuilder::new(request_id, writer);
        builder.push(&first)?;
        assert!(builder.is_finished());

        let err = builder.push(&second).err();
        assert!(matches!(err, Some(AegisError::ProtocolError { .. })));
        Ok(())
    }

    #[test]
    fn chunker_sequence_starts_at_zero_and_marks_last() -> Result<(), AegisError> {
        let request_id = 3u64;
        let data = vec![1u8; 10];
        let mut chunker = Chunker::new(data.as_slice(), 1024, request_id)?;

        let first = chunker.next().ok_or(AegisError::ProtocolError {
            message: "缺少 chunk".to_string(),
            code: None,
        })??;
        let MessagePayload::ArtifactChunk(chunk) = &first.payload else {
            return Err(AegisError::ProtocolError {
                message: "payload 不匹配".to_string(),
                code: None,
            });
        };
        assert_eq!(chunk.sequence_id, 0);
        assert!(chunk.is_last);
        assert!(chunker.next().is_none());
        Ok(())
    }
}
