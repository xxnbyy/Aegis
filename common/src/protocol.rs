use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessagePayload {
    Empty,
    SystemInfo(SystemInfo),
    ProcessInfo(ProcessInfo),
    FileInfo(FileInfo),
    NetworkInterfaceUpdate(NetworkInterfaceUpdate),
    AgentTelemetry(AgentTelemetry),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_version: String,
    pub kernel_version: String,
    pub ip_addresses: Vec<String>,
    pub boot_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: String,
    pub uid: u32,
    pub start_time: i64,
    pub is_ghost: bool,
    pub is_mismatched: bool,
    pub has_floating_code: bool,
    pub exec_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub created_si: i64,
    pub created_fn: i64,
    pub modified: i64,
    pub is_timestomped: bool,
    pub is_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInterfaceUpdate {
    pub timestamp: i64,
    pub new_ip_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentTelemetry {
    pub timestamp: i64,
    pub cpu_usage_percent: u32,
    pub memory_usage_mb: u32,
    pub dropped_events_count: u64,
}
