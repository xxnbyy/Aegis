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
}
