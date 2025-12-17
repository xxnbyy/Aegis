use serde::{Deserialize, Serialize};

#[doc = "Probe/Console 之间的消息封装：包含 Header 与 Payload。"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    #[doc = "消息头。"]
    pub header: MessageHeader,
    #[doc = "消息负载。"]
    pub payload: MessagePayload,
}

#[doc = "消息头：用于追踪与路由。"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageHeader {
    #[doc = "请求标识，用于幂等与追踪。"]
    pub request_id: u64,
    #[doc = "Unix 时间戳（秒或毫秒由上层约定）。"]
    pub timestamp: i64,
    #[doc = "控制命令。"]
    pub command: Command,
}

#[doc = "控制命令枚举。"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Command {
    #[doc = "启动 Probe。"]
    StartProbe,
    #[doc = "停止 Probe。"]
    StopProbe,
    #[doc = "拉取日志。"]
    FetchLogs,
}

#[doc = "消息负载：覆盖 Doc-06 中的核心消息类型。"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessagePayload {
    #[doc = "空负载。"]
    Empty,
    #[doc = "系统信息。"]
    SystemInfo(SystemInfo),
    #[doc = "进程信息（包含 Fix 1: exec_id）。"]
    ProcessInfo(ProcessInfo),
    #[doc = "文件信息。"]
    FileInfo(FileInfo),
    #[doc = "网络接口更新（Fix 5）。"]
    NetworkInterfaceUpdate(NetworkInterfaceUpdate),
    #[doc = "探针遥测心跳（Fix 6）。"]
    AgentTelemetry(AgentTelemetry),
}

#[doc = "Doc-06: SystemInfo。"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_version: String,
    pub kernel_version: String,
    pub ip_addresses: Vec<String>,
    pub boot_time: i64,
}

#[doc = "Doc-06: ProcessInfo（Fix 1: exec_id）。"]
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

#[doc = "Doc-06: FileInfo。"]
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

#[doc = "Doc-06: NetworkInterfaceUpdate（Fix 5）。"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInterfaceUpdate {
    pub timestamp: i64,
    pub new_ip_addresses: Vec<String>,
}

#[doc = "Doc-06: AgentTelemetry（Fix 6）。"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentTelemetry {
    pub timestamp: i64,
    pub cpu_usage_percent: u32,
    pub memory_usage_mb: u32,
    pub dropped_events_count: u64,
}
