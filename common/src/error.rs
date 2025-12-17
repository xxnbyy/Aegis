use std::fmt;

#[doc = "Doc-18 对齐的错误码标识。"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    #[doc = "AEGIS-CRYPTO-003: SystemInfo 块缺失或顺序错误。"]
    Crypto003,
    #[doc = "AEGIS-PROBE-101: VSS 快照创建失败。"]
    Probe101,
    #[doc = "AEGIS-PROBE-201: eBPF 加载被拒绝。"]
    Probe201,
    #[doc = "AEGIS-PLUGIN-501: Native 插件签名校验失败。"]
    Plugin501,
    #[doc = "AEGIS-PLUGIN-502: Wasm 插件尝试越权操作。"]
    Plugin502,
    #[doc = "AEGIS-AI-301: LLM 连接超时。"]
    Ai301,
    #[doc = "AEGIS-AI-399: AI 输出命中安全过滤器。"]
    Ai399,
}

impl ErrorCode {
    #[doc = "返回规范化错误码字符串。"]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Crypto003 => "AEGIS-CRYPTO-003",
            ErrorCode::Probe101 => "AEGIS-PROBE-101",
            ErrorCode::Probe201 => "AEGIS-PROBE-201",
            ErrorCode::Plugin501 => "AEGIS-PLUGIN-501",
            ErrorCode::Plugin502 => "AEGIS-PLUGIN-502",
            ErrorCode::Ai301 => "AEGIS-AI-301",
            ErrorCode::Ai399 => "AEGIS-AI-399",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[doc = "Aegis 的统一错误类型。"]
#[derive(thiserror::Error, Debug)]
pub enum AegisError {
    #[doc = "协议错误。"]
    #[error("协议错误: {message}")]
    ProtocolError {
        message: String,
        code: Option<ErrorCode>,
    },

    #[doc = "加密错误。"]
    #[error("加密错误: {message}")]
    CryptoError {
        message: String,
        code: Option<ErrorCode>,
    },

    #[doc = "IO 错误。"]
    #[error("IO 错误: {0}")]
    IoError(#[from] std::io::Error),

    #[doc = "配置错误。"]
    #[error("配置错误: {message}")]
    ConfigError { message: String },
}

impl From<getrandom::Error> for AegisError {
    fn from(err: getrandom::Error) -> Self {
        AegisError::CryptoError {
            message: err.to_string(),
            code: None,
        }
    }
}
