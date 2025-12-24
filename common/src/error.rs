use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Crypto003,
    Probe101,
    Probe201,
    Console701,
    Console702,
    Console703,
    Console711,
    Console721,
    Console722,
    Console731,
    Console732,
    Console733,
    Plugin501,
    Plugin502,
    Ai301,
    Ai302,
    Ai303,
    Ai399,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Crypto003 => "AEGIS-CRYPTO-003",
            ErrorCode::Probe101 => "AEGIS-PROBE-101",
            ErrorCode::Probe201 => "AEGIS-PROBE-201",
            ErrorCode::Console701 => "AEGIS-CONSOLE-701",
            ErrorCode::Console702 => "AEGIS-CONSOLE-702",
            ErrorCode::Console703 => "AEGIS-CONSOLE-703",
            ErrorCode::Console711 => "AEGIS-CONSOLE-711",
            ErrorCode::Console721 => "AEGIS-CONSOLE-721",
            ErrorCode::Console722 => "AEGIS-CONSOLE-722",
            ErrorCode::Console731 => "AEGIS-CONSOLE-731",
            ErrorCode::Console732 => "AEGIS-CONSOLE-732",
            ErrorCode::Console733 => "AEGIS-CONSOLE-733",
            ErrorCode::Plugin501 => "AEGIS-PLUGIN-501",
            ErrorCode::Plugin502 => "AEGIS-PLUGIN-502",
            ErrorCode::Ai301 => "AEGIS-AI-301",
            ErrorCode::Ai302 => "AEGIS-AI-302",
            ErrorCode::Ai303 => "AEGIS-AI-303",
            ErrorCode::Ai399 => "AEGIS-AI-399",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AegisError {
    #[error("协议错误: {message}")]
    ProtocolError {
        message: String,
        code: Option<ErrorCode>,
    },

    #[error("加密错误: {message}")]
    CryptoError {
        message: String,
        code: Option<ErrorCode>,
    },

    #[error("IO 错误: {0}")]
    IoError(#[from] std::io::Error),

    #[error("配置错误: {message}")]
    ConfigError { message: String },

    #[error("Packet size {size} exceeds limit {limit}")]
    PacketTooLarge { size: usize, limit: usize },
}

impl From<getrandom::Error> for AegisError {
    fn from(err: getrandom::Error) -> Self {
        AegisError::CryptoError {
            message: err.to_string(),
            code: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorCode;

    #[test]
    fn error_codes_match_doc18() {
        let cases = [
            (ErrorCode::Probe101, "AEGIS-PROBE-101"),
            (ErrorCode::Probe201, "AEGIS-PROBE-201"),
            (ErrorCode::Console701, "AEGIS-CONSOLE-701"),
            (ErrorCode::Console702, "AEGIS-CONSOLE-702"),
            (ErrorCode::Console703, "AEGIS-CONSOLE-703"),
            (ErrorCode::Console711, "AEGIS-CONSOLE-711"),
            (ErrorCode::Console721, "AEGIS-CONSOLE-721"),
            (ErrorCode::Console722, "AEGIS-CONSOLE-722"),
            (ErrorCode::Console731, "AEGIS-CONSOLE-731"),
            (ErrorCode::Console732, "AEGIS-CONSOLE-732"),
            (ErrorCode::Console733, "AEGIS-CONSOLE-733"),
            (ErrorCode::Plugin501, "AEGIS-PLUGIN-501"),
            (ErrorCode::Plugin502, "AEGIS-PLUGIN-502"),
            (ErrorCode::Ai301, "AEGIS-AI-301"),
            (ErrorCode::Ai302, "AEGIS-AI-302"),
            (ErrorCode::Ai303, "AEGIS-AI-303"),
            (ErrorCode::Ai399, "AEGIS-AI-399"),
            (ErrorCode::Crypto003, "AEGIS-CRYPTO-003"),
        ];

        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
            assert!(code.as_str().starts_with("AEGIS-"));
        }
    }
}
