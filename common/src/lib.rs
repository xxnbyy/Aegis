#![doc = "Aegis 通用基础库：协议类型、错误类型与加密原语。"]

#[doc = "加密模块：提供基于 XChaCha20-Poly1305 的加密与解密。"]
pub mod crypto;

#[doc = "错误模块：全局错误类型与错误码。"]
pub mod error;

#[doc = "协议模块：用于 Probe/Console 之间的消息结构定义。"]
pub mod protocol;

pub use crypto::{decrypt, encrypt};
pub use error::{AegisError, ErrorCode};
