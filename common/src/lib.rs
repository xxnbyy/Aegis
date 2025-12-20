#![allow(missing_docs)]

pub mod collectors;
pub mod config;
pub mod crypto;
pub mod detection;
pub mod error;
pub mod governor;
pub mod protocol;
pub mod telemetry;

pub use config::{AegisConfig, ConfigManager};
pub use crypto::{decrypt, encrypt};
pub use error::{AegisError, ErrorCode};
