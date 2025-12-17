#![allow(missing_docs)]

pub mod crypto;
pub mod error;
pub mod protocol;

pub use crypto::{decrypt, encrypt};
pub use error::{AegisError, ErrorCode};
