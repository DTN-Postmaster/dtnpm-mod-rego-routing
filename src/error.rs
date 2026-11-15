//! Error types for `dtnpm-mod-rego-routing`.

use thiserror::Error;

/// Domain errors returned by Rego policy compilation, CBOR codec operations,
/// configuration validation, and persistent storage.
#[derive(Debug, Error)]
pub enum RegoRoutingError {
    /// Failed to encode a BPv7 extension block or metadata slot to CBOR.
    #[error("CBOR encoding error: {0}")]
    CborEncode(String),

    /// Failed to decode a BPv7 extension block or metadata slot from CBOR.
    #[error("CBOR decoding error: {0}")]
    CborDecode(String),

    /// Failed to parse or compile an OPA Rego policy.
    #[error("Rego policy compilation error: {0}")]
    PolicyCompile(String),

    /// Failed to evaluate a compiled Rego policy against input context.
    #[error("Rego policy evaluation error: {0}")]
    PolicyEval(String),

    /// Invalid EID or wildcard blacklist pattern supplied by an operator/admin.
    #[error("Invalid EID pattern: {0}")]
    InvalidEidPattern(String),

    /// Invalid module configuration parameter.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// SQLite storage error.
    #[error("Storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    /// JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<hardy_cbor::decode::Error> for RegoRoutingError {
    fn from(err: hardy_cbor::decode::Error) -> Self {
        Self::CborDecode(err.to_string())
    }
}
