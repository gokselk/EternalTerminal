//! Error types for the ET library

use thiserror::Error;

/// Main error type for the ET library
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptography error
    #[error("Cryptography error: {0}")]
    Crypto(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Socket error
    #[error("Socket error: {0}")]
    Socket(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    /// Decryption failed
    #[error("Decryption failed - possible key mismatch")]
    DecryptionFailed,

    /// Invalid packet
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Invalid message size
    #[error("Invalid message size: {0}")]
    InvalidMessageSize(i64),

    /// Protobuf error
    #[error("Protobuf error: {0}")]
    Protobuf(#[from] prost::DecodeError),

    /// Connection closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Client too far behind
    #[error("Client is too far behind server during recovery")]
    ClientTooFarBehind,

    /// Recovery error
    #[error("Recovery error: {0}")]
    Recovery(String),

    /// Address resolution error
    #[error("Address resolution error: {0}")]
    AddressResolution(String),

    /// Nix error (Unix-specific)
    #[error("System error: {0}")]
    Nix(#[from] nix::Error),
}

/// Result type alias for the ET library
pub type Result<T> = std::result::Result<T, Error>;
