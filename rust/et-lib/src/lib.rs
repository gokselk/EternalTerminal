//! Eternal Terminal core library
//!
//! This library provides the core functionality for the Eternal Terminal protocol,
//! including cryptography, connection management, and packet handling.

pub mod backed_reader;
pub mod backed_writer;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod packet;
pub mod proto;
pub mod socket;

pub use backed_reader::BackedReader;
pub use backed_writer::BackedWriter;
pub use connection::Connection;
pub use crypto::CryptoHandler;
pub use error::{Error, Result};
pub use packet::Packet;

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: i32 = 6;

/// Default port for ET server
pub const DEFAULT_PORT: u16 = 2022;

/// Nonce MSB constants to distinguish client/server streams
pub mod nonce {
    /// Client to server nonce MSB
    pub const CLIENT_SERVER: u8 = 0;
    /// Server to client nonce MSB
    pub const SERVER_CLIENT: u8 = 1;
}
