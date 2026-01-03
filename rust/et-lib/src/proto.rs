//! Protocol buffer message types
//!
//! This module includes the generated protobuf types for the ET protocol.

pub mod et {
    include!(concat!(env!("OUT_DIR"), "/et.rs"));
}

pub use et::*;

/// Packet type constants matching the C++ enum values
pub mod packet_type {
    /// Heartbeat packet type
    pub const HEARTBEAT: u8 = 254;
    /// Initial payload packet type
    pub const INITIAL_PAYLOAD: u8 = 253;
    /// Initial response packet type
    pub const INITIAL_RESPONSE: u8 = 252;
}

/// Terminal packet type constants
pub mod terminal_packet_type {
    /// Keep alive packet
    pub const KEEP_ALIVE: u8 = 0;
    /// Terminal buffer data
    pub const TERMINAL_BUFFER: u8 = 1;
    /// Terminal info (size, etc.)
    pub const TERMINAL_INFO: u8 = 2;
    /// Port forward destination request
    pub const PORT_FORWARD_DESTINATION_REQUEST: u8 = 5;
    /// Port forward destination response
    pub const PORT_FORWARD_DESTINATION_RESPONSE: u8 = 6;
    /// Port forward data
    pub const PORT_FORWARD_DATA: u8 = 7;
    /// Terminal user info
    pub const TERMINAL_USER_INFO: u8 = 8;
    /// Terminal init
    pub const TERMINAL_INIT: u8 = 9;
    /// Jumphost init
    pub const JUMPHOST_INIT: u8 = 10;
}
