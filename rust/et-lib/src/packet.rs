//! Protocol packet handling
//!
//! This module implements the ET protocol packet format with optional encryption.

use crate::crypto::CryptoHandler;
use crate::error::{Error, Result};
use std::sync::Arc;

/// Header size in bytes (encrypted flag + header byte)
const HEADER_SIZE: usize = 2;

/// Represents a length-encoded protocol packet with optional encryption
#[derive(Debug, Clone)]
pub struct Packet {
    /// Whether the payload is currently encrypted
    encrypted: bool,
    /// Application-specific packet type value
    header: u8,
    /// Message body (encrypted or decrypted depending on flag)
    payload: Vec<u8>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            encrypted: false,
            header: 255,
            payload: Vec::new(),
        }
    }
}

impl Packet {
    /// Creates a new unencrypted packet with the given header and payload
    pub fn new(header: u8, payload: Vec<u8>) -> Self {
        Self {
            encrypted: false,
            header,
            payload,
        }
    }

    /// Creates a new unencrypted packet with the given header and string payload
    pub fn from_str(header: u8, payload: &str) -> Self {
        Self {
            encrypted: false,
            header,
            payload: payload.as_bytes().to_vec(),
        }
    }

    /// Creates a packet with explicit encryption flag
    pub fn with_encrypted(encrypted: bool, header: u8, payload: Vec<u8>) -> Self {
        Self {
            encrypted,
            header,
            payload,
        }
    }

    /// Deserializes a packet from its raw byte representation
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::InvalidPacket("Packet too short".into()));
        }
        Ok(Self {
            encrypted: data[0] != 0,
            header: data[1],
            payload: data[2..].to_vec(),
        })
    }

    /// Decrypts the payload if the encrypted flag is set
    pub fn decrypt(&mut self, crypto: &Arc<CryptoHandler>) -> Result<()> {
        if self.encrypted {
            self.payload = crypto.decrypt(&self.payload)?;
            self.encrypted = false;
            Ok(())
        } else {
            Err(Error::InvalidPacket(
                "Tried to decrypt a packet that wasn't encrypted".into(),
            ))
        }
    }

    /// Encrypts the payload and tags the packet as encrypted
    pub fn encrypt(&mut self, crypto: &Arc<CryptoHandler>) -> Result<()> {
        if self.encrypted {
            Err(Error::InvalidPacket(
                "Tried to encrypt a packet that was already encrypted".into(),
            ))
        } else {
            self.payload = crypto.encrypt(&self.payload);
            self.encrypted = true;
            Ok(())
        }
    }

    /// Returns true if the payload is currently encrypted
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Retrieves the application-specific header byte
    pub fn header(&self) -> u8 {
        self.header
    }

    /// Returns the stored payload (decrypted if needed)
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the packet and returns the payload
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Returns the serialized byte count including the header
    pub fn len(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Returns true if the packet has no payload
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Serializes the header byte and payload into the packet wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        data.push(if self.encrypted { 1 } else { 0 });
        data.push(self.header);
        data.extend_from_slice(&self.payload);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoHandler;

    #[test]
    fn test_packet_serialization() {
        let packet = Packet::new(42, b"Hello".to_vec());
        let serialized = packet.serialize();

        assert_eq!(serialized[0], 0); // not encrypted
        assert_eq!(serialized[1], 42); // header
        assert_eq!(&serialized[2..], b"Hello");

        let deserialized = Packet::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized.header(), 42);
        assert_eq!(deserialized.payload(), b"Hello");
        assert!(!deserialized.is_encrypted());
    }

    #[test]
    fn test_packet_encryption() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());

        let mut packet = Packet::new(42, b"Secret message".to_vec());
        packet.encrypt(&crypto).unwrap();

        assert!(packet.is_encrypted());
        assert_ne!(packet.payload(), b"Secret message");

        // Create a new crypto handler for decryption (same key, same nonce MSB)
        let crypto_decrypt = Arc::new(CryptoHandler::new(&key, 0).unwrap());
        packet.decrypt(&crypto_decrypt).unwrap();

        assert!(!packet.is_encrypted());
        assert_eq!(packet.payload(), b"Secret message");
    }

    #[test]
    fn test_packet_length() {
        let packet = Packet::new(0, vec![1, 2, 3, 4, 5]);
        assert_eq!(packet.len(), 7); // 2 header + 5 payload
    }
}
