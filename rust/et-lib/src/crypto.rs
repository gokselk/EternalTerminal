//! Cryptography handling using libsodium secretbox
//!
//! This module provides thread-safe encryption and decryption using
//! libsodium's secretbox (XChaCha20-Poly1305).

use crate::error::{Error, Result};
use parking_lot::Mutex;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce, KEYBYTES, MACBYTES, NONCEBYTES};

/// Thread-safe cryptographic handler for ET protocol
///
/// Uses libsodium's secretbox (XChaCha20-Poly1305) for authenticated encryption.
/// Maintains separate nonce tracking per direction (client->server, server->client).
pub struct CryptoHandler {
    /// The shared secret key
    key: Key,
    /// Current nonce value (incremented after each operation)
    nonce: Mutex<[u8; NONCEBYTES]>,
}

impl CryptoHandler {
    /// Creates a new CryptoHandler with the given key and nonce MSB.
    ///
    /// # Arguments
    /// * `key` - Exactly 32 bytes of shared key material
    /// * `nonce_msb` - Most significant byte used to distinguish client/server streams
    ///
    /// # Errors
    /// Returns an error if the key length is not exactly 32 bytes.
    pub fn new(key: &[u8], nonce_msb: u8) -> Result<Self> {
        // Initialize sodiumoxide
        sodiumoxide::init()
            .map_err(|_| Error::Crypto("Failed to initialize sodiumoxide".into()))?;

        if key.len() != KEYBYTES {
            return Err(Error::InvalidKeyLength {
                expected: KEYBYTES,
                got: key.len(),
            });
        }

        let key = Key::from_slice(key).ok_or_else(|| Error::Crypto("Invalid key".into()))?;

        // Initialize nonce with zeros, set the MSB at the last position
        let mut nonce = [0u8; NONCEBYTES];
        nonce[NONCEBYTES - 1] = nonce_msb;

        Ok(Self {
            key,
            nonce: Mutex::new(nonce),
        })
    }

    /// Generates a random key suitable for use with CryptoHandler
    pub fn generate_key() -> Vec<u8> {
        sodiumoxide::init().ok();
        secretbox::gen_key().0.to_vec()
    }

    /// Encrypts a plaintext buffer.
    ///
    /// Advances the nonce after encryption to ensure unique nonces for each message.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    /// The ciphertext including the MAC (authentication tag)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_guard = self.nonce.lock();
        self.increment_nonce(&mut nonce_guard);
        let nonce = Nonce::from_slice(&nonce_guard[..]).expect("Invalid nonce size");
        secretbox::seal(plaintext, &nonce, &self.key)
    }

    /// Decrypts a ciphertext buffer.
    ///
    /// Advances the nonce after decryption to stay synchronized with the sender.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data including the MAC
    ///
    /// # Returns
    /// The original plaintext
    ///
    /// # Errors
    /// Returns an error if decryption fails (authentication failure or key mismatch)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_guard = self.nonce.lock();
        self.increment_nonce(&mut nonce_guard);
        let nonce = Nonce::from_slice(&nonce_guard[..]).expect("Invalid nonce size");
        secretbox::open(ciphertext, &nonce, &self.key).map_err(|_| Error::DecryptionFailed)
    }

    /// Returns the MAC size added to each encrypted message
    pub const fn mac_bytes() -> usize {
        MACBYTES
    }

    /// Returns the required key size
    pub const fn key_bytes() -> usize {
        KEYBYTES
    }

    /// Increments the nonce to guarantee unique per-message secretbox input.
    ///
    /// Uses little-endian increment with carry propagation.
    fn increment_nonce(&self, nonce: &mut [u8; NONCEBYTES]) {
        for byte in nonce.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                // No overflow, stop propagating
                break;
            }
            // byte wrapped to 0, continue to next byte (carry)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = CryptoHandler::generate_key();
        let crypto_client = CryptoHandler::new(&key, 0).unwrap();
        let crypto_server = CryptoHandler::new(&key, 0).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = crypto_client.encrypt(plaintext);

        // Ciphertext should be larger due to MAC
        assert_eq!(ciphertext.len(), plaintext.len() + MACBYTES);

        let decrypted = crypto_server.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nonce_mismatch() {
        let key = CryptoHandler::generate_key();
        let crypto1 = CryptoHandler::new(&key, 0).unwrap();
        let crypto2 = CryptoHandler::new(&key, 1).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = crypto1.encrypt(plaintext);

        // Decryption should fail due to different nonce MSB
        assert!(crypto2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = vec![0u8; 16];
        assert!(CryptoHandler::new(&short_key, 0).is_err());
    }

    #[test]
    fn test_multiple_messages() {
        let key = CryptoHandler::generate_key();
        let crypto_client = CryptoHandler::new(&key, 0).unwrap();
        let crypto_server = CryptoHandler::new(&key, 0).unwrap();

        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let ciphertext = crypto_client.encrypt(plaintext.as_bytes());
            let decrypted = crypto_server.decrypt(&ciphertext).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }
}
