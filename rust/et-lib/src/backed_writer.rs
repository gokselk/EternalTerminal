//! Backed writer for connection recovery
//!
//! This module provides a writer that maintains backup buffers for reconnection scenarios.

use crate::crypto::CryptoHandler;
use crate::error::{Error, Result};
use crate::packet::Packet;
use crate::socket::SocketHandler;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Maximum bytes kept in the recovery backup (64 MB)
const MAX_BACKUP_BYTES: i64 = 64 * 1024 * 1024;

/// Describes whether a write succeeded, was skipped, or partially lost data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteState {
    /// Write attempt skipped because no socket is available
    Skipped,
    /// All bytes were transmitted successfully
    Success,
    /// Some bytes were written but the socket failed before completion
    WroteWithFailure,
}

/// Writes packets to a socket while maintaining an in-memory backup for recovery
pub struct BackedWriter {
    /// Platform socket helper
    socket_handler: Arc<dyn SocketHandler>,
    /// Encryption helper used before storing packets
    crypto_handler: Arc<CryptoHandler>,
    /// Current socket file descriptor for writes
    socket_fd: Mutex<RawFd>,
    /// Buffer of encrypted packets that may need to be replayed
    backup_buffer: Mutex<VecDeque<Packet>>,
    /// Running size of the backup buffer
    backup_size: Mutex<i64>,
    /// Sequence number that increments each time a packet is backed up
    sequence_number: Mutex<i64>,
}

impl BackedWriter {
    /// Creates a writer bound to a socket and crypto pair.
    ///
    /// # Arguments
    /// * `socket_handler` - Handler for socket operations
    /// * `crypto_handler` - Handler for encryption
    /// * `socket_fd` - Initial socket file descriptor
    pub fn new(
        socket_handler: Arc<dyn SocketHandler>,
        crypto_handler: Arc<CryptoHandler>,
        socket_fd: RawFd,
    ) -> Self {
        Self {
            socket_handler,
            crypto_handler,
            socket_fd: Mutex::new(socket_fd),
            backup_buffer: Mutex::new(VecDeque::new()),
            backup_size: Mutex::new(0),
            sequence_number: Mutex::new(0),
        }
    }

    /// Encrypts and transmits the packet while keeping a backup copy.
    ///
    /// # Returns
    /// State describing whether bytes were fully sent or buffered for recovery
    pub fn write(&self, mut packet: Packet) -> WriteState {
        let fd = *self.socket_fd.lock();

        if fd < 0 {
            // We have no socket to write to
            return WriteState::Skipped;
        }

        // Once we encrypt, there's no going back
        if let Err(e) = packet.encrypt(&self.crypto_handler) {
            warn!("Failed to encrypt packet: {}", e);
            return WriteState::WroteWithFailure;
        }

        // Backup the buffer
        {
            let mut backup = self.backup_buffer.lock();
            let mut backup_size = self.backup_size.lock();
            let mut seq = self.sequence_number.lock();

            backup.push_front(packet.clone());
            *backup_size += packet.len() as i64;
            *seq += 1;

            // Cleanup old values
            while *backup_size > MAX_BACKUP_BYTES {
                if let Some(old) = backup.pop_back() {
                    *backup_size -= old.len() as i64;
                }
            }
        }

        // Prepare the message with length header
        let serialized = packet.serialize();
        let message_size = (serialized.len() as i32).to_be_bytes();
        let mut data = Vec::with_capacity(4 + serialized.len());
        data.extend_from_slice(&message_size);
        data.extend_from_slice(&serialized);

        debug!("Message length with header: {}", data.len());

        // Write the data
        let mut bytes_written = 0;
        loop {
            let current_fd = *self.socket_fd.lock();
            if current_fd < 0 {
                return WriteState::WroteWithFailure;
            }

            match self
                .socket_handler
                .write(current_fd, &data[bytes_written..])
            {
                Ok(n) => {
                    bytes_written += n;
                    if bytes_written == data.len() {
                        return WriteState::Success;
                    }
                    std::thread::sleep(Duration::from_micros(1000));
                }
                Err(_) => {
                    // Error, but the caller should think bytes were written
                    return WriteState::WroteWithFailure;
                }
            }
        }
    }

    /// Returns serialized packets that the remote side still needs after reconnect.
    ///
    /// # Arguments
    /// * `last_valid_sequence_number` - Sequence number acknowledged by the remote peer
    pub fn recover(&self, last_valid_sequence_number: i64) -> Result<Vec<Vec<u8>>> {
        let fd = *self.socket_fd.lock();
        if fd >= 0 {
            return Err(Error::Recovery(
                "Can't recover when the fd is still alive".into(),
            ));
        }

        let seq = *self.sequence_number.lock();
        let messages_to_recover = seq - last_valid_sequence_number;

        if messages_to_recover < 0 {
            return Err(Error::Recovery(
                "Client is ahead of server - something went wrong".into(),
            ));
        }

        if messages_to_recover == 0 {
            return Ok(vec![]);
        }

        debug!("Recovering {} messages", messages_to_recover);

        let backup = self.backup_buffer.lock();
        let mut messages_seen = 0i64;
        let mut result = Vec::new();

        for packet in backup.iter() {
            result.push(packet.serialize());
            messages_seen += 1;
            if messages_seen == messages_to_recover {
                result.reverse();
                return Ok(result);
            }
        }

        Err(Error::ClientTooFarBehind)
    }

    /// Points the writer at a new socket fd so writes can resume
    pub fn revive(&self, new_socket_fd: RawFd) {
        *self.socket_fd.lock() = new_socket_fd;
    }

    /// Marks the current socket dead to prevent additional writes
    pub fn invalidate_socket(&self) {
        *self.socket_fd.lock() = -1;
    }

    /// Returns the total number of packets written since construction
    pub fn sequence_number(&self) -> i64 {
        *self.sequence_number.lock()
    }

    /// Get the current socket fd
    pub fn socket_fd(&self) -> RawFd {
        *self.socket_fd.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct MockSocketHandler {
        written: Mutex<Vec<u8>>,
        fail_after: Mutex<Option<usize>>,
    }

    impl MockSocketHandler {
        fn new() -> Self {
            Self {
                written: Mutex::new(Vec::new()),
                fail_after: Mutex::new(None),
            }
        }

        fn get_written(&self) -> Vec<u8> {
            self.written.lock().clone()
        }
    }

    impl SocketHandler for MockSocketHandler {
        fn has_data(&self, _fd: RawFd) -> bool {
            false
        }

        fn read(&self, _fd: RawFd, _buf: &mut [u8]) -> Result<usize> {
            Ok(0)
        }

        fn write(&self, _fd: RawFd, buf: &[u8]) -> Result<usize> {
            let mut fail_after = self.fail_after.lock();
            if let Some(n) = *fail_after {
                if n == 0 {
                    return Err(Error::Connection("Mock failure".into()));
                }
                *fail_after = Some(n - 1);
            }
            self.written.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn connect(&self, _endpoint: &crate::socket::SocketEndpoint) -> Result<RawFd> {
            Ok(1)
        }

        fn listen(&self, _endpoint: &crate::socket::SocketEndpoint) -> Result<HashSet<RawFd>> {
            Ok(HashSet::new())
        }

        fn get_endpoint_fds(
            &self,
            _endpoint: &crate::socket::SocketEndpoint,
        ) -> Option<HashSet<RawFd>> {
            None
        }

        fn accept(&self, _fd: RawFd) -> Result<RawFd> {
            Ok(1)
        }

        fn stop_listening(&self, _endpoint: &crate::socket::SocketEndpoint) -> Result<()> {
            Ok(())
        }

        fn close(&self, _fd: RawFd) {}

        fn get_active_sockets(&self) -> Vec<RawFd> {
            vec![]
        }
    }

    #[test]
    fn test_backed_writer_sequence_number() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());
        let socket = Arc::new(MockSocketHandler::new());
        let writer = BackedWriter::new(socket, crypto, 1);

        assert_eq!(writer.sequence_number(), 0);
    }

    #[test]
    fn test_backed_writer_write() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());
        let socket = Arc::new(MockSocketHandler::new());
        let writer = BackedWriter::new(socket.clone(), crypto, 1);

        let packet = Packet::new(42, b"Hello".to_vec());
        let state = writer.write(packet);

        assert_eq!(state, WriteState::Success);
        assert_eq!(writer.sequence_number(), 1);
        assert!(!socket.get_written().is_empty());
    }

    #[test]
    fn test_backed_writer_skipped() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());
        let socket = Arc::new(MockSocketHandler::new());
        let writer = BackedWriter::new(socket, crypto, -1);

        let packet = Packet::new(42, b"Hello".to_vec());
        let state = writer.write(packet);

        assert_eq!(state, WriteState::Skipped);
        assert_eq!(writer.sequence_number(), 0);
    }

    #[test]
    fn test_backed_writer_invalidate() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());
        let socket = Arc::new(MockSocketHandler::new());
        let writer = BackedWriter::new(socket, crypto, 1);

        assert_eq!(writer.socket_fd(), 1);
        writer.invalidate_socket();
        assert_eq!(writer.socket_fd(), -1);
    }
}
