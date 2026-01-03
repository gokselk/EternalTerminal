//! Backed reader for connection recovery
//!
//! This module provides a reader that maintains replay buffers for reconnection scenarios.

use crate::crypto::CryptoHandler;
use crate::error::{Error, Result};
use crate::packet::Packet;
use crate::socket::SocketHandler;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tracing::debug;

/// Reads packets from a socket while preserving enough state to replay
/// any messages after reconnecting.
pub struct BackedReader {
    /// Handler that interfaces with the platform socket API
    socket_handler: Arc<dyn SocketHandler>,
    /// Responsible for decrypting packets once they arrive
    crypto_handler: Arc<CryptoHandler>,
    /// Current socket file descriptor (-1 when disconnected)
    socket_fd: Mutex<RawFd>,
    /// Packet sequence counter that increments for every read packet
    sequence_number: Mutex<i64>,
    /// Serialized packets cached to be drained before resuming live reads
    local_buffer: Mutex<VecDeque<Vec<u8>>>,
    /// Buffer for accumulating length-prefixed packet data from the socket
    partial_message: Mutex<Vec<u8>>,
}

impl BackedReader {
    /// Constructs a reader bound to the supplied socket and crypto handlers.
    ///
    /// # Arguments
    /// * `socket_handler` - Handler that performs the underlying socket operations
    /// * `crypto_handler` - Handler used to decrypt packets once they are received
    /// * `socket_fd` - Initial socket file descriptor to read from
    pub fn new(
        socket_handler: Arc<dyn SocketHandler>,
        crypto_handler: Arc<CryptoHandler>,
        socket_fd: RawFd,
    ) -> Self {
        Self {
            socket_handler,
            crypto_handler,
            socket_fd: Mutex::new(socket_fd),
            sequence_number: Mutex::new(0),
            local_buffer: Mutex::new(VecDeque::new()),
            partial_message: Mutex::new(Vec::new()),
        }
    }

    /// Returns true if there is buffered data or the current socket is readable.
    pub fn has_data(&self) -> bool {
        let fd = *self.socket_fd.lock();
        if fd < 0 {
            return false;
        }

        if !self.local_buffer.lock().is_empty() {
            return true;
        }

        self.socket_handler.has_data(fd)
    }

    /// Reads the next packet from the local buffer or socket, decrypting it.
    ///
    /// # Returns
    /// * `Ok(Some(packet))` - A complete packet was read
    /// * `Ok(None)` - More bytes are required (partial read)
    /// * `Err(_)` - Fatal socket error
    pub fn read(&self) -> Result<Option<Packet>> {
        let fd = *self.socket_fd.lock();
        if fd < 0 {
            debug!("Tried to read from a dead socket");
            return Ok(None);
        }

        // Check local buffer first
        {
            let mut local_buffer = self.local_buffer.lock();
            if !local_buffer.is_empty() {
                debug!("Reading from local buffer");
                let data = local_buffer.pop_front().unwrap();
                debug!("New local buffer size: {}", local_buffer.len());
                drop(local_buffer);

                let mut packet = Packet::from_bytes(&data)?;
                packet.decrypt(&self.crypto_handler)?;
                return Ok(Some(packet));
            }
        }

        // Read from the socket
        let mut partial = self.partial_message.lock();

        // Read the header (4 bytes for message length)
        if partial.len() < 4 {
            let mut tmp_buf = [0u8; 4];
            let bytes_needed = 4 - partial.len();
            match self.socket_handler.read(fd, &mut tmp_buf[..bytes_needed]) {
                Ok(0) => {
                    // Connection closed
                    return Err(Error::ConnectionClosed);
                }
                Ok(n) => {
                    partial.extend_from_slice(&tmp_buf[..n]);
                }
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }

        if partial.len() < 4 {
            // Didn't get the full header yet
            return Ok(None);
        }

        // Parse message length
        let message_length = self.get_partial_message_length(&partial)?;
        debug!("Reading message of length: {}", message_length);

        let total_needed = 4 + message_length;
        let message_remainder = total_needed - partial.len();

        if message_remainder > 0 {
            debug!("bytes remaining: {}", message_remainder);
            let mut buf = vec![0u8; message_remainder];
            match self.socket_handler.read(fd, &mut buf) {
                Ok(0) => {
                    return Err(Error::ConnectionClosed);
                }
                Ok(n) => {
                    partial.extend_from_slice(&buf[..n]);
                }
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }

        // Check if we have the complete message
        if partial.len() == total_needed {
            let packet = self.construct_partial_message(&mut partial)?;
            return Ok(Some(packet));
        }

        Ok(None)
    }

    /// Returns the sequence number (count of packets processed)
    pub fn sequence_number(&self) -> i64 {
        *self.sequence_number.lock()
    }

    /// Resumes the reader on a new socket and queues any serialized packets
    /// that should be replayed before fresh reads.
    pub fn revive(&self, new_socket_fd: RawFd, new_local_entries: Vec<Vec<u8>>) {
        self.partial_message.lock().clear();

        let mut local_buffer = self.local_buffer.lock();
        local_buffer.extend(new_local_entries.iter().cloned());

        let mut seq = self.sequence_number.lock();
        *seq += new_local_entries.len() as i64;

        *self.socket_fd.lock() = new_socket_fd;
    }

    /// Marks the reader as disconnected so callers stop issuing reads.
    pub fn invalidate_socket(&self) {
        *self.socket_fd.lock() = -1;
    }

    /// Get the current socket fd
    pub fn socket_fd(&self) -> RawFd {
        *self.socket_fd.lock()
    }

    /// Parse the message length from the partial buffer
    fn get_partial_message_length(&self, partial: &[u8]) -> Result<usize> {
        if partial.len() < 4 {
            return Err(Error::Protocol(
                "Tried to construct a message header that wasn't complete".into(),
            ));
        }
        let message_size = i32::from_be_bytes([partial[0], partial[1], partial[2], partial[3]]);
        Ok(message_size as usize)
    }

    /// Finalizes a complete message and decrypts it into a packet
    fn construct_partial_message(&self, partial: &mut Vec<u8>) -> Result<Packet> {
        let message_size = self.get_partial_message_length(partial)?;

        if partial.len() - 4 != message_size {
            return Err(Error::Protocol(format!(
                "Tried to construct a message that wasn't complete or over-filled: {} != {}",
                partial.len() - 4,
                message_size
            )));
        }

        let serialized_packet: Vec<u8> = partial.drain(4..).collect();
        partial.clear();

        let mut packet = Packet::from_bytes(&serialized_packet)?;
        packet.decrypt(&self.crypto_handler)?;

        *self.sequence_number.lock() += 1;

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct MockSocketHandler {
        data: Mutex<Vec<u8>>,
        read_pos: Mutex<usize>,
    }

    impl MockSocketHandler {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: Mutex::new(data),
                read_pos: Mutex::new(0),
            }
        }
    }

    impl SocketHandler for MockSocketHandler {
        fn has_data(&self, _fd: RawFd) -> bool {
            let pos = *self.read_pos.lock();
            pos < self.data.lock().len()
        }

        fn read(&self, _fd: RawFd, buf: &mut [u8]) -> Result<usize> {
            let data = self.data.lock();
            let mut pos = self.read_pos.lock();
            let remaining = data.len() - *pos;
            let to_read = remaining.min(buf.len());
            buf[..to_read].copy_from_slice(&data[*pos..*pos + to_read]);
            *pos += to_read;
            Ok(to_read)
        }

        fn write(&self, _fd: RawFd, _buf: &[u8]) -> Result<usize> {
            unimplemented!()
        }

        fn connect(&self, _endpoint: &crate::socket::SocketEndpoint) -> Result<RawFd> {
            unimplemented!()
        }

        fn listen(&self, _endpoint: &crate::socket::SocketEndpoint) -> Result<HashSet<RawFd>> {
            unimplemented!()
        }

        fn get_endpoint_fds(
            &self,
            _endpoint: &crate::socket::SocketEndpoint,
        ) -> Option<HashSet<RawFd>> {
            unimplemented!()
        }

        fn accept(&self, _fd: RawFd) -> Result<RawFd> {
            unimplemented!()
        }

        fn stop_listening(&self, _endpoint: &crate::socket::SocketEndpoint) -> Result<()> {
            unimplemented!()
        }

        fn close(&self, _fd: RawFd) {}

        fn get_active_sockets(&self) -> Vec<RawFd> {
            vec![]
        }
    }

    #[test]
    fn test_backed_reader_sequence_number() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());
        let socket = Arc::new(MockSocketHandler::new(vec![]));
        let reader = BackedReader::new(socket, crypto, 1);

        assert_eq!(reader.sequence_number(), 0);
    }

    #[test]
    fn test_backed_reader_invalidate() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());
        let socket = Arc::new(MockSocketHandler::new(vec![]));
        let reader = BackedReader::new(socket, crypto, 1);

        assert_eq!(reader.socket_fd(), 1);
        reader.invalidate_socket();
        assert_eq!(reader.socket_fd(), -1);
    }
}
