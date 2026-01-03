//! Connection management with automatic recovery
//!
//! This module provides buffered client/server connections with automatic reconnection support.

use crate::backed_reader::BackedReader;
use crate::backed_writer::{BackedWriter, WriteState};
use crate::crypto::CryptoHandler;
use crate::error::{Error, Result};
use crate::packet::Packet;
use crate::proto::{CatchupBuffer, SequenceHeader};
use crate::socket::{SocketHandler, SocketHandlerExt};
use parking_lot::RwLock;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Check if an error is skippable (connection can be recovered)
fn is_skippable_error(err: &Error) -> bool {
    match err {
        Error::Io(e) => matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::ConnectionAborted
        ),
        Error::Nix(e) => {
            // Check against raw OS error codes for nix errors
            let errno = *e as i32;
            matches!(
                errno,
                libc::EAGAIN
                    | libc::ECONNRESET
                    | libc::ETIMEDOUT
                    | libc::EHOSTUNREACH
                    | libc::EPIPE
                    | libc::ENOTCONN
                    | libc::ECONNABORTED
                    | libc::EBADF
            )
        }
        Error::ConnectionClosed => true,
        _ => false,
    }
}

/// Represents a buffered client/server connection with automatic recovery
pub struct Connection {
    /// Socket API used by all derived connection types
    socket_handler: Arc<dyn SocketHandler>,
    /// Logical identifier for this connection
    id: String,
    /// Shared secret key used to seed per-direction crypto handlers
    key: String,
    /// Reader that understands reconnect buffers
    reader: Option<Arc<BackedReader>>,
    /// Writer that records packets for replay on reconnect
    writer: Option<Arc<BackedWriter>>,
    /// Active socket descriptor, -1 when no connection exists
    socket_fd: RwLock<RawFd>,
    /// Flag that is set when shutdown has been called
    shutting_down: RwLock<bool>,
}

impl Connection {
    /// Creates a new connection with the given socket handler, id, and key.
    pub fn new(
        socket_handler: Arc<dyn SocketHandler>,
        id: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            socket_handler,
            id: id.into(),
            key: key.into(),
            reader: None,
            writer: None,
            socket_fd: RwLock::new(-1),
            shutting_down: RwLock::new(false),
        }
    }

    /// Initialize the reader and writer with the given socket fd
    pub fn initialize(&mut self, socket_fd: RawFd, nonce_msb: u8) -> Result<()> {
        let crypto_reader = Arc::new(CryptoHandler::new(self.key.as_bytes(), nonce_msb)?);
        let crypto_writer = Arc::new(CryptoHandler::new(
            self.key.as_bytes(),
            if nonce_msb == 0 { 1 } else { 0 },
        )?);

        self.reader = Some(Arc::new(BackedReader::new(
            self.socket_handler.clone(),
            crypto_reader,
            socket_fd,
        )));

        self.writer = Some(Arc::new(BackedWriter::new(
            self.socket_handler.clone(),
            crypto_writer,
            socket_fd,
        )));

        *self.socket_fd.write() = socket_fd;
        Ok(())
    }

    /// Thread-safe entry point that reads a packet if available
    pub fn read_packet(&self) -> Result<Option<Packet>> {
        if *self.shutting_down.read() {
            return Ok(None);
        }
        self.read()
    }

    /// Repeatedly writes a packet until success or shutdown
    pub fn write_packet(&self, packet: Packet) {
        loop {
            if *self.shutting_down.read() {
                break;
            }

            if self.write(&packet) {
                return;
            }

            let has_connection = *self.socket_fd.read() != -1;

            if has_connection {
                std::thread::sleep(Duration::from_micros(1000));
            } else {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// Attempts to read one packet without looping
    pub fn read(&self) -> Result<Option<Packet>> {
        let reader = match &self.reader {
            Some(r) => r,
            None => {
                debug!("Cannot read: reader not initialized");
                return Ok(None);
            }
        };

        match reader.read() {
            Ok(packet) => Ok(packet),
            Err(e) if is_skippable_error(&e) => {
                info!("Closing socket due to: {}", e);
                self.close_socket_and_maybe_reconnect();
                Ok(None)
            }
            Err(e) => {
                warn!("Got a serious error trying to read: {}", e);
                Err(e)
            }
        }
    }

    /// Tries to write once and returns whether the call succeeded
    pub fn write(&self, packet: &Packet) -> bool {
        if *self.socket_fd.read() == -1 {
            return false;
        }

        let writer = match &self.writer {
            Some(w) => w,
            None => {
                debug!("Cannot write: writer not initialized");
                return false;
            }
        };

        match writer.write(packet.clone()) {
            WriteState::Skipped => false,
            WriteState::Success => true,
            WriteState::WroteWithFailure => {
                let fd = *self.socket_fd.read();
                if fd == -1 {
                    debug!("Socket closed");
                } else {
                    debug!("Connection is severed");
                    self.close_socket_and_maybe_reconnect();
                }
                true
            }
        }
    }

    /// Get the reader
    pub fn reader(&self) -> Option<Arc<BackedReader>> {
        self.reader.clone()
    }

    /// Get the writer
    pub fn writer(&self) -> Option<Arc<BackedWriter>> {
        self.writer.clone()
    }

    /// File descriptor of the currently connected socket or -1
    pub fn socket_fd(&self) -> RawFd {
        *self.socket_fd.read()
    }

    /// Get the socket handler
    pub fn socket_handler(&self) -> Arc<dyn SocketHandler> {
        self.socket_handler.clone()
    }

    /// Returns true if disconnected
    pub fn is_disconnected(&self) -> bool {
        *self.socket_fd.read() == -1
    }

    /// Get the connection id
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns true if there is data to read
    pub fn has_data(&self) -> bool {
        self.reader.as_ref().map(|r| r.has_data()).unwrap_or(false)
    }

    /// Closes the socket and invalidates the reader/writer
    pub fn close_socket(&self) {
        let fd = {
            let mut socket_fd = self.socket_fd.write();
            if *socket_fd == -1 {
                info!("Tried to close a dead socket");
                return;
            }

            if let Some(reader) = &self.reader {
                reader.invalidate_socket();
            }
            if let Some(writer) = &self.writer {
                writer.invalidate_socket();
            }

            let fd = *socket_fd;
            *socket_fd = -1;
            fd
        };

        self.socket_handler.close(fd);
        debug!("Closed socket");
    }

    /// Override to trigger reconnect behavior after closing the socket.
    /// The default simply closes the socket and does not reconnect.
    pub fn close_socket_and_maybe_reconnect(&self) {
        self.close_socket();
    }

    /// Signals that the connection should stop and tears down resources
    pub fn shutdown(&self) {
        info!("Shutting down connection");
        *self.shutting_down.write() = true;
        self.close_socket();
    }

    /// Returns true if the connection is shutting down
    pub fn is_shutting_down(&self) -> bool {
        *self.shutting_down.read()
    }

    /// Exchanges sequence headers and catchup buffers with a peer for recovery
    pub fn recover(&self, new_socket_fd: RawFd) -> Result<bool> {
        info!("Recovering with socket fd {}...", new_socket_fd);

        let reader = self
            .reader
            .as_ref()
            .ok_or_else(|| Error::Recovery("Reader not initialized".into()))?;
        let writer = self
            .writer
            .as_ref()
            .ok_or_else(|| Error::Recovery("Writer not initialized".into()))?;

        // Write the current sequence number
        let sh = SequenceHeader {
            sequence_number: reader.sequence_number() as i32,
        };
        self.socket_handler.write_proto(new_socket_fd, &sh, true)?;

        // Read the remote sequence number
        let remote_header: SequenceHeader = self.socket_handler.read_proto(new_socket_fd, true)?;

        // Fetch the catchup bytes and send
        let recovered_messages = writer.recover(remote_header.sequence_number as i64)?;
        let catchup_buffer = CatchupBuffer {
            buffer: recovered_messages,
        };
        self.socket_handler
            .write_proto(new_socket_fd, &catchup_buffer, true)?;

        // Read remote catchup buffer
        let remote_catchup: CatchupBuffer = self.socket_handler.read_proto(new_socket_fd, true)?;

        // Update socket fd
        *self.socket_fd.write() = new_socket_fd;

        // Revive reader and writer
        reader.revive(new_socket_fd, remote_catchup.buffer);
        writer.revive(new_socket_fd);

        info!("Finished recovering with socket fd: {}", new_socket_fd);
        Ok(true)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !*self.shutting_down.read() {
            warn!("Call shutdown before destructing a Connection.");
        }
        if *self.socket_fd.read() != -1 {
            info!("Connection destroyed");
            self.close_socket();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_new() {
        use crate::socket::TcpSocketHandler;
        let handler = Arc::new(TcpSocketHandler::new());
        let conn = Connection::new(handler, "test-id", "12345678901234567890123456789012");

        assert_eq!(conn.id(), "test-id");
        assert!(conn.is_disconnected());
        assert!(!conn.is_shutting_down());
    }

    #[test]
    fn test_connection_shutdown() {
        use crate::socket::TcpSocketHandler;
        let handler = Arc::new(TcpSocketHandler::new());
        let conn = Connection::new(handler, "test-id", "12345678901234567890123456789012");

        assert!(!conn.is_shutting_down());
        conn.shutdown();
        assert!(conn.is_shutting_down());
    }
}
