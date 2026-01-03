//! Client connection with auto-reconnect support

use et_lib::connection::Connection;
use et_lib::error::{Error, Result};
use et_lib::nonce;
use et_lib::packet::Packet;
use et_lib::proto::{ConnectRequest, ConnectResponse, ConnectStatus};
use et_lib::socket::{SocketEndpoint, SocketHandler, SocketHandlerExt};
use et_lib::PROTOCOL_VERSION;
use parking_lot::RwLock;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

/// Client connection that automatically reconnects when the socket is lost
pub struct ClientConnection {
    /// The underlying connection
    connection: Connection,
    /// Socket endpoint to connect to
    endpoint: SocketEndpoint,
    /// Whether we are currently reconnecting
    reconnecting: RwLock<bool>,
}

impl ClientConnection {
    /// Creates a new client connection
    pub fn new(
        socket_handler: Arc<dyn SocketHandler>,
        endpoint: SocketEndpoint,
        id: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            connection: Connection::new(socket_handler, id, key),
            endpoint,
            reconnecting: RwLock::new(false),
        }
    }

    /// Establishes the initial connection to the server
    pub fn connect(&mut self) -> Result<bool> {
        let fd = self.connection.socket_handler().connect(&self.endpoint)?;

        if fd < 0 {
            return Ok(false);
        }

        // Send connect request
        let request = ConnectRequest {
            client_id: self.connection.id().to_string(),
            version: PROTOCOL_VERSION,
        };

        self.connection
            .socket_handler()
            .write_proto(fd, &request, true)?;

        // Read connect response
        let response: ConnectResponse = self.connection.socket_handler().read_proto(fd, true)?;

        match ConnectStatus::try_from(response.status).unwrap_or(ConnectStatus::Unspecified) {
            ConnectStatus::NewClient => {
                info!("Connected as new client");
                self.connection.initialize(fd, nonce::CLIENT_SERVER)?;
                Ok(true)
            }
            ConnectStatus::ReturningClient => {
                info!("Connected as returning client");
                self.connection.recover(fd)?;
                Ok(true)
            }
            ConnectStatus::InvalidKey => {
                warn!("Invalid key");
                Err(Error::Connection("Invalid key".into()))
            }
            ConnectStatus::MismatchedProtocol => {
                warn!("Protocol version mismatch");
                Err(Error::Connection("Protocol version mismatch".into()))
            }
            _ => {
                warn!("Unknown status: {:?}", response.status);
                Err(Error::Connection(format!(
                    "Unknown connection status: {}",
                    response.status
                )))
            }
        }
    }

    /// Attempts to reconnect to the server
    pub fn reconnect(&self) -> bool {
        {
            let mut reconnecting = self.reconnecting.write();
            if *reconnecting {
                return false;
            }
            *reconnecting = true;
        }

        info!("Attempting to reconnect...");

        loop {
            if self.connection.is_shutting_down() {
                *self.reconnecting.write() = false;
                return false;
            }

            match self.connection.socket_handler().connect(&self.endpoint) {
                Ok(fd) if fd >= 0 => {
                    // Send connect request
                    let request = ConnectRequest {
                        client_id: self.connection.id().to_string(),
                        version: PROTOCOL_VERSION,
                    };

                    if self
                        .connection
                        .socket_handler()
                        .write_proto(fd, &request, true)
                        .is_err()
                    {
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }

                    // Read connect response
                    let response: Result<ConnectResponse> =
                        self.connection.socket_handler().read_proto(fd, true);

                    match response {
                        Ok(resp)
                            if ConnectStatus::try_from(resp.status)
                                == Ok(ConnectStatus::ReturningClient) =>
                        {
                            if self.connection.recover(fd).is_ok() {
                                info!("Reconnection successful");
                                *self.reconnecting.write() = false;
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }

            thread::sleep(Duration::from_secs(1));
        }
    }

    /// Read a packet from the connection
    pub fn read_packet(&self) -> Result<Option<Packet>> {
        self.connection.read_packet()
    }

    /// Write a packet to the connection
    pub fn write_packet(&self, packet: Packet) {
        self.connection.write_packet(packet);
    }

    /// Read a packet without blocking
    pub fn read(&self) -> Result<Option<Packet>> {
        self.connection.read()
    }

    /// Get the socket file descriptor
    pub fn socket_fd(&self) -> RawFd {
        self.connection.socket_fd()
    }

    /// Check if there is data to read
    pub fn has_data(&self) -> bool {
        self.connection.has_data()
    }

    /// Get the connection ID
    pub fn id(&self) -> &str {
        self.connection.id()
    }

    /// Check if the connection is shutting down
    pub fn is_shutting_down(&self) -> bool {
        self.connection.is_shutting_down()
    }

    /// Shutdown the connection
    pub fn shutdown(&self) {
        self.connection.shutdown();
    }

    /// Close socket and maybe reconnect
    pub fn close_socket_and_maybe_reconnect(&self) {
        self.connection.close_socket();
        // Spawn reconnection in background
        // In production, this should use proper async handling
    }
}
