//! Server-side connection handling

use et_lib::connection::Connection;
use et_lib::crypto::CryptoHandler;
use et_lib::error::{Error, Result};
use et_lib::nonce;
use et_lib::proto::{ConnectRequest, ConnectResponse, ConnectStatus};
use et_lib::socket::{SocketHandler, SocketHandlerExt};
use et_lib::PROTOCOL_VERSION;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tracing::info;

/// Manages server-side client connections
pub struct ServerConnection {
    /// Socket handler
    socket_handler: Arc<dyn SocketHandler>,
    /// Active connections by client ID
    connections: RwLock<HashMap<String, Arc<Connection>>>,
    /// Client keys by ID
    client_keys: RwLock<HashMap<String, String>>,
}

impl ServerConnection {
    /// Creates a new server connection manager
    pub fn new(socket_handler: Arc<dyn SocketHandler>) -> Self {
        Self {
            socket_handler,
            connections: RwLock::new(HashMap::new()),
            client_keys: RwLock::new(HashMap::new()),
        }
    }

    /// Accepts a new client connection
    pub fn accept_client(&self, fd: RawFd) -> Result<Arc<Connection>> {
        // Read connect request
        let request: ConnectRequest = self.socket_handler.read_proto(fd, true)?;

        info!(
            "Received connection request from client: {}",
            request.client_id
        );

        // Check protocol version
        if request.version != PROTOCOL_VERSION {
            let response = ConnectResponse {
                status: ConnectStatus::MismatchedProtocol as i32,
                error: format!(
                    "Protocol version mismatch: client={}, server={}",
                    request.version, PROTOCOL_VERSION
                ),
            };
            self.socket_handler.write_proto(fd, &response, true)?;
            return Err(Error::Protocol("Protocol version mismatch".into()));
        }

        // Check if this is a returning client
        let existing_key = self.client_keys.read().get(&request.client_id).cloned();

        if let Some(key) = existing_key {
            // Returning client - verify and recover
            let response = ConnectResponse {
                status: ConnectStatus::ReturningClient as i32,
                error: String::new(),
            };
            self.socket_handler.write_proto(fd, &response, true)?;

            // Get existing connection and recover
            if let Some(conn) = self.connections.read().get(&request.client_id) {
                conn.recover(fd)?;
                Ok(conn.clone())
            } else {
                // Connection was cleaned up, treat as new
                self.create_new_connection(fd, &request.client_id)
            }
        } else {
            // New client
            self.create_new_connection(fd, &request.client_id)
        }
    }

    /// Creates a new connection for a client
    fn create_new_connection(&self, fd: RawFd, client_id: &str) -> Result<Arc<Connection>> {
        // Generate a new key
        let key_bytes = CryptoHandler::generate_key();
        let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_bytes);

        // Send response
        let response = ConnectResponse {
            status: ConnectStatus::NewClient as i32,
            error: String::new(),
        };
        self.socket_handler.write_proto(fd, &response, true)?;

        // Create connection
        let mut connection = Connection::new(self.socket_handler.clone(), client_id, &key);
        connection.initialize(fd, nonce::SERVER_CLIENT)?;

        let connection = Arc::new(connection);

        // Store connection and key
        self.connections
            .write()
            .insert(client_id.to_string(), connection.clone());
        self.client_keys.write().insert(client_id.to_string(), key);

        info!("New client connected: {}", client_id);
        Ok(connection)
    }

    /// Removes a client connection
    pub fn remove_client(&self, client_id: &str) {
        self.connections.write().remove(client_id);
        self.client_keys.write().remove(client_id);
    }

    /// Gets a connection by client ID
    pub fn get_connection(&self, client_id: &str) -> Option<Arc<Connection>> {
        self.connections.read().get(client_id).cloned()
    }
}
