//! Terminal server implementation

use crate::server_connection::ServerConnection;
use crate::user_terminal_handler::UserTerminalHandler;
use et_lib::error::Result;
use et_lib::socket::{SocketEndpoint, SocketHandler, TcpSocketHandler};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::os::fd::BorrowedFd;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tracing::{error, info, warn};

/// The main terminal server
pub struct TerminalServer {
    /// Socket handler for network operations
    socket_handler: Arc<dyn SocketHandler>,
    /// Server connection manager
    server_connection: Arc<ServerConnection>,
    /// Listening socket fds
    listen_fds: Vec<RawFd>,
    /// Active terminal handlers
    terminal_handlers: Mutex<HashMap<String, JoinHandle<()>>>,
    /// Whether the server is running
    running: Mutex<bool>,
    /// Server port
    port: u16,
}

impl TerminalServer {
    /// Creates a new terminal server
    pub fn new(port: u16, bind_address: Option<&str>) -> Result<Self> {
        let socket_handler = Arc::new(TcpSocketHandler::new());
        let server_connection = Arc::new(ServerConnection::new(socket_handler.clone()));

        let endpoint = if let Some(addr) = bind_address {
            SocketEndpoint::new(addr, port)
        } else {
            SocketEndpoint::any(port)
        };

        let listen_fds: Vec<RawFd> = socket_handler.listen(&endpoint)?.into_iter().collect();

        info!("Terminal server listening on port {}", port);

        Ok(Self {
            socket_handler,
            server_connection,
            listen_fds,
            terminal_handlers: Mutex::new(HashMap::new()),
            running: Mutex::new(false),
            port,
        })
    }

    /// Runs the server main loop
    pub fn run(&self) -> Result<()> {
        *self.running.lock() = true;

        info!("Terminal server starting...");

        while *self.running.lock() {
            // Poll all listening sockets
            // SAFETY: listen_fds contains valid file descriptors that are kept alive by self
            let mut poll_fds: Vec<PollFd> = self
                .listen_fds
                .iter()
                .map(|&fd| {
                    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
                    PollFd::new(borrowed, PollFlags::POLLIN)
                })
                .collect();

            if poll(&mut poll_fds, PollTimeout::from(1000u16)).is_err() {
                continue;
            }

            for (i, pfd) in poll_fds.iter().enumerate() {
                if pfd
                    .revents()
                    .map(|e| e.contains(PollFlags::POLLIN))
                    .unwrap_or(false)
                {
                    let listen_fd = self.listen_fds[i];
                    match self.socket_handler.accept(listen_fd) {
                        Ok(client_fd) => {
                            info!("Accepted new connection on fd {}", client_fd);
                            self.handle_new_connection(client_fd);
                        }
                        Err(e) => {
                            warn!("Accept error: {}", e);
                        }
                    }
                }
            }

            // Clean up finished handlers
            self.cleanup_handlers();
        }

        Ok(())
    }

    /// Handles a new client connection
    fn handle_new_connection(&self, client_fd: RawFd) {
        let server_connection = self.server_connection.clone();
        let socket_handler = self.socket_handler.clone();

        // Spawn a thread to handle the connection
        let handle = thread::spawn(move || {
            match server_connection.accept_client(client_fd) {
                Ok(connection) => {
                    let client_id = connection.id().to_string();
                    info!("Client {} connected", client_id);

                    // Create and run the terminal handler
                    let handler = UserTerminalHandler::new(connection);
                    if let Err(e) = handler.start(-1) {
                        error!("Terminal handler error: {}", e);
                    }

                    server_connection.remove_client(&client_id);
                    info!("Client {} disconnected", client_id);
                }
                Err(e) => {
                    warn!("Failed to accept client: {}", e);
                    socket_handler.close(client_fd);
                }
            }
        });

        // Store the handle (we'll clean it up later)
        // Using a simple ID for now
        let handler_id = format!("{:?}", std::thread::current().id());
        self.terminal_handlers.lock().insert(handler_id, handle);
    }

    /// Cleans up finished handler threads
    fn cleanup_handlers(&self) {
        let mut handlers = self.terminal_handlers.lock();
        handlers.retain(|_, handle| !handle.is_finished());
    }

    /// Stops the server
    pub fn stop(&self) {
        *self.running.lock() = false;

        // Close all listening sockets
        for &fd in &self.listen_fds {
            self.socket_handler.close(fd);
        }

        // Wait for all handlers to finish
        let mut handlers = self.terminal_handlers.lock();
        for (_, handle) in handlers.drain() {
            let _ = handle.join();
        }
    }
}

impl Drop for TerminalServer {
    fn drop(&mut self) {
        if *self.running.lock() {
            self.stop();
        }
    }
}
