//! Terminal client implementation

use crate::client_connection::ClientConnection;
use crate::port_forward::PortForwardHandler;
use et_lib::packet::Packet;
use et_lib::proto::{terminal_packet_type, InitialPayload, InitialResponse, TerminalBuffer};
use et_lib::socket::{SocketEndpoint, SocketHandler};
use et_terminal::console::Console;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use parking_lot::Mutex;
use prost::Message;
use std::os::fd::BorrowedFd;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Helper to create a BorrowedFd from a RawFd
/// SAFETY: The caller must ensure the fd is valid for the duration of the borrow
unsafe fn borrow_fd(fd: RawFd) -> BorrowedFd<'static> {
    BorrowedFd::borrow_raw(fd)
}

/// Terminal client that manages the interactive session
pub struct TerminalClient {
    /// Console wrapper for local terminal I/O
    console: Option<Box<dyn Console>>,
    /// Client connection to the ET server
    connection: Arc<ClientConnection>,
    /// Port forward handler
    port_forward_handler: Arc<PortForwardHandler>,
    /// Flag that ends the run loop when set
    shutting_down: Mutex<bool>,
    /// Keepalive interval in seconds
    keepalive_duration: u64,
}

impl TerminalClient {
    /// Creates a new terminal client
    pub fn new(
        socket_handler: Arc<dyn SocketHandler>,
        pipe_socket_handler: Arc<dyn SocketHandler>,
        endpoint: SocketEndpoint,
        id: String,
        passkey: String,
        console: Option<Box<dyn Console>>,
        jumphost: bool,
        tunnels: &str,
        _reverse_tunnels: &str,
        keepalive_duration: u64,
    ) -> std::io::Result<Self> {
        let port_forward_handler = Arc::new(PortForwardHandler::new(
            socket_handler.clone(),
            pipe_socket_handler,
        ));

        // Set up tunnels
        if !tunnels.is_empty() {
            // Parse and set up local tunnels
            for tunnel in tunnels.split(',') {
                if let Some((_, local_port, remote_host, remote_port)) =
                    crate::ssh_setup::parse_tunnel_spec(tunnel.trim())
                {
                    let pfsr = et_lib::proto::PortForwardSourceRequest {
                        source: Some(et_lib::proto::SocketEndpoint {
                            name: "127.0.0.1".to_string(),
                            port: local_port as i32,
                        }),
                        destination: Some(et_lib::proto::SocketEndpoint {
                            name: remote_host,
                            port: remote_port as i32,
                        }),
                        environment_variable: String::new(),
                    };
                    if let Err(e) = port_forward_handler.create_source(&pfsr) {
                        warn!("Failed to create tunnel: {}", e);
                    }
                }
            }
        }

        let mut connection = ClientConnection::new(socket_handler, endpoint, id, passkey);

        // Connect to server
        match connection.connect() {
            Ok(true) => {
                // Send initial payload
                let payload = InitialPayload {
                    jumphost,
                    reverse_tunnels: Vec::new(),
                    environment_variables: Default::default(),
                };

                connection.write_packet(Packet::new(
                    et_lib::proto::packet_type::INITIAL_PAYLOAD,
                    payload.encode_to_vec(),
                ));

                // Wait for response
                std::thread::sleep(Duration::from_millis(100));

                // Read initial response
                for _ in 0..30 {
                    if let Ok(Some(packet)) = connection.read_packet() {
                        if packet.header() == et_lib::proto::packet_type::INITIAL_RESPONSE {
                            if let Ok(response) = InitialResponse::decode(packet.payload()) {
                                if !response.error.is_empty() {
                                    return Err(std::io::Error::other(format!(
                                        "Initial response error: {}",
                                        response.error
                                    )));
                                }
                                break;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            Ok(false) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Failed to connect",
                ));
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e.to_string(),
                ));
            }
        }

        info!("Client created with id: {}", connection.id());

        Ok(Self {
            console,
            connection: Arc::new(connection),
            port_forward_handler,
            shutting_down: Mutex::new(false),
            keepalive_duration,
        })
    }

    /// Runs the interactive session
    pub fn run(&mut self, command: Option<&str>, noexit: bool) -> std::io::Result<()> {
        if let Some(ref mut console) = self.console {
            console.setup()?;
        }

        const BUF_SIZE: usize = 16 * 1024;
        let mut buf = [0u8; BUF_SIZE];

        let mut keepalive_time = Instant::now() + Duration::from_secs(self.keepalive_duration);
        let mut waiting_on_keepalive = false;

        // Send initial command if provided
        if let Some(cmd) = command {
            info!("Got command: {}", cmd);
            let cmd_with_suffix = if noexit {
                format!("{}\n", cmd)
            } else {
                format!("{}; exit\n", cmd)
            };

            let tb = TerminalBuffer {
                buffer: cmd_with_suffix.into_bytes(),
            };
            self.connection.write_packet(Packet::new(
                terminal_packet_type::TERMINAL_BUFFER,
                tb.encode_to_vec(),
            ));
        }

        let mut last_terminal_info = et_terminal::TerminalInfo::default();

        if self.console.is_none() {
            println!("ET running, feel free to background...");
        }

        while !self.connection.is_shutting_down() {
            if *self.shutting_down.lock() {
                break;
            }

            // Set up poll
            let console_fd = self.console.as_ref().map(|c| c.get_fd()).unwrap_or(-1);
            let client_fd = self.connection.socket_fd();

            // Build poll fds and track indices
            let mut poll_fds = Vec::new();
            let console_poll_idx: Option<usize>;
            let client_poll_idx: Option<usize>;

            if console_fd >= 0 {
                console_poll_idx = Some(poll_fds.len());
                let borrowed = unsafe { borrow_fd(console_fd) };
                poll_fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
            } else {
                console_poll_idx = None;
            }

            if client_fd >= 0 {
                client_poll_idx = Some(poll_fds.len());
                let borrowed = unsafe { borrow_fd(client_fd) };
                poll_fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
            } else {
                client_poll_idx = None;
            }

            // Poll with 10ms timeout
            let _ = poll(&mut poll_fds, PollTimeout::from(10u16));

            // Check for console input using index
            if let (Some(ref console), Some(idx)) = (&self.console, console_poll_idx) {
                let has_input = poll_fds
                    .get(idx)
                    .and_then(|p| p.revents())
                    .map(|e| e.contains(PollFlags::POLLIN))
                    .unwrap_or(false);

                if has_input {
                    // Use libc directly for read
                    let n = unsafe {
                        libc::read(console_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                    };

                    if n > 0 {
                        let tb = TerminalBuffer {
                            buffer: buf[..n as usize].to_vec(),
                        };
                        self.connection.write_packet(Packet::new(
                            terminal_packet_type::TERMINAL_BUFFER,
                            tb.encode_to_vec(),
                        ));
                        keepalive_time =
                            Instant::now() + Duration::from_secs(self.keepalive_duration);
                    }
                }
            }

            // Check for data from server using index
            if let Some(idx) = client_poll_idx {
                let has_input = poll_fds
                    .get(idx)
                    .and_then(|p| p.revents())
                    .map(|e| e.contains(PollFlags::POLLIN))
                    .unwrap_or(false);

                if has_input {
                    while self.connection.has_data() {
                        if let Ok(Some(packet)) = self.connection.read() {
                            let packet_type = packet.header();

                            // Handle port forwarding packets
                            if packet_type == terminal_packet_type::PORT_FORWARD_DATA
                                || packet_type
                                    == terminal_packet_type::PORT_FORWARD_DESTINATION_REQUEST
                                || packet_type
                                    == terminal_packet_type::PORT_FORWARD_DESTINATION_RESPONSE
                            {
                                keepalive_time =
                                    Instant::now() + Duration::from_secs(self.keepalive_duration);
                                // Port forwarding packets handled separately
                                continue;
                            }

                            match packet_type {
                                terminal_packet_type::TERMINAL_BUFFER => {
                                    if let Some(ref console) = self.console {
                                        if let Ok(tb) = TerminalBuffer::decode(packet.payload()) {
                                            keepalive_time = Instant::now()
                                                + Duration::from_secs(self.keepalive_duration);
                                            let _ = console.write(&tb.buffer);
                                        }
                                    }
                                }
                                terminal_packet_type::KEEP_ALIVE => {
                                    waiting_on_keepalive = false;
                                    debug!("Got a keepalive");
                                }
                                _ => {
                                    warn!("Unknown packet type: {}", packet_type);
                                }
                            }
                        } else {
                            break;
                        }
                    }
                }
            }

            // Handle keepalive
            if client_fd >= 0 && Instant::now() > keepalive_time {
                keepalive_time = Instant::now() + Duration::from_secs(self.keepalive_duration);
                if waiting_on_keepalive {
                    info!("Missed a keepalive, reconnecting...");
                    self.connection.close_socket_and_maybe_reconnect();
                    waiting_on_keepalive = false;
                } else {
                    debug!("Writing keepalive packet");
                    self.connection
                        .write_packet(Packet::new(terminal_packet_type::KEEP_ALIVE, Vec::new()));
                    waiting_on_keepalive = true;
                }
            }

            if client_fd < 0 {
                waiting_on_keepalive = false;
            }

            // Check for terminal size changes
            if let Some(ref console) = self.console {
                let ti = console.get_terminal_info();
                let ti_proto: et_lib::proto::TerminalInfo = ti.clone().into();

                if ti != last_terminal_info {
                    info!(
                        "Window size changed: row: {} column: {} width: {} height: {}",
                        ti.row, ti.column, ti.width, ti.height
                    );
                    last_terminal_info = ti;
                    self.connection.write_packet(Packet::new(
                        terminal_packet_type::TERMINAL_INFO,
                        ti_proto.encode_to_vec(),
                    ));
                }
            }

            // Update port forwarding
            let mut requests = Vec::new();
            let mut data_to_send = Vec::new();
            self.port_forward_handler
                .update(&mut requests, &mut data_to_send);

            for pfr in requests {
                self.connection.write_packet(Packet::new(
                    terminal_packet_type::PORT_FORWARD_DESTINATION_REQUEST,
                    pfr.encode_to_vec(),
                ));
                keepalive_time = Instant::now() + Duration::from_secs(self.keepalive_duration);
            }

            for pfd in data_to_send {
                self.connection.write_packet(Packet::new(
                    terminal_packet_type::PORT_FORWARD_DATA,
                    pfd.encode_to_vec(),
                ));
                keepalive_time = Instant::now() + Duration::from_secs(self.keepalive_duration);
            }
        }

        if let Some(ref mut console) = self.console {
            console.teardown()?;
        }

        println!("Session terminated");
        Ok(())
    }

    /// Signals the client to shutdown
    pub fn shutdown(&self) {
        *self.shutting_down.lock() = true;
    }
}

impl Drop for TerminalClient {
    fn drop(&mut self) {
        self.connection.shutdown();
    }
}
