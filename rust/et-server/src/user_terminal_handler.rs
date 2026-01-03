//! User terminal handler for managing PTY sessions

use et_lib::connection::Connection;
use et_lib::packet::Packet;
use et_lib::proto::{terminal_packet_type, TerminalBuffer, TerminalInfo as TerminalInfoProto};
use et_terminal::pty::{PseudoUserTerminal, UserTerminal};
use et_terminal::TerminalInfo;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use parking_lot::Mutex;
use prost::Message;
use std::os::fd::BorrowedFd;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Helper to create a BorrowedFd from a RawFd
/// SAFETY: The caller must ensure the fd is valid for the duration of the borrow
unsafe fn borrow_fd(fd: RawFd) -> BorrowedFd<'static> {
    BorrowedFd::borrow_raw(fd)
}

/// Handles the terminal session for a connected user
pub struct UserTerminalHandler {
    /// The connection to the client
    connection: Arc<Connection>,
    /// The pseudo-terminal
    terminal: Mutex<PseudoUserTerminal>,
    /// Whether the handler is running
    running: Mutex<bool>,
}

impl UserTerminalHandler {
    /// Creates a new user terminal handler
    pub fn new(connection: Arc<Connection>) -> Self {
        Self {
            connection,
            terminal: Mutex::new(PseudoUserTerminal::new()),
            running: Mutex::new(false),
        }
    }

    /// Starts the terminal session
    pub fn start(&self, router_fd: RawFd) -> std::io::Result<()> {
        let master_fd = self.terminal.lock().setup(router_fd)?;
        *self.running.lock() = true;

        info!("Terminal session started with master fd: {}", master_fd);

        self.run_loop(master_fd)
    }

    /// Main event loop
    fn run_loop(&self, master_fd: RawFd) -> std::io::Result<()> {
        const BUF_SIZE: usize = 16 * 1024;
        let mut buf = [0u8; BUF_SIZE];

        while *self.running.lock() && !self.connection.is_shutting_down() {
            // Poll for data
            let client_fd = self.connection.socket_fd();

            // SAFETY: master_fd is valid for the duration of this loop
            let master_borrowed = unsafe { borrow_fd(master_fd) };
            let mut poll_fds = vec![PollFd::new(master_borrowed, PollFlags::POLLIN)];
            if client_fd >= 0 {
                let client_borrowed = unsafe { borrow_fd(client_fd) };
                poll_fds.push(PollFd::new(client_borrowed, PollFlags::POLLIN));
            }

            if poll(&mut poll_fds, PollTimeout::from(10u16)).is_err() {
                continue;
            }

            // Check for data from PTY (index 0)
            if poll_fds[0]
                .revents()
                .map(|e| e.contains(PollFlags::POLLIN))
                .unwrap_or(false)
            {
                // Use libc directly for read since nix requires AsFd
                let n = unsafe {
                    libc::read(master_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };

                if n > 0 {
                    let tb = TerminalBuffer {
                        buffer: buf[..n as usize].to_vec(),
                    };
                    self.connection.write_packet(Packet::new(
                        terminal_packet_type::TERMINAL_BUFFER,
                        tb.encode_to_vec(),
                    ));
                } else if n == 0 {
                    // EOF - terminal closed
                    info!("Terminal closed");
                    break;
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("PTY read error: {}", err);
                        break;
                    }
                }
            }

            // Check for data from client (index 1 if present)
            if client_fd >= 0
                && poll_fds.len() > 1
                && poll_fds[1]
                    .revents()
                    .map(|e| e.contains(PollFlags::POLLIN))
                    .unwrap_or(false)
            {
                while self.connection.has_data() {
                    if let Ok(Some(packet)) = self.connection.read() {
                        self.handle_packet(&packet, master_fd);
                    } else {
                        break;
                    }
                }
            }
        }

        // Clean up
        self.terminal.lock().cleanup();
        let _ = self.terminal.lock().handle_session_end();

        Ok(())
    }

    /// Handles a packet from the client
    fn handle_packet(&self, packet: &Packet, master_fd: RawFd) {
        match packet.header() {
            terminal_packet_type::TERMINAL_BUFFER => {
                if let Ok(tb) = TerminalBuffer::decode(packet.payload()) {
                    // Use libc directly for write
                    unsafe {
                        libc::write(
                            master_fd,
                            tb.buffer.as_ptr() as *const libc::c_void,
                            tb.buffer.len(),
                        );
                    }
                }
            }
            terminal_packet_type::TERMINAL_INFO => {
                if let Ok(ti) = TerminalInfoProto::decode(packet.payload()) {
                    let info = TerminalInfo::from(ti);
                    self.terminal.lock().set_info(&info);
                }
            }
            terminal_packet_type::KEEP_ALIVE => {
                self.connection
                    .write_packet(Packet::new(terminal_packet_type::KEEP_ALIVE, Vec::new()));
            }
            _ => {
                debug!("Unhandled packet type: {}", packet.header());
            }
        }
    }

    /// Stops the terminal session
    pub fn stop(&self) {
        *self.running.lock() = false;
    }
}
