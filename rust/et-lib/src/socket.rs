//! Socket handling abstractions
//!
//! This module provides socket operations for TCP and Unix domain sockets.

use crate::error::{Error, Result};
use crate::packet::Packet;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::RwLock;
use prost::Message;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::os::unix::io::{AsRawFd, BorrowedFd, RawFd};
use std::time::Duration;
use tracing::{info, warn};

/// Maximum message size (128 MB)
const MAX_MESSAGE_SIZE: i64 = 128 * 1024 * 1024;

/// Socket endpoint for connection/listening
#[derive(Debug, Clone)]
pub struct SocketEndpoint {
    /// Hostname or IP address (None for wildcard binding)
    pub name: Option<String>,
    /// Port number
    pub port: u16,
}

impl SocketEndpoint {
    /// Creates a new endpoint with name and port
    pub fn new(name: impl Into<String>, port: u16) -> Self {
        Self {
            name: Some(name.into()),
            port,
        }
    }

    /// Creates a new endpoint for wildcard binding on a port
    pub fn any(port: u16) -> Self {
        Self { name: None, port }
    }
}

impl std::fmt::Display for SocketEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{}:{}", name, self.port),
            None => write!(f, "*:{}", self.port),
        }
    }
}

/// Trait for socket operations
pub trait SocketHandler: Send + Sync {
    /// Returns true when data is ready to read on the descriptor
    fn has_data(&self, fd: RawFd) -> bool;

    /// Reads up to count bytes from fd
    fn read(&self, fd: RawFd, buf: &mut [u8]) -> Result<usize>;

    /// Writes bytes to fd
    fn write(&self, fd: RawFd, buf: &[u8]) -> Result<usize>;

    /// Opens a connection to the specified endpoint
    fn connect(&self, endpoint: &SocketEndpoint) -> Result<RawFd>;

    /// Starts listening on the endpoint and returns the active listen fds
    fn listen(&self, endpoint: &SocketEndpoint) -> Result<HashSet<RawFd>>;

    /// Returns fds associated with the endpoint
    fn get_endpoint_fds(&self, endpoint: &SocketEndpoint) -> Option<HashSet<RawFd>>;

    /// Accepts a pending connection on the given listening fd
    fn accept(&self, fd: RawFd) -> Result<RawFd>;

    /// Stops accepting new connections on the given endpoint
    fn stop_listening(&self, endpoint: &SocketEndpoint) -> Result<()>;

    /// Closes the supplied socket descriptor
    fn close(&self, fd: RawFd);

    /// Returns all currently active sockets
    fn get_active_sockets(&self) -> Vec<RawFd>;
}

/// Extension methods for socket handlers
pub trait SocketHandlerExt: SocketHandler {
    /// Reads exactly `count` bytes, retrying on EAGAIN until buffer fills
    fn read_all(&self, fd: RawFd, buf: &mut [u8], timeout: bool) -> Result<()> {
        let mut total_read = 0;
        let count = buf.len();
        let start = std::time::Instant::now();
        let timeout_duration = Duration::from_secs(if timeout { 5 } else { 300 });

        while total_read < count {
            if start.elapsed() > timeout_duration {
                return Err(Error::Timeout);
            }

            match self.read(fd, &mut buf[total_read..]) {
                Ok(0) => return Err(Error::ConnectionClosed),
                Ok(n) => total_read += n,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_micros(1000));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Writes all bytes, throwing if the operation times out or fails
    fn write_all_or_throw(&self, fd: RawFd, buf: &[u8], timeout: bool) -> Result<()> {
        let mut total_written = 0;
        let count = buf.len();
        let start = std::time::Instant::now();
        let timeout_duration = Duration::from_secs(if timeout { 5 } else { 300 });

        while total_written < count {
            if start.elapsed() > timeout_duration {
                return Err(Error::Timeout);
            }

            match self.write(fd, &buf[total_written..]) {
                Ok(n) => total_written += n,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_micros(1000));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Reads a length-prefixed protobuf from the socket
    fn read_proto<T: Message + Default>(&self, fd: RawFd, timeout: bool) -> Result<T> {
        let mut length_buf = [0u8; 8];
        self.read_all(fd, &mut length_buf, timeout)?;
        let length = i64::from_ne_bytes(length_buf);

        if !(0..=MAX_MESSAGE_SIZE).contains(&length) {
            return Err(Error::InvalidMessageSize(length));
        }

        if length == 0 {
            return Ok(T::default());
        }

        let mut data = vec![0u8; length as usize];
        self.read_all(fd, &mut data, timeout)?;
        T::decode(&data[..]).map_err(Error::from)
    }

    /// Serializes and writes a length-prefixed protobuf message
    fn write_proto<T: Message>(&self, fd: RawFd, msg: &T, timeout: bool) -> Result<()> {
        let data = msg.encode_to_vec();
        let length = data.len() as i64;

        if !(0..=MAX_MESSAGE_SIZE).contains(&length) {
            return Err(Error::InvalidMessageSize(length));
        }

        self.write_all_or_throw(fd, &length.to_ne_bytes(), timeout)?;
        if length > 0 {
            self.write_all_or_throw(fd, &data, timeout)?;
        }
        Ok(())
    }

    /// Reads a length-prefixed binary packet and deserializes it
    fn read_packet(&self, fd: RawFd) -> Result<Option<Packet>> {
        let mut length_buf = [0u8; 8];
        self.read_all(fd, &mut length_buf, false)?;
        let length = i64::from_ne_bytes(length_buf);

        if !(0..=MAX_MESSAGE_SIZE).contains(&length) {
            return Err(Error::InvalidMessageSize(length));
        }

        if length == 0 {
            return Ok(None);
        }

        let mut data = vec![0u8; length as usize];
        self.read_all(fd, &mut data, false)?;
        Ok(Some(Packet::from_bytes(&data)?))
    }

    /// Serializes and writes a packet with a leading length prefix
    fn write_packet(&self, fd: RawFd, packet: &Packet) -> Result<()> {
        let data = packet.serialize();
        let length = data.len() as i64;

        if !(0..=MAX_MESSAGE_SIZE).contains(&length) {
            return Err(Error::InvalidMessageSize(length));
        }

        self.write_all_or_throw(fd, &length.to_ne_bytes(), false)?;
        if length > 0 {
            self.write_all_or_throw(fd, &data, false)?;
        }
        Ok(())
    }

    /// Sends a base64-encoded version of the provided buffer
    fn write_b64(&self, fd: RawFd, buf: &[u8]) -> Result<()> {
        let encoded = BASE64.encode(buf);
        self.write_all_or_throw(fd, encoded.as_bytes(), false)
    }

    /// Reads base64-encoded data and decodes it
    fn read_b64(&self, fd: RawFd, count: usize) -> Result<Vec<u8>> {
        // Base64 encoding expands data by 4/3
        let encoded_len = (count * 4).div_ceil(3);
        let mut encoded = vec![0u8; encoded_len];
        self.read_all(fd, &mut encoded, false)?;
        let encoded_str = String::from_utf8_lossy(&encoded);
        BASE64
            .decode(encoded_str.trim())
            .map_err(|e| Error::Protocol(format!("Base64 decode error: {}", e)))
    }
}

// Implement SocketHandlerExt for all types that implement SocketHandler
impl<T: SocketHandler + ?Sized> SocketHandlerExt for T {}

/// Helper to create a BorrowedFd from a RawFd
/// SAFETY: The caller must ensure the fd is valid for the duration of the borrow
unsafe fn borrow_fd(fd: RawFd) -> BorrowedFd<'static> {
    BorrowedFd::borrow_raw(fd)
}

/// TCP socket handler implementation
pub struct TcpSocketHandler {
    /// Active sockets
    active_sockets: RwLock<HashSet<RawFd>>,
    /// Port to server socket mappings
    port_server_sockets: RwLock<HashMap<u16, HashSet<RawFd>>>,
}

impl Default for TcpSocketHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpSocketHandler {
    /// Creates a new TCP socket handler
    pub fn new() -> Self {
        Self {
            active_sockets: RwLock::new(HashSet::new()),
            port_server_sockets: RwLock::new(HashMap::new()),
        }
    }

    /// Initialize socket with TCP-specific options
    fn init_socket(&self, fd: RawFd) -> Result<()> {
        // Set TCP_NODELAY using libc directly for RawFd compatibility
        let flag: libc::c_int = 1;
        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &flag as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                warn!("Failed to set TCP_NODELAY");
            }
        }

        // Set SO_LINGER
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 5,
        };
        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
            if ret != 0 {
                warn!("Failed to set SO_LINGER");
            }
        }
        Ok(())
    }

    /// Initialize server socket
    fn init_server_socket(&self, fd: RawFd) -> Result<()> {
        // Set SO_REUSEADDR using libc directly
        let flag: libc::c_int = 1;
        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &flag as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                warn!("Failed to set SO_REUSEADDR");
            }
        }
        self.init_socket(fd)
    }

    /// Add socket to active set
    fn add_to_active(&self, fd: RawFd) {
        self.active_sockets.write().insert(fd);
    }

    /// Remove socket from active set
    fn remove_from_active(&self, fd: RawFd) {
        self.active_sockets.write().remove(&fd);
    }

    /// Set socket blocking mode
    fn set_blocking(&self, fd: RawFd, blocking: bool) -> Result<()> {
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;
        let mut flags = OFlag::from_bits_truncate(flags);
        if blocking {
            flags.remove(OFlag::O_NONBLOCK);
        } else {
            flags.insert(OFlag::O_NONBLOCK);
        }
        fcntl(fd, FcntlArg::F_SETFL(flags))?;
        Ok(())
    }
}

impl SocketHandler for TcpSocketHandler {
    fn has_data(&self, fd: RawFd) -> bool {
        use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
        // SAFETY: fd is assumed to be valid for the duration of this call
        let borrowed = unsafe { borrow_fd(fd) };
        let mut pfd = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match poll(&mut pfd, PollTimeout::ZERO) {
            Ok(n) => n > 0,
            Err(_) => false,
        }
    }

    fn read(&self, fd: RawFd, buf: &mut [u8]) -> Result<usize> {
        // Use libc::read directly for RawFd compatibility
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            return Err(Error::Io(err));
        }
        Ok(n as usize)
    }

    fn write(&self, fd: RawFd, buf: &[u8]) -> Result<usize> {
        // Use libc::write directly for RawFd compatibility
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            return Err(Error::Io(err));
        }
        Ok(n as usize)
    }

    fn connect(&self, endpoint: &SocketEndpoint) -> Result<RawFd> {
        let hostname = endpoint
            .name
            .as_ref()
            .ok_or_else(|| Error::AddressResolution("No hostname provided".into()))?;
        let addr_str = format!("{}:{}", hostname, endpoint.port);

        let addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|e| Error::AddressResolution(e.to_string()))?
            .collect();

        if addrs.is_empty() {
            return Err(Error::AddressResolution("No addresses found".into()));
        }

        let mut last_error = None;

        for addr in addrs {
            let domain = if addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };

            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .map_err(|e| Error::Socket(e.to_string()))?;

            let fd = socket.as_raw_fd();
            self.set_blocking(fd, false)?;

            let sock_addr = SockAddr::from(addr);
            match socket.connect(&sock_addr) {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
                Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => {}
                Err(e) => {
                    last_error = Some(Error::Socket(e.to_string()));
                    continue;
                }
            }

            // Wait for connection with timeout using poll
            use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
            // SAFETY: fd is valid as long as socket is alive
            let borrowed = unsafe { borrow_fd(fd) };
            let mut pfd = [PollFd::new(borrowed, PollFlags::POLLOUT)];
            match poll(&mut pfd, PollTimeout::from(3000u16)) {
                Ok(n) if n > 0 => {
                    // Check for connection error
                    let err: i32 = socket
                        .take_error()
                        .map_err(|e| Error::Socket(e.to_string()))?
                        .map_or(0, |e| e.raw_os_error().unwrap_or(0));
                    if err != 0 {
                        last_error = Some(Error::Socket(format!("Connection error: {}", err)));
                        continue;
                    }

                    self.set_blocking(fd, true)?;
                    self.init_socket(fd)?;
                    self.add_to_active(fd);

                    info!("Connected to {} using fd {}", addr, fd);

                    // Prevent socket from being closed when Socket is dropped
                    std::mem::forget(socket);
                    return Ok(fd);
                }
                Ok(_) => {
                    last_error = Some(Error::Timeout);
                    continue;
                }
                Err(e) => {
                    last_error = Some(Error::Socket(e.to_string()));
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::AddressResolution("No host found".into())))
    }

    fn listen(&self, endpoint: &SocketEndpoint) -> Result<HashSet<RawFd>> {
        let mut server_sockets = HashSet::new();

        // Bind to all addresses (IPv4 and IPv6)
        let bind_addr = match &endpoint.name {
            Some(name) => format!("{}:{}", name, endpoint.port),
            None => format!("0.0.0.0:{}", endpoint.port),
        };

        // Try IPv4
        if let Ok(listener) = TcpListener::bind(&bind_addr) {
            let fd = listener.as_raw_fd();
            self.init_server_socket(fd)?;
            info!("Listening on {} (IPv4)", bind_addr);
            server_sockets.insert(fd);
            std::mem::forget(listener);
        }

        // Try IPv6 if no explicit bind address
        if endpoint.name.is_none() {
            let bind_addr_v6 = format!("[::]:{}", endpoint.port);
            if let Ok(listener) = TcpListener::bind(&bind_addr_v6) {
                let fd = listener.as_raw_fd();
                // Set IPV6_V6ONLY using libc directly
                let flag: libc::c_int = 1;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_V6ONLY,
                        &flag as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
                self.init_server_socket(fd)?;
                info!("Listening on {} (IPv6)", bind_addr_v6);
                server_sockets.insert(fd);
                std::mem::forget(listener);
            }
        }

        if server_sockets.is_empty() {
            return Err(Error::Socket("Could not bind to any interface".into()));
        }

        self.port_server_sockets
            .write()
            .insert(endpoint.port, server_sockets.clone());
        Ok(server_sockets)
    }

    fn get_endpoint_fds(&self, endpoint: &SocketEndpoint) -> Option<HashSet<RawFd>> {
        self.port_server_sockets.read().get(&endpoint.port).cloned()
    }

    fn accept(&self, fd: RawFd) -> Result<RawFd> {
        // Use libc::accept directly for RawFd compatibility
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(Error::Io(err));
        }
        self.init_socket(client_fd)?;
        self.add_to_active(client_fd);
        Ok(client_fd)
    }

    fn stop_listening(&self, endpoint: &SocketEndpoint) -> Result<()> {
        if let Some(sockets) = self.port_server_sockets.write().remove(&endpoint.port) {
            for fd in sockets {
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    fn close(&self, fd: RawFd) {
        self.remove_from_active(fd);
        unsafe { libc::close(fd) };
    }

    fn get_active_sockets(&self) -> Vec<RawFd> {
        self.active_sockets.read().iter().copied().collect()
    }
}

/// Raw socket utility functions for blocking I/O
pub struct RawSocketUtils;

impl RawSocketUtils {
    /// Writes the entire buffer to the given descriptor, retrying on EAGAIN
    pub fn write_all(fd: RawFd, buf: &[u8]) -> Result<()> {
        let mut total_written = 0;
        while total_written < buf.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    buf[total_written..].as_ptr() as *const libc::c_void,
                    buf.len() - total_written,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::Interrupted
                {
                    std::thread::sleep(Duration::from_micros(1000));
                    continue;
                }
                return Err(Error::Io(err));
            }
            total_written += n as usize;
        }
        Ok(())
    }

    /// Reads exactly `count` bytes from the descriptor, waiting for data
    pub fn read_all(fd: RawFd, buf: &mut [u8]) -> Result<()> {
        let mut total_read = 0;
        while total_read < buf.len() {
            let n = unsafe {
                libc::read(
                    fd,
                    buf[total_read..].as_mut_ptr() as *mut libc::c_void,
                    buf.len() - total_read,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::Interrupted
                {
                    std::thread::sleep(Duration::from_micros(1000));
                    continue;
                }
                return Err(Error::Io(err));
            }
            if n == 0 {
                return Err(Error::ConnectionClosed);
            }
            total_read += n as usize;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_endpoint_display() {
        let ep = SocketEndpoint::new("localhost", 2022);
        assert_eq!(format!("{}", ep), "localhost:2022");

        let ep_any = SocketEndpoint::any(2022);
        assert_eq!(format!("{}", ep_any), "*:2022");
    }

    #[test]
    fn test_tcp_handler_creation() {
        let handler = TcpSocketHandler::new();
        assert!(handler.get_active_sockets().is_empty());
    }
}
