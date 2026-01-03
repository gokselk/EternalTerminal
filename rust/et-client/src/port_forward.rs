//! Port forwarding handler

use et_lib::connection::Connection;
use et_lib::error::Result;
use et_lib::packet::Packet;
use et_lib::proto::{
    terminal_packet_type, PortForwardData, PortForwardDestinationRequest,
    PortForwardDestinationResponse, PortForwardSourceRequest, PortForwardSourceResponse,
    SocketEndpoint,
};
use et_lib::socket::SocketHandler;
use parking_lot::Mutex;
use prost::Message;
use rand::Rng;
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Handles a source listening socket for port forwarding
pub struct ForwardSourceHandler {
    /// Socket handler for operations
    socket_handler: Arc<dyn SocketHandler>,
    /// Source endpoint (listening address)
    source: SocketEndpoint,
    /// Destination endpoint (where to forward)
    destination: SocketEndpoint,
    /// Listening socket fds
    listen_fds: Mutex<Vec<RawFd>>,
    /// Unassigned fds (accepted but not yet mapped to socket ID)
    unassigned_fds: Mutex<Vec<RawFd>>,
    /// Socket ID to fd mapping
    socket_map: Mutex<HashMap<i32, RawFd>>,
}

impl ForwardSourceHandler {
    /// Creates a new source handler
    pub fn new(
        socket_handler: Arc<dyn SocketHandler>,
        source: SocketEndpoint,
        destination: SocketEndpoint,
    ) -> Result<Self> {
        let endpoint = et_lib::socket::SocketEndpoint {
            name: if source.name.is_empty() {
                None
            } else {
                Some(source.name.clone())
            },
            port: source.port as u16,
        };

        let listen_fds = socket_handler.listen(&endpoint)?;

        Ok(Self {
            socket_handler,
            source,
            destination,
            listen_fds: Mutex::new(listen_fds.into_iter().collect()),
            unassigned_fds: Mutex::new(Vec::new()),
            socket_map: Mutex::new(HashMap::new()),
        })
    }

    /// Get the destination endpoint
    pub fn destination(&self) -> &SocketEndpoint {
        &self.destination
    }

    /// Check for new connections and data
    pub fn update(&self, data_to_send: &mut Vec<PortForwardData>) {
        // Check for data on existing connections
        let socket_map = self.socket_map.lock();
        let mut to_close = Vec::new();

        for (&socket_id, &fd) in socket_map.iter() {
            if self.socket_handler.has_data(fd) {
                let mut buf = vec![0u8; 16 * 1024];
                match self.socket_handler.read(fd, &mut buf) {
                    Ok(0) => {
                        // Connection closed
                        to_close.push(socket_id);
                        let mut pfd = PortForwardData::default();
                        pfd.source_to_destination = true;
                        pfd.socket_id = socket_id;
                        pfd.closed = true;
                        data_to_send.push(pfd);
                    }
                    Ok(n) => {
                        let mut pfd = PortForwardData::default();
                        pfd.source_to_destination = true;
                        pfd.socket_id = socket_id;
                        pfd.buffer = buf[..n].to_vec();
                        data_to_send.push(pfd);
                    }
                    Err(e) => {
                        debug!("Read error on socket {}: {}", socket_id, e);
                    }
                }
            }
        }
        drop(socket_map);

        // Close dead connections
        for socket_id in to_close {
            self.close_socket(socket_id);
        }
    }

    /// Accept a new connection if available
    pub fn listen(&self) -> Option<RawFd> {
        let listen_fds = self.listen_fds.lock();
        for &fd in listen_fds.iter() {
            if self.socket_handler.has_data(fd) {
                if let Ok(client_fd) = self.socket_handler.accept(fd) {
                    self.unassigned_fds.lock().push(client_fd);
                    return Some(client_fd);
                }
            }
        }
        None
    }

    /// Check if we have an unassigned fd
    pub fn has_unassigned_fd(&self, fd: RawFd) -> bool {
        self.unassigned_fds.lock().contains(&fd)
    }

    /// Close an unassigned fd
    pub fn close_unassigned_fd(&self, fd: RawFd) {
        let mut unassigned = self.unassigned_fds.lock();
        if let Some(pos) = unassigned.iter().position(|&x| x == fd) {
            unassigned.remove(pos);
            self.socket_handler.close(fd);
        }
    }

    /// Add a socket ID mapping for an unassigned fd
    pub fn add_socket(&self, socket_id: i32, fd: RawFd) {
        let mut unassigned = self.unassigned_fds.lock();
        if let Some(pos) = unassigned.iter().position(|&x| x == fd) {
            unassigned.remove(pos);
            self.socket_map.lock().insert(socket_id, fd);
        }
    }

    /// Close a socket by ID
    pub fn close_socket(&self, socket_id: i32) {
        if let Some(fd) = self.socket_map.lock().remove(&socket_id) {
            self.socket_handler.close(fd);
        }
    }

    /// Send data on a socket
    pub fn send_data_on_socket(&self, socket_id: i32, data: &[u8]) {
        if let Some(&fd) = self.socket_map.lock().get(&socket_id) {
            let _ = self.socket_handler.write(fd, data);
        }
    }
}

/// Handles a destination connection for port forwarding
pub struct ForwardDestinationHandler {
    /// Socket handler for operations
    socket_handler: Arc<dyn SocketHandler>,
    /// Connected socket fd
    fd: Mutex<RawFd>,
    /// Socket ID for this destination
    socket_id: i32,
}

impl ForwardDestinationHandler {
    /// Creates a new destination handler
    pub fn new(socket_handler: Arc<dyn SocketHandler>, fd: RawFd, socket_id: i32) -> Self {
        Self {
            socket_handler,
            fd: Mutex::new(fd),
            socket_id,
        }
    }

    /// Get the socket fd
    pub fn fd(&self) -> RawFd {
        *self.fd.lock()
    }

    /// Check for data and generate port forward data
    pub fn update(&self, data_to_send: &mut Vec<PortForwardData>) {
        let fd = *self.fd.lock();
        if fd < 0 {
            return;
        }

        if self.socket_handler.has_data(fd) {
            let mut buf = vec![0u8; 16 * 1024];
            match self.socket_handler.read(fd, &mut buf) {
                Ok(0) => {
                    // Connection closed
                    self.close();
                    let mut pfd = PortForwardData::default();
                    pfd.source_to_destination = false;
                    pfd.socket_id = self.socket_id;
                    pfd.closed = true;
                    data_to_send.push(pfd);
                }
                Ok(n) => {
                    let mut pfd = PortForwardData::default();
                    pfd.source_to_destination = false;
                    pfd.socket_id = self.socket_id;
                    pfd.buffer = buf[..n].to_vec();
                    data_to_send.push(pfd);
                }
                Err(_) => {}
            }
        }
    }

    /// Write data to the destination
    pub fn write(&self, data: &[u8]) {
        let fd = *self.fd.lock();
        if fd >= 0 {
            let _ = self.socket_handler.write(fd, data);
        }
    }

    /// Close the destination connection
    pub fn close(&self) {
        let mut fd = self.fd.lock();
        if *fd >= 0 {
            self.socket_handler.close(*fd);
            *fd = -1;
        }
    }
}

/// Coordinates port forwarding requests, source/destination sockets, and data flow
pub struct PortForwardHandler {
    /// Handler used for network-facing sockets
    network_socket_handler: Arc<dyn SocketHandler>,
    /// Handler used for pipe-facing sockets
    pipe_socket_handler: Arc<dyn SocketHandler>,
    /// Active destination handlers keyed by socket id
    destination_handlers: Mutex<HashMap<i32, Arc<ForwardDestinationHandler>>>,
    /// Handlers for the listening port forward sources
    source_handlers: Mutex<Vec<Arc<ForwardSourceHandler>>>,
    /// Maps socket IDs to their source handlers
    socket_id_source_handler_map: Mutex<HashMap<i32, Arc<ForwardSourceHandler>>>,
}

impl PortForwardHandler {
    /// Creates a new port forward handler
    pub fn new(
        network_socket_handler: Arc<dyn SocketHandler>,
        pipe_socket_handler: Arc<dyn SocketHandler>,
    ) -> Self {
        Self {
            network_socket_handler,
            pipe_socket_handler,
            destination_handlers: Mutex::new(HashMap::new()),
            source_handlers: Mutex::new(Vec::new()),
            socket_id_source_handler_map: Mutex::new(HashMap::new()),
        }
    }

    /// Polls all handlers for new connections and data
    pub fn update(
        &self,
        requests: &mut Vec<PortForwardDestinationRequest>,
        data_to_send: &mut Vec<PortForwardData>,
    ) {
        // Update source handlers
        for handler in self.source_handlers.lock().iter() {
            handler.update(data_to_send);
            if let Some(fd) = handler.listen() {
                let mut pfr = PortForwardDestinationRequest::default();
                pfr.destination = Some(handler.destination().clone());
                pfr.fd = fd;
                requests.push(pfr);
            }
        }

        // Update destination handlers
        let mut to_remove = Vec::new();
        {
            let handlers = self.destination_handlers.lock();
            for (&socket_id, handler) in handlers.iter() {
                handler.update(data_to_send);
                if handler.fd() == -1 {
                    to_remove.push(socket_id);
                }
            }
        }

        // Remove dead handlers
        let mut handlers = self.destination_handlers.lock();
        for socket_id in to_remove {
            handlers.remove(&socket_id);
        }
    }

    /// Creates a source handler for a port forward request
    pub fn create_source(
        &self,
        pfsr: &PortForwardSourceRequest,
    ) -> Result<PortForwardSourceResponse> {
        let source = pfsr.source.clone().unwrap_or_default();
        let destination = pfsr.destination.clone().unwrap_or_default();

        let handler = if source.port > 0 {
            Arc::new(ForwardSourceHandler::new(
                self.network_socket_handler.clone(),
                source,
                destination,
            )?)
        } else {
            Arc::new(ForwardSourceHandler::new(
                self.pipe_socket_handler.clone(),
                source,
                destination,
            )?)
        };

        self.source_handlers.lock().push(handler);
        Ok(PortForwardSourceResponse::default())
    }

    /// Creates a destination handler for a port forward request
    pub fn create_destination(
        &self,
        pfdr: &PortForwardDestinationRequest,
    ) -> PortForwardDestinationResponse {
        let destination = pfdr.destination.clone().unwrap_or_default();
        let is_tcp = destination.port > 0;

        let fd = if is_tcp {
            // Try IPv6 first, then IPv4
            let ipv6_endpoint = et_lib::socket::SocketEndpoint::new("::1", destination.port as u16);
            match self.network_socket_handler.connect(&ipv6_endpoint) {
                Ok(fd) if fd >= 0 => fd,
                _ => {
                    let ipv4_endpoint =
                        et_lib::socket::SocketEndpoint::new("127.0.0.1", destination.port as u16);
                    self.network_socket_handler
                        .connect(&ipv4_endpoint)
                        .unwrap_or(-1)
                }
            }
        } else {
            let endpoint = et_lib::socket::SocketEndpoint::new(&destination.name, 0);
            self.pipe_socket_handler.connect(&endpoint).unwrap_or(-1)
        };

        let mut response = PortForwardDestinationResponse::default();
        response.client_fd = pfdr.fd;

        if fd == -1 {
            response.error = "Connection failed".to_string();
        } else {
            let socket_id = rand::thread_rng().gen::<i32>().abs();
            info!("Created socket/fd pair: {} {}", socket_id, fd);

            let handler = Arc::new(ForwardDestinationHandler::new(
                if is_tcp {
                    self.network_socket_handler.clone()
                } else {
                    self.pipe_socket_handler.clone()
                },
                fd,
                socket_id,
            ));

            self.destination_handlers.lock().insert(socket_id, handler);
            response.socket_id = socket_id;
        }

        response
    }

    /// Handles a packet related to port forwarding
    pub fn handle_packet(&self, packet: &Packet, connection: &Arc<Connection>) {
        match packet.header() {
            terminal_packet_type::PORT_FORWARD_DATA => {
                if let Ok(pwd) = PortForwardData::decode(packet.payload()) {
                    if pwd.source_to_destination {
                        debug!("Got data for destination socket: {}", pwd.socket_id);
                        let handlers = self.destination_handlers.lock();
                        if let Some(handler) = handlers.get(&pwd.socket_id) {
                            if pwd.closed || !pwd.error.is_empty() {
                                info!("Port forward socket closed: {}", pwd.socket_id);
                                handler.close();
                            } else {
                                handler.write(&pwd.buffer);
                            }
                        } else {
                            warn!(
                                "Got data for a socket id that has already closed: {}",
                                pwd.socket_id
                            );
                        }
                    } else if pwd.closed || !pwd.error.is_empty() {
                        info!("Port forward socket closed: {}", pwd.socket_id);
                        self.close_source_socket_id(pwd.socket_id);
                    } else {
                        debug!("Got data for source socket: {}", pwd.socket_id);
                        self.send_data_to_source_on_socket(pwd.socket_id, &pwd.buffer);
                    }
                }
            }
            terminal_packet_type::PORT_FORWARD_DESTINATION_REQUEST => {
                if let Ok(pfdr) = PortForwardDestinationRequest::decode(packet.payload()) {
                    info!("Got new port destination request");
                    let response = self.create_destination(&pfdr);
                    let send_packet = Packet::new(
                        terminal_packet_type::PORT_FORWARD_DESTINATION_RESPONSE,
                        response.encode_to_vec(),
                    );
                    connection.write_packet(send_packet);
                }
            }
            terminal_packet_type::PORT_FORWARD_DESTINATION_RESPONSE => {
                if let Ok(pfdr) = PortForwardDestinationResponse::decode(packet.payload()) {
                    if !pfdr.error.is_empty() {
                        info!("Could not connect to server through tunnel: {}", pfdr.error);
                        self.close_source_fd(pfdr.client_fd);
                    } else {
                        info!(
                            "Received socket/fd map from server: {} {}",
                            pfdr.socket_id, pfdr.client_fd
                        );
                        self.add_source_socket_id(pfdr.socket_id, pfdr.client_fd);
                    }
                }
            }
            _ => {
                warn!("Unknown packet type: {}", packet.header());
            }
        }
    }

    /// Closes an unassigned source fd
    fn close_source_fd(&self, fd: RawFd) {
        for handler in self.source_handlers.lock().iter() {
            if handler.has_unassigned_fd(fd) {
                handler.close_unassigned_fd(fd);
                return;
            }
        }
    }

    /// Adds a socket ID mapping for a source
    fn add_source_socket_id(&self, socket_id: i32, source_fd: RawFd) {
        for handler in self.source_handlers.lock().iter() {
            if handler.has_unassigned_fd(source_fd) {
                handler.add_socket(socket_id, source_fd);
                self.socket_id_source_handler_map
                    .lock()
                    .insert(socket_id, handler.clone());
                return;
            }
        }
    }

    /// Closes a source socket by ID
    fn close_source_socket_id(&self, socket_id: i32) {
        if let Some(handler) = self.socket_id_source_handler_map.lock().remove(&socket_id) {
            handler.close_socket(socket_id);
        }
    }

    /// Sends data to a source socket
    fn send_data_to_source_on_socket(&self, socket_id: i32, data: &[u8]) {
        if let Some(handler) = self.socket_id_source_handler_map.lock().get(&socket_id) {
            handler.send_data_on_socket(socket_id, data);
        }
    }
}
