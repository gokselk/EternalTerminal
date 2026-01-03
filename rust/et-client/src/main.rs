//! Eternal Terminal client binary

use clap::Parser;
use et_lib::socket::{SocketEndpoint, TcpSocketHandler};
use et_terminal::console::PseudoTerminalConsole;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod client_connection;
mod port_forward;
mod ssh_setup;
mod terminal_client;

use terminal_client::TerminalClient;

/// Eternal Terminal - Remote shell that automatically reconnects without interrupting the session
#[derive(Parser, Debug)]
#[command(name = "et")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Destination host to connect to
    #[arg(value_name = "HOST")]
    host: String,

    /// Remote port to connect to
    #[arg(short, long, default_value_t = 2022)]
    port: u16,

    /// Username for SSH connection
    #[arg(short, long)]
    user: Option<String>,

    /// Command to execute on the remote host
    #[arg(short, long)]
    command: Option<String>,

    /// Keep the session alive after command completes
    #[arg(long)]
    noexit: bool,

    /// Local port forwarding (format: localport:remoteport or localport:host:remoteport)
    #[arg(short = 't', long)]
    tunnel: Option<String>,

    /// Reverse port forwarding
    #[arg(short = 'r', long)]
    reverse_tunnel: Option<String>,

    /// Jump host for ProxyJump
    #[arg(short = 'J', long)]
    jumphost: Option<String>,

    /// Keepalive interval in seconds
    #[arg(long, default_value_t = 5)]
    keepalive: u64,

    /// Verbose logging level (0-4)
    #[arg(short, long, default_value_t = 0)]
    verbose: u8,

    /// Connection passkey (for direct connection without SSH)
    #[arg(long)]
    passkey: Option<String>,

    /// Connection ID (for direct connection without SSH)
    #[arg(long)]
    id: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set up logging
    let log_level = match args.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Eternal Terminal client starting");
    info!("Connecting to {}:{}", args.host, args.port);

    // Create socket handlers
    let socket_handler = Arc::new(TcpSocketHandler::new());
    let pipe_socket_handler = Arc::new(TcpSocketHandler::new()); // Use TCP for now

    // Get connection credentials
    let (id, passkey) = if let (Some(id), Some(passkey)) = (args.id, args.passkey) {
        (id, passkey)
    } else {
        // Use SSH to establish connection and get credentials
        let mut ssh_handler = ssh_setup::SshSetupHandler::new(&args.host);

        if let Some(user) = args.user {
            ssh_handler = ssh_handler.user(user);
        }

        if let Some(jumphost) = args.jumphost.clone() {
            ssh_handler = ssh_handler.jumphost(jumphost);
        }

        // Run SSH to get connection info
        match ssh_handler.run(args.port, "placeholder") {
            Ok(info) => (info.id, info.key),
            Err(e) => {
                eprintln!("Failed to establish SSH connection: {}", e);
                eprintln!("You can use --id and --passkey for direct connection.");
                std::process::exit(1);
            }
        }
    };

    // Create endpoint
    let endpoint = SocketEndpoint::new(&args.host, args.port);

    // Create console
    let console: Option<Box<dyn et_terminal::console::Console>> = if args.command.is_none() {
        match PseudoTerminalConsole::new() {
            Ok(c) => Some(Box::new(c)),
            Err(e) => {
                eprintln!("Warning: Could not create console: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Create client
    let mut client = TerminalClient::new(
        socket_handler,
        pipe_socket_handler,
        endpoint,
        id,
        passkey,
        console,
        args.jumphost.is_some(),
        args.tunnel.as_deref().unwrap_or(""),
        args.reverse_tunnel.as_deref().unwrap_or(""),
        args.keepalive,
    )?;

    // Run the client
    client.run(args.command.as_deref(), args.noexit)?;

    Ok(())
}
