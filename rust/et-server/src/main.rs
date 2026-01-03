//! Eternal Terminal server binary

use clap::Parser;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod server_connection;
mod terminal_server;
mod user_terminal_handler;

use terminal_server::TerminalServer;

/// Eternal Terminal Server - Accepts client connections for remote terminals
#[derive(Parser, Debug)]
#[command(name = "etserver")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 2022)]
    port: u16,

    /// IP address to bind to (empty for all interfaces)
    #[arg(short, long)]
    bind: Option<String>,

    /// Run as a daemon
    #[arg(short, long)]
    daemon: bool,

    /// Configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Log directory
    #[arg(long)]
    logdir: Option<PathBuf>,

    /// PID file
    #[arg(long)]
    pidfile: Option<PathBuf>,

    /// Verbose logging level (0-4)
    #[arg(short, long, default_value_t = 0)]
    verbose: u8,
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

    info!("Eternal Terminal server starting");

    // Load configuration if specified
    if let Some(config_path) = &args.config {
        if config_path.exists() {
            info!("Loading configuration from {:?}", config_path);
            // Parse configuration file
            let mut config = configparser::ini::Ini::new();
            if let Err(e) = config.load(config_path) {
                eprintln!("Failed to load configuration: {}", e);
            }
        }
    }

    // Daemonize if requested
    if args.daemon {
        info!("Daemonizing...");
        daemonize(args.pidfile.as_ref())?;
    }

    // Create and run the server
    let server = TerminalServer::new(args.port, args.bind.as_deref())?;

    // Set up signal handlers
    let server_arc = std::sync::Arc::new(server);
    let server_clone = server_arc.clone();

    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        server_clone.stop();
    })?;

    // Run the server
    server_arc.run()?;

    info!("Server stopped");
    Ok(())
}

/// Daemonize the process
fn daemonize(pidfile: Option<&PathBuf>) -> anyhow::Result<()> {
    use nix::unistd::{fork, setsid, ForkResult};
    use std::fs::File;
    use std::io::Write;

    // First fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {}
        Err(e) => {
            return Err(anyhow::anyhow!("First fork failed: {}", e));
        }
    }

    // Create new session
    setsid()?;

    // Second fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {}
        Err(e) => {
            return Err(anyhow::anyhow!("Second fork failed: {}", e));
        }
    }

    // Write PID file
    if let Some(pidfile) = pidfile {
        let mut file = File::create(pidfile)?;
        writeln!(file, "{}", std::process::id())?;
    }

    // Close standard file descriptors
    let dev_null = std::fs::File::open("/dev/null")?;
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::dup2(dev_null.as_raw_fd(), libc::STDIN_FILENO);
        libc::dup2(dev_null.as_raw_fd(), libc::STDOUT_FILENO);
        libc::dup2(dev_null.as_raw_fd(), libc::STDERR_FILENO);
    }

    Ok(())
}
