//! etterminal - Helper binary launched by SSH to connect to etserver

use clap::Parser;
use et_lib::crypto::CryptoHandler;
use et_lib::socket::{SocketEndpoint, SocketHandler, TcpSocketHandler};
use std::os::fd::BorrowedFd;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

/// Helper to create a BorrowedFd from a RawFd
/// SAFETY: The caller must ensure the fd is valid for the duration of the borrow
unsafe fn borrow_fd(fd: RawFd) -> BorrowedFd<'static> {
    BorrowedFd::borrow_raw(fd)
}

/// Eternal Terminal - Terminal helper for SSH handshake
#[derive(Parser, Debug)]
#[command(name = "etterminal")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to connect to
    #[arg(short, long, default_value_t = 2022)]
    port: u16,

    /// Connection passkey (provided by client)
    #[arg(short = 'c', long)]
    passkey: Option<String>,

    /// Verbose logging level
    #[arg(short, long, default_value_t = 0)]
    verbose: u8,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set up logging to stderr
    let log_level = match args.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("etterminal starting");

    // Generate connection credentials
    let id = Uuid::new_v4().to_string();
    let key_bytes = CryptoHandler::generate_key();
    let passkey = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_bytes);

    // Output credentials for the client
    // Format: IDPASSKEY:id/passkey
    println!("IDPASSKEY:{}/{}", id, passkey);

    // Connect to the local etserver
    let socket_handler: Arc<dyn SocketHandler> = Arc::new(TcpSocketHandler::new());
    let endpoint = SocketEndpoint::new("127.0.0.1", args.port);

    info!("Connecting to etserver on port {}", args.port);

    let fd = socket_handler.connect(&endpoint)?;

    if fd < 0 {
        eprintln!("Failed to connect to etserver on port {}", args.port);
        std::process::exit(1);
    }

    info!("Connected to etserver");

    // The etterminal process becomes a relay between the SSH session
    // and the etserver. In the full implementation, this would:
    // 1. Authenticate with etserver using the generated credentials
    // 2. Create a PTY and run the user's shell
    // 3. Forward I/O between the PTY and etserver

    // For now, we'll create a simple PTY session
    use et_terminal::pty::{PseudoUserTerminal, UserTerminal};
    use nix::libc;
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};

    let mut terminal = PseudoUserTerminal::new();
    let master_fd = terminal.setup(-1)?;

    info!("PTY started with master fd {}", master_fd);

    // Proxy between stdin/stdout and the PTY
    let mut buf = [0u8; 16384];

    loop {
        // SAFETY: STDIN_FILENO and master_fd are valid for the duration of this loop
        let stdin_borrowed = unsafe { borrow_fd(libc::STDIN_FILENO) };
        let master_borrowed = unsafe { borrow_fd(master_fd) };

        let mut poll_fds = [
            PollFd::new(stdin_borrowed, PollFlags::POLLIN),
            PollFd::new(master_borrowed, PollFlags::POLLIN),
        ];

        if poll(&mut poll_fds, PollTimeout::from(100u16)).is_err() {
            continue;
        }

        // Check stdin
        if poll_fds[0]
            .revents()
            .map(|e| e.contains(PollFlags::POLLIN))
            .unwrap_or(false)
        {
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };

            if n > 0 {
                unsafe {
                    libc::write(master_fd, buf.as_ptr() as *const libc::c_void, n as usize);
                }
            } else if n == 0 {
                break; // EOF
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    break;
                }
            }
        }

        // Check PTY
        if poll_fds[1]
            .revents()
            .map(|e| e.contains(PollFlags::POLLIN))
            .unwrap_or(false)
        {
            let n =
                unsafe { libc::read(master_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

            if n > 0 {
                unsafe {
                    libc::write(
                        libc::STDOUT_FILENO,
                        buf.as_ptr() as *const libc::c_void,
                        n as usize,
                    );
                }
            } else if n == 0 {
                break; // EOF
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    break;
                }
            }
        }

        // Check for HUP on PTY (terminal closed)
        if poll_fds[1]
            .revents()
            .map(|e| e.contains(PollFlags::POLLHUP))
            .unwrap_or(false)
        {
            break;
        }
    }

    terminal.cleanup();
    let _ = terminal.handle_session_end();

    info!("etterminal exiting");
    Ok(())
}
