//! Pseudo-terminal (PTY) handling

use crate::terminal_info::TerminalInfo;
use nix::libc;
use nix::pty::{forkpty, ForkptyResult};
use nix::sys::signal::{signal, SigHandler, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execvp, getuid, Pid};
use std::ffi::CString;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use tracing::{debug, info};

/// Abstract terminal that can be started, resized, and observed through a fd
pub trait UserTerminal: Send + Sync {
    /// Prepares the terminal and configures it using the router endpoint
    fn setup(&mut self, router_fd: RawFd) -> io::Result<RawFd>;

    /// Returns the descriptor that can be polled for terminal output
    fn get_fd(&self) -> RawFd;

    /// Applies the current window geometry to the running terminal
    fn set_info(&self, info: &TerminalInfo);

    /// Blocks until the terminal child process ends
    fn handle_session_end(&self) -> io::Result<()>;

    /// Reclaims resources allocated by the terminal implementation
    fn cleanup(&mut self);
}

/// Forks a pseudo-terminal, runs the user's shell, and proxies the fd
pub struct PseudoUserTerminal {
    /// PID of the child shell spawned by forkpty
    pid: Option<Pid>,
    /// Master PTY file descriptor
    master_fd: RawFd,
}

impl PseudoUserTerminal {
    /// Creates a new pseudo user terminal
    pub fn new() -> Self {
        Self {
            pid: None,
            master_fd: -1,
        }
    }

    /// Executes the login shell after setting up the PTY child process
    fn run_terminal(&self) -> ! {
        // Get user's home directory and shell
        let uid = getuid();
        let pwd = unsafe { libc::getpwuid(uid.as_raw()) };

        if !pwd.is_null() {
            let home_dir = unsafe { std::ffi::CStr::from_ptr((*pwd).pw_dir) };
            if let Ok(home) = home_dir.to_str() {
                let _ = chdir(home);
            }
        }

        // Get the shell from environment or passwd
        let shell = std::env::var("SHELL").unwrap_or_else(|_| {
            if !pwd.is_null() {
                let shell = unsafe { std::ffi::CStr::from_ptr((*pwd).pw_shell) };
                shell.to_str().unwrap_or("/bin/sh").to_string()
            } else {
                "/bin/sh".to_string()
            }
        });

        info!("Child process launching terminal {}", shell);

        // Set ET_VERSION environment variable
        std::env::set_var("ET_VERSION", env!("CARGO_PKG_VERSION"));

        // Reset SIGCHLD to SIG_DFL
        // This is important for proper subprocess handling in the shell
        unsafe {
            let _ = signal(Signal::SIGCHLD, SigHandler::SigDfl);
        }

        // Execute the shell with -l flag for login shell
        let shell_cstr = CString::new(shell.as_str()).expect("CString creation failed");
        let login_flag = CString::new("-l").expect("CString creation failed");
        let args = [shell_cstr.as_c_str(), login_flag.as_c_str()];

        // This only returns if execvp fails
        let _ = execvp(&shell_cstr, &args);

        // If we get here, exec failed
        std::process::exit(1);
    }
}

impl Default for PseudoUserTerminal {
    fn default() -> Self {
        Self::new()
    }
}

impl UserTerminal for PseudoUserTerminal {
    fn setup(&mut self, router_fd: RawFd) -> io::Result<RawFd> {
        // Fork with a new PTY
        let result = unsafe { forkpty(None, None) }.map_err(|e| io::Error::other(e.to_string()))?;

        match result {
            ForkptyResult::Parent { child, master } => {
                self.pid = Some(child);
                self.master_fd = master.as_raw_fd();
                // Forget the master fd to prevent it from being closed
                std::mem::forget(master);
                debug!("PTY master fd: {}", self.master_fd);
                Ok(self.master_fd)
            }
            ForkptyResult::Child => {
                // Close router fd in child
                let _ = nix::unistd::close(router_fd);

                // Run the terminal (never returns)
                self.run_terminal();
            }
        }
    }

    fn get_fd(&self) -> RawFd {
        self.master_fd
    }

    fn set_info(&self, info: &TerminalInfo) {
        if self.master_fd < 0 {
            return;
        }

        let win = info.to_winsize();
        unsafe {
            libc::ioctl(self.master_fd, libc::TIOCSWINSZ, &win);
        }
    }

    fn handle_session_end(&self) -> io::Result<()> {
        if let Some(pid) = self.pid {
            match waitpid(pid, None) {
                Ok(WaitStatus::Exited(_, _)) => Ok(()),
                Ok(WaitStatus::Signaled(_, _, _)) => Ok(()),
                Ok(_) => Ok(()),
                Err(e) => Err(io::Error::other(e.to_string())),
            }
        } else {
            Ok(())
        }
    }

    fn cleanup(&mut self) {
        if self.master_fd >= 0 {
            let _ = nix::unistd::close(self.master_fd);
            self.master_fd = -1;
        }
    }
}

impl Drop for PseudoUserTerminal {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pseudo_user_terminal_new() {
        let terminal = PseudoUserTerminal::new();
        assert!(terminal.pid.is_none());
        assert_eq!(terminal.master_fd, -1);
    }
}
