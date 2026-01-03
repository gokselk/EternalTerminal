//! Console handling for terminal I/O

use crate::terminal_info::TerminalInfo;
use et_lib::socket::RawSocketUtils;
use nix::libc;
use parking_lot::Mutex;
use std::io;
use std::os::unix::io::RawFd;

/// Abstract console interface used by TerminalClient or terminal emulators
pub trait Console: Send + Sync {
    /// Returns metadata about the console (size, pixels)
    fn get_terminal_info(&self) -> TerminalInfo;

    /// Prepares the console/terminal before handing control to ET
    fn setup(&mut self) -> io::Result<()>;

    /// Restores the console state before exiting ET
    fn teardown(&mut self) -> io::Result<()>;

    /// Provides the descriptor that receives terminal input
    fn get_fd(&self) -> RawFd;

    /// Writes data to the console
    fn write(&self, data: &[u8]) -> io::Result<()>;
}

/// Console implementation that configures the local console into raw mode
pub struct PseudoTerminalConsole {
    /// Backup of the terminal's termios state for teardown (using libc type for Sync safety)
    terminal_backup: Mutex<Option<libc::termios>>,
    /// Whether the terminal has been set up
    is_setup: Mutex<bool>,
}

impl PseudoTerminalConsole {
    /// Creates a new console and saves the current terminal state
    pub fn new() -> io::Result<Self> {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut termios) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            terminal_backup: Mutex::new(Some(termios)),
            is_setup: Mutex::new(false),
        })
    }
}

impl Default for PseudoTerminalConsole {
    fn default() -> Self {
        Self::new().expect("Failed to get terminal attributes")
    }
}

impl Console for PseudoTerminalConsole {
    fn get_terminal_info(&self) -> TerminalInfo {
        TerminalInfo::from_stdout()
    }

    fn setup(&mut self) -> io::Result<()> {
        let mut is_setup = self.is_setup.lock();
        if *is_setup {
            return Ok(());
        }

        // Get current terminal attributes
        let mut terminal_local: libc::termios = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut terminal_local) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        // Save backup
        *self.terminal_backup.lock() = Some(terminal_local);

        // Set raw mode using cfmakeraw
        unsafe { libc::cfmakeraw(&mut terminal_local) };

        // Apply settings
        let result = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &terminal_local) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        *is_setup = true;
        Ok(())
    }

    fn teardown(&mut self) -> io::Result<()> {
        let mut is_setup = self.is_setup.lock();
        if !*is_setup {
            return Ok(());
        }

        // Restore original terminal settings
        let backup = self.terminal_backup.lock();
        if let Some(ref termios) = *backup {
            let result = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, termios) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        *is_setup = false;
        Ok(())
    }

    fn get_fd(&self) -> RawFd {
        libc::STDIN_FILENO
    }

    fn write(&self, data: &[u8]) -> io::Result<()> {
        RawSocketUtils::write_all(libc::STDOUT_FILENO, data)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

impl Drop for PseudoTerminalConsole {
    fn drop(&mut self) {
        if *self.is_setup.lock() {
            let _ = self.teardown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests need an actual terminal to run properly
    // They are disabled in CI environments

    #[test]
    #[ignore]
    fn test_console_creation() {
        let console = PseudoTerminalConsole::new();
        assert!(console.is_ok());
    }

    #[test]
    #[ignore]
    fn test_get_terminal_info() {
        let console = PseudoTerminalConsole::new().unwrap();
        let info = console.get_terminal_info();
        assert!(info.row > 0);
        assert!(info.column > 0);
    }
}
