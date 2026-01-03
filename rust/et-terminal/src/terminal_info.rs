//! Terminal information (size, pixels, etc.)

use nix::libc;
use std::os::unix::io::RawFd;

/// Terminal dimensions and metadata
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TerminalInfo {
    /// Unique identifier for the terminal
    pub id: String,
    /// Number of rows
    pub row: i32,
    /// Number of columns
    pub column: i32,
    /// Width in pixels
    pub width: i32,
    /// Height in pixels
    pub height: i32,
}

impl TerminalInfo {
    /// Creates a new empty terminal info
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates terminal info with dimensions
    pub fn with_size(row: i32, column: i32) -> Self {
        Self {
            id: String::new(),
            row,
            column,
            width: 0,
            height: 0,
        }
    }

    /// Query the current terminal dimensions from stdout
    pub fn from_stdout() -> Self {
        Self::from_fd(libc::STDOUT_FILENO)
    }

    /// Query terminal dimensions from a file descriptor
    pub fn from_fd(fd: RawFd) -> Self {
        let mut win = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        unsafe {
            if libc::ioctl(fd, libc::TIOCGWINSZ, &mut win) == 0 {
                return Self {
                    id: String::new(),
                    row: win.ws_row as i32,
                    column: win.ws_col as i32,
                    width: win.ws_xpixel as i32,
                    height: win.ws_ypixel as i32,
                };
            }
        }

        // Default fallback
        Self {
            id: String::new(),
            row: 24,
            column: 80,
            width: 0,
            height: 0,
        }
    }

    /// Convert to a winsize struct for use with ioctl
    pub fn to_winsize(&self) -> libc::winsize {
        libc::winsize {
            ws_row: self.row as u16,
            ws_col: self.column as u16,
            ws_xpixel: self.width as u16,
            ws_ypixel: self.height as u16,
        }
    }
}

impl From<et_lib::proto::TerminalInfo> for TerminalInfo {
    fn from(proto: et_lib::proto::TerminalInfo) -> Self {
        Self {
            id: proto.id,
            row: proto.row,
            column: proto.column,
            width: proto.width,
            height: proto.height,
        }
    }
}

impl From<TerminalInfo> for et_lib::proto::TerminalInfo {
    fn from(info: TerminalInfo) -> Self {
        Self {
            id: info.id,
            row: info.row,
            column: info.column,
            width: info.width,
            height: info.height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_info_default() {
        let info = TerminalInfo::new();
        assert_eq!(info.row, 0);
        assert_eq!(info.column, 0);
    }

    #[test]
    fn test_terminal_info_with_size() {
        let info = TerminalInfo::with_size(24, 80);
        assert_eq!(info.row, 24);
        assert_eq!(info.column, 80);
    }

    #[test]
    fn test_to_winsize() {
        let info = TerminalInfo::with_size(24, 80);
        let win = info.to_winsize();
        assert_eq!(win.ws_row, 24);
        assert_eq!(win.ws_col, 80);
    }
}
