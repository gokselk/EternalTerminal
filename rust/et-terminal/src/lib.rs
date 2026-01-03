//! Terminal handling for Eternal Terminal
//!
//! This library provides console and PTY management for the ET client and server.

pub mod console;
pub mod pty;
pub mod terminal_info;

pub use console::{Console, PseudoTerminalConsole};
pub use pty::PseudoUserTerminal;
pub use terminal_info::TerminalInfo;
