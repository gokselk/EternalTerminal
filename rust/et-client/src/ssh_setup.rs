//! SSH setup and subprocess handling

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use tracing::{debug, info};

/// Handles SSH setup and connection establishment
pub struct SshSetupHandler {
    /// SSH host
    host: String,
    /// SSH user
    user: Option<String>,
    /// SSH port
    port: u16,
    /// Jump host (ProxyJump)
    jumphost: Option<String>,
    /// Additional SSH options
    ssh_options: Vec<String>,
    /// Identity file
    identity_file: Option<String>,
}

impl SshSetupHandler {
    /// Creates a new SSH setup handler
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            user: None,
            port: 22,
            jumphost: None,
            ssh_options: Vec::new(),
            identity_file: None,
        }
    }

    /// Sets the SSH user
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Sets the SSH port
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the jump host
    pub fn jumphost(mut self, jumphost: impl Into<String>) -> Self {
        self.jumphost = Some(jumphost.into());
        self
    }

    /// Adds an SSH option
    pub fn option(mut self, option: impl Into<String>) -> Self {
        self.ssh_options.push(option.into());
        self
    }

    /// Sets the identity file
    pub fn identity_file(mut self, path: impl Into<String>) -> Self {
        self.identity_file = Some(path.into());
        self
    }

    /// Builds the SSH command
    pub fn build_ssh_command(&self, et_port: u16, passkey: &str) -> Command {
        let mut cmd = Command::new("ssh");

        // Add user if specified
        if let Some(ref user) = self.user {
            cmd.arg("-l").arg(user);
        }

        // Add port
        cmd.arg("-p").arg(self.port.to_string());

        // Add jump host if specified
        if let Some(ref jumphost) = self.jumphost {
            cmd.arg("-J").arg(jumphost);
        }

        // Add identity file if specified
        if let Some(ref identity) = self.identity_file {
            cmd.arg("-i").arg(identity);
        }

        // Add custom options
        for option in &self.ssh_options {
            cmd.arg("-o").arg(option);
        }

        // Add host
        cmd.arg(&self.host);

        // ET terminal command
        let et_command = format!("etterminal -c {} -p {}", passkey, et_port);
        cmd.arg(et_command);

        // Configure stdio
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        cmd
    }

    /// Spawns the SSH process and returns the child
    pub fn spawn(&self, et_port: u16, passkey: &str) -> std::io::Result<Child> {
        let mut cmd = self.build_ssh_command(et_port, passkey);
        info!("Spawning SSH connection to {}:{}", self.host, self.port);
        cmd.spawn()
    }

    /// Runs SSH and extracts the connection information
    pub fn run(&self, et_port: u16, passkey: &str) -> std::io::Result<SshConnectionInfo> {
        let mut child = self.spawn(et_port, passkey)?;

        // Read stdout for connection info
        let stdout = child.stdout.take().expect("Failed to get stdout");
        let reader = BufReader::new(stdout);

        let mut id = None;
        let mut key = None;

        for line in reader.lines() {
            let line = line?;
            debug!("SSH output: {}", line);

            // Parse connection info from etterminal output
            if line.starts_with("IDPASSKEY:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let id_key: Vec<&str> = parts[1].splitn(2, '/').collect();
                    if id_key.len() == 2 {
                        id = Some(id_key[0].to_string());
                        key = Some(id_key[1].to_string());
                        break;
                    }
                }
            }
        }

        match (id, key) {
            (Some(id), Some(key)) => Ok(SshConnectionInfo { id, key, child }),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to parse connection info from SSH",
            )),
        }
    }
}

/// Information extracted from SSH connection
pub struct SshConnectionInfo {
    /// Connection ID
    pub id: String,
    /// Connection passkey
    pub key: String,
    /// SSH child process
    pub child: Child,
}

impl SshConnectionInfo {
    /// Wait for the SSH process to exit
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait()
    }

    /// Kill the SSH process
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }
}

/// Parse tunnel specification (e.g., "8080:localhost:80" or "8000:9000")
pub fn parse_tunnel_spec(spec: &str) -> Option<(String, u16, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();

    match parts.len() {
        // "localport:remoteport" format
        2 => {
            let local_port: u16 = parts[0].parse().ok()?;
            let remote_port: u16 = parts[1].parse().ok()?;
            Some((
                "127.0.0.1".to_string(),
                local_port,
                "127.0.0.1".to_string(),
                remote_port,
            ))
        }
        // "localport:remotehost:remoteport" or "localhost:localport:remoteport"
        3 => {
            if let Ok(local_port) = parts[0].parse::<u16>() {
                let remote_port: u16 = parts[2].parse().ok()?;
                Some((
                    "127.0.0.1".to_string(),
                    local_port,
                    parts[1].to_string(),
                    remote_port,
                ))
            } else {
                let local_port: u16 = parts[1].parse().ok()?;
                let remote_port: u16 = parts[2].parse().ok()?;
                Some((
                    parts[0].to_string(),
                    local_port,
                    "127.0.0.1".to_string(),
                    remote_port,
                ))
            }
        }
        // "localhost:localport:remotehost:remoteport"
        4 => {
            let local_port: u16 = parts[1].parse().ok()?;
            let remote_port: u16 = parts[3].parse().ok()?;
            Some((
                parts[0].to_string(),
                local_port,
                parts[2].to_string(),
                remote_port,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tunnel_spec_simple() {
        let result = parse_tunnel_spec("8080:9090");
        assert!(result.is_some());
        let (lh, lp, rh, rp) = result.unwrap();
        assert_eq!(lh, "127.0.0.1");
        assert_eq!(lp, 8080);
        assert_eq!(rh, "127.0.0.1");
        assert_eq!(rp, 9090);
    }

    #[test]
    fn test_parse_tunnel_spec_with_remote_host() {
        let result = parse_tunnel_spec("8080:example.com:80");
        assert!(result.is_some());
        let (lh, lp, rh, rp) = result.unwrap();
        assert_eq!(lh, "127.0.0.1");
        assert_eq!(lp, 8080);
        assert_eq!(rh, "example.com");
        assert_eq!(rp, 80);
    }

    #[test]
    fn test_parse_tunnel_spec_full() {
        let result = parse_tunnel_spec("0.0.0.0:8080:example.com:80");
        assert!(result.is_some());
        let (lh, lp, rh, rp) = result.unwrap();
        assert_eq!(lh, "0.0.0.0");
        assert_eq!(lp, 8080);
        assert_eq!(rh, "example.com");
        assert_eq!(rp, 80);
    }

    #[test]
    fn test_ssh_setup_handler() {
        let handler = SshSetupHandler::new("example.com")
            .user("user")
            .port(22)
            .jumphost("jump.example.com");

        assert_eq!(handler.host, "example.com");
        assert_eq!(handler.user, Some("user".to_string()));
        assert_eq!(handler.port, 22);
        assert_eq!(handler.jumphost, Some("jump.example.com".to_string()));
    }
}
