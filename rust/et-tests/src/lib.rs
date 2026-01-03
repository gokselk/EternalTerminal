//! Integration tests for Eternal Terminal

#[cfg(test)]
mod crypto_tests {
    use et_lib::crypto::CryptoHandler;
    use std::sync::Arc;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = CryptoHandler::generate_key();
        let crypto_sender = CryptoHandler::new(&key, 0).unwrap();
        let crypto_receiver = CryptoHandler::new(&key, 0).unwrap();

        let original = b"Hello, World! This is a test message.";
        let encrypted = crypto_sender.encrypt(original);

        assert_ne!(&encrypted[..], original);
        assert_eq!(encrypted.len(), original.len() + CryptoHandler::mac_bytes());

        let decrypted = crypto_receiver.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted[..], original);
    }

    #[test]
    fn test_multiple_messages() {
        let key = CryptoHandler::generate_key();
        let crypto_sender = CryptoHandler::new(&key, 0).unwrap();
        let crypto_receiver = CryptoHandler::new(&key, 0).unwrap();

        for i in 0..100 {
            let message = format!("Message number {}", i);
            let encrypted = crypto_sender.encrypt(message.as_bytes());
            let decrypted = crypto_receiver.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, message.as_bytes());
        }
    }

    #[test]
    fn test_key_mismatch() {
        let key1 = CryptoHandler::generate_key();
        let key2 = CryptoHandler::generate_key();

        let crypto_sender = CryptoHandler::new(&key1, 0).unwrap();
        let crypto_receiver = CryptoHandler::new(&key2, 0).unwrap();

        let message = b"Secret message";
        let encrypted = crypto_sender.encrypt(message);

        assert!(crypto_receiver.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_nonce_msb_mismatch() {
        let key = CryptoHandler::generate_key();
        let crypto_sender = CryptoHandler::new(&key, 0).unwrap();
        let crypto_receiver = CryptoHandler::new(&key, 1).unwrap();

        let message = b"Secret message";
        let encrypted = crypto_sender.encrypt(message);

        assert!(crypto_receiver.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Too short
        assert!(CryptoHandler::new(&short_key, 0).is_err());

        let long_key = vec![0u8; 64]; // Too long
        assert!(CryptoHandler::new(&long_key, 0).is_err());
    }
}

#[cfg(test)]
mod packet_tests {
    use et_lib::crypto::CryptoHandler;
    use et_lib::packet::Packet;
    use std::sync::Arc;

    #[test]
    fn test_packet_creation() {
        let packet = Packet::new(42, b"Hello".to_vec());
        assert_eq!(packet.header(), 42);
        assert_eq!(packet.payload(), b"Hello");
        assert!(!packet.is_encrypted());
    }

    #[test]
    fn test_packet_serialization() {
        let packet = Packet::new(42, b"Hello".to_vec());
        let serialized = packet.serialize();

        assert_eq!(serialized[0], 0); // Not encrypted
        assert_eq!(serialized[1], 42); // Header
        assert_eq!(&serialized[2..], b"Hello"); // Payload

        let deserialized = Packet::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized.header(), 42);
        assert_eq!(deserialized.payload(), b"Hello");
    }

    #[test]
    fn test_packet_encryption() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());

        let mut packet = Packet::new(42, b"Secret".to_vec());
        packet.encrypt(&crypto).unwrap();

        assert!(packet.is_encrypted());
        assert_ne!(packet.payload(), b"Secret");

        // Decrypt with same key
        let crypto_decrypt = Arc::new(CryptoHandler::new(&key, 0).unwrap());
        packet.decrypt(&crypto_decrypt).unwrap();

        assert!(!packet.is_encrypted());
        assert_eq!(packet.payload(), b"Secret");
    }

    #[test]
    fn test_packet_double_encrypt_fails() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());

        let mut packet = Packet::new(42, b"Secret".to_vec());
        packet.encrypt(&crypto).unwrap();

        // Second encryption should fail
        assert!(packet.encrypt(&crypto).is_err());
    }

    #[test]
    fn test_packet_decrypt_unencrypted_fails() {
        let key = CryptoHandler::generate_key();
        let crypto = Arc::new(CryptoHandler::new(&key, 0).unwrap());

        let mut packet = Packet::new(42, b"Not encrypted".to_vec());

        // Decrypting unencrypted packet should fail
        assert!(packet.decrypt(&crypto).is_err());
    }
}

#[cfg(test)]
mod connection_tests {
    use et_lib::connection::Connection;
    use et_lib::socket::TcpSocketHandler;
    use std::sync::Arc;

    #[test]
    fn test_connection_creation() {
        let handler = Arc::new(TcpSocketHandler::new());
        let conn = Connection::new(handler, "test-id", "12345678901234567890123456789012");

        assert_eq!(conn.id(), "test-id");
        assert!(conn.is_disconnected());
        assert!(!conn.is_shutting_down());
    }

    #[test]
    fn test_connection_shutdown() {
        let handler = Arc::new(TcpSocketHandler::new());
        let conn = Connection::new(handler, "test-id", "12345678901234567890123456789012");

        conn.shutdown();
        assert!(conn.is_shutting_down());
    }
}

#[cfg(test)]
mod socket_tests {
    use et_lib::socket::{SocketEndpoint, SocketHandler, TcpSocketHandler};
    use std::sync::Arc;

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

#[cfg(test)]
mod terminal_info_tests {
    use et_terminal::TerminalInfo;

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

#[cfg(test)]
mod ssh_setup_tests {
    use et_client::ssh_setup::parse_tunnel_spec;

    #[test]
    fn test_parse_simple_tunnel() {
        let result = parse_tunnel_spec("8080:9090");
        assert!(result.is_some());
        let (lh, lp, rh, rp) = result.unwrap();
        assert_eq!(lh, "127.0.0.1");
        assert_eq!(lp, 8080);
        assert_eq!(rh, "127.0.0.1");
        assert_eq!(rp, 9090);
    }

    #[test]
    fn test_parse_tunnel_with_host() {
        let result = parse_tunnel_spec("8080:example.com:80");
        assert!(result.is_some());
        let (lh, lp, rh, rp) = result.unwrap();
        assert_eq!(lh, "127.0.0.1");
        assert_eq!(lp, 8080);
        assert_eq!(rh, "example.com");
        assert_eq!(rp, 80);
    }

    #[test]
    fn test_parse_full_tunnel() {
        let result = parse_tunnel_spec("0.0.0.0:8080:example.com:80");
        assert!(result.is_some());
        let (lh, lp, rh, rp) = result.unwrap();
        assert_eq!(lh, "0.0.0.0");
        assert_eq!(lp, 8080);
        assert_eq!(rh, "example.com");
        assert_eq!(rp, 80);
    }

    #[test]
    fn test_parse_invalid_tunnel() {
        assert!(parse_tunnel_spec("invalid").is_none());
        assert!(parse_tunnel_spec("not:a:valid:tunnel:spec:too:many").is_none());
    }
}
