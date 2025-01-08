use crate::{VALID_CIPHERS, VALID_HOST_KEY_ALGORITHMS, VALID_KBD_INTERACTIVE_DEVICES, VALID_MACS};

/// Configuration options for the Fores parser.
#[derive(Debug, Clone)]
pub struct ForesConfig {
    /// The maximum allowed value for the `ConnectionAttempts` option.
    pub max_connection_attempts: u32,
    /// The minimum allowed value for the `CompressionLevel` option.
    pub min_compression_level: u8,
    /// The maximum allowed value for the `CompressionLevel` option.
    pub max_compression_level: u8,
    /// The maximum allowed value for the `ConnectTimeout` option.
    pub max_connect_timeout: u32,
    /// The ciphers that the parser will consider valid.
    pub permitted_ciphers: Vec<&'static str>,
    /// The host key algorithms that the parser will consider valid.
    pub permitted_host_key_algorithms: Vec<&'static str>,
    /// The keyboard interactive devices that the parser will consider valid.
    pub permitted_kbd_interactive_devices: Vec<&'static str>,
    /// The MACs that the parser will consider valid.
    pub permitted_macs: Vec<&'static str>,
    /// The maximum allowed value for the `NumberOfPasswordPrompts` option.
    pub max_password_prompts: u32,
    /// The minimum allowed value for the `Port` option.
    pub min_port: u16,
    /// The maximum allowed value for the `Port` option.
    pub max_port: u16,
    /// The maximum allowed value for the `ServerAliveCountMax` option.
    pub max_server_alive_count_max: u32,
    /// The maximum allowed value for the `ServerAliveInterval` option.
    pub max_server_alive_interval: u32,
    /// Whether to enable strict validation for SSH protocol version 2.
    pub strict_v2_validation: bool,
}

impl Default for ForesConfig {
    fn default() -> Self {
        Self {
            max_connection_attempts: u32::MAX,
            min_compression_level: 1,
            max_compression_level: 9,
            max_connect_timeout: u32::MAX,
            permitted_ciphers: VALID_CIPHERS.to_vec(),
            permitted_host_key_algorithms: VALID_HOST_KEY_ALGORITHMS.to_vec(),
            permitted_kbd_interactive_devices: VALID_KBD_INTERACTIVE_DEVICES.to_vec(),
            permitted_macs: VALID_MACS.to_vec(),
            max_password_prompts: u32::MAX,
            min_port: 0,
            max_port: u16::MAX,
            max_server_alive_count_max: u32::MAX,
            max_server_alive_interval: u32::MAX,
            strict_v2_validation: false,
        }
    }
}
