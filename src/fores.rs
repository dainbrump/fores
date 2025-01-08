use crate::config::ForesConfig;
use crate::error::ConfigError;
// use crate::structs::sshconfig::SshConfigHost;
// use std::path::Path;

/// This is the main parser struct for the Fores SSH config parser. It uses a builder pattern to
/// configure the parser with certain customizable parameters. From there, the library consumer can
/// trigger a parsing operation on a string or file path.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Fores {
    config: ForesConfig,
}

impl Fores {
    pub fn new() -> ForesBuilder {
        ForesBuilder::default()
    }

    /* pub fn parse_string(&self, config_string: &str) -> Result<Vec<SshConfigHost>, ConfigError> {
        Ok(vec![])
    }

    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<SshConfigHost>, ConfigError> {
        let config_string = std::fs::read_to_string(path)?;
        self.parse_string(&config_string)
    } */
}

impl Default for Fores {
    fn default() -> Self {
        Self::new().build()
    }
}

/// Builder for configuring and creating a `Fores` parser.
pub struct ForesBuilder {
    config: ForesConfig,
}

impl ForesBuilder {
    /// Sets the maximum allowed value for the `ConnectionAttempts` option.
    ///
    /// The SSH spec does not define a maximum value for `ConnectionAttempts`, but theoretically it
    /// should be a 32-bit integer. This method allows you to set a sane maximum value for this
    /// option. The default is `u32::MAX`.
    ///
    /// # Arguments
    ///
    /// * `max_attempts` - The maximum allowed value for `ConnectionAttempts`.
    ///
    /// # Returns
    ///
    /// A `Result` containing the modified `ForesBuilder`, or a `ConfigError` if
    /// `max_attempts` is 0.
    /// @TODO: This might need to be an i32 instead of a u32.
    pub fn max_connection_attempts(mut self, max_attempts: u32) -> Result<Self, ConfigError> {
        if max_attempts == 0 {
            return Err(ConfigError::OutOfRangeU32 {
                field: "defining the maximum connection attempts in the Fores configuration is",
                value: max_attempts.to_string(),
                min: 1,
                max: u32::MAX,
            });
        }
        self.config.max_connection_attempts = max_attempts;
        Ok(self)
    }

    pub fn min_compression_level(mut self, min_compression_level: u8) -> Result<Self, ConfigError> {
        if min_compression_level > self.config.max_compression_level {
            return Err(ConfigError::OutOfRangeU8 {
                field: "min_compression_level",
                value: min_compression_level.to_string(),
                min: 1,
                max: self.config.max_compression_level,
            });
        }

        if !(1..=9).contains(&min_compression_level) {
            return Err(ConfigError::OutOfRangeU8 {
                field: "min_compression_level",
                value: min_compression_level.to_string(),
                min: 1,
                max: 9,
            });
        }
        self.config.min_compression_level = min_compression_level;
        Ok(self)
    }

    pub fn max_compression_level(mut self, max_compression_level: u8) -> Result<Self, ConfigError> {
        if max_compression_level < self.config.min_compression_level {
            return Err(ConfigError::OutOfRangeU8 {
                field: "max_compression_level",
                value: max_compression_level.to_string(),
                min: self.config.min_compression_level,
                max: 9,
            });
        }

        if !(1..=9).contains(&max_compression_level) {
            return Err(ConfigError::OutOfRangeU8 {
                field: "max_compression_level",
                value: max_compression_level.to_string(),
                min: 1,
                max: 9,
            });
        }
        self.config.max_compression_level = max_compression_level;
        Ok(self)
    }

    pub fn max_connect_timeout(mut self, max_connect_timeout: u32) -> Self {
        self.config.max_connect_timeout = max_connect_timeout;
        self
    }

    pub fn permitted_ciphers(mut self, ciphers: Vec<&'static str>) -> Self {
        self.config.permitted_ciphers = ciphers;
        self
    }

    pub fn permitted_host_key_algorithms(mut self, algorithms: Vec<&'static str>) -> Self {
        self.config.permitted_host_key_algorithms = algorithms;
        self
    }

    pub fn permitted_kbd_interactive_devices(mut self, devices: Vec<&'static str>) -> Self {
        self.config.permitted_kbd_interactive_devices = devices;
        self
    }

    pub fn permitted_macs(mut self, macs: Vec<&'static str>) -> Self {
        self.config.permitted_macs = macs;
        self
    }

    pub fn max_password_prompts(mut self, max_prompts: u32) -> Self {
        self.config.max_password_prompts = max_prompts;
        self
    }

    pub fn min_port(mut self, min_port: u16) -> Result<Self, ConfigError> {
        if min_port > self.config.max_port {
            return Err(ConfigError::OutOfRangeU16 {
                field: "min_port",
                value: min_port.to_string(),
                min: 0,
                max: self.config.max_port,
            });
        }
        self.config.min_port = min_port;
        Ok(self)
    }

    pub fn max_port(mut self, max_port: u16) -> Result<Self, ConfigError> {
        if max_port < self.config.min_port {
            return Err(ConfigError::OutOfRangeU16 {
                field: "max_port",
                value: max_port.to_string(),
                min: self.config.min_port,
                max: u16::MAX,
            });
        }
        self.config.max_port = max_port;
        Ok(self)
    }

    pub fn max_server_alive_count_max(mut self, max_count: u32) -> Self {
        self.config.max_server_alive_count_max = max_count;
        self
    }

    pub fn max_server_alive_interval(mut self, max_interval: u32) -> Self {
        self.config.max_server_alive_interval = max_interval;
        self
    }

    pub fn strict_v2_validation(mut self, enabled: bool) -> Self {
        self.config.strict_v2_validation = enabled;
        self
    }

    /// Builds a `Fores` parser with the current configuration.
    pub fn build(self) -> Fores {
        Fores { config: self.config }
    }
}

impl Default for ForesBuilder {
    fn default() -> Self {
        Self { config: ForesConfig::default() }
    }
}
