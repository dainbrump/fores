use crate::directive_mapping::{ProtocolVersion, SshStandard};
use crate::error::ConfigError;
use crate::{VALID_CIPHERS, VALID_HOST_KEY_ALGORITHMS, VALID_KBD_INTERACTIVE_DEVICES, VALID_MACS};

/// Policy options for the Fores parser.
#[derive(Debug, Clone)]
pub struct HostPolicy {
    /// The maximum allowed value for the `ConnectionAttempts` option.
    max_connection_attempts: u32,
    /// The minimum allowed value for the `CompressionLevel` option.
    min_compression_level: u8,
    /// The maximum allowed value for the `CompressionLevel` option.
    max_compression_level: u8,
    /// The maximum allowed value for the `ConnectTimeout` option.
    max_connect_timeout: u32,
    /// The ciphers that the parser will consider valid.
    permitted_ciphers: Vec<&'static str>,
    /// The host key algorithms that the parser will consider valid.
    permitted_host_key_algorithms: Vec<&'static str>,
    /// The keyboard interactive devices that the parser will consider valid.
    permitted_kbd_interactive_devices: Vec<&'static str>,
    /// The MACs that the parser will consider valid.
    permitted_macs: Vec<&'static str>,
    /// The maximum allowed value for the `NumberOfPasswordPrompts` option.
    max_password_prompts: u32,
    /// The minimum allowed value for the `Port` option.
    min_port: u16,
    /// The maximum allowed value for the `Port` option.
    max_port: u16,
    /// The maximum allowed value for the `ServerAliveCountMax` option.
    max_server_alive_count_max: u32,
    /// The maximum allowed value for the `ServerAliveInterval` option.
    max_server_alive_interval: u32,
    /// Whether to enforce standards compliance.
    enforce_standards_compliance: bool,
    /// The SSH protocol versions to enforce compliance with.
    compliance_mode: Option<Vec<ProtocolVersion>>,
    /// The supported SSH standards.
    supported_standards: Vec<SshStandard>,
}

impl Default for HostPolicy {
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
            enforce_standards_compliance: false,
            compliance_mode: None,
            supported_standards: vec![SshStandard::OpenSSH],
        }
    }
}

impl HostPolicy {
    // Returns the maximum allowed value for the `ConnectionAttempts` option.
    pub fn max_connection_attempts(&self) -> u32 {
        self.max_connection_attempts
    }

    // Returns the minimum allowed value for the `CompressionLevel` option.
    pub fn min_compression_level(&self) -> u8 {
        self.min_compression_level
    }

    // Returns the maximum allowed value for the `CompressionLevel` option.
    pub fn max_compression_level(&self) -> u8 {
        self.max_compression_level
    }

    // Returns the maximum allowed value for the `ConnectTimeout` option.
    pub fn max_connect_timeout(&self) -> u32 {
        self.max_connect_timeout
    }

    // Returns the ciphers that the parser will consider valid.
    pub fn permitted_ciphers(&self) -> Vec<&'static str> {
        self.permitted_ciphers.clone()
    }

    // Returns the host key algorithms that the parser will consider valid.
    pub fn permitted_host_key_algorithms(&self) -> Vec<&'static str> {
        self.permitted_host_key_algorithms.clone()
    }

    // Returns the keyboard interactive devices that the parser will consider valid.
    pub fn permitted_kbd_interactive_devices(&self) -> Vec<&'static str> {
        self.permitted_kbd_interactive_devices.clone()
    }

    // Returns the MACs that the parser will consider valid.
    pub fn permitted_macs(&self) -> Vec<&'static str> {
        self.permitted_macs.clone()
    }

    // Returns the maximum allowed value for the `NumberOfPasswordPrompts` option.
    pub fn max_password_prompts(&self) -> u32 {
        self.max_password_prompts
    }

    // Returns the minimum allowed value for the `Port` option.
    pub fn min_port(&self) -> u16 {
        self.min_port
    }

    // Returns the maximum allowed value for the `Port` option.
    pub fn max_port(&self) -> u16 {
        self.max_port
    }

    // Returns the maximum allowed value for the `ServerAliveCountMax` option.
    pub fn max_server_alive_count_max(&self) -> u32 {
        self.max_server_alive_count_max
    }

    // Returns the maximum allowed value for the `ServerAliveInterval` option.
    pub fn max_server_alive_interval(&self) -> u32 {
        self.max_server_alive_interval
    }

    // Returns whether to enforce standards compliance.
    pub fn enforce_standards_compliance(&self) -> bool {
        self.enforce_standards_compliance
    }

    // Returns the SSH protocol versions to enforce compliance with.
    pub fn compliance_mode(&self) -> Option<Vec<ProtocolVersion>> {
        if let Some(compliance_mode) = &self.compliance_mode {
            return Some(compliance_mode.clone());
        } else {
            return None;
        }
    }

    // Returns the supported SSH standards.
    pub fn supported_standards(&self) -> Vec<SshStandard> {
        self.supported_standards.clone()
    }
}

/// Defines the behavior for updating a lists of permitted values in specific policy options.
#[derive(Debug, Clone)]
pub enum ListSetBehavior {
    /// Appends supplied new values to the existing list.
    Append,
    /// Replaces the existing list with supplied new values.
    Replace,
    /// Removes the values specified in the provided list from the existing list and appends the
    /// supplied new values to the list.
    Remove(Vec<&'static str>),
}

#[derive(Debug, Clone)]
pub struct HostPolicyBuilder {
    policy: HostPolicy,
}

impl HostPolicyBuilder {
    /// Creates a new `HostPolicyBuilder` with default values.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let builder = HostPolicyBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self { policy: HostPolicy::default() }
    }

    /// Sets the maximum number of connection attempts.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.max_connection_attempts(5).build().unwrap();
    /// assert_eq!(policy.max_connection_attempts(), 5);
    /// ```
    pub fn max_connection_attempts(&mut self, connections: u32) -> &mut Self {
        self.policy.max_connection_attempts = connections;
        self
    }

    /// Sets the minimum compression level.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.min_compression_level(1).build().unwrap();
    /// assert_eq!(policy.min_compression_level(), 1);
    /// ```
    pub fn min_compression_level(&mut self, level: u8) -> &mut Self {
        self.policy.min_compression_level = level;
        self
    }

    /// Sets the maximum compression level.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.max_compression_level(9).build().unwrap();
    /// assert_eq!(policy.max_compression_level(), 9);
    /// ```
    pub fn max_compression_level(&mut self, level: u8) -> &mut Self {
        self.policy.max_compression_level = level;
        self
    }

    /// Sets the maximum connection timeout.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.max_connect_timeout(30).build().unwrap();
    /// assert_eq!(policy.max_connect_timeout(), 30);
    /// ```
    pub fn max_connect_timeout(&mut self, timeout: u32) -> &mut Self {
        self.policy.max_connect_timeout = timeout;
        self
    }

    /// Sets the permitted ciphers.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::{HostPolicyBuilder, ListSetBehavior};
    /// use fores::constants;
    ///
    /// // Append new ciphers to the existing list
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_ciphers(vec!["cipher1", "cipher2"], Some(ListSetBehavior::Append)).build().unwrap();
    /// let mut expected = constants::VALID_CIPHERS.to_vec();
    /// expected.extend(vec!["cipher1", "cipher2"]);
    /// assert_eq!(policy.permitted_ciphers(), expected);
    ///
    /// // Replace the existing list with the new ciphers
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_ciphers(vec!["cipher1", "cipher2"], Some(ListSetBehavior::Replace)).build().unwrap();
    /// assert_eq!(policy.permitted_ciphers(), vec!["cipher1", "cipher2"]);
    ///
    /// // Remove ciphers from the existing list and append the new ciphers
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_ciphers(vec!["cipher1", "cipher2"], Some(ListSetBehavior::Remove(vec!["aes128-ctr"]))).build().unwrap();
    /// let mut expected = constants::VALID_CIPHERS.to_vec();
    /// expected.retain(|&x| x != "aes128-ctr");
    /// expected.extend(vec!["cipher1", "cipher2"]);
    /// assert_eq!(policy.permitted_ciphers(), expected);
    /// ```
    pub fn permitted_ciphers(
        &mut self,
        ciphers: Vec<&'static str>,
        set_behavior: Option<ListSetBehavior>,
    ) -> &mut Self {
        let behavior = set_behavior.unwrap_or(ListSetBehavior::Append);
        match behavior {
            ListSetBehavior::Append => self.policy.permitted_ciphers.extend(ciphers),
            ListSetBehavior::Replace => self.policy.permitted_ciphers = ciphers,
            ListSetBehavior::Remove(values_to_remove) => {
                self.policy.permitted_ciphers.retain(|&x| !values_to_remove.contains(&x));
                self.policy.permitted_ciphers.extend(ciphers);
            }
        }
        self
    }

    /// Sets the permitted host key algorithms.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::{HostPolicyBuilder, ListSetBehavior};
    /// use fores::constants;
    ///
    /// // Append new algorithms to the existing list
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_host_key_algorithms(vec!["algorithm1", "algorithm2"], Some(ListSetBehavior::Append)).build().unwrap();
    /// let mut expected = constants::VALID_HOST_KEY_ALGORITHMS.to_vec();
    /// expected.extend(vec!["algorithm1", "algorithm2"]);
    /// assert_eq!(policy.permitted_host_key_algorithms(), expected);
    ///
    /// // Replace the existing list with the new algorithms
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_host_key_algorithms(vec!["algorithm1", "algorithm2"], Some(ListSetBehavior::Replace)).build().unwrap();
    /// assert_eq!(policy.permitted_host_key_algorithms(), vec!["algorithm1", "algorithm2"]);
    ///
    /// // Remove algorithms from the existing list and append the new algorithms
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_host_key_algorithms(vec!["algorithm1", "algorithm2"], Some(ListSetBehavior::Remove(vec!["ssh-ed25519"]))).build().unwrap();
    /// let mut expected = constants::VALID_HOST_KEY_ALGORITHMS.to_vec();
    /// expected.retain(|&x| x != "ssh-ed25519");
    /// expected.extend(vec!["algorithm1", "algorithm2"]);
    /// assert_eq!(policy.permitted_host_key_algorithms(), expected);
    /// ```
    pub fn permitted_host_key_algorithms(
        &mut self,
        algorithms: Vec<&'static str>,
        set_behavior: Option<ListSetBehavior>,
    ) -> &mut Self {
        let behavior = set_behavior.unwrap_or(ListSetBehavior::Append);
        match behavior {
            ListSetBehavior::Append => self.policy.permitted_host_key_algorithms.extend(algorithms),
            ListSetBehavior::Replace => self.policy.permitted_host_key_algorithms = algorithms,
            ListSetBehavior::Remove(values_to_remove) => {
                self.policy
                    .permitted_host_key_algorithms
                    .retain(|&x| !values_to_remove.contains(&x));
                self.policy.permitted_host_key_algorithms.extend(algorithms);
            }
        }
        self
    }

    /// Sets the permitted keyboard interactive devices.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::{HostPolicyBuilder, ListSetBehavior};
    /// use fores::constants;
    ///
    /// // Append new devices to the existing list
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_kbd_interactive_devices(vec!["device1", "device2"], Some(ListSetBehavior::Append)).build().unwrap();
    /// let mut expected = constants::VALID_KBD_INTERACTIVE_DEVICES.to_vec();
    /// expected.extend(vec!["device1", "device2"]);
    /// assert_eq!(policy.permitted_kbd_interactive_devices(), expected);
    ///
    /// // Replace the existing list with the new devices
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_kbd_interactive_devices(vec!["device1", "device2"], Some(ListSetBehavior::Replace)).build().unwrap();
    /// assert_eq!(policy.permitted_kbd_interactive_devices(), vec!["device1", "device2"]);
    ///
    /// // Remove devices from the existing list and append the new devices
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_kbd_interactive_devices(vec!["device1", "device2"], Some(ListSetBehavior::Remove(vec!["bsdauth"]))).build().unwrap();
    /// let mut expected = constants::VALID_KBD_INTERACTIVE_DEVICES.to_vec();
    /// expected.retain(|&x| x != "bsdauth");
    /// expected.extend(vec!["device1", "device2"]);
    /// assert_eq!(policy.permitted_kbd_interactive_devices(), expected);
    /// ```
    pub fn permitted_kbd_interactive_devices(
        &mut self,
        devices: Vec<&'static str>,
        set_behavior: Option<ListSetBehavior>,
    ) -> &mut Self {
        let behavior = set_behavior.unwrap_or(ListSetBehavior::Append);
        match behavior {
            ListSetBehavior::Append => {
                self.policy.permitted_kbd_interactive_devices.extend(devices)
            }
            ListSetBehavior::Replace => self.policy.permitted_kbd_interactive_devices = devices,
            ListSetBehavior::Remove(values_to_remove) => {
                self.policy
                    .permitted_kbd_interactive_devices
                    .retain(|&x| !values_to_remove.contains(&x));
                self.policy.permitted_kbd_interactive_devices.extend(devices);
            }
        }
        self
    }

    /// Sets the permitted MACs.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::{HostPolicyBuilder, ListSetBehavior};
    /// use fores::constants;
    ///
    /// // Append new MACs to the existing list
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_macs(vec!["mac1", "mac2"], Some(ListSetBehavior::Append)).build().unwrap();
    /// let mut expected = constants::VALID_MACS.to_vec();
    /// expected.extend(vec!["mac1", "mac2"]);
    /// assert_eq!(policy.permitted_macs(), expected);
    ///
    /// // Replace the existing list with the new MACs
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_macs(vec!["mac1", "mac2"], Some(ListSetBehavior::Replace)).build().unwrap();
    /// assert_eq!(policy.permitted_macs(), vec!["mac1", "mac2"]);
    ///
    /// // Remove MACs from the existing list and append the new MACs
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.permitted_macs(vec!["mac1", "mac2"], Some(ListSetBehavior::Remove(vec!["hmac-md5"]))).build().unwrap();
    /// let mut expected = constants::VALID_MACS.to_vec();
    /// expected.retain(|&x| x != "hmac-md5");
    /// expected.extend(vec!["mac1", "mac2"]);
    /// assert_eq!(policy.permitted_macs(), expected);
    /// ```
    pub fn permitted_macs(
        &mut self,
        macs: Vec<&'static str>,
        set_behavior: Option<ListSetBehavior>,
    ) -> &mut Self {
        let behavior = set_behavior.unwrap_or(ListSetBehavior::Append);
        match behavior {
            ListSetBehavior::Append => self.policy.permitted_macs.extend(macs),
            ListSetBehavior::Replace => self.policy.permitted_macs = macs,
            ListSetBehavior::Remove(values_to_remove) => {
                self.policy.permitted_macs.retain(|&x| !values_to_remove.contains(&x));
                self.policy.permitted_macs.extend(macs);
            }
        }
        self
    }

    /// Sets the maximum number of password prompts.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.max_password_prompts(3).build().unwrap();
    /// assert_eq!(policy.max_password_prompts(), 3);
    /// ```
    pub fn max_password_prompts(&mut self, prompts: u32) -> &mut Self {
        self.policy.max_password_prompts = prompts;
        self
    }

    /// Sets the minimum port number.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.min_port(22).build().unwrap();
    /// assert_eq!(policy.min_port(), 22);
    /// ```
    pub fn min_port(&mut self, port: u16) -> &mut Self {
        self.policy.min_port = port;
        self
    }

    /// Sets the maximum port number.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.max_port(2222).build().unwrap();
    /// assert_eq!(policy.max_port(), 2222);
    /// ```
    pub fn max_port(&mut self, port: u16) -> &mut Self {
        self.policy.max_port = port;
        self
    }

    /// Sets the maximum number of server alive count.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.max_server_alive_count_max(3).build().unwrap();
    /// assert_eq!(policy.max_server_alive_count_max(), 3);
    /// ```
    pub fn max_server_alive_count_max(&mut self, count: u32) -> &mut Self {
        self.policy.max_server_alive_count_max = count;
        self
    }

    /// Sets the maximum server alive interval.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.max_server_alive_interval(30).build().unwrap();
    /// assert_eq!(policy.max_server_alive_interval(), 30);
    /// ```
    pub fn max_server_alive_interval(&mut self, interval: u32) -> &mut Self {
        self.policy.max_server_alive_interval = interval;
        self
    }

    /// Sets whether to enforce standards compliance.
    /// If set to `true`, the `compliance_mode` must also be set.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    /// use fores::directive_mapping::ProtocolVersion;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let mut policy = builder.enforce_standards_compliance(true).compliance_mode(vec![ProtocolVersion::OpenSSHV2]).build().unwrap();
    /// assert_eq!(policy.enforce_standards_compliance(), true);
    /// assert_eq!(policy.compliance_mode().unwrap(), vec![ProtocolVersion::OpenSSHV2]);
    /// ```
    pub fn enforce_standards_compliance(&mut self, enforce: bool) -> &mut Self {
        self.policy.enforce_standards_compliance = enforce;
        self
    }

    /// Sets the SSH protocol versions to enforce compliance with.
    /// This option is required if `enforce_standards_compliance` is set to `true`.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    /// use fores::directive_mapping::ProtocolVersion;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.compliance_mode(vec![ProtocolVersion::OpenSSHV2]).build().unwrap();
    /// assert_eq!(policy.compliance_mode().unwrap(), vec![ProtocolVersion::OpenSSHV2]);
    /// ```
    pub fn compliance_mode(&mut self, protocols: Vec<ProtocolVersion>) -> &mut Self {
        self.policy.compliance_mode = Some(protocols);
        self
    }

    /// Sets the supported SSH standards.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    /// use fores::directive_mapping::SshStandard;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.supported_standards(vec![SshStandard::OpenSSH]).build().unwrap();
    /// assert_eq!(policy.supported_standards(), vec![SshStandard::OpenSSH]);
    /// ```
    pub fn supported_standards(&mut self, standards: Vec<SshStandard>) -> &mut Self {
        self.policy.supported_standards = standards;
        self
    }

    /// Builds the `HostPolicy` struct with the provided configuration options.
    /// If any of the configuration options are invalid, a `Vec<ConfigError>` will be returned.
    /// If all configuration options are valid, the `HostPolicy` struct will be returned.
    ///
    /// # Examples
    /// ```
    /// use fores::configuration::HostPolicyBuilder;
    /// use fores::error::ConfigError;
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.build().unwrap();
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.max_connection_attempts(0).build();
    /// assert!(policy.is_err());
    /// match policy.unwrap_err().first().unwrap() {
    ///   ConfigError::OutOfRangeU32 { field, value, min, max } => {
    ///     assert_eq!(*field, "max_connection_attempts");
    ///     assert_eq!(*value, "0");
    ///     assert_eq!(*min, 1);
    ///     assert_eq!(*max, u32::MAX);
    ///   }
    ///    _ => panic!("Expected OutOfRangeU32 error"),
    /// }
    ///
    /// let mut builder = HostPolicyBuilder::new();
    /// let policy = builder.min_port(100).max_port(50).build();
    /// assert!(policy.is_err());
    /// let errors = policy.unwrap_err();
    /// assert_eq!(errors.len(), 2);
    /// match errors.first().unwrap() {
    ///   ConfigError::OutOfRangeU16 { field, value, min, max } => {
    ///     assert_eq!(*field, "min_port");
    ///     assert_eq!(*value, "100");  
    ///     assert_eq!(*min, 0);
    ///     assert_eq!(*max, 50);
    ///   }
    ///   _ => panic!("Expected OutOfRangeU16 error"),
    /// }
    /// match errors.last().unwrap() {
    ///   ConfigError::OutOfRangeU16 { field, value, min, max } => {
    ///     assert_eq!(*field, "max_port");
    ///     assert_eq!(*value, "50");
    ///     assert_eq!(*min, 100);
    ///     assert_eq!(*max, u16::MAX);
    ///   }
    ///   _ => panic!("Expected OutOfRangeU16 error"),
    /// }
    /// ```
    pub fn build(&mut self) -> Result<HostPolicy, Vec<ConfigError>> {
        let mut errors: Vec<ConfigError> = Vec::new();
        let defaults = HostPolicy::default();

        // Validate max_connection_attempts
        if self.policy.max_connection_attempts != defaults.max_connection_attempts
            && self.policy.max_connection_attempts == 0
        {
            errors.push(ConfigError::OutOfRangeU32 {
                field: "max_connection_attempts",
                value: self.policy.max_connection_attempts.to_string(),
                min: 1,
                max: u32::MAX,
            });
        }

        // Validate min_compression_level
        if self.policy.min_compression_level != defaults.min_compression_level {
            if self.policy.min_compression_level < 1 || self.policy.min_compression_level > 9 {
                errors.push(ConfigError::OutOfRangeU8 {
                    field: "min_compression_level",
                    value: self.policy.min_compression_level.to_string(),
                    min: 1,
                    max: 9,
                });
            } else if self.policy.min_compression_level > self.policy.max_compression_level {
                errors.push(ConfigError::OutOfRangeU8 {
                    field: "min_compression_level",
                    value: self.policy.min_compression_level.to_string(),
                    min: 1,
                    max: self.policy.max_compression_level,
                });
            }
        }

        // Validate max_compression_level
        if self.policy.max_compression_level != defaults.max_compression_level {
            if self.policy.max_compression_level < 1 || self.policy.max_compression_level > 9 {
                errors.push(ConfigError::OutOfRangeU8 {
                    field: "max_compression_level",
                    value: self.policy.max_compression_level.to_string(),
                    min: 1,
                    max: 9,
                });
            } else if self.policy.max_compression_level < self.policy.min_compression_level {
                errors.push(ConfigError::OutOfRangeU8 {
                    field: "max_compression_level",
                    value: self.policy.max_compression_level.to_string(),
                    min: self.policy.min_compression_level,
                    max: 9,
                });
            }
        }

        // Validate min_port
        if self.policy.min_port != defaults.min_port && self.policy.min_port > self.policy.max_port
        {
            errors.push(ConfigError::OutOfRangeU16 {
                field: "min_port",
                value: self.policy.min_port.to_string(),
                min: 0,
                max: self.policy.max_port,
            });
        }

        // Validate max_port
        if self.policy.max_port != defaults.max_port && self.policy.max_port < self.policy.min_port
        {
            errors.push(ConfigError::OutOfRangeU16 {
                field: "max_port",
                value: self.policy.max_port.to_string(),
                min: self.policy.min_port,
                max: u16::MAX,
            });
        }

        // validate max_password_prompts
        if self.policy.max_password_prompts != defaults.max_password_prompts
            && self.policy.max_password_prompts == 0
        {
            errors.push(ConfigError::OutOfRangeU32 {
                field: "max_password_prompts",
                value: self.policy.max_password_prompts.to_string(),
                min: 1,
                max: u32::MAX,
            });
        }

        // validate max_server_alive_count_max
        if self.policy.max_server_alive_count_max != defaults.max_server_alive_count_max
            && self.policy.max_server_alive_count_max == 0
        {
            errors.push(ConfigError::OutOfRangeU32 {
                field: "max_server_alive_count_max",
                value: self.policy.max_server_alive_count_max.to_string(),
                min: 1,
                max: u32::MAX,
            });
        }

        // validate max_server_alive_interval
        if self.policy.max_server_alive_interval != defaults.max_server_alive_interval
            && self.policy.max_server_alive_interval == 0
        {
            errors.push(ConfigError::OutOfRangeU32 {
                field: "max_server_alive_interval",
                value: self.policy.max_server_alive_interval.to_string(),
                min: 1,
                max: u32::MAX,
            });
        }

        if self.policy.enforce_standards_compliance {
            if self.policy.compliance_mode.is_none() {
                errors.push(ConfigError::InvalidValue {
                    field: "compliance_mode",
                    value: "None".to_string(),
                });
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        // All validating policy options are valid. Return the policy.
        Ok(self.policy.clone())
    }
}
