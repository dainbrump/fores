use lazy_static::lazy_static;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Enum to represent the SSH client standard to use in config validations.
pub enum SshStandard {
    OpenSSH,
    // Add other SSH clients in the future (e.g., Putty, Dropbear)
}

/// Default SSH client standard is OpenSSH.
impl Default for SshStandard {
    fn default() -> Self {
        SshStandard::OpenSSH
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Maps the SSH client standard to the supported client protocol versions.
pub struct DirectiveSupport {
    pub protocol: ProtocolVersion,
    pub standard: SshStandard,
}

#[derive(Debug, Clone, PartialEq)]
/// Enumerate protocol versions supported by the SSH client standard.
/// Currently, OpenSSH supports both versions 1 and 2.
/// Future enumerations may support versions specific to other SSH clients.
pub enum ProtocolVersion {
    OpenSSHV1,
    OpenSSHV2,
    OpenSSHAll,
}

impl FromStr for ProtocolVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "opensshv1" => Ok(ProtocolVersion::OpenSSHV1),
            "opensshv2" => Ok(ProtocolVersion::OpenSSHV2),
            "opensshall" => Ok(ProtocolVersion::OpenSSHAll),
            _ => Err(()),
        }
    }
}

/// Maps SSH configuration directives to the supported protocol versions and SSH client standards.
/// This mapping is used to validate the configuration file. Currently, only OpenSSH is supported.
/// Future versions may support other SSH clients.
const DIRECTIVE_MAP: [(&str, DirectiveSupport); 71] = [
    (
        "AddressFamily",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "BatchMode",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "BindAddress",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ChallengeResponseAuthentication",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "CheckHostIP",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "Cipher",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV1, standard: SshStandard::OpenSSH },
    ),
    (
        "Ciphers",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "ClearAllForwardings",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "Compression",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "CompressionLevel",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV1, standard: SshStandard::OpenSSH },
    ),
    (
        "ConnectionAttempts",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ConnectTimeout",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ControlMaster",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "ControlPath",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "DynamicForward",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "EnableSSHKeysign",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "EscapeChar",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ExitOnForwardFailure",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ForwardAgent",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ForwardX11",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ForwardX11Trusted",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "GatewayPorts",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "GlobalKnownHostsFile",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "GSSAPIAuthentication",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "GSSAPIClientIdentity",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "GSSAPIDelegateCredentials",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "GSSAPIKeyExchange",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "GSSAPIRenewalForcesRekey",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "GSSAPITrustDns",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "HashKnownHosts",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "Host",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "HostbasedAuthentication",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "HostKeyAlgorithms",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "HostKeyAlias",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "HostName",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "IdentitiesOnly",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "IdentityFile",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "Include",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "KbdInteractiveAuthentication",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "KbdInteractiveDevices",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "LocalCommand",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "LocalForward",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "LogLevel",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "MACs",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "NoHostAuthenticationForLocalhost",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV1, standard: SshStandard::OpenSSH },
    ),
    (
        "NumberOfPasswordPrompts",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "PasswordAuthentication",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "PermitLocalCommand",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "Port",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "PreferredAuthentications",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "Protocol",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ProxyCommand",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "PubkeyAuthentication",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "RekeyLimit",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "RemoteForward",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "RHostsRSAAuthentication",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV1, standard: SshStandard::OpenSSH },
    ),
    (
        "RSAAuthentication",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV1, standard: SshStandard::OpenSSH },
    ),
    (
        "SendEnv",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ServerAliveCountMax",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "ServerAliveInterval",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "SmartcardDevice",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV2, standard: SshStandard::OpenSSH },
    ),
    (
        "StrictHostKeyChecking",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "TCPKeepAlive",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "Tunnel",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "TunnelDevice",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "UsePrivilegedPort",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHV1, standard: SshStandard::OpenSSH },
    ),
    (
        "User",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "UserKnownHostsFile",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "VerifyHostKeyDNS",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "VisualHostKey",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
    (
        "XAuthLocation",
        DirectiveSupport { protocol: ProtocolVersion::OpenSSHAll, standard: SshStandard::OpenSSH },
    ),
];

lazy_static! {
    /// Map the directive to the supported protocol version and SSH client standard. Directive names
    /// are converted to lowercase to ensure case-insensitive matching during validation.
    pub static ref DIRECTIVE_TO_PROTOCOL_MAP: HashMap<String, DirectiveSupport> = {
        let mut map = HashMap::new();
        DIRECTIVE_MAP.iter().for_each(|(k, v)| {
            map.insert(k.to_lowercase(), v.clone());
        });
        map
    };
}
