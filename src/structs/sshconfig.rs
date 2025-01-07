use crate::error::ConfigError;
use crate::structs::enums::addressfamily::AddressFamily;
use crate::structs::enums::loglevel::LogLevels;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
// Support yes/no values in the SSH configuration file.
pub enum YesNo {
  Yes,
  No,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
// Support yes/no/ask values in the SSH configuration file.
pub enum YesNoAsk {
  Yes,
  No,
  Ask,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
// Support ControlMaster values in the SSH configuration file.
pub enum YesNoAskAutoAutoask {
  Yes,
  No,
  Ask,
  Auto,
  AutoAsk,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
// Support tunnel values in the SSH configuration file.
pub enum TunnelOptions {
  Yes,
  PointToPoint,
  Ethernet,
  No,
}

/// This is a detailed representation of all properties possible for a single host record in an SSH
/// configuration file. Below you will find the struct property and definition followed by the
/// corresponding SSH configuration file property name and details.
///
/// For more information, see <https://linux.die.net/man/5/ssh_config>

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SshConfigHost {
  /// ## Host
  ///
  /// Restricts the following declarations (up to the next **Host** keyword) to be only for those
  /// hosts that match one of the patterns given after the keyword. If more than one pattern is
  /// provided, they should be separated by whitespace. A single `*` as a pattern can be used to
  /// provide global defaults for all hosts. The host is the hostname argument given on the
  /// command line (i.e. the name is not converted to a canonicalized host name before matching).
  ///
  /// See **PATTERNS** in <https://linux.die.net/man/5/ssh_config> for
  /// more information on patterns.
  pub host: String,
  /// ## AddressFamily
  ///
  /// Specifies which address family to use when connecting. Valid arguments are `any`, `inet`
  /// (use IPv4 only), or `inet6` (use IPv6 only).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub address_family: Option<AddressFamily>,
  /// ## BatchMode
  ///
  /// If set to `yes`, passphrase/password querying will be disabled. This option is useful in
  /// cripts and other batch jobs where no user is present to supply the password. The argument
  /// must be `yes` or `no`. The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub batch_mode: Option<YesNo>,
  /// ## BindAddress
  ///
  /// Use the specified address on the local machine as the source address of the connection.
  /// Only useful on systems with more than one address. Note that this option does not work if
  /// **UsePrivilegedPort** is set to `yes`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub bind_address: Option<String>,
  /// ## ChallengeResponseAuthentication
  ///
  /// Specifies whether to use challenge-response authentication. The argument to this keyword
  /// must be `yes` or `no`. The default is `yes`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub challenge_response_authentication: Option<YesNo>,
  /// ## CheckHostIP
  ///
  /// If this flag is set to `yes`, **ssh(1)** will additionally check the host IP address in the
  /// known_hosts file. This allows ssh to detect if a host key changed due to DNS spoofing. If
  /// the option is set to `no`, the check will not be executed. The default is `yes`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub check_host_ip: Option<YesNo>,
  /// ## Cipher
  ///
  /// Specifies the cipher to use for encrypting the session in protocol version 1. Currently,
  /// `blowfish`, `3des`, and `des` are supported. `des` is only supported in the **ssh(1)**
  /// client for interoperability with legacy protocol 1 implementations that do not support the
  /// `3des` cipher. Its use is strongly discouraged due to cryptographic weaknesses. The default
  /// is `3des`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub cipher: Option<String>,
  /// ## Ciphers
  ///
  /// Specifies the ciphers allowed for protocol version 2 in order of preference. Multiple
  /// ciphers must be comma-separated. The supported ciphers are `3des-cbc`, `aes128-cbc`,
  /// `aes192-cbc`, `aes256-cbc`, `aes128-ctr`, `aes192-ctr`, `aes256-ctr`, `arcfour128`,
  /// `arcfour256`, `arcfour`, `blowfish-cbc`, and `cast128-cbc`. The default is:
  ///
  /// `
  /// aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,
  /// cast128-cbc,aes192-cbc,aes256-cbc,arcfour
  /// `
  #[serde(skip_serializing_if = "Option::is_none")]
  pub ciphers: Option<String>,
  /// ## ClearAllForwardings
  ///
  /// Specifies that all local, remote, and dynamic port forwardings specified in the
  /// configuration files or on the command line be cleared. This option is primarily useful when
  /// used from the **ssh(1)** command line to clear port forwardings set in configuration files,
  /// and is automatically set by **scp(1)** and **sftp(1)**. The argument must be `yes` or `no`.
  /// The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub clear_all_forwardings: Option<YesNo>,
  /// ## Compression
  ///
  /// Specifies whether to use compression. The argument must be `yes` or `no`. The default is
  /// `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub compression: Option<YesNo>,
  /// ## CompressionLevel
  ///
  /// Specifies the compression level to use if compression is enabled. The argument must be an
  /// integer from 1 (fast) to 9 (slow, best). The default level is 6, which is good for most
  /// applications. The meaning of the values is the same as in **gzip(1)**. Note that this
  /// option applies to protocol version 1 only.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub compression_level: Option<u32>,
  /// ## ConnectionAttempts
  ///
  /// Specifies the number of tries (one per second) to make before exiting. The argument must be
  /// an integer. This may be useful in scripts if the connection sometimes fails. The default is
  /// 1.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub connection_attempts: Option<u32>,
  /// ## ConnectTimeout
  ///
  /// Specifies the timeout (in seconds) used when connecting to the SSH server, instead of using
  /// the default system TCP timeout. This value is used only when the target is down or really
  /// unreachable, not when it refuses the connection.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub connect_timeout: Option<u32>,
  /// ## ControlMaster
  ///
  /// Enables the sharing of multiple sessions over a single network connection. When set to
  /// `yes`, **ssh(1)**  will listen for connections on a control socket specified using the
  /// **ControlPath** argument. Additional sessions can connect to this socket using the same
  /// **ControlPath** with **ControlMaster** set to `no` (the default). These sessions will try
  /// to reuse the master instance's network connection rather than initiating new ones, but will
  /// fall back to connecting normally if the control socket does not exist, or is not listening.
  ///
  /// Setting this to `ask` will cause ssh to listen for control connections, but require
  /// confirmation using the *SSH_ASKPASS* program before they are accepted (see **ssh-add(1)**
  /// for details). If the **ControlPath** cannot be opened, ssh will continue without connecting
  /// to a master instance. X11 and **ssh-agent(1)** forwarding is supported over these
  /// multiplexed connections, however the display and agent forwarded will be the one belonging
  /// to the master connection i.e. it is not possible to forward multiple displays or agents.
  ///
  /// Two additional options allow for opportunistic multiplexing: try to use a master connection
  /// but fall back to creating a new one if one does not already exist. These options are:
  /// `auto` and `autoask`. The latter requires confirmation like the `ask` option.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub control_master: Option<YesNoAskAutoAutoask>,
  /// ## ControlPath
  ///
  /// Specify the path to the control socket used for connection sharing as described in the
  /// **ControlMaster** section above or the string `none` to disable connection sharing. In the
  /// path, `%l` will be substituted by the local host name, `%h` will be substituted by the
  /// target host name, `%p` the port, and `%r` by the remote login username. It is recommended
  /// that any **ControlPath** used for opportunistic connection sharing include at least `%h`,
  /// `%p`, and `%r`. This ensures that shared connections are uniquely identified.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub control_path: Option<String>,
  /// ## DynamicForward
  ///
  /// Specifies that a TCP port on the local machine be forwarded over the secure channel, and
  /// the application protocol is then used to determine where to connect to from the remote
  /// machine.
  ///
  /// The argument must be `[bind_address:]port`. IPv6 addresses can be specified by enclosing
  /// addresses in square brackets or by using an alternative syntax: `[bind_address/]port`.
  /// By  default, the local port is bound in accordance with the **GatewayPorts** setting.
  /// However,  an explicit `bind_address` may be used to bind the connection to a specific
  /// address. The `bind_address` of 'localhost' indicates that the listening port be bound for
  /// local use only, while an empty address or `*` indicates that the port should be available
  /// from all interfaces.
  ///
  /// Currently the SOCKS4 and SOCKS5 protocols are supported, and **ssh(1)** will act as a SOCKS
  /// server. Multiple forwardings may be specified, and additional forwardings can be given on
  /// the command line. Only the superuser can forward privileged ports.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub dynamic_forward: Option<String>,
  /// ## EnableSSHKeysign
  ///
  /// Setting this option to `yes` in the global client configuration file `/etc/ssh/ssh_config`
  /// enables the use of the helper program **ssh-keysign(8)** during **HostbasedAuthentication**.
  /// The argument must be `yes` or `no`. The default is `no`. This option should be placed in
  /// the non-hostspecific section. See **ssh-keysign(8)** for more information.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub enable_ssh_keysign: Option<YesNo>,
  /// ## EscapeChar
  ///
  /// Sets the escape character (default: `~`). The escape character can also be set on the
  /// command line. The argument should be a single character, `^` followed by a letter, or
  /// `none` to disable the escape character entirely (making the connection transparent for
  /// binary data).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub escape_char: Option<String>,
  /// ## ExitOnForwardFailure
  ///
  /// Specifies whether **ssh(1)** should terminate the connection if it cannot set up all
  /// requested dynamic, tunnel, local, and remote port forwardings. The argument must be `yes`
  /// or `no`. The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub exit_on_forward_failure: Option<YesNo>,
  /// ## ForwardAgent
  ///
  /// Specifies whether the connection to the authentication agent (if any) will be forwarded to
  /// the remote machine. The argument must be `yes` or `no`. The default is `no`.
  ///
  /// Agent forwarding should be enabled with caution. Users with the ability to bypass file
  /// permissions on the remote host (for the agent's Unix-domain socket) can access the local
  /// agent through the forwarded connection. An attacker cannot obtain key material from the
  /// agent, however they can perform operations on the keys that enable them to authenticate
  /// using the identities loaded into the agent.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub forward_agent: Option<YesNo>,
  /// ## ForwardX11
  ///
  /// Specifies whether X11 connections will be automatically redirected over the secure channel
  /// and DISPLAY set. The argument must be `yes` or `no`. The default is `no`.
  ///
  /// X11 forwarding should be enabled with caution. Users with the ability to bypass file
  /// permissions on the remote host (for the user's X11 authorization database) can access the
  /// local X11 display through the forwarded connection. An attacker may then be able to perform
  /// activities such as keystroke monitoring if the **ForwardX11Trusted** option is also enabled.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub forward_x11: Option<YesNo>,
  /// ## ForwardX11Trusted
  ///
  /// If this option is set to `yes`, remote X11 clients will have full access to the original
  /// X11 display.
  ///
  /// If this option is set to `no`, remote X11 clients will be considered untrusted and
  /// prevented from stealing or tampering with data belonging to trusted X11 clients.
  /// Furthermore, the **xauth(1)** token used for the session will be set to expire after 20
  /// minutes. Remote clients will be refused access after this time.
  ///
  /// The default is `no`.
  ///
  /// See the X11 SECURITY extension specification for full details on the restrictions imposed
  /// on untrusted clients.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub forward_x11_trusted: Option<YesNo>,
  /// ## GatewayPorts
  ///
  /// Specifies whether remote hosts are allowed to connect to local forwarded ports. By default,
  /// **ssh(1)** binds local port forwardings to the loopback address. This prevents other remote
  /// hosts from connecting to forwarded ports. **GatewayPorts** can be used to specify that ssh
  /// should bind local port forwardings to the wildcard address, thus allowing remote hosts to
  /// connect to forwarded ports. The argument must be `yes` or `no`. The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub gateway_ports: Option<YesNo>,
  /// ## GlobalKnownHostsFile
  ///
  /// Specifies a file to use for the global host key database instead of
  /// `/etc/ssh/ssh_known_hosts`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub global_known_hosts_file: Option<String>,
  /// ## GSSAPIAuthentication
  ///
  /// Specifies whether user authentication based on GSSAPI is allowed. The default is `no`. Note
  /// that this option applies to protocol version 2 only.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub gssapi_authentication: Option<YesNo>,
  /// ## GSSAPIKeyExchange
  ///
  /// Specifies whether key exchange based on GSSAPI may be used. When using GSSAPI key exchange
  /// the server need not have a host key. The default is `no`. Note that this option applies to
  /// protocol version 2 only.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub gssapi_key_exchange: Option<YesNo>,
  /// ## GSSAPIClientIdentity
  ///
  /// If set, specifies the GSSAPI client identity that ssh should use when connecting to the
  /// server. The default is unset, which means that the default identity will be used.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub gssapi_client_identity: Option<String>,
  /// ## GSSAPIDelegateCredentials
  ///
  /// Forward (delegate) credentials to the server. The default is `no`. Note that this option
  /// applies to protocol version 2 connections using GSSAPI.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub gssapi_delegate_credentials: Option<YesNo>,
  /// ## GSSAPIRenewalForcesRekey
  ///
  /// If set to `yes` then renewal of the client's GSSAPI credentials will force the rekeying of
  /// the ssh connection. With a compatible server, this can delegate the renewed credentials to
  /// a session on the server. The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub gssapi_renewal_forces_rekey: Option<YesNo>,
  /// ## GSSAPITrustDns
  ///
  /// Set to `yes` to indicate that the DNS is trusted to securely canonicalize the name of the
  /// host being connected to. If `no`, the hostname entered on the command line will be passed
  /// untouched to the GSSAPI library. The default is `no`. This option only applies to protocol
  /// version 2 connections using GSSAPI.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub gssapi_trust_dns: Option<YesNo>,
  /// ## HashKnownHosts
  ///
  /// Indicates that **ssh(1)** should hash host names and addresses when they are added to
  /// `~/.ssh/known_hosts`. These hashed names may be used normally by **ssh(1)** and **sshd(8)**,
  /// but they do not reveal identifying information should the file's contents be disclosed. The
  /// default is `no`. Note that existing names and addresses in known hosts files will not be
  /// converted automatically, but may be manually hashed using **ssh-keygen(1)**.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub hash_known_hosts: Option<YesNo>,
  /// ## HostbasedAuthentication
  ///
  /// Specifies whether to try rhosts based authentication with public key authentication. The
  /// argument must be `yes` or `no`. The default is `no`. This option applies to protocol
  /// version 2 only and is similar to **RhostsRSAAuthentication**.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub hostbased_authentication: Option<YesNo>,
  /// ## HostKeyAlgorithms
  ///
  /// Specifies the protocol version 2 host key algorithms that the client wants to use in order
  /// of preference. The default for this option is: `ssh-rsa,ssh-dss`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub host_key_algorithms: Option<String>,
  /// ## HostKeyAlias
  ///
  /// Specifies an alias that should be used instead of the real host name when looking up or
  /// saving the host key in the host key database files. This option is useful for tunneling SSH
  /// connections or for multiple servers running on a single host.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub host_key_alias: Option<String>,
  /// ## HostName
  ///
  /// Specifies the real host name to log into. This can be used to specify nicknames or
  /// abbreviations for hosts. The default is the name given on the command line. Numeric IP
  /// addresses are also permitted (both on the command line and in **HostName** specifications).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub host_name: Option<String>,
  /// ## IdentitiesOnly
  ///
  /// Specifies that **ssh(1)** should only use the authentication identity files configured in
  /// the ssh_config files, even if **ssh-agent(1)** offers more identities. The argument to this
  /// keyword must be `yes` or `no`. This option is intended for situations where ssh-agent
  /// offers many different identities. The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub identities_only: Option<YesNo>,
  /// ## IdentityFile
  ///
  /// Specifies a file from which the user's RSA or DSA authentication identity is read. The
  /// default is `~/.ssh/identity` for protocol version 1, and `~/.ssh/id_rsa` and
  /// `~/.ssh/id_dsa` for protocol version 2. Additionally, any identities represented by the
  /// authentication agent will be used for authentication.
  ///
  /// The file name may use the tilde syntax to refer to a user's home directory or one of the
  /// following escape characters:
  /// - `%d` (local user's home directory)
  /// - `%u` (local user name)
  /// - `%l` (local host name)
  /// - `%h` (remote host name)
  /// - `%r` (remote user name)
  ///
  /// It is possible to have multiple identity files specified in configuration files; all these
  /// identities will be tried in sequence.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub identity_file: Option<String>,
  /// ## Include
  ///
  /// Include the corresponding file as part of the ssh client configuration. If a configuration
  /// file is given on the command line, the **Include** directive will cause the specified
  /// configuration file to be processed before the rest of the configuration options. The other
  /// configuration directives will not be applied until after the **Include** configuration file
  /// has been processed. The **Include** directive may appear inside a **Match** or **Host**
  /// block to perform conditional inclusion.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub include: Option<String>,
  /// ## KbdInteractiveAuthentication
  ///
  /// Specifies whether to use keyboard-interactive authentication. The argument to this keyword
  /// must be `yes` or `no`. The default is `yes`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub kbd_interactive_authentication: Option<YesNo>,
  /// ## KbdInteractiveDevices
  ///
  /// Specifies the list of methods to use in keyboard-interactive authentication. Multiple
  /// method names must be comma-separated. The default is to use the server specified list. The
  /// methods available vary depending on what the server supports. For an OpenSSH server, it may
  /// be zero or more of: `bsdauth`, `pam`, and `skey`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub kbd_interactive_devices: Option<String>,
  /// ## LocalCommand
  ///
  /// Specifies a command to execute on the local machine after successfully connecting to the
  /// server. The command string extends to the end of the line, and is executed with the user's
  /// shell. The following escape character substitutions will be performed:
  /// - `%d` (local user's home directory)
  /// - `%h` (remote host name)
  /// - `%l` (local host name)
  /// - `%n` (host name as provided on the command line)
  /// - `%p` (remote port)
  /// - `%r` (remote user name)
  /// - `%u` (local user name)
  ///
  /// This directive is ignored unless **PermitLocalCommand** has been enabled.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub local_command: Option<String>,
  /// ## LocalForward
  ///
  /// Specifies that a TCP port on the local machine be forwarded over the secure channel to the
  /// specified host and port from the remote machine. The first argument must be
  /// `[bind_address:]port` and the second argument must be `host:hostport`.
  ///
  /// IPv6 addresses can be specified by enclosing addresses in square brackets or by using an
  /// alternative syntax: `[bind_address/]port` and `host/hostport`. Multiple forwardings may be
  /// specified, and additional forwardings can be given on the command line. Only the superuser
  /// can forward privileged ports. By default, the local port is bound in accordance with the
  /// **GatewayPorts** setting. However, an explicit `bind_address` may be used to bind the
  /// connection to a specific address. The `bind_address` of 'localhost' indicates that the
  /// listening port be bound for local use only, while an empty address or `*` indicates that
  /// the port should be available from all interfaces.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub local_forward: Option<String>,
  /// ## LogLevel
  ///
  /// Gives the verbosity level that is used when logging messages from **ssh(1)**. The possible
  /// values are: `QUIET`, `FATAL`, `ERROR`, `INFO`, `VERBOSE`, `DEBUG`, `DEBUG1`, `DEBUG2`, and
  /// `DEBUG3`. The default is `INFO`. `DEBUG` and `DEBUG1` are equivalent. `DEBUG2` and `DEBUG3`
  /// each specify higher levels of verbose output.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub log_level: Option<LogLevels>,
  /// ## MACs
  ///
  /// Specifies the MAC (message authentication code) algorithms in order of preference. The MAC
  /// algorithm is used in protocol version 2 for data integrity protection. Multiple algorithms
  /// must be comma-separated. The default is:
  ///
  /// `hmac-md5,hmac-sha1,umac-64@openssh.com, hmac-ripemd160,hmac-sha1-96,hmac-md5-96`
  #[serde(skip_serializing_if = "Option::is_none")]
  pub macs: Option<String>,
  /// ## NoHostAuthenticationForLocalhost
  ///
  /// This option can be used if the home directory is shared across machines. In this case
  /// localhost will refer to a different machine on each of the machines and the user will get
  /// many warnings about changed host keys. However, this option disables host authentication
  /// for localhost. The argument to this keyword must be `yes` or `no`. The default is to check
  /// the host key for localhost.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub no_host_authentication_for_localhost: Option<YesNo>,
  /// ## NumberOfPasswordPrompts
  ///
  /// Specifies the number of password prompts before giving up. The argument to this keyword
  /// must be an integer. The default is 3.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub number_of_password_prompts: Option<u32>,
  /// ## PasswordAuthentication
  ///
  /// Specifies whether to use password authentication. The argument to this keyword must be
  /// `yes` or `no`. The default is `yes`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub password_authentication: Option<YesNo>,
  /// ## PermitLocalCommand
  ///
  /// Allow local command execution via the **LocalCommand** option or using the
  /// **!**<em>command</em> escape sequence in **ssh(1)**. The argument must be `yes` or `no`.
  /// The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub permit_local_command: Option<YesNo>,
  /// ## Port
  ///
  /// Specifies the port number to connect on the remote host. The default is 22.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub port: Option<u32>,
  /// ## PreferredAuthentications
  ///
  /// Specifies the order in which the client should try protocol 2 authentication methods. This
  /// allows a client to prefer one method (e.g. keyboard-interactive) over another method
  /// (e.g. password) The default for this option is:
  ///
  /// `gssapi-with-mic, hostbased, publickey, keyboard-interactive, password`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub preferred_authentications: Option<String>,
  /// ## Protocol
  ///
  /// Specifies the protocol versions **ssh(1)** should support in order of preference. The
  /// possible values are `1` and `2`. Multiple versions must be comma-separated. The default is
  /// `2,1`. This means that ssh tries version 2 and falls back to version 1 if version 2 is not
  /// available.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub protocol: Option<String>,
  /// ## ProxyCommand
  ///
  /// Specifies the command to use to connect to the server. The command string extends to the
  /// end of the line, and is executed with the user's shell. In the command string, `%h` will be
  /// substituted by the host name to connect and `%p` by the port. The command can be basically
  /// anything, and should read from its standard input and write to its standard output. It
  /// should eventually connect an **sshd(8)** server running on some machine, or execute
  /// `sshd -i` somewhere. Host key management will be done using the **HostName** of the host
  /// being connected (defaulting to the name typed by the user). Setting the command to `none`
  /// disables this option entirely. Note that **CheckHostIP** is not available for connects with
  /// a proxy command.
  ///
  /// This directive is useful in conjunction with **nc(1)** and its proxy support. For example,
  /// the following directive would connect via an HTTP proxy at 192.0.2.0:
  ///
  /// `ProxyCommand /usr/bin/nc -X connect -x 192.0.2.0:8080 %h %p`
  #[serde(skip_serializing_if = "Option::is_none")]
  pub proxy_command: Option<String>,
  /// ## PubkeyAuthentication
  ///
  /// Specifies whether to try public key authentication. The argument to this keyword must be
  /// `yes` or `no`. The default is `yes`. This option applies to protocol version 2 only.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub pubkey_authentication: Option<YesNo>,
  /// ## RekeyLimit
  ///
  /// Specifies the maximum amount of data that may be transmitted before the session key is
  /// renegotiated. The argument is the number of bytes, with an optional suffix of `K`, `M`, or
  /// `G` to indicate Kilobytes, Megabytes, or Gigabytes, respectively. The default is between
  /// `1G` and `4G`, depending on the cipher. This option applies to protocol version 2 only.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub rekey_limit: Option<String>,
  /// ## RemoteForward
  ///
  /// Specifies that a TCP port on the remote machine be forwarded over the secure channel to the
  /// specified host and port from the local machine. The first argument must be
  /// `[bind_address:]port` and the second argument must be `host:hostport`. IPv6 addresses can
  /// be specified by enclosing addresses in square brackets or by using an alternative syntax:
  /// `[bind_address/]port` and `host/hostport`. Multiple forwardings may be specified, and
  /// additional forwardings can be given on the command line. Privileged ports can be forwarded
  /// only when logging in as root on the remote machine.
  ///
  /// If the port argument is `0`, the listen port will be dynamically allocated on the server
  /// and reported to the client at run time.
  ///
  /// If the `bind_address` is not specified, the default is to only bind to loopback addresses.
  /// If  the `bind_address` is `*` or an empty string, then the forwarding is requested to
  /// listen on  all interfaces. Specifying a remote `bind_address` will only succeed if the
  /// server's **GatewayPorts** option is enabled (see **sshd_config(5)**).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub remote_forward: Option<String>,
  /// ## RHostsRSAAuthentication
  ///
  /// Specifies whether to try rhosts based authentication with RSA host authentication. The
  /// argument must be `yes` or `no`. The default is `no`. This option applies to protocol
  /// version 1 only and requires **ssh(1)** to be setuid root.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub r_hosts_rsa_authentication: Option<YesNo>,
  /// ## RSAAuthentication
  ///
  /// Specifies whether to try RSA authentication. The argument to this keyword must be `yes` or
  /// `no`. RSA authentication will only be attempted if the identity file exists, or an
  /// authentication agent is running. The default is `yes`. Note that this option applies to
  /// protocol version 1 only.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub rsa_authentication: Option<YesNo>,
  /// ## SendEnv
  ///
  /// Specifies what variables from the local **environ(7)** should be sent to the server. Note
  /// that environment passing is only supported for protocol 2. The server must also support it,
  /// and the server must be configured to accept these environment variables. Refer to
  /// **AcceptEnv** in **sshd_config(5)** for how to configure the server. Variables are
  /// specified by name, which may contain wildcard characters. Multiple environment variables
  /// may be separated by whitespace or spread across multiple **SendEnv** directives. The
  /// default is not to send any environment variables.
  ///
  /// See **PATTERNS** for more information on patterns.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub send_env: Option<String>,
  /// ## ServerAliveCountMax
  ///
  /// Sets the number of server alive messages (see below) which may be sent without **ssh(1)**
  /// receiving any messages back from the server. If this threshold is reached while server
  /// alive messages are being sent, ssh will disconnect from the server, terminating the
  /// session. It is important to note that the use of server alive messages is very different
  /// from **TCPKeepAlive** (below). The server alive messages are sent through the encrypted
  /// channel and therefore will not be spoofable. The TCP keepalive option enabled by
  /// **TCPKeepAlive** is spoofable. The server alive mechanism is valuable when the client or
  /// server depend on knowing when a connection has become inactive.
  ///
  /// The default value is 3. If, for example, **ServerAliveInterval** (see below) is set to 15
  /// and **ServerAliveCountMax** is left at the default, if the server becomes unresponsive, ssh
  /// will disconnect after approximately 45 seconds. This option applies to protocol version 2
  /// only.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub server_alive_count_max: Option<u32>,
  /// ## ServerAliveInterval
  ///
  /// Sets a timeout interval in seconds after which if no data has been received from the
  /// server, **ssh(1)** will send a message through the encrypted channel to request a response
  /// from the server. The default is 0, indicating that these messages will not be sent to the
  /// server. This option applies to protocol version 2 only.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub server_alive_interval: Option<u32>,
  /// ## SmartcardDevice
  ///
  /// Specifies which smartcard device to use. The argument to this keyword is the device
  /// **ssh(1)** should use to communicate with a smartcard used for storing the user's private
  /// RSA key. By default, no device is specified and smartcard support is not activated.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub smartcard_device: Option<String>,
  /// ## StrictHostKeyChecking
  ///
  /// If this flag is set to `yes`, **ssh(1)** will never automatically add host keys to the
  /// `~/.ssh/known_hosts` file, and refuses to connect to hosts whose host key has changed.
  /// This provides maximum protection against trojan horse attacks, though it can be annoying
  /// when the `/etc/ssh/ssh_known_hosts` file is poorly maintained or when connections to new
  /// hosts are frequently made. This option forces the user to manually add all new hosts. If
  /// this flag is set to `no`, ssh will automatically add new host keys to the user known hosts
  /// files. If this flag is set to `ask`, new host keys will be added to the user known host
  /// files only after the user has confirmed that is what they really want to do, and ssh will
  /// refuse to connect to hosts whose host key has changed. The host keys of known hosts will be
  /// verified automatically in all cases. The argument must be `yes`, `no`, or `ask`. The
  /// default is `ask`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub strict_host_key_checking: Option<YesNoAsk>,
  /// ## TCPKeepAlive
  ///
  /// Specifies whether the system should send TCP keepalive messages to the other side. If they
  /// are sent, death of the connection or crash of one of the machines will be properly noticed.
  /// However, this means that connections will die if the route is down temporarily, and some
  /// people find it annoying.
  ///
  /// The default is `yes` (to send TCP keepalive messages), and the client will notice if the
  /// network goes down or the remote host dies. This is important in scripts, and many users
  /// want it too. To disable TCP keepalive messages, the value should be set to `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub tcp_keep_alive: Option<YesNo>,
  /// ## Tunnel
  ///
  /// Request **tun(4)** device forwarding between the client and the server. The argument must
  /// be `yes`, `point-to-point` (layer 3), `ethernet` (layer 2), or `no`. Specifying `yes`
  /// requests the default tunnel mode, which is `point-to-point`. The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub tunnel: Option<TunnelOptions>,
  /// ## TunnelDevice
  ///
  /// Specifies the **tun(4)** devices to open on the client (`local_tun`) and the server
  /// (`remote_tun`). The argument must be `local_tun[:remote_tun]`. The devices may be specified
  /// by numerical ID or the keyword `any`, which uses the next available tunnel device. If
  /// `remote_tun` is not specified, it defaults to `any`. The default is `any:any`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub tunnel_device: Option<String>,
  /// ## UsePrivilegedPort
  ///
  /// Specifies whether to use a privileged port for outgoing connections. The argument must be
  /// `yes` or `no`. The default is `no`. If set to `yes`, **ssh(1)** must be setuid root. Note
  /// that this option must be set to `yes` for **RhostsRSAAuthentication** with older servers.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub use_privileged_port: Option<YesNo>,
  /// ## User
  ///
  /// Specifies the user to log in as. This can be useful when a different user name is used on
  /// different machines. This saves the trouble of having to remember to give the user name on
  /// the command line.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub user: Option<String>,
  /// ## UserKnownHostsFile
  ///
  /// Specifies a file to use for the user host key database instead of `~/.ssh/known_hosts`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub user_known_hosts_file: Option<String>,
  /// ## VerifyHostKeyDNS
  ///
  /// Specifies whether to verify the remote key using DNS and SSHFP resource records. If this
  /// option is set to `yes`, the client will implicitly trust keys that match a secure
  /// fingerprint from DNS. Insecure fingerprints will be handled as if this option was set to
  /// `ask`. If this option is set to `ask`, information on fingerprint match will be displayed,
  /// but the user will still need to confirm new host keys according to the
  /// **StrictHostKeyChecking** option. The argument must be `yes`, `no`, or `ask`. The default
  /// is `no`. Note that this option applies to protocol version 2 only.
  ///
  /// See also VERIFYING HOST KEYS in **ssh(1)**.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub verify_host_key_dns: Option<YesNoAsk>,
  /// ## VisualHostKey
  ///
  /// If this flag is set to `yes`, an ASCII art representation of the remote host key
  /// fingerprint is printed in addition to the hex fingerprint string at login and for unknown
  /// host keys. If this flag is set to `no`, no fingerprint strings are printed at login and
  /// only the hex fingerprint string will be printed for unknown host keys. The default is `no`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub visual_host_key: Option<YesNo>,
  /// ## XAuthLocation
  ///
  /// Specifies the full pathname of the **xauth(1)** program. The default is `/usr/bin/xauth`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub x_auth_location: Option<String>,
  /// Unknown or potentially invalid configuration parameters.
  ///
  /// We don't want to lose any information, so we capture it here. This particular field is only
  /// used when loading configuration data from file. The UI should not produce any data that does
  /// not comply with the object structure.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub unknown: Option<HashMap<String, String>>,
}

impl SshConfigHost {
  /// Create a new `SshConfigHost` with default values.
  pub fn new() -> Self {
    Self {
      host: "".to_string(),
      address_family: None,
      batch_mode: None,
      bind_address: None,
      challenge_response_authentication: None,
      check_host_ip: None,
      cipher: None,
      ciphers: None,
      clear_all_forwardings: None,
      compression: None,
      compression_level: None,
      connection_attempts: None,
      connect_timeout: None,
      control_master: None,
      control_path: None,
      dynamic_forward: None,
      enable_ssh_keysign: None,
      escape_char: None,
      exit_on_forward_failure: None,
      forward_agent: None,
      forward_x11: None,
      forward_x11_trusted: None,
      gateway_ports: None,
      global_known_hosts_file: None,
      gssapi_authentication: None,
      gssapi_client_identity: None,
      gssapi_delegate_credentials: None,
      gssapi_key_exchange: None,
      gssapi_renewal_forces_rekey: None,
      gssapi_trust_dns: None,
      hash_known_hosts: None,
      hostbased_authentication: None,
      host_key_algorithms: None,
      host_key_alias: None,
      host_name: None,
      identities_only: None,
      identity_file: None,
      include: None,
      kbd_interactive_authentication: None,
      kbd_interactive_devices: None,
      local_command: None,
      local_forward: None,
      log_level: None,
      macs: None,
      no_host_authentication_for_localhost: None,
      number_of_password_prompts: None,
      password_authentication: None,
      permit_local_command: None,
      port: None,
      preferred_authentications: None,
      protocol: None,
      proxy_command: None,
      pubkey_authentication: None,
      rekey_limit: None,
      remote_forward: None,
      r_hosts_rsa_authentication: None,
      rsa_authentication: None,
      send_env: None,
      server_alive_count_max: None,
      server_alive_interval: None,
      smartcard_device: None,
      strict_host_key_checking: None,
      tcp_keep_alive: None,
      tunnel: None,
      tunnel_device: None,
      use_privileged_port: None,
      user: None,
      user_known_hosts_file: None,
      verify_host_key_dns: None,
      visual_host_key: None,
      x_auth_location: None,
      unknown: None,
    }
  }

  /// Set property values for the `SshConfigHost`.
  pub fn set_property(&mut self, key: &'static str, value: &str) -> Result<(), ConfigError> {
    match key.to_lowercase().as_str() {
      "host" => {
        self.host = value.to_string();
        Ok(())
      }
      "bindaddress" => {
        self.bind_address = Some(value.to_string());
        Ok(())
      }
      "cipher" => {
        self.cipher = Some(value.to_string());
        Ok(())
      }
      "controlpath" => {
        self.control_path = Some(value.to_string());
        Ok(())
      }
      "dynamicforward" => {
        self.dynamic_forward = Some(value.to_string());
        Ok(())
      }
      "escapechar" => {
        self.escape_char = Some(value.to_string());
        Ok(())
      }
      "globalknownhostsfile" => {
        self.global_known_hosts_file = Some(value.to_string());
        Ok(())
      }
      "gssapiclientidentity" => {
        self.gssapi_client_identity = Some(value.to_string());
        Ok(())
      }
      "hostkeyalgorithms" => {
        self.host_key_algorithms = Some(value.to_string());
        Ok(())
      }
      "hostkeyalias" => {
        self.host_key_alias = Some(value.to_string());
        Ok(())
      }
      "hostname" => {
        self.host_name = Some(value.to_string());
        Ok(())
      }
      "identityfile" => {
        self.identity_file = Some(value.to_string());
        Ok(())
      }
      "include" => {
        self.include = Some(value.to_string());
        Ok(())
      }
      "localcommand" => {
        self.local_command = Some(value.to_string());
        Ok(())
      }
      "localforward" => {
        self.local_forward = Some(value.to_string());
        Ok(())
      }
      "preferredauthentications" => {
        self.preferred_authentications = Some(value.to_string());
        Ok(())
      }
      "proxycommand" => {
        self.proxy_command = Some(value.to_string());
        Ok(())
      }
      "rekeylimit" => {
        self.rekey_limit = Some(value.to_string());
        Ok(())
      }
      "remoteforward" => {
        self.remote_forward = Some(value.to_string());
        Ok(())
      }
      "sendenv" => {
        self.send_env = Some(value.to_string());
        Ok(())
      }
      "smartcarddevice" => {
        self.smartcard_device = Some(value.to_string());
        Ok(())
      }
      "tunneldevice" => {
        self.tunnel_device = Some(value.to_string());
        Ok(())
      }
      "user" => {
        self.user = Some(value.to_string());
        Ok(())
      }
      "userknownhostsfile" => {
        self.user_known_hosts_file = Some(value.to_string());
        Ok(())
      }
      "xauthlocation" => {
        self.x_auth_location = Some(value.to_string());
        Ok(())
      }
      // Handle fields that should have numeric values
      "compressionlevel" => {
        if let Ok(parsed_value) = value.parse::<u32>() {
          self.compression_level = Some(parsed_value);
          Ok(())
        } else {
          Err(ConfigError::InvalidValue { field: key, value: value.to_string() })
        }
      }
      "connectionattempts" => {
        if let Ok(parsed_value) = value.parse::<u32>() {
          self.connection_attempts = Some(parsed_value);
          Ok(())
        } else {
          Err(ConfigError::InvalidValue { field: key, value: value.to_string() })
        }
      }
      "connecttimeout" => {
        if let Ok(parsed_value) = value.parse::<u32>() {
          self.connect_timeout = Some(parsed_value);
          Ok(())
        } else {
          Err(ConfigError::InvalidValue { field: key, value: value.to_string() })
        }
      }
      "numberofpasswordprompts" => {
        if let Ok(parsed_value) = value.parse::<u32>() {
          self.number_of_password_prompts = Some(parsed_value);
          Ok(())
        } else {
          Err(ConfigError::InvalidValue { field: key, value: value.to_string() })
        }
      }
      "port" => {
        if let Ok(parsed_value) = value.parse::<u32>() {
          self.port = Some(parsed_value);
          Ok(())
        } else {
          Err(ConfigError::InvalidValue { field: key, value: value.to_string() })
        }
      }
      "serveralivecountmax" => {
        if let Ok(parsed_value) = value.parse::<u32>() {
          self.server_alive_count_max = Some(parsed_value);
          Ok(())
        } else {
          Err(ConfigError::InvalidValue { field: key, value: value.to_string() })
        }
      }
      "serveraliveinterval" => {
        if let Ok(parsed_value) = value.parse::<u32>() {
          self.server_alive_interval = Some(parsed_value);
          Ok(())
        } else {
          Err(ConfigError::InvalidValue { field: key, value: value.to_string() })
        }
      }
      // Handle enumerated fields
      "addressfamily" => {
        self.address_family = Some(AddressFamily::from_str(value)?);
        Ok(())
      }
      "batchmode" => {
        match value.to_lowercase().as_str() {
          "yes" => self.batch_mode = Some(YesNo::Yes),
          "no" => self.batch_mode = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "challengeresponseauthentication" => {
        match value.to_lowercase().as_str() {
          "yes" => self.challenge_response_authentication = Some(YesNo::Yes),
          "no" => self.challenge_response_authentication = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "checkhostip" => {
        match value.to_lowercase().as_str() {
          "yes" => self.check_host_ip = Some(YesNo::Yes),
          "no" => self.check_host_ip = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "clearallforwardings" => {
        match value.to_lowercase().as_str() {
          "yes" => self.clear_all_forwardings = Some(YesNo::Yes),
          "no" => self.clear_all_forwardings = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "compression" => {
        match value.to_lowercase().as_str() {
          "yes" => self.compression = Some(YesNo::Yes),
          "no" => self.compression = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "controlmaster" => {
        match value.to_lowercase().as_str() {
          "yes" => self.control_master = Some(YesNoAskAutoAutoask::Yes),
          "no" => self.control_master = Some(YesNoAskAutoAutoask::No),
          "ask" => self.control_master = Some(YesNoAskAutoAutoask::Ask),
          "auto" => self.control_master = Some(YesNoAskAutoAutoask::Auto),
          "autoask" => self.control_master = Some(YesNoAskAutoAutoask::AutoAsk),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "enablesshkeysign" => {
        match value.to_lowercase().as_str() {
          "yes" => self.enable_ssh_keysign = Some(YesNo::Yes),
          "no" => self.enable_ssh_keysign = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "exitonforwardfailure" => {
        match value.to_lowercase().as_str() {
          "yes" => self.exit_on_forward_failure = Some(YesNo::Yes),
          "no" => self.exit_on_forward_failure = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "forwardagent" => {
        match value.to_lowercase().as_str() {
          "yes" => self.forward_agent = Some(YesNo::Yes),
          "no" => self.forward_agent = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "forwardx11" => {
        match value.to_lowercase().as_str() {
          "yes" => self.forward_x11 = Some(YesNo::Yes),
          "no" => self.forward_x11 = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "forwardx11trusted" => {
        match value.to_lowercase().as_str() {
          "yes" => self.forward_x11_trusted = Some(YesNo::Yes),
          "no" => self.forward_x11_trusted = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "gatewayports" => {
        match value.to_lowercase().as_str() {
          "yes" => self.gateway_ports = Some(YesNo::Yes),
          "no" => self.gateway_ports = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "gssapiauthentication" => {
        match value.to_lowercase().as_str() {
          "yes" => self.gssapi_authentication = Some(YesNo::Yes),
          "no" => self.gssapi_authentication = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "gssapidelegatecredentials" => {
        match value.to_lowercase().as_str() {
          "yes" => self.gssapi_delegate_credentials = Some(YesNo::Yes),
          "no" => self.gssapi_delegate_credentials = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "gssapikeyexchange" => {
        match value.to_lowercase().as_str() {
          "yes" => self.gssapi_key_exchange = Some(YesNo::Yes),
          "no" => self.gssapi_key_exchange = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "gssapirenewalforcesrekey" => {
        match value.to_lowercase().as_str() {
          "yes" => self.gssapi_renewal_forces_rekey = Some(YesNo::Yes),
          "no" => self.gssapi_renewal_forces_rekey = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "gssapitrustdns" => {
        match value.to_lowercase().as_str() {
          "yes" => self.gssapi_trust_dns = Some(YesNo::Yes),
          "no" => self.gssapi_trust_dns = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "hashknownhosts" => {
        match value.to_lowercase().as_str() {
          "yes" => self.hash_known_hosts = Some(YesNo::Yes),
          "no" => self.hash_known_hosts = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "hostbasedauthentication" => {
        match value.to_lowercase().as_str() {
          "yes" => self.hostbased_authentication = Some(YesNo::Yes),
          "no" => self.hostbased_authentication = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "identitiesonly" => {
        match value.to_lowercase().as_str() {
          "yes" => self.identities_only = Some(YesNo::Yes),
          "no" => self.identities_only = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "kbdinteractiveauthentication" => {
        match value.to_lowercase().as_str() {
          "yes" => self.kbd_interactive_authentication = Some(YesNo::Yes),
          "no" => self.kbd_interactive_authentication = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "loglevel" => {
        self.log_level = Some(LogLevels::from_str(value)?);
        Ok(())
      }
      "nohostauthenticationforlocalhost" => {
        match value.to_lowercase().as_str() {
          "yes" => self.no_host_authentication_for_localhost = Some(YesNo::Yes),
          "no" => self.no_host_authentication_for_localhost = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "passwordauthentication" => {
        match value.to_lowercase().as_str() {
          "yes" => self.password_authentication = Some(YesNo::Yes),
          "no" => self.password_authentication = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "permitlocalcommand" => {
        match value.to_lowercase().as_str() {
          "yes" => self.permit_local_command = Some(YesNo::Yes),
          "no" => self.permit_local_command = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "pubkeyauthentication" => {
        match value.to_lowercase().as_str() {
          "yes" => self.pubkey_authentication = Some(YesNo::Yes),
          "no" => self.pubkey_authentication = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "rhostsrsaauthentication" => {
        match value.to_lowercase().as_str() {
          "yes" => self.r_hosts_rsa_authentication = Some(YesNo::Yes),
          "no" => self.r_hosts_rsa_authentication = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "rsaauthentication" => {
        match value.to_lowercase().as_str() {
          "yes" => self.rsa_authentication = Some(YesNo::Yes),
          "no" => self.rsa_authentication = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "stricthostkeychecking" => {
        match value.to_lowercase().as_str() {
          "yes" => self.strict_host_key_checking = Some(YesNoAsk::Yes),
          "no" => self.strict_host_key_checking = Some(YesNoAsk::No),
          "ask" => self.strict_host_key_checking = Some(YesNoAsk::Ask),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "tcpkeepalive" => {
        match value.to_lowercase().as_str() {
          "yes" => self.tcp_keep_alive = Some(YesNo::Yes),
          "no" => self.tcp_keep_alive = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "tunnel" => {
        match value.to_lowercase().as_str() {
          "yes" => self.tunnel = Some(TunnelOptions::Yes),
          "point-to-point" => self.tunnel = Some(TunnelOptions::PointToPoint),
          "ethernet" => self.tunnel = Some(TunnelOptions::Ethernet),
          "no" => self.tunnel = Some(TunnelOptions::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "useprivilegedport" => {
        match value.to_lowercase().as_str() {
          "yes" => self.use_privileged_port = Some(YesNo::Yes),
          "no" => self.use_privileged_port = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "verifyhostkeydns" => {
        match value.to_lowercase().as_str() {
          "yes" => self.verify_host_key_dns = Some(YesNoAsk::Yes),
          "no" => self.verify_host_key_dns = Some(YesNoAsk::No),
          "ask" => self.verify_host_key_dns = Some(YesNoAsk::Ask),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      "visualhostkey" => {
        match value.to_lowercase().as_str() {
          "yes" => self.visual_host_key = Some(YesNo::Yes),
          "no" => self.visual_host_key = Some(YesNo::No),
          _ => {
            return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
          }
        }
        Ok(())
      }
      // Handle fields that must be comma-separated list strings
      "ciphers" => {
        let values: Vec<&str> = value.split(' ').collect();
        if values.is_empty() {
          return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
        }
        self.ciphers = Some(values.join(","));
        Ok(())
      }
      "kbdinteractivedevices" => {
        let values: Vec<&str> = value.split(' ').collect();
        if values.is_empty() {
          return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
        }
        self.kbd_interactive_devices = Some(values.join(","));
        Ok(())
      }
      "macs" => {
        let values: Vec<&str> = value.split(' ').collect();
        if values.is_empty() {
          return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
        }
        self.macs = Some(values.join(","));
        Ok(())
      }
      "protocol" => {
        let values: Vec<&str> = value.split(' ').collect();
        if values.is_empty() {
          return Err(ConfigError::InvalidValue { field: key, value: value.to_string() });
        }
        self.protocol = Some(values.join(","));
        Ok(())
      }
      // Unspecified or invalid ssh config file parameter was found. The key does not match
      // any known parameter or field. We'll store it here in case the user knows what to do
      // with it.
      _ => {
        let mut unknowns: HashMap<String, String> = HashMap::new();
        if self.unknown.is_some() {
          unknowns = self.unknown.clone().unwrap();
        }
        unknowns.insert(key.to_string(), value.to_string());
        self.unknown = Some(unknowns);
        Ok(())
      }
    }
  }
}
