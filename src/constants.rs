pub const VALID_CIPHERS: [&'static str; 19] = [
  "aes128-ctr",
  "aes192-ctr",
  "aes256-ctr",
  "arcfour256",
  "arcfour128",
  "aes128-cbc",
  "3des-cbc",
  "blowfish-cbc",
  "cast128-cbc",
  "aes192-cbc",
  "aes256-cbc",
  "arcfour",
  "rijndael-cbc@lysator.liu.se",
  "aes128-gcm@openssh.com",
  "aes256-gcm@openssh.com",
  "chacha20-poly1305@openssh.com",
  "aesa128-ctr",
  "aesa192-ctr",
  "aesa256-ctr",
];

pub const VALID_ADDRESS_FAMILIES: [&'static str; 3] = ["any", "inet", "inet6"];

pub const VALID_LOG_LEVELS: [&'static str; 9] =
  ["quiet", "fatal", "error", "info", "verbose", "debug", "debug1", "debug2", "debug3"];

pub const VALID_YES_NO: [&'static str; 2] = ["yes", "no"];

pub const VALID_YES_NO_ASK: [&'static str; 3] = ["yes", "no", "ask"];

pub const VALID_YES_NO_ASK_AUTO_AUTOASK: [&'static str; 5] =
  ["yes", "no", "ask", "auto", "autoask"];

pub const VALID_TUNNEL_OPTIONS: [&'static str; 4] = ["yes", "point-to-point", "ethernet", "no"];
