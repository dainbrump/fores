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

pub const VALID_KBD_INTERACTIVE_DEVICES: [&'static str; 3] = ["bsdauth", "pam", "skey"];

pub const VALID_MACS: [&'static str; 6] = [
    "hmac-md5",
    "hmac-sha1",
    "umac-64@openssh.com",
    "hmac-ripemd160",
    "hmac-sha1-96",
    "hmac-md5-96",
];

pub const VALID_HOST_KEY_ALGORITHMS: [&'static str; 5] =
    ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"];

pub const VALID_PROTOCOLS: [&'static str; 2] = ["1", "2"];
