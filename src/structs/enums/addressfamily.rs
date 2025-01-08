use crate::error::ConfigError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const VALID_ADDRESS_FAMILIES: [&'static str; 3] = ["any", "inet", "inet6"];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    Any,
    Inet,
    Inet6,
}

impl FromStr for AddressFamily {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(AddressFamily::Any),
            "inet" => Ok(AddressFamily::Inet),
            "inet6" => Ok(AddressFamily::Inet6),
            _ => Err(ConfigError::InvalidValue { field: "address_family", value: s.to_string() }),
        }
    }
}

impl AddressFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressFamily::Any => "any",
            AddressFamily::Inet => "inet",
            AddressFamily::Inet6 => "inet6",
        }
    }
}
