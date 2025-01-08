use crate::error::ConfigError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const VALID_YES_NO: [&'static str; 2] = ["yes", "no"];
pub const VALID_YES_NO_ASK: [&'static str; 3] = ["yes", "no", "ask"];
pub const VALID_YES_NO_ASK_AUTO_AUTOASK: [&'static str; 5] =
    ["yes", "no", "ask", "auto", "autoask"];
pub const VALID_TUNNEL_OPTIONS: [&'static str; 4] = ["yes", "point-to-point", "ethernet", "no"];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum YesNo {
    Yes,
    No,
}

impl FromStr for YesNo {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_with_field(s, "YesNo")
    }
}

/// Converts a string to a `YesNo` variant.
///
/// # Errors
///
/// Returns an error if the string does not match any of the variants.
/// ```
/// use std::str::FromStr;
/// use fores::structs::enums::shared::YesNo;
/// use fores::ConfigError;
///
/// let yes = YesNo::from_str("yes");
/// assert!(yes.is_ok());
/// assert_eq!(yes.unwrap(), YesNo::Yes);
///
/// let no = YesNo::from_str("no");
/// assert!(no.is_ok());
/// assert_eq!(no.unwrap(), YesNo::No);
///
/// let invalid = YesNo::from_str("invalid");
/// assert!(invalid.is_err());
/// match invalid.unwrap_err() {
///     ConfigError::InvalidValue { field, value } => {
///         assert_eq!(field, "YesNo");
///         assert_eq!(value, "invalid");
///     }
///     _ => panic!("Expected ConfigError::InvalidValue"),
/// }
/// ```
impl YesNo {
    pub fn from_str_with_field(s: &str, field: &'static str) -> Result<Self, ConfigError> {
        match s.to_lowercase().as_str() {
            "yes" => Ok(YesNo::Yes),
            "no" => Ok(YesNo::No),
            _ => Err(ConfigError::InvalidValue { field, value: s.to_string() }),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum YesNoAsk {
    Yes,
    No,
    Ask,
}

impl FromStr for YesNoAsk {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_with_field(s, "YesNoAsk")
    }
}

/// Converts a string to a `YesNoAsk` variant.
///
/// # Errors
///
/// Returns an error if the string does not match any of the variants.
/// ```
/// use std::str::FromStr;
/// use fores::structs::enums::shared::YesNoAsk;
/// use fores::ConfigError;
///
/// let yes = YesNoAsk::from_str("yes");
/// assert!(yes.is_ok());
/// assert_eq!(yes.unwrap(), YesNoAsk::Yes);
///
/// let no = YesNoAsk::from_str("no");
/// assert!(no.is_ok());
/// assert_eq!(no.unwrap(), YesNoAsk::No);
///
/// let ask = YesNoAsk::from_str("ask");
/// assert!(ask.is_ok());
/// assert_eq!(ask.unwrap(), YesNoAsk::Ask);
///
/// let invalid = YesNoAsk::from_str("invalid");
/// assert!(invalid.is_err());
/// match invalid.unwrap_err() {
///     ConfigError::InvalidValue { field, value } => {
///       assert_eq!(field, "YesNoAsk");
///       assert_eq!(value, "invalid");
///     }
///     _ => panic!("Expected ConfigError::InvalidValue"),
/// }
/// ```
impl YesNoAsk {
    pub fn from_str_with_field(s: &str, field: &'static str) -> Result<Self, ConfigError> {
        match s.to_lowercase().as_str() {
            "yes" => Ok(YesNoAsk::Yes),
            "no" => Ok(YesNoAsk::No),
            "ask" => Ok(YesNoAsk::Ask),
            _ => Err(ConfigError::InvalidValue { field, value: s.to_string() }),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum YesNoAskAutoAutoask {
    Yes,
    No,
    Ask,
    Auto,
    AutoAsk,
}

impl FromStr for YesNoAskAutoAutoask {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_with_field(s, "YesNoAskAutoAutoask")
    }
}

/// Converts a string to a `YesNoAskAutoAutoask` variant.
///
/// # Errors
///
/// Returns an error if the string does not match any of the variants.
/// ```
/// use std::str::FromStr;
/// use fores::structs::enums::shared::YesNoAskAutoAutoask;
/// use fores::ConfigError;
///
/// let yes = YesNoAskAutoAutoask::from_str("yes");
/// assert!(yes.is_ok());
/// assert_eq!(yes.unwrap(), YesNoAskAutoAutoask::Yes);
///
/// let no = YesNoAskAutoAutoask::from_str("no");
/// assert!(no.is_ok());
/// assert_eq!(no.unwrap(), YesNoAskAutoAutoask::No);
///
/// let ask = YesNoAskAutoAutoask::from_str("ask");
/// assert!(ask.is_ok());
/// assert_eq!(ask.unwrap(), YesNoAskAutoAutoask::Ask);
///
/// let auto = YesNoAskAutoAutoask::from_str("auto");
/// assert!(auto.is_ok());
/// assert_eq!(auto.unwrap(), YesNoAskAutoAutoask::Auto);
///
/// let autoask = YesNoAskAutoAutoask::from_str("autoask");
/// assert!(autoask.is_ok());
/// assert_eq!(autoask.unwrap(), YesNoAskAutoAutoask::AutoAsk);
///
/// let invalid = YesNoAskAutoAutoask::from_str("invalid");
/// assert!(invalid.is_err());
/// match invalid.unwrap_err() {
///     ConfigError::InvalidValue { field, value } => {
///       assert_eq!(field, "YesNoAskAutoAutoask");
///       assert_eq!(value, "invalid");
///     }
///     _ => panic!("Expected ConfigError::InvalidValue"),
/// }
/// ```
impl YesNoAskAutoAutoask {
    pub fn from_str_with_field(s: &str, field: &'static str) -> Result<Self, ConfigError> {
        match s.to_lowercase().as_str() {
            "yes" => Ok(YesNoAskAutoAutoask::Yes),
            "no" => Ok(YesNoAskAutoAutoask::No),
            "ask" => Ok(YesNoAskAutoAutoask::Ask),
            "auto" => Ok(YesNoAskAutoAutoask::Auto),
            "autoask" => Ok(YesNoAskAutoAutoask::AutoAsk),
            _ => Err(ConfigError::InvalidValue { field, value: s.to_string() }),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelOptions {
    Yes,
    PointToPoint,
    Ethernet,
    No,
}

impl FromStr for TunnelOptions {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_with_field(s, "TunnelOptions")
    }
}

/// Converts a string to a `TunnelOptions` variant.
///
/// # Errors
///
/// Returns an error if the string does not match any of the variants.
/// ```
/// use std::str::FromStr;
/// use fores::structs::enums::shared::TunnelOptions;
/// use fores::ConfigError;
///
/// let yes = TunnelOptions::from_str("yes");
/// assert!(yes.is_ok());
/// assert_eq!(yes.unwrap(), TunnelOptions::Yes);
///
/// let point_to_point = TunnelOptions::from_str("point-to-point");
/// assert!(point_to_point.is_ok());
/// assert_eq!(point_to_point.unwrap(), TunnelOptions::PointToPoint);
///
/// let ethernet = TunnelOptions::from_str("ethernet");
/// assert!(ethernet.is_ok());
/// assert_eq!(ethernet.unwrap(), TunnelOptions::Ethernet);
///
/// let no = TunnelOptions::from_str("no");
/// assert!(no.is_ok());
/// assert_eq!(no.unwrap(), TunnelOptions::No);
///
/// let invalid = TunnelOptions::from_str("invalid");
/// assert!(invalid.is_err());
/// match invalid.unwrap_err() {
///     ConfigError::InvalidValue { field, value } => {
///       assert_eq!(field, "TunnelOptions");
///       assert_eq!(value, "invalid");
///     }
///     _ => panic!("Expected ConfigError::InvalidValue"),
/// }
/// ```
impl TunnelOptions {
    pub fn from_str_with_field(s: &str, field: &'static str) -> Result<Self, ConfigError> {
        match s.to_lowercase().as_str() {
            "yes" => Ok(TunnelOptions::Yes),
            "point-to-point" => Ok(TunnelOptions::PointToPoint),
            "ethernet" => Ok(TunnelOptions::Ethernet),
            "no" => Ok(TunnelOptions::No),
            _ => Err(ConfigError::InvalidValue { field, value: s.to_string() }),
        }
    }
}
