use crate::error::ConfigError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const VALID_LOG_LEVELS: [&'static str; 9] =
    ["QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevels {
    Quiet,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug,
    Debug1,
    Debug2,
    Debug3,
}

impl FromStr for LogLevels {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "QUIET" => Ok(LogLevels::Quiet),
            "FATAL" => Ok(LogLevels::Fatal),
            "ERROR" => Ok(LogLevels::Error),
            "INFO" => Ok(LogLevels::Info),
            "VERBOSE" => Ok(LogLevels::Verbose),
            "DEBUG" => Ok(LogLevels::Debug),
            "DEBUG1" => Ok(LogLevels::Debug1),
            "DEBUG2" => Ok(LogLevels::Debug2),
            "DEBUG3" => Ok(LogLevels::Debug3),
            _ => Err(ConfigError::InvalidValue { field: "log_level", value: s.to_string() }),
        }
    }
}

impl LogLevels {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevels::Quiet => "QUIET",
            LogLevels::Fatal => "FATAL",
            LogLevels::Error => "ERROR",
            LogLevels::Info => "INFO",
            LogLevels::Verbose => "VERBOSE",
            LogLevels::Debug => "DEBUG",
            LogLevels::Debug1 => "DEBUG1",
            LogLevels::Debug2 => "DEBUG2",
            LogLevels::Debug3 => "DEBUG3",
        }
    }
}
