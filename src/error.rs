use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid value for {field}: {value}")]
    InvalidValue { field: &'static str, value: String },

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Failed to parse value for {field} as integer: {value}")]
    ParseInteger { field: &'static str, value: String },

    #[error("Value for {field} out of range ({min}-{max}): {value}")]
    OutOfRangeU8 { field: &'static str, value: String, min: u8, max: u8 },

    #[error("Value for {field} out of range ({min}-{max}): {value}")]
    OutOfRangeU16 { field: &'static str, value: String, min: u16, max: u16 },

    #[error("Value for {field} out of range ({min}-{max}): {value}")]
    OutOfRangeU32 { field: &'static str, value: String, min: u32, max: u32 },
}
