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
}
