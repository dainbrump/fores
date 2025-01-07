pub mod constants;
pub mod error;
pub mod structs;

pub use error::ConfigError;
pub use structs::sshconfig::*;

// @TODO: Implement the actual parsing logic
pub fn parse_config(config_string: &str) -> Result<String, ConfigError> {
  if config_string.is_empty() {
    Err(ConfigError::Parse("Empty configuration".to_string()))
  } else {
    Ok("Successfully parsed (not really)".to_string())
  }
}

// @TODO: Build out legitimate tests. These are just placeholders for now.
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_empty_config() {
    let result = parse_config("");
    assert!(result.is_err());
    match result {
      Err(ConfigError::Parse(msg)) => assert_eq!(msg, "Empty configuration"),
      _ => panic!("Expected Parse error"),
    }
  }

  #[test]
  fn test_parse_non_empty_config() {
    let result = parse_config("Some config here");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Successfully parsed (not really)");
  }
}
