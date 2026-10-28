#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("engine binary {0} not found")]
    BinaryNotFound(String),
    #[error("engine binary is unavailable: {0}")]
    BinaryUnavailable(String),
    #[error("engine does not support this configuration: {0}")]
    Unsupported(String),
    #[error("failed to render configuration: {0}")]
    Render(String),
    #[error("engine exited {}", exit_code_label(*code))]
    Exited { code: Option<i32> },
    #[error("statistics request failed: {0}")]
    Stats(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

fn exit_code_label(code: Option<i32>) -> String {
    match code {
        Some(code) => format!("with code {code}"),
        None => "without an exit code".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::EngineError;

    #[test]
    fn exited_displays_code_without_option_wrapper() {
        assert_eq!(
            EngineError::Exited { code: Some(1) }.to_string(),
            "engine exited with code 1"
        );
        assert_eq!(
            EngineError::Exited { code: None }.to_string(),
            "engine exited without an exit code"
        );
    }
}
