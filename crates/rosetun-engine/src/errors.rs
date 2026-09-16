#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("engine binary {0} not found")]
    BinaryNotFound(String),
    #[error("engine does not support this configuration: {0}")]
    Unsupported(String),
    #[error("failed to render configuration: {0}")]
    Render(String),
    #[error("engine exited with code {code:?}")]
    Exited { code: Option<i32> },
    #[error("statistics are not available for this engine")]
    StatsUnavailable,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}