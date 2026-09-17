#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("insufficient privileges: {0}")]
    NotPrivileged(String),
    #[error("missing system dependency: {0}")]
    MissingDependency(String),
    #[error("failed to bring up interface {name}: {reason}")]
    Tun { name: String, reason: String },
    #[error("failed to change routes: {0}")]
    Route(String),
    #[error("failed to configure dns: {0}")]
    Dns(String),
    #[error("could not resolve a VPN endpoint address")]
    EndpointUnresolved,
    #[error("Windows Filtering Platform error {code}: {context}")]
    Wfp { code: u32, context: &'static str },
    #[error("routing for this platform is not yet implemented")]
    Unsupported,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
