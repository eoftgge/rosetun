//! Kernel contract: what Rosetun requires from sing-box, xray, and everything that comes after.
//!
//! The crate lives on the helper side—the kernel doesn't launch the application. So the tunnel
//! survives a GUI crash, and the privilege escalation remains at one point.
//!
//! Traits are synchronous. Monitoring a child process is blocking by its nature,
//! and the helper allocates a thread for it. If xray needs
//! gRPC statistics, the runtime is started within that backend and doesn't leak out.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use rosetun_config::{EngineKind, Node, RuleSet, Settings, Traffic};

pub trait EngineBackend: Send + Sync + std::fmt::Debug {
    fn kind(&self) -> EngineKind;
    fn locate_binary(&self) -> Result<PathBuf, EngineError>;
    fn render(&self, request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError>;

    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError>;
}

#[derive(Debug, Clone, Copy)]
pub struct RenderRequest<'a> {
    pub node: &'a Node,
    pub rules: &'a RuleSet,
    pub settings: &'a Settings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedConfig {
    pub file_name: String,
    pub body: Vec<u8>,
}

impl RenderedConfig {
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }
}

pub trait EngineProcess: Send + std::fmt::Debug {
    fn is_running(&mut self) -> Result<bool, EngineError>;
    fn traffic(&mut self) -> Result<Traffic, EngineError>;
    fn stop(&mut self) -> Result<(), EngineError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("исполняемый файл ядра {0} не найден")]
    BinaryNotFound(String),
    #[error("ядро не поддерживает такую конфигурацию: {0}")]
    Unsupported(String),
    #[error("не удалось собрать конфигурацию: {0}")]
    Render(String),
    #[error("ядро завершилось с кодом {code:?}")]
    Exited { code: Option<i32> },
    #[error("статистика недоступна для этого ядра")]
    StatsUnavailable,
    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Default)]
pub struct EngineRegistry {
    backends: Vec<Box<dyn EngineBackend>>,
}

impl EngineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, backend: Box<dyn EngineBackend>) -> &mut Self {
        self.backends.push(backend);
        self
    }

    pub fn get(&self, kind: EngineKind) -> Option<&dyn EngineBackend> {
        self.backends
            .iter()
            .find(|backend| backend.kind() == kind)
            .map(|backend| backend.as_ref())
    }

    pub fn kinds(&self) -> impl Iterator<Item = EngineKind> + '_ {
        self.backends.iter().map(|backend| backend.kind())
    }
}