#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use rosetun_config::EngineKind;
use rosetun_core_engine::{
    EngineBackend, EngineError, EngineProcess, RenderRequest, RenderedConfig,
};

#[derive(Debug, Clone)]
pub struct XrayBackend {
    work_dir: PathBuf,
}

impl XrayBackend {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
        }
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }
}

impl EngineBackend for XrayBackend {
    fn kind(&self) -> EngineKind {
        EngineKind::Xray
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Err(EngineError::Unsupported("the xray backend is not yet implemented".into()))
    }

    fn render(&self, _request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Err(EngineError::Unsupported("the xray backend is not yet implemented".into()))
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        Err(EngineError::Unsupported("the xray backend is not yet implemented".into()))
    }
}