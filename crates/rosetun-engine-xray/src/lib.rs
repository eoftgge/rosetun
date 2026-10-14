#![forbid(unsafe_code)]

mod output;
mod render;
mod version;

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_engine::{EngineProcess, OutboundFailures, RenderedConfig, errors::EngineError};

pub use render::{render, render_probe};
pub use version::SUPPORTED_XRAY_VERSION;

const BINARY: &str = if cfg!(windows) { "xray.exe" } else { "xray" };

#[derive(Clone, PartialEq, Eq)]
pub struct SocksEndpoint {
    address: SocketAddr,
    username: String,
    password: String,
}

impl SocksEndpoint {
    pub fn local() -> std::io::Result<Self> {
        // As with ControlEndpoint::local, another process may take the port before spawn.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        let mut bytes = [0u8; 64];
        getrandom::fill(&mut bytes).map_err(|error| std::io::Error::other(error.to_string()))?;
        let hex = b"0123456789abcdef";
        let encode = |bytes: &[u8]| {
            let mut value = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                value.push(char::from(hex[usize::from(byte >> 4)]));
                value.push(char::from(hex[usize::from(byte & 0x0f)]));
            }
            value
        };
        Ok(Self {
            address,
            username: encode(&bytes[..32]),
            password: encode(&bytes[32..]),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for SocksEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksEndpoint")
            .field("address", &self.address)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct XrayHelper {
    work_dir: PathBuf,
    binary: Option<PathBuf>,
}

impl XrayHelper {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
            binary: None,
        }
    }

    pub fn with_binary(work_dir: impl Into<PathBuf>, binary: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
            binary: Some(binary.into()),
        }
    }

    pub fn probe_config_path(&self) -> PathBuf {
        self.work_dir.join("probe.json")
    }

    pub fn binary_path(&self) -> Result<PathBuf, EngineError> {
        if let Some(path) = &self.binary {
            return Ok(path.clone());
        }
        let executable = std::env::current_exe()?;
        Ok(executable
            .parent()
            .ok_or_else(|| EngineError::BinaryNotFound(BINARY.into()))?
            .join(BINARY))
    }

    pub fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        let path = self.binary_path()?;
        if !path.is_file() {
            return Err(EngineError::BinaryNotFound(BINARY.into()));
        }
        let binary = std::fs::canonicalize(path)?;
        version::check(&binary)?;
        Ok(binary)
    }

    pub fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
        endpoints: &[&SocksEndpoint],
        verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        std::fs::create_dir_all(&self.work_dir)?;
        let config_path = self.work_dir.join(&config.file_name);
        std::fs::write(&config_path, &config.body)?;
        let mut child = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .current_dir(&self.work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (ready_sender, ready_receiver) = mpsc::channel();
        let failures = Arc::new(output::FailureCounters::default());
        let secrets = endpoints
            .iter()
            .flat_map(|endpoint| [endpoint.username.clone(), endpoint.password.clone()])
            .collect::<Vec<_>>();
        let probe = config.file_name == "probe.json";
        for (stream, pipe) in [
            (
                "stdout",
                child
                    .stdout
                    .take()
                    .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
            ),
            (
                "stderr",
                child
                    .stderr
                    .take()
                    .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
            ),
        ] {
            let Some(pipe) = pipe else {
                stop_failed_spawn(&mut child);
                return Err(std::io::Error::other("Xray output pipe is unavailable").into());
            };
            if let Err(error) = spawn_output_drain(
                pipe,
                stream,
                ready_sender.clone(),
                Arc::clone(&failures),
                secrets.clone(),
                Arc::clone(&verbose_until_unix),
                probe,
            ) {
                stop_failed_spawn(&mut child);
                return Err(error.into());
            }
        }
        drop(ready_sender);
        Ok(Box::new(XrayProcess {
            child,
            ready_receiver,
            ready: false,
            failures,
        }))
    }
}

fn stop_failed_spawn(child: &mut Child) {
    if let Err(error) = child.kill() {
        tracing::error!(%error, "failed to kill Xray after startup setup failed");
    }
    if let Err(error) = child.wait() {
        tracing::error!(%error, "failed to reap Xray after startup setup failed");
    }
}

fn spawn_output_drain(
    reader: impl Read + Send + 'static,
    stream: &'static str,
    ready_sender: Sender<()>,
    failures: Arc<output::FailureCounters>,
    secrets: Vec<String>,
    verbose_until_unix: Arc<AtomicU64>,
    probe: bool,
) -> std::io::Result<()> {
    thread::Builder::new()
        .name(format!("xray-{stream}"))
        .spawn(move || {
            for line in BufReader::new(reader).lines() {
                match line {
                    Ok(line) => {
                        failures.observe(&line);
                        if output::line_level(&line) == output::LineLevel::Warn
                            && line.contains(&format!("Xray {SUPPORTED_XRAY_VERSION} started"))
                        {
                            let _ = ready_sender.send(());
                        }
                        if !probe {
                            log_output_line(stream, &line, &secrets, &verbose_until_unix);
                        }
                    }
                    Err(error) => {
                        tracing::debug!(stream, %error, "Xray output stream closed with a read error");
                        break;
                    }
                }
            }
            tracing::debug!(stream, "Xray output stream closed");
        })
        .map(|_| ())
}

fn log_output_line(stream: &'static str, line: &str, secrets: &[String], until_unix: &AtomicU64) {
    use rosetun_engine::ENGINE_OUTPUT_TARGET as TARGET;
    let verbose = now_unix() < until_unix.load(Ordering::Acquire);
    let mut safe = if verbose {
        line.to_owned()
    } else {
        output::hide_destinations(line)
    };
    for secret in secrets {
        safe = safe.replace(secret, "[redacted]");
    }
    match output::line_level(&safe) {
        output::LineLevel::Debug => tracing::debug!(target: TARGET, stream, "{safe}"),
        output::LineLevel::Info => tracing::info!(target: TARGET, stream, "{safe}"),
        output::LineLevel::Warn => tracing::warn!(target: TARGET, stream, "{safe}"),
        output::LineLevel::Error => tracing::error!(target: TARGET, stream, "{safe}"),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

#[derive(Debug)]
struct XrayProcess {
    child: Child,
    ready_receiver: Receiver<()>,
    ready: bool,
    failures: Arc<output::FailureCounters>,
}

impl EngineProcess for XrayProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        match self.child.try_wait()? {
            Some(status) => Err(EngineError::Exited {
                code: status.code(),
            }),
            None => Ok(true),
        }
    }

    fn is_ready(&mut self) -> Result<bool, EngineError> {
        if self.ready {
            return Ok(true);
        }
        match self.ready_receiver.try_recv() {
            Ok(()) => {
                self.ready = true;
                Ok(true)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Xray output closed before startup readiness",
            )
            .into()),
        }
    }

    fn outbound_failures(&self) -> OutboundFailures {
        self.failures.snapshot()
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        match self.child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
            Err(error) => {
                if self.child.try_wait()?.is_none() {
                    return Err(error.into());
                }
                return Ok(());
            }
        }
        self.child.wait()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_endpoint_uses_random_credentials_and_redacts_debug() {
        let first = SocksEndpoint::local().unwrap();
        let second = SocksEndpoint::local().unwrap();
        assert!(first.address().ip().is_loopback());
        assert_ne!(first.username(), second.username());
        assert_ne!(first.password(), second.password());
        assert_eq!(first.username().len(), 64);
        assert_eq!(first.password().len(), 64);
        let debug = format!("{first:?}");
        assert!(!debug.contains(first.username()));
        assert!(!debug.contains(first.password()));
    }
}
