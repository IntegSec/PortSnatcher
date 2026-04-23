//! Unified error type for ps-core. Downstream crates map any ps-core
//! failure through this single conversion point.

use crate::config::ConfigError;
use crate::port::PortSpecError;
use crate::scope::file::LoadError as ScopeLoadError;
use crate::scope::guard::ScopeViolation;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Scope(#[from] ScopeLoadError),
    #[error(transparent)]
    PortSpec(#[from] PortSpecError),
    #[error("scope violation: {0}")]
    ScopeViolation(ScopeViolation),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl From<ScopeViolation> for Error {
    fn from(v: ScopeViolation) -> Self {
        Self::ScopeViolation(v)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
