use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid minidump: {0}")]
    Minidump(#[from] minidump::Error),
    #[error("unsupported target: {0}")]
    UnsupportedTarget(String),
    #[error("the minidump contains no process memory")]
    MissingMemory,
    #[error("invalid scan specification: {0}")]
    InvalidSpec(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("memory source invariant failed: {0}")]
    SourceInvariant(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "IO_ERROR",
            Self::Minidump(_) => "INVALID_MINIDUMP",
            Self::UnsupportedTarget(_) => "UNSUPPORTED_TARGET",
            Self::MissingMemory => "MISSING_MEMORY",
            Self::InvalidSpec(_) => "INVALID_SCAN_SPEC",
            Self::InvalidArgument(_) => "INVALID_ARGUMENT",
            Self::SourceInvariant(_) => "SOURCE_INVARIANT",
            Self::Json(_) => "INVALID_JSON",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
