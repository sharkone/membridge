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
    #[error("unresolved scan scope: {0}")]
    UnresolvedScope(String),
    #[error("scan scope requires unavailable source metadata: {0}")]
    ScopeMetadataUnavailable(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("could not determine the user home directory: {0}")]
    HomeDirectoryUnavailable(String),
    #[error("memory source invariant failed: {0}")]
    SourceInvariant(String),
    #[error("minidump source exceeds a processing limit: {0}")]
    SourceTooLarge(String),
    #[error("unsupported host: {0}")]
    UnsupportedHost(String),
    #[error("process {0} was not found")]
    ProcessNotFound(u32),
    #[error("process access denied: {0}")]
    ProcessAccessDenied(String),
    #[error("process query failed: {0}")]
    ProcessQueryFailed(String),
    #[error("capture failed: {0}")]
    CaptureFailed(String),
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
            Self::UnresolvedScope(_) => "UNRESOLVED_SCOPE",
            Self::ScopeMetadataUnavailable(_) => "SCOPE_METADATA_UNAVAILABLE",
            Self::InvalidArgument(_) => "INVALID_ARGUMENT",
            Self::HomeDirectoryUnavailable(_) => "HOME_DIRECTORY_UNAVAILABLE",
            Self::SourceInvariant(_) => "SOURCE_INVARIANT",
            Self::SourceTooLarge(_) => "SOURCE_TOO_LARGE",
            Self::UnsupportedHost(_) => "UNSUPPORTED_HOST",
            Self::ProcessNotFound(_) => "PROCESS_NOT_FOUND",
            Self::ProcessAccessDenied(_) => "PROCESS_ACCESS_DENIED",
            Self::ProcessQueryFailed(_) => "PROCESS_QUERY_FAILED",
            Self::CaptureFailed(_) => "CAPTURE_FAILED",
            Self::Json(_) => "INVALID_JSON",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
