//! Crate-wide error type.

/// All failures the GNN engine can report.
#[derive(Debug)]
pub enum GnnError {
    InvalidGraph(String),
    InvalidConfig(String),
    InvalidWeights(String),
    Format(String),
    Dataset(String),
    Training(String),
    Io(std::io::Error),
    Json(String),
}

impl std::fmt::Display for GnnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGraph(msg) => write!(f, "invalid graph: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid model config: {msg}"),
            Self::InvalidWeights(msg) => write!(f, "invalid weights: {msg}"),
            Self::Format(msg) => write!(f, "weight file format: {msg}"),
            Self::Dataset(msg) => write!(f, "dataset: {msg}"),
            Self::Training(msg) => write!(f, "training: {msg}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Json(msg) => write!(f, "json: {msg}"),
        }
    }
}

impl std::error::Error for GnnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for GnnError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<omnisec_json::JsonError> for GnnError {
    fn from(err: omnisec_json::JsonError) -> Self {
        Self::Json(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, GnnError>;
