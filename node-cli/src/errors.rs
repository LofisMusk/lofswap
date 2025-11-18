use std::fmt;

#[derive(Debug)]
pub enum NodeError {
    NetworkError(String),
    SerializationError(String),
    ValidationError(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            NodeError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            NodeError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for NodeError {}
