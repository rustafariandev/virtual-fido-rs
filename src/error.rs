#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("{0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;
