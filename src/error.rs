use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    AuthFailed,
    BadFrame,
    RateLimited,
    UnsupportedVersion,
    Internal,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),

    #[error("noise: {0}")]
    Noise(#[from] snow::Error),

    #[error("argon2: {0}")]
    Argon2(argon2::Error),

    #[error("kdf failure")]
    Kdf,

    #[error("aead failure")]
    Aead,

    #[error("os rng unavailable")]
    Random,

    #[error("connection closed")]
    Closed,

    #[error("unsupported server version {0}")]
    UnsupportedVersion(u16),

    #[error("protocol violation: {0}")]
    Protocol(&'static str),

    #[error("server reported error: {0:?}")]
    Server(ErrorKind),
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Argon2(e)
    }
}

impl From<chacha20poly1305::Error> for Error {
    fn from(_: chacha20poly1305::Error) -> Self {
        Error::Aead
    }
}

pub type Result<T> = std::result::Result<T, Error>;
