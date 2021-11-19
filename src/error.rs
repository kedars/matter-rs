use std::{fmt, sync::PoisonError};

#[derive(Debug)]
pub enum Error {
    Crypto(ccm::aead::Error),
    OpenSSL(openssl::error::ErrorStack),
    NoEndpoint,
    NoHandler,
    NoSpace,
    NotFound,
    StdIoError,
    Invalid,
    InvalidAAD,
    InvalidData,
    InvalidKeyLength,
    InvalidOpcode,
    InvalidState,
    RwLock,
    TruncatedPacket,
}

impl From<std::io::Error> for Error {
    fn from(_e: std::io::Error) -> Self {
        // Keep things simple for now
        Self::StdIoError
    }
}

impl From<ccm::aead::Error> for Error {
    fn from(e: ccm::aead::Error) -> Self {
        Self::Crypto(e)
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_e: PoisonError<T>) -> Self {
        Self::RwLock
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(e)
    }
}

impl<'a> fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
