use std::{fmt, sync::PoisonError};

#[derive(Debug, PartialEq)]
pub enum Error {
    AttributeNotFound,
    ClusterNotFound,
    CommandNotFound,
    EndpointNotFound,
    Crypto,
    OpenSSL,
    NoCommand,
    NoEndpoint,
    NoExchange,
    NoHandler,
    NoSession,
    NoSpace,
    NoSpaceAckTable,
    NoSpaceRetransTable,
    NoTagFound,
    NotFound,
    StdIoError,
    Invalid,
    InvalidAAD,
    InvalidData,
    InvalidKeyLength,
    InvalidOpcode,
    InvalidPeerAddr,
    InvalidState,
    RwLock,
    TLVTypeMismatch,
    TruncatedPacket,
}

impl From<std::io::Error> for Error {
    fn from(_e: std::io::Error) -> Self {
        // Keep things simple for now
        Self::StdIoError
    }
}

impl From<ccm::aead::Error> for Error {
    fn from(_e: ccm::aead::Error) -> Self {
        Self::Crypto
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_e: PoisonError<T>) -> Self {
        Self::RwLock
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(_e: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL
    }
}

impl<'a> fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
