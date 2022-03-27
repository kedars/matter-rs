use std::{array::TryFromSliceError, fmt, sync::PoisonError, time::SystemTimeError};

use log::error;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    AttributeNotFound,
    AttributeIsCustom,
    ClusterNotFound,
    CommandNotFound,
    EndpointNotFound,
    Crypto,
    TLSStack,
    MdnsError,
    Network,
    NoCommand,
    NoEndpoint,
    NoExchange,
    NoFabricId,
    NoHandler,
    NoNodeId,
    NoSession,
    NoSpace,
    NoSpaceAckTable,
    NoSpaceRetransTable,
    NoTagFound,
    NotFound,
    StdIoError,
    SysTimeFail,
    Invalid,
    InvalidAAD,
    InvalidData,
    InvalidKeyLength,
    InvalidOpcode,
    InvalidPeerAddr,
    // Invalid Auth Key in the Matter Certificate
    InvalidAuthKey,
    InvalidSignature,
    InvalidState,
    RwLock,
    TLVNotFound,
    TLVTypeMismatch,
    TruncatedPacket,
}

impl From<std::io::Error> for Error {
    fn from(_e: std::io::Error) -> Self {
        // Keep things simple for now
        Self::StdIoError
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_e: PoisonError<T>) -> Self {
        Self::RwLock
    }
}

#[cfg(feature = "crypto_openssl")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        error!("Error in TLS: {}", e);
        Self::TLSStack
    }
}

#[cfg(feature = "crypto_mbedtls")]
impl From<mbedtls::Error> for Error {
    fn from(e: mbedtls::Error) -> Self {
        error!("Error in TLS: {}", e);
        Self::TLSStack
    }
}

impl From<SystemTimeError> for Error {
    fn from(_e: SystemTimeError) -> Self {
        Self::SysTimeFail
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_e: TryFromSliceError) -> Self {
        Self::Invalid
    }
}

impl<'a> fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
