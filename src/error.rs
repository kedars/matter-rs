use std::fmt;

#[derive(Debug)]
pub enum Error {
    Crypto(ccm::aead::Error),
    NoSpace,
    NoHandler,
    StdIoError,
    Invalid,
    InvalidAAD,
    InvalidData,
    InvalidOpcode,
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


impl<'a> fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}