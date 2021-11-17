use crate::error::Error;

pub trait CryptoUtils {
    fn new() -> Result<Self, Error>
    where
        Self: Sized;
}
