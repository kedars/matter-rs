pub mod data_model;
pub mod transport;
pub mod utils;

pub mod sbox {
    pub fn sbox_new<T> (var: T) -> Result<Box<T>, &'static str> {
        // Always success for now, since Box:new() always succeeds
        Ok(Box::new(var))
    }
}

