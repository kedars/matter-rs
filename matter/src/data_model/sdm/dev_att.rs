use crate::error::Error;

/// Device Attestation Data Type
pub enum DataType {
    /// Certificate Declaration
    CertDeclaration,
    /// Product Attestation Intermediary Certificate
    PAI,
    /// Device Attestation Certificate
    DAC,
    /// Device Attestation Certificate - Public Key
    DACPubKey,
    /// Device Attestation Certificate - Private Key
    DACPrivKey,
}

/// The Device Attestation Data Fetcher Trait
///
/// Objects that implement this trait allow the Matter subsystem to query the object
/// for the Device Attestation data that is programmed in the Matter device.
pub trait DevAttDataFetcher {
    /// Get Device Attestation Data
    ///
    /// This API is expected to return the particular Device Attestation data as is
    /// requested by the Matter subsystem.
    /// The type of data that can be queried is defined in the [DataType] enum.
    fn get_devatt_data(&self, data_type: DataType, data: &mut [u8]) -> Result<usize, Error>;
}
