use crate::error::Error;

pub enum DataType {
    CertDeclaration,
    PAI,
    DAC,
}

pub trait DevAttDataFetcher {
    fn get_devatt_data(&self, data_type: DataType, data: &mut [u8]) -> Result<usize, Error>;
}
