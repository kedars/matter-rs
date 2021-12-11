use crate::{
    data_model::core::DataModel, error::*, interaction_model::InteractionModel,
    sc_demux::SecureChannel, transport,
};
use std::sync::Arc;

pub struct Matter {
    transport_mgr: transport::mgr::Mgr,
    data_model: Arc<DataModel>,
}

impl Matter {
    pub fn new() -> Result<Matter, Error> {
        let data_model = Arc::new(DataModel::new()?);
        let interaction_model = Box::new(InteractionModel::new(data_model.clone()));
        let secure_channel = Box::new(SecureChannel::new());
        let mut matter = Matter {
            transport_mgr: transport::mgr::Mgr::new()?,
            data_model,
        };
        matter.transport_mgr.register_protocol(interaction_model)?;
        matter.transport_mgr.register_protocol(secure_channel)?;
        Ok(matter)
    }

    pub fn get_data_model(&self) -> Arc<DataModel> {
        self.data_model.clone()
    }

    pub fn start_daemon(&mut self) -> Result<(), Error> {
        self.transport_mgr.start()
    }
}
