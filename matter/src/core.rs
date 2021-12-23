use crate::{
    data_model::{core::DataModel, sdm::dev_att::DevAttDataFetcher},
    error::*,
    interaction_model::InteractionModel,
    secure_channel::core::SecureChannel,
    transport,
};
use std::sync::Arc;

pub struct Matter {
    transport_mgr: transport::mgr::Mgr,
    data_model: Arc<DataModel>,
}

impl Matter {
    pub fn new(dev_att: Box<dyn DevAttDataFetcher>) -> Result<Matter, Error> {
        let data_model = Arc::new(DataModel::new(dev_att)?);
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
