use crate::{
    data_model::{core::DataModel, sdm::dev_att::DevAttDataFetcher},
    error::*,
    fabric::FabricMgr,
    interaction_model::InteractionModel,
    secure_channel::core::SecureChannel,
    transport,
};
use std::sync::Arc;

pub struct Matter {
    transport_mgr: transport::mgr::Mgr,
    data_model: Arc<DataModel>,
    fabric_mgr: Arc<FabricMgr>,
}

impl Matter {
    pub fn new(dev_att: Box<dyn DevAttDataFetcher>) -> Result<Box<Matter>, Error> {
        let fabric_mgr = Arc::new(FabricMgr::new()?);
        let data_model = Arc::new(DataModel::new(dev_att, fabric_mgr.clone())?);
        let mut matter = Box::new(Matter {
            transport_mgr: transport::mgr::Mgr::new()?,
            data_model,
            fabric_mgr,
        });
        let interaction_model = Box::new(InteractionModel::new(matter.data_model.clone()));
        matter.transport_mgr.register_protocol(interaction_model)?;
        let secure_channel = Box::new(SecureChannel::new(matter.fabric_mgr.clone()));
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
