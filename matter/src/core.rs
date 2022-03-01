use crate::{
    data_model::{
        cluster_basic_information::BasicInfoConfig, core::DataModel,
        sdm::dev_att::DevAttDataFetcher,
    },
    error::*,
    fabric::FabricMgr,
    interaction_model::InteractionModel,
    secure_channel::core::SecureChannel,
    transport,
};
use std::sync::Arc;

/// The primary Matter Object
pub struct Matter {
    transport_mgr: transport::mgr::Mgr,
    data_model: DataModel,
    fabric_mgr: Arc<FabricMgr>,
}

impl Matter {
    /// Creates a new Matter object
    ///
    /// # Parameters
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    /// requires a set of device attestation certificates and keys. It is the responsibility of
    /// this object to return the device attestation details when queried upon.
    pub fn new(
        dev_det: BasicInfoConfig,
        dev_att: Box<dyn DevAttDataFetcher>,
    ) -> Result<Box<Matter>, Error> {
        let fabric_mgr = Arc::new(FabricMgr::new()?);
        let data_model = DataModel::new(dev_det, dev_att, fabric_mgr.clone())?;
        let mut matter = Box::new(Matter {
            transport_mgr: transport::mgr::Mgr::new()?,
            data_model,
            fabric_mgr,
        });
        let interaction_model =
            Box::new(InteractionModel::new(Box::new(matter.data_model.clone())));
        matter.transport_mgr.register_protocol(interaction_model)?;
        let secure_channel = Box::new(SecureChannel::new(matter.fabric_mgr.clone()));
        matter.transport_mgr.register_protocol(secure_channel)?;
        Ok(matter)
    }

    /// Returns an Arc to [DataModel]
    ///
    /// The Data Model is where you express what is the type of your device. Typically
    /// once you gets this reference, you acquire the write lock and add your device
    /// types, clusters, attributes, commands to the data model.
    pub fn get_data_model(&self) -> DataModel {
        self.data_model.clone()
    }

    /// Starts the Matter daemon
    ///
    /// This call does NOT return
    ///
    /// This call starts the Matter daemon that starts communication with other Matter
    /// devices on the network.
    pub fn start_daemon(&mut self) -> Result<(), Error> {
        self.transport_mgr.start()
    }
}
