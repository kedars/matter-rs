use super::{device_types::device_type_add_root_node, objects::*, sdm::dev_att::DevAttDataFetcher};
use crate::{
    error::*,
    interaction_model::{command::CommandReq, CmdPathIb, InteractionConsumer, Transaction},
    tlv::TLVElement,
    tlv_writer::TLVWriter,
};
use log::info;
use std::sync::RwLock;

pub struct DataModel {
    pub node: RwLock<Box<Node>>,
}

impl DataModel {
    pub fn new(dev_att: Box<dyn DevAttDataFetcher>) -> Result<Self, Error> {
        let dm = DataModel {
            node: RwLock::new(Node::new()?),
        };
        {
            let mut node = dm.node.write()?;
            device_type_add_root_node(&mut node, dev_att)?;
        }
        Ok(dm)
    }
}

impl InteractionConsumer for DataModel {
    fn consume_invoke_cmd(
        &self,
        cmd_path_ib: &CmdPathIb,
        data: TLVElement,
        trans: &mut Transaction,
        tlvwriter: &mut TLVWriter,
    ) -> Result<(), Error> {
        info!("Invoke Commmand Handler executing: {:?}", cmd_path_ib);

        let mut cmd_req = CommandReq {
            // TODO: Need to support wildcards
            endpoint: cmd_path_ib.endpoint.unwrap_or(1),
            cluster: cmd_path_ib.cluster.unwrap_or(0),
            command: cmd_path_ib.command,
            data,
            trans,
            resp: tlvwriter,
        };

        {
            let mut node = self.node.write()?;
            node.get_endpoint(cmd_req.endpoint.into())?
                .get_cluster(cmd_req.cluster.into())?
                .handle_command(&mut cmd_req)?;
        }

        Ok(())
    }
}
