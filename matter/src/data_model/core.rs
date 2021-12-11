use super::{device_types::device_type_add_root_node, objects::*};
use crate::{
    error::*,
    interaction_model::{CommandReq, HandleInteraction},
};
use log::info;
use std::sync::RwLock;

pub struct DataModel {
    pub node: RwLock<Box<Node>>,
}

impl DataModel {
    pub fn new() -> Result<Self, Error> {
        let dm = DataModel {
            node: RwLock::new(Node::new()?),
        };
        {
            let mut node = dm.node.write()?;
            device_type_add_root_node(&mut node)?;
        }
        Ok(dm)
    }
}

impl HandleInteraction for DataModel {
    fn handle_invoke_cmd(&self, cmd_req: &mut CommandReq) -> Result<(), Error> {
        info!(
            "Invoke Commmand Handler executing: {:?}",
            cmd_req.cmd_path_ib
        );

        {
            let mut node = self.node.write()?;
            // For now, let's not support wildcard
            node.get_endpoint(cmd_req.cmd_path_ib.endpoint.unwrap_or(1).into())?
                .get_cluster(cmd_req.cmd_path_ib.cluster.unwrap_or(1).into())?
                .handle_command(cmd_req)?;
        }

        Ok(())
    }
}
