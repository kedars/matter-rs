use super::{device_types::device_type_add_root_node, objects::*, sdm::dev_att::DevAttDataFetcher};
use crate::{
    error::*,
    fabric::FabricMgr,
    interaction_model::{
        command::{self, CommandReq, InvokeRespIb},
        core::IMStatusCode,
        CmdPathIb, InteractionConsumer, Transaction,
    },
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};
use log::info;
use std::sync::{Arc, RwLock};

pub struct DataModel {
    pub node: RwLock<Box<Node>>,
}

impl DataModel {
    pub fn new(
        dev_att: Box<dyn DevAttDataFetcher>,
        fabric_mgr: Arc<FabricMgr>,
    ) -> Result<Self, Error> {
        let dm = DataModel {
            node: RwLock::new(Node::new()?),
        };
        {
            let mut node = dm.node.write()?;
            device_type_add_root_node(&mut node, dev_att, fabric_mgr)?;
        }
        Ok(dm)
    }

    fn handle_command(&self, mut cmd_req: CommandReq) -> Result<(), IMStatusCode> {
        let mut node = self.node.write().unwrap();
        node.get_endpoint(cmd_req.endpoint.into())
            .map_err(|_| IMStatusCode::UnsupportedEndpoint)?
            .get_cluster(cmd_req.cluster)
            .map_err(|_| IMStatusCode::UnsupportedCluster)?
            .handle_command(&mut cmd_req)
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

        let cmd_req = CommandReq {
            // TODO: Need to support wildcards
            endpoint: cmd_path_ib.endpoint.unwrap_or(1),
            cluster: cmd_path_ib.cluster.unwrap_or(0),
            command: cmd_path_ib.command,
            data,
            trans,
            resp: tlvwriter,
        };
        let cmd_path_ib = cmd_req.to_cmd_path_ib();

        let result = self.handle_command(cmd_req);
        if let Err(result) = result {
            // Err return implies we must send the StatusIB with this code
            let invoke_resp = InvokeRespIb::Status(cmd_path_ib, result, 0, command::dummy);
            tlvwriter.put_object(TagType::Anonymous, &invoke_resp)?;
        }
        Ok(())
    }
}
