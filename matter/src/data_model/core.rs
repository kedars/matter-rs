use super::{device_types::device_type_add_root_node, objects::*, sdm::dev_att::DevAttDataFetcher};
use crate::{
    error::*,
    fabric::FabricMgr,
    interaction_model::{
        command::{self, CommandReq, InvokeRespIb},
        core::IMStatusCode,
        read::attr_path,
        CmdPathIb, InteractionConsumer, Transaction,
    },
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};
use log::{error, info};
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
    fn consume_read_attr(
        &self,
        attr_list: TLVElement,
        fab_scoped: bool,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        if fab_scoped {
            error!("Fabric scoped attribute read not yet supported");
        }
        let attr_list = attr_list
            .confirm_array()?
            .iter()
            .ok_or(Error::InvalidData)?;

        let node = self.node.read().unwrap();
        for attr_path_ib in attr_list {
            let attr_path = attr_path::Ib::from_tlv(&attr_path_ib)?;
            let result = node.for_attribute_path(&attr_path.path, |path, e, c, a| {
                let attr_path = attr_path::Ib::new(path);
                // For now, putting everything in here
                let _ = tw.put_start_struct(TagType::Anonymous);
                let _ = tw.put_start_struct(TagType::Context(1));
                let _ = tw.put_object(TagType::Context(1), &attr_path);
                // We will have to also support custom data types for encoding
                let _ = tw.put_object(TagType::Context(2), &a.value);
                let _ = tw.put_end_container();
                let _ = tw.put_end_container();
                Ok(())
            });
            if let Err(e) = result {
                // In this case, we'll have to add the AttributeStatusIb
                let _ = tw.put_start_struct(TagType::Anonymous);
                let _ = tw.put_start_struct(TagType::Context(0));
                // Attribute Status IB
                let _ = tw.put_object(TagType::Context(0), &attr_path);
                // Status IB
                let _ = tw.put_start_struct(TagType::Context(1));
                let _ = tw.put_u16(TagType::Context(0), e as u16);
                let _ = tw.put_u16(TagType::Context(1), 0);
                let _ = tw.put_end_container();
                let _ = tw.put_end_container();
                let _ = tw.put_end_container();
            }
        }
        Ok(())
    }

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
            let invoke_resp = InvokeRespIb::CommandStatus(cmd_path_ib, result, 0, command::dummy);
            tlvwriter.put_object(TagType::Anonymous, &invoke_resp)?;
        }
        Ok(())
    }
}
