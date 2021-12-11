use super::{device_types::device_type_add_root_node, objects::*};
use crate::{error::*, im_demux::*, tlv::*, utils::writebuf::WriteBuf};
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

pub struct CommandReq<'a, 'b> {
    pub cmd_id: u16,
    pub variable: TLVElement<'a>,
    pub resp_buf: &'a mut WriteBuf<'b>,
    pub trans: &'a mut Transaction,
}

impl HandleInteraction for DataModel {
    fn handle_invoke_cmd(
        &self,
        trans: &mut Transaction,
        cmd_path_ib: &CmdPathIb,
        variable: TLVElement,
        resp_buf: &mut WriteBuf,
    ) -> Result<(), Error> {
        info!("Invoke Commmand Handler executing: {:?}", cmd_path_ib);
        let mut cmd_req = CommandReq {
            trans,
            variable,
            resp_buf,
            cmd_id: cmd_path_ib.command.into(),
        };
        {
            let mut node = self.node.write()?;
            // For now, let's not support wildcard
            node.get_endpoint(cmd_path_ib.endpoint.unwrap_or(1).into())?
                .get_cluster(cmd_path_ib.cluster.unwrap_or(1).into())?
                .handle_command(&mut cmd_req)?;
        }

        Ok(())
    }
}
