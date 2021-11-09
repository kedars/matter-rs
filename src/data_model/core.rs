use std::sync::RwLock;
use crate::{
    error::*,
    im_demux::*,
    tlv::*,
    utils::writebuf::WriteBuf,
};
use log::info;
use super::{device_types::device_type_add_root_node, objects::*};

pub struct DataModel {
    pub node: RwLock<Box<Node>>,
}

impl DataModel {
    pub fn new() -> Result<Self, Error> {
        let dm = DataModel{
            node: RwLock::new(Node::new()?)
        };
        {
            let mut node = dm.node.write()?;
            device_type_add_root_node(&mut node)?;
        }
        Ok(dm)
    }
}

impl HandleInteraction for DataModel {
    fn handle_invoke_cmd(&self, cmd_path_ib: &CmdPathIb, _variable: TLVElement, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        info!("Invoke Commmand Handler executing: {:?}", cmd_path_ib);
        {
            let mut node = self.node.write()?;
            // For now, let's not support wildcard
            node.get_endpoint(cmd_path_ib.endpoint.unwrap_or(1).into())?
                 .get_cluster(cmd_path_ib.cluster.unwrap_or(1).into())?
                 .handle_command(cmd_path_ib.command.unwrap_or(1).into())?;
        }
        // This whole response is hard-coded here. Ideally, this should only write the status of it's own invoke
        // and the caller API should handle generation of the rest of the structure
        let dummy_invoke_resp = [0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x00, 0x24,
                                 0x02, 0x31, 0x24, 0x03, 0x02, 0x18, 0x36, 0x02, 0x04, 0x00, 0x04, 0x01, 0x04, 0x00, 0x18, 0x18,
                                 0x18, 0x18];
        resp_buf.copy_from_slice(&dummy_invoke_resp[..]).unwrap();
        Ok(())
    }
}
