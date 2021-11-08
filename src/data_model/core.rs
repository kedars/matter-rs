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
    fn handle_invoke_cmd(&self, cmd_path_ib: &CmdPathIb, variable: TLVElement, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        info!("In Data Model's Invoke Commmand Handler");
        println!("Found cmd_path_ib: {:?} and variable: {}", cmd_path_ib, variable);
        // This whole response is hard-coded here. Ideally, this should only write the status of it's own invoke
        // and the caller API should handle generation of the rest of the structure
        let dummy_invoke_resp = [0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x00, 0x24,
                                 0x02, 0x31, 0x24, 0x03, 0x02, 0x18, 0x36, 0x02, 0x04, 0x00, 0x04, 0x01, 0x04, 0x00, 0x18, 0x18,
                                 0x18, 0x18];
        resp_buf.copy_from_slice(&dummy_invoke_resp[..]).unwrap();
        Ok(())
    }
}
