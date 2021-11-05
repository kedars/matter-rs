use crate::{
    error::*,
    im_demux::*,
    sc_demux::SecureChannel,
    tlv::*,
    transport,
    utils::writebuf::WriteBuf
};
use log::{info};

pub struct Matter {
    transport_mgr: transport::mgr::Mgr,
}

impl Matter {
    pub fn new() -> Result<Matter, Error>  {
        let data_model = Box::new(MyDataModel::new());
        let interaction_model = Box::new(InteractionModel::new(data_model));
        let secure_channel = Box::new(SecureChannel::new());
        let mut matter = Matter{
            transport_mgr: transport::mgr::Mgr::new()?,
        };
        matter.transport_mgr.register_protocol(interaction_model)?;
        matter.transport_mgr.register_protocol(secure_channel)?;
        Ok(matter)
    }

    pub fn start_daemon(&mut self) -> Result<(), Error> {
        self.transport_mgr.start()
    }
}

// Temporary fake data model
struct MyDataModel {
    _a: u32,
}

impl MyDataModel {
    const fn new() -> MyDataModel {
        MyDataModel{_a: 12}
    }
}

impl HandleInteraction for MyDataModel {
    fn handle_invoke_cmd(&mut self, cmd_path_ib: &CmdPathIb, variable: TLVElement, resp_buf: &mut WriteBuf) -> Result<(), Error> {
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
