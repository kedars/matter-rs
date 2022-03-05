use matter::{
    data_model::objects::{Cluster, ClusterType},
    error::Error,
    interaction_model::{command::CommandReq, core::IMStatusCode, messages::ib},
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

pub const CLUSTER_ECHO_ID: u32 = 0xABCD;

pub const CMD_ECHO_REQUEST_ID: u16 = 0x00;
pub const CMD_ECHO_RESPONSE_ID: u16 = 0x01;

pub struct EchoCluster {
    base: Cluster,
    multiplier: u8,
}

impl ClusterType for EchoCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_attribute(&self, tag: TagType, tw: &mut TLVWriter, attr_id: u16) -> Result<(), Error> {
        self.base.read_attribute(tag, tw, attr_id)
    }

    fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode> {
        self.base.write_attribute(data, attr_id)
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req.cmd.path.leaf.map(|a| a as u16);
        match cmd {
            // This will generate an echo response on the same endpoint
            // with data multiplied by the multiplier
            Some(CMD_ECHO_REQUEST_ID) => {
                let a = cmd_req.data.get_u8().unwrap();
                let mut echo_response = cmd_req.cmd;
                echo_response.path.leaf = Some(CMD_ECHO_RESPONSE_ID as u32);
                let invoke_resp = ib::InvResponseOut::Cmd(echo_response, |t| {
                    // Echo = input * self.multiplier
                    t.put_u8(TagType::Context(0), a * self.multiplier)
                });
                let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
                cmd_req.trans.complete();
            }
            _ => {}
        }
        Ok(())
    }
}

impl EchoCluster {
    pub fn new(multiplier: u8) -> Result<Box<Self>, Error> {
        Ok(Box::new(Self {
            base: Cluster::new(CLUSTER_ECHO_ID)?,
            multiplier,
        }))
    }
}
