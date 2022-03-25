use matter::{
    data_model::objects::{Access, AttrValue, Attribute, Cluster, ClusterType, Quality},
    error::Error,
    interaction_model::{command::CommandReq, core::IMStatusCode, messages::ib},
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};
use num_derive::FromPrimitive;

pub const ID: u32 = 0xABCD;

#[derive(FromPrimitive)]
pub enum Commands {
    EchoReq = 0x00,
    EchoResp = 0x01,
}

pub struct EchoCluster {
    base: Cluster,
    multiplier: u8,
}

#[derive(FromPrimitive)]
pub enum Attributes {
    Att1 = 0,
    Att2 = 1,
    AttWrite = 2,
    AttCustom = 3,
}

pub const ATTR_CUSTOM_VALUE: u32 = 0xcafebeef;
pub const ATTR_WRITE_DEFAULT_VALUE: u16 = 0xcafe;

impl ClusterType for EchoCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }

    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_custom_attribute(
        &self,
        tag: TagType,
        tw: &mut TLVWriter,
        attr_id: u16,
    ) -> Result<(), IMStatusCode> {
        match num::FromPrimitive::from_u16(attr_id).ok_or(IMStatusCode::UnsupportedAttribute)? {
            Attributes::AttCustom => {
                let _ = tw.u32(tag, ATTR_CUSTOM_VALUE);
                Ok(())
            }
            _ => Err(IMStatusCode::UnsupportedAttribute),
        }
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req
            .cmd
            .path
            .leaf
            .map(|c| num::FromPrimitive::from_u32(c))
            .ok_or(IMStatusCode::UnsupportedCommand)?
            .ok_or(IMStatusCode::UnsupportedCommand)?;
        match cmd {
            // This will generate an echo response on the same endpoint
            // with data multiplied by the multiplier
            Commands::EchoReq => {
                let a = cmd_req.data.u8().unwrap();
                let mut echo_response = cmd_req.cmd;
                echo_response.path.leaf = Some(Commands::EchoResp as u32);

                let cmd_data = |t: &mut TLVWriter| {
                    // Echo = input * self.multiplier
                    t.u8(TagType::Context(0), a * self.multiplier)
                };

                let invoke_resp = ib::InvResp::Cmd(ib::CmdData::new(echo_response, &cmd_data));
                let _ = cmd_req.resp.object(TagType::Anonymous, &invoke_resp);
                cmd_req.trans.complete();
            }
            _ => {
                return Err(IMStatusCode::UnsupportedCommand);
            }
        }
        Ok(())
    }
}

impl EchoCluster {
    pub fn new(multiplier: u8) -> Result<Box<Self>, Error> {
        let mut c = Box::new(Self {
            base: Cluster::new(ID)?,
            multiplier,
        });
        c.base.add_attribute(Attribute::new(
            Attributes::Att1 as u16,
            AttrValue::Uint16(0x1234),
            Access::RV,
            Quality::NONE,
        )?)?;
        c.base.add_attribute(Attribute::new(
            Attributes::Att2 as u16,
            AttrValue::Uint16(0x5678),
            Access::RV,
            Quality::NONE,
        )?)?;
        c.base.add_attribute(Attribute::new(
            Attributes::AttWrite as u16,
            AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
            Access::WRITE | Access::NEED_OPERATE,
            Quality::NONE,
        )?)?;
        c.base.add_attribute(Attribute::new(
            Attributes::AttCustom as u16,
            AttrValue::Custom,
            Access::READ | Access::NEED_VIEW,
            Quality::NONE,
        )?)?;
        Ok(c)
    }
}
