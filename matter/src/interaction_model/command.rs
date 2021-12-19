use super::core::OpCode;
use super::CmdPathIb;
use super::InteractionModel;
use super::Transaction;
use crate::error::*;
use crate::proto_demux::ResponseRequired;
use crate::proto_demux::{ProtoRx, ProtoTx};
use crate::tlv;
use crate::tlv::*;
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use crate::tlv_writer::ToTLV;
use log::error;
use log::info;

#[derive(Debug, Clone, Copy)]
pub enum InvokeRespIb<F>
where
    F: Fn(&mut TLVWriter) -> Result<(), Error>,
{
    Command(CmdPathIb, F),
    Status(CmdPathIb, u32, u32, F),
}

#[allow(non_snake_case)]
pub fn dummy(_t: &mut TLVWriter) -> Result<(), Error> {
    Ok(())
}

impl<F: Fn(&mut TLVWriter) -> Result<(), Error>> ToTLV for InvokeRespIb<F> {
    fn to_tlv(self: &InvokeRespIb<F>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.put_start_struct(tag_type)?;
        match self {
            InvokeRespIb::Command(cmd_path, data_cb) => {
                tw.put_start_struct(TagType::Context(0))?;
                tw.put_object(TagType::Context(0), cmd_path)?;
                tw.put_start_struct(TagType::Context(1))?;
                data_cb(tw)?;
                tw.put_end_container()?;
            }
            InvokeRespIb::Status(cmd_path, status, cluster_status, _) => {
                tw.put_start_struct(TagType::Context(1))?;
                tw.put_object(TagType::Context(0), cmd_path)?;
                put_status_ib(tw, TagType::Context(1), *status, *cluster_status)?;
            }
        }
        tw.put_end_container()?;
        tw.put_end_container()
    }
}

pub struct CommandReq<'a, 'b, 'c> {
    pub endpoint: u16,
    pub cluster: u32,
    pub command: u16,
    pub data: TLVElement<'a>,
    pub resp: &'a mut TLVWriter<'b, 'c>,
    pub trans: &'a mut Transaction,
}

impl<'a, 'b, 'c> CommandReq<'a, 'b, 'c> {
    pub fn to_cmd_path_ib(&self) -> CmdPathIb {
        CmdPathIb {
            endpoint: Some(self.endpoint),
            cluster: Some(self.cluster),
            command: self.command,
        }
    }
}

impl CmdPathIb {
    fn from_tlv(cmd_path: &TLVElement) -> Result<Self, Error> {
        Ok(Self {
            endpoint: cmd_path
                .find_tag(0)
                .and_then(|x| x.get_u8())
                .ok()
                .map(|e| e as u16),
            cluster: cmd_path
                .find_tag(1)
                .and_then(|x| x.get_u8())
                .ok()
                .map(|c| c as u32),
            command: cmd_path.find_tag(2)?.get_u8()? as u16,
        })
    }
}

impl ToTLV for CmdPathIb {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.put_start_list(tag_type)?;
        if let Some(endpoint) = self.endpoint {
            tw.put_u16(TagType::Context(0), endpoint)?;
        }
        if let Some(cluster) = self.cluster {
            tw.put_u32(TagType::Context(1), cluster)?;
        }
        tw.put_u16(TagType::Context(2), self.command)?;

        tw.put_end_container()
    }
}

fn put_status_ib(
    tw: &mut TLVWriter,
    tag_type: TagType,
    status: u32,
    cluster_status: u32,
) -> Result<(), Error> {
    tw.put_start_struct(tag_type)?;
    tw.put_u32(TagType::Context(0), status)?;
    tw.put_u32(TagType::Context(1), cluster_status)?;
    tw.put_end_container()
}

const _INVOKE_REQ_CTX_TAG_SUPPRESS_RESPONSE: u32 = 0;
const _INVOKE_REQ_CTX_TAG_TIMED_REQ: u32 = 1;
const INVOKE_REQ_CTX_TAG_INVOKE_REQUESTS: u32 = 2;

impl InteractionModel {
    pub fn handle_invoke_req(
        &mut self,
        trans: &mut Transaction,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In Invoke Req");
        proto_tx.proto_opcode = OpCode::InvokeResponse as u8;

        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        let root = get_root_node_struct(proto_rx.buf)?;
        // Spec says tag should be 2, but CHIP Tool sends the tag as 0
        let mut cmd_list_iter = root
            .find_tag(INVOKE_REQ_CTX_TAG_INVOKE_REQUESTS)?
            .confirm_array()?
            .into_iter()
            .ok_or(Error::InvalidData)?;

        tw.put_start_struct(TagType::Anonymous)?;
        // Suppress Response
        tw.put_bool(TagType::Context(0), false)?;
        // Array of InvokeResponse IBs
        tw.put_start_array(TagType::Context(1))?;
        while let Some(cmd_data_ib) = cmd_list_iter.next() {
            // CommandDataIB has CommandPath(0) + Data(1)
            let cmd_path_ib = CmdPathIb::from_tlv(&cmd_data_ib.find_tag(0)?.confirm_list()?)?;
            let data = cmd_data_ib.find_tag(1)?;

            self.consumer
                .consume_invoke_cmd(&cmd_path_ib, data, trans, &mut tw)
                .map_err(|e| {
                    error!("Error in handling command: {:?}", e);
                    tlv::print_tlv_list(proto_rx.buf);
                    e
                })?;
        }
        tw.put_end_container()?;
        tw.put_end_container()?;
        Ok(ResponseRequired::Yes)
    }
}
