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
use log::error;

pub const COMMAND_DATA_PATH_TAG: u64 = 0;
pub const COMMAND_DATA_DATA_TAG: u64 = 1;
pub const COMMAND_DATA_STATUS_TAG: u64 = 2;

pub struct CommandReq<'a, 'b, 'c> {
    pub endpoint: u8,
    pub cluster: u8,
    pub command: u8,
    pub data: TLVElement<'a>,
    pub resp: &'a mut TLVWriter<'b, 'c>,
    pub trans: &'a mut Transaction,
}

fn get_cmd_path_ib(cmd_path: &TLVElement) -> Result<CmdPathIb, Error> {
    Ok(CmdPathIb {
        endpoint: cmd_path.find_element(0).and_then(|x| x.get_u8()),
        cluster: cmd_path.find_element(2).and_then(|x| x.get_u8()),
        command: cmd_path
            .find_element(3)
            .and_then(|x| x.get_u8())
            .ok_or(Error::NoCommand)?,
    })
}

pub fn put_cmd_path_ib(
    tlvwriter: &mut TLVWriter,
    tag_type: TagType,
    tag_val: u64,
    endpoint: u16,
    cluster: u32,
    command: u16,
) -> Result<(), Error> {
    tlvwriter.put_start_list(tag_type, tag_val)?;
    // Spec says U16, U32, U16, but chip-tool expects u8
    tlvwriter.put_u8(TagType::Context, 0, endpoint as u8)?;
    tlvwriter.put_u8(TagType::Context, 2, cluster as u8)?;
    tlvwriter.put_u8(TagType::Context, 3, command as u8)?;
    tlvwriter.put_end_container()
}

pub fn put_status_ib(
    tlvwriter: &mut TLVWriter,
    tag_type: TagType,
    tag_val: u64,
    general_code: u8,
) -> Result<(), Error> {
    tlvwriter.put_start_array(tag_type, tag_val)?;
    // Spec says U16, U32, U16, but chip-tool expects u8
    tlvwriter.put_u8(TagType::Anonymous, 0, general_code)?;
    // TODO: This seems to be a leftover in the chip-tool, the status IB has different elements actually
    tlvwriter.put_u8(TagType::Anonymous, 0, 1)?;
    tlvwriter.put_u8(TagType::Anonymous, 0, 0)?;
    tlvwriter.put_end_container()
}

pub fn put_cmd_status_ib_start(
    tlvwriter: &mut TLVWriter,
    tag_type: TagType,
    tag_val: u64,
) -> Result<(), Error> {
    tlvwriter.put_start_struct(tag_type, tag_val)
}

pub fn put_cmd_status_ib_end(tlvwriter: &mut TLVWriter) -> Result<(), Error> {
    tlvwriter.put_end_container()
}

pub fn put_cmd_status_status(cmd_req: &mut CommandReq, status: u8) -> Result<(), Error> {
    // TODO: This whole thing is completely mismatched with the spec. But it is what the chip-tool
    // expects, so...
    put_cmd_status_ib_start(&mut cmd_req.resp, TagType::Anonymous, 0)?;
    put_cmd_path_ib(
        &mut cmd_req.resp,
        TagType::Context,
        COMMAND_DATA_PATH_TAG,
        cmd_req.endpoint as u16,
        cmd_req.cluster as u32,
        cmd_req.command as u16,
    )?;
    put_status_ib(
        &mut cmd_req.resp,
        TagType::Context,
        COMMAND_DATA_STATUS_TAG,
        status,
    )?;
    put_cmd_status_ib_end(&mut cmd_req.resp)
}

impl InteractionModel {
    pub fn handle_invoke_req(
        &mut self,
        trans: &mut Transaction,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.proto_opcode = OpCode::InvokeResponse as u8;

        let mut tlvwriter = TLVWriter::new(&mut proto_tx.write_buf);
        let root = get_root_node_struct(proto_rx.buf).ok_or(Error::InvalidData)?;
        // Spec says tag should be 2, but CHIP Tool sends the tag as 0
        let mut cmd_list_iter = root
            .find_element(0)
            .ok_or(Error::InvalidData)?
            .confirm_array()
            .ok_or(Error::InvalidData)?
            .into_iter()
            .ok_or(Error::InvalidData)?;

        tlvwriter.put_start_struct(TagType::Anonymous, 0)?;
        tlvwriter.put_start_array(TagType::Context, 0)?;
        while let Some(cmd_data_ib) = cmd_list_iter.next() {
            // CommandDataIB has CommandPath(0) + Data(1)
            let cmd_path_ib = get_cmd_path_ib(
                &cmd_data_ib
                    .find_element(0)
                    .ok_or(Error::InvalidData)?
                    .confirm_list()
                    .ok_or(Error::InvalidData)?,
            )?;
            let data = cmd_data_ib.find_element(1).ok_or(Error::InvalidData)?;

            self.consumer
                .consume_invoke_cmd(&cmd_path_ib, data, trans, &mut tlvwriter)
                .map_err(|e| {
                    error!("Error in handling command: {:?}", e);
                    tlv::print_tlv_list(proto_rx.buf);
                    e
                })?;
        }
        tlvwriter.put_end_container()?;
        tlvwriter.put_end_container()?;
        Ok(ResponseRequired::Yes)
    }
}
