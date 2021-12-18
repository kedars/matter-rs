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
use log::info;

pub const COMMAND_DATA_PATH_TAG: u8 = 0;
pub const COMMAND_DATA_DATA_TAG: u8 = 1;
pub const COMMAND_DATA_STATUS_TAG: u8 = 2;

#[derive(Debug, PartialEq)]
pub enum InvokeResponseType {
    Command,
    Status,
}

pub struct CommandReq<'a, 'b, 'c> {
    pub endpoint: u16,
    pub cluster: u32,
    pub command: u16,
    pub data: TLVElement<'a>,
    pub resp: &'a mut TLVWriter<'b, 'c>,
    pub trans: &'a mut Transaction,
}

fn get_cmd_path_ib(cmd_path: &TLVElement) -> Result<CmdPathIb, Error> {
    Ok(CmdPathIb {
        endpoint: cmd_path
            .find_element(0)
            .and_then(|x| x.get_u8())
            .map(|e| e as u16),
        cluster: cmd_path
            .find_element(1)
            .and_then(|x| x.get_u8())
            .map(|c| c as u32),
        command: cmd_path
            .find_element(2)
            .and_then(|x| x.get_u8())
            .ok_or(Error::NoCommand)? as u16,
    })
}

pub fn put_cmd_path_ib(
    tlvwriter: &mut TLVWriter,
    tag_type: TagType,
    endpoint: u16,
    cluster: u32,
    command: u16,
) -> Result<(), Error> {
    tlvwriter.put_start_list(tag_type)?;
    tlvwriter.put_u16(TagType::Context(0), endpoint)?;
    tlvwriter.put_u32(TagType::Context(1), cluster)?;
    tlvwriter.put_u16(TagType::Context(2), command)?;
    tlvwriter.put_end_container()
}

pub fn put_status_ib(
    tlvwriter: &mut TLVWriter,
    tag_type: TagType,
    status: u32,
    cluster_status: u32,
) -> Result<(), Error> {
    tlvwriter.put_start_struct(tag_type)?;
    tlvwriter.put_u32(TagType::Context(0), status)?;
    tlvwriter.put_u32(TagType::Context(1), cluster_status)?;
    tlvwriter.put_end_container()
}

pub fn put_invoke_response_ib_start(
    tlvwriter: &mut TLVWriter,
    tag_type: TagType,
    response_type: InvokeResponseType,
) -> Result<(), Error> {
    tlvwriter.put_start_struct(tag_type)?;
    match response_type {
        InvokeResponseType::Command => tlvwriter.put_start_struct(TagType::Context(0)),
        InvokeResponseType::Status => tlvwriter.put_start_struct(TagType::Context(1)),
    }
}

pub fn put_invoke_response_ib_end(tlvwriter: &mut TLVWriter) -> Result<(), Error> {
    tlvwriter.put_end_container()?;
    tlvwriter.put_end_container()
}

pub fn put_invoke_response_ib_with_status(
    cmd_req: &mut CommandReq,
    status: u32,
    cluster_status: u32,
) -> Result<(), Error> {
    put_invoke_response_ib_start(
        &mut cmd_req.resp,
        TagType::Anonymous,
        InvokeResponseType::Status,
    )?;
    put_cmd_path_ib(
        &mut cmd_req.resp,
        TagType::Context(COMMAND_DATA_PATH_TAG),
        cmd_req.endpoint,
        cmd_req.cluster,
        cmd_req.command,
    )?;
    put_status_ib(
        &mut cmd_req.resp,
        TagType::Context(COMMAND_DATA_STATUS_TAG),
        status,
        cluster_status,
    )?;
    put_invoke_response_ib_end(&mut cmd_req.resp)
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

        let mut tlvwriter = TLVWriter::new(&mut proto_tx.write_buf);
        let root = get_root_node_struct(proto_rx.buf).ok_or(Error::InvalidData)?;
        // Spec says tag should be 2, but CHIP Tool sends the tag as 0
        let mut cmd_list_iter = root
            .find_element(INVOKE_REQ_CTX_TAG_INVOKE_REQUESTS)
            .ok_or(Error::InvalidData)?
            .confirm_array()
            .ok_or(Error::InvalidData)?
            .into_iter()
            .ok_or(Error::InvalidData)?;

        tlvwriter.put_start_struct(TagType::Anonymous)?;
        // Suppress Response
        tlvwriter.put_bool(TagType::Context(0), false)?;
        // Array of InvokeResponse IBs
        tlvwriter.put_start_array(TagType::Context(1))?;
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
