use super::demux::OpCode;
use super::CmdPathIb;
use super::CommandReq;
use super::InteractionModel;
use super::Transaction;
use crate::error::*;
use crate::proto_demux::ResponseRequired;
use crate::proto_demux::{ProtoRx, ProtoTx};
use crate::tlv;
use crate::tlv::*;
use log::error;

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

impl InteractionModel {
    pub fn invoke_req_handler(
        &mut self,
        trans: &mut Transaction,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.proto_opcode = OpCode::InvokeResponse as u8;

        let root = get_root_node_struct(proto_rx.buf).ok_or(Error::InvalidData)?;
        // Spec says tag should be 2, but CHIP Tool sends the tag as 0
        let mut cmd_list_iter = root
            .find_element(0)
            .ok_or(Error::InvalidData)?
            .confirm_array()
            .ok_or(Error::InvalidData)?
            .into_iter()
            .ok_or(Error::InvalidData)?;

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
            let mut cmd_req = CommandReq {
                cmd_path_ib,
                data,
                trans,
                resp_buf: &mut proto_tx.write_buf,
            };
            self.handler.handle_invoke_cmd(&mut cmd_req).map_err(|e| {
                error!("Error in handling command: {:?}", e);
                tlv::print_tlv_list(proto_rx.buf);
                e
            })?;
        }
        Ok(ResponseRequired::Yes)
    }
}
