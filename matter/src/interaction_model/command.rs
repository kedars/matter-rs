use super::core::IMStatusCode;
use super::core::OpCode;
use super::messages::command_path;
use super::InteractionModel;
use super::Transaction;
use crate::error::*;
use crate::proto_demux::ProtoTx;
use crate::proto_demux::ResponseRequired;
use crate::tlv::*;
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use crate::tlv_writer::ToTLV;
use log::error;
use log::info;

#[macro_export]
macro_rules! cmd_enter {
    ($e:expr) => {{
        use colored::Colorize;
        info! {"{} {}", "Handling Command".cyan(), $e.cyan()}
    }};
}

#[derive(Debug, Clone, Copy)]
pub enum InvokeRespIb<F>
where
    F: Fn(&mut TLVWriter) -> Result<(), Error>,
{
    CommandData(command_path::Ib, F),
    CommandStatus(command_path::Ib, IMStatusCode, u32, F),
}

#[allow(non_snake_case)]
pub fn dummy(_t: &mut TLVWriter) -> Result<(), Error> {
    Ok(())
}

impl<F: Fn(&mut TLVWriter) -> Result<(), Error>> ToTLV for InvokeRespIb<F> {
    fn to_tlv(self: &InvokeRespIb<F>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.put_start_struct(tag_type)?;
        match self {
            InvokeRespIb::CommandData(cmd_path, data_cb) => {
                tw.put_start_struct(TagType::Context(0))?;
                tw.put_object(TagType::Context(0), cmd_path)?;
                tw.put_start_struct(TagType::Context(1))?;
                data_cb(tw)?;
                tw.put_end_container()?;
            }
            InvokeRespIb::CommandStatus(cmd_path, status, cluster_status, _) => {
                tw.put_start_struct(TagType::Context(1))?;
                tw.put_object(TagType::Context(0), cmd_path)?;
                put_status_ib(tw, TagType::Context(1), *status, *cluster_status)?;
            }
        }
        tw.put_end_container()?;
        tw.put_end_container()
    }
}

pub struct CommandReq<'a, 'b, 'c, 'd, 'e> {
    pub cmd: command_path::Ib,
    pub data: TLVElement<'a>,
    pub resp: &'a mut TLVWriter<'b, 'c>,
    pub trans: &'a mut Transaction<'d, 'e>,
}

fn put_status_ib(
    tw: &mut TLVWriter,
    tag_type: TagType,
    status: IMStatusCode,
    cluster_status: u32,
) -> Result<(), Error> {
    tw.put_start_struct(tag_type)?;
    tw.put_u32(TagType::Context(0), status as u32)?;
    tw.put_u32(TagType::Context(1), cluster_status)?;
    tw.put_end_container()
}

enum Tag {
    _SupressResponse = 0,
    _TimedReq = 1,
    InvokeRequests = 2,
}

impl InteractionModel {
    pub fn handle_invoke_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In Invoke Req");
        proto_tx.proto_opcode = OpCode::InvokeResponse as u8;

        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        let root = get_root_node_struct(rx_buf)?;
        // Spec says tag should be 2, but CHIP Tool sends the tag as 0
        let cmd_list_iter = root
            .find_tag(Tag::InvokeRequests as u32)?
            .confirm_array()?
            .iter()
            .ok_or(Error::InvalidData)?;

        tw.put_start_struct(TagType::Anonymous)?;
        // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
        tw.put_bool(TagType::Context(0), false)?;
        // Array of InvokeResponse IBs
        tw.put_start_array(TagType::Context(1))?;
        for cmd_data_ib in cmd_list_iter {
            // CommandDataIB has CommandPath(0) + Data(1)
            let cmd_path_ib =
                command_path::Ib::from_tlv(&cmd_data_ib.find_tag(0)?.confirm_list()?)?;
            let data = cmd_data_ib.find_tag(1)?;

            self.consumer
                .consume_invoke_cmd(&cmd_path_ib, data, trans, &mut tw)
                .map_err(|e| {
                    error!("Error in handling command: {:?}", e);
                    print_tlv_list(rx_buf);
                    e
                })?;
        }
        tw.put_end_container()?;
        tw.put_end_container()?;
        Ok(ResponseRequired::Yes)
    }
}
