use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use matter::{
    data_model::{
        cluster_basic_information::BasicInfoConfig,
        core::DataModel,
        device_types::device_type_add_on_off_light,
        sdm::dev_att::{DataType, DevAttDataFetcher},
    },
    error::Error,
    fabric::FabricMgr,
    interaction_model::{
        command,
        core::OpCode,
        messages::ib::{CmdPath, InvResponseIn},
        messages::msg,
        InteractionModel,
    },
    proto_demux::{HandleProto, ProtoRx, ProtoTx},
    tlv,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
    transport::{exchange::Exchange, session::SessionMgr},
    utils::writebuf::WriteBuf,
};

mod common;
use common::echo_cluster;

pub struct DummyDevAtt {}
impl DevAttDataFetcher for DummyDevAtt {
    fn get_devatt_data(&self, _data_type: DataType, _data: &mut [u8]) -> Result<usize, Error> {
        Ok(2)
    }
}

// Create an Interaction Model, Data Model and run a rx/tx transaction through it
fn handle_data(action: OpCode, data_in: &[u8], proto_tx: &mut ProtoTx) -> DataModel {
    let dev_det = BasicInfoConfig {
        vid: 10,
        pid: 11,
        hw_ver: 12,
        sw_ver: 13,
    };
    let dev_att = Box::new(DummyDevAtt {});
    let fabric_mgr = Arc::new(FabricMgr::new().unwrap());
    let data_model = DataModel::new(dev_det, dev_att, fabric_mgr.clone()).unwrap();

    {
        let mut d = data_model.node.write().unwrap();
        let light_endpoint = device_type_add_on_off_light(&mut d).unwrap();
        d.add_cluster(0, echo_cluster::EchoCluster::new(2).unwrap())
            .unwrap();
        d.add_cluster(light_endpoint, echo_cluster::EchoCluster::new(3).unwrap())
            .unwrap();
    }

    let mut interaction_model = Box::new(InteractionModel::new(Box::new(data_model.clone())));
    let mut exch: Exchange = Default::default();
    exch.acquire();
    let mut sess_mgr: SessionMgr = Default::default();
    let sess = sess_mgr
        .get_or_add(
            0,
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5542),
            None,
            false,
        )
        .unwrap();
    let mut proto_rx = ProtoRx::new(
        0x01,
        action as u8,
        sess,
        &mut exch,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        data_in,
    );
    interaction_model
        .handle_proto_id(&mut proto_rx, proto_tx)
        .unwrap();
    data_model
}

pub struct TestData<'a, 'b> {
    tw: TLVWriter<'a, 'b>,
}

impl<'a, 'b> TestData<'a, 'b> {
    pub fn new(buf: &'b mut WriteBuf<'a>) -> Self {
        Self {
            tw: TLVWriter::new(buf),
        }
    }

    pub fn commands(&mut self, cmds: &[(CmdPath, u8)]) -> Result<(), Error> {
        self.tw.put_start_struct(TagType::Anonymous)?;
        self.tw
            .put_bool(TagType::Context(command::Tag::SupressResponse as u8), false)?;
        self.tw
            .put_bool(TagType::Context(command::Tag::TimedReq as u8), false)?;
        self.tw
            .put_start_array(TagType::Context(command::Tag::InvokeRequests as u8))?;

        for (cmd, data) in cmds {
            self.tw.put_start_struct(TagType::Anonymous)?;
            self.tw.put_object(TagType::Context(0), cmd)?;
            self.tw.put_u8(TagType::Context(1), *data)?;
            self.tw.put_end_container()?;
        }

        self.tw.put_end_container()?;
        self.tw.put_end_container()
    }
}

enum ExpectedInvResp {
    Cmd(CmdPath, u8),
    Status(CmdPath, u16),
}

// Helper for handling Invoke Command sequences
fn handle_commands(input: &[(CmdPath, u8)], expected: &[ExpectedInvResp]) {
    let mut buf = [0u8; 100];

    let buf_len = buf.len();
    let mut wb = WriteBuf::new(&mut buf, buf_len);
    let mut td = TestData::new(&mut wb);
    let mut out_buf = [0u8; 100];
    let mut proto_tx = ProtoTx::new(&mut out_buf, 0).unwrap();

    td.commands(input).unwrap();

    let _ = handle_data(OpCode::InvokeRequest, wb.as_slice(), &mut proto_tx);
    let root = tlv::get_root_node_struct(proto_tx.write_buf.as_slice()).unwrap();

    let mut index = 0;
    let cmd_list_iter = root
        .find_tag(msg::InvResponseTag::InvokeResponses as u32)
        .unwrap()
        .confirm_array()
        .unwrap()
        .iter()
        .unwrap();
    for response in cmd_list_iter {
        let inv_response = InvResponseIn::from_tlv(&response).unwrap();
        match expected[index] {
            ExpectedInvResp::Cmd(e_c, e_b) => match inv_response {
                InvResponseIn::Cmd(c, d) => {
                    assert_eq!(e_c, c);
                    assert_eq!(e_b, d.find_tag(0).unwrap().get_u8().unwrap());
                }
                _ => {
                    panic!("Invalid response, expected InvResponse::Cmd");
                }
            },
            ExpectedInvResp::Status(e_c, e_status) => match inv_response {
                InvResponseIn::Status(c, status) => {
                    assert_eq!(e_c, c);
                    assert_eq!(e_status, status.status as u16);
                }
                _ => {
                    panic!("Invalid response, expected InvResponse::Status");
                }
            },
        }
        index += 1;
    }
}

macro_rules! echo_req {
    ($endpoint:literal, $data:literal) => {
        (
            CmdPath::new(
                Some($endpoint),
                Some(echo_cluster::CLUSTER_ECHO_ID),
                Some(echo_cluster::CMD_ECHO_REQUEST_ID),
            ),
            $data,
        )
    };
}

macro_rules! echo_resp {
    ($endpoint:literal, $data:literal) => {
        ExpectedInvResp::Cmd(
            CmdPath::new(
                Some($endpoint),
                Some(echo_cluster::CLUSTER_ECHO_ID),
                Some(echo_cluster::CMD_ECHO_RESPONSE_ID),
            ),
            $data,
        )
    };
}

#[test]
fn test_invoke_cmds_success() {
    // 2 echo Requests
    // - one on endpoint 0 with data 5,
    // - another on endpoint 1 with data 10
    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    let expected = &[echo_resp!(0, 10), echo_resp!(1, 30)];
    handle_commands(input, expected);
}
