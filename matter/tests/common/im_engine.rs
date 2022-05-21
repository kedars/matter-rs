use crate::common::echo_cluster;
use boxslab::Slab;
use matter::{
    data_model::{
        cluster_basic_information::BasicInfoConfig,
        core::DataModel,
        device_types::device_type_add_on_off_light,
        sdm::dev_att::{DataType, DevAttDataFetcher},
    },
    error::Error,
    fabric::FabricMgr,
    interaction_model::{core::OpCode, messages::ib::CmdPath, messages::msg, InteractionModel},
    tlv::{TLVWriter, TagType, ToTLV},
    transport::packet::Packet,
    transport::proto_demux::HandleProto,
    transport::{
        exchange::{Exchange, ExchangeCtx},
        packet::PacketPool,
        proto_demux::ProtoCtx,
        session::SessionMgr,
    },
    utils::writebuf::WriteBuf,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

pub struct DummyDevAtt {}
impl DevAttDataFetcher for DummyDevAtt {
    fn get_devatt_data(&self, _data_type: DataType, _data: &mut [u8]) -> Result<usize, Error> {
        Ok(2)
    }
}

// Create an Interaction Model, Data Model and run a rx/tx transaction through it
pub fn im_engine(action: OpCode, data_in: &[u8], data_out: &mut [u8]) -> (DataModel, usize) {
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
    let sess_idx = sess_mgr
        .get_or_add(
            0,
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5542),
            None,
            false,
        )
        .unwrap();
    let sess = sess_mgr.get_session_handle(sess_idx);
    let exch_ctx = ExchangeCtx {
        exch: &mut exch,
        sess,
    };
    let mut rx = Slab::<PacketPool>::new(Packet::new_rx().unwrap()).unwrap();
    let tx = Slab::<PacketPool>::new(Packet::new_tx().unwrap()).unwrap();
    // Create fake rx packet
    rx.set_proto_id(0x01);
    rx.set_proto_opcode(action as u8);
    rx.peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let in_data_len = data_in.len();
    let rx_buf = rx.as_borrow_slice();
    rx_buf[..in_data_len].copy_from_slice(data_in);

    let mut ctx = ProtoCtx::new(exch_ctx, rx, tx);
    interaction_model.handle_proto_id(&mut ctx).unwrap();
    let out_data_len = ctx.tx.as_borrow_slice().len();
    data_out[..out_data_len].copy_from_slice(ctx.tx.as_borrow_slice());
    (data_model, out_data_len)
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

    pub fn commands(&mut self, cmds: &[(CmdPath, Option<u8>)]) -> Result<(), Error> {
        self.tw.start_struct(TagType::Anonymous)?;
        self.tw.bool(
            TagType::Context(msg::InvReqTag::SupressResponse as u8),
            false,
        )?;
        self.tw
            .bool(TagType::Context(msg::InvReqTag::TimedReq as u8), false)?;
        self.tw
            .start_array(TagType::Context(msg::InvReqTag::InvokeRequests as u8))?;

        for (cmd, data) in cmds {
            self.tw.start_struct(TagType::Anonymous)?;
            cmd.to_tlv(&mut self.tw, TagType::Context(0))?;
            if let Some(d) = *data {
                self.tw.u8(TagType::Context(1), d)?;
            }
            self.tw.end_container()?;
        }

        self.tw.end_container()?;
        self.tw.end_container()
    }
}
