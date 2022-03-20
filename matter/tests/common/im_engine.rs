use crate::common::echo_cluster;
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
    proto_demux::{HandleProto, ProtoRx, ProtoTx},
    tlv_common::TagType,
    tlv_writer::TLVWriter,
    transport::{exchange::Exchange, session::SessionMgr},
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
pub fn im_engine(action: OpCode, data_in: &[u8], proto_tx: &mut ProtoTx) -> DataModel {
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

    pub fn commands(&mut self, cmds: &[(CmdPath, Option<u8>)]) -> Result<(), Error> {
        self.tw.put_start_struct(TagType::Anonymous)?;
        self.tw.put_bool(
            TagType::Context(msg::InvReqTag::SupressResponse as u8),
            false,
        )?;
        self.tw
            .put_bool(TagType::Context(msg::InvReqTag::TimedReq as u8), false)?;
        self.tw
            .put_start_array(TagType::Context(msg::InvReqTag::InvokeRequests as u8))?;

        for (cmd, data) in cmds {
            self.tw.put_start_struct(TagType::Anonymous)?;
            self.tw.put_object(TagType::Context(0), cmd)?;
            if let Some(d) = *data {
                self.tw.put_u8(TagType::Context(1), d)?;
            }
            self.tw.put_end_container()?;
        }

        self.tw.put_end_container()?;
        self.tw.put_end_container()
    }
}
