use matter::error::Error;
use matter::interaction_model::core::OpCode;
use matter::interaction_model::messages::ib;
use matter::interaction_model::messages::msg::ReadReq;
use matter::interaction_model::messages::msg::WriteReq;
use matter::interaction_model::InteractionConsumer;
use matter::interaction_model::InteractionModel;
use matter::interaction_model::Transaction;
use matter::tlv::{TLVElement, TLVWriter};
use matter::transport::exchange::Exchange;
use matter::transport::proto_demux::HandleProto;
use matter::transport::proto_demux::ProtoRx;
use matter::transport::proto_demux::ProtoTx;
use matter::transport::session::SessionMgr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

struct Node {
    pub endpoint: u16,
    pub cluster: u32,
    pub command: u16,
    pub variable: u8,
}

struct DataModel {
    node: Arc<Mutex<Node>>,
}

impl DataModel {
    pub fn new(node: Node) -> Self {
        DataModel {
            node: Arc::new(Mutex::new(node)),
        }
    }
}

impl Clone for DataModel {
    fn clone(&self) -> Self {
        Self {
            node: self.node.clone(),
        }
    }
}

impl InteractionConsumer for DataModel {
    fn consume_invoke_cmd(
        &self,
        cmd_path_ib: &ib::CmdPath,
        data: TLVElement,
        _trans: &mut Transaction,
        _tlvwriter: &mut TLVWriter,
    ) -> Result<(), Error> {
        let mut common_data = self.node.lock().unwrap();
        common_data.endpoint = cmd_path_ib.path.endpoint.unwrap_or(1);
        common_data.cluster = cmd_path_ib.path.cluster.unwrap_or(0);
        common_data.command = cmd_path_ib.path.leaf.unwrap_or(0) as u16;
        data.confirm_struct().unwrap();
        common_data.variable = data.find_tag(0).unwrap().u8().unwrap();
        Ok(())
    }

    fn consume_read_attr(&self, _req: &ReadReq, _tlvwriter: &mut TLVWriter) -> Result<(), Error> {
        Ok(())
    }

    fn consume_write_attr(&self, _req: &WriteReq, _tlvwriter: &mut TLVWriter) -> Result<(), Error> {
        Ok(())
    }
}

fn handle_data(action: OpCode, data_in: &[u8], data_out: &mut [u8]) -> DataModel {
    let data_model = DataModel::new(Node {
        endpoint: 0,
        cluster: 0,
        command: 0,
        variable: 0,
    });
    let mut interaction_model = InteractionModel::new(Box::new(data_model.clone()));
    let mut exch: Exchange = Default::default();
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
    let mut proto_tx = ProtoTx::new(data_out, 0).unwrap();
    interaction_model
        .handle_proto_id(&mut proto_rx, &mut proto_tx)
        .unwrap();
    data_model
}

#[test]
fn test_valid_invoke_cmd() -> Result<(), Error> {
    // An invoke command for endpoint 0, cluster 49, command 12 and a u8 variable value of 0x05

    let b = [
        0x15, 0x28, 0x00, 0x28, 0x01, 0x36, 0x02, 0x15, 0x37, 0x00, 0x24, 0x00, 0x00, 0x24, 0x01,
        0x31, 0x24, 0x02, 0x0c, 0x18, 0x35, 0x01, 0x24, 0x00, 0x05, 0x18, 0x18, 0x18, 0x18,
    ];

    let mut out_buf: [u8; 20] = [0; 20];

    let data_model = handle_data(OpCode::InvokeRequest, &b, &mut out_buf);
    let data = data_model.node.lock().unwrap();
    assert_eq!(data.endpoint, 0);
    assert_eq!(data.cluster, 49);
    assert_eq!(data.command, 12);
    assert_eq!(data.variable, 5);
    Ok(())
}
