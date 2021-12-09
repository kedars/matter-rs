use crate::error::*;
use crate::proto_demux;
use crate::proto_demux::ResponseRequired;
use crate::proto_demux::{ProtoRx, ProtoTx};
use crate::tlv;
use crate::tlv::*;
use crate::utils::writebuf::WriteBuf;
use log::error;
use num;
use num_derive::FromPrimitive;
use std::any::Any;
use std::sync::Arc;

/* Handle messages related to the Interation Model
 */

/* Interaction Model ID as per the Matter Spec */
const PROTO_ID_INTERACTION_MODEL: usize = 0x01;

#[derive(FromPrimitive, Debug)]
enum OpCode {
    Reserved = 0,
    StatusResponse = 1,
    ReadRequest = 2,
    SubscribeRequest = 3,
    SubscriptResponse = 4,
    ReportData = 5,
    WriteRequest = 6,
    WriteResponse = 7,
    InvokeRequest = 8,
    InvokeResponse = 9,
    TimedRequest = 10,
}

#[derive(PartialEq)]
pub enum TransactionState {
    Ongoing,
    Complete,
}
pub struct Transaction {
    pub state: TransactionState,
    pub data: Option<Box<dyn Any>>,
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            state: TransactionState::Ongoing,
            data: None,
        }
    }

    pub fn complete(&mut self) {
        self.state = TransactionState::Complete
    }

    pub fn is_complete(&self) -> bool {
        self.state == TransactionState::Complete
    }
}

pub trait HandleInteraction {
    fn handle_invoke_cmd(
        &self,
        trans: &mut Transaction,
        cmd_path_ib: &CmdPathIb,
        variable: TLVElement,
        resp_buf: &mut WriteBuf,
    ) -> Result<(), Error>;
}

pub struct InteractionModel {
    handler: Arc<dyn HandleInteraction>,
}

#[derive(Debug)]
pub struct CmdPathIb {
    /* As per the spec these should be U16, U32, and U16 respectively */
    pub endpoint: Option<u8>,
    pub cluster: Option<u8>,
    pub command: Option<u8>,
}

fn get_cmd_path_ib(cmd_path: &TLVElement) -> CmdPathIb {
    CmdPathIb {
        endpoint: cmd_path.find_element(0).and_then(|x| x.get_u8()),
        cluster: cmd_path.find_element(2).and_then(|x| x.get_u8()),
        command: cmd_path.find_element(3).and_then(|x| x.get_u8()),
    }
}

impl InteractionModel {
    pub fn new(handler: Arc<dyn HandleInteraction>) -> InteractionModel {
        InteractionModel { handler }
    }

    // For now, we just return without doing anything to this exchange. This needs change
    fn invoke_req_handler(
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
            // CommandDataIB has CommandPath(0) + Variable(1)
            let cmd_path_ib = get_cmd_path_ib(
                &cmd_data_ib
                    .find_element(0)
                    .ok_or(Error::InvalidData)?
                    .confirm_list()
                    .ok_or(Error::InvalidData)?,
            );
            let variable = cmd_data_ib.find_element(1).ok_or(Error::InvalidData)?;
            self.handler
                .handle_invoke_cmd(trans, &cmd_path_ib, variable, &mut proto_tx.write_buf)
                .map_err(|e| {
                    error!("Error in handling command: {:?}", e);
                    tlv::print_tlv_list(proto_rx.buf);
                    e
                })?;
        }
        Ok(ResponseRequired::Yes)
    }
}

impl proto_demux::HandleProto for InteractionModel {
    fn handle_proto_id(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        let mut trans = Transaction::new();
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(proto_rx.proto_opcode).ok_or(Error::Invalid)?;
        proto_tx.proto_id = PROTO_ID_INTERACTION_MODEL;

        let result = match proto_opcode {
            OpCode::InvokeRequest => self.invoke_req_handler(&mut trans, proto_rx, proto_tx)?,
            _ => {
                error!("Opcode Not Handled: {:?}", proto_opcode);
                return Err(Error::InvalidOpcode);
            }
        };

        if trans.is_complete() {
            proto_rx.exchange.close();
        }
        Ok(result)
    }

    fn get_proto_id(&self) -> usize {
        PROTO_ID_INTERACTION_MODEL as usize
    }
}

#[cfg(test)]
mod tests {
    use crate::im_demux::*;
    use crate::proto_demux::HandleProto;
    use crate::transport::exchange::Exchange;
    use crate::transport::session::Session;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct Node {
        pub endpoint: u8,
        pub cluster: u8,
        pub command: u8,
        pub variable: u8,
    }

    struct DataModel {
        node: Mutex<Node>,
    }

    impl DataModel {
        pub fn new(node: Node) -> Self {
            DataModel {
                node: Mutex::new(node),
            }
        }
    }
    impl HandleInteraction for DataModel {
        fn handle_invoke_cmd(
            &self,
            _trans: &mut Transaction,
            cmd_path_ib: &CmdPathIb,
            variable: TLVElement,
            _resp_buf: &mut WriteBuf,
        ) -> Result<(), Error> {
            let mut data = self.node.lock().unwrap();
            data.endpoint = cmd_path_ib.endpoint.unwrap();
            data.cluster = cmd_path_ib.cluster.unwrap();
            data.command = cmd_path_ib.command.unwrap();
            variable.confirm_struct().unwrap();
            data.variable = variable.find_element(1).unwrap().get_u8().unwrap();
            Ok(())
        }
    }

    #[test]
    fn test_valid_invoke_cmd() -> Result<(), Error> {
        // An invoke command for endpoint 0, cluster 49, command 12 and a u8 variable value of 0x05
        let b = [
            0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x00, 0x24, 0x02, 0x31, 0x24, 0x03,
            0x0c, 0x18, 0x35, 0x01, 0x24, 0x01, 0x05, 0x18, 0x18, 0x18, 0x18,
        ];

        let data_model = Arc::new(DataModel::new(Node {
            endpoint: 0,
            cluster: 0,
            command: 0,
            variable: 0,
        }));
        let mut interaction_model = InteractionModel::new(data_model.clone());
        let mut exch: Exchange = Default::default();
        let mut sess: Session = Default::default();
        let mut proto_rx = ProtoRx::new(
            0x01,
            0x08,
            &mut sess,
            &mut exch,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            &b,
        );
        let mut out_buf: [u8; 20] = [0; 20];
        let mut proto_tx = ProtoTx::new(&mut out_buf, 0)?;
        let _result = interaction_model.handle_proto_id(&mut proto_rx, &mut proto_tx);

        let data = data_model.node.lock().unwrap();
        assert_eq!(data.endpoint, 0);
        assert_eq!(data.cluster, 49);
        assert_eq!(data.command, 12);
        assert_eq!(data.variable, 5);
        Ok(())
    }
}
