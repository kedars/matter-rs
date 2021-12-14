use crate::error::*;
use crate::proto_demux;
use crate::proto_demux::ResponseRequired;
use crate::proto_demux::{ProtoRx, ProtoTx};
use log::error;
use num;
use num_derive::FromPrimitive;
use std::sync::Arc;

use super::InteractionConsumer;
use super::InteractionModel;
use super::Transaction;
use super::TransactionState;

/* Handle messages related to the Interation Model
 */

/* Interaction Model ID as per the Matter Spec */
const PROTO_ID_INTERACTION_MODEL: usize = 0x01;

#[derive(FromPrimitive, Debug)]
pub enum OpCode {
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

impl InteractionModel {
    pub fn new(consumer: Arc<dyn InteractionConsumer>) -> InteractionModel {
        InteractionModel { consumer }
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
            OpCode::InvokeRequest => self.handle_invoke_req(&mut trans, proto_rx, proto_tx)?,
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
    use crate::interaction_model::core::*;
    use crate::interaction_model::CmdPathIb;
    use crate::proto_demux::HandleProto;
    use crate::tlv::TLVElement;
    use crate::tlv_writer::TLVWriter;
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
    impl InteractionConsumer for DataModel {
        fn consume_invoke_cmd(
            &self,
            cmd_path_ib: &CmdPathIb,
            data: TLVElement,
            _trans: &mut Transaction,
            _tlvwriter: &mut TLVWriter,
        ) -> Result<(), Error> {
            let mut common_data = self.node.lock().unwrap();
            common_data.endpoint = cmd_path_ib.endpoint.unwrap_or(1);
            common_data.cluster = cmd_path_ib.cluster.unwrap_or(0);
            common_data.command = cmd_path_ib.command;
            data.confirm_struct().unwrap();
            common_data.variable = data.find_element(1).unwrap().get_u8().unwrap();
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
