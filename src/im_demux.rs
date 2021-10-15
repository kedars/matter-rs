use crate::error::*;
use crate::proto_demux;
use crate::tlv::*;
use log::{error, info};
use num;
use num_derive::FromPrimitive;

/* Handle messages related to the Interation Model
 *
 * I am going to try doing this without an InteractionModel object, just to check what kind of complexity I incur/not-incur
 */


/* Interaction Model ID as per the Matter Spec */
const PROTO_ID_INTERACTION_MODEL: usize = 0x01;

#[derive(FromPrimitive)]
enum OpCode {
    Reserved          = 0,
    StatusResponse    = 1,
    ReadRequest       = 2,
    SubscribeRequest  = 3,
    SubscriptResponse = 4,
    ReportData        = 5,
    WriteRequest      = 6,
    WriteResponse     = 7,
    InvokeRequest     = 8,
    InvokeResponse    = 9,
    TimedRequest      = 10,
}

pub trait HandleInteraction {
    fn handle_invoke_cmd(&mut self, cmd_path_ib: &CmdPathIb, variable: TLVElement) -> Result<(), Error>;
}

pub struct InteractionModel<'a> {
    handler: &'a mut dyn HandleInteraction,
}

#[derive(Debug)]
pub struct CmdPathIb {
    /* As per the spec these should be U16, U32, and U16 respectively */
    endpoint: Option<u8>,
    cluster: Option<u8>,
    command: Option<u8>,
}

fn get_cmd_path_ib(cmd_path: &TLVElement) -> CmdPathIb {
    CmdPathIb {
        endpoint: cmd_path.find_element(0).map_or(Some(2), |x| x.get_u8()),
        cluster: cmd_path.find_element(2).map_or(None, |x| x.get_u8()),
        command: cmd_path.find_element(3).map_or(None, |x| x.get_u8()),
    }
}

impl<'a> InteractionModel<'a> {
    pub fn init(handler: &'a mut dyn HandleInteraction) -> InteractionModel {
        InteractionModel{handler}
    }


    // For now, we just return without doing anything to this exchange. This needs change
    fn invoke_req_handler(&mut self, _opcode: OpCode, buf: &[u8]) -> Result<(), Error> {
        info!("In invoke req handler");
        let root = get_root_node_struct(buf).ok_or(Error::InvalidData)?;

        // Spec says tag should be 2, but CHIP Tool sends the tag as 0
        let mut cmd_list_iter = root.find_element(0).ok_or(Error::InvalidData)?
            .confirm_array().ok_or(Error::InvalidData)?
            .into_iter().ok_or(Error::InvalidData)?;
        loop {
            // This is an array of CommandDataIB
            let cmd_data_ib = cmd_list_iter.next().ok_or(Error::InvalidData)?;

            // CommandDataIB has CommandPath(0) + Variable(1)
            let cmd_path_ib = get_cmd_path_ib(&cmd_data_ib.find_element(0).ok_or(Error::InvalidData)?
                                           .confirm_list().ok_or(Error::InvalidData)?);
            let variable  = cmd_data_ib.find_element(1).ok_or(Error::InvalidData)?;
            return self.handler.handle_invoke_cmd(&cmd_path_ib, variable);
        }
    }
}

impl <'a> proto_demux::HandleProto for InteractionModel<'a> {
    fn handle_proto_id(&mut self, proto_id: u8, buf: &[u8]) -> Result<(), Error> {
        let proto_id: OpCode = num::FromPrimitive::from_u8(proto_id).
            ok_or(Error::Invalid)?;
        match proto_id {
            OpCode::InvokeRequest => return self.invoke_req_handler(proto_id, buf),
            _ => {
                error!("Invalid Opcode");
                return Err(Error::InvalidOpcode);
            }
        }
    }

    fn get_proto_id(& self) -> usize {
        PROTO_ID_INTERACTION_MODEL as usize
    }
}


#[cfg(test)]
mod tests {
    use crate::tlv::*;
    use crate::im_demux::*;
    use crate::proto_demux::HandleProto;

    struct TestDataModel {
        pub endpoint: Option<u8>,
        pub cluster: Option<u8>,
        pub command: Option<u8>,
        pub variable: Option<u8>,
    }

    impl TestDataModel {
        fn init() -> TestDataModel {
            TestDataModel{endpoint: None,
                          cluster: None,
                          command: None,
                          variable: None}
        }
    }

    impl HandleInteraction for TestDataModel {
        fn handle_invoke_cmd(&mut self, cmd_path_ib: &CmdPathIb, variable: TLVElement) -> Result<(), Error> {
            self.endpoint = cmd_path_ib.endpoint;
            self.cluster = cmd_path_ib.cluster;
            self.command = cmd_path_ib.command;
            variable.confirm_struct().unwrap();
            self.variable = variable.find_element(1).unwrap().get_u8();
            Ok(())
        }
    }

    #[test]
    fn test_valid_invoke_cmd() {
        // An invoke command for endpoint 0, cluster 49, command 12 and a u8 variable value of 0x05
        let b = [ 0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x00, 0x24,
                  0x02, 0x31, 0x24, 0x03, 0x0c, 0x18, 0x35, 0x01, 0x24, 0x01, 0x05, 0x18, 0x18, 0x18,
                  0x18];


        let mut data_model = TestDataModel::init();
        let mut interaction_model = InteractionModel::init(&mut data_model);
        interaction_model.handle_proto_id(0x08, &b);
        assert_eq!(data_model.endpoint, Some(0));
        assert_eq!(data_model.cluster, Some(49));
        assert_eq!(data_model.command, Some(12));
        assert_eq!(data_model.variable, Some(5));
    }
}
