use std::sync::Arc;

use log::info;

use crate::{
    crypto::{CryptoKeyPair, KeyPair},
    error::Error,
    fabric::FabricMgr,
    proto_demux::{ProtoRx, ProtoTx},
    secure_channel::common,
    tlv::get_root_node_struct,
};

#[derive(PartialEq)]
enum State {
    Sigma1Rx,
    Sigma3Rx,
}

pub struct CaseSession {
    state: State,
    initiator_sessid: u16,
}
impl CaseSession {
    pub fn new(initiator_sessid: u16) -> Result<Self, Error> {
        Ok(Self {
            state: State::Sigma1Rx,
            initiator_sessid,
        })
    }
}

pub struct Case {
    fabric_mgr: Arc<FabricMgr>,
}

impl Case {
    pub fn new(fabric_mgr: Arc<FabricMgr>) -> Self {
        Self { fabric_mgr }
    }

    pub fn handle_casesigma1(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let root = get_root_node_struct(proto_rx.buf)?;
        let initiator_random = root.find_tag(1)?.get_slice()?;
        let initiator_sessid = root.find_tag(2)?.get_u8()?;
        let dest_id = root.find_tag(3)?.get_slice()?;
        let pub_key = root.find_tag(4)?.get_slice()?;

        let local_fabric = self.fabric_mgr.match_dest_id(initiator_random, dest_id);
        if local_fabric.is_err() {
            common::create_sc_status_report(proto_tx, common::SCStatusCodes::NoSharedTrustRoots)?;
            proto_rx.exchange.close();
        }
        let local_fabric = local_fabric?;
        info!("Destination ID matched to fabric index {}", local_fabric);
        let session = Box::new(CaseSession::new(initiator_sessid as u16)?);

        let key_pair = KeyPair::new()?;
        let mut our_pub_key: [u8; 66] = [0; 66];
        key_pair.get_public_key(&mut our_pub_key)?;
        proto_rx.exchange.set_exchange_data(session);
        Ok(())
    }

    pub fn handle_casesigma3(
        &mut self,
        _proto_rx: &mut ProtoRx,
        _proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        Ok(())
    }
}
