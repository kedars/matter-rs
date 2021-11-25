use crate::error::*;
use crate::transport::plain_hdr;
use crate::transport::proto_hdr;
use log::{error, info};

use super::session::SessionMgr;

#[derive(Debug)]
pub struct RetransEntry {
    // The session index
    sess_index: usize,
    // The index of the exchange for which this is pending
    exch_index: usize,
    // The msg counter that we are waiting to be acknowledged
    msg_ctr: u32,
    // This will additionally have retransmission count and periods once we implement it
}

impl RetransEntry {
    pub fn new(sess_index: usize, exch_index: usize, msg_ctr: u32) -> Self {
        Self {
            sess_index,
            exch_index,
            msg_ctr,
        }
    }

    pub fn is_match(&self, sess_index: usize, exch_index: usize, msg_ctr: u32) -> bool {
        self.sess_index == sess_index && self.exch_index == exch_index && self.msg_ctr == msg_ctr
    }
}

const MAX_RETRANS_ENTRIES: usize = 3;
#[derive(Default, Debug)]
pub struct ReliableMessage {
    retrans_table: [Option<RetransEntry>; MAX_RETRANS_ENTRIES],
}

impl ReliableMessage {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn before_msg_send(
        &mut self,
        sess_mgr: &mut SessionMgr,
        sess_index: usize,
        exch_index: usize,
        plain_hdr: &plain_hdr::PlainHdr,
        proto_hdr: &mut proto_hdr::ProtoHdr,
    ) -> Result<(), Error> {
        let e = sess_mgr
            .get_exchange(sess_index, exch_index)
            .ok_or(Error::NoExchange)?;

        // Check if any pending acknowledgements are pending for this exchange,
        // if so, piggy back in the encoded header here
        if let Some(pending_ack) = e.is_ack_pending() {
            proto_hdr.set_ack(pending_ack);
            e.clear_ack_pending();
        }

        // For now, let's always set reliable, not sure when it is unreliable
        proto_hdr.set_reliable();

        let new_entry = RetransEntry::new(sess_index, exch_index, plain_hdr.ctr);
        if let Some(index) = self.retrans_table.iter().position(|x| x.is_none()) {
            self.retrans_table[index] = Some(new_entry);
            e.ack_recv_pending();
            Ok(())
        } else {
            error!("Couldn't add to retrans table");
            Err(Error::NoSpaceRetransTable)
        }
    }

    /* A note about Message ACKs, it is a bit asymmetric in the sense that:
     * -  there can be only one pending ACK per exchange (so this is per-exchange)
     * -  there can be only one pending retransmission per exchange (so this is per-exchange)
     * -  duplicate detection should happen per session (obviously), so that part is per-session
     */
    pub fn on_msg_recv(
        &mut self,
        sess_mgr: &mut SessionMgr,
        sess_index: usize,
        exch_index: usize,
        plain_hdr: &plain_hdr::PlainHdr,
        proto_hdr: &proto_hdr::ProtoHdr,
    ) -> Result<(), Error> {
        let e = sess_mgr
            .get_exchange(sess_index, exch_index)
            .ok_or(Error::NoExchange)?;

        if proto_hdr.is_ack() {
            // Acknowledgement handling
            let ack_msg_ctr = proto_hdr.get_ack_msg_ctr().ok_or(Error::Invalid)?;

            if let Some(index) = self.retrans_table.iter().position(|x| {
                if let Some(r) = x {
                    r.is_match(sess_index, exch_index, ack_msg_ctr)
                } else {
                    false
                }
            }) {
                // Remove from retransmission table
                self.retrans_table[index] = None;
                e.clear_ack_recv_pending();
            }
        }

        if proto_hdr.is_reliable() {
            e.ack_pending(plain_hdr.ctr);
        }
        info!("Retrans table now is: {:?}", self.retrans_table);
        Ok(())
    }
}
