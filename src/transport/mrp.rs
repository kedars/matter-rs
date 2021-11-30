use crate::error::*;
use crate::transport::plain_hdr;
use crate::transport::proto_hdr;
use log::{error, info};

#[derive(Debug)]
pub struct RetransEntry {
    // The session index
    sess_id: u16,
    // The index of the exchange for which this is pending
    exch_id: u16,
    // The msg counter that we are waiting to be acknowledged
    msg_ctr: u32,
    // This will additionally have retransmission count and periods once we implement it
}

impl RetransEntry {
    pub fn new(sess_id: u16, exch_id: u16, msg_ctr: u32) -> Self {
        Self {
            sess_id,
            exch_id,
            msg_ctr,
        }
    }

    pub fn is_match(&self, sess_id: u16, exch_id: u16, msg_ctr: u32) -> bool {
        self.sess_id == sess_id && self.exch_id == exch_id && self.msg_ctr == msg_ctr
    }
}

#[derive(Debug)]
pub struct AckEntry {
    // The session index
    sess_id: u16,
    // The index of the exchange for which this is pending
    exch_id: u16,
    // The msg counter that we should acknowledge
    msg_ctr: u32,
}

impl AckEntry {
    pub fn new(sess_id: u16, exch_id: u16, msg_ctr: u32) -> Self {
        Self {
            sess_id,
            exch_id,
            msg_ctr,
        }
    }

    pub fn is_match(&self, sess_id: u16, exch_id: u16) -> bool {
        self.sess_id == sess_id && self.exch_id == exch_id
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }
}

const MAX_MRP_ENTRIES: usize = 3;
#[derive(Default, Debug)]
pub struct ReliableMessage {
    retrans_table: [Option<RetransEntry>; MAX_MRP_ENTRIES],
    ack_table: [Option<AckEntry>; MAX_MRP_ENTRIES],
}

impl ReliableMessage {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn before_msg_send(
        &mut self,
        sess_id: u16,
        exch_id: u16,
        plain_hdr: &plain_hdr::PlainHdr,
        proto_hdr: &mut proto_hdr::ProtoHdr,
    ) -> Result<(), Error> {
        // Check if any acknowledgements are pending for this exchange,
        // if so, piggy back in the encoded header here
        if let Some(index) = self.ack_table.iter().position(|x| {
            if let Some(r) = x {
                r.is_match(sess_id, exch_id)
            } else {
                false
            }
        }) {
            if let Some(ack_entry) = &self.ack_table[index] {
                // Ack Entry exists, set ACK bit and remove from table
                proto_hdr.set_ack(ack_entry.get_msg_ctr());
                self.ack_table[index] = None;
            }
        }

        // For now, let's always set reliable, not sure when it is unreliable
        proto_hdr.set_reliable();

        let new_entry = RetransEntry::new(sess_id, exch_id, plain_hdr.ctr);
        if let Some(index) = self.retrans_table.iter().position(|x| x.is_none()) {
            self.retrans_table[index] = Some(new_entry);
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
        sess_id: u16,
        exch_id: u16,
        plain_hdr: &plain_hdr::PlainHdr,
        proto_hdr: &proto_hdr::ProtoHdr,
    ) -> Result<(), Error> {
        if proto_hdr.is_ack() {
            // Acknowledgement handling
            let ack_msg_ctr = proto_hdr.get_ack_msg_ctr().ok_or(Error::Invalid)?;

            if let Some(index) = self.retrans_table.iter().position(|x| {
                if let Some(r) = x {
                    r.is_match(sess_id, exch_id, ack_msg_ctr)
                } else {
                    false
                }
            }) {
                // Remove from retransmission table
                self.retrans_table[index] = None;
            }
        }

        if proto_hdr.is_reliable() {
            let new_entry = AckEntry::new(sess_id, exch_id, plain_hdr.ctr);
            if let Some(index) = self.ack_table.iter().position(|x| x.is_none()) {
                self.ack_table[index] = Some(new_entry);
            } else {
                error!("Couldn't add to retrans table");
                return Err(Error::NoSpaceRetransTable);
            }
        }
        info!("Retrans table now is: {:?}", self.retrans_table);
        info!("Ack table now is: {:?}", self.ack_table);
        Ok(())
    }
}
