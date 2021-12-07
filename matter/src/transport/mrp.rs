use std::time::Duration;
use std::time::SystemTime;

use crate::error::*;
use crate::proto_demux::ProtoTx;
use crate::secure_channel;
use crate::transport::plain_hdr;
use crate::transport::proto_hdr;
use heapless::LinearMap;
use log::{error, info};

// 200 ms
const MRP_STANDALONE_ACK_TIMEOUT: u64 = 200;

#[derive(Debug)]
pub struct RetransEntry {
    // The msg counter that we are waiting to be acknowledged
    msg_ctr: u32,
    // This will additionally have retransmission count and periods once we implement it
}

impl RetransEntry {
    pub fn new(msg_ctr: u32) -> Self {
        Self { msg_ctr }
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AckEntry {
    // The msg counter that we should acknowledge
    msg_ctr: u32,
    // The max time after which this entry must be ACK
    ack_timeout: SystemTime,
}

impl AckEntry {
    pub fn new(msg_ctr: u32) -> Result<Self, Error> {
        if let Some(ack_timeout) =
            SystemTime::now().checked_add(Duration::from_millis(MRP_STANDALONE_ACK_TIMEOUT))
        {
            Ok(Self {
                msg_ctr,
                ack_timeout,
            })
        } else {
            Err(Error::Invalid)
        }
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }

    pub fn has_timed_out(&self) -> bool {
        self.ack_timeout > SystemTime::now()
    }
}

pub const MAX_MRP_ENTRIES: usize = 3;
#[derive(Default, Debug)]
pub struct ReliableMessage {
    // keys: sess-id exch-id
    retrans_table: LinearMap<(u16, u16), RetransEntry, MAX_MRP_ENTRIES>,
    ack_table: LinearMap<(u16, u16), AckEntry, MAX_MRP_ENTRIES>,
}

impl ReliableMessage {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    // Check any pending acknowledgements / retransmissions and take action
    pub fn get_acks_to_send(
        &self,
        expired_entries: &mut LinearMap<(u16, u16), (), MAX_MRP_ENTRIES>,
    ) {
        // Acknowledgements
        for ((sess_id, exch_id), ack_entry) in self.ack_table.iter() {
            if ack_entry.has_timed_out() {
                let _ok = expired_entries.insert((*sess_id, *exch_id), ());
            }
        }
    }

    pub fn prepare_ack(&self, _sess_id: u16, _exch_id: u16, proto_tx: &mut ProtoTx) {
        secure_channel::common::create_mrp_standalone_ack(proto_tx);
    }

    pub fn pre_send(
        &mut self,
        sess_id: u16,
        exch_id: u16,
        reliable: bool,
        plain_hdr: &plain_hdr::PlainHdr,
        proto_hdr: &mut proto_hdr::ProtoHdr,
    ) -> Result<(), Error> {
        // Check if any acknowledgements are pending for this exchange,
        // if so, piggy back in the encoded header here
        if let Some(ack_entry) = self.ack_table.get(&(sess_id, exch_id)) {
            // Ack Entry exists, set ACK bit and remove from table
            proto_hdr.set_ack(ack_entry.get_msg_ctr());
            self.ack_table.remove(&(sess_id, exch_id));
        }

        if !reliable {
            return Ok(());
        }

        proto_hdr.set_reliable();

        let new_entry = RetransEntry::new(plain_hdr.ctr);
        if let Ok(result) = self.retrans_table.insert((sess_id, exch_id), new_entry) {
            if let Some(_) = result {
                // This indicates there was some existing entry for same sess-id/exch-id, which shouldnt happen
                error!("Previous retrans entry for this exchange already exists");
                Err(Error::Invalid)
            } else {
                Ok(())
            }
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
    pub fn recv(
        &mut self,
        sess_id: u16,
        exch_id: u16,
        plain_hdr: &plain_hdr::PlainHdr,
        proto_hdr: &proto_hdr::ProtoHdr,
    ) -> Result<(), Error> {
        if proto_hdr.is_ack() {
            // Handle received Acks
            let ack_msg_ctr = proto_hdr.get_ack_msg_ctr().ok_or(Error::Invalid)?;
            if let Some(entry) = self.retrans_table.get(&(sess_id, exch_id)) {
                if entry.get_msg_ctr() != ack_msg_ctr {
                    error!("Mismatch in retrans-table's msg counter and received msg counter: received {}, expected {}", ack_msg_ctr, entry.get_msg_ctr());
                } else {
                    self.retrans_table.remove(&(sess_id, exch_id));
                }
            }
        }

        if proto_hdr.is_reliable() {
            let new_entry = AckEntry::new(plain_hdr.ctr)?;
            if let Ok(result) = self.ack_table.insert((sess_id, exch_id), new_entry) {
                if let Some(_) = result {
                    // This indicates there was some existing entry for same sess-id/exch-id, which shouldnt happen
                    // TODO: As per the spec if this happens, we need to send out the previous ACK and note this new ACK
                    error!("Previous ACK entry for this exchange already exists");
                    return Err(Error::Invalid);
                }
            } else {
                error!("Couldn't add to ACK table");
                return Err(Error::NoSpaceRetransTable);
            }
        }
        info!("Retrans table now is: {:?}", self.retrans_table);
        info!("Ack table now is: {:?}", self.ack_table);
        Ok(())
    }
}
