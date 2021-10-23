use crate::transport::enc_hdr;
use crate::error::*;
use crate::transport::exchange::*;
use crate::transport::plain_hdr;

/* A note about Message ACKs, it is a bit asymmetric in the sense that:
 * -  there can be only one pending ACK per exchange (so this is per-exchange)
 * -  there can be only one pending retransmission per exchange (so this is per-exchange)
 * -  duplicate detection should happen per session (obviously), so that part is per-session
 */
pub fn on_msg_recv(e: &mut Exchange, plain_hdr: &plain_hdr::PlainHdr, enc_hdr: &enc_hdr::EncHdr) {
    if enc_hdr.is_ack() {
        // Acknowledgement handling to be implemented
    }

    if enc_hdr.is_reliable() {
        e.ack_pending(plain_hdr.ctr);
    }
}

pub fn before_msg_send(e: &mut Exchange, _plain_hdr: &mut plain_hdr::PlainHdr, enc_hdr: &mut enc_hdr::EncHdr) -> Result<(), Error> {
    // Check if any pending acknowledgements are pending for this exchange,
    // if so, piggy back in the encoded header here
    if let Some(pending_ack) = e.is_ack_pending() {
        enc_hdr.set_ack(pending_ack);
        e.clear_ack_pending();
    }

    // For now, let's always set reliable, not sure when it is unreliable
    enc_hdr.set_reliable();
    // Handling of retransmissions is pending

    Ok(())
}