use crate::transport::enc_hdr;
use crate::transport::exchange::*;
use crate::transport::plain_hdr;

pub fn on_msg_recv(e: &mut Exchange, plain_hdr: &plain_hdr::PlainHdr, enc_hdr: &enc_hdr::EncHdr) {
    if enc_hdr.is_ack() {
        // Acknowledgement handling to be implemented
    }

    if enc_hdr.is_reliable() {
        e.ack_pending(plain_hdr.ctr);
    }
}
