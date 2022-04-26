use log::error;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Mutex, Once},
};

use crate::{
    error::Error,
    utils::{parsebuf::ParseBuf, writebuf::WriteBuf},
};

use super::{
    plain_hdr::{self, PlainHdr},
    proto_hdr::{self, ProtoHdr},
};

const MAX_POOL_SIZE: usize = 4;

pub const MAX_RX_BUF_SIZE: usize = 1583;
type Buffer = [u8; MAX_RX_BUF_SIZE];

// TODO: I am not very happy with this construction, need to find another way to do this
pub struct BufferPool {
    buffers: [Option<Buffer>; MAX_POOL_SIZE],
}

impl BufferPool {
    const INIT: Option<Buffer> = None;
    fn get() -> &'static Mutex<BufferPool> {
        static mut BUFFER_HOLDER: Option<Mutex<BufferPool>> = None;
        static ONCE: Once = Once::new();
        unsafe {
            ONCE.call_once(|| {
                BUFFER_HOLDER = Some(Mutex::new(BufferPool {
                    buffers: [BufferPool::INIT; MAX_POOL_SIZE],
                }));
            });
            BUFFER_HOLDER.as_ref().unwrap()
        }
    }

    pub fn alloc() -> Option<(usize, &'static mut Buffer)> {
        println!("Buffer Alloc called\n");

        let mut pool = BufferPool::get().lock().unwrap();
        for i in 0..MAX_POOL_SIZE {
            print!("{} ", pool.buffers[i].is_some());
        }
        println!("");
        for i in 0..MAX_POOL_SIZE {
            if pool.buffers[i].is_none() {
                pool.buffers[i] = Some([0; MAX_RX_BUF_SIZE]);
                // Sigh! to by-pass the borrow-checker telling us we are stealing a mutable reference
                // from under the lock
                // In this case the lock only protects against the setting of Some/None,
                // the objects then are independently accessed in a unique way
                let buffer = unsafe { &mut *(pool.buffers[i].as_mut().unwrap() as *mut Buffer) };
                return Some((i, buffer));
            }
        }
        None
    }

    pub fn free(index: usize) {
        println!("Buffer Free called\n");
        let mut pool = BufferPool::get().lock().unwrap();
        if pool.buffers[index].is_some() {
            pool.buffers[index] = None;
        }
    }
}

pub enum Direction<'a> {
    Tx(WriteBuf<'a>),
    Rx(ParseBuf<'a>),
}

pub struct Packet<'a> {
    pub plain: PlainHdr,
    pub proto: ProtoHdr,
    pub peer: SocketAddr,
    data: Direction<'a>,
    buffer_index: usize,
}

impl<'a> Packet<'a> {
    const HDR_RESERVE: usize = plain_hdr::max_plain_hdr_len() + proto_hdr::max_proto_hdr_len();

    pub fn new_rx() -> Result<Self, Error> {
        let (buffer_index, buffer) = BufferPool::alloc().ok_or(Error::NoSpace)?;
        let buf_len = buffer.len();
        Ok(Self {
            plain: Default::default(),
            proto: Default::default(),
            buffer_index,
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
            data: Direction::Rx(ParseBuf::new(buffer, buf_len)),
        })
    }

    pub fn new_tx() -> Result<Self, Error> {
        let (buffer_index, buffer) = BufferPool::alloc().ok_or(Error::NoSpace)?;
        let buf_len = buffer.len();

        let mut wb = WriteBuf::new(buffer, buf_len);
        wb.reserve(Packet::HDR_RESERVE)?;

        let mut p = Self {
            plain: Default::default(),
            proto: Default::default(),
            buffer_index,
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
            data: Direction::Tx(wb),
        };
        // Reliability on by default
        p.proto.set_reliable();
        Ok(p)
    }

    pub fn reset(&mut self) {
        self.plain = PlainHdr::default();
        self.proto = ProtoHdr::default();
        self.peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
        match &mut self.data {
            Direction::Rx(_pb) => {
                error!("Not yet implemented for Rx");
            }
            Direction::Tx(wb) => (wb.reset(Packet::HDR_RESERVE)),
        }
    }

    pub fn as_borrow_slice(&mut self) -> &mut [u8] {
        match &mut self.data {
            Direction::Rx(pb) => (pb.as_borrow_slice()),
            Direction::Tx(wb) => (wb.as_mut_slice()),
        }
    }

    pub fn get_parsebuf(&self) -> Result<&ParseBuf, Error> {
        if let Direction::Rx(pbuf) = &self.data {
            Ok(pbuf)
        } else {
            Err(Error::Invalid)
        }
    }

    pub fn get_writebuf(&mut self) -> Result<&mut WriteBuf<'a>, Error> {
        if let Direction::Tx(wbuf) = &mut self.data {
            Ok(wbuf)
        } else {
            Err(Error::Invalid)
        }
    }

    pub fn get_proto_id(&self) -> u16 {
        self.proto.proto_id
    }

    pub fn set_proto_id(&mut self, proto_id: u16) {
        self.proto.proto_id = proto_id;
    }

    pub fn get_proto_opcode(&self) -> u8 {
        self.proto.proto_opcode
    }

    pub fn set_proto_opcode(&mut self, proto_opcode: u8) {
        self.proto.proto_opcode = proto_opcode;
    }

    pub fn set_reliable(&mut self) {
        self.proto.set_reliable()
    }

    pub fn unset_reliable(&mut self) {
        self.proto.unset_reliable()
    }

    pub fn is_reliable(&mut self) -> bool {
        self.proto.is_reliable()
    }
}

impl<'a> Drop for Packet<'a> {
    fn drop(&mut self) {
        BufferPool::free(self.buffer_index);
        println!("Dropping Packet......");
    }
}

// A pool of Packet data structures
pub mod packet_pool {
    use boxslab::box_slab;

    box_slab!(PacketPool, super::Packet<'static>, { super::MAX_POOL_SIZE });
}
