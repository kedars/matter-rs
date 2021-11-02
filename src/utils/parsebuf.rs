use crate::error::*;
use byteorder::{ByteOrder, LittleEndian};

pub struct ParseBuf<'a> {
    pub buf: &'a mut [u8],
    pub read_off: usize,
    pub left: usize,
}

impl<'a> ParseBuf<'a> {
    pub fn new(buf: &'a mut [u8], len: usize) -> ParseBuf<'a> {
        ParseBuf{buf: &mut buf[..len], read_off: 0, left: len}
    }

    // Return the data that is valid as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.read_off..(self.read_off + self.left)]
    }

    pub fn truncate(&mut self, truncate_by: usize) -> Result<(), Error> {
        if truncate_by < self.left {
            self.left -= truncate_by;
            Ok(())
        } else {
            return Err(Error::Invalid);
        }
    }

    fn advance(&mut self, len: usize) {
        self.read_off += len;
        self.left -= len;
    }

    pub fn le_u8(& mut self) -> Result<u8, Error> {
        // RustQ: Is there a better idiomatic way to do this in Rust? 
        if self.left > 1 {
            let data: u8 = self.buf[self.read_off];
            self.advance(1);
            Ok(data)
        } else {
            return Err(Error::TruncatedPacket);
        }
    }

    pub fn le_u16(& mut self) -> Result<u16, Error> {
        if self.left > 2 {
            let data: u16 = LittleEndian::read_u16(&self.buf[self.read_off..]);
            self.advance(2);
            Ok(data)
        } else {
            return Err(Error::TruncatedPacket);
        }
    }

    pub fn le_u32(& mut self) -> Result<u32, Error> {
        if self.left > 4 {
            let data: u32 = LittleEndian::read_u32(&self.buf[self.read_off..]);
            self.advance(4);
            Ok(data)
        } else {
            return Err(Error::TruncatedPacket);
        }
    }
}

