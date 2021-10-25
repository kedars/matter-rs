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

pub struct WriteBuf<'a> {
    pub buf: &'a mut[u8],
    pub write_off: usize,
}

impl<'a> WriteBuf<'a> {
    pub fn new(buf: &'a mut [u8], len: usize) -> WriteBuf<'a> {
        WriteBuf{buf: &mut buf[..len], write_off: 0}
    }

    pub fn len(&self) -> usize {
        self.write_off
    }

    pub fn copy_from_slice(&mut self, src: &[u8]) -> Result<(), Error> {
        let expected_len = self.write_off + src.len();
        if expected_len >= self.buf.len() {
            return Err(Error::NoSpace);
        }
        self.buf[self.write_off..expected_len].copy_from_slice(src);
        Ok(())
    }

    pub fn le_u8(& mut self, data: u8) -> Result<(), Error> {
        if self.buf.len() > 1 {
            self.buf[self.write_off] = data;
            self.write_off += 1;
            Ok(())
        } else {
            return Err(Error::NoSpace);
        }
    }
    pub fn le_u16(& mut self, data: u16) -> Result<(), Error> {
        if self.buf.len() > 2 {
            LittleEndian::write_u16(&mut self.buf[self.write_off..], data);
            self.write_off += 2;
            Ok(())
        } else {
            return Err(Error::NoSpace);
        }
    }

    pub fn le_u32(& mut self, data: u32) -> Result<(), Error> {
        if self.buf.len() > 4 {
            LittleEndian::write_u32(&mut self.buf[self.write_off..], data);
            self.write_off += 4;
            Ok(())
        } else {
            return Err(Error::NoSpace);
        }
    }

    pub fn le_u64(& mut self, data: u64) -> Result<(), Error> {
        if self.buf.len() > 8 {
            LittleEndian::write_u64(&mut self.buf[self.write_off..], data);
            self.write_off += 8;
            Ok(())
        } else {
            return Err(Error::NoSpace);
        }
    }
}
