use crate::error::*;
use byteorder::{ByteOrder, LittleEndian};

pub struct ParseBuf<'a> {
    pub buf: &'a mut [u8],
    pub read_off: usize,
}

impl<'a> ParseBuf<'a> {
    pub fn new(buf: &'a mut [u8], len: usize) -> ParseBuf<'a> {
        ParseBuf{buf: &mut buf[..len], read_off: 0}
    }

    // Reset the Parsebuf to a slice that starts at read_offset (making read_offset 0 in the process)
    // and ends at end_offset
    pub fn update(&'a mut self, end_offset: usize) {
        self.buf = &mut self.buf[self.read_off..end_offset];
        self.read_off = 0;
    }
    
    pub fn le_u8(& mut self) -> Result<u8, Error> {
        // RustQ: Is there a better idiomatic way to do this in Rust? 
        if self.buf.len() > 1 {
            let data: u8 = self.buf[self.read_off];
            self.read_off +=  1;
            Ok(data)
        } else {
            return Err(Error::TruncatedPacket);
        }
    }

    pub fn le_u16(& mut self) -> Result<u16, Error> {
        if self.buf.len() > 2 {
            let data: u16 = LittleEndian::read_u16(&self.buf[self.read_off..]);
            self.read_off += 2;
            Ok(data)
        } else {
            return Err(Error::TruncatedPacket);
        }
    }

    pub fn le_u32(& mut self) -> Result<u32, Error> {
        if self.buf.len() > 4 {
            let data: u32 = LittleEndian::read_u32(&self.buf[self.read_off..]);
            self.read_off += 4;
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
