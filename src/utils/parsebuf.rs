use crate::error::*;
use byteorder::{ByteOrder, LittleEndian};

pub struct ParseBuf<'a> {
    buf: &'a mut [u8],
    read_off: usize,
    left: usize,
}

impl<'a> ParseBuf<'a> {
    pub fn new(buf: &'a mut [u8], len: usize) -> ParseBuf<'a> {
        ParseBuf {
            buf: &mut buf[..len],
            read_off: 0,
            left: len,
        }
    }

    // Return the data that is valid as a slice
    pub fn as_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.read_off..(self.read_off + self.left)]
    }

    pub fn parsed_as_slice(&self) -> &[u8] {
        &self.buf[0..self.read_off]
    }

    pub fn tail(&mut self, size: usize) -> Result<&[u8], Error> {
        if size <= self.left {
            let end_offset = self.read_off + self.left;
            let tail = &self.buf[(end_offset - size)..end_offset];
            self.left -= size;
            return Ok(tail);
        }
        return Err(Error::TruncatedPacket);
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

    pub fn parse_head_with<F, T>(&mut self, size: usize, f: F) -> Result<T, Error>
                            where F: FnOnce(&mut Self) -> T {
        if self.left > size {
            let data: T = f(self);
            self.advance(size);
            return Ok(data);
        }
        Err(Error::TruncatedPacket)
    }

    pub fn le_u8(&mut self) -> Result<u8, Error> {
        self.parse_head_with(1, |x| {
            x.buf[x.read_off]
        })
    }

    pub fn le_u16(&mut self) -> Result<u16, Error> {
        self.parse_head_with(2, |x| {
            LittleEndian::read_u16(&x.buf[x.read_off..])
        })
    }

    pub fn le_u32(&mut self) -> Result<u32, Error> {
        self.parse_head_with(4, |x| {
            LittleEndian::read_u32(&x.buf[x.read_off..])
        })
    }
}
