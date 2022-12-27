/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */


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

    pub fn set_len(&mut self, left: usize) {
        self.left = left;
    }

    // Return the data that is valid as a slice, consume self
    pub fn as_slice(self) -> &'a mut [u8] {
        &mut self.buf[self.read_off..(self.read_off + self.left)]
    }

    // Return the data that is valid as a slice
    pub fn as_borrow_slice(&mut self) -> &mut [u8] {
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
        Err(Error::TruncatedPacket)
    }

    fn advance(&mut self, len: usize) {
        self.read_off += len;
        self.left -= len;
    }

    pub fn parse_head_with<F, T>(&mut self, size: usize, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Self) -> T,
    {
        if self.left >= size {
            let data: T = f(self);
            self.advance(size);
            return Ok(data);
        }
        Err(Error::TruncatedPacket)
    }

    pub fn le_u8(&mut self) -> Result<u8, Error> {
        self.parse_head_with(1, |x| x.buf[x.read_off])
    }

    pub fn le_u16(&mut self) -> Result<u16, Error> {
        self.parse_head_with(2, |x| LittleEndian::read_u16(&x.buf[x.read_off..]))
    }

    pub fn le_u32(&mut self) -> Result<u32, Error> {
        self.parse_head_with(4, |x| LittleEndian::read_u32(&x.buf[x.read_off..]))
    }

    pub fn le_u64(&mut self) -> Result<u64, Error> {
        self.parse_head_with(8, |x| LittleEndian::read_u64(&x.buf[x.read_off..]))
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::parsebuf::*;

    #[test]
    fn test_parse_with_success() {
        let mut test_slice: [u8; 11] = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb, 0xc, 0xd];
        let mut buf = ParseBuf::new(&mut test_slice, 11);

        assert_eq!(buf.le_u8().unwrap(), 0x01);
        assert_eq!(buf.le_u16().unwrap(), 65);
        assert_eq!(buf.le_u32().unwrap(), 0xcafebabe);
        assert_eq!(buf.as_slice(), [0xa, 0xb, 0xc, 0xd]);
    }

    #[test]
    fn test_parse_with_overrun() {
        let mut test_slice: [u8; 2] = [0x01, 65];
        let mut buf = ParseBuf::new(&mut test_slice, 2);

        assert_eq!(buf.le_u8().unwrap(), 0x01);

        match buf.le_u16() {
            Ok(_) => panic!("This should have returned error"),
            Err(_) => (),
        }

        match buf.le_u32() {
            Ok(_) => panic!("This should have returned error"),
            Err(_) => (),
        }

        // Now consume the leftover byte
        assert_eq!(buf.le_u8().unwrap(), 65);

        match buf.le_u8() {
            Ok(_) => panic!("This should have returned error"),
            Err(_) => (),
        }
        assert_eq!(buf.as_slice(), []);
    }

    #[test]
    fn test_tail_with_success() {
        let mut test_slice: [u8; 11] = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb, 0xc, 0xd];
        let mut buf = ParseBuf::new(&mut test_slice, 11);

        assert_eq!(buf.le_u8().unwrap(), 0x01);
        assert_eq!(buf.le_u16().unwrap(), 65);
        assert_eq!(buf.le_u32().unwrap(), 0xcafebabe);

        assert_eq!(buf.tail(2).unwrap(), [0xc, 0xd]);
        assert_eq!(buf.as_borrow_slice(), [0xa, 0xb]);

        assert_eq!(buf.tail(2).unwrap(), [0xa, 0xb]);
        assert_eq!(buf.as_slice(), []);
    }

    #[test]
    fn test_tail_with_overrun() {
        let mut test_slice: [u8; 11] = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb, 0xc, 0xd];
        let mut buf = ParseBuf::new(&mut test_slice, 11);

        assert_eq!(buf.le_u8().unwrap(), 0x01);
        assert_eq!(buf.le_u16().unwrap(), 65);
        assert_eq!(buf.le_u32().unwrap(), 0xcafebabe);
        match buf.tail(5) {
            Ok(_) => panic!("This should have returned error"),
            Err(_) => (),
        }
        assert_eq!(buf.tail(2).unwrap(), [0xc, 0xd]);
    }

    #[test]
    fn test_parsed_as_slice() {
        let mut test_slice: [u8; 11] = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb, 0xc, 0xd];
        let mut buf = ParseBuf::new(&mut test_slice, 11);

        assert_eq!(buf.parsed_as_slice(), []);
        assert_eq!(buf.le_u8().unwrap(), 0x1);
        assert_eq!(buf.le_u16().unwrap(), 65);
        assert_eq!(buf.le_u32().unwrap(), 0xcafebabe);
        assert_eq!(buf.parsed_as_slice(), [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca]);
    }
}
