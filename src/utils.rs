use byteorder::{ByteOrder, LittleEndian};

pub struct ParseBuf<'a> {
    pub buf: &'a [u8],
    pub read_off: usize,
}

impl<'a> ParseBuf<'a> {
    pub fn new(buf: &'a [u8], len: usize) -> ParseBuf<'a> {
        ParseBuf{buf: &buf[..len], read_off: 0}
    }

    pub fn le_u8(& mut self, data: &mut u8) -> Result<(), &'static str> {
        // RustQ: Is there a better idiomatic way to do this in Rust? 
        if self.buf.len() > 1 {
            *data = self.buf[self.read_off];
            self.read_off +=  1;
            Ok(())
        } else {
            return Err("Out of Bounds");
        }
    }

    pub fn le_u16(& mut self, data: &mut u16) -> Result<(), &'static str> {
        if self.buf.len() > 2 {
            *data = LittleEndian::read_u16(&self.buf[self.read_off..]);
            self.read_off += 2;
            Ok(())
        } else {
            return Err("Out of Bounds");
        }
    }

    pub fn le_u32(& mut self, data: &mut u32) -> Result<(), &'static str> {
        if self.buf.len() > 4 {
            *data = LittleEndian::read_u32(&self.buf[self.read_off..]);
            self.read_off += 4;
            Ok(())
        } else {
            return Err("Out of Bounds");
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

    pub fn le_u16(& mut self, data: u16) -> Result<(), &'static str> {
        if self.buf.len() > 2 {
            LittleEndian::write_u16(&mut self.buf[self.write_off..], data);
            self.write_off += 2;
            Ok(())
        } else {
            return Err("Out of Bounds");
        }
    }

    pub fn le_u32(& mut self, data: u32) -> Result<(), &'static str> {
        if self.buf.len() > 4 {
            LittleEndian::write_u32(&mut self.buf[self.write_off..], data);
            self.write_off += 4;
            Ok(())
        } else {
            return Err("Out of Bounds");
        }
    }

    pub fn le_u64(& mut self, data: u64) -> Result<(), &'static str> {
        if self.buf.len() > 8 {
            LittleEndian::write_u64(&mut self.buf[self.write_off..], data);
            self.write_off += 8;
            Ok(())
        } else {
            return Err("Out of Bounds");
        }
    }
}
