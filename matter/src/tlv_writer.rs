use crate::{
    error::*,
    tlv_common::{TagType, TAG_SHIFT_BITS, TAG_SIZE_MAP},
    utils::writebuf::WriteBuf,
};

#[allow(dead_code)]
enum WriteElementType {
    S8 = 0,
    S16 = 1,
    S32 = 2,
    S64 = 3,
    U8 = 4,
    U16 = 5,
    U32 = 6,
    U64 = 7,
    False = 8,
    True = 9,
    F32 = 10,
    F64 = 11,
    Utf8l = 12,
    Utf16l = 13,
    Utf32l = 14,
    Utf64l = 15,
    Str8l = 16,
    Str16l = 17,
    Str32l = 18,
    Str64l = 19,
    Null = 20,
    Struct = 21,
    Array = 22,
    List = 23,
    EndCnt = 24,
    Last,
}

pub struct TLVWriter<'a, 'b> {
    buf: &'b mut WriteBuf<'a>,
}

impl<'a, 'b> TLVWriter<'a, 'b> {
    pub fn new(buf: &'b mut WriteBuf<'a>) -> Self {
        TLVWriter { buf }
    }

    // TODO: The current method of using writebuf's put methods force us to do
    // at max 3 checks while writing a single TLV (once for control, once for tag,
    // once for value), so do a single check and write the whole thing.
    #[inline(always)]
    fn put_control_tag(
        &mut self,
        tag_type: TagType,
        tag_val: u64,
        val_type: WriteElementType,
    ) -> Result<(), Error> {
        self.buf
            .le_u8(((tag_type as u8) << TAG_SHIFT_BITS) | (val_type as u8))?;
        if tag_type != TagType::Anonymous {
            self.buf.le_uint(TAG_SIZE_MAP[tag_type as usize], tag_val)?;
        }
        Ok(())
    }

    pub fn put_u8(&mut self, tag_type: TagType, tag_val: u64, data: u8) -> Result<(), Error> {
        self.put_control_tag(tag_type, tag_val, WriteElementType::U8)?;
        self.buf.le_u8(data)
    }

    pub fn put_u16(&mut self, tag_type: TagType, tag_val: u64, data: u16) -> Result<(), Error> {
        self.put_control_tag(tag_type, tag_val, WriteElementType::U16)?;
        self.buf.le_u16(data)
    }

    pub fn put_u32(&mut self, tag_type: TagType, tag_val: u64, data: u32) -> Result<(), Error> {
        self.put_control_tag(tag_type, tag_val, WriteElementType::U32)?;
        self.buf.le_u32(data)
    }

    pub fn put_str8(&mut self, tag_type: TagType, tag_val: u64, data: &[u8]) -> Result<(), Error> {
        self.put_control_tag(tag_type, tag_val, WriteElementType::Str8l)?;
        self.buf.le_u8(data.len() as u8)?;
        self.buf.copy_from_slice(data)
    }

    fn put_no_val(
        &mut self,
        tag_type: TagType,
        tag_val: u64,
        element: WriteElementType,
    ) -> Result<(), Error> {
        self.put_control_tag(tag_type, tag_val, element)
    }

    pub fn put_start_struct(&mut self, tag_type: TagType, tag_val: u64) -> Result<(), Error> {
        self.put_no_val(tag_type, tag_val, WriteElementType::Struct)
    }

    pub fn put_start_array(&mut self, tag_type: TagType, tag_val: u64) -> Result<(), Error> {
        self.put_no_val(tag_type, tag_val, WriteElementType::Array)
    }

    pub fn put_start_list(&mut self, tag_type: TagType, tag_val: u64) -> Result<(), Error> {
        self.put_no_val(tag_type, tag_val, WriteElementType::List)
    }

    pub fn put_end_container(&mut self) -> Result<(), Error> {
        self.put_no_val(TagType::Anonymous, 0, WriteElementType::EndCnt)
    }

    pub fn put_bool(&mut self, tag_type: TagType, tag_val: u64, val: bool) -> Result<(), Error> {
        if val {
            self.put_no_val(tag_type, tag_val, WriteElementType::True)
        } else {
            self.put_no_val(tag_type, tag_val, WriteElementType::False)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{tlv_common::*, utils::writebuf::WriteBuf};

    use super::TLVWriter;

    #[test]
    fn test_write_success() {
        let mut buf: [u8; 20] = [0; 20];
        let buf_len = buf.len();
        let mut writebuf = WriteBuf::new(&mut buf, buf_len);
        let mut tlvwriter = TLVWriter::new(&mut writebuf);

        tlvwriter.put_start_struct(TagType::Anonymous, 12).unwrap();
        tlvwriter.put_u8(TagType::Anonymous, 0, 12).unwrap();
        tlvwriter.put_u8(TagType::Context, 1, 13).unwrap();
        tlvwriter.put_u16(TagType::Anonymous, 0, 12).unwrap();
        tlvwriter.put_u16(TagType::Context, 2, 13).unwrap();
        tlvwriter.put_start_array(TagType::Context, 3).unwrap();
        tlvwriter.put_bool(TagType::Anonymous, 0, true).unwrap();
        tlvwriter.put_end_container().unwrap();
        tlvwriter.put_end_container().unwrap();
        assert_eq!(
            buf,
            [21, 4, 12, 36, 1, 13, 5, 12, 0, 37, 2, 13, 0, 54, 3, 9, 24, 24, 0, 0]
        );
    }

    #[test]
    fn test_write_overflow() {
        let mut buf: [u8; 6] = [0; 6];
        let buf_len = buf.len();
        let mut writebuf = WriteBuf::new(&mut buf, buf_len);
        let mut tlvwriter = TLVWriter::new(&mut writebuf);

        tlvwriter.put_u8(TagType::Anonymous, 0, 12).unwrap();
        tlvwriter.put_u8(TagType::Context, 1, 13).unwrap();
        match tlvwriter.put_u16(TagType::Anonymous, 0, 12) {
            Ok(_) => panic!("This should have returned error"),
            _ => (),
        }
        match tlvwriter.put_u16(TagType::Context, 2, 13) {
            Ok(_) => panic!("This should have returned error"),
            _ => (),
        }
        assert_eq!(buf, [4, 12, 36, 1, 13, 5]);
    }

    #[test]
    fn test_put_str8() {
        let mut buf: [u8; 20] = [0; 20];
        let buf_len = buf.len();
        let mut writebuf = WriteBuf::new(&mut buf, buf_len);
        let mut tlvwriter = TLVWriter::new(&mut writebuf);

        tlvwriter.put_u8(TagType::Context, 1, 13).unwrap();
        tlvwriter
            .put_str8(TagType::Anonymous, 0, &[10, 11, 12, 13, 14])
            .unwrap();
        tlvwriter.put_u16(TagType::Context, 2, 13).unwrap();
        tlvwriter
            .put_str8(TagType::Context, 3, &[20, 21, 22])
            .unwrap();
        assert_eq!(
            buf,
            [36, 1, 13, 16, 5, 10, 11, 12, 13, 14, 37, 2, 13, 0, 48, 3, 3, 20, 21, 22]
        );
    }
}
