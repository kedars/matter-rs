use crate::{
    error::*,
    tlv_common::{OctetStr, TagType, UtfStr, TAG_SHIFT_BITS, TAG_SIZE_MAP},
    utils::writebuf::WriteBuf,
};
use log::error;
pub use matter_macro_derive::ToTLV;

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
        val_type: WriteElementType,
    ) -> Result<(), Error> {
        let (tag_id, tag_val) = match tag_type {
            TagType::Anonymous => (0_u8, 0),
            TagType::Context(v) => (1, v as u64),
            TagType::CommonPrf16(v) => (2, v as u64),
            TagType::CommonPrf32(v) => (3, v as u64),
            TagType::ImplPrf16(v) => (4, v as u64),
            TagType::ImplPrf32(v) => (5, v as u64),
            TagType::FullQual48(v) => (6, v as u64),
            TagType::FullQual64(v) => (7, v as u64),
        };
        self.buf
            .le_u8(((tag_id) << TAG_SHIFT_BITS) | (val_type as u8))?;
        if tag_type != TagType::Anonymous {
            self.buf.le_uint(TAG_SIZE_MAP[tag_id as usize], tag_val)?;
        }
        Ok(())
    }

    pub fn i8(&mut self, tag_type: TagType, data: i8) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::S8)?;
        self.buf.le_i8(data)
    }

    pub fn u8(&mut self, tag_type: TagType, data: u8) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::U8)?;
        self.buf.le_u8(data)
    }

    pub fn u16(&mut self, tag_type: TagType, data: u16) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::U16)?;
        self.buf.le_u16(data)
    }

    pub fn u32(&mut self, tag_type: TagType, data: u32) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::U32)?;
        self.buf.le_u32(data)
    }

    pub fn u64(&mut self, tag_type: TagType, data: u64) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::U64)?;
        self.buf.le_u64(data)
    }

    pub fn str8(&mut self, tag_type: TagType, data: &[u8]) -> Result<(), Error> {
        if data.len() > 256 {
            error!("use put_str16() instead");
            return Err(Error::Invalid);
        }
        self.put_control_tag(tag_type, WriteElementType::Str8l)?;
        self.buf.le_u8(data.len() as u8)?;
        self.buf.copy_from_slice(data)
    }

    pub fn str16(&mut self, tag_type: TagType, data: &[u8]) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::Str16l)?;
        self.buf.le_u16(data.len() as u16)?;
        self.buf.copy_from_slice(data)
    }

    pub fn utf8(&mut self, tag_type: TagType, data: &[u8]) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::Utf8l)?;
        self.buf.le_u8(data.len() as u8)?;
        self.buf.copy_from_slice(data)
    }

    pub fn utf16(&mut self, tag_type: TagType, data: &[u8]) -> Result<(), Error> {
        self.put_control_tag(tag_type, WriteElementType::Utf16l)?;
        self.buf.le_u16(data.len() as u16)?;
        self.buf.copy_from_slice(data)
    }

    fn no_val(&mut self, tag_type: TagType, element: WriteElementType) -> Result<(), Error> {
        self.put_control_tag(tag_type, element)
    }

    pub fn start_struct(&mut self, tag_type: TagType) -> Result<(), Error> {
        self.no_val(tag_type, WriteElementType::Struct)
    }

    pub fn start_array(&mut self, tag_type: TagType) -> Result<(), Error> {
        self.no_val(tag_type, WriteElementType::Array)
    }

    pub fn start_list(&mut self, tag_type: TagType) -> Result<(), Error> {
        self.no_val(tag_type, WriteElementType::List)
    }

    pub fn end_container(&mut self) -> Result<(), Error> {
        self.no_val(TagType::Anonymous, WriteElementType::EndCnt)
    }

    pub fn bool(&mut self, tag_type: TagType, val: bool) -> Result<(), Error> {
        if val {
            self.no_val(tag_type, WriteElementType::True)
        } else {
            self.no_val(tag_type, WriteElementType::False)
        }
    }

    pub fn object(&mut self, tag_type: TagType, object: &dyn ToTLV) -> Result<(), Error> {
        object.to_tlv(self, tag_type)
    }

    pub fn get_tail(&self) -> usize {
        self.buf.get_tail()
    }

    pub fn rewind_to(&mut self, anchor: usize) {
        self.buf.rewind_tail_to(anchor);
    }
}
pub trait ToTLV {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error>;
}

macro_rules! totlv_for {
    ($($t:ident)*) => {
        $(
            impl ToTLV for $t {
                fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
                    tw.$t(tag, *self)
                }
            }
        )*
    };
}

impl<'a, T: ToTLV> ToTLV for &'a [T] {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.start_array(tag)?;
        for i in *self {
            i.to_tlv(tw, TagType::Anonymous)?;
        }
        tw.end_container()
    }
}

// Generate ToTLV for standard data types
totlv_for!(i8 u8 u16 u32 u64 bool);

impl<'a> ToTLV for OctetStr<'a> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.str16(tag, self.0)
    }
}

impl<'a> ToTLV for UtfStr<'a> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        tw.utf16(tag, self.0)
    }
}

impl<T: ToTLV> ToTLV for Option<T> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag: TagType) -> Result<(), Error> {
        match self {
            Some(s) => (s.to_tlv(tw, tag)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TLVWriter;
    use crate::{error::Error, tlv_common::*, tlv_writer::ToTLV, utils::writebuf::WriteBuf};

    #[test]
    fn test_write_success() {
        let mut buf: [u8; 20] = [0; 20];
        let buf_len = buf.len();
        let mut writebuf = WriteBuf::new(&mut buf, buf_len);
        let mut tw = TLVWriter::new(&mut writebuf);

        tw.start_struct(TagType::Anonymous).unwrap();
        tw.u8(TagType::Anonymous, 12).unwrap();
        tw.u8(TagType::Context(1), 13).unwrap();
        tw.u16(TagType::Anonymous, 12).unwrap();
        tw.u16(TagType::Context(2), 13).unwrap();
        tw.start_array(TagType::Context(3)).unwrap();
        tw.bool(TagType::Anonymous, true).unwrap();
        tw.end_container().unwrap();
        tw.end_container().unwrap();
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
        let mut tw = TLVWriter::new(&mut writebuf);

        tw.u8(TagType::Anonymous, 12).unwrap();
        tw.u8(TagType::Context(1), 13).unwrap();
        match tw.u16(TagType::Anonymous, 12) {
            Ok(_) => panic!("This should have returned error"),
            _ => (),
        }
        match tw.u16(TagType::Context(2), 13) {
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
        let mut tw = TLVWriter::new(&mut writebuf);

        tw.u8(TagType::Context(1), 13).unwrap();
        tw.str8(TagType::Anonymous, &[10, 11, 12, 13, 14]).unwrap();
        tw.u16(TagType::Context(2), 13).unwrap();
        tw.str8(TagType::Context(3), &[20, 21, 22]).unwrap();
        assert_eq!(
            buf,
            [36, 1, 13, 16, 5, 10, 11, 12, 13, 14, 37, 2, 13, 0, 48, 3, 3, 20, 21, 22]
        );
    }

    #[derive(ToTLV)]
    struct TestDerive {
        a: u16,
        b: u32,
    }
    #[test]
    fn test_derive_totlv() {
        let mut buf: [u8; 20] = [0; 20];
        let buf_len = buf.len();
        let mut writebuf = WriteBuf::new(&mut buf, buf_len);
        let mut tw = TLVWriter::new(&mut writebuf);

        let abc = TestDerive { a: 10, b: 20 };
        abc.to_tlv(&mut tw, TagType::Anonymous).unwrap();
        assert_eq!(
            buf,
            [21, 37, 0, 10, 0, 38, 1, 20, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
