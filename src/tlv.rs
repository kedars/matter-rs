use std::fmt;
use byteorder::{ByteOrder,LittleEndian};
use num;
use num_derive::FromPrimitive;

pub struct TLVList<'a> {
    buf: &'a [u8],
    len: usize,
}

impl<'a> TLVList<'a> {
    pub fn new(buf: &'a [u8], len: usize) -> TLVList<'a> {
        TLVList{buf, len}
    }
}

/* Tag Types */
#[derive(FromPrimitive, Debug, Copy, Clone, PartialEq)]
enum TagType {
    Anonymous   = 0,
    Context     = 1,
    CommonPrf16 = 2,
    CommonPrf32 = 3,
    ImplPrf16   = 4,
    ImplPrf32   = 5,
    FullQual48  = 6,
    FullQual64  = 7,
    Last,
}
const TAG_SHIFT_BITS:     u8 = 5;
const TAG_MASK:           u8 = 0xe0;

static TAG_SIZE_MAP: [usize; TagType::Last as usize]  = [
    // Anonymous
    0,
    // Context
    1,
    // CommonPrf16
    2,
    // CommonPrf32
    4,
    // ImplPrf16
    2,
    // ImplPrf32
    4,
    // FullQual48
    6,
    // FullQual64
    8
];

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Pointer<'a> {
    buf: &'a[u8],
    current: usize,
    left: usize,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ElementType<'a> {
    S8(i8),
    S16(i16),
    S32(i32),
    S64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    True,
    False,
    F32(f32),
    F64(f64),
    Utf8l,
    Utf16l,
    Utf32l,
    Utf64l,
    Str8l(&'a str),
    Str16l,
    Str32l,
    Str64l,
    Null,
    Struct(Pointer<'a>),
    Array(Pointer<'a>),
    List(Pointer<'a>),
    EndCnt,
    Last,
}

const TYPE_MASK:           u8 = 0x1f;

// The array indices here correspond to the numeric value of the Element Type as defined in the Matter Spec
static VALUE_SIZE_MAP: [usize; 25] = [
    // S8   0
    1,
    // S16  1
    2,
    // S32  2
    4,
    // S64  3
    8,
    // U8   4
    1,
    // U16  5
    2,
    // U32  6
    4,
    // U64  7
    8,
    // True 8
    0,
    // False 9
    0,
    // F32  10
    4,
    // F64  11
    8,
    // Utf8l 12
    1,
    // Utf16l  13
    2,
    // Utf32l 14
    4,
    // Utf64l 15
    8,
    // Str8l 16
    1,
    // Str16l 17
    2,
    // Str32l 18
    4,
    // Str64l 19
    8,
    // Null  20
    0,
    // Struct 21
    0,
    // Array  22
    0,
    // List  23
    0,
    // EndCnt  24
    0,
];

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TLVElement<'a> {
    tag_type: TagType,
    element_type: ElementType<'a>,
    tag: u32,
}

impl<'a> TLVElement<'a> {
    pub fn into_iter(&self) -> Option<TLVContainerIterator<'a>> {
        let ptr = match self.element_type {
            ElementType::Struct(a) | ElementType::Array(a) | ElementType::List(a)=> a,
            _ => return None,
        };
        let list_iter = TLVListIterator{
            buf: ptr.buf,
            current: ptr.current,
            left: ptr.left,
        };
        return Some(TLVContainerIterator{list_iter, prev_container: false, iterator_consumed: false});
    }

    pub fn get_u8(&self) -> Option<u8> {
        match self.element_type {
            ElementType::U8(a) => Some(a),
            _ => None,
        }
    }

    pub fn get_u16(&self) -> Option<u16> {
        match self.element_type {
            ElementType::U16(a) => Some(a),
            _ => None,
        }
    }

    pub fn get_u32(&self) -> Option<u32> {
        match self.element_type {
            ElementType::U32(a) => Some(a),
            _ => None,
        }
    }
    
    pub fn confirm_struct(&self) -> Option<TLVElement<'a>> {
        match self.element_type {
            ElementType::Struct(_) => Some(*self),
            _ => None,
        }
    }

    pub fn confirm_array(&self) -> Option<TLVElement<'a>> {
        match self.element_type {
            ElementType::Array(_) => Some(*self),
            _ => None,
        }
    }

    pub fn confirm_list(&self) -> Option<TLVElement<'a>> {
        match self.element_type {
            ElementType::List(_) => Some(*self),
            _ => None,
        }
    }

    pub fn find_element(&self, tag: u32) -> Option<TLVElement<'a>> {
        let mut iter = self.into_iter()?;
        loop {
            match iter.next() {
                Some(a) => if a.tag_type != TagType::Anonymous && a.tag == tag {return Some(a);},
                None => return None,
            }
        }
    }
}

impl<'a> fmt::Display for TLVElement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tag_type {
            TagType::Anonymous => (),
            _ => write!(f, "{}:", self.tag)?
        }
        match self.element_type {
            ElementType::Struct(_) => write!(f, "{{"),
            ElementType::Array(_) =>  write!(f, "["),
            ElementType::List(_)  =>  write!(f, "["),
            ElementType::EndCnt => write!(f, ">"),
            ElementType::True =>   write!(f, "True"),
            ElementType::False =>  write!(f, "False"),
            ElementType::Str8l(a) =>  write!(f, "{}", a),
            _ => write!(f, "{:?}", self.element_type),
        }
    }
}

// This is a TLV List iterator, it only iterates over the individual TLVs in a TLV list
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TLVListIterator<'a> {
    buf: &'a [u8],
    current: usize,
    left: usize,
}

impl<'a> TLVListIterator<'a> {
    fn advance(&mut self, len: usize) {
        self.current += len;
        self.left -= len;
    }

    // Caller should ensure they are reading the _right_ tag at the _right_ place
    fn read_this_tag(&mut self, tag_type: TagType) -> Option<u32> {
        let tag_size = TAG_SIZE_MAP[tag_type as usize];
        if tag_size > self.left {
            return None;
        }
        let tag: u32 = match tag_type {
            TagType::Anonymous => 0 as u32,
            TagType::Context => self.buf[self.current] as u32,
            TagType::CommonPrf16 | TagType::ImplPrf16 => LittleEndian::read_u16(&self.buf[self.current..]) as u32,
            TagType::CommonPrf32 | TagType::ImplPrf32  => LittleEndian::read_u32(&self.buf[self.current..]),
            TagType::FullQual48  => LittleEndian::read_u48(&self.buf[self.current..]) as u32,
            TagType::FullQual64  => LittleEndian::read_u64(&self.buf[self.current..]) as u32,
            _ => { return None; },
        };
        self.advance(tag_size);
        return Some(tag);
    }

    fn read_this_value(&mut self, element_type: u8) -> Option<ElementType<'a>> {
        let mut size = VALUE_SIZE_MAP[element_type as usize];
        if size > self.left {
            return None;
        }
        use ElementType::*;
        let element: ElementType = match element_type {
            0 => S8(self.buf[self.current] as i8),
            1 => S16(LittleEndian::read_i16(&self.buf[self.current..])),
            2 => S32(LittleEndian::read_i32(&self.buf[self.current..])),
            3 => S64(LittleEndian::read_i64(&self.buf[self.current..])),
            4 => U8(self.buf[self.current]),
            5 => U16(LittleEndian::read_u16(&self.buf[self.current..])),
            6 => U32(LittleEndian::read_u32(&self.buf[self.current..])),
            7 => U64(LittleEndian::read_u64(&self.buf[self.current..])),
            8 => True,
            9 => False,
            16 => {
                // The current byte is the string size
                let string_size: usize = self.buf[self.current] as usize;
                // Add this size to the size, since we'll consume that too
                size += string_size;
                if size > self.left {
                    return None;
                }
                Str8l(std::str::from_utf8(
                    &self.buf[(self.current + 1)..(self.current + string_size)])
                    .unwrap_or_default())
            },
            20 => Null,
            21 => Struct(Pointer{buf: &self.buf[..], current: self.current, left: self.left}),
            22 => Array(Pointer{buf: &self.buf[..], current: self.current, left: self.left}),
            23 => List(Pointer{buf: &self.buf[..], current: self.current, left: self.left}),
            24 => EndCnt,
            _ => {println!("Found invalid element: {}", element_type); return None;},
        };

        self.advance(size);
        return Some(element);
    }

}

impl<'a> TLVListIterator<'a> {

    /* Code for going to the next Element */
    pub fn next(& mut self) -> Option<TLVElement<'a>> {
        if self.left < 1 {
            return None;
        }
        /* Read Control */
        let control = self.buf[self.current];
        let tag_type = (control & TAG_MASK) >> TAG_SHIFT_BITS;
        let tag_type: TagType = num::FromPrimitive::from_u8(tag_type)?;
        let element_type = control & TYPE_MASK;
        self.advance(1);

        /* Consume Tag */
        let tag = self.read_this_tag(tag_type)?;

        /* Consume Value */
        let element_type = self.read_this_value(element_type)?;

        Some(TLVElement{tag_type, element_type, tag})
    }
}

impl<'a> TLVList<'a> {
    pub fn into_iter(&self) -> TLVListIterator<'a> {
        TLVListIterator{current : 0, left: self.len, buf: self.buf}
    }
}

fn is_container<'a>(element_type: ElementType<'a>) -> bool {
    match element_type {
        ElementType::Struct(_) | ElementType::Array(_) | ElementType::List(_) => true,
        _ => false,
    }
}

// This is a Container iterator, it iterates over containers in a TLV list
#[derive(Debug, PartialEq)]
pub struct TLVContainerIterator<'a> {
    list_iter: TLVListIterator<'a>,
    prev_container: bool,
    iterator_consumed: bool,
}

impl<'a> TLVContainerIterator<'a> {
    fn skip_to_end_of_container(& mut self) -> Option<TLVElement<'a>>{
        let mut nest_level = 0;
        while let Some(element) = self.list_iter.next() {
            // We know we are already in a container, we have to keep looking for end-of-container
//            println!("Skip: element: {:x?} nest_level: {}", element, nest_level);
            match element.element_type {
                ElementType::EndCnt => {
                    if nest_level == 0 {
                        // Return the element following this element
//                        println!("Returning");
                        // The final next() may be the end of the top-level container itself, if so, we must return None
                        let last_elem = self.list_iter.next()?;
                        match last_elem.element_type {
                            ElementType::EndCnt => {self.iterator_consumed = true; return None},
                            _ => return Some(last_elem),
                        }
                    } else {
                        nest_level -= 1;
                    }
                },
                _ => if is_container(element.element_type) { nest_level += 1; },
            }
        }
        None
    }
}

impl<'a> TLVContainerIterator<'a> {

    /* Code for going to the next Element */
    pub fn next(& mut self) -> Option<TLVElement<'a>> {
        // This iterator may be consumed, but the underlying might not. This protects it from such occurrences
        if self.iterator_consumed { return None; }
        let element: TLVElement = if self.prev_container == true {
//            println!("Calling skip to end of container");
            self.skip_to_end_of_container()?
        } else {
            self.list_iter.next()?
        };
//        println!("Found element: {:x?}", element);
        /* If we found end of container, that means our own container is over */
        match element.element_type {
            ElementType::EndCnt => {self.iterator_consumed = true; return None},
            _ => (),
        }
        if is_container(element.element_type) {
            self.prev_container = true;
        } else {
            self.prev_container = false;
        }
        Some(element)
    }
}

pub fn get_root_node_struct<'a>(b: &'a [u8]) -> Option<TLVElement<'a>> {
    return TLVList::new(&b, b.len()).into_iter().next()?.confirm_struct();
}

pub fn get_root_node_list<'a>(b: &'a [u8]) -> Option<TLVElement<'a>> {
    return TLVList::new(&b, b.len()).into_iter().next()?.confirm_list();
}

#[cfg(test)]
mod tests {
    use crate::tlv::*;
    use std::mem;

    #[test]
    fn test_short_length_tag() {
        // The 0x36 is an array with a tag, but we leave out the tag field
        let b = [ 0x15, 0x36];
        let tlvlist = TLVList::new(&b, b.len());
        let mut tlv_iter = tlvlist.into_iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_short_length_value_immediate() {
        // The 0x24 is a a tagged integer, here we leave out the integer value
        let b = [ 0x15, 0x24, 0x0];
        let tlvlist = TLVList::new(&b, b.len());
        let mut tlv_iter = tlvlist.into_iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_short_length_value_string() {
        // This is a tagged string, with tag 0 and length 0xb, but we only have 4 bytes in the string
        let b = [ 0x15, 0x30, 0x00, 0x0b, 0x73, 0x6d, 0x61, 0x72];
        let tlvlist = TLVList::new(&b, b.len());
        let mut tlv_iter = tlvlist.into_iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_valid_tag() {
        // The 0x36 is an array with a tag, here tag is 0
        let b = [ 0x15, 0x36, 0x0];
        let tlvlist = TLVList::new(&b, b.len());
        let mut tlv_iter = tlvlist.into_iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(),
                   Some(TLVElement{
                       tag_type: TagType::Context,
                       element_type: ElementType::Array(Pointer {
                           buf: &[21, 54, 0],
                           current: 3,
                           left: 0 }),
                       tag: 0 }
                   ));
    }

    #[test]
    fn test_valid_value_immediate() {
        // The 0x24 is a a tagged integer, here the integer is 2
        let b = [ 0x15, 0x24, 0x1, 0x2];
        let tlvlist = TLVList::new(&b, b.len());
        let mut tlv_iter = tlvlist.into_iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), Some(TLVElement{
            tag_type: TagType::Context,
            element_type: ElementType::U8(2),
            tag: 1 }));
    }

    #[test]
    fn test_valid_value_string() {
        // This is a tagged string, with tag 0 and length 4, and we have 4 bytes in the string
        let b = [ 0x15, 0x30, 0x5, 0x04, 0x73, 0x6d, 0x61, 0x72];
        let tlvlist = TLVList::new(&b, b.len());
        let mut tlv_iter = tlvlist.into_iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), Some(TLVElement {
            tag_type: TagType::Context,
            element_type: ElementType::Str8l("sma"),
            tag: 5 }));
    }

    #[test]
    fn test_no_iterator_for_int() {
        // The 0x24 is a a tagged integer, here the integer is 2
        let b = [ 0x15, 0x24, 0x1, 0x2];
        let tlvlist = TLVList::new(&b, b.len());
        let mut tlv_iter = tlvlist.into_iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next().unwrap().into_iter(), None);
    }

    #[test]
    fn test_struct_iteration_with_mix_values() {
        // This is a struct with 3 valid values
        let b = [ 0x15, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d, 0x61, 0x72];
        let mut root_iter = get_root_node_struct(&b).unwrap().into_iter().unwrap();
        assert_eq!(root_iter.next(), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U8(2), tag: 0 }));
        assert_eq!(root_iter.next(), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U32(135246), tag: 2 }));
        assert_eq!(root_iter.next(), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::Str8l("sma"), tag: 3 }));
    }

    #[test]
    fn test_struct_find_element_mix_values() {
        // This is a struct with 3 valid values
        let b = [ 0x15, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d, 0x61, 0x72];
        let root = get_root_node_struct(&b).unwrap();
            
        assert_eq!(root.find_element(0), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U8(2), tag: 0 }));
        assert_eq!(root.find_element(2), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U32(135246), tag: 2 }));
        assert_eq!(root.find_element(3), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::Str8l("sma"), tag: 3 }));
    }

    #[test]
    fn test_list_iteration_with_mix_values() {
        // This is a list with 3 valid values
        let b = [ 0x17, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d, 0x61, 0x72];
        let mut root_iter = get_root_node_list(&b).unwrap().into_iter().unwrap();
        assert_eq!(root_iter.next(), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U8(2), tag: 0 }));
        assert_eq!(root_iter.next(), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U32(135246), tag: 2 }));
        assert_eq!(root_iter.next(), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::Str8l("sma"), tag: 3 }));
    }

    #[test]
    fn test_complex_structure_invoke_cmd() {
        // This is what we typically get in an invoke command
        let b = [ 0x15,  0x36,   0x0,  0x15,  0x37,  0x0,  0x24,    0x0,  0x2, 0x24,    0x2,  0x6,  0x24,   0x3,  0x1, 0x18, 0x35,  0x1,  0x18, 0x18, 0x18, 0x18];

        let root = get_root_node_struct(&b).unwrap();

        let mut cmd_list_iter = root.find_element(0).unwrap().confirm_array().unwrap().into_iter().unwrap();
        println!("Command list iterator: {:?}", cmd_list_iter);

        // This is an array of CommandDataIB, but we'll only use the first element
        let cmd_data_ib = cmd_list_iter.next().unwrap();

        let cmd_path = cmd_data_ib.find_element(0).unwrap().confirm_list().unwrap();
        assert_eq!(cmd_path.find_element(0),Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U8(2), tag:0}));
        assert_eq!(cmd_path.find_element(2),Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U8(6), tag:2}));
        assert_eq!(cmd_path.find_element(3),Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U8(1), tag:3}));
        assert_eq!(cmd_path.find_element(1),None);

        // This is the variable of the invoke command
        assert_eq!(cmd_data_ib.find_element(1).unwrap().into_iter().unwrap().next(), None);
    }
    
    #[test]
    fn test_read_past_end_of_container() {
        let b = [ 0x15, 0x35, 0x0, 0x24, 0x1, 0x2, 0x18, 0x24, 0x0, 0x2, 0x18];

        let mut sub_root_iter = get_root_node_struct(&b).unwrap().find_element(0).unwrap().into_iter().unwrap();
        assert_eq!(sub_root_iter.next(), Some(TLVElement { tag_type: TagType::Context, element_type: ElementType::U8(2), tag: 1 }));
        assert_eq!(sub_root_iter.next(), None);
        // Call next, even after the first next returns None
        assert_eq!(sub_root_iter.next(), None);
        assert_eq!(sub_root_iter.next(), None);
    }

    #[test]
    fn test_basic_list_iterator() {
        // This is the input we have
        let b = [ 0x15,  0x36,   0x0,  0x15,  0x37,  0x0,  0x24,    0x0,  0x2, 0x24,    0x2,  0x6,  0x24,   0x3,  0x1, 0x18, 0x35,  0x1,  0x18, 0x18, 0x18, 0x18];

        let dummy_pointer = Pointer{buf: &b, current: 1, left: 21};
        // These are the decoded elements that we expect from this input
        let verify_matrix: [(TagType, ElementType); 13] = [
            (TagType::Anonymous, ElementType::Struct(dummy_pointer)),
            (TagType::Context,ElementType::Array(dummy_pointer)),
            (TagType::Anonymous,ElementType::Struct(dummy_pointer)),
            (TagType::Context,ElementType::List(dummy_pointer)),
            (TagType::Context,ElementType::U8(2)),
            (TagType::Context,ElementType::U8(6)),
            (TagType::Context,ElementType::U8(1)),
            (TagType::Anonymous,ElementType::EndCnt),
            (TagType::Context,ElementType::Struct(dummy_pointer)),
            (TagType::Anonymous,ElementType::EndCnt),
            (TagType::Anonymous,ElementType::EndCnt),
            (TagType::Anonymous,ElementType::EndCnt),
            (TagType::Anonymous,ElementType::EndCnt),
        ];

        let mut list_iter = TLVList::new(&b, b.len()).into_iter();
        let mut index = 0;
        loop {
            let element = list_iter.next();
            match element {
                None => break,
                Some(a) => {
                    assert_eq!(a.tag_type, verify_matrix[index].0);
                    assert_eq!(std::mem::discriminant(&a.element_type), std::mem::discriminant(&verify_matrix[index].1));
                }
            }
            index += 1;
        }
        // After the end, purposefully try a few more next
        assert_eq!(list_iter.next(), None);
        assert_eq!(list_iter.next(), None);
    }
}
