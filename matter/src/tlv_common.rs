/* Tag Types */
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TagType {
    Anonymous,
    Context(u8),
    CommonPrf16(u16),
    CommonPrf32(u32),
    ImplPrf16(u16),
    ImplPrf32(u32),
    FullQual48(u64),
    FullQual64(u64),
}
pub const TAG_SHIFT_BITS: u8 = 5;
pub const TAG_MASK: u8 = 0xe0;
pub const TYPE_MASK: u8 = 0x1f;
pub const MAX_TAG_INDEX: usize = 8;

pub static TAG_SIZE_MAP: [usize; MAX_TAG_INDEX] = [
    0, // Anonymous
    1, // Context
    2, // CommonPrf16
    4, // CommonPrf32
    2, // ImplPrf16
    4, // ImplPrf32
    6, // FullQual48
    8, // FullQual64
];

// These versions of string only keep references within the
// original TLVList
// If you wish to have 'owned' versions, it would be good to implement
// FromTLV and ToTLV for Vec<u8> and String for Octet and UTF respectively
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct UtfStr<'a>(pub &'a [u8]);

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct OctetStr<'a>(pub &'a [u8]);
