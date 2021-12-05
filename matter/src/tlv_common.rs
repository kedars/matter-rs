use num_derive::FromPrimitive;

/* Tag Types */
#[derive(FromPrimitive, Debug, Copy, Clone, PartialEq)]
pub enum TagType {
    Anonymous = 0,
    Context = 1,
    CommonPrf16 = 2,
    CommonPrf32 = 3,
    ImplPrf16 = 4,
    ImplPrf32 = 5,
    FullQual48 = 6,
    FullQual64 = 7,
    Last,
}
pub const TAG_SHIFT_BITS: u8 = 5;
pub const TAG_MASK: u8 = 0xe0;
pub const TYPE_MASK: u8 = 0x1f;

pub static TAG_SIZE_MAP: [usize; TagType::Last as usize] = [
    0, // Anonymous
    1, // Context
    2, // CommonPrf16
    4, // CommonPrf32
    2, // ImplPrf16
    4, // ImplPrf32
    6, // FullQual48
    8, // FullQual64
];
