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

mod parser;
mod traits;
mod writer;

pub use matter_macro_derive::{FromTLV, ToTLV};
pub use parser::*;
pub use traits::*;
pub use writer::*;
