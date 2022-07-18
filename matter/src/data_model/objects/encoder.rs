use std::fmt::{Debug, Formatter};

use crate::{
    interaction_model::core::IMStatusCode,
    tlv::{TLVElement, TLVWriter, TagType, ToTLV},
};

type ValueGen<'a> = &'a dyn Fn(TagType, &mut TLVWriter) -> Result<(), IMStatusCode>;
pub trait ToTLVDebug: ToTLV + Debug {}

#[derive(Copy, Clone)]
pub enum EncodeValue<'a> {
    Closure(ValueGen<'a>),
    Tlv(TLVElement<'a>),
    Value(&'a dyn ToTLVDebug),
}

pub trait Encoder {
    fn encode(&mut self, value: EncodeValue);
    fn encode_status(&mut self, status: IMStatusCode, cluster_status: u16);
}

impl<'a> PartialEq for EncodeValue<'a> {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            EncodeValue::Closure(_) => false,
            EncodeValue::Tlv(a) => {
                if let EncodeValue::Tlv(b) = *other {
                    a == b
                } else {
                    false
                }
            }
            // Just claim false for now
            EncodeValue::Value(a) => false,
        }
    }
}

impl<'a> Debug for EncodeValue<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match *self {
            EncodeValue::Closure(_) => write!(f, "Contains closure"),
            EncodeValue::Tlv(t) => write!(f, "{:?}", t),
            EncodeValue::Value(v) => write!(f, "{:?}", v),
        }?;
        Ok(())
    }
}
