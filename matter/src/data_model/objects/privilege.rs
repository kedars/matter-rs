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


use crate::{
    error::Error,
    tlv::{FromTLV, TLVElement, ToTLV},
};
use log::error;

use bitflags::bitflags;

bitflags! {
    #[derive(Default)]
    pub struct Privilege: u8 {
        const V = 0x01;
        const O = 0x02;
        const M = 0x04;
        const A = 0x08;

        const VIEW = Self::V.bits;
        const OPERATE = Self::V.bits | Self::O.bits;
        const MANAGE = Self::V.bits | Self::O.bits | Self::M.bits;
        const ADMIN = Self::V.bits | Self::O.bits| Self::M.bits| Self::A.bits;
    }
}

impl FromTLV<'_> for Privilege {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match t.u32()? {
            1 => Ok(Privilege::VIEW),
            2 => {
                error!("ProxyView privilege not yet supporteds");
                Err(Error::Invalid)
            }
            3 => Ok(Privilege::OPERATE),
            4 => Ok(Privilege::MANAGE),
            5 => Ok(Privilege::ADMIN),
            _ => Err(Error::Invalid),
        }
    }
}

impl ToTLV for Privilege {
    fn to_tlv(
        &self,
        tw: &mut crate::tlv::TLVWriter,
        tag: crate::tlv::TagType,
    ) -> Result<(), Error> {
        let val = if self.contains(Privilege::ADMIN) {
            5
        } else if self.contains(Privilege::OPERATE) {
            4
        } else if self.contains(Privilege::MANAGE) {
            3
        } else if self.contains(Privilege::VIEW) {
            1
        } else {
            0
        };
        tw.u8(tag, val)
    }
}
