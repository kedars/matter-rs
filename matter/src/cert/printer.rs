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


use super::{CertConsumer, MAX_DEPTH};
use crate::error::Error;
use chrono::{TimeZone, Utc};
use std::fmt;

pub struct CertPrinter<'a, 'b> {
    level: usize,
    f: &'b mut fmt::Formatter<'a>,
}

impl<'a, 'b> CertPrinter<'a, 'b> {
    pub fn new(f: &'b mut fmt::Formatter<'a>) -> Self {
        Self { level: 0, f }
    }
}

const SPACE: [&str; MAX_DEPTH] = [
    "",
    "",
    "    ",
    "        ",
    "            ",
    "                ",
    "                    ",
    "                        ",
    "                            ",
    "                                ",
];

impl<'a, 'b> CertConsumer for CertPrinter<'a, 'b> {
    fn start_seq(&mut self, tag: &str) -> Result<(), Error> {
        if !tag.is_empty() {
            let _ = writeln!(self.f, "{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_seq(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn integer(&mut self, tag: &str, i: &[u8]) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {:x?}", SPACE[self.level], tag, i);
        Ok(())
    }
    fn utf8str(&mut self, tag: &str, s: &str) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {:x?}", SPACE[self.level], tag, s);
        Ok(())
    }
    fn bitstr(&mut self, tag: &str, _truncate: bool, s: &[u8]) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {:x?}", SPACE[self.level], tag, s);
        Ok(())
    }
    fn ostr(&mut self, tag: &str, s: &[u8]) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {:x?}", SPACE[self.level], tag, s);
        Ok(())
    }
    fn start_compound_ostr(&mut self, tag: &str) -> Result<(), Error> {
        if !tag.is_empty() {
            let _ = writeln!(self.f, "{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_compound_ostr(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn bool(&mut self, tag: &str, b: bool) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {}", SPACE[self.level], tag, b);
        Ok(())
    }
    fn start_set(&mut self, tag: &str) -> Result<(), Error> {
        if !tag.is_empty() {
            let _ = writeln!(self.f, "{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_set(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn ctx(&mut self, tag: &str, id: u8, val: &[u8]) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {}[{}]{:x?}", SPACE[self.level], tag, id, val);
        Ok(())
    }
    fn start_ctx(&mut self, tag: &str, val: u8) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} [{}]", SPACE[self.level], tag, val);
        self.level += 1;
        Ok(())
    }
    fn end_ctx(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn oid(&mut self, tag: &str, _oid: &[u8]) -> Result<(), Error> {
        if !tag.is_empty() {
            let _ = writeln!(self.f, "{} {}", SPACE[self.level], tag);
        }
        Ok(())
    }
    fn utctime(&mut self, tag: &str, epoch: u32) -> Result<(), Error> {
        let mut matter_epoch = Utc.ymd(2000, 1, 1).and_hms(0, 0, 0).timestamp();
        matter_epoch += epoch as i64;
        let _ = writeln!(
            self.f,
            "{} {} {}",
            SPACE[self.level],
            tag,
            Utc.timestamp(matter_epoch, 0)
        );
        Ok(())
    }
}
