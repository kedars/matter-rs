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


use matter::{
    data_model::{core::DataModel, objects::EncodeValue},
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::{
            ib::{AttrData, AttrPath, AttrStatus},
            msg::WriteReq,
        },
        messages::{msg, GenericPath},
    },
    tlv::{self, FromTLV, Nullable, TLVWriter, TagType, ToTLV},
    utils::writebuf::WriteBuf,
};

use crate::common::{
    echo_cluster::{self, TestChecker},
    im_engine::im_engine,
};

// Helper for handling Write Attribute sequences
fn handle_write_reqs(input: &[AttrData], expected: &[AttrStatus]) -> DataModel {
    let mut buf = [0u8; 400];
    let mut out_buf = [0u8; 400];

    let buf_len = buf.len();
    let mut wb = WriteBuf::new(&mut buf, buf_len);
    let mut tw = TLVWriter::new(&mut wb);

    let write_req = WriteReq::new(false, input);
    write_req.to_tlv(&mut tw, TagType::Anonymous).unwrap();

    let (dm, out_buf_len) = im_engine(OpCode::WriteRequest, wb.as_borrow_slice(), &mut out_buf);
    let out_buf = &out_buf[..out_buf_len];
    tlv::print_tlv_list(out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();

    let mut index = 0;
    let response_iter = root
        .find_tag(msg::WriteRespTag::WriteResponses as u32)
        .unwrap()
        .confirm_array()
        .unwrap()
        .enter()
        .unwrap();
    for response in response_iter {
        println!("Validating index {}", index);
        let status = AttrStatus::from_tlv(&response).unwrap();
        assert_eq!(expected[index], status);
        println!("Index {} success", index);
        index += 1;
    }
    assert_eq!(index, expected.len());
    dm
}

#[test]
/// This tests all the attribute list operations
/// add item, edit item, delete item, overwrite list, delete list
fn attr_list_ops() {
    let val0: u16 = 10;
    let val1: u16 = 15;
    let tc_handle = TestChecker::get().unwrap();

    let _ = env_logger::try_init();

    let delete_item = EncodeValue::Closure(&|tag, t| {
        let _ = t.null(tag);
    });
    let delete_all = EncodeValue::Closure(&|tag, t| {
        let _ = t.start_array(tag);
        let _ = t.end_container();
    });

    let att_data = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWriteList as u32),
    );
    let mut att_path = AttrPath::new(&att_data);

    // Test 1: Add Operation - add val0
    let input = &[AttrData::new(None, att_path, EncodeValue::Value(&val0))];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Sucess, 0)];
    let _ = handle_write_reqs(input, expected);

    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([Some(val0), None, None, None, None], tc.write_list);
    }

    // Test 2: Another Add Operation - add val1
    let input = &[AttrData::new(None, att_path, EncodeValue::Value(&val1))];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Sucess, 0)];
    let _ = handle_write_reqs(input, expected);

    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([Some(val0), Some(val1), None, None, None], tc.write_list);
    }

    // Test 3: Edit Operation - edit val1 to val0
    att_path.list_index = Some(Nullable::NotNull(1));
    let input = &[AttrData::new(None, att_path, EncodeValue::Value(&val0))];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Sucess, 0)];
    let _ = handle_write_reqs(input, expected);

    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([Some(val0), Some(val0), None, None, None], tc.write_list);
    }

    // Test 4: Delete Operation - delete index 0
    att_path.list_index = Some(Nullable::NotNull(0));
    let input = &[AttrData::new(None, att_path, delete_item)];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Sucess, 0)];
    let _ = handle_write_reqs(input, expected);

    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([None, Some(val0), None, None, None], tc.write_list);
    }

    // Test 5: Overwrite Operation - overwrite first 2 entries
    let overwrite_val: [u32; 2] = [20, 21];
    att_path.list_index = None;
    let input = &[AttrData::new(
        None,
        att_path,
        EncodeValue::Value(&overwrite_val),
    )];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Sucess, 0)];
    let _ = handle_write_reqs(input, expected);

    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([Some(20), Some(21), None, None, None], tc.write_list);
    }

    // Test 6: Overwrite Operation - delete whole list
    att_path.list_index = None;
    let input = &[AttrData::new(None, att_path, delete_all)];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Sucess, 0)];
    let _ = handle_write_reqs(input, expected);

    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([None, None, None, None, None], tc.write_list);
    }
}
