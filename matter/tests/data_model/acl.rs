use matter::{
    acl::{AclEntry, AuthMode, Target},
    data_model::objects::{AttrValue, EncodeValue, Privilege},
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::{
            ib::{AttrData, AttrDataTag, AttrPath, AttrResp, AttrStatus},
            msg::{ReadReq, WriteReq},
        },
        messages::{msg, GenericPath},
    },
    tlv::{self, ElementType, FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
    utils::writebuf::WriteBuf,
};

use crate::{
    attr_data, attr_status,
    common::{
        attributes::*,
        echo_cluster::{self, ATTR_WRITE_DEFAULT_VALUE},
        im_engine::{ImEngine, ImInput},
    },
};

// Helper for handling Read Req sequences for this file
fn handle_read_reqs(
    im: &mut ImEngine,
    peer_node_id: u64,
    input: &[AttrPath],
    expected: &[AttrResp],
) {
    let mut buf = [0u8; 400];

    let buf_len = buf.len();
    let mut wb = WriteBuf::new(&mut buf, buf_len);
    let mut tw = TLVWriter::new(&mut wb);
    let mut out_buf = [0u8; 400];

    let read_req = ReadReq::new(true).set_attr_requests(input);
    read_req.to_tlv(&mut tw, TagType::Anonymous).unwrap();

    let mut input = ImInput::new(OpCode::ReadRequest, wb.as_borrow_slice());
    input.set_peer_node_id(peer_node_id);

    let out_buf_len = im.process(&input, &mut out_buf);
    let out_buf = &out_buf[..out_buf_len];
    assert_attr_report(out_buf, expected)
}

// Helper for handling Write Attribute sequences
fn handle_write_reqs(
    im: &mut ImEngine,
    peer_node_id: u64,
    input: &[AttrData],
    expected: &[AttrStatus],
) {
    let mut buf = [0u8; 400];
    let mut out_buf = [0u8; 400];

    let buf_len = buf.len();
    let mut wb = WriteBuf::new(&mut buf, buf_len);
    let mut tw = TLVWriter::new(&mut wb);

    let write_req = WriteReq::new(false, input);
    write_req.to_tlv(&mut tw, TagType::Anonymous).unwrap();

    let mut input = ImInput::new(OpCode::WriteRequest, wb.as_borrow_slice());
    input.set_peer_node_id(peer_node_id);
    let out_buf_len = im.process(&input, &mut out_buf);

    let out_buf = &out_buf[..out_buf_len];
    tlv::print_tlv_list(out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();

    let mut index = 0;
    let response_iter = root
        .find_tag(msg::WriteRespTag::WriteResponses as u32)
        .unwrap()
        .confirm_array()
        .unwrap()
        .iter()
        .unwrap();
    for response in response_iter {
        println!("Validating index {}", index);
        let status = AttrStatus::from_tlv(&response).unwrap();
        assert_eq!(expected[index], status);
        println!("Index {} success", index);
        index += 1;
    }
    assert_eq!(index, expected.len());
}

#[test]
/// Ensure that wildcard read attributes don't include error response
/// and silently drop the data when access is not granted
fn wc_read_attribute() {
    let _ = env_logger::try_init();

    let wc_att1 = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let ep1_att1 = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );

    let peer = 98765;
    let mut im = ImEngine::new();

    // Test1: Empty Response as no ACL matches
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[];
    handle_read_reqs(&mut im, peer, input, expected);

    // Add ACL to allow our peer to only access endpoint 0
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(0), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test2: Only Single response as only single endpoint is allowed
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[attr_data!(ep0_att1, ElementType::U16(0x1234))];
    handle_read_reqs(&mut im, peer, input, expected);

    // Add ACL to allow our peer to only access endpoint 1
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(1), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test3: Both responses are valid
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[
        attr_data!(ep0_att1, ElementType::U16(0x1234)),
        attr_data!(ep1_att1, ElementType::U16(0x1234)),
    ];
    handle_read_reqs(&mut im, peer, input, expected);
}

#[test]
/// Ensure that exact read attribute includes error response
/// when access is not granted
fn exact_read_attribute() {
    let _ = env_logger::try_init();

    let wc_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );

    let peer = 98765;
    let mut im = ImEngine::new();

    // Test1: Unsupported Access error as no ACL matches
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[attr_status!(&ep0_att1, IMStatusCode::UnsupportedAccess)];
    handle_read_reqs(&mut im, peer, input, expected);

    // Add ACL to allow our peer to access any endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test2: Only Single response as only single endpoint is allowed
    let input = &[AttrPath::new(&wc_att1)];
    let expected = &[attr_data!(ep0_att1, ElementType::U16(0x1234))];
    handle_read_reqs(&mut im, peer, input, expected);
}

fn read_cluster_id_write_attr(im: &ImEngine, endpoint: u16) -> AttrValue {
    let node = im.dm.node.read().unwrap();
    let echo = node.get_cluster(endpoint, echo_cluster::ID).unwrap();

    *echo
        .base()
        .read_attribute_raw(echo_cluster::Attributes::AttWrite as u16)
        .unwrap()
}

#[test]
/// Ensure that an write attribute with a wildcard either performs the operation,
/// if allowed, or silently drops the request
fn wc_write_attribute() {
    let _ = env_logger::try_init();
    let val0 = 10;
    let val1 = 20;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };
    let attr_data1 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val1);
    };

    let wc_att = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );
    let ep1_att = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );

    let input0 = &[AttrData::new(
        None,
        AttrPath::new(&wc_att),
        EncodeValue::Closure(&attr_data0),
    )];
    let input1 = &[AttrData::new(
        None,
        AttrPath::new(&wc_att),
        EncodeValue::Closure(&attr_data1),
    )];

    let peer = 98765;
    let mut im = ImEngine::new();

    // Test 1: Wildcard write to an attribute without permission should return
    // no error
    handle_write_reqs(&mut im, peer, input0, &[]);
    {
        let node = im.dm.node.read().unwrap();
        let echo = node.get_cluster(0, echo_cluster::ID).unwrap();
        assert_eq!(
            AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
            *echo
                .base()
                .read_attribute_raw(echo_cluster::Attributes::AttWrite as u16)
                .unwrap()
        );
    }

    // Add ACL to allow our peer to access one endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(0), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test 2: Wildcard write to attributes will only return attributes
    // where the writes were successful
    handle_write_reqs(
        &mut im,
        peer,
        input0,
        &[AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0)],
    );
    assert_eq!(AttrValue::Uint16(val0), read_cluster_id_write_attr(&im, 0));
    assert_eq!(
        AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
        read_cluster_id_write_attr(&im, 1)
    );

    // Add ACL to allow our peer to access another endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    acl.add_target(Target::new(Some(1), None, None)).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test 3: Wildcard write to attributes will return multiple attributes
    // where the writes were successful
    handle_write_reqs(
        &mut im,
        peer,
        input1,
        &[
            AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0),
            AttrStatus::new(&ep1_att, IMStatusCode::Sucess, 0),
        ],
    );
    assert_eq!(AttrValue::Uint16(val1), read_cluster_id_write_attr(&im, 0));
    assert_eq!(AttrValue::Uint16(val1), read_cluster_id_write_attr(&im, 1));
}

#[test]
/// Ensure that an write attribute without a wildcard returns an error when the
/// ACL disallows the access, and returns success once access is granted
fn exact_write_attribute() {
    let _ = env_logger::try_init();
    let val0 = 10;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttWrite as u32),
    );

    let input = &[AttrData::new(
        None,
        AttrPath::new(&ep0_att),
        EncodeValue::Closure(&attr_data0),
    )];
    let expected_fail = &[AttrStatus::new(
        &ep0_att,
        IMStatusCode::UnsupportedAccess,
        0,
    )];
    let expected_success = &[AttrStatus::new(&ep0_att, IMStatusCode::Sucess, 0)];

    let peer = 98765;
    let mut im = ImEngine::new();

    // Test 1: Exact write to an attribute without permission should return
    // Unsupported Access Error
    handle_write_reqs(&mut im, peer, input, expected_fail);
    assert_eq!(
        AttrValue::Uint16(ATTR_WRITE_DEFAULT_VALUE),
        read_cluster_id_write_attr(&im, 0)
    );

    // Add ACL to allow our peer to access any endpoint
    let mut acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(peer).unwrap();
    im.acl_mgr.add(acl).unwrap();

    // Test 1: Exact write to an attribute with permission should grant
    // access
    handle_write_reqs(&mut im, peer, input, expected_success);
    assert_eq!(AttrValue::Uint16(val0), read_cluster_id_write_attr(&im, 0));
}
