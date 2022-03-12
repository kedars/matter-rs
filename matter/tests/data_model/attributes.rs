use matter::{
    data_model::{cluster_on_off, objects::GlobalElements},
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::{
            ib::{AttrDataIn, AttrDataTag, AttrPath, AttrRespIn, AttrStatus},
            msg::ReadReq,
        },
        messages::{msg, GenericPath},
    },
    proto_demux::ProtoTx,
    tlv::{self, ElementType, TLVElement, TLVList},
    tlv_common::TagType,
    tlv_writer::TLVWriter,
    utils::writebuf::WriteBuf,
};

use crate::common::{echo_cluster, im_engine::im_engine};

enum ExpectedReportData<'a> {
    Data(AttrDataIn<'a>),
    Status(AttrStatus),
}

// Helper for handling Invoke Command sequences
fn handle_read_reqs(input: &[AttrPath], expected: &[ExpectedReportData]) {
    let mut buf = [0u8; 400];

    let buf_len = buf.len();
    let mut wb = WriteBuf::new(&mut buf, buf_len);
    let mut tw = TLVWriter::new(&mut wb);
    let mut out_buf = [0u8; 400];
    let mut proto_tx = ProtoTx::new(&mut out_buf, 0).unwrap();

    let read_req = ReadReq::new(true).set_attr_requests(input);
    tw.put_object(TagType::Anonymous, &read_req).unwrap();

    let _ = im_engine(OpCode::ReadRequest, wb.as_borrow_slice(), &mut proto_tx);
    tlv::print_tlv_list(proto_tx.write_buf.as_borrow_slice());
    let root = tlv::get_root_node_struct(proto_tx.write_buf.as_borrow_slice()).unwrap();

    let mut index = 0;
    let response_iter = root
        .find_tag(msg::ReportDataTag::AttributeReports as u32)
        .unwrap()
        .confirm_array()
        .unwrap()
        .iter()
        .unwrap();
    for response in response_iter {
        println!("Validating index {}", index);
        let inv_response = AttrRespIn::from_tlv(&response).unwrap();
        match expected[index] {
            ExpectedReportData::Data(e_d) => match inv_response {
                AttrRespIn::Data(d) => {
                    assert_eq!(e_d.path, d.path);
                    assert_eq!(e_d.data, d.data);
                }
                _ => {
                    panic!("Invalid response, expected AttrRespIn::Data");
                }
            },
            ExpectedReportData::Status(e_s) => match inv_response {
                AttrRespIn::Status(s) => {
                    assert_eq!(e_s, s);
                }
                _ => {
                    panic!("Invalid response, expected AttrRespIn::Status");
                }
            },
        }
        println!("Index {} success", index);
        index += 1;
    }
    assert_eq!(index, expected.len());
}

macro_rules! attr_data {
    ($path:expr, $data:expr) => {
        ExpectedReportData::Data(AttrDataIn {
            data_ver: None,
            path: AttrPath {
                path: $path,
                ..Default::default()
            },
            data: TLVElement::new(TagType::Context(AttrDataTag::Data as u8), $data),
        })
    };
}

macro_rules! attr_status {
    ($path:expr, $status:expr) => {
        ExpectedReportData::Status(AttrStatus::new($path, $status, 0))
    };
}

#[test]
fn test_read_success() {
    // 3 Attr Read Requests
    // - first on endpoint 0, att1
    // - second on endpoint 1, att2
    // - third on endpoint 1, attcustom a custom attribute
    let _ = env_logger::try_init();

    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let ep1_att2 = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att2 as u32),
    );
    let ep1_attcustom = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::AttCustom as u32),
    );
    let input = &[
        AttrPath::new(&ep0_att1),
        AttrPath::new(&ep1_att2),
        AttrPath::new(&ep1_attcustom),
    ];
    let expected = &[
        attr_data!(ep0_att1, ElementType::U16(0x1234)),
        attr_data!(ep1_att2, ElementType::U16(0x5678)),
        attr_data!(
            ep1_attcustom,
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
    ];
    handle_read_reqs(input, expected);
}

#[test]
fn test_read_unsupported_fields() {
    // 6 reads
    // - endpoint doesn't exist - UnsupportedEndpoint
    // - cluster doesn't exist - UnsupportedCluster
    // - cluster doesn't exist and endpoint is wildcard - UnsupportedCluster
    // - attribute doesn't exist - UnsupportedAttribute
    // - attribute doesn't exist and endpoint is wildcard - UnsupportedAttribute
    // - attribute doesn't exist and cluster is wildcard - UnsupportedAttribute
    let _ = env_logger::try_init();

    let invalid_endpoint = GenericPath::new(
        Some(2),
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let invalid_cluster = GenericPath::new(
        Some(0),
        Some(0x1234),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let invalid_cluster_wc_endpoint = GenericPath::new(
        None,
        Some(0x1234),
        Some(echo_cluster::Attributes::AttCustom as u32),
    );
    let invalid_attribute = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(0x1234));
    let invalid_attribute_wc_endpoint =
        GenericPath::new(None, Some(echo_cluster::ID), Some(0x1234));
    let invalid_attribute_wc_cluster = GenericPath::new(Some(0), None, Some(0x1234));
    let input = &[
        AttrPath::new(&invalid_endpoint),
        AttrPath::new(&invalid_cluster),
        AttrPath::new(&invalid_cluster_wc_endpoint),
        AttrPath::new(&invalid_attribute),
        AttrPath::new(&invalid_attribute_wc_endpoint),
        AttrPath::new(&invalid_attribute_wc_cluster),
    ];

    let expected = &[
        attr_status!(&invalid_endpoint, IMStatusCode::UnsupportedEndpoint),
        attr_status!(&invalid_cluster, IMStatusCode::UnsupportedCluster),
        attr_status!(
            &invalid_cluster_wc_endpoint,
            IMStatusCode::UnsupportedCluster
        ),
        attr_status!(&invalid_attribute, IMStatusCode::UnsupportedAttribute),
        attr_status!(
            &invalid_attribute_wc_endpoint,
            IMStatusCode::UnsupportedAttribute
        ),
        attr_status!(
            &invalid_attribute_wc_cluster,
            IMStatusCode::UnsupportedAttribute
        ),
    ];
    handle_read_reqs(input, expected);
}

#[test]
fn test_read_wc_endpoint_all_have_clusters() {
    // 1 Attr Read Requests
    // - wildcard endpoint, att1
    // - 2 responses are expected
    let _ = env_logger::try_init();

    let wc_ep_att1 = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Attributes::Att1 as u32),
    );
    let input = &[AttrPath::new(&wc_ep_att1)];

    let expected = &[
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att1 as u32)
            ),
            ElementType::U16(0x1234)
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att1 as u32)
            ),
            ElementType::U16(0x1234)
        ),
    ];
    handle_read_reqs(input, expected);
}

#[test]
fn test_read_wc_endpoint_only_1_has_cluster() {
    // 1 Attr Read Requests
    // - wildcard endpoint, on/off Cluster OnOff Attribute
    // - 1 response are expected
    let _ = env_logger::try_init();

    let wc_ep_onoff = GenericPath::new(
        None,
        Some(cluster_on_off::ID),
        Some(cluster_on_off::Attributes::OnOff as u32),
    );
    let input = &[AttrPath::new(&wc_ep_onoff)];

    let expected = &[attr_data!(
        GenericPath::new(
            Some(1),
            Some(cluster_on_off::ID),
            Some(cluster_on_off::Attributes::OnOff as u32)
        ),
        ElementType::False
    )];
    handle_read_reqs(input, expected);
}

fn get_tlvs<'a>(buf: &'a mut [u8], data: &[u16]) -> TLVElement<'a> {
    let buf_len = buf.len();
    let mut wb = WriteBuf::new(buf, buf_len);
    let mut tw = TLVWriter::new(&mut wb);
    let _ = tw.put_start_array(TagType::Context(2));
    for e in data {
        let _ = tw.put_u16(TagType::Anonymous, *e);
    }
    let _ = tw.put_end_container();
    let wb_len = wb.as_borrow_slice().len();
    let tlv_array = TLVList::new(wb.as_slice(), wb_len).iter().next().unwrap();
    tlv_array
}

#[test]
fn test_read_wc_endpoint_wc_attribute() {
    // 1 Attr Read Request
    // - wildcard endpoint, wildcard attribute
    // - 8 responses are expected, 1+3 attributes on endpoint 0, 1+3 on endpoint 1
    let _ = env_logger::try_init();
    let wc_ep_wc_attr = GenericPath::new(None, Some(echo_cluster::ID), None);
    let input = &[AttrPath::new(&wc_ep_wc_attr)];

    let mut buf = [0u8; 100];
    let attr_list_tlvs = get_tlvs(
        &mut buf,
        &[
            GlobalElements::AttributeList as u16,
            echo_cluster::Attributes::Att1 as u16,
            echo_cluster::Attributes::Att2 as u16,
            echo_cluster::Attributes::AttCustom as u16,
        ],
    );

    let expected = &[
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(GlobalElements::AttributeList as u32),
            ),
            attr_list_tlvs.get_element_type()
        ),
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att1 as u32),
            ),
            ElementType::U16(0x1234)
        ),
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att2 as u32),
            ),
            ElementType::U16(0x5678)
        ),
        attr_data!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::AttCustom as u32),
            ),
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(GlobalElements::AttributeList as u32),
            ),
            attr_list_tlvs.get_element_type()
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att1 as u32),
            ),
            ElementType::U16(0x1234)
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::Att2 as u32),
            ),
            ElementType::U16(0x5678)
        ),
        attr_data!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::Attributes::AttCustom as u32),
            ),
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
    ];
    handle_read_reqs(input, expected);
}
