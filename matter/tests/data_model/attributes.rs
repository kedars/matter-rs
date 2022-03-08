use matter::{
    data_model::cluster_on_off,
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::{
            ib::{AttrDataIn, AttrDataTag, AttrPath, AttrRespIn, AttrStatus},
            msg::ReadReq,
        },
        messages::{msg, GenericPath},
    },
    proto_demux::ProtoTx,
    tlv::{self, ElementType, TLVElement},
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

    let _ = im_engine(OpCode::ReadRequest, wb.as_slice(), &mut proto_tx);
    tlv::print_tlv_list(proto_tx.write_buf.as_slice());
    let root = tlv::get_root_node_struct(proto_tx.write_buf.as_slice()).unwrap();

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
                    assert_eq!(e_d.data, d.data);
                    assert_eq!(e_d.path, d.path);
                }
                _ => {
                    panic!("Invalid response, expected AttrRespIn::Data");
                }
            },
            ExpectedReportData::Status(e_s) => match inv_response {
                AttrRespIn::Status(s) => {}
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

#[test]
fn test_attr_read_success() {
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
