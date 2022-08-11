use matter::{
    interaction_model::{messages::ib::AttrResp, messages::msg},
    tlv::{self, FromTLV},
};

/// Assert that the data received in the outbuf matches our expectations
pub fn assert_attr_report(out_buf: &[u8], expected: &[AttrResp]) {
    tlv::print_tlv_list(out_buf);
    let root = tlv::get_root_node_struct(out_buf).unwrap();

    let mut index = 0;
    let response_iter = root
        .find_tag(msg::ReportDataTag::AttributeReports as u32)
        .unwrap()
        .confirm_array()
        .unwrap()
        .enter()
        .unwrap();
    for response in response_iter {
        println!("Validating index {}", index);
        let inv_response = AttrResp::from_tlv(&response).unwrap();
        match expected[index] {
            AttrResp::Data(e_d) => match inv_response {
                AttrResp::Data(d) => {
                    assert_eq!(e_d.path, d.path);
                    assert_eq!(e_d.data, d.data);
                }
                _ => {
                    panic!("Invalid response, expected AttrRespIn::Data");
                }
            },
            AttrResp::Status(e_s) => match inv_response {
                AttrResp::Status(s) => {
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

// We have to hard-code this here, and it should match the tag
// of the 'data' part in AttrData
pub const ATTR_DATA_TAG_DATA: u8 = 2;

#[macro_export]
macro_rules! attr_data {
    ($path:expr, $data:expr) => {
        AttrResp::Data(AttrData {
            data_ver: None,
            path: AttrPath {
                endpoint: $path.endpoint,
                cluster: $path.cluster,
                attr: $path.leaf.map(|x| x as u16),
                ..Default::default()
            },
            data: EncodeValue::Tlv(TLVElement::new(TagType::Context(ATTR_DATA_TAG_DATA), $data)),
        })
    };
}

#[macro_export]
macro_rules! attr_status {
    ($path:expr, $status:expr) => {
        AttrResp::Status(AttrStatus::new($path, $status, 0))
    };
}
