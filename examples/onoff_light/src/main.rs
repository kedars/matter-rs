mod dev_att;
use matter::core::{self, CommissioningData};
use matter::data_model::cluster_basic_information::BasicInfoConfig;
use matter::data_model::device_types::device_type_add_on_off_light;
use rand::prelude::*;

fn main() {
    env_logger::init();
    let mut comm_data = CommissioningData {
        // TODO: Hard-coded for now
        passwd: 123456,
        discriminator: 250,
        ..Default::default()
    };
    rand::thread_rng().fill_bytes(&mut comm_data.salt);

    // vid/pid should match those in the DAC
    let dev_info = BasicInfoConfig {
        vid: 0xFFF1,
        pid: 0x8002,
        hw_ver: 2,
        sw_ver: 1,
    };
    let dev_att = Box::new(dev_att::HardCodedDevAtt::new());

    let mut matter = core::Matter::new(dev_info, dev_att, comm_data).unwrap();
    let dm = matter.get_data_model();
    {
        let mut node = dm.node.write().unwrap();
        let endpoint = device_type_add_on_off_light(&mut node).unwrap();
        println!("Added OnOff Light Device type at endpoint id: {}", endpoint);
        println!("Data Model now is: {}", node);
    }

    matter.start_daemon().unwrap();
}
