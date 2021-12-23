use onoff_light::dev_att;
use matter::core;
use matter::data_model::device_types::device_type_add_on_off_light;

fn main() {
    env_logger::init();

    let dev_att = Box::new(dev_att::HardCodedDevAtt::new());

    let mut matter = core::Matter::new(dev_att).unwrap();
    let dm = matter.get_data_model();
    {
        let mut node = dm.node.write().unwrap();
        let endpoint = device_type_add_on_off_light(&mut node).unwrap();
        println!("Added OnOff Light Device type at endpoint id: {}", endpoint);
        println!("Data Model now is: {}", node);
    }

    matter.start_daemon().unwrap();
}
