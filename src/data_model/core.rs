use std::sync::RwLock;
use crate::error::*;
use super::{device_types::device_type_add_root_node, objects::*};

pub struct DataModel {
    pub node: RwLock<Box<Node>>,
}

impl DataModel {
    pub fn new() -> Result<Self, Error> {
        let dm = DataModel{
            node: RwLock::new(Node::new()?)
        };
        {
            let mut node = dm.node.write()?;
            device_type_add_root_node(&mut node)?;
        }
        Ok(dm)
    }
}