use super::{
    cluster_basic_information::BasicInfoConfig,
    device_types::device_type_add_root_node,
    objects::{self, *},
    sdm::dev_att::DevAttDataFetcher,
    system_model::descriptor::DescriptorCluster,
};
use crate::{
    error::*,
    fabric::FabricMgr,
    interaction_model::{
        command::CommandReq,
        core::IMStatusCode,
        messages::{
            ib::{self, AttrDataIn, AttrPath},
            GenericPath,
        },
        InteractionConsumer, Transaction,
    },
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};
use log::{error, info};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub struct DataModel {
    pub node: Arc<RwLock<Box<Node>>>,
}

impl DataModel {
    pub fn new(
        dev_details: BasicInfoConfig,
        dev_att: Box<dyn DevAttDataFetcher>,
        fabric_mgr: Arc<FabricMgr>,
    ) -> Result<Self, Error> {
        let dm = DataModel {
            node: Arc::new(RwLock::new(Node::new()?)),
        };
        {
            let mut node = dm.node.write()?;
            node.set_changes_cb(Box::new(dm.clone()));
            device_type_add_root_node(&mut node, dev_details, dev_att, fabric_mgr)?;
        }
        Ok(dm)
    }

    // A valid attribute on a valid cluster should be encoded. Both wildcard and non-wildcard paths end up calling this API
    fn handle_write_attr_data(
        c: &mut dyn ClusterType,
        tw: &mut TLVWriter,
        path: &GenericPath,
        data: &TLVElement,
        attr_id: u16,
    ) {
        let result = c.write_attribute(data, attr_id);
        if let Err(e) = result {
            let attr_status = ib::AttrStatus::new(path, e, 0);
            let _ = tw.put_object(TagType::Anonymous, &attr_status);
        }
    }

    // Encode a write attribute from a path that may or may not be wildcard
    fn handle_write_attr_path(
        node: &mut RwLockWriteGuard<Box<Node>>,
        attr_data: &AttrDataIn,
        tw: &mut TLVWriter,
    ) {
        if let Ok((e, c, a)) = attr_data.path.path.not_wildcard() {
            // The non-wildcard path
            let cluster = node.get_cluster_mut(e, c);
            match cluster {
                Ok(cluster) => DataModel::handle_write_attr_data(
                    cluster,
                    tw,
                    &attr_data.path.path,
                    &attr_data.data,
                    a as u16,
                ),
                Err(e) => {
                    let attr_status = ib::AttrStatus::new(&attr_data.path.path, e.into(), 0);
                    let attr_resp = ib::AttrRespOut::Status(attr_status, ib::attr_resp_dummy);
                    let _ = tw.put_object(TagType::Anonymous, &attr_resp);
                }
            }
        } else {
            // The wildcard path
            if attr_data.path.path.cluster.is_none() || attr_data.path.path.leaf.is_none() {
                error!("Cluster/Attribute cannot be wildcard in Write Interaction");
                let attr_status = ib::AttrStatus::new(
                    &attr_data.path.path,
                    IMStatusCode::UnsupportedAttribute,
                    0,
                );
                let _ = tw.put_object(TagType::Anonymous, &attr_status);
                return;
            }

            node.for_each_cluster_mut(&attr_data.path.path, |path, c| {
                let attr_id = if let Some(a) = path.leaf { a } else { 0 } as u16;
                DataModel::handle_write_attr_data(c, tw, path, &attr_data.data, attr_id);
            });
        }
    }

    // A valid attribute on a valid cluster should be encoded. Both wildcard and non-wildcard paths end up calling this API
    // Note that it is possibe that some internal checks don't match even at this stage (read on a write-only attribute, invalid attr-id).
    // If there was an error, we rewind, so the TLVWriter doesn't include any half-baked data about the 'AttrData' IB
    fn handle_read_attr_data(
        c: &dyn ClusterType,
        tw: &mut TLVWriter,
        path: AttrPath,
        attr_id: u16,
    ) -> Result<(), IMStatusCode> {
        let anchor = tw.get_tail();
        let data = |tag: TagType, tw: &mut TLVWriter| Cluster::read_attribute(c, tag, tw, attr_id);

        let attr_resp = ib::AttrRespOut::new(c.base().get_dataver(), &path, data);
        let result = attr_resp.write_tlv(tw, TagType::Anonymous);
        if result.is_err() {
            tw.rewind_to(anchor);
        }
        result
    }

    // Encode a read attribute from a path that may or may not be wildcard
    fn handle_read_attr_path(
        node: &RwLockReadGuard<Box<Node>>,
        attr_path: AttrPath,
        tw: &mut TLVWriter,
    ) {
        if let Ok((e, c, a)) = attr_path.path.not_wildcard() {
            // The non-wildcard path
            let cluster = node.get_cluster(e, c);
            let result = match cluster {
                Ok(cluster) => DataModel::handle_read_attr_data(cluster, tw, attr_path, a as u16),
                Err(e) => Err(e.into()),
            };

            if let Err(e) = result {
                let attr_status = ib::AttrStatus::new(&attr_path.path, e, 0);
                let attr_resp = ib::AttrRespOut::Status(attr_status, ib::attr_resp_dummy);
                let _ = tw.put_object(TagType::Anonymous, &attr_resp);
            }
        } else {
            // The wildcard path
            node.for_each_attribute(&attr_path.path, |path, c| {
                let attr_id = if let Some(a) = path.leaf { a } else { 0 } as u16;
                let path = ib::AttrPath::new(path);
                // Note: In the case of wildcard scenario, we do NOT encode AttrStatus in case of errors
                // This is as per the spec, because we don't want ot encode UnsupportedRead/UnsupportedWrite type of errors

                // TODO: It is likely that there may be genuine cases where the error code needs to be encoded
                // in this response. If such a thing is desirable, we'll have to make the wildcard traversal
                // routines 'Access' aware, so that they only provide attributes that are compatible with the
                // operation under consideration (Access:RV for read, Access:W*for write)
                let _ = DataModel::handle_read_attr_data(c, tw, path, attr_id);
            });
        }
    }

    // Handle command from a path that may or may not be wildcard
    fn handle_command_path(node: &mut RwLockWriteGuard<Box<Node>>, cmd_req: &mut CommandReq) {
        if let Ok((e, c, _cmd)) = cmd_req.cmd.path.not_wildcard() {
            // The non-wildcard path
            let cluster = node.get_cluster_mut(e, c);
            let result: Result<(), IMStatusCode> = match cluster {
                Ok(cluster) => cluster.handle_command(cmd_req),
                Err(e) => Err(e.into()),
            };

            if let Err(e) = result {
                let status = ib::Status::new(e, 0);
                let invoke_resp =
                    ib::InvResponseOut::Status(cmd_req.cmd, status, ib::cmd_resp_dummy);
                let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
            }
        } else {
            // The wildcard path
            let path = cmd_req.cmd.path;
            node.for_each_cluster_mut(&path, |path, c| {
                cmd_req.cmd.path = *path;
                let result = c.handle_command(cmd_req);
                if let Err(e) = result {
                    // It is likely that we might have to do an 'Access' aware traversal
                    // if there are other conditions in the wildcard scenario that shouldn't be
                    // encoded as CmdStatus
                    if e != IMStatusCode::UnsupportedCommand {
                        let status = ib::Status::new(e, 0);
                        let invoke_resp =
                            ib::InvResponseOut::Status(cmd_req.cmd, status, ib::cmd_resp_dummy);
                        let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
                    }
                }
            });
        }
    }
}

impl Clone for DataModel {
    fn clone(&self) -> Self {
        DataModel {
            node: self.node.clone(),
        }
    }
}

impl objects::ChangeConsumer for DataModel {
    fn endpoint_added(&self, id: u16, endpoint: &mut Endpoint) -> Result<(), Error> {
        endpoint.add_cluster(DescriptorCluster::new(id, self.clone())?)?;
        Ok(())
    }
}

impl InteractionConsumer for DataModel {
    fn consume_write_attr(
        &self,
        attr_list: TLVElement,
        fab_scoped: bool,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        if fab_scoped {
            error!("Fabric scoped attribute write not yet supported");
        }
        let attr_list = attr_list
            .confirm_array()?
            .iter()
            .ok_or(Error::InvalidData)?;

        let mut node = self.node.write().unwrap();
        for attr_data_ib in attr_list {
            let attr_data = ib::AttrDataIn::from_tlv(&attr_data_ib)?;
            error!("Received attr data {:?}", attr_data);
            DataModel::handle_write_attr_path(&mut node, &attr_data, tw);
        }
        Ok(())
    }

    fn consume_read_attr(
        &self,
        attr_list: TLVElement,
        fab_scoped: bool,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        if fab_scoped {
            error!("Fabric scoped attribute read not yet supported");
        }
        let attr_list = attr_list
            .confirm_array()?
            .iter()
            .ok_or(Error::InvalidData)?;

        let node = self.node.read().unwrap();
        for attr_path_ib in attr_list {
            let attr_path = ib::AttrPath::from_tlv(&attr_path_ib)?;
            DataModel::handle_read_attr_path(&node, attr_path, tw);
        }
        Ok(())
    }

    fn consume_invoke_cmd(
        &self,
        cmd_path_ib: &ib::CmdPath,
        data: TLVElement,
        trans: &mut Transaction,
        tlvwriter: &mut TLVWriter,
    ) -> Result<(), Error> {
        info!("Invoke Commmand Handler executing: {:?}", cmd_path_ib);

        let mut cmd_req = CommandReq {
            cmd: *cmd_path_ib,
            data,
            trans,
            resp: tlvwriter,
        };

        let mut node = self.node.write().unwrap();
        DataModel::handle_command_path(&mut node, &mut cmd_req);

        Ok(())
    }
}
