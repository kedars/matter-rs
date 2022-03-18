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
        messages::ib::{self, AttrPath},
        InteractionConsumer, Transaction,
    },
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};
use log::{error, info};
use std::sync::{Arc, RwLock, RwLockReadGuard};

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
    // Note that it is possibe that some internal checks don't match even at this stage (read on a write-only attribute, invalid attr-id).
    // If there was an error, we rewind, so the TLVWriter doesn't include any half-baked data about the 'AttrData' IB
    fn encode_read_attr_data(
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
    fn encode_read_attr_path(
        node: &RwLockReadGuard<Box<Node>>,
        attr_path: AttrPath,
        tw: &mut TLVWriter,
    ) {
        if let Ok((e, c, a)) = attr_path.path.not_wildcard() {
            // The non-wildcard path
            let get_cluster = |e, c| {
                node.get_endpoint(e)
                    .map_err(|_| IMStatusCode::UnsupportedEndpoint)?
                    .get_cluster(c)
                    .map_err(|_| IMStatusCode::UnsupportedCluster)
            };
            let cluster = get_cluster(e, c);
            let result = match cluster {
                Ok(cluster) => DataModel::encode_read_attr_data(cluster, tw, attr_path, a as u16),
                Err(e) => Err(e),
            };

            if let Err(e) = result {
                let attr_status = ib::AttrStatus::new(&attr_path.path, e, 0);
                let attr_resp = ib::AttrRespOut::Status(attr_status, ib::attr_resp_dummy);
                let _ = tw.put_object(TagType::Anonymous, &attr_resp);
            }
        } else {
            // The wildcard path
            println!("In wildcard path for {:?}", attr_path.path);
            let result = node.for_each_attribute(&attr_path.path, |path, c| {
                println!("In the each attribute loop for {:?}", path);
                let attr_id = if let Some(a) = path.leaf { a } else { 0 } as u16;
                let path = ib::AttrPath::new(path);
                // Note: In the case of wildcard scenario, we do NOT encode AttrStatus in case of errors
                // This is as per the spec, because we don't want ot encode UnsupportedRead/UnsupportedWrite type of errors

                // TODO: It is likely that there may be genuine cases where the error code needs to be encoded
                // in this response. If such a thing is desirable, we'll have to make the wildcard traversal
                // routines 'Access' aware, so that they only provide attributes that are compatible with the
                // operation under consideration (Access:RV for read, Access:W*for write)
                let _ = DataModel::encode_read_attr_data(c, tw, path, attr_id);
                Ok(())
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

            if attr_data.path.path.cluster.is_none() || attr_data.path.path.leaf.is_none() {
                error!("Cluster/Attribute cannot be wildcard in Write Interaction");
                let attr_status = ib::AttrStatus::new(
                    &attr_data.path.path,
                    IMStatusCode::UnsupportedAttribute,
                    0,
                );
                let _ = tw.put_object(TagType::Anonymous, &attr_status);
                continue;
            }

            let result = node.for_each_cluster_mut(&attr_data.path.path, |path, c| {
                let attr_id = if let Some(a) = path.leaf { a } else { 0 } as u16;
                let result = c.write_attribute(&attr_data.data, attr_id);
                if let Err(e) = result {
                    let attr_status = ib::AttrStatus::new(path, e, 0);
                    let _ = tw.put_object(TagType::Anonymous, &attr_status);
                }
                Ok(())
            });
            if let Err(e) = result {
                let attr_status = ib::AttrStatus::new(&attr_data.path.path, e, 0);
                let _ = tw.put_object(TagType::Anonymous, &attr_status);
            }
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
            DataModel::encode_read_attr_path(&node, attr_path, tw);
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
        let result = node.for_each_cluster_mut(&cmd_path_ib.path, |path, c| {
            cmd_req.cmd.path = *path;
            let result = c.handle_command(&mut cmd_req);
            if let Err(e) = result {
                if e == IMStatusCode::UnsupportedCommand {
                    // If this is an error in path component, we don't return error here
                    return Err(e);
                }
                let status = ib::Status::new(e, 0);
                let invoke_resp =
                    ib::InvResponseOut::Status(cmd_req.cmd, status, ib::cmd_resp_dummy);
                let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
            }
            Ok(())
        });
        if let Err(result) = result {
            // Err return here implies that the path itself is incorrect
            let status = ib::Status::new(result, 0);
            let invoke_resp = ib::InvResponseOut::Status(*cmd_path_ib, status, ib::cmd_resp_dummy);
            tlvwriter.put_object(TagType::Anonymous, &invoke_resp)?;
            trans.complete();
        }
        Ok(())
    }
}
