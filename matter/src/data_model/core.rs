use super::{
    cluster_basic_information::BasicInfoConfig,
    device_types::device_type_add_root_node,
    objects::{self, *},
    sdm::dev_att::DevAttDataFetcher,
    system_model::descriptor::DescriptorCluster,
};
use crate::{
    acl::AclMgr,
    error::*,
    fabric::FabricMgr,
    interaction_model::{
        command::CommandReq,
        core::IMStatusCode,
        messages::{
            ib::{self, AttrData, AttrPath},
            msg::{self, ReadReq, WriteReq},
            GenericPath,
        },
        InteractionConsumer, Transaction,
    },
    tlv::{TLVElement, TLVWriter, TagType, ToTLV},
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
        acl_mgr: Arc<AclMgr>,
    ) -> Result<Self, Error> {
        let dm = DataModel {
            node: Arc::new(RwLock::new(Node::new()?)),
        };
        {
            let mut node = dm.node.write()?;
            node.set_changes_cb(Box::new(dm.clone()));
            device_type_add_root_node(&mut node, dev_details, dev_att, fabric_mgr, acl_mgr)?;
        }
        Ok(dm)
    }

    pub fn read_attribute_raw(
        &self,
        endpoint: u16,
        cluster: u32,
        attr: u16,
    ) -> Result<AttrValue, IMStatusCode> {
        let node = self.node.read().unwrap();
        let cluster = node.get_cluster(endpoint, cluster)?;
        cluster.base().read_attribute_raw(attr).map(|a| *a)
    }

    // Encode a write attribute from a path that may or may not be wildcard
    fn handle_write_attr_path(
        node: &mut RwLockWriteGuard<Box<Node>>,
        attr_data: &AttrData,
        tw: &mut TLVWriter,
    ) {
        let gen_path = attr_data.path.to_gp();
        let mut encoder = AttrWriteEncoder::new(tw, TagType::Anonymous);
        encoder.set_path(gen_path);

        // The unsupported pieces of the wildcard path
        if attr_data.path.cluster.is_none() {
            encoder.encode_status(IMStatusCode::UnsupportedCluster, 0);
            return;
        }
        if attr_data.path.attr.is_none() {
            encoder.encode_status(IMStatusCode::UnsupportedAttribute, 0);
            return;
        }

        let write_data = match &attr_data.data {
            EncodeValue::Closure(_) | EncodeValue::Value(_) => {
                error!("Not supported");
                return;
            }
            EncodeValue::Tlv(t) => t,
        };

        if gen_path.not_wildcard().is_err() {
            // This is a wildcard path, skip error
            //    This is required because there could be access control errors too that need
            // to be take care of.
            encoder.skip_error();
        }

        let result = node.for_each_cluster_mut(&gen_path, |path, c| {
            let attr_id = if let Some(a) = path.leaf { a } else { 0 } as u16;
            encoder.set_path(*path);

            let r = match c.write_attribute(write_data, attr_id) {
                Ok(_) => IMStatusCode::Sucess,
                Err(e) => e,
            };
            encoder.encode_status(r, 0);
            Ok(())
        });
        if let Err(e) = result {
            // We hit this only if this is a non-wildcard path and some parts of the path are missing
            encoder.encode_status(e, 0);
        }
    }

    // Encode a read attribute from a path that may or may not be wildcard
    fn handle_read_attr_path(
        node: &RwLockReadGuard<Box<Node>>,
        attr_path: AttrPath,
        tw: &mut TLVWriter,
    ) {
        let gen_path = attr_path.to_gp();
        let mut attr_encoder = AttrReadEncoder::new(tw, TagType::Anonymous);
        if gen_path.not_wildcard().is_err() {
            // This is a wildcard path, skip error
            //    This is required because there could be access control errors too that need
            // to be take care of.
            attr_encoder.skip_error();
        }
        attr_encoder.set_path(gen_path);

        let result = node.for_each_attribute(&gen_path, |path, c| {
            let attr_id = if let Some(a) = path.leaf { a } else { 0 } as u16;
            attr_encoder.set_path(*path);

            Cluster::read_attribute(c, &mut attr_encoder, attr_id);
            Ok(())
        });
        if let Err(e) = result {
            // We hit this only if this is a non-wildcard path
            attr_encoder.encode_status(e, 0);
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
                let invoke_resp = ib::InvResp::Status(cmd_req.cmd, status);
                let _ = invoke_resp.to_tlv(cmd_req.resp, TagType::Anonymous);
            }
        } else {
            // The wildcard path
            let path = cmd_req.cmd.path;
            let _ = node.for_each_cluster_mut(&path, |path, c| {
                cmd_req.cmd.path = *path;
                let result = c.handle_command(cmd_req);
                if let Err(e) = result {
                    // It is likely that we might have to do an 'Access' aware traversal
                    // if there are other conditions in the wildcard scenario that shouldn't be
                    // encoded as CmdStatus
                    if e != IMStatusCode::UnsupportedCommand {
                        let status = ib::Status::new(e, 0);
                        let invoke_resp = ib::InvResp::Status(cmd_req.cmd, status);
                        let _ = invoke_resp.to_tlv(cmd_req.resp, TagType::Anonymous);
                    }
                }
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
    fn consume_write_attr(&self, write_req: &WriteReq, tw: &mut TLVWriter) -> Result<(), Error> {
        let mut node = self.node.write().unwrap();

        tw.start_array(TagType::Context(msg::WriteRespTag::WriteResponses as u8))?;
        for attr_data in write_req.write_requests.iter() {
            DataModel::handle_write_attr_path(&mut node, &attr_data, tw);
        }
        tw.end_container()?;

        Ok(())
    }

    fn consume_read_attr(&self, read_req: &ReadReq, tw: &mut TLVWriter) -> Result<(), Error> {
        if read_req.fabric_filtered {
            error!("Fabric scoped attribute read not yet supported");
        }
        if read_req.dataver_filters.is_some() {
            error!("Data Version Filter not yet supported");
        }

        let node = self.node.read().unwrap();
        if let Some(attr_requests) = &read_req.attr_requests {
            tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;

            for attr_path in attr_requests.iter() {
                DataModel::handle_read_attr_path(&node, attr_path, tw);
            }

            tw.end_container()?;
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

/// Encoder for generating a response to a read request
pub struct AttrReadEncoder<'a, 'b, 'c> {
    tw: &'a mut TLVWriter<'b, 'c>,
    tag: TagType,
    data_ver: u32,
    path: GenericPath,
    skip_error: bool,
}

impl<'a, 'b, 'c> AttrReadEncoder<'a, 'b, 'c> {
    pub fn new(tw: &'a mut TLVWriter<'b, 'c>, tag: TagType) -> Self {
        Self {
            tw,
            tag,
            data_ver: 0,
            path: Default::default(),
            skip_error: false,
        }
    }

    pub fn skip_error(&mut self) {
        self.skip_error = true;
    }

    pub fn set_data_ver(&mut self, data_ver: u32) {
        self.data_ver = data_ver;
    }

    pub fn set_path(&mut self, path: GenericPath) {
        self.path = path;
    }
}

impl<'a, 'b, 'c> Encoder for AttrReadEncoder<'a, 'b, 'c> {
    fn encode(&mut self, value: EncodeValue) {
        let resp = ib::AttrResp::Data(ib::AttrData::new(
            Some(self.data_ver),
            ib::AttrPath::new(&self.path),
            value,
        ));
        let _ = resp.to_tlv(self.tw, self.tag);
    }

    fn encode_status(&mut self, status: IMStatusCode, cluster_status: u16) {
        if !self.skip_error {
            let resp =
                ib::AttrResp::Status(ib::AttrStatus::new(&self.path, status, cluster_status));
            let _ = resp.to_tlv(self.tw, self.tag);
        }
    }
}

/// Encoder for generating a response to a write request
pub struct AttrWriteEncoder<'a, 'b, 'c> {
    tw: &'a mut TLVWriter<'b, 'c>,
    tag: TagType,
    path: GenericPath,
    skip_error: bool,
}
impl<'a, 'b, 'c> AttrWriteEncoder<'a, 'b, 'c> {
    pub fn new(tw: &'a mut TLVWriter<'b, 'c>, tag: TagType) -> Self {
        Self {
            tw,
            tag,
            path: Default::default(),
            skip_error: false,
        }
    }

    pub fn skip_error(&mut self) {
        self.skip_error = true;
    }

    pub fn set_path(&mut self, path: GenericPath) {
        self.path = path;
    }
}

impl<'a, 'b, 'c> Encoder for AttrWriteEncoder<'a, 'b, 'c> {
    fn encode(&mut self, _value: EncodeValue) {
        // Only status encodes for AttrWriteResponse
    }

    fn encode_status(&mut self, status: IMStatusCode, cluster_status: u16) {
        if self.skip_error && status != IMStatusCode::Sucess {
            // Don't encode errors
            return;
        }
        let resp = ib::AttrStatus::new(&self.path, status, cluster_status);
        let _ = resp.to_tlv(self.tw, self.tag);
    }
}
