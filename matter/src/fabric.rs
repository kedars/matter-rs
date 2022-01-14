use std::sync::RwLock;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use log::info;
use owning_ref::RwLockReadGuardRef;
use sha2::Sha256;

use crate::{
    cert::Cert,
    crypto::KeyPair,
    crypto::{crypto_dummy::KeyPairDummy, CryptoKeyPair},
    error::Error,
};

const COMPRESSED_FABRIC_ID_LEN: usize = 8;

#[allow(dead_code)]
pub struct Fabric {
    node_id: u64,
    fabric_id: u64,
    key_pair: Box<dyn CryptoKeyPair>,
    pub root_ca: Cert,
    pub icac: Cert,
    pub noc: Cert,
    ipk: Cert,
    compressed_id: [u8; COMPRESSED_FABRIC_ID_LEN],
}

impl Fabric {
    pub fn new(
        key_pair: KeyPair,
        root_ca: Cert,
        icac: Cert,
        noc: Cert,
        ipk: Cert,
    ) -> Result<Self, Error> {
        let node_id = noc.get_node_id()?;
        let fabric_id = noc.get_fabric_id()?;

        let mut f = Self {
            node_id,
            fabric_id,
            key_pair: Box::new(key_pair),
            root_ca,
            icac,
            noc,
            ipk,
            compressed_id: [0; COMPRESSED_FABRIC_ID_LEN],
        };
        Fabric::get_compressed_id(f.root_ca.get_pubkey()?, fabric_id, &mut f.compressed_id)?;
        let mut mdns_service_name = String::with_capacity(33);
        for c in f.compressed_id {
            mdns_service_name.push_str(&format!("{:02X}", c));
        }
        mdns_service_name.push('-');
        let mut node_id_be: [u8; 8] = [0; 8];
        BigEndian::write_u64(&mut node_id_be, node_id);
        for c in node_id_be {
            mdns_service_name.push_str(&format!("{:02X}", c));
        }
        info!("MDNS Service Name: {}", mdns_service_name);
        Ok(f)
    }

    pub fn dummy() -> Result<Self, Error> {
        Ok(Self {
            node_id: 0,
            fabric_id: 0,
            key_pair: Box::new(KeyPairDummy::new()?),
            root_ca: Cert::default(),
            icac: Cert::default(),
            noc: Cert::default(),
            ipk: Cert::default(),
            compressed_id: [0; COMPRESSED_FABRIC_ID_LEN],
        })
    }

    fn get_compressed_id(root_pubkey: &[u8], fabric_id: u64, out: &mut [u8]) -> Result<(), Error> {
        let root_pubkey = &root_pubkey[1..];
        let mut fabric_id_be: [u8; 8] = [0; 8];
        BigEndian::write_u64(&mut fabric_id_be, fabric_id);
        const COMPRESSED_FABRIC_ID_INFO: [u8; 16] = [
            0x43, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x46, 0x61, 0x62, 0x72,
            0x69, 0x63,
        ];
        let h = Hkdf::<Sha256>::new(Some(&fabric_id_be), root_pubkey);
        h.expand(&COMPRESSED_FABRIC_ID_INFO, out)
            .map_err(|_| Error::NoSpace)
    }

    pub fn match_dest_id(&self, random: &[u8], target: &[u8]) -> Result<(), Error> {
        // TODO: Currently chip-tool expect ipk as all zeroes
        let dummy_ipk: [u8; 16] = [0; 16];
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&dummy_ipk).map_err(|_x| Error::InvalidKeyLength)?;
        mac.update(random);
        mac.update(self.root_ca.get_pubkey()?);

        let mut buf: [u8; 8] = [0; 8];
        LittleEndian::write_u64(&mut buf, self.fabric_id);
        mac.update(&buf);

        LittleEndian::write_u64(&mut buf, self.node_id);
        mac.update(&buf);

        let id = mac.finalize().into_bytes();
        if id.as_slice() == target {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        self.key_pair.sign_msg(msg, signature)
    }

    pub fn get_node_id(&self) -> u64 {
        self.node_id
    }

    pub fn get_fabric_id(&self) -> u64 {
        self.fabric_id
    }
}

const MAX_SUPPORTED_FABRICS: usize = 3;
#[derive(Default)]
pub struct FabricMgrInner {
    // The outside world expects Fabric Index to be one more than the actual one
    // since 0 is not allowed. Need to handle this cleanly somehow
    pub fabrics: [Option<Fabric>; MAX_SUPPORTED_FABRICS],
}

pub struct FabricMgr(RwLock<FabricMgrInner>);

impl FabricMgr {
    pub fn new() -> Result<Self, Error> {
        let dummy_fabric = Fabric::dummy()?;
        let mut mgr = FabricMgrInner::default();
        mgr.fabrics[0] = Some(dummy_fabric);
        Ok(Self(RwLock::new(mgr)))
    }

    pub fn add(&self, f: Fabric) -> Result<u8, Error> {
        let mut mgr = self.0.write()?;
        let index = mgr
            .fabrics
            .iter()
            .position(|f| f.is_none())
            .ok_or(Error::NoSpace)?;
        mgr.fabrics[index] = Some(f);
        Ok(index as u8)
    }

    pub fn match_dest_id(&self, random: &[u8], target: &[u8]) -> Result<usize, Error> {
        let mgr = self.0.read()?;
        for i in 0..MAX_SUPPORTED_FABRICS {
            if let Some(fabric) = &mgr.fabrics[i] {
                if fabric.match_dest_id(random, target).is_ok() {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    pub fn get_fabric<'ret, 'me: 'ret>(
        &'me self,
        idx: usize,
    ) -> Result<RwLockReadGuardRef<'ret, FabricMgrInner, Option<Fabric>>, Error> {
        Ok(RwLockReadGuardRef::new(self.0.read()?).map(|fm| &fm.fabrics[idx]))
    }
}
