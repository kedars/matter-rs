use std::sync::Arc;

use aes::Aes128;
use ccm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use ccm::{
    consts::{U13, U16},
    Ccm,
};

use hkdf::Hkdf;
use log::{error, trace};
use owning_ref::RwLockReadGuardRef;
use rand::prelude::*;
use sha2::{Digest, Sha256};

use crate::cert::Cert;
use crate::secure_channel::common::SCStatusCodes;
use crate::transport::session::CloneData;
use crate::{
    crypto::{CryptoKeyPair, KeyPair},
    error::Error,
    fabric::{Fabric, FabricMgr, FabricMgrInner},
    proto_demux::{ProtoRx, ProtoTx},
    secure_channel::common,
    tlv::get_root_node_struct,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
    utils::writebuf::WriteBuf,
};

#[derive(PartialEq)]
enum State {
    Sigma1Rx,
    Sigma3Rx,
}

pub struct CaseSession {
    state: State,
    initiator_sessid: u16,
    tt_hash: Sha256,
    shared_secret: [u8; 32],
    local_fabric_idx: usize,
}
impl CaseSession {
    pub fn new(initiator_sessid: u16) -> Result<Self, Error> {
        Ok(Self {
            state: State::Sigma1Rx,
            initiator_sessid,
            tt_hash: Sha256::new(),
            shared_secret: [0; 32],
            local_fabric_idx: 0,
        })
    }
}

pub struct Case {
    fabric_mgr: Arc<FabricMgr>,
}

impl Case {
    pub fn new(fabric_mgr: Arc<FabricMgr>) -> Self {
        Self { fabric_mgr }
    }

    pub fn handle_casesigma3(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let mut case_session = proto_rx
            .exchange
            .take_exchange_data::<CaseSession>()
            .ok_or(Error::InvalidState)?;
        if case_session.state != State::Sigma1Rx {
            return Err(Error::Invalid);
        }
        case_session.state = State::Sigma3Rx;

        let root = get_root_node_struct(proto_rx.buf)?;
        let encrypted = root.find_tag(1)?.get_slice()?;

        // TODO: Fix IPK
        let dummy_ipk: [u8; 16] = [0; 16];
        let mut sigma3_key: [u8; 16] = [0; 16];
        Case::get_sigma3_key(
            &dummy_ipk,
            &case_session.tt_hash,
            &case_session.shared_secret,
            &mut sigma3_key,
        )?;
        // println!("Sigma3 Key: {:x?}", sigma3_key);
        let mut decrypted: [u8; 800] = [0; 800];
        let mut decrypted = &mut decrypted[..encrypted.len()];
        decrypted.copy_from_slice(encrypted);

        let len = Case::get_sigma3_decryption(&sigma3_key, &mut decrypted)?;
        let decrypted = &decrypted[..len];
        println!("Decrypted: {:x?}", decrypted);

        let root = get_root_node_struct(decrypted)?;
        let initiator_noc = Cert::new(root.find_tag(1)?.get_slice()?);
        let initiator_icac = Cert::new(root.find_tag(2)?.get_slice()?);
        let signature = root.find_tag(3)?.get_slice()?;
        // TODO: Signature Validation

        let fabric = self.fabric_mgr.get_fabric(case_session.local_fabric_idx)?;
        if fabric.is_none() {
            common::create_sc_status_report(proto_tx, common::SCStatusCodes::NoSharedTrustRoots)?;
            proto_rx.exchange.close();
            return Ok(());
        }
        // Safe to unwrap here
        let fabric = fabric.as_ref().as_ref().unwrap();

        if (fabric.get_fabric_id() != initiator_noc.get_fabric_id()?)
            || (fabric.get_fabric_id() != initiator_icac.get_fabric_id()?)
        {
            common::create_sc_status_report(proto_tx, common::SCStatusCodes::InvalidParameter)?;
            proto_rx.exchange.close();
            return Ok(());
        }

        if !initiator_noc.is_authority(&initiator_icac)?
            || !initiator_icac.is_authority(&fabric.root_ca)?
        {
            error!("Certificate Chain doesn't match");
            common::create_sc_status_report(proto_tx, common::SCStatusCodes::InvalidParameter)?;
            proto_rx.exchange.close();
            return Ok(());
        }
        // TODO: Cert Chain Validation

        case_session.tt_hash.update(proto_rx.buf);
        // TODO: Fix IPK
        let dummy_ipk: [u8; 16] = [0; 16];
        let mut session_keys: [u8; 48] = [0; 48];
        Case::get_session_keys(
            &dummy_ipk,
            &case_session.tt_hash,
            &case_session.shared_secret,
            &mut session_keys,
        )?;

        let mut clone_data = CloneData::new(case_session.initiator_sessid);
        clone_data.dec_key.copy_from_slice(&session_keys[0..16]);
        clone_data.enc_key.copy_from_slice(&session_keys[16..32]);
        clone_data
            .att_challenge
            .copy_from_slice(&session_keys[32..48]);
        proto_tx.new_session = Some(proto_rx.session.clone(&clone_data));

        common::create_sc_status_report(proto_tx, SCStatusCodes::SessionEstablishmentSuccess)?;
        proto_rx.exchange.clear_exchange_data();
        proto_rx.exchange.close();

        Ok(())
    }

    pub fn handle_casesigma1(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let root = get_root_node_struct(proto_rx.buf)?;
        let initiator_random = root.find_tag(1)?.get_slice()?;
        let initiator_sessid = root.find_tag(2)?.get_u8()?;
        let dest_id = root.find_tag(3)?.get_slice()?;
        let peer_pub_key = root.find_tag(4)?.get_slice()?;

        let local_fabric_idx = self.fabric_mgr.match_dest_id(initiator_random, dest_id);
        if local_fabric_idx.is_err() {
            common::create_sc_status_report(proto_tx, common::SCStatusCodes::NoSharedTrustRoots)?;
            proto_rx.exchange.close();
            return Ok(());
        }

        let mut case_session = Box::new(CaseSession::new(initiator_sessid as u16)?);
        case_session.tt_hash.update(proto_rx.buf);
        case_session.local_fabric_idx = local_fabric_idx?;
        trace!(
            "Destination ID matched to fabric index {}",
            case_session.local_fabric_idx
        );

        // Create an ephemeral Key Pair
        let key_pair = KeyPair::new()?;
        let mut our_pub_key: [u8; 66] = [0; 66];
        let len = key_pair.get_public_key(&mut our_pub_key)?;
        let our_pub_key = &our_pub_key[..len];

        // Derive the Shared Secret
        let len = key_pair.derive_secret(peer_pub_key, &mut case_session.shared_secret)?;
        if len != 32 {
            error!("Derived secret length incorrect");
            return Err(Error::Invalid);
        }
        //        println!("Derived secret: {:x?} len: {}", secret, len);

        let mut our_random: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut our_random);

        // Derive the Encrypted Part
        const MAX_ENCRYPTED_SIZE: usize = 800;

        let mut encrypted: [u8; MAX_ENCRYPTED_SIZE] = [0; MAX_ENCRYPTED_SIZE];
        let encrypted_len = {
            let mut signature: [u8; 160] = [0; 160];
            let fabric = self.fabric_mgr.get_fabric(case_session.local_fabric_idx)?;
            if fabric.is_none() {
                common::create_sc_status_report(
                    proto_tx,
                    common::SCStatusCodes::NoSharedTrustRoots,
                )?;
                proto_rx.exchange.close();
                return Ok(());
            }

            let sign_len =
                Case::get_sigma2_signature(&fabric, our_pub_key, peer_pub_key, &mut signature)?;
            let signature = &signature[..sign_len];

            // TODO: Fix IPK
            let dummy_ipk: [u8; 16] = [0; 16];
            let mut sigma2_key: [u8; 16] = [0; 16];
            Case::get_sigma2_key(
                &dummy_ipk,
                &our_random,
                our_pub_key,
                &case_session.tt_hash,
                &case_session.shared_secret,
                &mut sigma2_key,
            )?;

            Case::get_sigma2_encryption(&fabric, &sigma2_key, signature, &mut encrypted)?
        };
        let encrypted = &encrypted[0..encrypted_len];

        // Generate our Response Body
        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        tw.put_start_struct(TagType::Anonymous)?;
        tw.put_str8(TagType::Context(1), &our_random)?;
        tw.put_u16(
            TagType::Context(2),
            proto_rx.session.get_child_local_sess_id(),
        )?;
        tw.put_str8(TagType::Context(3), our_pub_key)?;
        tw.put_str16(TagType::Context(4), encrypted)?;
        tw.put_end_container()?;
        case_session.tt_hash.update(proto_tx.write_buf.as_slice());
        proto_rx.exchange.set_exchange_data(case_session);
        Ok(())
    }

    fn get_session_keys(
        ipk: &[u8],
        tt_hash: &Sha256,
        shared_secret: &[u8],
        key: &mut [u8],
    ) -> Result<(), Error> {
        const SEKEYS_INFO: [u8; 11] = [
            0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x73,
        ];
        if key.len() < 48 {
            return Err(Error::NoSpace);
        }
        let mut salt = Vec::<u8>::with_capacity(256);
        salt.extend_from_slice(ipk);
        let tt_hash = tt_hash.clone();
        let tt_hash = tt_hash.finalize();
        let tt_hash = tt_hash.as_slice();
        salt.extend_from_slice(tt_hash);
        //        println!("Session Key: salt: {:x?}, len: {}", salt, salt.len());

        let h = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared_secret);
        h.expand(&SEKEYS_INFO, key).map_err(|_x| Error::NoSpace)?;
        println!("Session Key: key: {:x?}", key);

        Ok(())
    }

    fn get_sigma3_decryption(sigma3_key: &[u8], encrypted: &mut [u8]) -> Result<usize, Error> {
        let nonce: [u8; 13] = [
            0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x33, 0x4e,
        ];

        let nonce = GenericArray::from_slice(&nonce);
        const TAG_LEN: usize = 16;
        let encrypted_len = encrypted.len();
        let mut tag: [u8; TAG_LEN] = [0; TAG_LEN];
        tag.copy_from_slice(&encrypted[(encrypted_len - TAG_LEN)..]);
        let tag = GenericArray::from_slice(&tag);

        type AesCcm = Ccm<Aes128, U16, U13>;
        let cipher = AesCcm::new(GenericArray::from_slice(&sigma3_key));

        let encrypted = &mut encrypted[..(encrypted_len - TAG_LEN)];
        cipher.decrypt_in_place_detached(nonce, &[], encrypted, tag)?;
        Ok(encrypted_len - TAG_LEN)
    }

    fn get_sigma3_key(
        ipk: &[u8],
        tt_hash: &Sha256,
        shared_secret: &[u8],
        key: &mut [u8],
    ) -> Result<(), Error> {
        const S3K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x33];
        if key.len() < 16 {
            return Err(Error::NoSpace);
        }
        let mut salt = Vec::<u8>::with_capacity(256);
        salt.extend_from_slice(ipk);

        let tt_hash = tt_hash.clone();
        let tt_hash = tt_hash.finalize();
        let tt_hash = tt_hash.as_slice();
        salt.extend_from_slice(tt_hash);
        //        println!("Sigma3Key: salt: {:x?}, len: {}", salt, salt.len());

        let h = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared_secret);
        h.expand(&S3K_INFO, key).map_err(|_x| Error::NoSpace)?;
        //        println!("Sigma3Key: key: {:x?}", key);

        Ok(())
    }

    fn get_sigma2_key(
        ipk: &[u8],
        our_random: &[u8],
        our_pub_key: &[u8],
        tt_hash: &Sha256,
        shared_secret: &[u8],
        key: &mut [u8],
    ) -> Result<(), Error> {
        const S2K_INFO: [u8; 6] = [0x53, 0x69, 0x67, 0x6d, 0x61, 0x32];
        if key.len() < 16 {
            return Err(Error::NoSpace);
        }
        let mut salt = Vec::<u8>::with_capacity(256);
        salt.extend_from_slice(ipk);
        salt.extend_from_slice(our_random);
        salt.extend_from_slice(our_pub_key);

        let tt_hash = tt_hash.clone();
        let tt_hash = tt_hash.finalize();
        let tt_hash = tt_hash.as_slice();
        salt.extend_from_slice(tt_hash);
        //        println!("Sigma2Key: salt: {:x?}, len: {}", salt, salt.len());

        let h = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared_secret);
        h.expand(&S2K_INFO, key).map_err(|_x| Error::NoSpace)?;
        //        println!("Sigma2Key: key: {:x?}", key);

        Ok(())
    }

    fn get_sigma2_encryption(
        fabric: &RwLockReadGuardRef<FabricMgrInner, Option<Fabric>>,
        key: &[u8],
        signature: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut resumption_id: [u8; 16] = [0; 16];
        rand::thread_rng().fill_bytes(&mut resumption_id);

        // We are guaranteed this unwrap will work
        let fabric = fabric.as_ref().as_ref().unwrap();
        let mut write_buf = WriteBuf::new(out, out.len());
        let mut tw = TLVWriter::new(&mut write_buf);
        tw.put_start_struct(TagType::Anonymous)?;
        tw.put_str8(TagType::Context(1), fabric.noc.as_slice()?)?;
        tw.put_str8(TagType::Context(2), fabric.icac.as_slice()?)?;
        tw.put_str8(TagType::Context(3), signature)?;
        tw.put_str8(TagType::Context(4), &resumption_id)?;
        tw.put_end_container()?;
        //        println!("TBE is {:x?}", write_buf.as_slice());
        let nonce: [u8; 13] = [
            0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x32, 0x4e,
        ];
        let nonce = GenericArray::from_slice(&nonce);
        let cipher_text = write_buf.as_mut_slice();

        type AesCcm = Ccm<Aes128, U16, U13>;
        let cipher = AesCcm::new(GenericArray::from_slice(key));
        let tag = cipher.encrypt_in_place_detached(nonce, &[], cipher_text)?;
        write_buf.append(tag.as_slice())?;

        Ok(write_buf.as_slice().len())
    }

    fn get_sigma2_signature(
        fabric: &RwLockReadGuardRef<FabricMgrInner, Option<Fabric>>,
        our_pub_key: &[u8],
        peer_pub_key: &[u8],
        signature: &mut [u8],
    ) -> Result<usize, Error> {
        // We are guaranteed this unwrap will work
        let fabric = fabric.as_ref().as_ref().unwrap();
        const MAX_TBS_SIZE: usize = 800;
        let mut buf: [u8; MAX_TBS_SIZE] = [0; MAX_TBS_SIZE];
        let mut write_buf = WriteBuf::new(&mut buf, MAX_TBS_SIZE);
        let mut tw = TLVWriter::new(&mut write_buf);
        tw.put_start_struct(TagType::Anonymous)?;
        tw.put_str8(TagType::Context(1), fabric.noc.as_slice()?)?;
        tw.put_str8(TagType::Context(2), fabric.icac.as_slice()?)?;
        tw.put_str8(TagType::Context(3), our_pub_key)?;
        tw.put_str8(TagType::Context(4), peer_pub_key)?;
        tw.put_end_container()?;
        Ok(fabric.sign_msg(write_buf.as_slice(), signature)?)
    }
}
