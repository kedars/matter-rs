/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */


use crate::crypto::{self, HmacSha256};
use byteorder::{ByteOrder, LittleEndian};
use subtle::ConstantTimeEq;

use crate::{
    crypto::{pbkdf2_hmac, Sha256},
    error::Error,
};

#[cfg(feature = "crypto_openssl")]
use super::crypto_openssl::CryptoOpenSSL;

#[cfg(feature = "crypto_mbedtls")]
use super::crypto_mbedtls::CryptoMbedTLS;

#[cfg(feature = "crypto_esp_mbedtls")]
use super::crypto_esp_mbedtls::CryptoEspMbedTls;

use super::{common::SCStatusCodes, crypto::CryptoSpake2};

// This file handle Spake2+ specific instructions. In itself, this file is
// independent from the BigNum and EC operations that are typically required
// Spake2+. We use the CryptoSpake2 trait object that allows us to abstract
// out the specific implementations.
//
// In the case of the verifier, we don't actually release the Ke until we
// validate that the cA is confirmed.

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum Spake2VerifierState {
    // Initialised - w0, L are set
    Init,
    // Pending Confirmation - Keys are derived but pending confirmation
    PendingConfirmation,
    // Confirmed
    Confirmed,
}

#[derive(PartialEq, Debug)]
pub enum Spake2Mode {
    Unknown,
    Prover,
    Verifier(Spake2VerifierState),
}

#[allow(non_snake_case)]
pub struct Spake2P {
    mode: Spake2Mode,
    context: Option<Sha256>,
    Ke: [u8; 16],
    cA: [u8; 32],
    crypto_spake2: Option<Box<dyn CryptoSpake2>>,
    app_data: u32,
}

const SPAKE2P_KEY_CONFIRM_INFO: [u8; 16] = *b"ConfirmationKeys";
const SPAKE2P_CONTEXT_PREFIX: [u8; 26] = *b"CHIP PAKE V1 Commissioning";
const CRYPTO_GROUP_SIZE_BYTES: usize = 32;
const CRYPTO_W_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES + 8;

#[cfg(feature = "crypto_openssl")]
fn crypto_spake2_new() -> Result<Box<dyn CryptoSpake2>, Error> {
    Ok(Box::new(CryptoOpenSSL::new()?))
}

#[cfg(feature = "crypto_mbedtls")]
fn crypto_spake2_new() -> Result<Box<dyn CryptoSpake2>, Error> {
    Ok(Box::new(CryptoMbedTLS::new()?))
}

#[cfg(feature = "crypto_esp_mbedtls")]
fn crypto_spake2_new() -> Result<Box<dyn CryptoSpake2>, Error> {
    Ok(Box::new(CryptoEspMbedTls::new()?))
}

impl Default for Spake2P {
    fn default() -> Self {
        Self::new()
    }
}

impl Spake2P {
    pub fn new() -> Self {
        Spake2P {
            mode: Spake2Mode::Unknown,
            context: None,
            crypto_spake2: None,
            Ke: [0; 16],
            cA: [0; 32],
            app_data: 0,
        }
    }

    pub fn set_app_data(&mut self, data: u32) {
        self.app_data = data;
    }

    pub fn get_app_data(&mut self) -> u32 {
        self.app_data
    }

    pub fn set_context(&mut self, buf1: &[u8], buf2: &[u8]) -> Result<(), Error> {
        let mut context = Sha256::new()?;
        context.update(&SPAKE2P_CONTEXT_PREFIX)?;
        context.update(buf1)?;
        context.update(buf2)?;
        self.context = Some(context);
        Ok(())
    }

    #[inline(always)]
    fn get_w0w1s(pw: u32, iter: u32, salt: &[u8], w0w1s: &mut [u8]) {
        let mut pw_str: [u8; 4] = [0; 4];
        LittleEndian::write_u32(&mut pw_str, pw);
        let _ = pbkdf2_hmac(&pw_str, iter as usize, salt, w0w1s);
    }

    pub fn start_verifier(&mut self, pw: u32, iter: u32, salt: &[u8]) -> Result<(), Error> {
        let mut w0w1s: [u8; (2 * CRYPTO_W_SIZE_BYTES)] = [0; (2 * CRYPTO_W_SIZE_BYTES)];
        Spake2P::get_w0w1s(pw, iter, salt, &mut w0w1s);
        self.crypto_spake2 = Some(crypto_spake2_new()?);

        let w0s_len = w0w1s.len() / 2;
        if let Some(crypto_spake2) = &mut self.crypto_spake2 {
            crypto_spake2.set_w0_from_w0s(&w0w1s[0..w0s_len])?;
            crypto_spake2.set_L(&w0w1s[w0s_len..])?;
        }

        self.mode = Spake2Mode::Verifier(Spake2VerifierState::Init);
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn handle_pA(&mut self, pA: &[u8], pB: &mut [u8], cB: &mut [u8]) -> Result<(), Error> {
        if self.mode != Spake2Mode::Verifier(Spake2VerifierState::Init) {
            return Err(Error::InvalidState);
        }

        if let Some(crypto_spake2) = &mut self.crypto_spake2 {
            crypto_spake2.get_pB(pB)?;
            if let Some(context) = self.context.take() {
                let mut hash = [0u8; crypto::SHA256_HASH_LEN_BYTES];
                context.finish(&mut hash)?;
                let mut TT = [0u8; crypto::SHA256_HASH_LEN_BYTES];
                crypto_spake2.get_TT_as_verifier(&hash, pA, pB, &mut TT)?;

                Spake2P::get_Ke_and_cAcB(&TT, pA, pB, &mut self.Ke, &mut self.cA, cB)?;
            }
        }
        // We are finished with using the crypto_spake2 now
        self.crypto_spake2 = None;
        self.mode = Spake2Mode::Verifier(Spake2VerifierState::PendingConfirmation);
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn handle_cA(&mut self, cA: &[u8]) -> (SCStatusCodes, Option<&[u8]>) {
        if self.mode != Spake2Mode::Verifier(Spake2VerifierState::PendingConfirmation) {
            return (SCStatusCodes::SessionNotFound, None);
        }
        self.mode = Spake2Mode::Verifier(Spake2VerifierState::Confirmed);
        if cA.ct_eq(&self.cA).unwrap_u8() == 1 {
            (SCStatusCodes::SessionEstablishmentSuccess, Some(&self.Ke))
        } else {
            (SCStatusCodes::InvalidParameter, None)
        }
    }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn get_Ke_and_cAcB(
        TT: &[u8],
        pA: &[u8],
        pB: &[u8],
        Ke: &mut [u8],
        cA: &mut [u8],
        cB: &mut [u8],
    ) -> Result<(), Error> {
        // Step 1: Ka || Ke = Hash(TT)
        let KaKe = TT;
        let KaKe_len = KaKe.len();
        let Ka = &KaKe[0..KaKe_len / 2];
        let ke_internal = &KaKe[(KaKe_len / 2)..];
        if ke_internal.len() == Ke.len() {
            Ke.copy_from_slice(ke_internal);
        } else {
            return Err(Error::NoSpace);
        }

        // Step 2: KcA || KcB = KDF(nil, Ka, "ConfirmationKeys")
        let mut KcAKcB: [u8; 32] = [0; 32];
        crypto::hkdf_sha256(&[], Ka, &SPAKE2P_KEY_CONFIRM_INFO, &mut KcAKcB)
            .map_err(|_x| Error::NoSpace)?;

        let KcA = &KcAKcB[0..(KcAKcB.len() / 2)];
        let KcB = &KcAKcB[(KcAKcB.len() / 2)..];

        // Step 3: cA = HMAC(KcA, pB), cB = HMAC(KcB, pA)
        let mut mac = HmacSha256::new(KcA)?;
        mac.update(pB)?;
        mac.finish(cA)?;

        let mut mac = HmacSha256::new(KcB)?;
        mac.update(pA)?;
        mac.finish(cB)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::Spake2P;
    use crate::{
        crypto,
        secure_channel::{spake2p::CRYPTO_W_SIZE_BYTES, spake2p_test_vectors::test_vectors::*},
    };

    #[test]
    fn test_pbkdf2() {
        // These are the vectors from one sample run of chip-tool along with our PBKDFParamResponse
        let salt = [
            0x4, 0xa1, 0xd2, 0xc6, 0x11, 0xf0, 0xbd, 0x36, 0x78, 0x67, 0x79, 0x7b, 0xfe, 0x82,
            0x36, 0x0,
        ];
        let mut w0w1s: [u8; (2 * CRYPTO_W_SIZE_BYTES)] = [0; (2 * CRYPTO_W_SIZE_BYTES)];
        Spake2P::get_w0w1s(123456, 2000, &salt, &mut w0w1s);
        assert_eq!(
            w0w1s,
            [
                0xc7, 0x89, 0x33, 0x9c, 0xc5, 0xeb, 0xbc, 0xf6, 0xdf, 0x04, 0xa9, 0x11, 0x11, 0x06,
                0x4c, 0x15, 0xac, 0x5a, 0xea, 0x67, 0x69, 0x9f, 0x32, 0x62, 0xcf, 0xc6, 0xe9, 0x19,
                0xe8, 0xa4, 0x0b, 0xb3, 0x42, 0xe8, 0xc6, 0x8e, 0xa9, 0x9a, 0x73, 0xe2, 0x59, 0xd1,
                0x17, 0xd8, 0xed, 0xcb, 0x72, 0x8c, 0xbf, 0x3b, 0xa9, 0x88, 0x02, 0xd8, 0x45, 0x4b,
                0xd0, 0x2d, 0xe5, 0xe4, 0x1c, 0xc3, 0xd7, 0x00, 0x03, 0x3c, 0x86, 0x20, 0x9a, 0x42,
                0x5f, 0x55, 0x96, 0x3b, 0x9f, 0x6f, 0x79, 0xef, 0xcb, 0x37
            ]
        )
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_Ke_and_cAcB() {
        for t in RFC_T {
            let mut Ke: [u8; 16] = [0; 16];
            let mut cA: [u8; 32] = [0; 32];
            let mut cB: [u8; 32] = [0; 32];
            let mut TT_hash = [0u8; crypto::SHA256_HASH_LEN_BYTES];
            let mut h = crypto::Sha256::new().unwrap();
            h.update(&t.TT[0..t.TT_len]).unwrap();
            h.finish(&mut TT_hash).unwrap();
            Spake2P::get_Ke_and_cAcB(&TT_hash, &t.X, &t.Y, &mut Ke, &mut cA, &mut cB).unwrap();
            assert_eq!(Ke, t.Ke);
            assert_eq!(cA, t.cA);
            assert_eq!(cB, t.cB);
        }
    }
}
