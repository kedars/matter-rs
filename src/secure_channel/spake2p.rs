use byteorder::{ByteOrder, LittleEndian};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};

#[derive(PartialEq)]
pub enum Spake2Mode {
    Unknown,
    Prover,
    Verifier,
}
pub struct Spake2P {
    mode: Spake2Mode,
    context: Sha256,
    w0w1: [u8; (2 * CRYPTO_W_SIZE_BYTES)],
}

const SPAKE2P_CONTEXT_PREFIX: [u8; 26] = *b"CHIP PAKE V1 Commissioning";
const CRYPTO_GROUP_SIZE_BYTES: usize = 32;
const CRYPTO_W_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES + 8;

impl Spake2P {
    pub fn new() -> Self {
        let mut s = Spake2P {
            mode: Spake2Mode::Unknown,
            w0w1: [0; (2 * CRYPTO_W_SIZE_BYTES)],
            context: Sha256::new(),
        };
        if s.mode == Spake2Mode::Verifier {}
        s.context.update(SPAKE2P_CONTEXT_PREFIX);
        s
    }

    pub fn add_to_context(&mut self, buf: &[u8]) {
        self.context.update(buf);
    }

    pub fn start_verifier(&mut self, pw: u32, iter: u32, salt: &[u8]) {
        let mut pw_str: [u8; 4] = [0; 4];
        LittleEndian::write_u32(&mut pw_str, pw);
        pbkdf2::pbkdf2::<Hmac<Sha256>>(&pw_str, salt, iter, &mut self.w0w1);
    }
}

#[cfg(test)]
mod tests {
    use super::Spake2P;

    #[test]
    fn test_pbkdf2() {
        // These are the vectors from one sample run of chip-tool along with our PBKDFParamResponse
        let mut spake2 = Spake2P::new();
        let salt = [
            0x4, 0xa1, 0xd2, 0xc6, 0x11, 0xf0, 0xbd, 0x36, 0x78, 0x67, 0x79, 0x7b, 0xfe, 0x82,
            0x36, 0x0,
        ];
        spake2.start_verifier(123456, 2000, &salt);
        assert_eq!(
            spake2.w0w1,
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
}
