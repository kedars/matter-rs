use sha2::{Digest, Sha256};

pub enum Spake2Mode {
    Prover,
    Verifier,
}
pub struct Spake2P {
    _mode: Spake2Mode,
    context: Sha256,
}

const SPAKE2P_CONTEXT_PREFIX: [u8; 26] = *b"CHIP PAKE V1 Commissioning";

impl Spake2P {
    pub fn new(mode: Spake2Mode) -> Self {
        let mut s = Spake2P {
            _mode: mode,
            context: Sha256::new(),
        };
        s.context.update(SPAKE2P_CONTEXT_PREFIX);
        s
    }

    pub fn add_to_context(&mut self, buf: &[u8]) {
        self.context.update(buf);
    }
}
