use crate::consts::AES_NUM_ROUNDS_128;

use super::{Aes128KeyExpansionStrategy, AesBlock, AesKeyExpansionStrategy};

impl AesKeyExpansionStrategy for Aes128KeyExpansionStrategy {
    fn get_round_key(&self, round_num: usize) -> &AesBlock {
        &self._round_keys[round_num]
    }

    fn round_keys_num(&self) -> usize {
        self._round_keys.len()
    }
}

impl Aes128KeyExpansionStrategy {
    fn expand_key_128(_key_bytes: &[u8]) -> [AesBlock; AES_NUM_ROUNDS_128] {
        unimplemented!("expand_key_128")
    }

    pub fn new(init_key: &[u8]) -> Self {
        let _round_keys = Self::expand_key_128(init_key);

        Self { _round_keys }
    }
}
