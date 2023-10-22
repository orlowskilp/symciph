use crate::consts::AES_NUM_ROUNDS_256;

use super::{Aes256KeyExpansionStrategy, AesBlock, AesKeyExpansionStrategy};

impl AesKeyExpansionStrategy for Aes256KeyExpansionStrategy {
    fn get_round_key(&self, round_num: usize) -> &AesBlock {
        &self._round_keys[round_num]
    }

    fn round_keys_num(&self) -> usize {
        self._round_keys.len()
    }
}

impl Aes256KeyExpansionStrategy {
    fn expand_key_256(_key_bytes: &[u8]) -> [AesBlock; AES_NUM_ROUNDS_256] {
        unimplemented!("expand_key_256")
    }

    pub fn new(init_key: &[u8]) -> Self {
        let _round_keys = Self::expand_key_256(init_key);

        Self { _round_keys }
    }
}
