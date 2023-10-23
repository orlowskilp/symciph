mod aes_128;
mod aes_192;
mod aes_256;

use std::ops::Index;

use super::{consts::*, AesBlock};

pub enum AesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

pub(super) struct AesKey {
    _key_expansion_strategy: Box<dyn AesKeyExpansionStrategy>,
}

trait AesKeyExpansionStrategy {
    fn get_round_key(&self, round_num: usize) -> &AesBlock;
    fn round_keys_num(&self) -> usize;
}

struct Aes128KeyExpansionStrategy {
    round_keys: [AesBlock; AES_NUM_ROUNDS_128],
}

struct Aes192KeyExpansionStrategy {
    _round_keys: [AesBlock; AES_NUM_ROUNDS_192],
}

struct Aes256KeyExpansionStrategy {
    _round_keys: [AesBlock; AES_NUM_ROUNDS_256],
}

impl AesKey {
    pub fn new(init_key: &[u8], key_size: AesKeySize) -> Self {
        let _key_expansion_strategy: Box<dyn AesKeyExpansionStrategy> = match key_size {
            AesKeySize::Aes128 => Box::new(Aes128KeyExpansionStrategy::new(init_key)),
            AesKeySize::Aes192 => Box::new(Aes192KeyExpansionStrategy::new(init_key)),
            AesKeySize::Aes256 => Box::new(Aes256KeyExpansionStrategy::new(init_key)),
        };

        Self {
            _key_expansion_strategy,
        }
    }

    pub fn _len(&self) -> usize {
        self._key_expansion_strategy.round_keys_num()
    }
}

impl Index<usize> for AesKey {
    type Output = AesBlock;

    fn index(&self, index: usize) -> &Self::Output {
        assert!(
            index < self._key_expansion_strategy.round_keys_num(),
            "AES Key: Index is {}, but the number of round keys is {}",
            index,
            self._key_expansion_strategy.round_keys_num()
        );

        self._key_expansion_strategy.get_round_key(index)
    }
}
