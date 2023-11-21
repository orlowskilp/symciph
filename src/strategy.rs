mod aes128;
mod aes_commons;
mod des;
mod tdes;

use self::{
    aes128::Aes128EncryptionStrategy, des::DesEncryptionStrategy, tdes::TripleDesEncryptionStrategy,
};

use super::{DataChunk, EncryptionSchemes};

pub trait EncryptionStrategy {
    fn encrypt(&self, plaintext: &[DataChunk]) -> Vec<DataChunk>;
    fn decrypt(&self, ciphertext: &[DataChunk]) -> Vec<DataChunk>;
}

impl EncryptionSchemes {
    pub fn strategy(&self, key_bytes: &[DataChunk]) -> Box<dyn EncryptionStrategy> {
        match self {
            Self::Des => Box::new(DesEncryptionStrategy::new(key_bytes)),
            Self::Tdes => Box::new(TripleDesEncryptionStrategy::new(key_bytes)),
            Self::Aes128 => Box::new(Aes128EncryptionStrategy::new(key_bytes)),
            _ => todo!("Implement remaining encryption strategies"),
        }
    }

    pub const fn key_size(&self) -> usize {
        match self {
            Self::Des => 1,
            Self::Tdes => 3,
            Self::Aes128 => 2,
            Self::Aes192 => 3,
            Self::Aes256 => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rustfmt::skip]
    pub const KEY_64_BITS: [DataChunk; 1] = [
        [0x6F, 0x2B, 0x91, 0xE7, 0x4F, 0xD8, 0xA9, 0x5C]
    ];

    #[rustfmt::skip]
    pub const KEY_128_BITS: [DataChunk; 2] = [
        [0x6F, 0x2B, 0x91, 0xE7, 0x4F, 0xD8, 0xA9, 0x5C],
        [0x1A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80, 0x91],
    ];

    pub const KEY_196_BITS: [DataChunk; 3] = [
        [0x6F, 0x2B, 0x91, 0xE7, 0x4F, 0xD8, 0xA9, 0x5C],
        [0x1A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80, 0x91],
        [0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x19],
    ];

    pub const PLAINTEXT_64_BITS: [DataChunk; 1] =
        [[0x4A, 0x7F, 0x22, 0xC3, 0x8D, 0x5E, 0xA1, 0x3B]; 1];

    pub const PLAINTEXT_128_BITS: [DataChunk; 2] = [
        [0x4A, 0x7F, 0x22, 0xC3, 0x8D, 0x5E, 0xA1, 0x3B],
        [0x6C, 0x9D, 0x2E, 0x5F, 0xA0, 0x1B, 0x4C, 0x7D],
    ];
}
