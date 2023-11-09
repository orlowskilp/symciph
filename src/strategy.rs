use super::{EncryptionSchemes, _DataChunk};

pub trait EncryptionStrategy {
    fn encrypt(&self, plaintext: &[_DataChunk]) -> Vec<_DataChunk>;
    fn decrypt(&self, ciphertext: &[_DataChunk]) -> Vec<_DataChunk>;
}

impl EncryptionSchemes {
    pub fn _strategy(&self, _key_bytes: &[_DataChunk]) -> Box<dyn EncryptionStrategy> {
        todo!("Implement factory method")
    }

    pub const fn _key_size(&self) -> usize {
        match self {
            Self::Des => 1,
            Self::Tdes => 3,
            Self::Aes128 => 2,
            Self::Aes192 => 3,
            Self::Aes256 => 4,
        }
    }
}
