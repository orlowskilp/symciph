use super::{DataChunk, EncryptionSchemes};

pub trait EncryptionStrategy {
    fn encrypt(&self, plaintext: &[DataChunk]) -> Vec<DataChunk>;
    fn decrypt(&self, ciphertext: &[DataChunk]) -> Vec<DataChunk>;
}

impl EncryptionSchemes {
    pub fn _strategy(&self, _key_bytes: &[DataChunk]) -> Box<dyn EncryptionStrategy> {
        todo!("Implement factory method")
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
