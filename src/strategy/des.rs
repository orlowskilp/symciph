use des::DesCipher;

use crate::DataChunk;

use super::EncryptionStrategy;

const DES_KEY_CHUNKS: usize = 1;

pub(super) struct DesEncryptionStrategy {
    scheme: DesCipher,
}

impl DesEncryptionStrategy {
    pub fn new(key_bytes: &[DataChunk]) -> Self {
        assert!(
            key_bytes.len() == DES_KEY_CHUNKS,
            "DES: Key not 64 bits long"
        );

        let key = key_bytes[0];
        let scheme = DesCipher::new(&key);

        Self { scheme }
    }
}

impl EncryptionStrategy for DesEncryptionStrategy {
    fn encrypt(&self, plaintext: &[DataChunk]) -> Vec<DataChunk> {
        let mut ciphertext_blocks: Vec<DataChunk> = Vec::new();

        for plaintext_block in plaintext {
            ciphertext_blocks.push(self.scheme.encrypt(plaintext_block));
        }

        ciphertext_blocks
    }

    fn decrypt(&self, ciphertext: &[DataChunk]) -> Vec<DataChunk> {
        let mut plaintext_blocks: Vec<DataChunk> = Vec::new();

        for ciphertext_block in ciphertext {
            plaintext_blocks.push(self.scheme.decrypt(ciphertext_block));
        }

        plaintext_blocks
    }
}

#[cfg(test)]
mod tests {
    use crate::strategy::tests::*;

    use super::*;

    const DES_CIPHERTEXT: [DataChunk; 1] = [[0x4E, 0x7F, 0x27, 0xC3, 0x9C, 0x0F, 0xF0, 0x2B]; 1];

    #[test]
    fn encrypt() {
        let strategy = DesEncryptionStrategy::new(&KEY_64_BITS);
        let ciphertext = strategy.encrypt(&PLAINTEXT_64_BITS);

        let left = ciphertext[0];
        let right = DES_CIPHERTEXT[0];

        assert_eq!(left, right);
    }

    #[test]
    fn decrypt() {
        let strategy = DesEncryptionStrategy::new(&KEY_64_BITS);
        let plaintext = strategy.decrypt(&DES_CIPHERTEXT);

        let left = plaintext[0];
        let right = PLAINTEXT_64_BITS[0];

        assert_eq!(left, right);
    }
}
