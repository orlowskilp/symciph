use triple_des::TripleDesCipher;

use crate::DataChunk;

use super::EncryptionStrategy;

const TRIPLE_DES_KEY_CHUNKS: usize = 3;

pub(super) struct TripleDesEncryptionStrategy {
    scheme: TripleDesCipher,
}

impl TripleDesEncryptionStrategy {
    pub fn new(key_bytes: &[DataChunk]) -> Self {
        assert!(
            key_bytes.len() == TRIPLE_DES_KEY_CHUNKS,
            "3DES: Key not 196 bits long"
        );

        let key = [key_bytes[0], key_bytes[1], key_bytes[2]];
        let scheme = TripleDesCipher::new(&key);

        Self { scheme }
    }
}

impl EncryptionStrategy for TripleDesEncryptionStrategy {
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

    const TRIPLE_DES_CIPHERTEXT: [DataChunk; 1] =
        [[0x0B, 0x7A, 0x37, 0xC2, 0x88, 0x5A, 0xE0, 0x2E]; 1];

    #[test]
    fn encrypt() {
        let strategy = TripleDesEncryptionStrategy::new(&KEY_196_BITS);

        let ciphertext = strategy.encrypt(&PLAINTEXT_64_BITS);

        assert_eq!(ciphertext, TRIPLE_DES_CIPHERTEXT);
    }

    #[test]
    fn decrypt() {
        let strategy = TripleDesEncryptionStrategy::new(&KEY_196_BITS);

        let plaintext = strategy.decrypt(&TRIPLE_DES_CIPHERTEXT);

        assert_eq!(plaintext, PLAINTEXT_64_BITS);
    }
}
