use aes::key::AesKeySize;
use aes::AesCipher;

use crate::DataChunk;

use super::EncryptionStrategy;

const AES128_KEY_CHUNKS: usize = 2;
const AES_BLOCK_CHUNKS: usize = 2;

pub(super) struct Aes128EncryptionStrategy {
    scheme: AesCipher,
}

impl Aes128EncryptionStrategy {
    pub fn new(key_bytes: &[DataChunk]) -> Self {
        const KEY_BITS_LEN: usize = AES128_KEY_CHUNKS * u8::BITS as usize;
        assert!(
            key_bytes.len() == AES128_KEY_CHUNKS,
            "AES128: Key not 128 bits long"
        );

        let key = &mut [0u8; KEY_BITS_LEN];
        for (i, key_chunk) in key_bytes.iter().enumerate() {
            let left = i * (KEY_BITS_LEN / 2);
            let right = left + KEY_BITS_LEN / 2;

            key[left..right].copy_from_slice(key_chunk);
        }

        let scheme = AesCipher::new(key, AesKeySize::Aes128);

        Self { scheme }
    }
}

impl EncryptionStrategy for Aes128EncryptionStrategy {
    fn encrypt(&self, plaintext: &[DataChunk]) -> Vec<DataChunk> {
        assert!(
            plaintext.len() % 2 == 0,
            "AES128: Plaintext buffer not multiple of 128 bits"
        );

        let mut ciphertext_blocks: Vec<DataChunk> = Vec::new();

        for i in (0..plaintext.len()).step_by(AES_BLOCK_CHUNKS) {
            let plaintext_block = [plaintext[i], plaintext[i + 1]];
            let aes_ciphertext_block = self.scheme.encrypt(&plaintext_block);

            for aes_block in aes_ciphertext_block.iter() {
                ciphertext_blocks.push(*aes_block);
            }
        }

        ciphertext_blocks
    }

    fn decrypt(&self, ciphertext: &[DataChunk]) -> Vec<DataChunk> {
        assert!(
            ciphertext.len() % 2 == 0,
            "AES128: Ciphertext buffer not multiple of 128 bits"
        );

        let mut plaintext_blocks: Vec<DataChunk> = Vec::new();

        for i in (0..ciphertext.len()).step_by(AES_BLOCK_CHUNKS) {
            let ciphertext_block = [ciphertext[i], ciphertext[i + 1]];
            let aes_plaintext_block = self.scheme.decrypt(&ciphertext_block);

            for aes_block in aes_plaintext_block.iter() {
                plaintext_blocks.push(*aes_block);
            }
        }

        plaintext_blocks
    }
}

#[cfg(test)]
mod tests {
    use crate::strategy::tests::{KEY_128_BITS, PLAINTEXT_128_BITS};

    use super::*;

    const AES128_CIPHERTEXT: [DataChunk; AES_BLOCK_CHUNKS] = [
        [0x1C, 0xE9, 0xF9, 0xE1, 0xAC, 0x8A, 0xCD, 0x69],
        [0x7F, 0x52, 0xE4, 0xF6, 0x0C, 0x2C, 0xFC, 0x73],
    ];

    #[test]
    fn encrypt_single_block() {
        let scheme = Aes128EncryptionStrategy::new(&KEY_128_BITS);

        let ciphertext = scheme.encrypt(&PLAINTEXT_128_BITS);

        let left = ciphertext.as_slice();
        let right = &AES128_CIPHERTEXT;

        assert_eq!(left, right)
    }

    #[test]
    fn decrypt_single_block() {
        let scheme = Aes128EncryptionStrategy::new(&KEY_128_BITS);

        let plaintext = scheme.decrypt(&AES128_CIPHERTEXT);

        let left = plaintext.as_slice();
        let right = &PLAINTEXT_128_BITS;

        assert_eq!(left, right)
    }

    #[should_panic]
    #[test]
    fn encrypt_illegal_buffer() {
        let scheme = Aes128EncryptionStrategy::new(&KEY_128_BITS);

        scheme.decrypt(&[PLAINTEXT_128_BITS[0]]);
    }

    #[should_panic]
    #[test]
    fn decrypt_illegal_buffer() {
        let scheme = Aes128EncryptionStrategy::new(&KEY_128_BITS);

        scheme.decrypt(&[AES128_CIPHERTEXT[0]]);
    }

    #[test]
    fn encrypt_two_blocks() {
        let scheme = Aes128EncryptionStrategy::new(&KEY_128_BITS);

        let ciphertext = scheme.encrypt(&[
            PLAINTEXT_128_BITS[0],
            PLAINTEXT_128_BITS[1],
            PLAINTEXT_128_BITS[0],
            PLAINTEXT_128_BITS[1],
        ]);

        let left = ciphertext.as_slice();
        let right = &[
            AES128_CIPHERTEXT[0],
            AES128_CIPHERTEXT[1],
            AES128_CIPHERTEXT[0],
            AES128_CIPHERTEXT[1],
        ];

        assert_eq!(left, right)
    }

    #[test]
    fn decrypt_two_blocks() {
        let scheme = Aes128EncryptionStrategy::new(&KEY_128_BITS);

        let plaintext = scheme.decrypt(&[
            AES128_CIPHERTEXT[0],
            AES128_CIPHERTEXT[1],
            AES128_CIPHERTEXT[0],
            AES128_CIPHERTEXT[1],
        ]);

        let left = plaintext.as_slice();
        let right = &[
            PLAINTEXT_128_BITS[0],
            PLAINTEXT_128_BITS[1],
            PLAINTEXT_128_BITS[0],
            PLAINTEXT_128_BITS[1],
        ];

        assert_eq!(left, right)
    }
}
