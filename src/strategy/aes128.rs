use aes::{key::AesKeySize, AesCipher};

use crate::DataChunk;

use super::{
    aes_commons::{aes_decrypt, aes_encrypt, init_aes_scheme},
    EncryptionStrategy,
};

pub(super) struct Aes128EncryptionStrategy {
    scheme: AesCipher,
}

impl Aes128EncryptionStrategy {
    pub fn new(key_bytes: &[DataChunk]) -> Self {
        let scheme = init_aes_scheme(key_bytes, AesKeySize::Aes128);

        Self { scheme }
    }
}

impl EncryptionStrategy for Aes128EncryptionStrategy {
    fn encrypt(&self, plaintext: &[DataChunk]) -> Vec<DataChunk> {
        aes_encrypt(&self.scheme, plaintext)
    }

    fn decrypt(&self, ciphertext: &[DataChunk]) -> Vec<DataChunk> {
        aes_decrypt(&self.scheme, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use crate::strategy::{
        aes_commons::AES_BLOCK_CHUNKS,
        tests::{KEY_128_BITS, PLAINTEXT_128_BITS},
    };

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
