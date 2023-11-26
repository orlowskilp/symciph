use aes::{key::AesKeySize, AesCipher};

use crate::DataChunk;

use super::{
    aes_commons::{aes_decrypt, aes_encrypt, init_aes_scheme},
    EncryptionStrategy,
};

pub(super) struct Aes256EncryptionStrategy {
    scheme: AesCipher,
}

impl Aes256EncryptionStrategy {
    pub fn new(key_bytes: &[DataChunk]) -> Self {
        let scheme = init_aes_scheme(key_bytes, AesKeySize::Aes256);

        Self { scheme }
    }
}

impl EncryptionStrategy for Aes256EncryptionStrategy {
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
        tests::{KEY_256_BITS, PLAINTEXT_128_BITS},
    };

    use super::*;

    const AES192_CIPHERTEXT: [DataChunk; AES_BLOCK_CHUNKS] = [
        [0x68, 0x52, 0x27, 0x55, 0x5B, 0xAB, 0xA0, 0xC1],
        [0xAB, 0xF7, 0x20, 0x42, 0xC6, 0x8D, 0x8D, 0xA6],
    ];

    #[test]
    fn encrypt_single_block() {
        let scheme = Aes256EncryptionStrategy::new(&KEY_256_BITS);

        let ciphertext = scheme.encrypt(&PLAINTEXT_128_BITS);

        let left = ciphertext.as_slice();
        let right = &AES192_CIPHERTEXT;

        assert_eq!(left, right)
    }

    #[test]
    fn decrypt_single_block() {
        let scheme = Aes256EncryptionStrategy::new(&KEY_256_BITS);

        let plaintext = scheme.decrypt(&AES192_CIPHERTEXT);

        let left = plaintext.as_slice();
        let right = &PLAINTEXT_128_BITS;

        assert_eq!(left, right)
    }

    #[should_panic]
    #[test]
    fn encrypt_illegal_buffer() {
        let scheme = Aes256EncryptionStrategy::new(&KEY_256_BITS);

        scheme.decrypt(&[PLAINTEXT_128_BITS[0]]);
    }

    #[should_panic]
    #[test]
    fn decrypt_illegal_buffer() {
        let scheme = Aes256EncryptionStrategy::new(&KEY_256_BITS);

        scheme.decrypt(&[AES192_CIPHERTEXT[0]]);
    }

    #[test]
    fn encrypt_two_blocks() {
        let scheme = Aes256EncryptionStrategy::new(&KEY_256_BITS);

        let ciphertext = scheme.encrypt(&[
            PLAINTEXT_128_BITS[0],
            PLAINTEXT_128_BITS[1],
            PLAINTEXT_128_BITS[0],
            PLAINTEXT_128_BITS[1],
        ]);

        let left = ciphertext.as_slice();
        let right = &[
            AES192_CIPHERTEXT[0],
            AES192_CIPHERTEXT[1],
            AES192_CIPHERTEXT[0],
            AES192_CIPHERTEXT[1],
        ];

        assert_eq!(left, right)
    }

    #[test]
    fn decrypt_two_blocks() {
        let scheme = Aes256EncryptionStrategy::new(&KEY_256_BITS);

        let plaintext = scheme.decrypt(&[
            AES192_CIPHERTEXT[0],
            AES192_CIPHERTEXT[1],
            AES192_CIPHERTEXT[0],
            AES192_CIPHERTEXT[1],
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
