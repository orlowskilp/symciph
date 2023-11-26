use aes::{key::AesKeySize, AesCipher};

use crate::DataChunk;

use super::{
    aes_commons::{aes_decrypt, aes_encrypt, init_aes_scheme},
    EncryptionStrategy,
};

pub(super) struct Aes192EncryptionStrategy {
    scheme: AesCipher,
}

impl Aes192EncryptionStrategy {
    pub fn new(key_bytes: &[DataChunk]) -> Self {
        let scheme = init_aes_scheme(key_bytes, AesKeySize::Aes192);

        Self { scheme }
    }
}

impl EncryptionStrategy for Aes192EncryptionStrategy {
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
        tests::{KEY_196_BITS, PLAINTEXT_128_BITS},
    };

    use super::*;

    const AES192_CIPHERTEXT: [DataChunk; AES_BLOCK_CHUNKS] = [
        [0x9B, 0x96, 0xB8, 0xBE, 0xF2, 0xEF, 0x4A, 0xED],
        [0xA7, 0x84, 0x8B, 0xFA, 0x88, 0x0B, 0xDF, 0xBA],
    ];

    #[test]
    fn encrypt_single_block() {
        let scheme = Aes192EncryptionStrategy::new(&KEY_196_BITS);

        let ciphertext = scheme.encrypt(&PLAINTEXT_128_BITS);

        let left = ciphertext.as_slice();
        let right = &AES192_CIPHERTEXT;

        assert_eq!(left, right)
    }

    #[test]
    fn decrypt_single_block() {
        let scheme = Aes192EncryptionStrategy::new(&KEY_196_BITS);

        let plaintext = scheme.decrypt(&AES192_CIPHERTEXT);

        let left = plaintext.as_slice();
        let right = &PLAINTEXT_128_BITS;

        assert_eq!(left, right)
    }

    #[should_panic]
    #[test]
    fn encrypt_illegal_buffer() {
        let scheme = Aes192EncryptionStrategy::new(&KEY_196_BITS);

        scheme.decrypt(&[PLAINTEXT_128_BITS[0]]);
    }

    #[should_panic]
    #[test]
    fn decrypt_illegal_buffer() {
        let scheme = Aes192EncryptionStrategy::new(&KEY_196_BITS);

        scheme.decrypt(&[AES192_CIPHERTEXT[0]]);
    }

    #[test]
    fn encrypt_two_blocks() {
        let scheme = Aes192EncryptionStrategy::new(&KEY_196_BITS);

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
        let scheme = Aes192EncryptionStrategy::new(&KEY_196_BITS);

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
