use aes::{key::AesKeySize, AesCipher};

use crate::DataChunk;

pub const AES128_KEY_CHUNKS: usize = 2;
pub const AES192_KEY_CHUNKS: usize = 3;
pub const AES256_KEY_CHUNKS: usize = 4;
pub const AES_BLOCK_CHUNKS: usize = 2;

pub fn init_aes_scheme(key_bytes: &[DataChunk], key_size: AesKeySize) -> AesCipher {
    match key_size {
        AesKeySize::Aes128 => assert!(
            key_bytes.len() == AES128_KEY_CHUNKS,
            "AES128: Key not 128 bits long"
        ),
        AesKeySize::Aes192 => assert!(
            key_bytes.len() == AES192_KEY_CHUNKS,
            "AES192: Key not 192 bits long"
        ),
        AesKeySize::Aes256 => assert!(
            key_bytes.len() == AES256_KEY_CHUNKS,
            "AES256: Key not 256 bits long"
        ),
    }

    let mut key: Vec<u8> = Vec::new();
    for key_chunk in key_bytes {
        key.extend_from_slice(key_chunk);
    }

    AesCipher::new(key.as_slice(), key_size)
}

pub fn aes_encrypt(scheme: &AesCipher, plaintext: &[DataChunk]) -> Vec<DataChunk> {
    assert!(
        plaintext.len() % 2 == 0,
        "AES: Plaintext buffer not multiple of 128 bits"
    );

    let mut ciphertext_blocks: Vec<DataChunk> = Vec::new();

    for i in (0..plaintext.len()).step_by(AES_BLOCK_CHUNKS) {
        let plaintext_block = [plaintext[i], plaintext[i + 1]];
        let aes_ciphertext_block = scheme.encrypt(&plaintext_block);

        for aes_block in aes_ciphertext_block.iter() {
            ciphertext_blocks.push(*aes_block);
        }
    }

    ciphertext_blocks
}

pub fn aes_decrypt(scheme: &AesCipher, plaintext: &[DataChunk]) -> Vec<DataChunk> {
    assert!(
        plaintext.len() % 2 == 0,
        "AES: Ciphertext buffer not multiple of 128 bits"
    );

    let mut ciphertext_blocks: Vec<DataChunk> = Vec::new();

    for i in (0..plaintext.len()).step_by(AES_BLOCK_CHUNKS) {
        let plaintext_block = [plaintext[i], plaintext[i + 1]];
        let aes_ciphertext_block = scheme.decrypt(&plaintext_block);

        for aes_block in aes_ciphertext_block.iter() {
            ciphertext_blocks.push(*aes_block);
        }
    }

    ciphertext_blocks
}
