use super::{key::AesKeySize, AesCipher, AesKey};

impl AesCipher {
    pub fn new(init_key: &[u8], key_size: AesKeySize) -> Self {
        // TODO: Rename _key to key
        let _key = AesKey::new(init_key, key_size);

        Self { _key }
    }
}
