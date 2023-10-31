pub mod cipher;
mod consts;
pub mod key;

use crypto_primitives::Word;
use key::AesKey;

type AesBlock = [Word; consts::AES_BLOCK_SIZE];

pub struct AesCipher {
    key: AesKey,
}
