mod galois_field_ops;

use super::{consts::*, key::AesKeySize, AesBlock, AesCipher, AesKey, Word};
use galois_field_ops::_mix_column;

impl AesCipher {
    pub fn new(init_key: &[u8], key_size: AesKeySize) -> Self {
        // TODO: Rename _key to key
        let _key = AesKey::new(init_key, key_size);

        Self { _key }
    }

    pub fn encrypt(&self, block: &[[u8; 8]; 2]) -> [[u8; 8]; 2] {
        let aes_block = Self::to_aes_block(block);

        Self::from_aes_block(&self.encrypt_block(&aes_block))
    }

    pub fn decrypt(&self, block: &[[u8; 8]; 2]) -> [[u8; 8]; 2] {
        let aes_block = Self::to_aes_block(block);

        Self::from_aes_block(&self.decrypt_block(&aes_block))
    }

    fn encrypt_block(&self, _block: &AesBlock) -> AesBlock {
        unimplemented!("AesCipher::encrypt_block")
    }

    fn decrypt_block(&self, _block: &AesBlock) -> AesBlock {
        unimplemented!("AesCipher::decrypt_block")
    }

    fn to_aes_block(block: &[[u8; 8]; 2]) -> AesBlock {
        let mut out = [Word::zero(); AES_BLOCK_SIZE];

        for (i, chunk) in block.iter().enumerate() {
            (out[i * 2], out[i * 2 + 1]) = Word::from(chunk).split(u32::BITS as usize);
        }

        out
    }

    fn from_aes_block(block: &AesBlock) -> [[u8; 8]; 2] {
        let mut out = [[0u8; 8]; 2];

        for i in 0..out.len() {
            out[i] = block[i * 2]
                .concatenate(block[i * 2 + 1], u32::BITS as usize)
                .into()
        }

        out
    }

    fn _sub_bytes(state: &AesBlock) -> AesBlock {
        let mut out = [Word::zero(); AES_BLOCK_SIZE];

        for row in 0..AES_BLOCK_SIZE {
            out[row] = state[row].substitute_bytes(BYTES_PER_WORD, &SBOX);
        }

        out
    }

    fn _shift_rows(state: &AesBlock) -> AesBlock {
        let mut out = [Word::zero(); AES_BLOCK_SIZE];

        for row in 0..AES_BLOCK_SIZE {
            let rotate_by = row * u8::BITS as usize;

            out[row] = state[row].rotate_left(rotate_by, u32::BITS as usize);
        }

        out
    }

    fn _mix_columns(state: &AesBlock) -> AesBlock {
        let mut bytes = [[0u8; BYTES_PER_WORD]; AES_BLOCK_SIZE];

        for col in 0..AES_BLOCK_SIZE {
            bytes[col] = state[col].into();
        }

        let mut out = [Word::zero(); AES_BLOCK_SIZE];

        for row in 0..AES_BLOCK_SIZE {
            let column = [bytes[0][row], bytes[1][row], bytes[2][row], bytes[3][row]];
            let mixed_column = _mix_column(&column);

            for col in 0..BYTES_PER_WORD {
                bytes[col][row] = mixed_column[col];
            }
        }

        for row in 0..AES_BLOCK_SIZE {
            out[row] = Word::from(bytes[row]);
        }

        out
    }

    fn _add_round_key(state: &AesBlock, round_key: &AesBlock) -> AesBlock {
        let mut out = [Word::zero(); AES_BLOCK_SIZE];

        for word in 0..AES_BLOCK_SIZE {
            out[word] = state[word] ^ round_key[word];
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod to_from_aes_block {
        use super::*;

        #[test]
        fn to_aes_block() {
            const INPUT: [[u8; 8]; 2] = [
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB],
                [0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33],
            ];

            let left = AesCipher::to_aes_block(&INPUT);
            let right = [
                Word::from(0x0011_2233u32),
                Word::from(0x4455_AABBu32),
                Word::from(0xCCDD_EEFFu32),
                Word::from(0x0011_2233u32),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn from_aes_block() {
            let input = [
                Word::from(0x0011_2233u32),
                Word::from(0x4455_AABBu32),
                Word::from(0xCCDD_EEFFu32),
                Word::from(0x0011_2233u32),
            ];

            let left = AesCipher::from_aes_block(&input);
            let right = [
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB],
                [0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33],
            ];

            assert_eq!(left, right);
        }
    }

    mod sub_bytes {
        use super::*;

        #[test]
        fn incremental_bytes() {
            let left = AesCipher::_sub_bytes(&[
                Word::zero(),
                Word::one(),
                Word::from(2u8),
                Word::from(3u8),
            ]);
            let right = [
                Word::from(0x6363_6363u32),
                Word::from(0x6363_637Cu32),
                Word::from(0x6363_6377u32),
                Word::from(0x6363_637Bu32),
            ];

            assert_eq!(left, right);
        }
    }

    mod shift_rows {
        use super::*;

        #[test]
        fn trivial_four_ones() {
            let left = AesCipher::_shift_rows(&[Word::one(); AES_BLOCK_SIZE]);
            let right = [
                Word::one(),
                Word::one() << 8u8,
                Word::one() << 16u8,
                Word::one() << 24u8,
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn four_0x80000000s() {
            let left = AesCipher::_shift_rows(&[Word::from(0x8000_0000u32); AES_BLOCK_SIZE]);
            let right = [
                Word::one() << 31u8,
                Word::one() << 7u8,
                Word::one() << 15u8,
                Word::one() << 23u8,
            ];

            assert_eq!(left, right);
        }
    }

    mod mix_columns {
        use super::*;

        #[test]
        fn trivial_all_0x01s() {
            const INPUT: AesBlock = [Word::one(); AES_BLOCK_SIZE];

            let left = AesCipher::_mix_columns(&INPUT);
            let right = INPUT;

            assert_eq!(left, right);
        }

        #[test]
        fn nontrivial() {
            let left = AesCipher::_mix_columns(&[
                Word::from(0xDBF2_D42Du32),
                Word::from(0x130A_D426u32),
                Word::from(0x5322_D431u32),
                Word::from(0x455C_D54Cu32),
            ]);
            let right = [
                Word::from(0x8E9F_D54Du32),
                Word::from(0x4DDC_D57Eu32),
                Word::from(0xA158_D7BDu32),
                Word::from(0xBC9D_D6F8u32),
            ];

            assert_eq!(left, right);
        }
    }
}
