mod galois_field_ops;

use super::{consts::*, key::AesKeySize, AesBlock, AesCipher, AesKey, Word};
use galois_field_ops::mix_column;

impl AesCipher {
    pub fn new(init_key: &[u8], key_size: AesKeySize) -> Self {
        let key = AesKey::new(init_key, key_size);

        Self { key }
    }

    pub fn encrypt(&self, block: &[[u8; 8]; 2]) -> [[u8; 8]; 2] {
        let aes_block = Self::to_aes_block(block);

        Self::from_aes_block(&self.encrypt_block(&aes_block))
    }

    pub fn decrypt(&self, block: &[[u8; 8]; 2]) -> [[u8; 8]; 2] {
        let aes_block = Self::to_aes_block(block);

        Self::from_aes_block(&self.decrypt_block(&aes_block))
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

    fn encrypt_block(&self, block: &AesBlock) -> AesBlock {
        let last_round = self.key.len() - 1;
        let mut state = Self::add_round_key(block, &self.key[0]);

        for round in 1..last_round {
            state = Self::sub_bytes(&state, false);
            state = Self::shift_rows(&state, false);
            state = Self::mix_columns(&state, false);
            state = Self::add_round_key(&state, &self.key[round]);
        }

        state = Self::sub_bytes(&state, false);
        state = Self::shift_rows(&state, false);

        Self::add_round_key(&state, &self.key[last_round])
    }

    fn decrypt_block(&self, block: &AesBlock) -> AesBlock {
        let last_round = self.key.len() - 1;
        let mut state = Self::add_round_key(block, &self.key[last_round]);

        for round in (1..last_round).rev() {
            state = Self::shift_rows(&state, true);
            state = Self::sub_bytes(&state, true);
            state = Self::add_round_key(&state, &self.key[round]);
            state = Self::mix_columns(&state, true);
        }

        state = Self::shift_rows(&state, true);
        state = Self::sub_bytes(&state, true);

        Self::add_round_key(&state, &self.key[0])
    }

    fn sub_bytes(state: &AesBlock, inverse: bool) -> AesBlock {
        let sbox = match inverse {
            false => &SBOX,
            true => &INV_SBOX,
        };

        let mut out = [Word::zero(); AES_BLOCK_SIZE];

        for row in 0..AES_BLOCK_SIZE {
            out[row] = state[row].substitute_bytes(BYTES_PER_WORD, sbox);
        }

        out
    }

    fn shift_rows(state: &AesBlock, inverse: bool) -> AesBlock {
        let mut out = [Word::zero(); AES_BLOCK_SIZE];

        for row in 0..AES_BLOCK_SIZE {
            let rotate_by = match inverse {
                false => row,
                true => AES_BLOCK_SIZE - row,
            } * u8::BITS as usize;

            out[row] = state[row].rotate_left(rotate_by, u32::BITS as usize);
        }

        out
    }

    fn mix_columns(state: &AesBlock, inverse: bool) -> AesBlock {
        let mut bytes = [[0u8; BYTES_PER_WORD]; AES_BLOCK_SIZE];

        for col in 0..AES_BLOCK_SIZE {
            bytes[col] = state[col].into();
        }

        let mut out = [Word::zero(); AES_BLOCK_SIZE];

        for row in 0..AES_BLOCK_SIZE {
            let column = [bytes[0][row], bytes[1][row], bytes[2][row], bytes[3][row]];
            let mixed_column = mix_column(&column, inverse);

            for col in 0..BYTES_PER_WORD {
                bytes[col][row] = mixed_column[col];
            }
        }

        for row in 0..AES_BLOCK_SIZE {
            out[row] = Word::from(bytes[row]);
        }

        out
    }

    fn add_round_key(state: &AesBlock, round_key: &AesBlock) -> AesBlock {
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

        const SUB_BYTES_DATA_1: [u32; 4] = [0, 1, 2, 3];
        const SUB_BYTES_DATA_2: [u32; 4] = [0x6363_6363, 0x6363_637C, 0x6363_6377, 0x6363_637B];

        #[test]
        fn incremental_bytes() {
            let left = AesCipher::sub_bytes(
                &[
                    Word::from(SUB_BYTES_DATA_1[0]),
                    Word::from(SUB_BYTES_DATA_1[1]),
                    Word::from(SUB_BYTES_DATA_1[2]),
                    Word::from(SUB_BYTES_DATA_1[3]),
                ],
                false,
            );
            let right = [
                Word::from(SUB_BYTES_DATA_2[0]),
                Word::from(SUB_BYTES_DATA_2[1]),
                Word::from(SUB_BYTES_DATA_2[2]),
                Word::from(SUB_BYTES_DATA_2[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn inv_incremental_bytes() {
            let left = AesCipher::sub_bytes(
                &[
                    Word::from(SUB_BYTES_DATA_2[0]),
                    Word::from(SUB_BYTES_DATA_2[1]),
                    Word::from(SUB_BYTES_DATA_2[2]),
                    Word::from(SUB_BYTES_DATA_2[3]),
                ],
                true,
            );
            let right = [
                Word::from(SUB_BYTES_DATA_1[0]),
                Word::from(SUB_BYTES_DATA_1[1]),
                Word::from(SUB_BYTES_DATA_1[2]),
                Word::from(SUB_BYTES_DATA_1[3]),
            ];

            assert_eq!(left, right);
        }
    }

    mod shift_rows {
        use super::*;

        const SHIFT_ROWS_VAL: u32 = 0x8000_0000;
        const SHIFT_ROWS_DATA_1: [u32; 4] = [1, 1 << 8, 1 << 16, 1 << 24];
        const SHIFT_ROWS_DATA_2: [u32; 4] = [1 << 31, 1 << 7, 1 << 15, 1 << 23];

        #[test]
        fn trivial_four_ones() {
            let left = AesCipher::shift_rows(&[Word::one(); AES_BLOCK_SIZE], false);
            let right = [
                Word::from(SHIFT_ROWS_DATA_1[0]),
                Word::from(SHIFT_ROWS_DATA_1[1]),
                Word::from(SHIFT_ROWS_DATA_1[2]),
                Word::from(SHIFT_ROWS_DATA_1[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn inv_trivial_four_ones() {
            let left = AesCipher::shift_rows(
                &[
                    Word::from(SHIFT_ROWS_DATA_1[0]),
                    Word::from(SHIFT_ROWS_DATA_1[1]),
                    Word::from(SHIFT_ROWS_DATA_1[2]),
                    Word::from(SHIFT_ROWS_DATA_1[3]),
                ],
                true,
            );
            let right = [Word::one(); AES_BLOCK_SIZE];

            assert_eq!(left, right);
        }

        #[test]
        fn four_0x80000000s() {
            let left = AesCipher::shift_rows(&[Word::from(SHIFT_ROWS_VAL); AES_BLOCK_SIZE], false);
            let right = [
                Word::from(SHIFT_ROWS_DATA_2[0]),
                Word::from(SHIFT_ROWS_DATA_2[1]),
                Word::from(SHIFT_ROWS_DATA_2[2]),
                Word::from(SHIFT_ROWS_DATA_2[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn inv_four_0x80000000s() {
            let left = AesCipher::shift_rows(
                &[
                    Word::from(SHIFT_ROWS_DATA_2[0]),
                    Word::from(SHIFT_ROWS_DATA_2[1]),
                    Word::from(SHIFT_ROWS_DATA_2[2]),
                    Word::from(SHIFT_ROWS_DATA_2[3]),
                ],
                true,
            );
            let right = [Word::from(SHIFT_ROWS_VAL); AES_BLOCK_SIZE];

            assert_eq!(left, right);
        }
    }

    mod mix_columns {
        use super::*;

        const MIX_COLUMNS_DATA_1: [u32; 4] = [0xDBF2_D42D, 0x130A_D426, 0x5322_D431, 0x455C_D54C];
        const MIX_COLUMNS_DATA_2: [u32; 4] = [0x8E9F_D54D, 0x4DDC_D57E, 0xA158_D7BD, 0xBC9D_D6F8];

        #[test]
        fn trivial_all_0x01s() {
            const INPUT: AesBlock = [Word::one(); AES_BLOCK_SIZE];

            let left = AesCipher::mix_columns(&INPUT, false);
            let right = INPUT;

            assert_eq!(left, right);
        }

        #[test]
        fn inv_trivial_all_0x01s() {
            const INPUT: AesBlock = [Word::one(); AES_BLOCK_SIZE];

            let left = AesCipher::mix_columns(&INPUT, true);
            let right = INPUT;

            assert_eq!(left, right);
        }

        #[test]
        fn nontrivial() {
            let left = AesCipher::mix_columns(
                &[
                    Word::from(MIX_COLUMNS_DATA_1[0]),
                    Word::from(MIX_COLUMNS_DATA_1[1]),
                    Word::from(MIX_COLUMNS_DATA_1[2]),
                    Word::from(MIX_COLUMNS_DATA_1[3]),
                ],
                false,
            );
            let right = [
                Word::from(MIX_COLUMNS_DATA_2[0]),
                Word::from(MIX_COLUMNS_DATA_2[1]),
                Word::from(MIX_COLUMNS_DATA_2[2]),
                Word::from(MIX_COLUMNS_DATA_2[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn inv_nontrivial() {
            let left = AesCipher::mix_columns(
                &[
                    Word::from(MIX_COLUMNS_DATA_2[0]),
                    Word::from(MIX_COLUMNS_DATA_2[1]),
                    Word::from(MIX_COLUMNS_DATA_2[2]),
                    Word::from(MIX_COLUMNS_DATA_2[3]),
                ],
                true,
            );
            let right = [
                Word::from(MIX_COLUMNS_DATA_1[0]),
                Word::from(MIX_COLUMNS_DATA_1[1]),
                Word::from(MIX_COLUMNS_DATA_1[2]),
                Word::from(MIX_COLUMNS_DATA_1[3]),
            ];

            assert_eq!(left, right);
        }
    }

    const PLAINTEXT: [u32; AES_BLOCK_SIZE] = [0x3243_F6A8, 0x885A_308D, 0x3131_98A2, 0xE037_0734];

    mod encrypt_decrypt_aes128 {
        use super::*;

        const CIPHERTEXT: [u32; AES_BLOCK_SIZE] =
            [0xB822_FE47, 0x6F13_F2CA, 0x8211_ED45, 0xE337_5882];

        #[rustfmt::skip]
        const KEY: [u8; BYTES_PER_WORD * AES_KEY_SIZE_128] = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
        ];

        fn helper_get_cipher() -> AesCipher {
            AesCipher::new(&KEY, AesKeySize::Aes128)
        }

        #[test]
        fn encrypt_block() {
            let cipher = helper_get_cipher();

            let plaintext = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            let left = cipher.encrypt_block(&plaintext);
            let right = [
                Word::from(CIPHERTEXT[0]),
                Word::from(CIPHERTEXT[1]),
                Word::from(CIPHERTEXT[2]),
                Word::from(CIPHERTEXT[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn decrypt_block() {
            let cipher = helper_get_cipher();

            let ciphertext = [
                Word::from(CIPHERTEXT[0]),
                Word::from(CIPHERTEXT[1]),
                Word::from(CIPHERTEXT[2]),
                Word::from(CIPHERTEXT[3]),
            ];

            let left = cipher.decrypt_block(&ciphertext);
            let right = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn encrypt_then_decrypt_block() {
            let cipher = helper_get_cipher();

            let left = cipher.decrypt_block(&&cipher.encrypt_block(&[
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ]));
            let right = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            assert_eq!(left, right);
        }
    }

    mod encrypt_decrypt_aes192 {
        use super::*;

        const CIPHERTEXT: [u32; AES_BLOCK_SIZE] =
            [0x0157_B159, 0xC778_A975, 0xC8EE_71BE, 0x4973_CCE1];

        #[rustfmt::skip]
        const KEY: [u8; BYTES_PER_WORD * AES_KEY_SIZE_192] = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
            0x28, 0xAE, 0xD2, 0xA6,
            0x09, 0xCF, 0x4F, 0x3C,
        ];

        fn helper_get_cipher() -> AesCipher {
            AesCipher::new(&KEY, AesKeySize::Aes192)
        }

        #[test]
        fn encrypt_block() {
            let cipher = helper_get_cipher();

            let plaintext = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            let left = cipher.encrypt_block(&plaintext);
            let right = [
                Word::from(CIPHERTEXT[0]),
                Word::from(CIPHERTEXT[1]),
                Word::from(CIPHERTEXT[2]),
                Word::from(CIPHERTEXT[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn decrypt_block() {
            let cipher = helper_get_cipher();

            let ciphertext = [
                Word::from(CIPHERTEXT[0]),
                Word::from(CIPHERTEXT[1]),
                Word::from(CIPHERTEXT[2]),
                Word::from(CIPHERTEXT[3]),
            ];

            let left = cipher.decrypt_block(&ciphertext);
            let right = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn encrypt_then_decrypt_block() {
            let cipher = helper_get_cipher();

            let left = cipher.decrypt_block(&&cipher.encrypt_block(&[
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ]));
            let right = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            assert_eq!(left, right);
        }
    }

    mod encrypt_decrypt_aes256 {
        use super::*;

        const CIPHERTEXT: [u32; AES_BLOCK_SIZE] = [0x5EA0CBC0, 0x9CA417B9, 0x8D940DF3, 0x6EC3F5EB];

        #[rustfmt::skip]
        const KEY: [u8; BYTES_PER_WORD * AES_KEY_SIZE_256] = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
            0x28, 0xAE, 0xD2, 0xA6,
            0x09, 0xCF, 0x4F, 0x3C,
            0xAB, 0xF7, 0x15, 0x88,
            0x2B, 0x7E, 0x15, 0x16,
        ];

        fn helper_get_cipher() -> AesCipher {
            AesCipher::new(&KEY, AesKeySize::Aes256)
        }

        #[test]
        fn encrypt_block() {
            let cipher = helper_get_cipher();

            let plaintext = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            let left = cipher.encrypt_block(&plaintext);
            let right = [
                Word::from(CIPHERTEXT[0]),
                Word::from(CIPHERTEXT[1]),
                Word::from(CIPHERTEXT[2]),
                Word::from(CIPHERTEXT[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn decrypt_block() {
            let cipher = helper_get_cipher();

            let ciphertext = [
                Word::from(CIPHERTEXT[0]),
                Word::from(CIPHERTEXT[1]),
                Word::from(CIPHERTEXT[2]),
                Word::from(CIPHERTEXT[3]),
            ];

            let left = cipher.decrypt_block(&ciphertext);
            let right = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            assert_eq!(left, right);
        }

        #[test]
        fn encrypt_then_decrypt_block() {
            let cipher = helper_get_cipher();

            let left = cipher.decrypt_block(&cipher.encrypt_block(&[
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ]));
            let right = [
                Word::from(PLAINTEXT[0]),
                Word::from(PLAINTEXT[1]),
                Word::from(PLAINTEXT[2]),
                Word::from(PLAINTEXT[3]),
            ];

            assert_eq!(left, right);
        }
    }
}
