use crate::consts::AES_NUM_ROUNDS_192;

use super::{Aes192KeyExpansionStrategy, AesBlock, AesKeyExpansionStrategy};

impl AesKeyExpansionStrategy for Aes192KeyExpansionStrategy {
    fn get_round_key(&self, round_num: usize) -> &AesBlock {
        &self.round_keys[round_num]
    }

    fn round_keys_num(&self) -> usize {
        self.round_keys.len()
    }
}

impl Aes192KeyExpansionStrategy {
    fn expand_key_192(_key_bytes: &[u8]) -> [AesBlock; AES_NUM_ROUNDS_192] {
        unimplemented!("expand_key_192")
    }

    pub fn new(init_key: &[u8]) -> Self {
        let round_keys = Self::expand_key_192(init_key);

        Self { round_keys }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{AES_BLOCK_SIZE, BYTES_PER_WORD, _AES_KEY_SIZE_192};
    use crypto_primitives::Word;

    #[ignore = "not implemented"]
    #[test]
    fn trivial_all_zeros() {
        const AES192_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_192] = [
            [0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x6263_6363, 0x6263_6363],
            [0x6263_6363, 0x6263_6363, 0x6263_6363, 0x6263_6363],
            [0x9B98_98C9, 0xF9FB_FBAA, 0x9B98_98C9, 0xF9FB_FBAA],
            [0x9B98_98C9, 0xF9FB_FBAA, 0x9097_3450, 0x696C_CFFA],
            [0xF2F4_5733, 0x0B0F_AC99, 0x9097_3450, 0x696C_CFFA],
            [0xC81D_19A9, 0xA171_D653, 0x5385_8160, 0x588A_2DF9],
            [0xC81D_19A9, 0xA171_D653, 0x7BEB_F49B, 0xDA9A_22C8],
            [0x891F_A3A8, 0xD195_8E51, 0x1988_97F8, 0xB8F9_41AB],
            [0xC268_96F7, 0x18F2_B43F, 0x91ED_1797, 0x4078_99C6],
            [0x59F0_0E3E, 0xE109_4F95, 0x83EC_BC0F, 0x9B1E_0830],
            [0x0AF3_1FA7, 0x4A8B_8661, 0x137B_885F, 0xF272_C7CA],
            [0x432A_C886, 0xD834_C0B6, 0xD2C7_DF11, 0x984C_5970],
        ];

        let left =
            Aes192KeyExpansionStrategy::expand_key_192(&[0x0; _AES_KEY_SIZE_192 * BYTES_PER_WORD]);
        let mut right = [[Word::zero(); AES_BLOCK_SIZE]; AES_NUM_ROUNDS_192];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES192_KEYS[i][j]);
            }
        }

        assert_eq!(left, right);
    }

    #[ignore = "not implemented"]
    #[test]
    fn trivial_all_ones() {
        const AES192_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_192] = [
            [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF],
            [0xFFFF_FFFF, 0xFFFF_FFFF, 0xE8E9_E9E9, 0x1716_1616],
            [0xE8E9_E9E9, 0x1716_1616, 0xE8E9_E9E9, 0x1716_1616],
            [0xADAE_AE19, 0xBAB8_B80F, 0x5251_51E6, 0x4547_47F0],
            [0xADAE_AE19, 0xBAB8_B80F, 0xC5C2_D8ED, 0x7F7A_60E2],
            [0x2D2B_3104, 0x686C_76F4, 0xC5C2_D8ED, 0x7F7A_60E2],
            [0x1712_403F, 0x6868_20DD, 0x4543_11D9, 0x2D2F_672D],
            [0xE8ED_BFC0, 0x9797_DF22, 0x8F8C_D3B7, 0xE7E4_F36A],
            [0xA2A7_E2B3, 0x8F88_859E, 0x6765_3A5E, 0xF0F2_E57C],
            [0x2655_C33B, 0xC1B1_3051, 0x6316_D2E2, 0xEC9E_577C],
            [0x8BFB_6D22, 0x7B09_885E, 0x6791_9B1A, 0xA620_AB4B],
            [0xC536_79A9, 0x29A8_2ED5, 0xA253_43F7, 0xD95A_CBA9],
            [0x598E_482F, 0xFFAE_E364, 0x3A98_9ACD, 0x1330_B418],
        ];

        let left =
            Aes192KeyExpansionStrategy::expand_key_192(&[0xFF; _AES_KEY_SIZE_192 * BYTES_PER_WORD]);
        let mut right = [[Word::zero(); AES_BLOCK_SIZE]; AES_NUM_ROUNDS_192];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES192_KEYS[i][j]);
            }
        }

        assert_eq!(left, right);
    }

    #[ignore = "not implemented"]
    #[test]
    fn trivial_incremental_bytes() {
        const AES192_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_192] = [
            [0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F],
            [0x1011_1213, 0x1415_1617, 0x5846_F2F9, 0x5C43_F4FE],
            [0x544A_FEF5, 0x5847_F0FA, 0x4856_E2E9, 0x5C43_F4FE],
            [0x40F9_49B3, 0x1CBA_BD4D, 0x48F0_43B8, 0x10B7_B342],
            [0x58E1_51AB, 0x04A2_A555, 0x7EFF_B541, 0x6245_080C],
            [0x2AB5_4BB4, 0x3A02_F8F6, 0x62E3_A95D, 0x6641_0C08],
            [0xF501_8572, 0x9744_8D7E, 0xBDF1_C6CA, 0x87F3_3E3C],
            [0xE510_9761, 0x8351_9B69, 0x3415_7C9E, 0xA351_F1E0],
            [0x1EA0_372A, 0x9953_0916, 0x7C43_9E77, 0xFF12_051E],
            [0xDD7E_0E88, 0x7E2F_FF68, 0x608F_C842, 0xF9DC_C154],
            [0x859F_5F23, 0x7A8D_5A3D, 0xC0C0_2952, 0xBEEF_D63A],
            [0xDE60_1E78, 0x27BC_DF2C, 0xA223_800F, 0xD8AE_DA32],
            [0xA497_0A33, 0x1A78_DC09, 0xC418_C271, 0xE3A4_1D5D],
        ];

        let left = Aes192KeyExpansionStrategy::expand_key_192(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ]);
        let mut right = [[Word::zero(); AES_BLOCK_SIZE]; AES_NUM_ROUNDS_192];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES192_KEYS[i][j]);
            }
        }

        assert_eq!(left, right);
    }
}
