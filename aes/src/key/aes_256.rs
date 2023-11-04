use crate::consts::AES_NUM_ROUNDS_256;

use super::{Aes256KeyExpansionStrategy, AesBlock, AesKeyExpansionStrategy};

impl AesKeyExpansionStrategy for Aes256KeyExpansionStrategy {
    fn get_round_key(&self, round_num: usize) -> &AesBlock {
        &self.round_keys[round_num]
    }

    fn round_keys_num(&self) -> usize {
        self.round_keys.len()
    }
}

impl Aes256KeyExpansionStrategy {
    fn expand_key_256(_key_bytes: &[u8]) -> [AesBlock; AES_NUM_ROUNDS_256] {
        unimplemented!("expand_key_256")
    }

    pub fn new(init_key: &[u8]) -> Self {
        let round_keys = Self::expand_key_256(init_key);

        Self { round_keys }
    }
}

#[cfg(test)]
mod tests {
    use crypto_primitives::Word;

    use crate::consts::{AES_BLOCK_SIZE, BYTES_PER_WORD, _AES_KEY_SIZE_256};

    use super::*;

    #[ignore = "not implemented"]
    #[test]
    fn trivial_all_zeros() {
        const AES256_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_256] = [
            [0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0],
            [0x6263_6363, 0x6263_6363, 0x6263_6363, 0x6263_6363],
            [0xAAFB_FBFB, 0xAAFB_FBFB, 0xAAFB_FBFB, 0xAAFB_FBFB],
            [0x6F6C_6CCF, 0x0D0F_0FAC, 0x6F6C_6CCF, 0x0D0F_0FAC],
            [0x7D8D_8D6A, 0xD776_7691, 0x7D8D_8D6A, 0xD776_7691],
            [0x5354_EDC1, 0x5E5B_E26D, 0x3137_8EA2, 0x3C38_810E],
            [0x968A_81C1, 0x41FC_F750, 0x3C71_7A3A, 0xEB07_0CAB],
            [0x9EAA_8F28, 0xC0F1_6D45, 0xF1C6_E3E7, 0xCDFE_62E9],
            [0x2B31_2BDF, 0x6ACD_DC8F, 0x56BC_A6B5, 0xBDBB_AA1E],
            [0x6406_FD52, 0xA4F7_9017, 0x5531_73F0, 0x98CF_1119],
            [0x6DBB_A90B, 0x0776_7584, 0x51CA_D331, 0xEC71_792F],
            [0xE7B0_E89C, 0x4347_788B, 0x1676_0B7B, 0x8EB9_1A62],
            [0x74ED_0BA1, 0x739B_7E25, 0x2251_AD14, 0xCE20_D43B],
            [0x10F8_0A17, 0x53BF_729C, 0x45C9_79E7, 0xCB70_6385],
        ];

        let left =
            Aes256KeyExpansionStrategy::expand_key_256(&[0x0; _AES_KEY_SIZE_256 * BYTES_PER_WORD]);
        let mut right = [[Word::zero(); AES_BLOCK_SIZE]; AES_NUM_ROUNDS_256];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES256_KEYS[i][j]);
            }
        }

        assert_eq!(left, right)
    }

    #[ignore = "not implemented"]
    #[test]
    fn trivial_all_ones() {
        const AES256_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_256] = [
            [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF],
            [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF],
            [0xE8E9_E9E9, 0x1716_1616, 0xE8E9_E9E9, 0x1716_1616],
            [0x0FB8_B8B8, 0xF047_4747, 0x0FB8_B8B8, 0xF047_4747],
            [0x4A49_4965, 0x5D5F_5F73, 0xB5B6_B69A, 0xA2A0_A08C],
            [0x3558_58DC, 0xC51F_1F9B, 0xCAA7_A723, 0x3AE0_E064],
            [0xAFA8_0AE5, 0xF2F7_5596, 0x4741_E30C, 0xE5E1_4380],
            [0xECA0_4211, 0x29BF_5D8A, 0xE318_FAA9, 0xD9F8_1ACD],
            [0xE60A_B7D0, 0x14FD_E246, 0x53BC_014A, 0xB65D_42CA],
            [0xA2EC_6E65, 0x8B53_33EF, 0x684B_C946, 0xB1B3_D38B],
            [0x9B6C_8A18, 0x8F91_685E, 0xDC2D_6914, 0x6A70_2BDE],
            [0xA0BD_9F78, 0x2BEE_AC97, 0x43A5_65D1, 0xF216_B65A],
            [0xFC22_3491, 0x73B3_5CCF, 0xAF9E_35DB, 0xC5EE_1E05],
            [0x0695_ED13, 0x2D7B_4184, 0x6EDE_2455, 0x9CC8_920F],
            [0x546D_424F, 0x27DE_1E80, 0x8840_2B5B, 0x4DAE_355E],
        ];

        let left =
            Aes256KeyExpansionStrategy::expand_key_256(&[0xFF; _AES_KEY_SIZE_256 * BYTES_PER_WORD]);
        let mut right = [[Word::zero(); AES_BLOCK_SIZE]; AES_NUM_ROUNDS_256];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES256_KEYS[i][j]);
            }
        }

        assert_eq!(left, right);
    }

    #[ignore = "not implemented"]
    #[test]
    fn trivial_incremental_bytes() {
        const AES256_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_256] = [
            [0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F],
            [0x1011_1213, 0x1415_1617, 0x1819_1A1B, 0x1C1D_1E1F],
            [0xA573_C29F, 0xA176_C498, 0xA97F_CE93, 0xA572_C09C],
            [0x1651_A8CD, 0x0244_BEDA, 0x1A5D_A4C1, 0x0640_BADE],
            [0xAE87_DFF0, 0x0FF1_1B68, 0xA68E_D5FB, 0x03FC_1567],
            [0x6DE1_F148, 0x6FA5_4F92, 0x75F8_EB53, 0x73B8_518D],
            [0xC656_827F, 0xC9A7_9917, 0x6F29_4CEC, 0x6CD5_598B],
            [0x3DE2_3A75, 0x5247_75E7, 0x27BF_9EB4, 0x5407_CF39],
            [0x0BDC_905F, 0xC27B_0948, 0xAD52_45A4, 0xC187_1C2F],
            [0x45F5_A660, 0x17B2_D387, 0x300D_4D33, 0x640A_820A],
            [0x7CCF_F71C, 0xBEB4_FE54, 0x13E6_BBF0, 0xD261_A7DF],
            [0xF01A_FAFE, 0xE7A8_2979, 0xD7A5_644A, 0xB3AF_E640],
            [0x2541_FE71, 0x9BF5_0025, 0x8813_BBD5, 0x5A72_1C0A],
            [0x4E5A_6699, 0xA9F2_4FE0, 0x7E57_2BAA, 0xCDF8_CDEA],
            [0x24FC_79CC, 0xBF09_79E9, 0x371A_C23C, 0x6D68_DE36],
        ];

        let left = Aes256KeyExpansionStrategy::expand_key_256(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ]);
        let mut right = [[Word::zero(); AES_BLOCK_SIZE]; AES_NUM_ROUNDS_256];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES256_KEYS[i][j]);
            }
        }

        assert_eq!(left, right);
    }
}
