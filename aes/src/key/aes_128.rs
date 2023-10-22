use crate::consts::AES_NUM_ROUNDS_128;

use super::{Aes128KeyExpansionStrategy, AesBlock, AesKeyExpansionStrategy};

impl AesKeyExpansionStrategy for Aes128KeyExpansionStrategy {
    fn get_round_key(&self, round_num: usize) -> &AesBlock {
        &self._round_keys[round_num]
    }

    fn round_keys_num(&self) -> usize {
        self._round_keys.len()
    }
}

impl Aes128KeyExpansionStrategy {
    fn expand_key_128(_key_bytes: &[u8]) -> [AesBlock; AES_NUM_ROUNDS_128] {
        unimplemented!("expand_key_128")
    }

    pub fn new(init_key: &[u8]) -> Self {
        let _round_keys = Self::expand_key_128(init_key);

        Self { _round_keys }
    }
}

#[cfg(test)]
mod tests {
    use crate::consts::{_AES_KEY_SIZE_128, _BYTES_PER_WORD};

    use super::*;

    #[ignore = "not implemented"]
    #[test]
    fn trivial_all_zeros() {
        const AES128_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_128] = [
            [0x0, 0x0, 0x0, 0x0],
            [0x6263_6363, 0x6263_6363, 0x6263_6363, 0x6263_6363],
            [0x9B98_98C9, 0xF9FB_FBAA, 0x9B98_98C9, 0xF9FB_FBAA],
            [0x9097_3450, 0x696C_CFFA, 0xF2F4_5733, 0x0B0F_AC99],
            [0xEE06_DA7B, 0x876A_1581, 0x759E_42B2, 0x7E91_EE2B],
            [0x7F2E_2B88, 0xF844_3E09, 0x8DDA_7CBB, 0xF34B_9290],
            [0xEC61_4B85, 0x1425_758C, 0x99FF_0937, 0x6AB4_9BA7],
            [0x2175_1787, 0x3550_620B, 0xACAF_6B3C, 0xC61B_F09B],
            [0x0EF9_0333, 0x3BA9_6138, 0x9706_0A04, 0x511D_FA9F],
            [0xB1D4_D8E2, 0x8A7D_B9DA, 0x1D7B_B3DE, 0x4C66_4941],
            [0xB4EF_5BCB, 0x3E92_E211, 0x23E9_51CF, 0x6F8F_188E],
        ];

        let left =
            Aes128KeyExpansionStrategy::expand_key_128(&[0x0; _AES_KEY_SIZE_128 * _BYTES_PER_WORD]);
        let mut right = [[Word::zero(); AES_BLOCK_SIZE]; AES_NUM_ROUNDS_128];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES128_KEYS[i][j]);
            }
        }

        assert_eq!(left, right);
    }

    #[ignore = "not implemented"]
    #[test]
    fn trivial_all_ones() {
        const AES128_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_128] = [
            [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF],
            [0xE8E9_E9E9, 0x1716_1616, 0xE8E9_E9E9, 0x1716_1616],
            [0xADAE_AE19, 0xBAB8_B80F, 0x5251_51E6, 0x4547_47F0],
            [0x090E_2277, 0xB3B6_9A78, 0xE1E7_CB9E, 0xA4A0_8C6E],
            [0xE16A_BD3E, 0x52DC_2746, 0xB33B_ECD8, 0x179B_60B6],
            [0xE5BA_F3CE, 0xB766_D488, 0x045D_3850, 0x13C6_58E6],
            [0x71D0_7DB3, 0xC6B6_A93B, 0xC2EB_916B, 0xD12D_C98D],
            [0xE90D_208D, 0x2FBB_89B6, 0xED50_18DD, 0x3C7D_D150],
            [0x9633_7366, 0xB988_FAD0, 0x54D8_E20D, 0x68A5_335D],
            [0x8BF0_3F23, 0x3278_C5F3, 0x66A0_27FE, 0x0E05_14A3],
            [0xD60A_3588, 0xE472_F07B, 0x82D2_D785, 0x8CD7_C326],
        ];

        let left =
            Aes128KeyExpansionStrategy::expand_key_128(&[0xFF; AES_BLOCK_SIZE * _BYTES_PER_WORD]);
        let mut right = [[Word::zero(); _AES_KEY_SIZE_128]; AES_NUM_ROUNDS_128];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES128_KEYS[i][j]);
            }
        }

        assert_eq!(left, right);
    }

    #[ignore = "not implemented"]
    #[test]
    fn trivial_incremental_bytes() {
        const AES128_KEYS: [[u32; AES_BLOCK_SIZE]; AES_NUM_ROUNDS_128] = [
            [0x0001_0203, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F],
            [0xD6AA_74FD, 0xD2AF_72FA, 0xDAA6_78F1, 0xD6AB_76FE],
            [0xB692_CF0B, 0x643D_BDF1, 0xBE9B_C500, 0x6830_B3FE],
            [0xB6FF_744E, 0xD2C2_C9BF, 0x6C59_0CBF, 0x0469_BF41],
            [0x47F7_F7BC, 0x9535_3E03, 0xF96C_32BC, 0xFD05_8DFD],
            [0x3CAA_A3E8, 0xA99F_9DEB, 0x50F3_AF57, 0xADF6_22AA],
            [0x5E39_0F7D, 0xF7A6_9296, 0xA755_3DC1, 0x0AA3_1F6B],
            [0x14F9_701A, 0xE35F_E28C, 0x440A_DF4D, 0x4EA9_C026],
            [0x4743_8735, 0xA41C_65B9, 0xE016_BAF4, 0xAEBF_7AD2],
            [0x5499_32D1, 0xF085_5768, 0x1093_ED9C, 0xBE2C_974E],
            [0x1311_1D7F, 0xE394_4A17, 0xF307_A78B, 0x4D2B_30C5],
        ];

        let left = Aes128KeyExpansionStrategy::expand_key_128(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);
        let mut right = [[Word::zero(); AES_BLOCK_SIZE]; AES_NUM_ROUNDS_128];

        for i in 0..left.len() {
            for j in 0..left[i].len() {
                right[i][j] = Word::from(AES128_KEYS[i][j]);
            }
        }

        assert_eq!(left, right);
    }
}
