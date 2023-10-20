pub mod consts;

use consts::*;
use crypto_primitives::Word;

pub struct DesCipher {
    generated_keys: [Word; NUM_ROUNDS],
}

impl DesCipher {
    // Key length in 64 bit blocks
    pub const KEY_LEN: usize = 1;

    pub fn new(key: &[u64]) -> Self {
        Self {
            generated_keys: Self::generate_key(&Word::from(key[0])),
        }
    }

    fn encrypt_block(&self, plaintext_block: &Word) -> Word {
        let mut ciphertext_block = Self::ip(plaintext_block);
        for round_key in self.generated_keys.iter() {
            ciphertext_block = Self::fn_round(&ciphertext_block, round_key);
        }
        Self::fp(&ciphertext_block)
    }

    fn decrypt_block(&self, ciphertext_block: &Word) -> Word {
        let mut plaintext_block = Self::ip(ciphertext_block);
        for round_key in self.generated_keys.iter().rev() {
            plaintext_block = DesCipher::fn_round(&plaintext_block, round_key);
        }
        Self::fp(&plaintext_block)
    }

    fn ip(data: &Word) -> Word {
        data.permute_bits(IP_TABLE.len(), &IP_TABLE)
    }

    fn apply_ebox(data: &Word) -> Word {
        const HALF_BLOCK_LENGTH: usize = BLOCK_LENGTH / 2;
        data.permute_bits(HALF_BLOCK_LENGTH, &EBOX)
    }

    fn apply_sboxes(data: &Word) -> Word {
        const INPUT_LENGTH: usize = COMPRESSED_KEY_LENGTH;
        const INPUT_SUBWORD_LENGTH: usize = INPUT_LENGTH / SBOX_ARRAY.len();
        const OUTPUT_SUBWORD_LENGTH: usize = 4;
        const MASK: Word = Word::ones(INPUT_SUBWORD_LENGTH);

        let mut output = Word::zero();

        for (i, sbox) in SBOX_ARRAY.iter().rev().enumerate() {
            let subword: u64 = (*data >> (i * INPUT_SUBWORD_LENGTH) & MASK).into();
            let substitution = Word::from(sbox[subword as usize]);
            output |= substitution << (i * OUTPUT_SUBWORD_LENGTH);
        }

        output
    }

    fn apply_pbox(data: &Word) -> Word {
        data.permute_bits(PBOX.len(), &PBOX)
    }

    fn f(data: &Word, key: &Word) -> Word {
        let expanded_data = Self::apply_ebox(data);
        let xored_data = expanded_data ^ *key;
        let substituted_data = Self::apply_sboxes(&xored_data);

        Self::apply_pbox(&substituted_data)
    }

    fn fn_round(data: &Word, key: &Word) -> Word {
        let (left, right) = data.split(BLOCK_LENGTH / 2);
        let new_left = right;
        let new_right = left ^ Self::f(&right, key);

        new_right.concatenate(new_left, BLOCK_LENGTH / 2)
    }

    fn fp(data: &Word) -> Word {
        data.permute_bits(FP_TABLE.len(), &FP_TABLE)
    }

    fn pc1(key: &Word) -> Word {
        key.permute_bits(KEY_LENGTH, &PC1_TABLE)
    }

    fn pc2(key: &Word) -> Word {
        key.permute_bits(REDUCED_KEY_LENGTH, &PC2_TABLE)
    }

    fn generate_key(init_key: &Word) -> [Word; NUM_ROUNDS] {
        let mut keys: [Word; NUM_ROUNDS] = [Word::zero(); NUM_ROUNDS];
        let key = Self::pc1(init_key);
        let (mut c, mut d) = key.split(SUBKEY_LENGTH);

        for (i, round_key) in keys.iter_mut().enumerate() {
            c = c.rotate_left(SHIFT_VALUES[i], SUBKEY_LENGTH);
            d = d.rotate_left(SHIFT_VALUES[i], SUBKEY_LENGTH);

            *round_key = Self::pc2(&c.concatenate(d, SUBKEY_LENGTH));
        }

        keys
    }
}

impl DesCipher {
    pub fn encrypt(&self, plaintext_block: u64) -> u64 {
        self.encrypt_block(&Word::from(plaintext_block)).into()
    }

    pub fn decrypt(&self, ciphertext_block: u64) -> u64 {
        self.decrypt_block(&Word::from(ciphertext_block)).into()
    }
}

#[cfg(test)]
mod des_cipher {
    use super::*;

    mod gen_key_helpers {
        use super::*;

        #[test]
        fn pc1_only_first_on() {
            let w = Word::one() << 63u8;

            let left = DesCipher::pc1(&w);
            let right = Word::one() << 48u8;

            assert_eq!(left, right);
        }

        #[test]
        fn pc1_only_last_on() {
            let w = Word::one();

            let left = DesCipher::pc1(&w);
            let right = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn pc1_parity_bits_only() {
            let mut w = Word::one();
            for i in 1..8 {
                w |= Word::one() << i * 8u8;
            }

            let left = DesCipher::pc1(&w);
            let right = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn pc1_all_ones() {
            let w = Word::ones(64usize);

            let left = DesCipher::pc1(&w);
            let right = Word::ones(56usize);

            assert_eq!(left, right);
        }

        #[test]
        fn pc2_only_first_on() {
            let w = Word::one() << 55u8;

            let left = DesCipher::pc2(&w);
            let right = Word::one() << 43u8;

            assert_eq!(left, right);
        }

        #[test]
        fn pc2_only_last_on() {
            let w = Word::one();

            let left = DesCipher::pc2(&w);
            let right = Word::one() << 8u8;

            assert_eq!(left, right);
        }

        #[test]
        fn pc2_all_ones() {
            let w = Word::ones(56usize);

            let left = DesCipher::pc2(&w);
            let right = Word::ones(48usize);

            assert_eq!(left, right);
        }

        #[test]
        fn gen_key_all_zeros() {
            let keys: [Word; NUM_ROUNDS] = DesCipher::generate_key(&Word::zero());

            let right = Word::zero();
            assert!(keys.iter().all(|&left| left == right), "left != right");
        }

        #[test]
        fn gen_key_all_ones() {
            let keys: [Word; NUM_ROUNDS] = DesCipher::generate_key(&Word::ones(64usize));

            let right = Word::ones(48usize);
            assert!(keys.iter().all(|&left| left == right), "left != right");
        }
    }

    mod permutation_helpers {
        use super::*;

        #[test]
        fn ip_only_last_on() {
            let w = Word::one();

            let left = DesCipher::ip(&w);
            let right = Word::one() << 39u8;

            assert_eq!(left, right);
        }

        #[test]
        fn ip_only_first_on() {
            let w = Word::one() << 63u8;

            let left = DesCipher::ip(&w);
            let right = Word::one() << 24u8;

            assert_eq!(left, right);
        }

        #[test]
        fn fp_only_last_on() {
            let w = Word::one();

            let left = DesCipher::fp(&w);
            let right = Word::one() << 57u8;

            assert_eq!(left, right);
        }

        #[test]
        fn fp_only_first_on() {
            let w = Word::one() << 63u8;

            let left = DesCipher::fp(&w);
            let right = Word::one() << 6u8;

            assert_eq!(left, right);
        }

        #[test]
        fn ip_and_fp() {
            const WORD_LEN_64: u64 =
                0b1100_1010_1110_1010_0101_1100_1110_0010_0001_0011_0110_1010_0000_1100_1011_0001;
            let w = Word::from(WORD_LEN_64);

            let left = DesCipher::ip(&DesCipher::fp(&w));
            let right = w;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_pbox_only_first_on() {
            let w = Word::one() << 31u8;

            let left = DesCipher::apply_pbox(&w);
            let right = Word::one() << 23u8;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_pbox_only_last_on() {
            let w = Word::one();

            let left = DesCipher::apply_pbox(&w);
            let right = Word::one() << 11u8;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_pbox_all_ones() {
            let w = Word::ones(32usize);

            let left = DesCipher::apply_pbox(&w);
            let right = w;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_ebox_only_first_on() {
            let w = Word::one() << 31u8;

            let left = DesCipher::apply_ebox(&w);
            let right = Word::one() << 46u8 | Word::one();

            assert_eq!(left, right);
        }

        #[test]
        fn apply_ebox_only_last_on() {
            let w = Word::one();

            let left = DesCipher::apply_ebox(&w);
            let right = Word::one() << 47u8 | Word::one() << 1u8;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_ebox_all_ones() {
            let w = Word::ones(32usize);

            let left = DesCipher::apply_ebox(&w);
            let right = Word::ones(48usize);

            assert_eq!(left, right);
        }
    }

    mod block_encrypt_and_decrypt {
        use super::*;

        const KEY: [u64; 1] = [0x0AEA_5CE2_136A_0CB1];
        const PLAINTEXT: u64 = 0x00E4_CF83_2D26;
        const CIPHERTEXT: u64 = 0x0400_00E4_CBC6_3936;

        #[test]
        fn test_encrypt_block() {
            let des = DesCipher::new(&KEY);
            let left = des.encrypt_block(&Word::from(PLAINTEXT));
            let right = Word::from(CIPHERTEXT);

            assert_eq!(left, right);
        }

        #[test]
        fn test_decrypt_block() {
            let des = DesCipher::new(&KEY);
            let left = des.decrypt_block(&Word::from(CIPHERTEXT));
            let right = Word::from(PLAINTEXT);

            assert_eq!(left, right);
        }

        #[test]
        fn test_encrypt_and_decrypt_block() {
            let des = DesCipher::new(&KEY);
            let left = des.decrypt_block(&des.encrypt_block(&Word::from(PLAINTEXT)));
            let right = Word::from(PLAINTEXT);

            assert_eq!(left, right);
        }
    }

    #[test]
    fn f_non_trivial() {
        const INPUT: u64 = 0b0000_0001_0100_0000_0000_0011_0000_1100;
        const KEY: u64 = 0b0100_0001_0111_1001_0110_1111_0000_0000_1100_0100_0110_1000;

        let input = Word::from(INPUT);
        let key = Word::from(KEY);

        let left = DesCipher::f(&input, &key);
        let right = Word::from(0b0100_0000_0011_0011_0011_0100_1000_0000u64);

        assert_eq!(left, right);
    }
}
