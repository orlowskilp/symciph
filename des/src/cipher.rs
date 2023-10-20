use super::{consts::*, DesCipher, DesKey, Word};

impl DesCipher {
    pub fn new(init_key: &[u8; 8]) -> Self {
        Self {
            key: DesKey::new(init_key),
        }
    }

    pub fn encrypt(&self, plaintext_block: &[u8; 8]) -> [u8; 8] {
        self.encrypt_block(Word::from(plaintext_block)).into()
    }

    pub fn decrypt(&self, ciphertext_block: &[u8; 8]) -> [u8; 8] {
        self.decrypt_block(Word::from(ciphertext_block)).into()
    }

    fn encrypt_block(&self, plaintext: Word) -> Word {
        let mut ciphertext = Self::initial_permutation(plaintext);

        for round_key in self.key.iter() {
            ciphertext = Self::feistel_network_round(ciphertext, *round_key);
        }

        Self::final_permutation(ciphertext)
    }

    fn decrypt_block(&self, ciphertext: Word) -> Word {
        let mut plaintext = Self::initial_permutation(ciphertext);

        for round_key in self.key.iter().rev() {
            plaintext = DesCipher::feistel_network_round(plaintext, *round_key);
        }

        Self::final_permutation(plaintext)
    }

    fn feistel_network_round(data: Word, key: Word) -> Word {
        let (left, right) = data.split(BLOCK_LENGTH / 2);

        let new_left = right;
        let new_right = left ^ Self::feistel_function(right, key);

        new_right.concatenate(new_left, BLOCK_LENGTH / 2)
    }

    fn feistel_function(data: Word, key: Word) -> Word {
        let expanded_data = Self::apply_ebox(data);

        let substituted_data = Self::apply_sboxes(expanded_data ^ key);

        Self::apply_pbox(substituted_data)
    }

    fn initial_permutation(data: Word) -> Word {
        data.permute_bits(IP_TABLE.len(), &IP_TABLE)
    }

    fn apply_ebox(data: Word) -> Word {
        const HALF_BLOCK_LENGTH: usize = BLOCK_LENGTH / 2;

        data.permute_bits(HALF_BLOCK_LENGTH, &EBOX)
    }

    fn apply_sboxes(data: Word) -> Word {
        const INPUT_LENGTH: usize = COMPRESSED_KEY_LENGTH;
        const INPUT_SUBWORD_LENGTH: usize = INPUT_LENGTH / SBOX_ARRAY.len();
        const OUTPUT_SUBWORD_LENGTH: usize = 4;
        const MASK: Word = Word::ones(INPUT_SUBWORD_LENGTH);

        let mut output = Word::zero();

        for (i, sbox) in SBOX_ARRAY.iter().rev().enumerate() {
            let subword: u64 = (data >> (i * INPUT_SUBWORD_LENGTH) & MASK).into();

            let substitution = Word::from(sbox[subword as usize]);

            output |= substitution << (i * OUTPUT_SUBWORD_LENGTH);
        }

        output
    }

    fn apply_pbox(data: Word) -> Word {
        data.permute_bits(PBOX.len(), &PBOX)
    }

    fn final_permutation(data: Word) -> Word {
        data.permute_bits(FP_TABLE.len(), &FP_TABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod permutation_helpers {
        use super::*;

        #[test]
        fn initial_permutation_only_last_on() {
            let w = Word::one();

            let left = DesCipher::initial_permutation(w);
            let right = Word::one() << 39u8;

            assert_eq!(left, right);
        }

        #[test]
        fn initial_permutation_only_first_on() {
            let w = Word::one() << 63u8;

            let left = DesCipher::initial_permutation(w);
            let right = Word::one() << 24u8;

            assert_eq!(left, right);
        }

        #[test]
        fn final_permutation_only_last_on() {
            let w = Word::one();

            let left = DesCipher::final_permutation(w);
            let right = Word::one() << 57u8;

            assert_eq!(left, right);
        }

        #[test]
        fn final_permutation_only_first_on() {
            let w = Word::one() << 63u8;

            let left = DesCipher::final_permutation(w);
            let right = Word::one() << 6u8;

            assert_eq!(left, right);
        }

        #[test]
        fn initial_and_final_permutation() {
            const WORD_LEN_64: u64 =
                0b1100_1010_1110_1010_0101_1100_1110_0010_0001_0011_0110_1010_0000_1100_1011_0001;
            let w = Word::from(WORD_LEN_64);

            let left = DesCipher::initial_permutation(DesCipher::final_permutation(w));
            let right = w;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_pbox_only_first_on() {
            let w = Word::one() << 31u8;

            let left = DesCipher::apply_pbox(w);
            let right = Word::one() << 23u8;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_pbox_only_last_on() {
            let w = Word::one();

            let left = DesCipher::apply_pbox(w);
            let right = Word::one() << 11u8;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_pbox_all_ones() {
            let w = Word::ones(32usize);

            let left = DesCipher::apply_pbox(w);
            let right = w;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_ebox_only_first_on() {
            let w = Word::one() << 31u8;

            let left = DesCipher::apply_ebox(w);
            let right = Word::one() << 46u8 | Word::one();

            assert_eq!(left, right);
        }

        #[test]
        fn apply_ebox_only_last_on() {
            let w = Word::one();

            let left = DesCipher::apply_ebox(w);
            let right = Word::one() << 47u8 | Word::one() << 1u8;

            assert_eq!(left, right);
        }

        #[test]
        fn apply_ebox_all_ones() {
            let w = Word::ones(32usize);

            let left = DesCipher::apply_ebox(w);
            let right = Word::ones(48usize);

            assert_eq!(left, right);
        }
    }

    mod block_encrypt_and_decrypt {
        use super::*;

        const KEY: [u8; 8] = [0x0A, 0xEA, 0x5C, 0xE2, 0x13, 0x6A, 0x0C, 0xB1];
        const PLAINTEXT: u64 = 0x00E4_CF83_2D26;
        const CIPHERTEXT: u64 = 0x0400_00E4_CBC6_3936;

        #[test]
        fn test_encrypt_block() {
            let des = DesCipher::new(&KEY);
            let left = des.encrypt_block(Word::from(PLAINTEXT));
            let right = Word::from(CIPHERTEXT);

            assert_eq!(left, right);
        }

        #[test]
        fn test_decrypt_block() {
            let des = DesCipher::new(&KEY);
            let left = des.decrypt_block(Word::from(CIPHERTEXT));
            let right = Word::from(PLAINTEXT);

            assert_eq!(left, right);
        }

        #[test]
        fn test_encrypt_and_decrypt_block() {
            let des = DesCipher::new(&KEY);
            let left = des.decrypt_block(des.encrypt_block(Word::from(PLAINTEXT)));
            let right = Word::from(PLAINTEXT);

            assert_eq!(left, right);
        }
    }

    #[test]
    fn feistel_function_non_trivial() {
        const INPUT: u64 = 0b0000_0001_0100_0000_0000_0011_0000_1100;
        const KEY: u64 = 0b0100_0001_0111_1001_0110_1111_0000_0000_1100_0100_0110_1000;

        let input = Word::from(INPUT);
        let key = Word::from(KEY);

        let left = DesCipher::feistel_function(input, key);
        let right = Word::from(0b0100_0000_0011_0011_0011_0100_1000_0000u64);

        assert_eq!(left, right);
    }
}
