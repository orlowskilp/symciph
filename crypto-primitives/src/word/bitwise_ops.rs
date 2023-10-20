use super::Word;

impl Word {
    pub fn split(self, subword_len: usize) -> (Self, Self) {
        assert!(
            subword_len <= Self::MAX_LENGTH / 2 && subword_len > 0,
            "Word: attempt to split word into subwords with invalid length"
        );

        assert!(
            self.len() <= subword_len * 2,
            "Word: attempt to split word into subwords shorter than half the word length"
        );

        let right_mask = Self::ones(subword_len);

        (self >> subword_len, self & right_mask)
    }

    pub fn concatenate(self, rhs: Self, subword_len: usize) -> Self {
        let max_subword_len = Self::MAX_LENGTH / 2;

        assert!(
            subword_len != 0,
            "Word: attempt to concatenate words of length 0"
        );

        assert!(
            subword_len <= max_subword_len && subword_len > 0,
            "Word: attempt to concatenate words with invalid subword length"
        );

        assert!(
            self.len() <= max_subword_len && rhs.len() <= max_subword_len,
            "Word: concatenated word longer than desired subword length"
        );

        self << subword_len | rhs
    }

    pub fn rotate_left(self, rotate_by: usize, word_len: usize) -> Self {
        assert!(
            word_len <= Self::MAX_LENGTH,
            "Word: attempted rotation with mask longer than 64 bits"
        );

        // No cyclic rotations
        assert!(
            rotate_by <= word_len,
            "Word: attempted rotation longer than mask"
        );

        assert!(
            self.len() <= word_len,
            "Word: attempted rotation on word longer than mask"
        );

        // Idempotent operation
        if word_len == rotate_by || (word_len == Self::MAX_LENGTH && rotate_by == 0) {
            return self;
        }

        let right_mask = Self::ones(word_len) >> rotate_by;
        let left_mask = Self::ones(word_len) & !right_mask;

        let left = self & left_mask;
        let right = self & right_mask;

        right << rotate_by | left >> (word_len - rotate_by)
    }

    pub fn permute_bits(self, word_len: usize, permutation_array: &[usize]) -> Self {
        assert!(
            word_len <= Self::MAX_LENGTH && permutation_array.len() <= Self::MAX_LENGTH,
            "Word: attempted permutation would result in overflow"
        );

        assert!(
            !permutation_array.is_empty(),
            "Word: attempted permutation with empty permutation array"
        );

        assert!(
            self.len() <= word_len,
            "Word: word length parameter less than actual word length"
        );

        for entry in permutation_array.iter() {
            assert!(
                *entry != 0 && *entry <= word_len,
                "Word: attempted permutation with indices out of bound"
            );
        }

        let mut output = Self::zero();

        for (i, &j) in permutation_array.iter().enumerate() {
            if j <= word_len {
                let bit = (self >> (word_len - j)) & Self::one();
                let position = permutation_array.len() - i - 1;

                output |= bit << position;
            }
        }

        output
    }

    pub fn substitute_bytes(self, word_len_bytes: usize, substitution_array: &[u8; 256]) -> Self {
        const BITS_IN_WORD: usize = Word::MAX_LENGTH / u8::BITS as usize;

        assert!(
            word_len_bytes <= BITS_IN_WORD,
            "Word: attempted substitution with word length longer than 8 bytes"
        );

        assert!(
            word_len_bytes * u8::BITS as usize >= self.len(),
            "Word: attempted substitution with word length less than actual word length"
        );

        let index_from = BITS_IN_WORD - word_len_bytes;
        let mut bytes: [u8; BITS_IN_WORD] = self.into();

        for byte in bytes[index_from..].iter_mut() {
            let index = *byte as usize;
            *byte = substitution_array[index];
        }

        Word::from(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::word::tests::*;
    use crate::Word;

    mod split {
        use super::*;

        #[test]
        #[should_panic]
        fn subword_len_0() {
            Word::from(WORD_LEN_47).split(0usize);
        }

        #[test]
        #[should_panic]
        fn subword_len_shorter_than_half_of_actual_word() {
            const WORD_LEN: usize = 16;

            Word::ones(WORD_LEN).split(WORD_LEN / 2 - 1);
        }

        #[test]
        #[should_panic]
        fn subword_len_too_long() {
            Word::from(WORD_LEN_47).split(Word::MAX_LENGTH + 1);
        }

        #[test]
        fn nontrivial_word_and_subword_len_28() {
            const SW_LEN: usize = 28;
            let w = Word::from(WORD_LEN_52);

            let (left_l, left_r) = w.split(SW_LEN);
            let (right_l, right_r) = (
                Word::from(0b0000_1011_1101_0101_0111_0111_0001u64),
                Word::from(0b0001_0011_1101_0100_0011_0101_1000u64),
            );

            assert_eq!(
                (left_l, left_r),
                (right_l, right_r),
                "Word.split: left subwords not equal right subwords"
            );
            assert_eq!(
                left_l << SW_LEN | left_r,
                w,
                "Word.split: concatenated subwords different from original word"
            );
        }

        #[test]
        fn trivial_ones_max_len() {
            let (left_l, left_r) = Word::MAX.split(Word::MAX_LENGTH / 2);
            let (right_l, right_r) = (
                Word::ones(Word::MAX_LENGTH / 2),
                Word::ones(Word::MAX_LENGTH / 2),
            );

            assert_eq!((left_l, left_r), (right_l, right_r));
        }
    }

    mod concatenate {
        use super::*;

        #[test]
        #[should_panic]
        fn subword_len_0() {
            const SW_LEN: usize = 0;
            let rhs = Word::one();

            Word::ones(Word::MAX_LENGTH / 2).concatenate(rhs, SW_LEN);
        }

        #[test]
        #[should_panic]
        fn subword_len_too_long() {
            const SW_LEN: usize = 33;
            let rhs = Word::one();

            Word::ones(Word::MAX_LENGTH / 2).concatenate(rhs, SW_LEN);
        }

        #[test]
        #[should_panic]
        fn lhs_too_long() {
            const SW_LEN: usize = 32;
            let rhs = Word::one();

            Word::ones(Word::MAX_LENGTH / 2 + 1).concatenate(rhs, SW_LEN);
        }

        #[test]
        #[should_panic]
        fn rhs_too_long() {
            const SW_LEN: usize = 32;
            let rhs = Word::ones(Word::MAX_LENGTH / 2 + 1);

            Word::ones(Word::MAX_LENGTH / 2).concatenate(rhs, SW_LEN);
        }

        #[test]
        fn subword_len_28() {
            const SW_LEN: usize = 28;
            const LEFT_SW: u64 = 0b0000_1011_1101_0101_0111_0111_0001;
            const RIGHT_SW: u64 = 0b0001_0011_1101_0100_0011_0101_1000;

            let left = Word::from(LEFT_SW).concatenate(Word::from(RIGHT_SW), SW_LEN);
            let right = Word::from(WORD_LEN_52);

            assert_eq!(left, right);
        }

        #[test]
        fn subword_len_32() {
            const SW_LEN: usize = 32;
            const LEFT_SW: u64 = 0b0000_1011_1101_0101_0111_0111_0001;
            const RIGHT_SW: u64 = 0b0001_0011_1101_0100_0011_0101_1000;
            const WORD: u64 =
                0b0000_0000_1011_1101_0101_0111_0111_0001_0000_0001_0011_1101_0100_0011_0101_1000;

            let left = Word::from(LEFT_SW).concatenate(Word::from(RIGHT_SW), SW_LEN);
            let right = Word::from(WORD);

            assert_eq!(left, right);
        }

        #[test]
        fn min_subwords() {
            let left = Word::MIN.concatenate(Word::MIN, Word::MIN.len());
            let right = Word::MIN;

            assert_eq!(left, right);
        }

        #[test]
        fn max_subwords() {
            const SW_LEN: usize = Word::MAX_LENGTH / 2;
            let left = Word::ones(SW_LEN).concatenate(Word::ones(SW_LEN), SW_LEN);
            let right = Word::MAX;

            assert_eq!(left, right);
        }
    }

    mod rotate_left {
        use super::*;

        #[test]
        #[should_panic]
        fn rotation_longer_than_mask() {
            const WORD_LEN: usize = 28;
            const ROTATE_BY: usize = WORD_LEN + 1;

            let w = Word::from(WORD_LEN_47);
            w.rotate_left(ROTATE_BY, WORD_LEN);
        }

        #[test]
        #[should_panic]
        fn rotation_shorter_than_word() {
            const WORD_LEN: usize = 28;
            const ROTATE_BY: usize = 22;

            let w = Word::from(WORD_LEN_47);
            w.rotate_left(ROTATE_BY, WORD_LEN);
        }

        #[test]
        #[should_panic]
        fn mask_too_long() {
            const WORD_LEN: usize = Word::MAX_LENGTH + 1;
            const ROTATE_BY: usize = 28;

            let w = Word::from(WORD_LEN_47);
            w.rotate_left(ROTATE_BY, WORD_LEN);
        }

        #[test]
        fn null_rotation() {
            const ROTATE_BY: usize = 0;

            let w = Word::from(WORD_LEN_47);

            let left = w.rotate_left(ROTATE_BY, w.len());
            let right = w;

            assert_eq!(left, right);
        }

        #[test]
        fn full_rotation() {
            let w = Word::from(WORD_LEN_47);

            let left = w.rotate_left(w.len(), w.len());
            let right = w;

            assert_eq!(left, right);
        }

        #[test]
        fn null_rotation_full_mask() {
            const WORD_LEN: usize = Word::MAX_LENGTH;
            const ROTATE_BY: usize = 0;

            let w = Word::from(WORD_LEN_47);

            let left = w.rotate_left(ROTATE_BY, WORD_LEN);
            let right = w;

            assert_eq!(left, right);
        }

        #[test]
        fn by_4_mask_len_28() {
            const WORD_LEN: usize = 28;
            const ROTATE_BY: usize = 4;

            let left = Word::from(WORD_LEN_28).rotate_left(ROTATE_BY, WORD_LEN);
            let right = Word::from(0b0000_1100_1100_1010_1010_1001_1111u64);

            assert_eq!(left, right);
        }

        #[test]
        fn by_63_full_mask() {
            const WORD_LEN: usize = 64;
            const ROTATE_BY: usize = WORD_LEN - 1;

            let left = Word::from(WORD_LEN_60).rotate_left(ROTATE_BY, WORD_LEN);
            let right = Word::from(
                0b1000_0101_0111_0101_0010_1110_0111_0001_0000_1001_1011_0101_0000_0110_0101_1000u64
            );

            assert_eq!(left, right);
        }
    }

    mod permute_bits {
        use super::*;

        #[test]
        #[should_panic]
        fn word_len_zero() {
            const WORD_LEN: usize = 0;
            const ARRAY_LEN: usize = 4;
            const PERMUTATION_ARRAY: [usize; ARRAY_LEN] = [10; ARRAY_LEN];

            Word::from(WORD_LEN_28).permute_bits(WORD_LEN, &PERMUTATION_ARRAY);
        }

        #[test]
        #[should_panic]
        fn word_len_longer_than_max() {
            const WORD_LEN: usize = Word::MAX_LENGTH + 1;
            const ARRAY_LEN: usize = 4;
            const PERMUTATION_ARRAY: [usize; ARRAY_LEN] = [10; ARRAY_LEN];

            Word::from(WORD_LEN_28).permute_bits(WORD_LEN, &PERMUTATION_ARRAY);
        }

        #[test]
        #[should_panic]
        fn permutation_array_empty() {
            const EMPTY_PERMUTATION_ARRAY: [usize; 0] = [];

            Word::from(WORD_LEN_28).permute_bits(30, &EMPTY_PERMUTATION_ARRAY);
        }

        #[test]
        #[should_panic]
        fn permutation_array_too_long() {
            const WORD_LEN: usize = 30;
            const ARRAY_LEN: usize = Word::MAX_LENGTH + 1;
            const TOO_LONG_PERMUTATION_ARRAY: [usize; ARRAY_LEN] = [6; ARRAY_LEN];

            Word::from(WORD_LEN_28).permute_bits(WORD_LEN, &TOO_LONG_PERMUTATION_ARRAY);
        }

        #[test]
        #[should_panic]
        fn permutation_array_with_zero_entries() {
            const WORD_LEN: usize = 30;
            const ARRAY_LEN: usize = 16;
            const PERMUTATION_ARRAY_WITH_ZEROS: [usize; ARRAY_LEN] = [0; ARRAY_LEN];

            Word::from(WORD_LEN_28).permute_bits(WORD_LEN, &PERMUTATION_ARRAY_WITH_ZEROS);
        }

        #[test]
        #[should_panic]
        fn permutation_array_with_entries_larger_than_word_len() {
            const WORD_LEN: usize = 30;
            const ARRAY_LEN: usize = 13;
            const PERMUTATION_ARRAY_WITH_TOO_LARGE_ENTRIES: [usize; ARRAY_LEN] =
                [WORD_LEN + 1; ARRAY_LEN];

            Word::from(WORD_LEN_28)
                .permute_bits(WORD_LEN, &PERMUTATION_ARRAY_WITH_TOO_LARGE_ENTRIES);
        }

        #[test]
        #[should_panic]
        fn permutation_array_with_entries_larger_than_max_word_len() {
            const WORD_LEN: usize = 30;
            const ARRAY_LEN: usize = 13;
            const PERMUTATION_ARRAY_WITH_TOO_LARGE_ENTRIES: [usize; ARRAY_LEN] =
                [Word::MAX_LENGTH + 1; ARRAY_LEN];

            Word::from(WORD_LEN_28)
                .permute_bits(WORD_LEN, &PERMUTATION_ARRAY_WITH_TOO_LARGE_ENTRIES);
        }

        #[test]
        fn idempotent_8_bit_permutation() {
            const WORD_LEN: usize = 8;
            const ARRAY_LEN: usize = WORD_LEN;
            const PERMUTATION_ARRAY: [usize; ARRAY_LEN] = [1, 2, 3, 4, 5, 6, 7, 8];

            let w = Word::from(0b1100_1010u64);

            let left = w.permute_bits(WORD_LEN, &PERMUTATION_ARRAY);
            let right = w;

            assert_eq!(left, right);
        }

        #[test]
        fn reverse_8_bit_permutation() {
            const WORD_LEN: usize = 8;
            const ARRAY_LEN: usize = WORD_LEN;
            const PERMUTATION_ARRAY: [usize; ARRAY_LEN] = [8, 7, 6, 5, 4, 3, 2, 1];

            let left = Word::from(0b1100_1010u64).permute_bits(WORD_LEN, &PERMUTATION_ARRAY);
            let right = Word::from(0b0101_0011u64);

            assert_eq!(left, right);
        }

        #[test]
        fn reverse_and_forward_16_bit_permutation() {
            const WORD_LEN: usize = 8;
            const ARRAY_LEN: usize = 16;
            const PERMUTATION_ARRAY: [usize; ARRAY_LEN] =
                [8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8];

            let left = Word::from(0b1100_1010u64).permute_bits(WORD_LEN, &PERMUTATION_ARRAY);
            let right = Word::from(0b0101_0011_1100_1010u64);

            assert_eq!(left, right);
        }

        #[test]
        fn expand_0x0a_to_0xa0a0() {
            const WORD_LEN: usize = 8;
            const ARRAY_LEN: usize = 16;
            const PERMUTATION_ARRAY: [usize; ARRAY_LEN] =
                [5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4];

            let left = Word::from(0xau64).permute_bits(WORD_LEN, &PERMUTATION_ARRAY);
            let right = Word::from(0xA0A0u64);

            assert_eq!(left, right);
        }

        #[test]
        fn contract_0xaaaa_aaaa_aaaa_aaaa_to_0xffff_ffff() {
            const WORD_LEN: usize = Word::MAX_LENGTH;
            const ARRAY_LEN: usize = WORD_LEN / 2;
            const PERMUTATION_ARRAY: [usize; ARRAY_LEN] = [
                1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43,
                45, 47, 49, 51, 53, 55, 57, 59, 61, 63,
            ];

            let left =
                Word::from(0xAAAA_AAAA_AAAA_AAAAu64).permute_bits(WORD_LEN, &PERMUTATION_ARRAY);
            let right = Word::from(0xFFFF_FFFFu64);

            assert_eq!(left, right);
        }
    }

    mod substitute_bytes {
        use crate::{word::tests::WORD_LEN_60, Word};

        const SUBSTITUTION_ARRAY: [u8; 256] = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7,
            0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF,
            0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5,
            0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
            0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,
            0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
            0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF,
            0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF,
            0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
            0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
            0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
            0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5,
            0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E,
            0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
            0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
            0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
            0xB0, 0x54, 0xBB, 0x16,
        ];

        #[test]
        #[should_panic(expected = "word length longer than 8 bytes")]
        fn word_len_too_long() {
            Word::from(0xFFFF_FFFFu64).substitute_bytes(9, &SUBSTITUTION_ARRAY);
        }

        #[test]
        #[should_panic(expected = "word length less than actual word length")]
        fn word_len_less_than_actual_word_len() {
            Word::from(0xFFFF_FFFFu64).substitute_bytes(3, &SUBSTITUTION_ARRAY);
        }

        #[test]
        fn trivial_zero_6_bytes() {
            let left = Word::zero().substitute_bytes(6, &SUBSTITUTION_ARRAY);
            let right = Word::from([0x0u8, 0x0, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63]);

            assert_eq!(left, right);
        }

        #[test]
        fn trivial_zero_full_len() {
            let left = Word::zero().substitute_bytes(8, &SUBSTITUTION_ARRAY);
            let right = Word::from([0x63u8; 8]);

            assert_eq!(left, right);
        }

        #[test]
        fn trivial_all_ones_5_bytes() {
            let left = Word::from(u32::MAX).substitute_bytes(5, &SUBSTITUTION_ARRAY);
            let right = Word::from([0x0u8, 0x0, 0x0, 0x63, 0x16, 0x16, 0x16, 0x16]);

            assert_eq!(left, right);
        }

        #[test]
        fn trivial_all_ones_full_len() {
            let left = Word::MAX.substitute_bytes(8, &SUBSTITUTION_ARRAY);
            let right = Word::from([0x16u8; 8]);

            assert_eq!(left, right);
        }

        #[test]
        fn non_trivial_full_len() {
            let left = Word::from(WORD_LEN_60).substitute_bytes(8, &SUBSTITUTION_ARRAY);
            let right = Word::from(0x6787_4A98_7D02_FEC8u64);

            assert_eq!(left, right);
        }
    }
}
