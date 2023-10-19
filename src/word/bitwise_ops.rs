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
}
