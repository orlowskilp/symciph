#[derive(Clone, Copy)]
pub struct Word {
    value: u64,
}

pub mod consts {
    use super::Word;

    impl Word {
        pub const MAX_LENGTH: usize = u64::BITS as usize;
        pub const MAX: Self = Self { value: u64::MAX };
        pub const MIN: Self = Self { value: u64::MIN };
    }
}

pub mod core {
    use super::Word;

    impl Word {
        // Synonym for readibility
        pub const fn zero() -> Self {
            Self::MIN
        }

        // Shorthand for single bit masks by shifts
        pub const fn one() -> Self {
            Self { value: 1 }
        }

        pub const fn ones(length: usize) -> Self {
            assert!(
                length <= Self::MAX_LENGTH,
                "Word: attempt to create a word longer than 64 bits"
            );

            if length == 0 {
                return Self::MIN;
            }

            Self {
                value: u64::MAX >> (Self::MAX_LENGTH - length),
            }
        }

        pub const fn len(&self) -> usize {
            if self.value == 0 {
                return 1;
            }

            Self::MAX_LENGTH - self.value.leading_zeros() as usize
        }

        pub const fn is_empty(&self) -> bool {
            self.value == 0
        }
    }
}

pub mod bitwise_ops {
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

            (self >> subword_len, self & Self::ones(subword_len))
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

            let left_part = self & left_mask;
            let right_part = self & right_mask;

            right_part << rotate_by | left_part >> (word_len - rotate_by)
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

            let mut trace = vec![false; word_len];
            let input_msb = Self::one() << (word_len - 1);

            for (i, bit) in trace.iter_mut().enumerate() {
                if (self & input_msb >> i).value > 0 {
                    *bit = true;
                }
            }

            let output_msb = Self::one() << (permutation_array.len() - 1);
            let mut permutation = Self::zero();

            for (i, position) in permutation_array.iter().enumerate() {
                permutation |= if trace[position - 1] {
                    output_msb >> i
                } else {
                    Self::zero()
                };
            }

            permutation
        }
    }
}

pub mod from {
    use super::Word;

    macro_rules! impl_from_for_word_for_unsigned_types {
        ($($uint_type: ty),*) => {
            $(
                impl From<$uint_type> for Word {
                    fn from(val: $uint_type) -> Self {
                        Self{ value: val as u64 }
                    }
                }
            )*
        }
    }

    impl_from_for_word_for_unsigned_types!(usize, u8, u16, u32, u64);

    impl From<Word> for u64 {
        fn from(val: Word) -> Self {
            val.value
        }
    }

    impl From<Word> for [u8; 8] {
        fn from(val: Word) -> Self {
            val.value.to_be_bytes()
        }
    }

    impl From<[u8; 8]> for Word {
        fn from(bytes: [u8; 8]) -> Self {
            Self {
                value: u64::from_be_bytes(bytes),
            }
        }
    }

    impl From<&[u8; 8]> for Word {
        fn from(bytes: &[u8; 8]) -> Self {
            Self {
                value: u64::from_be_bytes(*bytes),
            }
        }
    }

    impl From<Word> for [u16; 4] {
        fn from(val: Word) -> Self {
            [
                (val.value >> (u16::BITS * 3)) as u16,
                ((val.value >> (u16::BITS * 2)) & 0xFFFF) as u16,
                ((val.value >> u16::BITS) & 0xFFFF) as u16,
                (val.value & 0xFFFF) as u16,
            ]
        }
    }

    impl From<[u16; 4]> for Word {
        fn from(val: [u16; 4]) -> Self {
            Self {
                value: ((val[0] as u64) << (u16::BITS * 3)
                    | (val[1] as u64) << (u16::BITS * 2)
                    | (val[2] as u64) << u16::BITS
                    | val[3] as u64),
            }
        }
    }

    impl From<&[u16; 4]> for Word {
        fn from(val: &[u16; 4]) -> Self {
            Self {
                value: ((val[0] as u64) << (u16::BITS * 3)
                    | (val[1] as u64) << (u16::BITS * 2)
                    | (val[2] as u64) << u16::BITS
                    | val[3] as u64),
            }
        }
    }

    impl From<Word> for [u32; 2] {
        fn from(val: Word) -> Self {
            [
                (val.value >> u32::BITS) as u32,
                (val.value & 0xFFFF_FFFF) as u32,
            ]
        }
    }

    impl From<[u32; 2]> for Word {
        fn from(val: [u32; 2]) -> Self {
            Self {
                value: ((val[0] as u64) << u32::BITS | val[1] as u64),
            }
        }
    }

    impl From<&[u32; 2]> for Word {
        fn from(val: &[u32; 2]) -> Self {
            Self {
                value: ((val[0] as u64) << u32::BITS | val[1] as u64),
            }
        }
    }
}

pub mod cmp {
    use super::Word;

    impl PartialEq for Word {
        fn eq(&self, other: &Self) -> bool {
            self.value == other.value
        }
    }

    impl Eq for Word {}
}

pub mod ops {
    use super::Word;
    use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, Shr};

    impl BitAnd for Word {
        type Output = Self;

        fn bitand(self, rhs: Self) -> Self {
            Self::from(self.value & rhs.value)
        }
    }

    impl BitAndAssign for Word {
        fn bitand_assign(&mut self, rhs: Self) {
            *self = *self & rhs
        }
    }

    impl BitOr for Word {
        type Output = Self;

        fn bitor(self, rhs: Self) -> Self {
            Self::from(self.value | rhs.value)
        }
    }

    impl BitOrAssign for Word {
        fn bitor_assign(&mut self, rhs: Self) {
            *self = *self | rhs
        }
    }

    impl BitXor for Word {
        type Output = Self;

        fn bitxor(self, rhs: Self) -> Self {
            Self::from(self.value ^ rhs.value)
        }
    }

    impl BitXorAssign for Word {
        fn bitxor_assign(&mut self, rhs: Self) {
            *self = *self ^ rhs
        }
    }

    impl Not for Word {
        type Output = Self;

        fn not(self) -> Self {
            Self::from(!self.value)
        }
    }

    macro_rules! impl_shl_for_word_for_unsigned_types {
        ($($uint_type: ty),*) => {
            $(
                impl Shl<$uint_type> for Word {
                    type Output = Self;

                    fn shl(self, rhs: $uint_type) -> Self {
                        assert!(
                            rhs < Self::MAX_LENGTH as $uint_type,
                            "Word: attempt to shift left with overflow"
                        );

                        Self::from(self.value << rhs)
                    }
                }
            )*
        }
    }

    impl_shl_for_word_for_unsigned_types!(usize, u8, u16, u32, u64);

    macro_rules! impl_shr_for_word_for_unsigned_types {
        ($($uint_type: ty),*) => {
            $(
                impl Shr<$uint_type> for Word {
                    type Output = Self;

                    fn shr(self, rhs: $uint_type) -> Self {
                        assert!(
                            rhs < Self::MAX_LENGTH as $uint_type,
                            "Word: attempt to shift right with overflow"
                        );

                        Self::from(self.value >> rhs)
                    }
                }
            )*
        }
    }

    impl_shr_for_word_for_unsigned_types!(usize, u8, u16, u32, u64);
}

pub mod fmt {
    use super::Word;
    use std::fmt::{Debug, Display};

    impl Display for Word {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:064b}", self.value)
        }
    }

    impl Debug for Word {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_fmt(format_args!("{:064b}", self.value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORD_LEN_60: u64 =
        0b1010_1110_1010_0101_1100_1110_0010_0001_0011_0110_1010_0000_1100_1011_0001;
    const WORD_LEN_52: u64 = 0b1011_1101_0101_0111_0111_0001_0001_0011_1101_0100_0011_0101_1000;
    const WORD_LEN_47: u64 = 0b0100_1111_1011_1000_1010_1011_0110_0001_1101_0101_0111_0110;
    const WORD_LEN_28: u64 = 0b1111_0000_1100_1100_1010_1010_1001;

    mod ops {
        use super::*;

        #[test]
        fn binand_zero_mask() {
            let right = Word::from(WORD_LEN_47) & Word::zero();
            let left = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn binand_ones_mask() {
            let w = Word::from(WORD_LEN_47);

            let right = w & Word::ones(w.len());
            let left = w;

            assert_eq!(left, right);
        }

        #[test]
        fn binand_0xff_and_0xff0() {
            let right = Word::from(0xFFu64) & Word::from(0xFF0u64);
            let left = Word::from(0xF0u64);

            assert_eq!(left, right);
        }

        #[test]
        fn binand_assign_trivial_ones_and_zero() {
            let mut right = Word::MAX;
            right &= Word::zero();
            let left = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn binand_assign_trivial_ones_and_ones() {
            let mut right = Word::MAX;
            right &= Word::MAX;
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn binand_assign_0xff_and_0xff0() {
            let mut right = Word::from(0xFFu64);
            right &= Word::from(0xFF0u64);
            let left = Word::from(0xF0u64);

            assert_eq!(left, right);
        }

        #[test]
        fn binor_zero_mask() {
            let w = Word::from(WORD_LEN_47);

            let right = w | Word::zero();
            let left = w;

            assert_eq!(left, right);
        }

        #[test]
        fn binor_ones_mask() {
            let w = Word::from(WORD_LEN_47);

            let right = w | Word::ones(w.len());
            let left = Word::ones(w.len());

            assert_eq!(left, right);
        }

        #[test]
        fn binor_0xff_or_0xff0() {
            let right = Word::from(0xFFu64) | Word::from(0xFF0u64);
            let left = Word::from(0xFFFu64);

            assert_eq!(left, right);
        }

        #[test]
        fn binor_assign_trivial_ones_and_zero() {
            let mut right = Word::MAX;
            right |= Word::zero();
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn binor_assign_trivial_ones_and_ones() {
            let mut right = Word::MAX;
            right |= Word::MAX;
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn binor_assign_0xff_and_0xff0() {
            let mut right = Word::from(0xFFu64);
            right |= Word::from(0xFF0u64);
            let left = Word::from(0xFFFu64);

            assert_eq!(left, right);
        }

        #[test]
        fn binxor_trivial_zero_xor_ones() {
            let w = Word::MAX;
            let right = w ^ Word::zero();
            let left = w;

            assert_eq!(left, right);
        }

        #[test]
        fn bixnor_trivial_ones_xor_ones() {
            let w = Word::MAX;

            let right = w ^ w;
            let left = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn bixnor_0xff_xor_0xff0() {
            let right = Word::from(0xFFu64) ^ Word::from(0xFF0u64);
            let left = Word::from(0xF0Fu64);

            assert_eq!(left, right);
        }

        #[test]
        fn binxor_assign_trivial_ones_and_zero() {
            let mut right = Word::MAX;
            right ^= Word::zero();
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn binxor_assign_trivial_ones_and_ones() {
            let mut right = Word::MAX;
            right ^= Word::MAX;
            let left = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn binxor_assign_0xff_and_0xff0() {
            let mut right = Word::from(0xFFu64);
            right ^= Word::from(0xFF0u64);
            let left = Word::from(0xF0Fu64);

            assert_eq!(left, right);
        }

        #[test]
        fn not_trivial_ones() {
            let right = !Word::MAX;
            let left = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn not_trivial_zero() {
            let right = !Word::zero();
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn not_trivial_half_full_word_flip() {
            let right = !Word::ones(Word::MAX_LENGTH / 2);
            let left = Word::from(u64::MAX - 2u64.pow(Word::MAX_LENGTH as u32 / 2) + 1);

            assert_eq!(left, right);
        }

        #[test]
        fn not_nontrivial() {
            let right = !Word::from(WORD_LEN_47);
            let left = Word::from(18446656419141659273u64);

            assert_eq!(left, right);
        }

        #[test]
        fn shl_by_0() {
            let left = Word::from(0xFFu64);
            let right = left << 0usize;

            assert_eq!(left, right);
        }

        #[test]
        fn shl_by_4() {
            let right = Word::from(0xFFu64) << 4usize;
            let left = Word::from(0xFF0u64);

            assert_eq!(left, right);
        }

        #[test]
        #[should_panic]
        fn shl_with_overflow() {
            let _ = Word::from(0xFFu64) << 64usize;
        }

        #[test]
        fn shr_by_0() {
            let left = Word::from(0xFFu64);
            let right = left >> 0usize;

            assert_eq!(left, right);
        }

        #[test]
        fn shr_by_4() {
            let right = Word::from(0xFFu64) >> 4usize;
            let left = Word::from(0xFu64);

            assert_eq!(left, right);
        }

        #[test]
        #[should_panic]
        fn shr_with_overflow() {
            let _ = Word::from(0xFFu64) >> 64usize;
        }
    }

    mod core {
        use super::*;

        #[test]
        fn ones_zero_length() {
            let right = Word::ones(0);
            let left = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        #[should_panic]
        fn ones_too_long() {
            Word::ones(Word::MAX_LENGTH + 1);
        }

        #[test]
        fn ones_max_length() {
            let right = Word::MAX;
            let left = Word::ones(Word::MAX_LENGTH);

            assert_eq!(left, right);
        }

        #[test]
        fn ones_48_bit_long() {
            const WORD_LENGTH: usize = 48;
            let right = Word::from(2u64.pow(WORD_LENGTH as u32) - 1);
            let left = Word::ones(WORD_LENGTH);

            assert_eq!(left, right);
        }

        #[test]
        fn len_0() {
            const WORD_LENGTH: usize = 1;

            let right = Word::zero().len();
            let left = WORD_LENGTH;

            assert_eq!(left, right);
        }

        #[test]
        fn len_1() {
            const WORD_LENGTH: usize = 1;

            let right = Word::ones(1).len();
            let left = WORD_LENGTH;

            assert_eq!(left, right);
        }

        #[test]
        fn len_48() {
            const WORD_LENGTH: usize = 48;

            let right = Word::ones(WORD_LENGTH).len();
            let left = WORD_LENGTH;

            assert_eq!(left, right);
        }

        #[test]
        fn len_64() {
            const WORD_LENGTH: usize = Word::MAX_LENGTH;

            let right = Word::MAX.len();
            let left = WORD_LENGTH;

            assert_eq!(left, right);
        }
    }

    mod from {
        use super::*;

        #[test]
        fn word_to_u64() {
            let right: u64 = Word::from(WORD_LEN_60).into();
            let left = WORD_LEN_60;

            assert_eq!(left, right);
        }

        #[test]
        fn word_to_u8_array() {
            let right: [u8; 8] = Word::MAX.into();
            let left = [0xFFu8; 8];

            assert!(left
                .iter()
                .zip(right.iter())
                .all(|(left, right)| left == right));
        }

        #[test]
        fn u8_array_to_word() {
            let right = Word::from([0xFFu8; 8]);
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn word_to_u16_array() {
            let right: [u16; 4] = Word::ones(40).into();
            let left = [0x0, 0x00FF, 0xFFFF, 0xFFFF];

            assert!(left
                .iter()
                .zip(right.iter())
                .all(|(left, right)| left == right));
        }

        #[test]
        fn u16_array_to_word() {
            let right = Word::from([0x0, 0x00FF, 0xFFFF, 0xFFFF]);
            let left = Word::ones(40);

            assert_eq!(left, right);
        }

        #[test]
        fn word_to_u32_array() {
            let right: [u32; 2] = Word::ones(32).into();
            let left = [0x0, 0xFFFF_FFFF];

            assert!(left
                .iter()
                .zip(right.iter())
                .all(|(left, right)| left == right));
        }

        #[test]
        fn u32_array_to_word() {
            let right = Word::from([0x0, 0xFFFF_FFFF]);
            let left = Word::ones(32);

            assert_eq!(left, right);
        }
    }

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
