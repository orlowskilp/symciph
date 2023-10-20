use super::Word;

pub mod bitwise_ops;
pub mod fmt;
pub mod from;
pub mod ops;

impl Word {
    pub const MAX_LENGTH: usize = u64::BITS as usize;
    pub const MAX: Self = Self { value: u64::MAX };
    pub const MIN: Self = Self { value: u64::MIN };
}

mod core {
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

    #[cfg(test)]
    mod tests {
        use crate::Word;

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
}

#[cfg(test)]
mod tests {
    // Some constants for unit tests
    pub const WORD_LEN_60: u64 =
        0b1010_1110_1010_0101_1100_1110_0010_0001_0011_0110_1010_0000_1100_1011_0001;
    pub const WORD_LEN_52: u64 = 0b1011_1101_0101_0111_0111_0001_0001_0011_1101_0100_0011_0101_1000;
    pub const WORD_LEN_47: u64 = 0b0100_1111_1011_1000_1010_1011_0110_0001_1101_0101_0111_0110;
    pub const WORD_LEN_28: u64 = 0b1111_0000_1100_1100_1010_1010_1001;
}
