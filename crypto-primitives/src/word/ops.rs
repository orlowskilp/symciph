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

#[cfg(test)]
mod tests {
    use crate::word::tests::*;
    use crate::Word;

    mod binand {
        use super::*;

        #[test]
        fn zero_mask() {
            let right = Word::from(WORD_LEN_47) & Word::zero();
            let left = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn ones_mask() {
            let w = Word::from(WORD_LEN_47);

            let right = w & Word::ones(w.len());
            let left = w;

            assert_eq!(left, right);
        }

        #[test]
        fn value_0xff_and_0xff0() {
            let right = Word::from(0xFFu64) & Word::from(0xFF0u64);
            let left = Word::from(0xF0u64);

            assert_eq!(left, right);
        }

        #[test]
        fn assign_trivial_ones_and_zero() {
            let mut right = Word::MAX;
            right &= Word::zero();
            let left = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn assign_trivial_ones_and_ones() {
            let mut right = Word::MAX;
            right &= Word::MAX;
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn assign_0xff_and_0xff0() {
            let mut right = Word::from(0xFFu64);
            right &= Word::from(0xFF0u64);
            let left = Word::from(0xF0u64);

            assert_eq!(left, right);
        }
    }

    mod binor {
        use super::*;

        #[test]
        fn zero_mask() {
            let w = Word::from(WORD_LEN_47);

            let right = w | Word::zero();
            let left = w;

            assert_eq!(left, right);
        }

        #[test]
        fn ones_mask() {
            let w = Word::from(WORD_LEN_47);

            let right = w | Word::ones(w.len());
            let left = Word::ones(w.len());

            assert_eq!(left, right);
        }

        #[test]
        fn value_0xff_or_0xff0() {
            let right = Word::from(0xFFu64) | Word::from(0xFF0u64);
            let left = Word::from(0xFFFu64);

            assert_eq!(left, right);
        }

        #[test]
        fn assign_trivial_ones_and_zero() {
            let mut right = Word::MAX;
            right |= Word::zero();
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn assign_trivial_ones_and_ones() {
            let mut right = Word::MAX;
            right |= Word::MAX;
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        fn assign_0xff_and_0xff0() {
            let mut right = Word::from(0xFFu64);
            right |= Word::from(0xFF0u64);
            let left = Word::from(0xFFFu64);

            assert_eq!(left, right);
        }
    }

    mod binxor {
        use super::*;

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
    }

    mod not {
        use super::*;

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
    }

    mod shl {
        use super::*;

        #[test]
        fn by_0() {
            let left = Word::from(0xFFu64);
            let right = left << 0usize;

            assert_eq!(left, right);
        }

        #[test]
        fn by_4() {
            let right = Word::from(0xFFu64) << 4usize;
            let left = Word::from(0xFF0u64);

            assert_eq!(left, right);
        }

        #[test]
        #[should_panic]
        fn with_overflow() {
            let _ = Word::from(0xFFu64) << 64usize;
        }
    }

    mod shr {
        use super::*;

        #[test]
        fn by_0() {
            let left = Word::from(0xFFu64);
            let right = left >> 0usize;

            assert_eq!(left, right);
        }

        #[test]
        fn by_4() {
            let right = Word::from(0xFFu64) >> 4usize;
            let left = Word::from(0xFu64);

            assert_eq!(left, right);
        }

        #[test]
        #[should_panic]
        fn with_overflow() {
            let _ = Word::from(0xFFu64) >> 64usize;
        }
    }
}
