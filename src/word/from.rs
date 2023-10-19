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

impl From<Word> for [u8; 4] {
    fn from(val: Word) -> Self {
        assert!(
            val.len() <= u32::BITS as usize,
            "From Word to [u8; 4] failed: Word length is greater than 32 bits"
        );

        (val.value as u32).to_be_bytes()
    }
}

impl From<[u8; 4]> for Word {
    fn from(bytes: [u8; 4]) -> Self {
        Self {
            value: u32::from_be_bytes(bytes) as u64,
        }
    }
}

impl From<&[u8; 4]> for Word {
    fn from(bytes: &[u8; 4]) -> Self {
        Self {
            value: u32::from_be_bytes(*bytes) as u64,
        }
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

#[cfg(test)]
mod tests {
    use crate::word::tests::*;
    use crate::Word;

    mod from {
        use super::*;

        #[test]
        fn word_to_u8_8_element_array() {
            let right: [u8; 8] = Word::MAX.into();
            let left = [0xFFu8; 8];

            assert!(left
                .iter()
                .zip(right.iter())
                .all(|(left, right)| left == right));
        }

        #[test]
        fn u8_8_element_array_to_word() {
            let right = Word::from([0xFFu8; 8]);
            let left = Word::MAX;

            assert_eq!(left, right);
        }

        #[test]
        #[should_panic]
        fn too_long_word_to_u8_4_element_array() {
            let _: [u8; 4] = Word::MAX.into();
        }

        #[test]
        fn word_to_u8_4_element_array() {
            let right: [u8; 4] = Word::from(u32::MAX).into();
            let left = [0xFFu8; 4];

            assert!(left
                .iter()
                .zip(right.iter())
                .all(|(left, right)| left == right));
        }

        #[test]
        fn u8_4_element_array_to_word() {
            let right = Word::from([0xFFu8; 4]);
            let left = Word::from(u32::MAX);

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
            let right = Word::from([0x0u16, 0x00FF, 0xFFFF, 0xFFFF]);
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

        #[test]
        fn word_to_u64() {
            let right: u64 = Word::from(WORD_LEN_60).into();
            let left = WORD_LEN_60;

            assert_eq!(left, right);
        }
    }
}
