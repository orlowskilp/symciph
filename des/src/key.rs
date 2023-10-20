use std::slice::Iter;

use super::{consts::*, DesKey, Word};

impl DesKey {
    pub(super) fn new(init_key: &[u8; 8]) -> Self {
        Self {
            round_keys: Self::expand_round_keys(Word::from(init_key)),
        }
    }

    pub(super) fn iter(&self) -> Iter<'_, Word> {
        self.round_keys.iter()
    }

    fn expand_round_keys(init_key: Word) -> [Word; NUM_ROUNDS] {
        let key = Self::permutation_choice_1(init_key);

        let (mut c, mut d) = key.split(SUBKEY_LENGTH);

        let round_keys: Vec<_> = (0..NUM_ROUNDS)
            .map(|i| {
                c = c.rotate_left(SHIFT_VALUES[i], SUBKEY_LENGTH);
                d = d.rotate_left(SHIFT_VALUES[i], SUBKEY_LENGTH);

                Self::permutation_choice_2(c.concatenate(d, SUBKEY_LENGTH))
            })
            .collect();

        round_keys
            .as_slice()
            .try_into()
            .expect("🙀🧨 DES key generation failed. This was not supposed to happen.")
    }

    fn permutation_choice_1(key: Word) -> Word {
        key.permute_bits(KEY_LENGTH, &PC1_TABLE)
    }

    fn permutation_choice_2(key: Word) -> Word {
        key.permute_bits(REDUCED_KEY_LENGTH, &PC2_TABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod permutation_choice_1 {
        use super::*;

        #[test]
        fn only_first_on() {
            let w = Word::one() << 63u8;

            let left = DesKey::permutation_choice_1(w);
            let right = Word::one() << 48u8;

            assert_eq!(left, right);
        }

        #[test]
        fn only_last_on() {
            let w = Word::one();

            let left = DesKey::permutation_choice_1(w);
            let right = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn parity_bits_only() {
            let mut w = Word::one();
            for i in 1..8 {
                w |= Word::one() << i * 8u8;
            }

            let left = DesKey::permutation_choice_1(w);
            let right = Word::zero();

            assert_eq!(left, right);
        }

        #[test]
        fn all_ones() {
            let w = Word::ones(64usize);

            let left = DesKey::permutation_choice_1(w);
            let right = Word::ones(56usize);

            assert_eq!(left, right);
        }
    }

    mod permutation_choice_2 {
        use super::*;

        #[test]
        fn only_first_on() {
            let w = Word::one() << 55u8;

            let left = DesKey::permutation_choice_2(w);
            let right = Word::one() << 43u8;

            assert_eq!(left, right);
        }

        #[test]
        fn only_last_on() {
            let w = Word::one();

            let left = DesKey::permutation_choice_2(w);
            let right = Word::one() << 8u8;

            assert_eq!(left, right);
        }

        #[test]
        fn all_ones() {
            let w = Word::ones(56usize);

            let left = DesKey::permutation_choice_2(w);
            let right = Word::ones(48usize);

            assert_eq!(left, right);
        }
    }

    mod expand_round_keys {
        use super::*;

        #[test]
        fn all_zeros() {
            let left = DesKey::expand_round_keys(Word::zero());
            let right = [Word::zero(); NUM_ROUNDS];

            assert_eq!(left, right);
        }

        #[test]
        fn all_ones() {
            let left: [Word; NUM_ROUNDS] = DesKey::expand_round_keys(Word::ones(64usize));
            let right = [Word::ones(48usize); NUM_ROUNDS];

            assert_eq!(left, right);
        }
    }
}
