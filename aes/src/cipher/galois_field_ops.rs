use super::{AES_BLOCK_SIZE, BYTES_PER_WORD, _MIX_COLUMN_MATRIX};

fn _mul(left: u8, right: u8) -> u8 {
    const MSB_MASK: u8 = 0x80;
    const LSB_MASK: u8 = 0x01;

    let mut left = left;
    let mut right = right;

    let mut out = 0;

    for _ in 0..u8::BITS {
        if right & LSB_MASK == 1 {
            out ^= left;
        }

        let msb = left & MSB_MASK;
        left <<= 1;

        if msb == MSB_MASK {
            // XOR with bitwise irreducible polynomial coefficients
            // i.e.: x^8 + x^4 + x^3 + x + 1 of order less than 7
            // i.e.       '-----------------' these ones
            left ^= 0b0001_1011;
        }

        right >>= 1;
    }

    out
}

pub(super) fn _mix_column(column: &[u8; BYTES_PER_WORD]) -> [u8; BYTES_PER_WORD] {
    let mut out = [0u8; AES_BLOCK_SIZE];

    for (row, byte) in out.iter_mut().enumerate() {
        for (col, coefficient) in column.iter().enumerate() {
            *byte ^= _mul(*coefficient, _MIX_COLUMN_MATRIX[row][col]);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Word;

    #[test]
    fn mix_column_trivial_4_0x01s() {
        const INPUT: [u8; BYTES_PER_WORD] = [0x01; BYTES_PER_WORD];

        let left = Word::from(_mix_column(&INPUT));
        let right = Word::from(INPUT);

        assert_eq!(left, right);
    }

    #[test]
    fn mix_column_0xdb135345() {
        let left = Word::from(_mix_column(&[0xDB, 0x13, 0x53, 0x45]));
        let right = Word::from([0x8Eu8, 0x4D, 0xA1, 0xBC]);

        assert_eq!(left, right);
    }

    #[test]
    fn mix_column_0xf20a225c() {
        let left = Word::from(_mix_column(&[0xF2, 0x0A, 0x22, 0x5C]));
        let right = Word::from([0x9Fu8, 0xDC, 0x58, 0x9D]);

        assert_eq!(left, right);
    }
}
