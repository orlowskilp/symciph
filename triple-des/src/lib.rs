use des::DesCipher;

const NUM_STEPS: usize = 3;

pub struct TripleDesCipher {
    steps: [DesCipher; NUM_STEPS],
}

impl TripleDesCipher {
    pub fn new(key_bytes: &[[u8; 8]; NUM_STEPS]) -> Self {
        let mut step_vec: Vec<DesCipher> = Vec::with_capacity(NUM_STEPS);

        for key in key_bytes {
            step_vec.push(DesCipher::new(key));
        }

        let steps = match step_vec.try_into() {
            Ok(steps) => steps,
            Err(_) => panic!("3DES: Key expansion failed. This was not supposed to happen."),
        };

        Self { steps }
    }

    pub fn encrypt(&self, plaintext_block: &[u8; 8]) -> [u8; 8] {
        let mut ciphertext_block = *plaintext_block;

        for step in &self.steps {
            ciphertext_block = step.encrypt(&ciphertext_block);
        }

        ciphertext_block
    }

    pub fn decrypt(&self, ciphertext_block: &[u8; 8]) -> [u8; 8] {
        let mut plaintext_block = *ciphertext_block;

        for step in self.steps.iter().rev() {
            plaintext_block = step.decrypt(&plaintext_block);
        }

        plaintext_block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: [[u8; 8]; NUM_STEPS] = [
        [0x72, 0x48, 0xF2, 0x36, 0xD6, 0x0C, 0x40, 0x39],
        [0x37, 0x4E, 0xC6, 0x25, 0x3A, 0x12, 0x94, 0x8E],
        [0x01, 0x4D, 0x66, 0x32, 0x8C, 0x61, 0x4D, 0x4F],
    ];

    const PLAINTEXT: [u8; 8] = [0x03, 0x4C, 0x65, 0x52, 0x8D, 0x32, 0x4D, 0x4F];
    const CIPHERTEXT: [u8; 8] = [0x07, 0x19, 0x64, 0x46, 0x99, 0x33, 0x19, 0x1B];

    #[test]
    fn encrypt() {
        let tdes = TripleDesCipher::new(&KEYS);

        let left = tdes.encrypt(&PLAINTEXT);
        let right = CIPHERTEXT;

        assert_eq!(left, right);
    }

    #[test]
    fn decrypt() {
        let tdes = TripleDesCipher::new(&KEYS);

        let left = tdes.decrypt(&CIPHERTEXT);
        let right = PLAINTEXT;

        assert_eq!(left, right);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let tdes = TripleDesCipher::new(&KEYS);

        let left = tdes.decrypt(&tdes.encrypt(&PLAINTEXT));
        let right = PLAINTEXT;

        assert_eq!(left, right);
    }
}
