mod cipher;

use des::DesCipher;

const NUM_STEPS: usize = 3;

pub struct TripleDesCipher {
    steps: [DesCipher; NUM_STEPS],
}
