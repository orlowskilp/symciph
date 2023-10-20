mod cipher;
mod consts;
mod key;

use consts::*;
use crypto_primitives::Word;

pub struct DesCipher {
    key: DesKey,
}

struct DesKey {
    round_keys: [Word; NUM_ROUNDS],
}
