// Block size in 32 bit words
pub(super) const AES_BLOCK_SIZE: usize = 4;
pub(super) const _BYTES_PER_WORD: usize = (u32::BITS / u8::BITS) as usize;

pub(super) const AES_NUM_ROUNDS_128: usize = 11;
pub(super) const AES_NUM_ROUNDS_192: usize = 13;
pub(super) const AES_NUM_ROUNDS_256: usize = 15;
