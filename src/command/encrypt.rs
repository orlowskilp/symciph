use std::{fs::File, io::Result};

use crate::{
    io::{read_chunks, read_key, write_chunks},
    BLOCK_CHUNK_SIZE,
};

use super::{super::Encrypt, Command, READ_BUFFER_LEN};

impl Command for Encrypt {
    fn run(&self) -> Result<()> {
        let mut input_file = File::open(&self.input_path)?;
        let mut output_file = File::create(&self.output_path)?;

        let key = read_key(&self.key)?;
        let encryption_scheme = self.cipher.strategy(&key);

        let read_buffer = &mut [[0u8; BLOCK_CHUNK_SIZE]; READ_BUFFER_LEN];

        loop {
            let (num_chunks, bytes_read) = read_chunks(&mut input_file, read_buffer)?;

            if num_chunks == 0 {
                break;
            }

            write_chunks(
                &mut output_file,
                encryption_scheme
                    .encrypt(&read_buffer[..num_chunks])
                    .as_slice(),
            )?;

            if bytes_read < BLOCK_CHUNK_SIZE {
                break;
            }
        }

        Ok(())
    }
}
