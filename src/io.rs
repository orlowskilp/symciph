use std::{
    fs::File,
    io::{Error, ErrorKind, Read, Result, Write},
};

use crate::{DataChunk, BLOCK_CHUNK_SIZE};

pub fn read_chunks(file: &mut File, buffer: &mut [DataChunk]) -> Result<(usize, usize)> {
    let mut num_chunks = 0;
    let mut bytes_read = 0;
    let buffer_len = buffer.len();

    assert!(buffer_len > 0, "I/O Read: Buffer length cannot be 0");

    for (chunk_idx, chunk) in buffer.iter_mut().enumerate() {
        chunk.fill(0);
        bytes_read = file.read(chunk)?;

        if bytes_read < BLOCK_CHUNK_SIZE {
            num_chunks = match bytes_read {
                // No more data to read
                0 if chunk_idx == 0 => 0,
                // Previous read was full, this one is empty, but chunk_idx incremented
                0 if chunk_idx > 0 => {
                    bytes_read = BLOCK_CHUNK_SIZE;
                    chunk_idx
                }
                _ => chunk_idx + 1,
            };

            break;
        }

        num_chunks = buffer_len;
    }

    Ok((num_chunks, bytes_read))
}

pub fn write_chunks(file: &mut File, buffer: &[DataChunk]) -> Result<()> {
    assert!(!buffer.is_empty(), "I/O Write: Buffer length cannot be 0");

    for chunk in buffer.iter() {
        let mut end_position = chunk.len();

        for byte in chunk.iter().rev() {
            match *byte {
                0 => end_position -= 1,
                _ => break,
            }
        }

        let bytes_written = file.write(&chunk[..end_position])?;

        if bytes_written < end_position {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "📝🙀: Failed to write full chunk.",
            ));
        }
    }

    Ok(())
}

// TODO: Express in terms of read_chunks()
pub fn read_key(key_path: &String) -> Result<Vec<DataChunk>> {
    let mut key_file = File::open(key_path)?;
    let mut key: Vec<DataChunk> = Vec::new();
    let mut chunk = [0u8; BLOCK_CHUNK_SIZE];

    loop {
        let bytes_read = key_file.read(&mut chunk)?;

        match bytes_read {
            0 => break,
            BLOCK_CHUNK_SIZE => key.push(chunk),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "🔑🙀: Key file is not a multiple of {} bytes.",
                        BLOCK_CHUNK_SIZE
                    ),
                ))
            }
        }
    }

    Ok(key)
}

// TODO: Express in terms of write_chunks()
pub fn write_key(key_path: &String, key: &[DataChunk]) -> Result<()> {
    let mut output_file = File::create(key_path)?;
    let mut buffer = [0; BLOCK_CHUNK_SIZE];

    for chunk in key.iter() {
        buffer.copy_from_slice(chunk);

        let bytes_written = output_file.write(&buffer)?;

        if bytes_written != BLOCK_CHUNK_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "📝🔑🙀: Failed to fully write generated key to file.",
            ));
        }
    }

    Ok(())
}
