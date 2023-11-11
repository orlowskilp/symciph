use std::{
    fs::remove_file,
    io::{Error, ErrorKind, Result},
    time::{SystemTime, UNIX_EPOCH},
};

use rand::Rng;

use crate::{io::write_key, DataChunk};

use super::{super::GenerateKey, Command};

impl Command for GenerateKey {
    fn run(&self) -> Result<()> {
        let key_chunks_num = self.cipher.key_size();
        let mut generated_key: Vec<DataChunk> = Vec::new();

        for _ in 0..key_chunks_num {
            generated_key.push(generate_key_chunk());
        }

        if let Err(write_key_error) = write_key(&self.output_path, &generated_key) {
            let deletion_status_message = match remove_file(&self.output_path) {
                Ok(_) => "Incomplete file deleted",
                Err(_) => "Attempted to delete file but failed 😩",
            };

            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("{} {}", write_key_error, deletion_status_message,),
            ));
        }

        Ok(())
    }
}

fn generate_key_chunk() -> DataChunk {
    let mut rng = rand::thread_rng();
    let mask = u64::MAX as u128;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("⏱️🪄😵‍💫: System time before Unix time. The OS is misconfigured")
        .as_nanos();

    ((now & mask) as u64 ^ rng.gen::<u64>()).to_be_bytes()
}
