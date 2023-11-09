mod decrypt;
mod encrypt;
mod generate_key;

use std::io::Result;

use super::Commands;

trait Command {
    fn run(&self) -> Result<()>;
}

impl Commands {
    pub(super) fn run(&self) -> Result<()> {
        let cmd: Box<&dyn Command> = match self {
            Commands::Encrypt(encrypt) => Box::new(encrypt),
            Commands::Decrypt(decrypt) => Box::new(decrypt),
            Commands::GenerateKey(generate_key) => Box::new(generate_key),
        };

        cmd.run()
    }
}
