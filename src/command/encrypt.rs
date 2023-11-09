use std::io::Result;

use super::{super::Encrypt, Command};

impl Command for Encrypt {
    fn run(&self) -> Result<()> {
        unimplemented!("Encrypt");
    }
}
