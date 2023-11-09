use std::io::Result;

use super::{super::Decrypt, Command};

impl Command for Decrypt {
    fn run(&self) -> Result<()> {
        unimplemented!("Decrypt");
    }
}
