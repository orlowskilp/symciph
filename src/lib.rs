mod command;
mod strategy;

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::Result;

type _Byte = u8;
type _DataChunk = [_Byte; _BLOCK_CHUNK_SIZE];

const _BLOCK_CHUNK_SIZE: usize = 8;

#[derive(Parser)]
#[command(author, version)]
#[command(about = "A simple CLI tool for symmetric encryption and decryption

Currently supporting DES, 3DES, AES-128, AES-192 and AES-256.")]
pub struct App {
    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone)]
enum EncryptionSchemes {
    Des,
    Tdes,
    Aes128,
    Aes192,
    Aes256,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a plaintext file
    #[command(short_flag = 'e')]
    Encrypt(Encrypt),
    /// Decrypt a ciphertext file
    #[command(short_flag = 'd')]
    Decrypt(Decrypt),
    /// Generate a pseudorandom symmetric key
    #[command(short_flag = 'g')]
    GenerateKey(GenerateKey),
}

#[derive(Args)]
struct Encrypt {
    /// Encryption algorithm
    cipher: EncryptionSchemes,
    /// Plaintext file path
    input_path: String,
    /// Ciphertext file path
    output_path: String,
    /// Encryption key file path
    key: String,
}

#[derive(Args)]
struct Decrypt {
    /// Encryption algorithm
    cipher: EncryptionSchemes,
    /// Ciphertext file path
    input_path: String,
    /// Plaintext file path
    output_path: String,
    /// Decryption key file path
    key: String,
}

#[derive(Args)]
struct GenerateKey {
    /// Encryption algorithm
    cipher: EncryptionSchemes,
    /// Generated key file path
    output_path: String,
}

impl App {
    pub fn new() -> Self {
        App::parse()
    }

    pub fn run(&self) -> Result<()> {
        self.command.run()
    }
}

impl Default for App {
    fn default() -> Self {
        App::new()
    }
}
