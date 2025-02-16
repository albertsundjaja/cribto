use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{builder::NonEmptyStringValueParser, Parser, Subcommand, ValueEnum};
use cribto::argon2;
use cribto::{chacha20poly1305::ChaCha20, rsa4096::RSA4096, traits::CryptoAlgorithm};
use rsa::pkcs8::der::Encode;
use std::io::Read;
use std::{ffi::OsString, fs};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
#[command(about)]
enum Commands {
    /// Encrypt a file or text
    Encrypt {
        key: String,   // Path to key or password text
        input: String, // File path or text to be encrypted
        #[arg(long, short, value_enum)]
        input_type: Option<InputType>, // File path or text, if not provided, file is assumed
        #[arg(long, short, value_enum)]
        algo_type: Option<AlgoType>, // Crypto algorithm, if not provided, X25519 is assumed
        #[arg(long, short, value_enum)]
        key_type: Option<KeyType>, // File path or text, if not provided, password text is assumed
        #[arg(long, short, value_enum)]
        output_type: Option<OutputType>, // File path or text, if not provided, file is assumed
    },

    /// Decrypt a file or text
    Decrypt {
        key: String,   // Path to key or password text
        input: String, // File path or base64 text to be decrypted
        #[arg(long, short, value_enum)]
        input_type: Option<InputType>, // File path or text, if not provided, file is assumed
        #[arg(long, short, value_enum)]
        algo_type: Option<AlgoType>, // Crypto algorithm, if not provided, X25519 is assumed
        #[arg(long, short, value_enum)]
        key_type: Option<KeyType>, // File path or text, if not provided, password text is assumed
        #[arg(long, short, value_enum)]
        output_type: Option<OutputType>, // File path or text, if not provided, file is assumed
    },

    /// Generate an encryption key
    Generate {
        #[arg(long, short, value_enum)]
        algo_type: Option<AlgoType>, // Crypto algorithm, if not provided, X25519 is assumed
        #[arg(long, short, value_enum)]
        output_type: Option<OutputType>, // File path or text, if not provided, file is assumed
    },
}

#[derive(Clone, ValueEnum)]
enum InputType {
    File,
    Text,
}

#[derive(Clone, ValueEnum)]
enum KeyType {
    Password, // Whether the input is a password text
    Key,      // Whether the input is a key
}

#[derive(Clone, ValueEnum)]
enum AlgoType {
    RSA4096,
    X25519,
    CHACHA20,
}

#[derive(Clone, ValueEnum)]
enum OutputType {
    File,
    Text,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Encrypt {
            key: raw_key,
            input: raw_input,
            input_type,
            algo_type,
            key_type,
            output_type,
        }) => {
            match key_type {
                Some(KeyType::Password) | None => {
                    encrypt_kdf(raw_key, raw_input, input_type, algo_type, key_type, output_type);
                }
                _ => {
                    unimplemented!("key type not yet implemented");
                }
            }
        }
        Some(Commands::Decrypt {
            key: raw_key,
            input: raw_input,
            input_type,
            algo_type,
            key_type,
            output_type,
        }) => {
            match key_type {
                Some(KeyType::Password) | None => {
                    decrypt_kdf(raw_key, raw_input, input_type, algo_type, key_type, output_type);
                }
                _ => {
                    unimplemented!("key type not yet implemented");
                }
            }
        }
        Some(Commands::Generate {
            algo_type,
            output_type,
        }) => {
            let algo = get_algo(algo_type);
            let (private, public) = algo.generate_key_pair();
            fs::write("private_key.pem", &private).expect("Failed to write private key");
            fs::write("public_key.pem", &public).expect("Failed to write public key");
        }
        _ => {
            println!("Invalid command")
        }
    };
}

fn encrypt_kdf(raw_key: &str, raw_input: &str, input_type: &Option<InputType>, algo_type: &Option<AlgoType>, key_type: &Option<KeyType>, output_type: &Option<OutputType>) {
    let input = get_input(input_type, raw_input);
    let salt = argon2::generate_salt();
    let key = get_key(key_type, raw_key, &salt);
    let algo = get_algo(algo_type);

    let mut encrypted = String::from_utf8(algo.encrypt(&key, &input).expect("Failed to encrypt")).expect("Failed to convert to string");
    encrypted = format!("{}${}", salt, encrypted);

    match output_type {
        Some(OutputType::Text) => {
            println!("{}", encrypted);
        }
        _ => {
            fs::write("encrypted", &encrypted).expect("Failed to write encrypted file");
        }
    }
}

fn decrypt_kdf(raw_key: &str, raw_input: &str, input_type: &Option<InputType>, algo_type: &Option<AlgoType>, key_type: &Option<KeyType>, output_type: &Option<OutputType>) {
    let input = get_input(input_type, raw_input);
    let input_str = String::from_utf8(input.clone()).expect("Failed to convert to string");
    let (ciphertext, salt) = if let Some(pos) = input_str.find('$') {
        (
            &input_str[pos + 1..].to_string(),
            input_str[..pos].to_string(),
        )
    } else {
        (&input_str, String::default())
    };
    let key = get_key(key_type, raw_key, &salt);

    let algo = get_algo(algo_type);
    let decrypted = algo.decrypt(&key, &ciphertext.as_bytes().to_vec()).expect("Failed to decrypt");

    match output_type {
        Some(OutputType::Text) => {
            println!(
                "{}",
                String::from_utf8(decrypted).expect("Failed to convert to string")
            );
        }
        _ => {
            fs::write("decrypted", &decrypted).expect("Failed to write decrypted file");
        }
    }
}

/// Get the input based on the input type.
fn get_input(input_type: &Option<InputType>, raw_input: &str) -> Vec<u8> {
    match input_type {
        Some(InputType::File) | None => fs::read(raw_input).expect("Failed to read input file"),
        _ => raw_input.as_bytes().to_vec(),
    }
}

/// Get the key (and optionally a salt) based on the key type.
fn get_key(key_type: &Option<KeyType>, raw_key: &str, salt: &str) -> Vec<u8> {
    match key_type {
        Some(KeyType::Key) => {fs::read(raw_key).expect("Failed to read key")}
        _ => {
            let derived_key =
                argon2::create_key(raw_key.as_bytes(), salt).expect("Failed to create key");
                derived_key.key.expect("Failed to get key")
        }
    }
}

/// Get the algorithm based on the algorithm type.
fn get_algo(algo_type: &Option<AlgoType>) -> Box<dyn CryptoAlgorithm> {
    match algo_type {
        Some(AlgoType::X25519) => Box::new(RSA4096 {}),
        Some(AlgoType::RSA4096) => Box::new(RSA4096 {}),
        Some(AlgoType::CHACHA20) => Box::new(ChaCha20 {}),
        _ => Box::new(ChaCha20 {}),
    }
}
