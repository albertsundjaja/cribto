use clap::{
    Parser,
    Subcommand,
    ValueEnum,
};
use cribto::{chacha20poly1305::ChaCha20Poly1305, rsa4096::RSA4096, traits::CryptoAlgorithm};
use std::fs;
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>
}

#[derive(Subcommand)]
#[command(about)]
enum Commands {
    /// Encrypt a file or text
    Encrypt {
        key: String, // Path to key or password text
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
        key: String, // Path to key or password text
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
    Key, // Whether the input is a key
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
        Some(Commands::Encrypt { key: raw_key, input: raw_input, input_type, algo_type, key_type, output_type}) => {
            let input: Vec<u8>;
            let key: Vec<u8>;
            match input_type {
                Some(InputType::File) | None => {
                    input = fs::read(raw_input).expect("Failed to read input file");
                }
                _ => {
                    input = raw_input.as_bytes().to_vec();
                }
            }
            match key_type {
                Some(KeyType::Key) => {
                    key = fs::read(raw_key).expect("Failed to read key");
                }
                _ => {
                    key = raw_key.as_bytes().to_vec();
                }
            }

            let algo = get_algo(algo_type);
            let encrypted = algo.encrypt(&key, &input).expect("Failed to encrypt");

            let encoded = STANDARD.encode(&encrypted);
            match output_type {
                Some(OutputType::Text) => {
                    println!("{}", encoded);
                }
                _ => {
                    fs::write("encrypted", &encoded).expect("Failed to write encrypted file");
                }
            }
        }
        Some(Commands::Decrypt { key: raw_key, input: raw_input, input_type, algo_type, key_type, output_type }) => {
            let input: Vec<u8>;
            let key: Vec<u8>;
            match input_type {
                Some(InputType::File) | None => {
                    input = fs::read(raw_input).expect("Failed to read encrypted file");
                }
                _ => {
                    input = STANDARD.decode(raw_input.as_bytes()).expect("Failed to decode base 64");
                }
            }
            match key_type {
                Some(KeyType::Key) => {
                    key = fs::read(raw_key).expect("Failed to read key");
                }
                _ => {
                    key = raw_key.as_bytes().to_vec();
                }
            }

            let algo = get_algo(algo_type);
            let decrypted = algo.decrypt(&key, &input).expect("Failed to decrypt");

            match output_type {
                Some(OutputType::Text) => {
                    println!("{}", String::from_utf8(decrypted).expect("Failed to convert to string"));
                }
                _ => {
                    fs::write("decrypted", &decrypted).expect("Failed to write decrypted file");
                }
            }
        }
        Some(Commands::Generate{algo_type, output_type}) => {
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

fn get_algo(algo_type: &Option<AlgoType>) -> Box<dyn CryptoAlgorithm> {
    match algo_type {
        Some(AlgoType::X25519) => Box::new(RSA4096{}),
        Some(AlgoType::RSA4096) => Box::new(RSA4096{}),
        Some(AlgoType::CHACHA20) => Box::new(ChaCha20Poly1305{}),
        _ => Box::new(RSA4096{})
    }
}
