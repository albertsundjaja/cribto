use clap::{
    Parser,
    Subcommand,
    ValueEnum,
};
use cribto::rsa2048::RSA2048;
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
        key: String, // Path to key
        input: String, // File path or text
        #[arg(value_enum)]
        input_type: Option<InputType>, // File path or text, if not provided, text is assumed
    },
    
    /// Decrypt a file or text
    Decrypt {
        key: String, // Path to key
        input: String, // File path
        #[arg(value_enum)]
        input_type: Option<InputType>, // File path or base 64 text, if not provided, text is assumed
    },

    /// Generate an encryption key
    Generate,
}

#[derive(Clone, ValueEnum)]
enum InputType {
    File,
    Text,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Encrypt { input_type, key, input }) => {
            match input_type {
                Some(InputType::File) => {
                    let key = fs::read(key).expect("Failed to read key");
                    let input = fs::read(input).expect("Failed to read input file");
                    let encrypted = RSA2048::encrypt(&key, &input).expect("Failed to encrypt");
                    fs::write("encrypted", &encrypted).expect("Failed to write encrypted file");
                }
                Some(InputType::Text) | None => {
                    let key = fs::read(key).expect("Failed to read key");
                    let encrypted = RSA2048::encrypt(&key, &input.as_bytes().to_vec()).expect("Failed to encrypt");
                    println!("{}", STANDARD.encode(&encrypted));
                }
            }
        }
        Some(Commands::Decrypt { input_type, key, input }) => {
            match input_type {
                Some(InputType::File) => {
                    let key = fs::read(key).expect("Failed to read key");
                    let encrypted = fs::read(input).expect("Failed to read encrypted file");
                    let decrypted = RSA2048::decrypt(&key, &encrypted).expect("Failed to decrypt");
                    fs::write("decrypted", &decrypted).expect("Failed to write decrypted file");
                }
                Some(InputType::Text) | None => {
                    let key = fs::read(key).expect("Failed to read key");
                    let unencode = STANDARD.decode(input.as_bytes()).expect("Failed to decode base 64");
                    let decrypted = RSA2048::decrypt(&key, &unencode).expect("Failed to decrypt");
                    println!("{}", String::from_utf8(decrypted).expect("Failed to convert to string"));
                }
            }
        }
        Some(Commands::Generate) => {
            let (private, public) = RSA2048::generate_key_pair();
            fs::write("private_key.pem", &private).expect("Failed to write private key");
            fs::write("public_key.pem", &public).expect("Failed to write public key");
        }
        _ => {
            println!("Invalid command")
        }
    };
}
