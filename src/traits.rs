use std::error::Error;

pub trait CryptoAlgorithm {
    fn new() -> Self;
    fn generate_key_pair() -> (Vec<u8>, Vec<u8>);
    fn encrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    fn decrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
}