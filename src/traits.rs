use std::error::Error;

pub trait CryptoAlgorithm {
    fn generate_key_pair(self: &Self) -> (Vec<u8>, Vec<u8>);
    fn encrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    fn decrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
}