use std::error::Error;
use crate::traits::CryptoAlgorithm;

pub struct X25519 {}

impl CryptoAlgorithm for X25519 {
    fn generate_key_pair(self: &Self) -> (Vec<u8>, Vec<u8>) {
        unimplemented!()
    }
    fn encrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        unimplemented!()
    }
    fn decrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        unimplemented!()
    }
}