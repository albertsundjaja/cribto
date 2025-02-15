use std::error::Error;
use crate::traits::CryptoAlgorithm;
use rsa::rand_core::OsRng;

pub struct ChaCha20Poly1305 {}

impl CryptoAlgorithm for ChaCha20Poly1305 {
    fn generate_key_pair(self: &Self) -> (Vec<u8>, Vec<u8>) {
        // let mut key = [0u8; 32];
        // let mut nonce = [0u8; 12];
        // OsRng.fill_bytes(&mut key);
        // OsRng.fill_bytes(&mut nonce);
        // (key.to_vec(), nonce.to_vec())
        unimplemented!()
    }
    fn encrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        // let mut cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_slice()), GenericArray::from_slice(nonce.as_slice()));
        // let mut output = vec![0u8; input.len()];
        // cipher.encrypt(input.as_slice(), output.as_mut_slice());
        // Ok(output)
        unimplemented!()
    }
    fn decrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        // let mut cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_slice()), GenericArray::from_slice(nonce.as_slice()));
        // let mut output = vec![0u8; input.len()];
        // cipher.decrypt(input.as_slice(), output.as_mut_slice());
        // Ok(output)
        unimplemented!()
    }
}